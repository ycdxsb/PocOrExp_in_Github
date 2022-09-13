# Update 2022-09-13
## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/Expl0desploit/CVE-2022-32548](https://github.com/Expl0desploit/CVE-2022-32548) :  ![starts](https://img.shields.io/github/stars/Expl0desploit/CVE-2022-32548.svg) ![forks](https://img.shields.io/github/forks/Expl0desploit/CVE-2022-32548.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/Ziggy78/CVE-2022-26809-RCE-MASS](https://github.com/Ziggy78/CVE-2022-26809-RCE-MASS) :  ![starts](https://img.shields.io/github/stars/Ziggy78/CVE-2022-26809-RCE-MASS.svg) ![forks](https://img.shields.io/github/forks/Ziggy78/CVE-2022-26809-RCE-MASS.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Gustavo-Nogueira/Dirty-Pipe-Exploits](https://github.com/Gustavo-Nogueira/Dirty-Pipe-Exploits) :  ![starts](https://img.shields.io/github/stars/Gustavo-Nogueira/Dirty-Pipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/Gustavo-Nogueira/Dirty-Pipe-Exploits.svg)


## CVE-2021-42321
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/xnyuq/cve-2021-42321](https://github.com/xnyuq/cve-2021-42321) :  ![starts](https://img.shields.io/github/stars/xnyuq/cve-2021-42321.svg) ![forks](https://img.shields.io/github/forks/xnyuq/cve-2021-42321.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/3bd0x45/CVE-2021-41773](https://github.com/3bd0x45/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/3bd0x45/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/3bd0x45/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/k4u5h41/CVE-2021-4034](https://github.com/k4u5h41/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2021-4034.svg)


## CVE-2019-7213
 SmarterTools SmarterMail 16.x before build 6985 allows directory traversal. An authenticated user could delete arbitrary files or could create files in new folders in arbitrary locations on the mail server. This could lead to command execution on the server for instance by putting files inside the web directories.

- [https://github.com/secunnix/CVE-2019-7213](https://github.com/secunnix/CVE-2019-7213) :  ![starts](https://img.shields.io/github/stars/secunnix/CVE-2019-7213.svg) ![forks](https://img.shields.io/github/forks/secunnix/CVE-2019-7213.svg)


## CVE-2018-14699
 System command injection in the /DroboAccess/enable_user endpoint in Drobo 5N2 NAS version 4.0.5-13.28.96115 allows unauthenticated attackers to execute system commands via the &quot;username&quot; URL parameter.

- [https://github.com/RevoCain/CVE-2018-14699](https://github.com/RevoCain/CVE-2018-14699) :  ![starts](https://img.shields.io/github/stars/RevoCain/CVE-2018-14699.svg) ![forks](https://img.shields.io/github/forks/RevoCain/CVE-2018-14699.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/wiredaem0n/chk-ms15-034](https://github.com/wiredaem0n/chk-ms15-034) :  ![starts](https://img.shields.io/github/stars/wiredaem0n/chk-ms15-034.svg) ![forks](https://img.shields.io/github/forks/wiredaem0n/chk-ms15-034.svg)


## CVE-2013-2186
 The DiskFileItem class in Apache Commons FileUpload, as used in Red Hat JBoss BRMS 5.3.1; JBoss Portal 4.3 CP07, 5.2.2, and 6.0.0; and Red Hat JBoss Web Server 1.0.2 allows remote attackers to write to arbitrary files via a NULL byte in a file name in a serialized instance.

- [https://github.com/sa1g0n1337/CVE_2013_2186](https://github.com/sa1g0n1337/CVE_2013_2186) :  ![starts](https://img.shields.io/github/stars/sa1g0n1337/CVE_2013_2186.svg) ![forks](https://img.shields.io/github/forks/sa1g0n1337/CVE_2013_2186.svg)
- [https://github.com/sa1g0n1337/Payload_CVE_2013_2186](https://github.com/sa1g0n1337/Payload_CVE_2013_2186) :  ![starts](https://img.shields.io/github/stars/sa1g0n1337/Payload_CVE_2013_2186.svg) ![forks](https://img.shields.io/github/forks/sa1g0n1337/Payload_CVE_2013_2186.svg)

