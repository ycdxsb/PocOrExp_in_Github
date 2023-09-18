# Update 2023-09-18
## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/an040702/CVE-2023-38831](https://github.com/an040702/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/an040702/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/an040702/CVE-2023-38831.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/savior-only/CVE-2022-30525](https://github.com/savior-only/CVE-2022-30525) :  ![starts](https://img.shields.io/github/stars/savior-only/CVE-2022-30525.svg) ![forks](https://img.shields.io/github/forks/savior-only/CVE-2022-30525.svg)


## CVE-2022-4061
 The JobBoardWP WordPress plugin before 1.2.2 does not properly validate file names and types in its file upload functionalities, allowing unauthenticated users to upload arbitrary files such as PHP.

- [https://github.com/im-hanzou/JBWPer](https://github.com/im-hanzou/JBWPer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/JBWPer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/JBWPer.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/ab0x90/CVE-2021-44228_PoC](https://github.com/ab0x90/CVE-2021-44228_PoC) :  ![starts](https://img.shields.io/github/stars/ab0x90/CVE-2021-44228_PoC.svg) ![forks](https://img.shields.io/github/forks/ab0x90/CVE-2021-44228_PoC.svg)


## CVE-2021-42321
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/FDlucifer/Proxy-Attackchain](https://github.com/FDlucifer/Proxy-Attackchain) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Proxy-Attackchain.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Proxy-Attackchain.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)
- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/r0eXpeR/CVE-2021-22205](https://github.com/r0eXpeR/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/r0eXpeR/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/r0eXpeR/CVE-2021-22205.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Fato07/Pwnkit-exploit](https://github.com/Fato07/Pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/Fato07/Pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Fato07/Pwnkit-exploit.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/ejlevin99/CVE---2020---1350](https://github.com/ejlevin99/CVE---2020---1350) :  ![starts](https://img.shields.io/github/stars/ejlevin99/CVE---2020---1350.svg) ![forks](https://img.shields.io/github/forks/ejlevin99/CVE---2020---1350.svg)


## CVE-2019-20372
 NGINX before 1.17.7, with certain error_page configurations, allows HTTP request smuggling, as demonstrated by the ability of an attacker to read unauthorized web pages in environments where NGINX is being fronted by a load balancer.

- [https://github.com/0xleft/CVE-2019-20372](https://github.com/0xleft/CVE-2019-20372) :  ![starts](https://img.shields.io/github/stars/0xleft/CVE-2019-20372.svg) ![forks](https://img.shields.io/github/forks/0xleft/CVE-2019-20372.svg)


## CVE-2019-16278
 Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.

- [https://github.com/0xTabun/CVE-2019-16278](https://github.com/0xTabun/CVE-2019-16278) :  ![starts](https://img.shields.io/github/stars/0xTabun/CVE-2019-16278.svg) ![forks](https://img.shields.io/github/forks/0xTabun/CVE-2019-16278.svg)

