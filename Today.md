# Update 2022-04-10
## CVE-2022-28281
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0vercl0k/CVE-2022-28281](https://github.com/0vercl0k/CVE-2022-28281) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2022-28281.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2022-28281.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/tangxiaofeng7/CVE-2022-22965-Spring-Core-Rce](https://github.com/tangxiaofeng7/CVE-2022-22965-Spring-Core-Rce) :  ![starts](https://img.shields.io/github/stars/tangxiaofeng7/CVE-2022-22965-Spring-Core-Rce.svg) ![forks](https://img.shields.io/github/forks/tangxiaofeng7/CVE-2022-22965-Spring-Core-Rce.svg)
- [https://github.com/CalumHutton/CVE-2022-22965-PoC_Payara](https://github.com/CalumHutton/CVE-2022-22965-PoC_Payara) :  ![starts](https://img.shields.io/github/stars/CalumHutton/CVE-2022-22965-PoC_Payara.svg) ![forks](https://img.shields.io/github/forks/CalumHutton/CVE-2022-22965-PoC_Payara.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/polakow/CVE-2022-21907](https://github.com/polakow/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/polakow/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/polakow/CVE-2022-21907.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/ArkAngeL43/CVE-2021-4034](https://github.com/ArkAngeL43/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ArkAngeL43/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ArkAngeL43/CVE-2021-4034.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/sentryCyberSec/sentryCyberSec.github.io](https://github.com/sentryCyberSec/sentryCyberSec.github.io) :  ![starts](https://img.shields.io/github/stars/sentryCyberSec/sentryCyberSec.github.io.svg) ![forks](https://img.shields.io/github/forks/sentryCyberSec/sentryCyberSec.github.io.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/ret2basic/SudoScience](https://github.com/ret2basic/SudoScience) :  ![starts](https://img.shields.io/github/stars/ret2basic/SudoScience.svg) ![forks](https://img.shields.io/github/forks/ret2basic/SudoScience.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/cuongtop4598/CVE-2021-3129-Script](https://github.com/cuongtop4598/CVE-2021-3129-Script) :  ![starts](https://img.shields.io/github/stars/cuongtop4598/CVE-2021-3129-Script.svg) ![forks](https://img.shields.io/github/forks/cuongtop4598/CVE-2021-3129-Script.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/BabyTeam1024/CVE-2021-2394](https://github.com/BabyTeam1024/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-2394.svg)


## CVE-2020-1206
 An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.

- [https://github.com/ZecOps/CVE-2020-1206-POC](https://github.com/ZecOps/CVE-2020-1206-POC) :  ![starts](https://img.shields.io/github/stars/ZecOps/CVE-2020-1206-POC.svg) ![forks](https://img.shields.io/github/forks/ZecOps/CVE-2020-1206-POC.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/bananaphones/exim-rce-quickfix](https://github.com/bananaphones/exim-rce-quickfix) :  ![starts](https://img.shields.io/github/stars/bananaphones/exim-rce-quickfix.svg) ![forks](https://img.shields.io/github/forks/bananaphones/exim-rce-quickfix.svg)
- [https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim](https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim) :  ![starts](https://img.shields.io/github/stars/MNEMO-CERT/PoC--CVE-2019-10149_Exim.svg) ![forks](https://img.shields.io/github/forks/MNEMO-CERT/PoC--CVE-2019-10149_Exim.svg)


## CVE-2019-0841
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0730, CVE-2019-0731, CVE-2019-0796, CVE-2019-0805, CVE-2019-0836.

- [https://github.com/mappl3/CVE-2019-0841](https://github.com/mappl3/CVE-2019-0841) :  ![starts](https://img.shields.io/github/stars/mappl3/CVE-2019-0841.svg) ![forks](https://img.shields.io/github/forks/mappl3/CVE-2019-0841.svg)


## CVE-2018-3783
 A privilege escalation detected in flintcms versions &lt;= 1.1.9 allows account takeover due to blind MongoDB injection in password reset.

- [https://github.com/nisaruj/nosqli-flintcms](https://github.com/nisaruj/nosqli-flintcms) :  ![starts](https://img.shields.io/github/stars/nisaruj/nosqli-flintcms.svg) ![forks](https://img.shields.io/github/forks/nisaruj/nosqli-flintcms.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/0zvxr/CVE-2017-9841](https://github.com/0zvxr/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/0zvxr/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/0zvxr/CVE-2017-9841.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/persian64/CVE-2007-2447](https://github.com/persian64/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/persian64/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/persian64/CVE-2007-2447.svg)

