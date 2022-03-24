# Update 2022-03-24
## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0xf4n9x/CVE-2022-24990](https://github.com/0xf4n9x/CVE-2022-24990) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2022-24990.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2022-24990.svg)


## CVE-2021-46398
 A Cross-Site Request Forgery vulnerability exists in Filebrowser &lt; 2.18.0 that allows attackers to create a backdoor user with admin privilege and get access to the filesystem via a malicious HTML webpage that is sent to the victim. An admin can run commands using the FileBrowser and hence it leads to RCE.

- [https://github.com/febinrev/CVE-2021-46398_Chamilo-LMS-RCE](https://github.com/febinrev/CVE-2021-46398_Chamilo-LMS-RCE) :  ![starts](https://img.shields.io/github/stars/febinrev/CVE-2021-46398_Chamilo-LMS-RCE.svg) ![forks](https://img.shields.io/github/forks/febinrev/CVE-2021-46398_Chamilo-LMS-RCE.svg)


## CVE-2021-41338
 Windows AppContainer Firewall Rules Security Feature Bypass Vulnerability

- [https://github.com/Mario-Kart-Felix/firewall-cve](https://github.com/Mario-Kart-Felix/firewall-cve) :  ![starts](https://img.shields.io/github/stars/Mario-Kart-Felix/firewall-cve.svg) ![forks](https://img.shields.io/github/forks/Mario-Kart-Felix/firewall-cve.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/J0hnbX/CVE-2021-4034-new](https://github.com/J0hnbX/CVE-2021-4034-new) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2021-4034-new.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2021-4034-new.svg)
- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/seanachao/CVE-2020-9484](https://github.com/seanachao/CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/seanachao/CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/seanachao/CVE-2020-9484.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/gdwnet/cve-2020-1350](https://github.com/gdwnet/cve-2020-1350) :  ![starts](https://img.shields.io/github/stars/gdwnet/cve-2020-1350.svg) ![forks](https://img.shields.io/github/forks/gdwnet/cve-2020-1350.svg)


## CVE-2020-1337
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'.

- [https://github.com/sailay1996/cve-2020-1337-poc](https://github.com/sailay1996/cve-2020-1337-poc) :  ![starts](https://img.shields.io/github/stars/sailay1996/cve-2020-1337-poc.svg) ![forks](https://img.shields.io/github/forks/sailay1996/cve-2020-1337-poc.svg)
- [https://github.com/VoidSec/CVE-2020-1337](https://github.com/VoidSec/CVE-2020-1337) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2020-1337.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2020-1337.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a &quot;sudo -u \#$((0xffffffff))&quot; command.

- [https://github.com/shyambhanushali/AttackDefendExercise](https://github.com/shyambhanushali/AttackDefendExercise) :  ![starts](https://img.shields.io/github/stars/shyambhanushali/AttackDefendExercise.svg) ![forks](https://img.shields.io/github/forks/shyambhanushali/AttackDefendExercise.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/S3ntinelX/nmap-scripts](https://github.com/S3ntinelX/nmap-scripts) :  ![starts](https://img.shields.io/github/stars/S3ntinelX/nmap-scripts.svg) ![forks](https://img.shields.io/github/forks/S3ntinelX/nmap-scripts.svg)


## CVE-2016-1827
 The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1828, CVE-2016-1829, and CVE-2016-1830.

- [https://github.com/domain9065v/bazad3](https://github.com/domain9065v/bazad3) :  ![starts](https://img.shields.io/github/stars/domain9065v/bazad3.svg) ![forks](https://img.shields.io/github/forks/domain9065v/bazad3.svg)

