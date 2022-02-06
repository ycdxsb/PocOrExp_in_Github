# Update 2022-02-06
## CVE-2022-21241
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/satoki/csv-plus_vulnerability](https://github.com/satoki/csv-plus_vulnerability) :  ![starts](https://img.shields.io/github/stars/satoki/csv-plus_vulnerability.svg) ![forks](https://img.shields.io/github/forks/satoki/csv-plus_vulnerability.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/qingtengyun/cve-2021-44228-qingteng-patch](https://github.com/qingtengyun/cve-2021-44228-qingteng-patch) :  ![starts](https://img.shields.io/github/stars/qingtengyun/cve-2021-44228-qingteng-patch.svg) ![forks](https://img.shields.io/github/forks/qingtengyun/cve-2021-44228-qingteng-patch.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Nickguitar/YAPS](https://github.com/Nickguitar/YAPS) :  ![starts](https://img.shields.io/github/stars/Nickguitar/YAPS.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/YAPS.svg)
- [https://github.com/drapl0n/dawnKit](https://github.com/drapl0n/dawnKit) :  ![starts](https://img.shields.io/github/stars/drapl0n/dawnKit.svg) ![forks](https://img.shields.io/github/forks/drapl0n/dawnKit.svg)
- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)
- [https://github.com/ravindubw/CVE-2021-4034](https://github.com/ravindubw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ravindubw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ravindubw/CVE-2021-4034.svg)


## CVE-2020-7934
 In LifeRay Portal CE 7.1.0 through 7.2.1 GA2, the First Name, Middle Name, and Last Name fields for user accounts in MyAccountPortlet are all vulnerable to a persistent XSS issue. Any user can modify these fields with a particular XSS payload, and it will be stored in the database. The payload will then be rendered when a user utilizes the search feature to search for other users (i.e., if a user with modified fields occurs in the search results). This issue was fixed in Liferay Portal CE version 7.3.0 GA1.

- [https://github.com/Sergio235705/audit-xss-cve-2020-7934](https://github.com/Sergio235705/audit-xss-cve-2020-7934) :  ![starts](https://img.shields.io/github/stars/Sergio235705/audit-xss-cve-2020-7934.svg) ![forks](https://img.shields.io/github/forks/Sergio235705/audit-xss-cve-2020-7934.svg)


## CVE-2017-0505
 An elevation of privilege vulnerability in MediaTek components, including the M4U driver, sound driver, touchscreen driver, GPU driver, and Command Queue driver, could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: N/A. Android ID: A-31822282. References: M-ALPS02992041.

- [https://github.com/R0rt1z2/CVE-2017-0505-mtk](https://github.com/R0rt1z2/CVE-2017-0505-mtk) :  ![starts](https://img.shields.io/github/stars/R0rt1z2/CVE-2017-0505-mtk.svg) ![forks](https://img.shields.io/github/forks/R0rt1z2/CVE-2017-0505-mtk.svg)

