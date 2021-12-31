# Update 2021-12-31
## CVE-2021-45232
 In Apache APISIX Dashboard before 2.10.1, the Manager API uses two frameworks and introduces framework `droplet` on the basis of framework `gin`, all APIs and authentication middleware are developed based on framework `droplet`, but some API directly use the interface of framework `gin` thus bypassing the authentication.

- [https://github.com/wuppp/cve-2021-45232-exp](https://github.com/wuppp/cve-2021-45232-exp) :  ![starts](https://img.shields.io/github/stars/wuppp/cve-2021-45232-exp.svg) ![forks](https://img.shields.io/github/forks/wuppp/cve-2021-45232-exp.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack where an attacker with permission to modify the logging configuration file can construct a malicious configuration using a JDBC Appender with a data source referencing a JNDI URI which can execute remote code. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/name/log4j](https://github.com/name/log4j) :  ![starts](https://img.shields.io/github/stars/name/log4j.svg) ![forks](https://img.shields.io/github/forks/name/log4j.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)
- [https://github.com/NS-Sp4ce/Vm4J](https://github.com/NS-Sp4ce/Vm4J) :  ![starts](https://img.shields.io/github/stars/NS-Sp4ce/Vm4J.svg) ![forks](https://img.shields.io/github/forks/NS-Sp4ce/Vm4J.svg)
- [https://github.com/puzzlepeaches/Log4jUnifi](https://github.com/puzzlepeaches/Log4jUnifi) :  ![starts](https://img.shields.io/github/stars/puzzlepeaches/Log4jUnifi.svg) ![forks](https://img.shields.io/github/forks/puzzlepeaches/Log4jUnifi.svg)
- [https://github.com/kubearmor/log4j-CVE-2021-44228](https://github.com/kubearmor/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/kubearmor/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kubearmor/log4j-CVE-2021-44228.svg)


## CVE-2021-40859
 Backdoors were discovered in Auerswald COMpact 5500R 7.8A and 8.0B devices, that allow attackers with access to the web based management application full administrative access to the device.

- [https://github.com/pussycat0x/CVE-2021-40859](https://github.com/pussycat0x/CVE-2021-40859) :  ![starts](https://img.shields.io/github/stars/pussycat0x/CVE-2021-40859.svg) ![forks](https://img.shields.io/github/forks/pussycat0x/CVE-2021-40859.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/DIVD-NL/GitLab-cve-2021-22205-nse](https://github.com/DIVD-NL/GitLab-cve-2021-22205-nse) :  ![starts](https://img.shields.io/github/stars/DIVD-NL/GitLab-cve-2021-22205-nse.svg) ![forks](https://img.shields.io/github/forks/DIVD-NL/GitLab-cve-2021-22205-nse.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/trganda/CVE-2021-22204](https://github.com/trganda/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/trganda/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/trganda/CVE-2021-22204.svg)


## CVE-2020-17087
 Windows Kernel Local Elevation of Privilege Vulnerability

- [https://github.com/Rinkal26/CVE-2020-17087](https://github.com/Rinkal26/CVE-2020-17087) :  ![starts](https://img.shields.io/github/stars/Rinkal26/CVE-2020-17087.svg) ![forks](https://img.shields.io/github/forks/Rinkal26/CVE-2020-17087.svg)


## CVE-2020-0674
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.

- [https://github.com/forrest-orr/Exploits](https://github.com/forrest-orr/Exploits) :  ![starts](https://img.shields.io/github/stars/forrest-orr/Exploits.svg) ![forks](https://img.shields.io/github/forks/forrest-orr/Exploits.svg)


## CVE-2019-17026
 Incorrect alias information in IonMonkey JIT compiler for setting array elements could lead to a type confusion. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR &lt; 68.4.1, Thunderbird &lt; 68.4.1, and Firefox &lt; 72.0.1.

- [https://github.com/forrest-orr/Exploits](https://github.com/forrest-orr/Exploits) :  ![starts](https://img.shields.io/github/stars/forrest-orr/Exploits.svg) ![forks](https://img.shields.io/github/forks/forrest-orr/Exploits.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/Asbatel/CVE-2019-5736_POC](https://github.com/Asbatel/CVE-2019-5736_POC) :  ![starts](https://img.shields.io/github/stars/Asbatel/CVE-2019-5736_POC.svg) ![forks](https://img.shields.io/github/forks/Asbatel/CVE-2019-5736_POC.svg)


## CVE-2019-1064
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'.

- [https://github.com/0x00-0x00/CVE-2019-1064](https://github.com/0x00-0x00/CVE-2019-1064) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2019-1064.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2019-1064.svg)


## CVE-2016-4437
 Apache Shiro before 1.2.5, when a cipher key has not been configured for the &quot;remember me&quot; feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

- [https://github.com/4nth0ny1130/shisoserial](https://github.com/4nth0ny1130/shisoserial) :  ![starts](https://img.shields.io/github/stars/4nth0ny1130/shisoserial.svg) ![forks](https://img.shields.io/github/forks/4nth0ny1130/shisoserial.svg)

