# Update 2022-10-23
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/humbss/CVE-2022-42889](https://github.com/humbss/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/humbss/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/humbss/CVE-2022-42889.svg)
- [https://github.com/s3l33/CVE-2022-42889](https://github.com/s3l33/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/s3l33/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/s3l33/CVE-2022-42889.svg)
- [https://github.com/stavrosgns/Text4ShellPayloads](https://github.com/stavrosgns/Text4ShellPayloads) :  ![starts](https://img.shields.io/github/stars/stavrosgns/Text4ShellPayloads.svg) ![forks](https://img.shields.io/github/forks/stavrosgns/Text4ShellPayloads.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/Bendalledj/CVE-2022-40684](https://github.com/Bendalledj/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/Bendalledj/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/Bendalledj/CVE-2022-40684.svg)
- [https://github.com/Grapphy/fortipwn](https://github.com/Grapphy/fortipwn) :  ![starts](https://img.shields.io/github/stars/Grapphy/fortipwn.svg) ![forks](https://img.shields.io/github/forks/Grapphy/fortipwn.svg)


## CVE-2022-2402
 The vulnerability in the driver dlpfde.sys enables a user logged into the system to perform system calls leading to kernel stack overflow, resulting in a system crash, for instance, a BSOD.

- [https://github.com/SecurityAndStuff/CVE-2022-2402](https://github.com/SecurityAndStuff/CVE-2022-2402) :  ![starts](https://img.shields.io/github/stars/SecurityAndStuff/CVE-2022-2402.svg) ![forks](https://img.shields.io/github/forks/SecurityAndStuff/CVE-2022-2402.svg)


## CVE-2022-1000
 Path Traversal in GitHub repository prasathmani/tinyfilemanager prior to 2.4.7.

- [https://github.com/yonggui-li/CVE-2022-1000_poc](https://github.com/yonggui-li/CVE-2022-1000_poc) :  ![starts](https://img.shields.io/github/stars/yonggui-li/CVE-2022-1000_poc.svg) ![forks](https://img.shields.io/github/forks/yonggui-li/CVE-2022-1000_poc.svg)


## CVE-2021-21220
 Insufficient validation of untrusted input in V8 in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/security-dbg/CVE-2021-21220](https://github.com/security-dbg/CVE-2021-21220) :  ![starts](https://img.shields.io/github/stars/security-dbg/CVE-2021-21220.svg) ![forks](https://img.shields.io/github/forks/security-dbg/CVE-2021-21220.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/k4u5h41/CVE-2021-4034](https://github.com/k4u5h41/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2021-4034.svg)


## CVE-2018-11311
 A hardcoded FTP username of myscada and password of Vikuk63 in 'myscadagate.exe' in mySCADA myPRO 7 allows remote attackers to access the FTP server on port 2121, and upload files or list directories, by entering these credentials.

- [https://github.com/EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password](https://github.com/EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password) :  ![starts](https://img.shields.io/github/stars/EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password.svg) ![forks](https://img.shields.io/github/forks/EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/trhacknon/CVE-2018-7600](https://github.com/trhacknon/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2018-7600.svg)

