# Update 2022-09-26
## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/yqcs/CSPOC](https://github.com/yqcs/CSPOC) :  ![starts](https://img.shields.io/github/stars/yqcs/CSPOC.svg) ![forks](https://img.shields.io/github/forks/yqcs/CSPOC.svg)
- [https://github.com/purple-WL/Cobaltstrike-RCE-CVE-2022-39197](https://github.com/purple-WL/Cobaltstrike-RCE-CVE-2022-39197) :  ![starts](https://img.shields.io/github/stars/purple-WL/Cobaltstrike-RCE-CVE-2022-39197.svg) ![forks](https://img.shields.io/github/forks/purple-WL/Cobaltstrike-RCE-CVE-2022-39197.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/scoobyd00bi/CVE-2022-26809-RCE](https://github.com/scoobyd00bi/CVE-2022-26809-RCE) :  ![starts](https://img.shields.io/github/stars/scoobyd00bi/CVE-2022-26809-RCE.svg) ![forks](https://img.shields.io/github/forks/scoobyd00bi/CVE-2022-26809-RCE.svg)


## CVE-2022-2274
 The OpenSSL 3.0.4 release introduced a serious bug in the RSA implementation for X86_64 CPUs supporting the AVX512IFMA instructions. This issue makes the RSA implementation with 2048 bit private keys incorrect on such machines and memory corruption will happen during the computation. As a consequence of the memory corruption an attacker may be able to trigger a remote code execution on the machine performing the computation. SSL/TLS servers or other servers using 2048 bit RSA private keys running on machines supporting AVX512IFMA instructions of the X86_64 architecture are affected by this issue.

- [https://github.com/Malwareman007/CVE-2022-2274](https://github.com/Malwareman007/CVE-2022-2274) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-2274.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-2274.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/name/log4j](https://github.com/name/log4j) :  ![starts](https://img.shields.io/github/stars/name/log4j.svg) ![forks](https://img.shields.io/github/forks/name/log4j.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/flux10n/CVE-2021-4034](https://github.com/flux10n/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/flux10n/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/flux10n/CVE-2021-4034.svg)


## CVE-2017-8486
 Microsoft Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an information disclosure due to the way it handles objects in memory, aka &quot;Win32k Information Disclosure Vulnerability&quot;.

- [https://github.com/doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/doudouhala/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/doudouhala/CVE-2017-8464-exp-generator.svg)


## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;

- [https://github.com/doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/doudouhala/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/doudouhala/CVE-2017-8464-exp-generator.svg)


## CVE-2016-2098
 Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.

- [https://github.com/Shakun8/CVE-2016-2098](https://github.com/Shakun8/CVE-2016-2098) :  ![starts](https://img.shields.io/github/stars/Shakun8/CVE-2016-2098.svg) ![forks](https://img.shields.io/github/forks/Shakun8/CVE-2016-2098.svg)

