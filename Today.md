# Update 2022-02-01
## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/roxas-tan/CVE-2021-44228](https://github.com/roxas-tan/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/roxas-tan/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/roxas-tan/CVE-2021-44228.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/OXDBXKXO/go-PwnKit](https://github.com/OXDBXKXO/go-PwnKit) :  ![starts](https://img.shields.io/github/stars/OXDBXKXO/go-PwnKit.svg) ![forks](https://img.shields.io/github/forks/OXDBXKXO/go-PwnKit.svg)
- [https://github.com/EstamelGG/CVE-2021-4034-NoGCC](https://github.com/EstamelGG/CVE-2021-4034-NoGCC) :  ![starts](https://img.shields.io/github/stars/EstamelGG/CVE-2021-4034-NoGCC.svg) ![forks](https://img.shields.io/github/forks/EstamelGG/CVE-2021-4034-NoGCC.svg)
- [https://github.com/milot/dissecting-pkexec-cve-2021-4034](https://github.com/milot/dissecting-pkexec-cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/milot/dissecting-pkexec-cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/milot/dissecting-pkexec-cve-2021-4034.svg)
- [https://github.com/glowbase/PwnKit-CVE-2021-4034](https://github.com/glowbase/PwnKit-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/glowbase/PwnKit-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/glowbase/PwnKit-CVE-2021-4034.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/litt1eb0yy/CVE-2021-3156](https://github.com/litt1eb0yy/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/litt1eb0yy/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/litt1eb0yy/CVE-2021-3156.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/AndrewTrube/CVE-2021-1675](https://github.com/AndrewTrube/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/AndrewTrube/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/AndrewTrube/CVE-2021-1675.svg)


## CVE-2019-5420
 A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.

- [https://github.com/CyberSecurityUP/CVE-2019-5420-POC](https://github.com/CyberSecurityUP/CVE-2019-5420-POC) :  ![starts](https://img.shields.io/github/stars/CyberSecurityUP/CVE-2019-5420-POC.svg) ![forks](https://img.shields.io/github/forks/CyberSecurityUP/CVE-2019-5420-POC.svg)

