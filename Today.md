# Update 2022-07-25
## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/keven1z/CVE-2022-26134](https://github.com/keven1z/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/keven1z/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/keven1z/CVE-2022-26134.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Jeromeyoung/log4j2burpscanner](https://github.com/Jeromeyoung/log4j2burpscanner) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/log4j2burpscanner.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/log4j2burpscanner.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/T3slaa/pwnkit-pwn](https://github.com/T3slaa/pwnkit-pwn) :  ![starts](https://img.shields.io/github/stars/T3slaa/pwnkit-pwn.svg) ![forks](https://img.shields.io/github/forks/T3slaa/pwnkit-pwn.svg)

