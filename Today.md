# Update 2022-10-04
## CVE-2022-41208
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/L34ked/CVE-2022-41208](https://github.com/L34ked/CVE-2022-41208) :  ![starts](https://img.shields.io/github/stars/L34ked/CVE-2022-41208.svg) ![forks](https://img.shields.io/github/forks/L34ked/CVE-2022-41208.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/mr-r3b00t/NotProxyShellHunter](https://github.com/mr-r3b00t/NotProxyShellHunter) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/NotProxyShellHunter.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/NotProxyShellHunter.svg)
- [https://github.com/k1vin-beaumont/CVE-2022-41082-RCE-POC](https://github.com/k1vin-beaumont/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/k1vin-beaumont/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/k1vin-beaumont/CVE-2022-41082-RCE-POC.svg)
- [https://github.com/krc0m/CVE-2022-41082](https://github.com/krc0m/CVE-2022-41082) :  ![starts](https://img.shields.io/github/stars/krc0m/CVE-2022-41082.svg) ![forks](https://img.shields.io/github/forks/krc0m/CVE-2022-41082.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/numanturle/CVE-2022-41040](https://github.com/numanturle/CVE-2022-41040) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2022-41040.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2022-41040.svg)
- [https://github.com/k1vin-beaumont/CVE-2022-41040-RCE-POC](https://github.com/k1vin-beaumont/CVE-2022-41040-RCE-POC) :  ![starts](https://img.shields.io/github/stars/k1vin-beaumont/CVE-2022-41040-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/k1vin-beaumont/CVE-2022-41040-RCE-POC.svg)


## CVE-2022-40140
 An origin validation error vulnerability in Trend Micro Apex One and Apex One as a Service could allow a local attacker to cause a denial-of-service on affected installations. Please note: an attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability.

- [https://github.com/mr-r3b00t/NotProxyShellHunter](https://github.com/mr-r3b00t/NotProxyShellHunter) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/NotProxyShellHunter.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/NotProxyShellHunter.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/rakutentech/jndi-ldap-test-server](https://github.com/rakutentech/jndi-ldap-test-server) :  ![starts](https://img.shields.io/github/stars/rakutentech/jndi-ldap-test-server.svg) ![forks](https://img.shields.io/github/forks/rakutentech/jndi-ldap-test-server.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/darkerego/pwnkit](https://github.com/darkerego/pwnkit) :  ![starts](https://img.shields.io/github/stars/darkerego/pwnkit.svg) ![forks](https://img.shields.io/github/forks/darkerego/pwnkit.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/Senz4wa/CVE-2021-3493](https://github.com/Senz4wa/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Senz4wa/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Senz4wa/CVE-2021-3493.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/Shakun8/CVE-2017-9805](https://github.com/Shakun8/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Shakun8/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Shakun8/CVE-2017-9805.svg)

