# Update 2022-08-21
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/k3rwin/spring-core-rce](https://github.com/k3rwin/spring-core-rce) :  ![starts](https://img.shields.io/github/stars/k3rwin/spring-core-rce.svg) ![forks](https://img.shields.io/github/forks/k3rwin/spring-core-rce.svg)
- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)
- [https://github.com/zer0yu/CVE-2022-22965](https://github.com/zer0yu/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/zer0yu/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/zer0yu/CVE-2022-22965.svg)
- [https://github.com/iyamrotrix/CVE-2022-22965](https://github.com/iyamrotrix/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iyamrotrix/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iyamrotrix/CVE-2022-22965.svg)
- [https://github.com/D1mang/Spring4Shell-CVE-2022-22965](https://github.com/D1mang/Spring4Shell-CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/D1mang/Spring4Shell-CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/D1mang/Spring4Shell-CVE-2022-22965.svg)
- [https://github.com/irgoncalves/f5-waf-enforce-sig-Spring4Shell](https://github.com/irgoncalves/f5-waf-enforce-sig-Spring4Shell) :  ![starts](https://img.shields.io/github/stars/irgoncalves/f5-waf-enforce-sig-Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/irgoncalves/f5-waf-enforce-sig-Spring4Shell.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/decrypthing/CVE_2022_0847](https://github.com/decrypthing/CVE_2022_0847) :  ![starts](https://img.shields.io/github/stars/decrypthing/CVE_2022_0847.svg) ![forks](https://img.shields.io/github/forks/decrypthing/CVE_2022_0847.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/julian911015/Log4j-Scanner-Exploit](https://github.com/julian911015/Log4j-Scanner-Exploit) :  ![starts](https://img.shields.io/github/stars/julian911015/Log4j-Scanner-Exploit.svg) ![forks](https://img.shields.io/github/forks/julian911015/Log4j-Scanner-Exploit.svg)


## CVE-2021-35296
 An issue in the administrator authentication panel of PTCL HG150-Ub v3.0 allows attackers to bypass authentication via modification of the cookie value and Response Path.

- [https://github.com/afaq1337/CVE-2021-35296](https://github.com/afaq1337/CVE-2021-35296) :  ![starts](https://img.shields.io/github/stars/afaq1337/CVE-2021-35296.svg) ![forks](https://img.shields.io/github/forks/afaq1337/CVE-2021-35296.svg)


## CVE-2019-0227
 A Server Side Request Forgery (SSRF) vulnerability affected the Apache Axis 1.4 distribution that was last released in 2006. Security and bug commits commits continue in the projects Axis 1.x Subversion repository, legacy users are encouraged to build from source. The successor to Axis 1.x is Axis2, the latest version is 1.7.9 and is not vulnerable to this issue.

- [https://github.com/ianxtianxt/cve-2019-0227](https://github.com/ianxtianxt/cve-2019-0227) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/cve-2019-0227.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/cve-2019-0227.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/technicaldada/hack-winrar](https://github.com/technicaldada/hack-winrar) :  ![starts](https://img.shields.io/github/stars/technicaldada/hack-winrar.svg) ![forks](https://img.shields.io/github/forks/technicaldada/hack-winrar.svg)

