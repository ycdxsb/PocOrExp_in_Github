# Update 2022-01-01
## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/yannart/log4shell-scanner-rs](https://github.com/yannart/log4shell-scanner-rs) :  ![starts](https://img.shields.io/github/stars/yannart/log4shell-scanner-rs.svg) ![forks](https://img.shields.io/github/forks/yannart/log4shell-scanner-rs.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/zhzyker/logmap](https://github.com/zhzyker/logmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/logmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/logmap.svg)
- [https://github.com/yannart/log4shell-scanner-rs](https://github.com/yannart/log4shell-scanner-rs) :  ![starts](https://img.shields.io/github/stars/yannart/log4shell-scanner-rs.svg) ![forks](https://img.shields.io/github/forks/yannart/log4shell-scanner-rs.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/cckuailong/log4j_RCE_CVE-2021-44832](https://github.com/cckuailong/log4j_RCE_CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/cckuailong/log4j_RCE_CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/cckuailong/log4j_RCE_CVE-2021-44832.svg)
- [https://github.com/DanielRuf/CVE-2021-44832](https://github.com/DanielRuf/CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/DanielRuf/CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/DanielRuf/CVE-2021-44832.svg)
- [https://github.com/yannart/log4shell-scanner-rs](https://github.com/yannart/log4shell-scanner-rs) :  ![starts](https://img.shields.io/github/stars/yannart/log4shell-scanner-rs.svg) ![forks](https://img.shields.io/github/forks/yannart/log4shell-scanner-rs.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Puliczek/awesome-list-of-secrets-in-environment-variables](https://github.com/Puliczek/awesome-list-of-secrets-in-environment-variables) :  ![starts](https://img.shields.io/github/stars/Puliczek/awesome-list-of-secrets-in-environment-variables.svg) ![forks](https://img.shields.io/github/forks/Puliczek/awesome-list-of-secrets-in-environment-variables.svg)


## CVE-2021-30860
 An integer overflow was addressed with improved input validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. Processing a maliciously crafted PDF may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/30440r/gex](https://github.com/30440r/gex) :  ![starts](https://img.shields.io/github/stars/30440r/gex.svg) ![forks](https://img.shields.io/github/forks/30440r/gex.svg)

