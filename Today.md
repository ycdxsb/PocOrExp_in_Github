# Update 2022-01-14
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/taise-hub/log4j-poc](https://github.com/taise-hub/log4j-poc) :  ![starts](https://img.shields.io/github/stars/taise-hub/log4j-poc.svg) ![forks](https://img.shields.io/github/forks/taise-hub/log4j-poc.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/kubearmor/log4j-CVE-2021-44228](https://github.com/kubearmor/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/kubearmor/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kubearmor/log4j-CVE-2021-44228.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/norrig/CVE-2021-41773-exploiter](https://github.com/norrig/CVE-2021-41773-exploiter) :  ![starts](https://img.shields.io/github/stars/norrig/CVE-2021-41773-exploiter.svg) ![forks](https://img.shields.io/github/forks/norrig/CVE-2021-41773-exploiter.svg)


## CVE-2021-32099
 A SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session via the /include/chart_generator.php session_id parameter, leading to a login bypass.

- [https://github.com/ibnuuby/CVE-2021-32099](https://github.com/ibnuuby/CVE-2021-32099) :  ![starts](https://img.shields.io/github/stars/ibnuuby/CVE-2021-32099.svg) ![forks](https://img.shields.io/github/forks/ibnuuby/CVE-2021-32099.svg)


## CVE-2021-22569
 An issue in protobuf-java allowed the interleaving of com.google.protobuf.UnknownFieldSet fields in such a way that would be processed out of order. A small malicious payload can occupy the parser for several minutes by creating large numbers of short-lived objects that cause frequent, repeated pauses. We recommend upgrading libraries beyond the vulnerable versions.

- [https://github.com/Mario-Kart-Felix/A-potential-Denial-of-Service-issue-in-protobuf-java](https://github.com/Mario-Kart-Felix/A-potential-Denial-of-Service-issue-in-protobuf-java) :  ![starts](https://img.shields.io/github/stars/Mario-Kart-Felix/A-potential-Denial-of-Service-issue-in-protobuf-java.svg) ![forks](https://img.shields.io/github/forks/Mario-Kart-Felix/A-potential-Denial-of-Service-issue-in-protobuf-java.svg)


## CVE-2020-15261
 On Windows the Veyon Service before version 4.4.2 contains an unquoted service path vulnerability, allowing locally authenticated users with administrative privileges to run malicious executables with LocalSystem privileges. Since Veyon users (both students and teachers) usually don't have administrative privileges, this vulnerability is only dangerous in anyway unsafe setups. The problem has been fixed in version 4.4.2. As a workaround, the exploitation of the vulnerability can be prevented by revoking administrative privileges from all potentially untrustworthy users.

- [https://github.com/yaoyao-cool/CVE-2020-15261](https://github.com/yaoyao-cool/CVE-2020-15261) :  ![starts](https://img.shields.io/github/stars/yaoyao-cool/CVE-2020-15261.svg) ![forks](https://img.shields.io/github/forks/yaoyao-cool/CVE-2020-15261.svg)

