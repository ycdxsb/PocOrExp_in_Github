# Update 2021-12-26
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/cisagov/log4j-scanner](https://github.com/cisagov/log4j-scanner) :  ![starts](https://img.shields.io/github/stars/cisagov/log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/cisagov/log4j-scanner.svg)
- [https://github.com/X1pe0/Log4J-Scan-Win](https://github.com/X1pe0/Log4J-Scan-Win) :  ![starts](https://img.shields.io/github/stars/X1pe0/Log4J-Scan-Win.svg) ![forks](https://img.shields.io/github/forks/X1pe0/Log4J-Scan-Win.svg)
- [https://github.com/CaptanMoss/Log4Shell-Sandbox-Signature](https://github.com/CaptanMoss/Log4Shell-Sandbox-Signature) :  ![starts](https://img.shields.io/github/stars/CaptanMoss/Log4Shell-Sandbox-Signature.svg) ![forks](https://img.shields.io/github/forks/CaptanMoss/Log4Shell-Sandbox-Signature.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/cisagov/log4j-scanner](https://github.com/cisagov/log4j-scanner) :  ![starts](https://img.shields.io/github/stars/cisagov/log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/cisagov/log4j-scanner.svg)
- [https://github.com/hackinghippo/log4shell_ioc_ips](https://github.com/hackinghippo/log4shell_ioc_ips) :  ![starts](https://img.shields.io/github/stars/hackinghippo/log4shell_ioc_ips.svg) ![forks](https://img.shields.io/github/forks/hackinghippo/log4shell_ioc_ips.svg)
- [https://github.com/LiveOverflow/log4shell](https://github.com/LiveOverflow/log4shell) :  ![starts](https://img.shields.io/github/stars/LiveOverflow/log4shell.svg) ![forks](https://img.shields.io/github/forks/LiveOverflow/log4shell.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/thomsdev/CVE-2021-41773](https://github.com/thomsdev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-41773.svg)


## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

- [https://github.com/thomsdev/CVE-2021-40870](https://github.com/thomsdev/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-40870.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/thomsdev/CVE-2021-38314](https://github.com/thomsdev/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-38314.svg)


## CVE-2021-30860
 An integer overflow was addressed with improved input validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. Processing a maliciously crafted PDF may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/jeffssh/CVE-2021-30860](https://github.com/jeffssh/CVE-2021-30860) :  ![starts](https://img.shields.io/github/stars/jeffssh/CVE-2021-30860.svg) ![forks](https://img.shields.io/github/forks/jeffssh/CVE-2021-30860.svg)


## CVE-2021-30573
 Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/thomsdev/CVE-2021-30573](https://github.com/thomsdev/CVE-2021-30573) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-30573.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-30573.svg)


## CVE-2021-27651
 In versions 8.2.1 through 8.5.2 of Pega Infinity, the password reset functionality for local accounts can be used to bypass local authentication checks.

- [https://github.com/thomsdev/CVE-2021-27651](https://github.com/thomsdev/CVE-2021-27651) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-27651.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-27651.svg)


## CVE-2021-26857
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/Immersive-Labs-Sec/ProxyLogon](https://github.com/Immersive-Labs-Sec/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/ProxyLogon.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/thomsdev/CVE-2021-26084](https://github.com/thomsdev/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-26084.svg)


## CVE-2021-22893
 Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway. This vulnerability has been exploited in the wild.

- [https://github.com/thomsdev/CVE-2021-22893](https://github.com/thomsdev/CVE-2021-22893) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-22893.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-22893.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/thomsdev/CVE-2021-21972](https://github.com/thomsdev/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-21972.svg)


## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

- [https://github.com/thomsdev/CVE-2021-20837](https://github.com/thomsdev/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2021-20837.svg)


## CVE-2020-35191
 The official drupal docker images before 8.5.10-fpm-alpine (Alpine specific) contain a blank password for a root user. System using the drupal docker container deployed by affected versions of the docker image may allow a remote attacker to achieve root access with a blank password.

- [https://github.com/megadimenex/MegaHiDocker](https://github.com/megadimenex/MegaHiDocker) :  ![starts](https://img.shields.io/github/stars/megadimenex/MegaHiDocker.svg) ![forks](https://img.shields.io/github/forks/megadimenex/MegaHiDocker.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/thomsdev/CVE-2020-0796](https://github.com/thomsdev/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2020-0796.svg)


## CVE-2019-15858
 admin/includes/class.import.snippet.php in the &quot;Woody ad snippets&quot; plugin before 2.2.5 for WordPress allows unauthenticated options import, as demonstrated by storing an XSS payload for remote code execution.

- [https://github.com/thomsdev/CVE-2019-15858](https://github.com/thomsdev/CVE-2019-15858) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2019-15858.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2019-15858.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/BernieLane/CMS-Made-Simple-SQLi](https://github.com/BernieLane/CMS-Made-Simple-SQLi) :  ![starts](https://img.shields.io/github/stars/BernieLane/CMS-Made-Simple-SQLi.svg) ![forks](https://img.shields.io/github/forks/BernieLane/CMS-Made-Simple-SQLi.svg)


## CVE-2018-15961
 Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/thomsdev/CVE-2018-15961](https://github.com/thomsdev/CVE-2018-15961) :  ![starts](https://img.shields.io/github/stars/thomsdev/CVE-2018-15961.svg) ![forks](https://img.shields.io/github/forks/thomsdev/CVE-2018-15961.svg)


## CVE-2003-0282
 Directory traversal vulnerability in UnZip 5.50 allows attackers to overwrite arbitrary files via invalid characters between two . (dot) characters, which are filtered and result in a &quot;..&quot; sequence.

- [https://github.com/runtimed/cve-2003-0282](https://github.com/runtimed/cve-2003-0282) :  ![starts](https://img.shields.io/github/stars/runtimed/cve-2003-0282.svg) ![forks](https://img.shields.io/github/forks/runtimed/cve-2003-0282.svg)

