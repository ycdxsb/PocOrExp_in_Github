# Update 2022-01-12
## CVE-2022-21660
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/UzJu/Gin-Vue-admin-poc-CVE-2022-21660](https://github.com/UzJu/Gin-Vue-admin-poc-CVE-2022-21660) :  ![starts](https://img.shields.io/github/stars/UzJu/Gin-Vue-admin-poc-CVE-2022-21660.svg) ![forks](https://img.shields.io/github/forks/UzJu/Gin-Vue-admin-poc-CVE-2022-21660.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)


## CVE-2021-40490
 A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in the Linux kernel through 5.13.13.

- [https://github.com/Nivaskumark/CVE-2021-40490_kernel_v4.19.72](https://github.com/Nivaskumark/CVE-2021-40490_kernel_v4.19.72) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2021-40490_kernel_v4.19.72.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2021-40490_kernel_v4.19.72.svg)


## CVE-2021-39623
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/marcinguy/CVE-2021-39623](https://github.com/marcinguy/CVE-2021-39623) :  ![starts](https://img.shields.io/github/stars/marcinguy/CVE-2021-39623.svg) ![forks](https://img.shields.io/github/forks/marcinguy/CVE-2021-39623.svg)


## CVE-2021-20038
 A Stack-based buffer overflow vulnerability in SMA100 Apache httpd server's mod_cgi module environment variables allows a remote unauthenticated attacker to potentially execute code as a 'nobody' user in the appliance. This vulnerability affected SMA 200, 210, 400, 410 and 500v appliances firmware 10.2.0.8-37sv, 10.2.1.1-19sv, 10.2.1.2-24sv and earlier versions.

- [https://github.com/jbaines-r7/badblood](https://github.com/jbaines-r7/badblood) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/badblood.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/badblood.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)
- [https://github.com/open-AIMS/log4j](https://github.com/open-AIMS/log4j) :  ![starts](https://img.shields.io/github/stars/open-AIMS/log4j.svg) ![forks](https://img.shields.io/github/forks/open-AIMS/log4j.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/Veids/CVE-2020-3452_auto](https://github.com/Veids/CVE-2020-3452_auto) :  ![starts](https://img.shields.io/github/stars/Veids/CVE-2020-3452_auto.svg) ![forks](https://img.shields.io/github/forks/Veids/CVE-2020-3452_auto.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2012-5519
 CUPS 1.4.4, when running in certain Linux distributions such as Debian GNU/Linux, stores the web interface administrator key in /var/run/cups/certs/0 using certain permissions, which allows local users in the lpadmin group to read or write arbitrary files as root by leveraging the web interface.

- [https://github.com/0zvxr/CVE-2012-5519](https://github.com/0zvxr/CVE-2012-5519) :  ![starts](https://img.shields.io/github/stars/0zvxr/CVE-2012-5519.svg) ![forks](https://img.shields.io/github/forks/0zvxr/CVE-2012-5519.svg)

