# Update 2022-01-05
## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg)
- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg)
- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg)
- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/mergebase/log4j-samples](https://github.com/mergebase/log4j-samples) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-samples.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-samples.svg)
- [https://github.com/rakutentech/jndi-ldap-test-server](https://github.com/rakutentech/jndi-ldap-test-server) :  ![starts](https://img.shields.io/github/stars/rakutentech/jndi-ldap-test-server.svg) ![forks](https://img.shields.io/github/forks/rakutentech/jndi-ldap-test-server.svg)


## CVE-2021-43858
 MinIO is a Kubernetes native application for cloud storage. Prior to version `RELEASE.2021-12-27T07-23-18Z`, a malicious client can hand-craft an HTTP API call that allows for updating policy for a user and gaining higher privileges. The patch in version `RELEASE.2021-12-27T07-23-18Z` changes the accepted request body type and removes the ability to apply policy changes through this API. There is a workaround for this vulnerability: Changing passwords can be disabled by adding an explicit `Deny` rule to disable the API for users.

- [https://github.com/khuntor/cve-2021-43858](https://github.com/khuntor/cve-2021-43858) :  ![starts](https://img.shields.io/github/stars/khuntor/cve-2021-43858.svg) ![forks](https://img.shields.io/github/forks/khuntor/cve-2021-43858.svg)


## CVE-2021-43857
 Gerapy is a distributed crawler management framework. Gerapy prior to version 0.9.8 is vulnerable to remote code execution, and this issue is patched in version 0.9.8.

- [https://github.com/LongWayHomie/CVE-2021-43857](https://github.com/LongWayHomie/CVE-2021-43857) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2021-43857.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2021-43857.svg)


## CVE-2021-42550
 In logback version 1.2.7 and prior versions, an attacker with the required privileges to edit configurations files could craft a malicious configuration allowing to execute arbitrary code loaded from LDAP servers.

- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2017-0147
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to obtain sensitive information from process memory via a crafted packets, aka &quot;Windows SMB Information Disclosure Vulnerability.&quot;

- [https://github.com/Malware-S/Exploit-Win32.CVE-2017-0147.A](https://github.com/Malware-S/Exploit-Win32.CVE-2017-0147.A) :  ![starts](https://img.shields.io/github/stars/Malware-S/Exploit-Win32.CVE-2017-0147.A.svg) ![forks](https://img.shields.io/github/forks/Malware-S/Exploit-Win32.CVE-2017-0147.A.svg)


## CVE-2014-7205
 Eval injection vulnerability in the internals.batch function in lib/batch.js in the bassmaster plugin before 1.5.2 for the hapi server framework for Node.js allows remote attackers to execute arbitrary Javascript code via unspecified vectors.

- [https://github.com/AndrewTrube/CVE-2014-7205](https://github.com/AndrewTrube/CVE-2014-7205) :  ![starts](https://img.shields.io/github/stars/AndrewTrube/CVE-2014-7205.svg) ![forks](https://img.shields.io/github/forks/AndrewTrube/CVE-2014-7205.svg)


## CVE-2012-2593
 Cross-site scripting (XSS) vulnerability in the administrative interface in Atmail Webmail Server 6.4 allows remote attackers to inject arbitrary web script or HTML via the Date field of an email.

- [https://github.com/AndrewTrube/CVE-2012-2593](https://github.com/AndrewTrube/CVE-2012-2593) :  ![starts](https://img.shields.io/github/stars/AndrewTrube/CVE-2012-2593.svg) ![forks](https://img.shields.io/github/forks/AndrewTrube/CVE-2012-2593.svg)


## CVE-2012-0158
 The (1) ListView, (2) ListView2, (3) TreeView, and (4) TreeView2 ActiveX controls in MSCOMCTL.OCX in the Common Controls in Microsoft Office 2003 SP3, 2007 SP2 and SP3, and 2010 Gold and SP1; Office 2003 Web Components SP3; SQL Server 2000 SP4, 2005 SP4, and 2008 SP2, SP3, and R2; BizTalk Server 2002 SP1; Commerce Server 2002 SP4, 2007 SP2, and 2009 Gold and R2; Visual FoxPro 8.0 SP1 and 9.0 SP2; and Visual Basic 6.0 Runtime allow remote attackers to execute arbitrary code via a crafted (a) web site, (b) Office document, or (c) .rtf file that triggers &quot;system state&quot; corruption, as exploited in the wild in April 2012, aka &quot;MSCOMCTL.OCX RCE Vulnerability.&quot;

- [https://github.com/Malware-S/Exploit-Win32.CVE-2012-0158.F.doc](https://github.com/Malware-S/Exploit-Win32.CVE-2012-0158.F.doc) :  ![starts](https://img.shields.io/github/stars/Malware-S/Exploit-Win32.CVE-2012-0158.F.doc.svg) ![forks](https://img.shields.io/github/forks/Malware-S/Exploit-Win32.CVE-2012-0158.F.doc.svg)

