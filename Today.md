# Update 2022-01-19
## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/xiska62314/CVE-2022-21907](https://github.com/xiska62314/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/xiska62314/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/xiska62314/CVE-2022-21907.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection](https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg)


## CVE-2022-0236
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/xiska62314/CVE-2022-0236](https://github.com/xiska62314/CVE-2022-0236) :  ![starts](https://img.shields.io/github/stars/xiska62314/CVE-2022-0236.svg) ![forks](https://img.shields.io/github/forks/xiska62314/CVE-2022-0236.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2021-43297
 A deserialization vulnerability existed in dubbo hessian-lite 3.2.11 and its earlier versions, which could lead to malicious code execution. Most Dubbo users use Hessian2 as the default serialization/deserialization protocol, during Hessian catch unexpected exceptions, Hessian will log out some imformation for users, which may cause remote command execution. This issue affects Apache Dubbo Apache Dubbo 2.6.x versions prior to 2.6.12; Apache Dubbo 2.7.x versions prior to 2.7.15; Apache Dubbo 3.0.x versions prior to 3.0.5.

- [https://github.com/longofo/Apache-Dubbo-Hessian2-CVE-2021-43297](https://github.com/longofo/Apache-Dubbo-Hessian2-CVE-2021-43297) :  ![starts](https://img.shields.io/github/stars/longofo/Apache-Dubbo-Hessian2-CVE-2021-43297.svg) ![forks](https://img.shields.io/github/forks/longofo/Apache-Dubbo-Hessian2-CVE-2021-43297.svg)
- [https://github.com/bitterzzZZ/CVE-2021-43297-POC](https://github.com/bitterzzZZ/CVE-2021-43297-POC) :  ![starts](https://img.shields.io/github/stars/bitterzzZZ/CVE-2021-43297-POC.svg) ![forks](https://img.shields.io/github/forks/bitterzzZZ/CVE-2021-43297-POC.svg)


## CVE-2021-42550
 In logback version 1.2.7 and prior versions, an attacker with the required privileges to edit configurations files could craft a malicious configuration allowing to execute arbitrary code loaded from LDAP servers.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- [https://github.com/jrgdiaz/ProxyShell-CVE-2021-34473](https://github.com/jrgdiaz/ProxyShell-CVE-2021-34473) :  ![starts](https://img.shields.io/github/stars/jrgdiaz/ProxyShell-CVE-2021-34473.svg) ![forks](https://img.shields.io/github/forks/jrgdiaz/ProxyShell-CVE-2021-34473.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/hh-hunter/nacos-cve-2021-29441](https://github.com/hh-hunter/nacos-cve-2021-29441) :  ![starts](https://img.shields.io/github/stars/hh-hunter/nacos-cve-2021-29441.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/nacos-cve-2021-29441.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2020-4422
 IBM i2 Intelligent Analyis Platform 9.2.1 could allow a remote attacker to execute arbitrary code on the system, caused by a memory corruption. By persuading a victim to open a specially crafted file, a remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 180167.

- [https://github.com/arnaudluti/PS-CVE-2020-44228](https://github.com/arnaudluti/PS-CVE-2020-44228) :  ![starts](https://img.shields.io/github/stars/arnaudluti/PS-CVE-2020-44228.svg) ![forks](https://img.shields.io/github/forks/arnaudluti/PS-CVE-2020-44228.svg)


## CVE-2019-1083
 A denial of service vulnerability exists when Microsoft Common Object Runtime Library improperly handles web requests, aka '.NET Denial of Service Vulnerability'.

- [https://github.com/stevenseeley/HowCVE-2019-1083Works](https://github.com/stevenseeley/HowCVE-2019-1083Works) :  ![starts](https://img.shields.io/github/stars/stevenseeley/HowCVE-2019-1083Works.svg) ![forks](https://img.shields.io/github/forks/stevenseeley/HowCVE-2019-1083Works.svg)


## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/0zvxr/CVE-2009-2265](https://github.com/0zvxr/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/0zvxr/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/0zvxr/CVE-2009-2265.svg)


## CVE-2003-0201
 Buffer overflow in the call_trans2open function in trans2.c for Samba 2.2.x before 2.2.8a, 2.0.10 and earlier 2.0.x versions, and Samba-TNG before 0.3.2, allows remote attackers to execute arbitrary code.

- [https://github.com/KernelPan1k/trans2open-CVE-2003-0201](https://github.com/KernelPan1k/trans2open-CVE-2003-0201) :  ![starts](https://img.shields.io/github/stars/KernelPan1k/trans2open-CVE-2003-0201.svg) ![forks](https://img.shields.io/github/forks/KernelPan1k/trans2open-CVE-2003-0201.svg)

