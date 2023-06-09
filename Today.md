# Update 2023-06-09
## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/hheeyywweellccoommee/CVE-2023-34362-nhjxn](https://github.com/hheeyywweellccoommee/CVE-2023-34362-nhjxn) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-34362-nhjxn.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-34362-nhjxn.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/hheeyywweellccoommee/CVE-2023-33246-rnkku](https://github.com/hheeyywweellccoommee/CVE-2023-33246-rnkku) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-33246-rnkku.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-33246-rnkku.svg)


## CVE-2023-29325
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/a-bazi/test-CVE-2023-29325](https://github.com/a-bazi/test-CVE-2023-29325) :  ![starts](https://img.shields.io/github/stars/a-bazi/test-CVE-2023-29325.svg) ![forks](https://img.shields.io/github/forks/a-bazi/test-CVE-2023-29325.svg)


## CVE-2023-23488
 The Paid Memberships Pro WordPress Plugin, version &lt; 2.9.8, is affected by an unauthenticated SQL injection vulnerability in the 'code' parameter of the '/pmpro/v1/order' REST route.

- [https://github.com/cybfar/CVE-2023-23488-pmpro-2.8](https://github.com/cybfar/CVE-2023-23488-pmpro-2.8) :  ![starts](https://img.shields.io/github/stars/cybfar/CVE-2023-23488-pmpro-2.8.svg) ![forks](https://img.shields.io/github/forks/cybfar/CVE-2023-23488-pmpro-2.8.svg)


## CVE-2023-21971
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that are affected are 8.0.32 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Connectors as well as unauthorized update, insert or delete access to some of MySQL Connectors accessible data and unauthorized read access to a subset of MySQL Connectors accessible data. CVSS 3.1 Base Score 5.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:H).

- [https://github.com/Avento/CVE-2023-21971_Analysis](https://github.com/Avento/CVE-2023-21971_Analysis) :  ![starts](https://img.shields.io/github/stars/Avento/CVE-2023-21971_Analysis.svg) ![forks](https://img.shields.io/github/forks/Avento/CVE-2023-21971_Analysis.svg)


## CVE-2022-39227
 python-jwt is a module for generating and verifying JSON Web Tokens. Versions prior to 3.3.4 are subject to Authentication Bypass by Spoofing, resulting in identity spoofing, session hijacking or authentication bypass. An attacker who obtains a JWT can arbitrarily forge its contents without knowing the secret key. Depending on the application, this may for example enable the attacker to spoof other user's identities, hijack their sessions, or bypass authentication. Users should upgrade to version 3.3.4. There are no known workarounds.

- [https://github.com/user0x1337/CVE-2022-39227](https://github.com/user0x1337/CVE-2022-39227) :  ![starts](https://img.shields.io/github/stars/user0x1337/CVE-2022-39227.svg) ![forks](https://img.shields.io/github/forks/user0x1337/CVE-2022-39227.svg)


## CVE-2022-25765
 The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.

- [https://github.com/GrandNabil/testpdfkit](https://github.com/GrandNabil/testpdfkit) :  ![starts](https://img.shields.io/github/stars/GrandNabil/testpdfkit.svg) ![forks](https://img.shields.io/github/forks/GrandNabil/testpdfkit.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/dbgee/Spring4Shell](https://github.com/dbgee/Spring4Shell) :  ![starts](https://img.shields.io/github/stars/dbgee/Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/dbgee/Spring4Shell.svg)


## CVE-2021-44521
 When running Apache Cassandra with the following configuration: enable_user_defined_functions: true enable_scripted_user_defined_functions: true enable_user_defined_functions_threads: false it is possible for an attacker to execute arbitrary code on the host. The attacker would need to have enough permissions to create user defined functions in the cluster to be able to exploit this. Note that this configuration is documented as unsafe, and will continue to be considered unsafe after this CVE.

- [https://github.com/Yeyvo/poc-CVE-2021-44521](https://github.com/Yeyvo/poc-CVE-2021-44521) :  ![starts](https://img.shields.io/github/stars/Yeyvo/poc-CVE-2021-44521.svg) ![forks](https://img.shields.io/github/forks/Yeyvo/poc-CVE-2021-44521.svg)


## CVE-2021-43617
 Laravel Framework through 8.70.2 does not sufficiently block the upload of executable PHP content because Illuminate/Validation/Concerns/ValidatesAttributes.php lacks a check for .phar files, which are handled as application/x-httpd-php on systems based on Debian. NOTE: this CVE Record is for Laravel Framework, and is unrelated to any reports concerning incorrectly written user applications for image upload.

- [https://github.com/Sybelle03/CVE-2021-43617](https://github.com/Sybelle03/CVE-2021-43617) :  ![starts](https://img.shields.io/github/stars/Sybelle03/CVE-2021-43617.svg) ![forks](https://img.shields.io/github/forks/Sybelle03/CVE-2021-43617.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/cybfar/cve-2021-42013-httpd](https://github.com/cybfar/cve-2021-42013-httpd) :  ![starts](https://img.shields.io/github/stars/cybfar/cve-2021-42013-httpd.svg) ![forks](https://img.shields.io/github/forks/cybfar/cve-2021-42013-httpd.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-36949
 Microsoft Azure Active Directory Connect Authentication Bypass Vulnerability

- [https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability](https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability) :  ![starts](https://img.shields.io/github/stars/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg)


## CVE-2021-2109
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2020-27786
 A flaw was found in the Linux kernel&#8217;s implementation of MIDI, where an attacker with a local account and the permissions to issue ioctl commands to midi devices could trigger a use-after-free issue. A write to this specific memory while freed and before use causes the flow of execution to change and possibly allow for memory corruption or privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.

- [https://github.com/Trinadh465/linux-4.19.72_CVE-2020-27786](https://github.com/Trinadh465/linux-4.19.72_CVE-2020-27786) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.19.72_CVE-2020-27786.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.19.72_CVE-2020-27786.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/Nigmaz/CVE-2018-1160](https://github.com/Nigmaz/CVE-2018-1160) :  ![starts](https://img.shields.io/github/stars/Nigmaz/CVE-2018-1160.svg) ![forks](https://img.shields.io/github/forks/Nigmaz/CVE-2018-1160.svg)


## CVE-2012-1495
 install/index.php in WebCalendar before 1.2.5 allows remote attackers to execute arbitrary code via the form_single_user_login parameter.

- [https://github.com/axelbankole/CVE-2012-1495-Webcalendar-](https://github.com/axelbankole/CVE-2012-1495-Webcalendar-) :  ![starts](https://img.shields.io/github/stars/axelbankole/CVE-2012-1495-Webcalendar-.svg) ![forks](https://img.shields.io/github/forks/axelbankole/CVE-2012-1495-Webcalendar-.svg)

