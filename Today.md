# Update 2023-06-14
## CVE-2023-34965
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AgentY0/CVE-2023-34965](https://github.com/AgentY0/CVE-2023-34965) :  ![starts](https://img.shields.io/github/stars/AgentY0/CVE-2023-34965.svg) ![forks](https://img.shields.io/github/forks/AgentY0/CVE-2023-34965.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/horizon3ai/CVE-2023-34362](https://github.com/horizon3ai/CVE-2023-34362) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-34362.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-34362.svg)
- [https://github.com/sfewer-r7/CVE-2023-34362](https://github.com/sfewer-r7/CVE-2023-34362) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2023-34362.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2023-34362.svg)
- [https://github.com/lithuanian-g/cve-2023-34362-iocs](https://github.com/lithuanian-g/cve-2023-34362-iocs) :  ![starts](https://img.shields.io/github/stars/lithuanian-g/cve-2023-34362-iocs.svg) ![forks](https://img.shields.io/github/forks/lithuanian-g/cve-2023-34362-iocs.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/hheeyywweellccoommee/CVE-2023-33246-dgjfd](https://github.com/hheeyywweellccoommee/CVE-2023-33246-dgjfd) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-33246-dgjfd.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-33246-dgjfd.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols. CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/7imbitz/CVE-2023-25157-checker](https://github.com/7imbitz/CVE-2023-25157-checker) :  ![starts](https://img.shields.io/github/stars/7imbitz/CVE-2023-25157-checker.svg) ![forks](https://img.shields.io/github/forks/7imbitz/CVE-2023-25157-checker.svg)


## CVE-2023-20963
 In WorkSource, there is a possible parcel mismatch. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-220302519

- [https://github.com/Chal13W1zz/BadParcel](https://github.com/Chal13W1zz/BadParcel) :  ![starts](https://img.shields.io/github/stars/Chal13W1zz/BadParcel.svg) ![forks](https://img.shields.io/github/forks/Chal13W1zz/BadParcel.svg)


## CVE-2023-2008
 A flaw was found in the Linux kernel's udmabuf device driver. The specific flaw exists within a fault handler. The issue results from the lack of proper validation of user-supplied data, which can result in a memory access past the end of an array. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of the kernel.

- [https://github.com/bluefrostsecurity/CVE-2023-2008](https://github.com/bluefrostsecurity/CVE-2023-2008) :  ![starts](https://img.shields.io/github/stars/bluefrostsecurity/CVE-2023-2008.svg) ![forks](https://img.shields.io/github/forks/bluefrostsecurity/CVE-2023-2008.svg)


## CVE-2023-1430
 The FluentCRM - Marketing Automation For WordPress plugin for WordPress is vulnerable to unauthorized modification of data in versions up to, and including, 2.7.40 due to the use of an MD5 hash without a salt to control subscriptions. This makes it possible for unauthenticated attackers to unsubscribe users from lists and manage subscriptions, granted they gain access to any targeted subscribers email address.

- [https://github.com/karlemilnikka/CVE-2023-1430](https://github.com/karlemilnikka/CVE-2023-1430) :  ![starts](https://img.shields.io/github/stars/karlemilnikka/CVE-2023-1430.svg) ![forks](https://img.shields.io/github/forks/karlemilnikka/CVE-2023-1430.svg)


## CVE-2022-29455
 DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.

- [https://github.com/0xkucing/CVE-2022-29455](https://github.com/0xkucing/CVE-2022-29455) :  ![starts](https://img.shields.io/github/stars/0xkucing/CVE-2022-29455.svg) ![forks](https://img.shields.io/github/forks/0xkucing/CVE-2022-29455.svg)


## CVE-2022-3590
 WordPress is affected by an unauthenticated blind SSRF in the pingback feature. Because of a TOCTOU race condition between the validation checks and the HTTP request, attackers can reach internal hosts that are explicitly forbidden.

- [https://github.com/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner](https://github.com/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/roxas-tan/CVE-2021-44228](https://github.com/roxas-tan/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/roxas-tan/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/roxas-tan/CVE-2021-44228.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-21311
 Adminer is an open-source database management in a single PHP file. In adminer from version 4.0.0 and before 4.7.9 there is a server-side request forgery vulnerability. Users of Adminer versions bundling all drivers (e.g. `adminer.php`) are affected. This is fixed in version 4.7.9.

- [https://github.com/omoknooni/CVE-2021-21311](https://github.com/omoknooni/CVE-2021-21311) :  ![starts](https://img.shields.io/github/stars/omoknooni/CVE-2021-21311.svg) ![forks](https://img.shields.io/github/forks/omoknooni/CVE-2021-21311.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/AzizMea/CVE-2019-10149-privilege-escalation](https://github.com/AzizMea/CVE-2019-10149-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/AzizMea/CVE-2019-10149-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/AzizMea/CVE-2019-10149-privilege-escalation.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/sl4cky/CVE-2018-7600-Masschecker](https://github.com/sl4cky/CVE-2018-7600-Masschecker) :  ![starts](https://img.shields.io/github/stars/sl4cky/CVE-2018-7600-Masschecker.svg) ![forks](https://img.shields.io/github/forks/sl4cky/CVE-2018-7600-Masschecker.svg)
- [https://github.com/cved-sources/cve-2018-7600](https://github.com/cved-sources/cve-2018-7600) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2018-7600.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2018-7600.svg)
- [https://github.com/VictorMora97/Drupalgeddon2](https://github.com/VictorMora97/Drupalgeddon2) :  ![starts](https://img.shields.io/github/stars/VictorMora97/Drupalgeddon2.svg) ![forks](https://img.shields.io/github/forks/VictorMora97/Drupalgeddon2.svg)
- [https://github.com/1AmG0d/myDrupal](https://github.com/1AmG0d/myDrupal) :  ![starts](https://img.shields.io/github/stars/1AmG0d/myDrupal.svg) ![forks](https://img.shields.io/github/forks/1AmG0d/myDrupal.svg)


## CVE-2015-5995
 Mediabridge Medialink MWN-WAPR300N devices with firmware 5.07.50 and Tenda N3 Wireless N150 devices allow remote attackers to obtain administrative access via a certain admin substring in an HTTP Cookie header.

- [https://github.com/shaheemirza/TendaSpill](https://github.com/shaheemirza/TendaSpill) :  ![starts](https://img.shields.io/github/stars/shaheemirza/TendaSpill.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/TendaSpill.svg)


## CVE-2014-3544
 Cross-site scripting (XSS) vulnerability in user/profile.php in Moodle through 2.3.11, 2.4.x before 2.4.11, 2.5.x before 2.5.7, 2.6.x before 2.6.4, and 2.7.x before 2.7.1 allows remote authenticated users to inject arbitrary web script or HTML via the Skype ID profile field.

- [https://github.com/aforesaid/MoodleHack](https://github.com/aforesaid/MoodleHack) :  ![starts](https://img.shields.io/github/stars/aforesaid/MoodleHack.svg) ![forks](https://img.shields.io/github/forks/aforesaid/MoodleHack.svg)

