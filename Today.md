# Update 2024-06-30
## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/11whoami99/CVE-2024-34102](https://github.com/11whoami99/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/11whoami99/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/11whoami99/CVE-2024-34102.svg)
- [https://github.com/Chocapikk/CVE-2024-34102](https://github.com/Chocapikk/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-34102.svg)
- [https://github.com/d0rb/CVE-2024-34102](https://github.com/d0rb/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2024-34102.svg)


## CVE-2024-21650
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. XWiki is vulnerable to a remote code execution (RCE) attack through its user registration feature. This issue allows an attacker to execute arbitrary code by crafting malicious payloads in the &quot;first name&quot; or &quot;last name&quot; fields during user registration. This impacts all installations that have user registration enabled for guests. This vulnerability has been patched in XWiki 14.10.17, 15.5.3 and 15.8 RC1.

- [https://github.com/codeb0ss/CVE-2024-21650-PoC](https://github.com/codeb0ss/CVE-2024-21650-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-21650-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-21650-PoC.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/olebris/CVE-2024-21413](https://github.com/olebris/CVE-2024-21413) :  ![starts](https://img.shields.io/github/stars/olebris/CVE-2024-21413.svg) ![forks](https://img.shields.io/github/forks/olebris/CVE-2024-21413.svg)


## CVE-2024-5737
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2024-5737](https://github.com/afine-com/CVE-2024-5737) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2024-5737.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2024-5737.svg)


## CVE-2024-5736
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2024-5736](https://github.com/afine-com/CVE-2024-5736) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2024-5736.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2024-5736.svg)


## CVE-2024-5735
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2024-5735](https://github.com/afine-com/CVE-2024-5735) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2024-5735.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2024-5735.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/olebris/CVE-2024-4577](https://github.com/olebris/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/olebris/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/olebris/CVE-2024-4577.svg)


## CVE-2024-4040
 A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.

- [https://github.com/olebris/CVE-2024-4040](https://github.com/olebris/CVE-2024-4040) :  ![starts](https://img.shields.io/github/stars/olebris/CVE-2024-4040.svg) ![forks](https://img.shields.io/github/forks/olebris/CVE-2024-4040.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/glen-pearson/MoveIT-CVE-2023-34362-RCE](https://github.com/glen-pearson/MoveIT-CVE-2023-34362-RCE) :  ![starts](https://img.shields.io/github/stars/glen-pearson/MoveIT-CVE-2023-34362-RCE.svg) ![forks](https://img.shields.io/github/forks/glen-pearson/MoveIT-CVE-2023-34362-RCE.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/PavilionQ/CVE-2023-33246-mitigation](https://github.com/PavilionQ/CVE-2023-33246-mitigation) :  ![starts](https://img.shields.io/github/stars/PavilionQ/CVE-2023-33246-mitigation.svg) ![forks](https://img.shields.io/github/forks/PavilionQ/CVE-2023-33246-mitigation.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/olebris/Exploit_CVE_2023_7028-](https://github.com/olebris/Exploit_CVE_2023_7028-) :  ![starts](https://img.shields.io/github/stars/olebris/Exploit_CVE_2023_7028-.svg) ![forks](https://img.shields.io/github/forks/olebris/Exploit_CVE_2023_7028-.svg)


## CVE-2022-46395
 An issue was discovered in the Arm Mali GPU Kernel Driver. A non-privileged user can make improper GPU processing operations to gain access to already freed memory. This affects Midgard r0p0 through r32p0, Bifrost r0p0 through r41p0 before r42p0, Valhall r19p0 through r41p0 before r42p0, and Avalon r41p0 before r42p0.

- [https://github.com/SmileTabLabo/CVE-2022-46395](https://github.com/SmileTabLabo/CVE-2022-46395) :  ![starts](https://img.shields.io/github/stars/SmileTabLabo/CVE-2022-46395.svg) ![forks](https://img.shields.io/github/forks/SmileTabLabo/CVE-2022-46395.svg)


## CVE-2022-20186
 In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A

- [https://github.com/SmileTabLabo/CVE-2022-20186](https://github.com/SmileTabLabo/CVE-2022-20186) :  ![starts](https://img.shields.io/github/stars/SmileTabLabo/CVE-2022-20186.svg) ![forks](https://img.shields.io/github/forks/SmileTabLabo/CVE-2022-20186.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/glen-pearson/ProxyLogon-CVE-2021-26855](https://github.com/glen-pearson/ProxyLogon-CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/glen-pearson/ProxyLogon-CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/glen-pearson/ProxyLogon-CVE-2021-26855.svg)


## CVE-2020-7656
 jquery prior to 1.9.0 allows Cross-site Scripting attacks via the load method. The load method fails to recognize and remove &quot;&lt;script&gt;&quot; HTML tags that contain a whitespace character, i.e: &quot;&lt;/script &gt;&quot;, which results in the enclosed script logic to be executed.

- [https://github.com/ossf-cve-benchmark/CVE-2020-7656](https://github.com/ossf-cve-benchmark/CVE-2020-7656) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-7656.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-7656.svg)


## CVE-2016-10993
 The ScoreMe theme through 2016-04-01 for WordPress has XSS via the s parameter.

- [https://github.com/0xc4t/CVE-2016-10993](https://github.com/0xc4t/CVE-2016-10993) :  ![starts](https://img.shields.io/github/stars/0xc4t/CVE-2016-10993.svg) ![forks](https://img.shields.io/github/forks/0xc4t/CVE-2016-10993.svg)


## CVE-2005-3299
 PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.

- [https://github.com/Cr0w-ui/-CVE-2005-3299-](https://github.com/Cr0w-ui/-CVE-2005-3299-) :  ![starts](https://img.shields.io/github/stars/Cr0w-ui/-CVE-2005-3299-.svg) ![forks](https://img.shields.io/github/forks/Cr0w-ui/-CVE-2005-3299-.svg)

