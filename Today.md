# Update 2025-09-07
## CVE-2025-58780
 index.em7 in ScienceLogic SL1 before 12.1.1 allows SQL Injection via a parameter in a request.

- [https://github.com/SexyShoelessGodofWar/CVE-2025-58780](https://github.com/SexyShoelessGodofWar/CVE-2025-58780) :  ![starts](https://img.shields.io/github/stars/SexyShoelessGodofWar/CVE-2025-58780.svg) ![forks](https://img.shields.io/github/forks/SexyShoelessGodofWar/CVE-2025-58780.svg)


## CVE-2025-58440
 The unisharp/laravel-filemanager is a separate project, unrelated to laravel-filemanager.

- [https://github.com/ph-hitachi/CVE-2025-58440](https://github.com/ph-hitachi/CVE-2025-58440) :  ![starts](https://img.shields.io/github/stars/ph-hitachi/CVE-2025-58440.svg) ![forks](https://img.shields.io/github/forks/ph-hitachi/CVE-2025-58440.svg)


## CVE-2025-57833
 An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6. FilteredRelation is subject to SQL injection in column aliases, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed QuerySet.annotate() or QuerySet.alias().

- [https://github.com/Mkway/CVE-2025-57833](https://github.com/Mkway/CVE-2025-57833) :  ![starts](https://img.shields.io/github/stars/Mkway/CVE-2025-57833.svg) ![forks](https://img.shields.io/github/forks/Mkway/CVE-2025-57833.svg)


## CVE-2025-57576
 PHPGurukul Online Shopping Portal 2.1 is vulnerable to Cross Site Scripting (XSS) in /admin/updateorder.php.

- [https://github.com/p0et08/DWrwq](https://github.com/p0et08/DWrwq) :  ![starts](https://img.shields.io/github/stars/p0et08/DWrwq.svg) ![forks](https://img.shields.io/github/forks/p0et08/DWrwq.svg)


## CVE-2025-53690
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Code Injection.This issue affects Experience Manager (XM): through 9.0; Experience Platform (XP): through 9.0.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-53690](https://github.com/B1ack4sh/Blackash-CVE-2025-53690) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53690.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53690.svg)


## CVE-2025-49388
 Incorrect Privilege Assignment vulnerability in kamleshyadav Miraculous Core Plugin allows Privilege Escalation. This issue affects Miraculous Core Plugin: from n/a through 2.0.7.

- [https://github.com/Nxploited/CVE-2025-49388](https://github.com/Nxploited/CVE-2025-49388) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-49388.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-49388.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/blackcat4347/CVE-2025-32463_PoC](https://github.com/blackcat4347/CVE-2025-32463_PoC) :  ![starts](https://img.shields.io/github/stars/blackcat4347/CVE-2025-32463_PoC.svg) ![forks](https://img.shields.io/github/forks/blackcat4347/CVE-2025-32463_PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/l1uk/nextjs-middleware-exploit](https://github.com/l1uk/nextjs-middleware-exploit) :  ![starts](https://img.shields.io/github/stars/l1uk/nextjs-middleware-exploit.svg) ![forks](https://img.shields.io/github/forks/l1uk/nextjs-middleware-exploit.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/andwati/CVE-2025-24893](https://github.com/andwati/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/andwati/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/andwati/CVE-2025-24893.svg)


## CVE-2025-22131
 PhpSpreadsheet is a PHP library for reading and writing spreadsheet files. Cross-Site Scripting (XSS) vulnerability in the code which translates the XLSX file into a HTML representation and displays it in the response.

- [https://github.com/s0ck37/CVE-2025-22131-POC](https://github.com/s0ck37/CVE-2025-22131-POC) :  ![starts](https://img.shields.io/github/stars/s0ck37/CVE-2025-22131-POC.svg) ![forks](https://img.shields.io/github/forks/s0ck37/CVE-2025-22131-POC.svg)


## CVE-2025-2502
 An improper default permissions vulnerability was reported in Lenovo PC Manager that could allow a local attacker to elevate privileges.

- [https://github.com/IHK-ONE/CVE-2025-2502](https://github.com/IHK-ONE/CVE-2025-2502) :  ![starts](https://img.shields.io/github/stars/IHK-ONE/CVE-2025-2502.svg) ![forks](https://img.shields.io/github/forks/IHK-ONE/CVE-2025-2502.svg)


## CVE-2024-40094
 GraphQL Java (aka graphql-java) before 21.5 does not properly consider ExecutableNormalizedFields (ENFs) as part of preventing denial of service via introspection queries. 20.9 and 19.11 are also fixed versions.

- [https://github.com/kabiri-labs/CVE-2024-40094](https://github.com/kabiri-labs/CVE-2024-40094) :  ![starts](https://img.shields.io/github/stars/kabiri-labs/CVE-2024-40094.svg) ![forks](https://img.shields.io/github/forks/kabiri-labs/CVE-2024-40094.svg)


## CVE-2024-22722
 Server Side Template Injection (SSTI) vulnerability in Form Tools 3.1.1 allows attackers to run arbitrary commands via the Group Name field under the add forms section of the application.

- [https://github.com/terribledactyl/Form-Tools-3.1.1-RCE](https://github.com/terribledactyl/Form-Tools-3.1.1-RCE) :  ![starts](https://img.shields.io/github/stars/terribledactyl/Form-Tools-3.1.1-RCE.svg) ![forks](https://img.shields.io/github/forks/terribledactyl/Form-Tools-3.1.1-RCE.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/kabiri-labs/CVE-2024-4367-PoC](https://github.com/kabiri-labs/CVE-2024-4367-PoC) :  ![starts](https://img.shields.io/github/stars/kabiri-labs/CVE-2024-4367-PoC.svg) ![forks](https://img.shields.io/github/forks/kabiri-labs/CVE-2024-4367-PoC.svg)


## CVE-2023-49543
 Incorrect access control in Book Store Management System v1 allows attackers to access unauthorized pages and execute administrative functions without authenticating.

- [https://github.com/geraldoalcantara/CVE-2023-49543](https://github.com/geraldoalcantara/CVE-2023-49543) :  ![starts](https://img.shields.io/github/stars/geraldoalcantara/CVE-2023-49543.svg) ![forks](https://img.shields.io/github/forks/geraldoalcantara/CVE-2023-49543.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/zs1n/CVE-2023-46818](https://github.com/zs1n/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2023-46818.svg)


## CVE-2022-24992
 A vulnerability in the component process.php of QR Code Generator v5.2.7 allows attackers to perform directory traversal.

- [https://github.com/n0lsec1337/CVE-2022-24992](https://github.com/n0lsec1337/CVE-2022-24992) :  ![starts](https://img.shields.io/github/stars/n0lsec1337/CVE-2022-24992.svg) ![forks](https://img.shields.io/github/forks/n0lsec1337/CVE-2022-24992.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Makavellik/POC-CVE-2021-42013-EXPLOIT](https://github.com/Makavellik/POC-CVE-2021-42013-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/Makavellik/POC-CVE-2021-42013-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/Makavellik/POC-CVE-2021-42013-EXPLOIT.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/bsec404/CVE-2020-0796](https://github.com/bsec404/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/bsec404/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/bsec404/CVE-2020-0796.svg)


## CVE-2020-0079
 In decrypt_1_2 of CryptoPlugin.cpp, there is a possible out of bounds write due to stale pointer. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10Android ID: A-144506242

- [https://github.com/bsec404/cve-2020-00796](https://github.com/bsec404/cve-2020-00796) :  ![starts](https://img.shields.io/github/stars/bsec404/cve-2020-00796.svg) ![forks](https://img.shields.io/github/forks/bsec404/cve-2020-00796.svg)


## CVE-2019-10078
 A carefully crafted plugin link invocation could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking. Initial reporting indicated ReferredPagesPlugin, but further analysis showed that multiple plugins were vulnerable.

- [https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/MuhammadAbdullah192/CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION](https://github.com/MuhammadAbdullah192/CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION) :  ![starts](https://img.shields.io/github/stars/MuhammadAbdullah192/CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION.svg) ![forks](https://img.shields.io/github/forks/MuhammadAbdullah192/CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION.svg)


## CVE-2015-5736
 The Fortishield.sys driver in Fortinet FortiClient before 5.2.4 allows local users to execute arbitrary code with kernel privileges by setting the callback function in a (1) 0x220024 or (2) 0x220028 ioctl call.

- [https://github.com/avielzecharia/CVE-2015-5736](https://github.com/avielzecharia/CVE-2015-5736) :  ![starts](https://img.shields.io/github/stars/avielzecharia/CVE-2015-5736.svg) ![forks](https://img.shields.io/github/forks/avielzecharia/CVE-2015-5736.svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/oukridrig772/-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation](https://github.com/oukridrig772/-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation) :  ![starts](https://img.shields.io/github/stars/oukridrig772/-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation.svg) ![forks](https://img.shields.io/github/forks/oukridrig772/-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation.svg)

