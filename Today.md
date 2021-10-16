# Update 2021-10-16
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/twseptian/CVE-2021-42013-Lab](https://github.com/twseptian/CVE-2021-42013-Lab) :  ![starts](https://img.shields.io/github/stars/twseptian/CVE-2021-42013-Lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/CVE-2021-42013-Lab.svg)
- [https://github.com/MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/SimplesApachePathTraversal.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/SimplesApachePathTraversal.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/SimplesApachePathTraversal.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/SimplesApachePathTraversal.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/KnoooW/CVE-2021-40444-docx-Generate](https://github.com/KnoooW/CVE-2021-40444-docx-Generate) :  ![starts](https://img.shields.io/github/stars/KnoooW/CVE-2021-40444-docx-Generate.svg) ![forks](https://img.shields.io/github/forks/KnoooW/CVE-2021-40444-docx-Generate.svg)


## CVE-2021-38295
 In Apache CouchDB, a malicious user with permission to create documents in a database is able to attach a HTML attachment to a document. If a CouchDB admin opens that attachment in a browser, e.g. via the CouchDB admin interface Fauxton, any JavaScript code embedded in that HTML attachment will be executed within the security context of that admin. A similar route is available with the already deprecated _show and _list functionality. This privilege escalation vulnerability allows an attacker to add or remove data in any database or make configuration changes. This issue affected Apache CouchDB prior to 3.1.2

- [https://github.com/ProfessionallyEvil/CVE-2021-38295-PoC](https://github.com/ProfessionallyEvil/CVE-2021-38295-PoC) :  ![starts](https://img.shields.io/github/stars/ProfessionallyEvil/CVE-2021-38295-PoC.svg) ![forks](https://img.shields.io/github/forks/ProfessionallyEvil/CVE-2021-38295-PoC.svg)


## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/BrucessKING/CVE-2021-36749](https://github.com/BrucessKING/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/BrucessKING/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/BrucessKING/CVE-2021-36749.svg)
- [https://github.com/dorkerdevil/CVE-2021-36749](https://github.com/dorkerdevil/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-36749.svg)


## CVE-2021-33766
 Microsoft Exchange Information Disclosure Vulnerability

- [https://github.com/bhdresh/CVE-2021-33766](https://github.com/bhdresh/CVE-2021-33766) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2021-33766.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2021-33766.svg)


## CVE-2021-33739
 Microsoft DWM Core Library Elevation of Privilege Vulnerability

- [https://github.com/freeide2017/CVE-2021-33739-POC](https://github.com/freeide2017/CVE-2021-33739-POC) :  ![starts](https://img.shields.io/github/stars/freeide2017/CVE-2021-33739-POC.svg) ![forks](https://img.shields.io/github/forks/freeide2017/CVE-2021-33739-POC.svg)


## CVE-2021-31955
 Windows Kernel Information Disclosure Vulnerability

- [https://github.com/freeide/CVE-2021-31955-POC](https://github.com/freeide/CVE-2021-31955-POC) :  ![starts](https://img.shields.io/github/stars/freeide/CVE-2021-31955-POC.svg) ![forks](https://img.shields.io/github/forks/freeide/CVE-2021-31955-POC.svg)


## CVE-2021-30858
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/PeterMxx/ps4_8.00_vuln_poc](https://github.com/PeterMxx/ps4_8.00_vuln_poc) :  ![starts](https://img.shields.io/github/stars/PeterMxx/ps4_8.00_vuln_poc.svg) ![forks](https://img.shields.io/github/forks/PeterMxx/ps4_8.00_vuln_poc.svg)
- [https://github.com/KameleonReloaded/CVEREV3](https://github.com/KameleonReloaded/CVEREV3) :  ![starts](https://img.shields.io/github/stars/KameleonReloaded/CVEREV3.svg) ![forks](https://img.shields.io/github/forks/KameleonReloaded/CVEREV3.svg)


## CVE-2021-30632
 Out of bounds write in V8 in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/avboy1337/CVE-2021-30632](https://github.com/avboy1337/CVE-2021-30632) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2021-30632.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2021-30632.svg)


## CVE-2021-28378
 Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.

- [https://github.com/pandatix/CVE-2021-28378](https://github.com/pandatix/CVE-2021-28378) :  ![starts](https://img.shields.io/github/stars/pandatix/CVE-2021-28378.svg) ![forks](https://img.shields.io/github/forks/pandatix/CVE-2021-28378.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/convisolabs/CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool) :  ![starts](https://img.shields.io/github/stars/convisolabs/CVE-2021-22204-exiftool.svg) ![forks](https://img.shields.io/github/forks/convisolabs/CVE-2021-22204-exiftool.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/musergi/CVE-2021-3156](https://github.com/musergi/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/musergi/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/musergi/CVE-2021-3156.svg)


## CVE-2020-28018
 Exim 4 before 4.94.2 allows Use After Free in smtp_reset in certain situations that may be common for builds with OpenSSL.

- [https://github.com/zr0tt/CVE-2020-28018](https://github.com/zr0tt/CVE-2020-28018) :  ![starts](https://img.shields.io/github/stars/zr0tt/CVE-2020-28018.svg) ![forks](https://img.shields.io/github/forks/zr0tt/CVE-2020-28018.svg)


## CVE-2020-17519
 A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.

- [https://github.com/MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/SimplesApachePathTraversal.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/SimplesApachePathTraversal.svg)


## CVE-2020-16846
 An issue was discovered in SaltStack Salt through 3002. Sending crafted web requests to the Salt API, with the SSH client enabled, can result in shell injection.

- [https://github.com/zomy22/CVE-2020-16846-Saltstack-Salt-API](https://github.com/zomy22/CVE-2020-16846-Saltstack-Salt-API) :  ![starts](https://img.shields.io/github/stars/zomy22/CVE-2020-16846-Saltstack-Salt-API.svg) ![forks](https://img.shields.io/github/forks/zomy22/CVE-2020-16846-Saltstack-Salt-API.svg)


## CVE-2020-14295
 A SQL injection issue in color.php in Cacti 1.2.12 allows an admin to inject SQL via the filter parameter. This can lead to remote command execution because the product accepts stacked queries.

- [https://github.com/mrg3ntl3m4n/CVE-2020-14295](https://github.com/mrg3ntl3m4n/CVE-2020-14295) :  ![starts](https://img.shields.io/github/stars/mrg3ntl3m4n/CVE-2020-14295.svg) ![forks](https://img.shields.io/github/forks/mrg3ntl3m4n/CVE-2020-14295.svg)


## CVE-2020-10770
 A flaw was found in Keycloak before 13.0.0, where it is possible to force the server to call out an unverified URL using the OIDC parameter request_uri. This flaw allows an attacker to use this parameter to execute a Server-side request forgery (SSRF) attack.

- [https://github.com/ColdFusionX/Keycloak-12.0.1-CVE-2020-10770](https://github.com/ColdFusionX/Keycloak-12.0.1-CVE-2020-10770) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/Keycloak-12.0.1-CVE-2020-10770.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/Keycloak-12.0.1-CVE-2020-10770.svg)


## CVE-2020-8811
 ajax/profile-picture-upload.php in Bludit 3.10.0 allows authenticated users to change other users' profile pictures.

- [https://github.com/team0se7en/CVE-2020-8816](https://github.com/team0se7en/CVE-2020-8816) :  ![starts](https://img.shields.io/github/stars/team0se7en/CVE-2020-8816.svg) ![forks](https://img.shields.io/github/forks/team0se7en/CVE-2020-8816.svg)


## CVE-2020-1020
 A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format.For all systems except Windows 10, an attacker who successfully exploited the vulnerability could execute code remotely, aka 'Adobe Font Manager Library Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0938.

- [https://github.com/CrackerCat/CVE-2020-1020-Exploit](https://github.com/CrackerCat/CVE-2020-1020-Exploit) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2020-1020-Exploit.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2020-1020-Exploit.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Devang-Solanki/CVE-2018-6574](https://github.com/Devang-Solanki/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/Devang-Solanki/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/Devang-Solanki/CVE-2018-6574.svg)


## CVE-2016-5983
 IBM WebSphere Application Server (WAS) 7.0 before 7.0.0.43, 8.0 before 8.0.0.13, 8.5 before 8.5.5.11, 9.0 before 9.0.0.2, and Liberty before 16.0.0.4 allows remote authenticated users to execute arbitrary Java code via a crafted serialized object.

- [https://github.com/BitWrecker/CVE-2016-5983](https://github.com/BitWrecker/CVE-2016-5983) :  ![starts](https://img.shields.io/github/stars/BitWrecker/CVE-2016-5983.svg) ![forks](https://img.shields.io/github/forks/BitWrecker/CVE-2016-5983.svg)

