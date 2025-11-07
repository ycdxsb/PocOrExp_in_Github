# Update 2025-11-07
## CVE-2025-61304
 OS command injection vulnerability in Dynatrace ActiveGate ping extension up to 1.016 via crafted ip address.

- [https://github.com/pentastic-be/CVE-2025-61304](https://github.com/pentastic-be/CVE-2025-61304) :  ![starts](https://img.shields.io/github/stars/pentastic-be/CVE-2025-61304.svg) ![forks](https://img.shields.io/github/forks/pentastic-be/CVE-2025-61304.svg)


## CVE-2025-56383
 Notepad++ v8.8.3 has a DLL hijacking vulnerability, which can replace the original DLL file to execute malicious code. NOTE: this is disputed by multiple parties because the behavior only occurs when a user installs the product into a directory tree that allows write access by arbitrary unprivileged users.

- [https://github.com/NewComrade12211/CVE-2025-56383](https://github.com/NewComrade12211/CVE-2025-56383) :  ![starts](https://img.shields.io/github/stars/NewComrade12211/CVE-2025-56383.svg) ![forks](https://img.shields.io/github/forks/NewComrade12211/CVE-2025-56383.svg)


## CVE-2025-53690
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Code Injection.This issue affects Experience Manager (XM): through 9.0; Experience Platform (XP): through 9.0.

- [https://github.com/ErikLearningSec/CVE-2025-53690-POC](https://github.com/ErikLearningSec/CVE-2025-53690-POC) :  ![starts](https://img.shields.io/github/stars/ErikLearningSec/CVE-2025-53690-POC.svg) ![forks](https://img.shields.io/github/forks/ErikLearningSec/CVE-2025-53690-POC.svg)


## CVE-2025-52665
Update your UniFi Access Application to Version 4.0.21 or later.

- [https://github.com/callinston/CVE-2025-52665](https://github.com/callinston/CVE-2025-52665) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-52665.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-52665.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/BugHawak/CVE-2025-29927](https://github.com/BugHawak/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/BugHawak/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/BugHawak/CVE-2025-29927.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/kimtangker/CVE-2025-24893](https://github.com/kimtangker/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/kimtangker/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/kimtangker/CVE-2025-24893.svg)


## CVE-2025-11953
 The Metro Development Server, which is opened by the React Native Community CLI, binds to external interfaces by default. The server exposes an endpoint that is vulnerable to OS command injection. This allows unauthenticated network attackers to send a POST request to the server and run arbitrary executables. On Windows, the attackers can also execute arbitrary shell commands with fully controlled arguments.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-11953](https://github.com/B1ack4sh/Blackash-CVE-2025-11953) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-11953.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-11953.svg)


## CVE-2025-9209
 The RestroPress – Online Food Ordering System plugin for WordPress is vulnerable to Authentication Bypass in versions 3.0.0 to 3.1.9.2. This is due to the plugin exposing user private tokens and API data via the /wp-json/wp/v2/users REST API endpoint. This makes it possible for unauthenticated attackers to forge JWT tokens for other users, including administrators, and authenticate as them.

- [https://github.com/Nxploited/CVE-2025-9209](https://github.com/Nxploited/CVE-2025-9209) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-9209.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-9209.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/xxoprt/CVE-2025-6440](https://github.com/xxoprt/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/xxoprt/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/xxoprt/CVE-2025-6440.svg)


## CVE-2025-6358
 A vulnerability was found in code-projects Simple Pizza Ordering System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /saveorder.php. The manipulation of the argument ID leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/cybercrewinc/CVE-2025-63589](https://github.com/cybercrewinc/CVE-2025-63589) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2025-63589.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2025-63589.svg)
- [https://github.com/cybercrewinc/CVE-2025-63588](https://github.com/cybercrewinc/CVE-2025-63588) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2025-63588.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2025-63588.svg)


## CVE-2025-6357
 A vulnerability was found in code-projects Simple Pizza Ordering System 1.0. It has been classified as critical. Affected is an unknown function of the file /paymentportal.php. The manipulation of the argument person leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/RRespxwnss/CVE-2025-63571](https://github.com/RRespxwnss/CVE-2025-63571) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/CVE-2025-63571.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/CVE-2025-63571.svg)
- [https://github.com/RRespxwnss/CVE-2025-63572](https://github.com/RRespxwnss/CVE-2025-63572) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/CVE-2025-63572.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/CVE-2025-63572.svg)


## CVE-2025-6330
 A vulnerability classified as critical has been found in PHPGurukul Directory Management System 1.0. Affected is an unknown function of the file /searchdata.php. The manipulation of the argument searchdata leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Theethat-Thamwasin/CVE-2025-63307](https://github.com/Theethat-Thamwasin/CVE-2025-63307) :  ![starts](https://img.shields.io/github/stars/Theethat-Thamwasin/CVE-2025-63307.svg) ![forks](https://img.shields.io/github/forks/Theethat-Thamwasin/CVE-2025-63307.svg)


## CVE-2025-4859
 A vulnerability was found in D-Link DAP-2695 120b36r137_ALL_en_20210528. It has been rated as problematic. This issue affects some unknown processing of the file /adv_macbypass.php of the component MAC Bypass Settings Page. The manipulation of the argument f_mac leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/daiens/CVE-2025-48593](https://github.com/daiens/CVE-2025-48593) :  ![starts](https://img.shields.io/github/stars/daiens/CVE-2025-48593.svg) ![forks](https://img.shields.io/github/forks/daiens/CVE-2025-48593.svg)


## CVE-2024-46256
 A Command injection vulnerability in requestLetsEncryptSsl in NginxProxyManager 2.11.3 allows an attacker to RCE via Add Let's Encrypt Certificate.

- [https://github.com/kimtangker/CVE-2024-46256](https://github.com/kimtangker/CVE-2024-46256) :  ![starts](https://img.shields.io/github/stars/kimtangker/CVE-2024-46256.svg) ![forks](https://img.shields.io/github/forks/kimtangker/CVE-2024-46256.svg)


## CVE-2024-40725
Users are recommended to upgrade to version 2.4.62, which fixes this issue.

- [https://github.com/YassineOUAHMANE/CVE-2024-40725](https://github.com/YassineOUAHMANE/CVE-2024-40725) :  ![starts](https://img.shields.io/github/stars/YassineOUAHMANE/CVE-2024-40725.svg) ![forks](https://img.shields.io/github/forks/YassineOUAHMANE/CVE-2024-40725.svg)


## CVE-2024-4040
 A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.

- [https://github.com/juanorts/CrushFTP10-Docker-CVE-2024-4040](https://github.com/juanorts/CrushFTP10-Docker-CVE-2024-4040) :  ![starts](https://img.shields.io/github/stars/juanorts/CrushFTP10-Docker-CVE-2024-4040.svg) ![forks](https://img.shields.io/github/forks/juanorts/CrushFTP10-Docker-CVE-2024-4040.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/B1ack4sh/Blackash-CVE-2024-3094](https://github.com/B1ack4sh/Blackash-CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2024-3094.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/CankunWang/Tryhackme_Billing](https://github.com/CankunWang/Tryhackme_Billing) :  ![starts](https://img.shields.io/github/stars/CankunWang/Tryhackme_Billing.svg) ![forks](https://img.shields.io/github/forks/CankunWang/Tryhackme_Billing.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the "Hardware Layer Code Box" component on the "/hardware" page of the application.

- [https://github.com/tranquac/OpenPLC_v3](https://github.com/tranquac/OpenPLC_v3) :  ![starts](https://img.shields.io/github/stars/tranquac/OpenPLC_v3.svg) ![forks](https://img.shields.io/github/forks/tranquac/OpenPLC_v3.svg)


## CVE-2020-35667
 JetBrains TeamCity Plugin before 2020.2.85695 SSRF. Vulnerability that could potentially expose user credentials.

- [https://github.com/stefan-500/teamcity-idea-cve-2020-35667-poc](https://github.com/stefan-500/teamcity-idea-cve-2020-35667-poc) :  ![starts](https://img.shields.io/github/stars/stefan-500/teamcity-idea-cve-2020-35667-poc.svg) ![forks](https://img.shields.io/github/forks/stefan-500/teamcity-idea-cve-2020-35667-poc.svg)


## CVE-2020-14883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/B1ack4sh/Blackash-CVE-2020-14883](https://github.com/B1ack4sh/Blackash-CVE-2020-14883) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2020-14883.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2020-14883.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/B1ack4sh/Blackash-CVE-2020-2551](https://github.com/B1ack4sh/Blackash-CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2020-2551.svg)

