# Update 2025-08-06
## CVE-2025-54962
 /edit-user in webserver in OpenPLC Runtime 3 through 9cd8f1b allows authenticated users to upload arbitrary files (such as .html or .svg), and these are then publicly accessible under the /static URI.

- [https://github.com/Eyodav/CVE-2025-54962](https://github.com/Eyodav/CVE-2025-54962) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-54962.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-54962.svg)


## CVE-2025-54574
 Squid is a caching proxy for the Web. In versions 6.3 and below, Squid is vulnerable to a heap buffer overflow and possible remote code execution attack when processing URN due to incorrect buffer management. This has been fixed in version 6.4. To work around this issue, disable URN access permissions.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-54574](https://github.com/B1ack4sh/Blackash-CVE-2025-54574) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-54574.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-54574.svg)


## CVE-2025-54554
 tiaudit in Tera Insights tiCrypt before 2025-07-17 allows unauthenticated REST API requests that reveal sensitive information about the underlying SQL queries and database structure.

- [https://github.com/Aman-Parmar/CVE-2025-54554](https://github.com/Aman-Parmar/CVE-2025-54554) :  ![starts](https://img.shields.io/github/stars/Aman-Parmar/CVE-2025-54554.svg) ![forks](https://img.shields.io/github/forks/Aman-Parmar/CVE-2025-54554.svg)


## CVE-2025-54424
 1Panel is a web interface and MCP Server that manages websites, files, containers, databases, and LLMs on a Linux server. In versions 2.0.5 and below, the HTTPS protocol used for communication between the Core and Agent endpoints has incomplete certificate verification during certificate validation, leading to unauthorized interface access. Due to the presence of numerous command execution or high-privilege interfaces in 1Panel, this results in Remote Code Execution (RCE). This is fixed in version 2.0.6. The CVE has been translated from Simplified Chinese using GitHub Copilot.

- [https://github.com/Mr-xn/CVE-2025-54424](https://github.com/Mr-xn/CVE-2025-54424) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2025-54424.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2025-54424.svg)


## CVE-2025-54381
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. In versions 1.4.0 until 1.4.19, the file upload processing system contains an SSRF vulnerability that allows unauthenticated remote attackers to force the server to make arbitrary HTTP requests. The vulnerability stems from the multipart form data and JSON request handlers, which automatically download files from user-provided URLs without validating whether those URLs point to internal network addresses, cloud metadata endpoints, or other restricted resources. The documentation explicitly promotes this URL-based file upload feature, making it an intended design that exposes all deployed services to SSRF attacks by default. Version 1.4.19 contains a patch for the issue.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-54381](https://github.com/B1ack4sh/Blackash-CVE-2025-54381) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-54381.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-54381.svg)


## CVE-2025-51726
 CyberGhostVPNSetup.exe (Windows installer) is signed using the weak cryptographic hash algorithm SHA-1, which is vulnerable to collision attacks. This allows a malicious actor to craft a fake installer with a forged SHA-1 certificate that may still be accepted by Windows signature verification mechanisms, particularly on systems without strict SmartScreen or trust policy enforcement. Additionally, the installer lacks High Entropy Address Space Layout Randomization (ASLR), as confirmed by BinSkim (BA2015 rule) and repeated WinDbg analysis. The binary consistently loads into predictable memory ranges, increasing the success rate of memory corruption exploits. These two misconfigurations, when combined, significantly lower the bar for successful supply-chain style attacks or privilege escalation through fake installers.

- [https://github.com/meisterlos/CVE-2025-51726](https://github.com/meisterlos/CVE-2025-51726) :  ![starts](https://img.shields.io/github/stars/meisterlos/CVE-2025-51726.svg) ![forks](https://img.shields.io/github/forks/meisterlos/CVE-2025-51726.svg)


## CVE-2025-50754
 Unisite CMS version 5.0 contains a stored Cross-Site Scripting (XSS) vulnerability in the "Report" functionality. A malicious script submitted by an attacker is rendered in the admin panel when viewed by an administrator. This allows attackers to hijack the admin session and, by leveraging the template editor, upload and execute a PHP web shell on the server, leading to full remote code execution.

- [https://github.com/furk4nyildiz/CVE-2025-50754-PoC](https://github.com/furk4nyildiz/CVE-2025-50754-PoC) :  ![starts](https://img.shields.io/github/stars/furk4nyildiz/CVE-2025-50754-PoC.svg) ![forks](https://img.shields.io/github/forks/furk4nyildiz/CVE-2025-50754-PoC.svg)


## CVE-2025-50422
 An issue was discovered in freedesktop poppler v25.04.0. The heap memory containing PDF stream objects is not cleared upon program exit, allowing attackers to obtain sensitive PDF content via a memory dump.

- [https://github.com/Landw-hub/CVE-2025-50422](https://github.com/Landw-hub/CVE-2025-50422) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-50422.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-50422.svg)


## CVE-2025-50420
 An issue in the pdfseparate utility of freedesktop poppler v25.04.0 allows attackers to cause an infinite recursion via supplying a crafted PDF file. This can lead to a Denial of Service (DoS).

- [https://github.com/Landw-hub/CVE-2025-50420](https://github.com/Landw-hub/CVE-2025-50420) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-50420.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-50420.svg)


## CVE-2025-50341
 A Boolean-based SQL injection vulnerability was discovered in Axelor 5.2.4 via the _domain parameter. An attacker can manipulate the SQL query logic and determine true/false conditions, potentially leading to data exposure or further exploitation.

- [https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341](https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341) :  ![starts](https://img.shields.io/github/stars/millad7/Axelor-vulnerability-CVE-2025-50341.svg) ![forks](https://img.shields.io/github/forks/millad7/Axelor-vulnerability-CVE-2025-50341.svg)


## CVE-2025-50340
 An Insecure Direct Object Reference (IDOR) vulnerability was discovered in SOGo Webmail thru 5.6.0, allowing an authenticated user to send emails on behalf of other users by manipulating a user-controlled identifier in the email-sending request. The server fails to verify whether the authenticated user is authorized to use the specified sender identity, resulting in unauthorized message delivery as another user. This can lead to impersonation, phishing, or unauthorized communication within the system.

- [https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340](https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340) :  ![starts](https://img.shields.io/github/stars/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340.svg) ![forks](https://img.shields.io/github/forks/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/beishanxueyuan/CVE-2025-48384-test](https://github.com/beishanxueyuan/CVE-2025-48384-test) :  ![starts](https://img.shields.io/github/stars/beishanxueyuan/CVE-2025-48384-test.svg) ![forks](https://img.shields.io/github/forks/beishanxueyuan/CVE-2025-48384-test.svg)


## CVE-2025-46206
 An issue in Artifex mupdf 1.25.6, 1.25.5 allows a remote attacker to cause a denial of service via an infinite recursion in the `mutool clean` utility. When processing a crafted PDF file containing cyclic /Next references in the outline structure, the `strip_outline()` function enters infinite recursion

- [https://github.com/Landw-hub/CVE-2025-46206](https://github.com/Landw-hub/CVE-2025-46206) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-46206.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-46206.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/mickhacking/Thank-u-Next](https://github.com/mickhacking/Thank-u-Next) :  ![starts](https://img.shields.io/github/stars/mickhacking/Thank-u-Next.svg) ![forks](https://img.shields.io/github/forks/mickhacking/Thank-u-Next.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/gunzf0x/CVE-2025-24893](https://github.com/gunzf0x/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2025-24893.svg)
- [https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC](https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC.svg)


## CVE-2025-8517
 A vulnerability was found in givanz Vvveb 1.0.6.1. It has been declared as critical. Affected by this vulnerability is an unknown functionality. The manipulation leads to session fixiation. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.0.7 is able to address this issue. The patch is named d4b1e030066417b77d15b4ac505eed5ae7bf2c5e. It is recommended to upgrade the affected component.

- [https://github.com/helloandrewpaul/Session-Fixation-in-Vvveb-CMS-v1.0.6.1](https://github.com/helloandrewpaul/Session-Fixation-in-Vvveb-CMS-v1.0.6.1) :  ![starts](https://img.shields.io/github/stars/helloandrewpaul/Session-Fixation-in-Vvveb-CMS-v1.0.6.1.svg) ![forks](https://img.shields.io/github/forks/helloandrewpaul/Session-Fixation-in-Vvveb-CMS-v1.0.6.1.svg)


## CVE-2025-7340
 The HT Contact Form Widget For Elementor Page Builder & Gutenberg Blocks & Form Builder. plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the temp_file_upload function in all versions up to, and including, 2.2.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE](https://github.com/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE) :  ![starts](https://img.shields.io/github/stars/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE.svg)


## CVE-2025-5182
 A vulnerability has been found in Summer Pearl Group Vacation Rental Management Platform up to 1.0.1 and classified as critical. This vulnerability affects unknown code of the component Listing Handler. The manipulation leads to authorization bypass. The attack can be initiated remotely. Upgrading to version 1.0.2 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/shk-mubashshir/CVE-2025-51820](https://github.com/shk-mubashshir/CVE-2025-51820) :  ![starts](https://img.shields.io/github/stars/shk-mubashshir/CVE-2025-51820.svg) ![forks](https://img.shields.io/github/forks/shk-mubashshir/CVE-2025-51820.svg)


## CVE-2025-5059
 A vulnerability classified as critical has been found in Campcodes Online Shopping Portal 1.0. This affects an unknown part of the file /admin/edit-subcategory.php. The manipulation of the argument productimage1/productimage2/productimage3 leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/1515601525/CVE-2025-50592](https://github.com/1515601525/CVE-2025-50592) :  ![starts](https://img.shields.io/github/stars/1515601525/CVE-2025-50592.svg) ![forks](https://img.shields.io/github/forks/1515601525/CVE-2025-50592.svg)


## CVE-2025-4604
 The vulnerable code can bypass the Captcha check in Liferay Portal 7.4.3.80 through 7.4.3.132, and Liferay DXP 2024.Q1.1 through 2024.Q1.19, 2024.Q2.0 through 2024.Q2.13, 2024.Q3.0 through 2024.Q3.13, 2024.Q4.0 through 2024.Q4.7, 2025.Q1.0 through 2025.Q1.15 and 7.4 update 80 through update 92 and then attackers can run scripts in the Gogo shell

- [https://github.com/J0ey17/CVE-2025-46047](https://github.com/J0ey17/CVE-2025-46047) :  ![starts](https://img.shields.io/github/stars/J0ey17/CVE-2025-46047.svg) ![forks](https://img.shields.io/github/forks/J0ey17/CVE-2025-46047.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/xAL6/cve-2024-4577-scanner](https://github.com/xAL6/cve-2024-4577-scanner) :  ![starts](https://img.shields.io/github/stars/xAL6/cve-2024-4577-scanner.svg) ![forks](https://img.shields.io/github/forks/xAL6/cve-2024-4577-scanner.svg)


## CVE-2023-22077
 Vulnerability in the Oracle Database Recovery Manager component of Oracle Database Server.  Supported versions that are affected are 19.3-19.20 and  21.3-21.11. Easily exploitable vulnerability allows high privileged attacker having DBA account privilege with network access via Oracle Net to compromise Oracle Database Recovery Manager.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Database Recovery Manager. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/emad-almousa/CVE-2023-22077](https://github.com/emad-almousa/CVE-2023-22077) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2023-22077.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2023-22077.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/bomberfish/Whitelist](https://github.com/bomberfish/Whitelist) :  ![starts](https://img.shields.io/github/stars/bomberfish/Whitelist.svg) ![forks](https://img.shields.io/github/forks/bomberfish/Whitelist.svg)
- [https://github.com/bomberfish/Mandela-Legacy](https://github.com/bomberfish/Mandela-Legacy) :  ![starts](https://img.shields.io/github/stars/bomberfish/Mandela-Legacy.svg) ![forks](https://img.shields.io/github/forks/bomberfish/Mandela-Legacy.svg)
- [https://github.com/bomberfish/Mandela-Classic](https://github.com/bomberfish/Mandela-Classic) :  ![starts](https://img.shields.io/github/stars/bomberfish/Mandela-Classic.svg) ![forks](https://img.shields.io/github/forks/bomberfish/Mandela-Classic.svg)
- [https://github.com/bomberfish/AbsoluteSolver-iOS](https://github.com/bomberfish/AbsoluteSolver-iOS) :  ![starts](https://img.shields.io/github/stars/bomberfish/AbsoluteSolver-iOS.svg) ![forks](https://img.shields.io/github/forks/bomberfish/AbsoluteSolver-iOS.svg)
- [https://github.com/bomberfish/DirtyCowKit](https://github.com/bomberfish/DirtyCowKit) :  ![starts](https://img.shields.io/github/stars/bomberfish/DirtyCowKit.svg) ![forks](https://img.shields.io/github/forks/bomberfish/DirtyCowKit.svg)
- [https://github.com/bomberfish/JailedCement](https://github.com/bomberfish/JailedCement) :  ![starts](https://img.shields.io/github/stars/bomberfish/JailedCement.svg) ![forks](https://img.shields.io/github/forks/bomberfish/JailedCement.svg)


## CVE-2022-46463
 An access control issue in Harbor v1.X.X to v2.5.3 allows attackers to access public and private image repositories without authentication. NOTE: the vendor's position is that this "is clearly described in the documentation as a feature."

- [https://github.com/sevbandonmez/harbor-stalker](https://github.com/sevbandonmez/harbor-stalker) :  ![starts](https://img.shields.io/github/stars/sevbandonmez/harbor-stalker.svg) ![forks](https://img.shields.io/github/forks/sevbandonmez/harbor-stalker.svg)


## CVE-2022-4556
 A vulnerability was found in Alinto SOGo up to 5.7.1 and classified as problematic. Affected by this issue is the function _migrateMailIdentities of the file SoObjects/SOGo/SOGoUserDefaults.m of the component Identity Handler. The manipulation of the argument fullName leads to cross site scripting. The attack may be launched remotely. Upgrading to version 5.8.0 is able to address this issue. The name of the patch is efac49ae91a4a325df9931e78e543f707a0f8e5e. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-215960.

- [https://github.com/AshkanRafiee/CVE-2022-4556](https://github.com/AshkanRafiee/CVE-2022-4556) :  ![starts](https://img.shields.io/github/stars/AshkanRafiee/CVE-2022-4556.svg) ![forks](https://img.shields.io/github/forks/AshkanRafiee/CVE-2022-4556.svg)


## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/NUDTTAN91/Webmin-CVE-2022-0824-Enhanced-Exploit](https://github.com/NUDTTAN91/Webmin-CVE-2022-0824-Enhanced-Exploit) :  ![starts](https://img.shields.io/github/stars/NUDTTAN91/Webmin-CVE-2022-0824-Enhanced-Exploit.svg) ![forks](https://img.shields.io/github/forks/NUDTTAN91/Webmin-CVE-2022-0824-Enhanced-Exploit.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/tvdat20004/CVE-2020-0688](https://github.com/tvdat20004/CVE-2020-0688) :  ![starts](https://img.shields.io/github/stars/tvdat20004/CVE-2020-0688.svg) ![forks](https://img.shields.io/github/forks/tvdat20004/CVE-2020-0688.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/M-Abid34/CVE-2018-7600](https://github.com/M-Abid34/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/M-Abid34/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/M-Abid34/CVE-2018-7600.svg)

