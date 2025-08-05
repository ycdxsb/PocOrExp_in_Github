# Update 2025-08-05
## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/beishanxueyuan/CVE-2025-48384](https://github.com/beishanxueyuan/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/beishanxueyuan/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/beishanxueyuan/CVE-2025-48384.svg)
- [https://github.com/fluoworite/CVE-2025-48384-sub](https://github.com/fluoworite/CVE-2025-48384-sub) :  ![starts](https://img.shields.io/github/stars/fluoworite/CVE-2025-48384-sub.svg) ![forks](https://img.shields.io/github/forks/fluoworite/CVE-2025-48384-sub.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/Infinit3i/CVE-2025-24893](https://github.com/Infinit3i/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Infinit3i/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Infinit3i/CVE-2025-24893.svg)
- [https://github.com/AliElKhatteb/CVE-2024-32019-POC](https://github.com/AliElKhatteb/CVE-2024-32019-POC) :  ![starts](https://img.shields.io/github/stars/AliElKhatteb/CVE-2024-32019-POC.svg) ![forks](https://img.shields.io/github/forks/AliElKhatteb/CVE-2024-32019-POC.svg)
- [https://github.com/hackersonsteroids/cve-2025-24893](https://github.com/hackersonsteroids/cve-2025-24893) :  ![starts](https://img.shields.io/github/stars/hackersonsteroids/cve-2025-24893.svg) ![forks](https://img.shields.io/github/forks/hackersonsteroids/cve-2025-24893.svg)
- [https://github.com/dhiaZnaidi/CVE-2025-24893-PoC](https://github.com/dhiaZnaidi/CVE-2025-24893-PoC) :  ![starts](https://img.shields.io/github/stars/dhiaZnaidi/CVE-2025-24893-PoC.svg) ![forks](https://img.shields.io/github/forks/dhiaZnaidi/CVE-2025-24893-PoC.svg)


## CVE-2025-8471
 A vulnerability, which was classified as critical, has been found in projectworlds Online Admission System 1.0. This issue affects some unknown processing of the file /adminlogin.php. The manipulation of the argument a_id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/byteReaper77/CVE-2025-8471](https://github.com/byteReaper77/CVE-2025-8471) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8471.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8471.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/gmh5225/CVE-2025-6554](https://github.com/gmh5225/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-6554.svg)


## CVE-2024-38041
 Windows Kernel Information Disclosure Vulnerability

- [https://github.com/dgkim-dong/CVE-2024-38041](https://github.com/dgkim-dong/CVE-2024-38041) :  ![starts](https://img.shields.io/github/stars/dgkim-dong/CVE-2024-38041.svg) ![forks](https://img.shields.io/github/forks/dgkim-dong/CVE-2024-38041.svg)


## CVE-2024-35250
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/CrackerCat/CVE-2024-35250](https://github.com/CrackerCat/CVE-2024-35250) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2024-35250.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2024-35250.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/AliElKhatteb/CVE-2024-32019-POC](https://github.com/AliElKhatteb/CVE-2024-32019-POC) :  ![starts](https://img.shields.io/github/stars/AliElKhatteb/CVE-2024-32019-POC.svg) ![forks](https://img.shields.io/github/forks/AliElKhatteb/CVE-2024-32019-POC.svg)
- [https://github.com/AzureADTrent/CVE-2024-32019-POC](https://github.com/AzureADTrent/CVE-2024-32019-POC) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2024-32019-POC.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2024-32019-POC.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/dkstar11q/CVE-2024-26229-lpe](https://github.com/dkstar11q/CVE-2024-26229-lpe) :  ![starts](https://img.shields.io/github/stars/dkstar11q/CVE-2024-26229-lpe.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/CVE-2024-26229-lpe.svg)


## CVE-2024-21338
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/wusijie/CVE-2024-21338-1](https://github.com/wusijie/CVE-2024-21338-1) :  ![starts](https://img.shields.io/github/stars/wusijie/CVE-2024-21338-1.svg) ![forks](https://img.shields.io/github/forks/wusijie/CVE-2024-21338-1.svg)


## CVE-2024-10793
 The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the user_id parameter in all versions up to, and including, 5.2.1 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever an administrative user accesses an injected page.

- [https://github.com/djayaGit/CVE-2024-10793](https://github.com/djayaGit/CVE-2024-10793) :  ![starts](https://img.shields.io/github/stars/djayaGit/CVE-2024-10793.svg) ![forks](https://img.shields.io/github/forks/djayaGit/CVE-2024-10793.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/MihranGIT/CVE-2024-4367](https://github.com/MihranGIT/CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/MihranGIT/CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/MihranGIT/CVE-2024-4367.svg)
- [https://github.com/MihranGIT/POC_CVE-2024-4367](https://github.com/MihranGIT/POC_CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/MihranGIT/POC_CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/MihranGIT/POC_CVE-2024-4367.svg)


## CVE-2024-2782
 The Contact Form Plugin by Fluent Forms for Quiz, Survey, and Drag & Drop WP Form Builder plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the /wp-json/fluentform/v1/global-settings REST API endpoint in all versions up to, and including, 5.1.16. This makes it possible for unauthenticated attackers to modify all of the plugin's settings.

- [https://github.com/whale93/CVE-2024-2782-PoC](https://github.com/whale93/CVE-2024-2782-PoC) :  ![starts](https://img.shields.io/github/stars/whale93/CVE-2024-2782-PoC.svg) ![forks](https://img.shields.io/github/forks/whale93/CVE-2024-2782-PoC.svg)


## CVE-2024-2771
 The Contact Form Plugin by Fluent Forms for Quiz, Survey, and Drag & Drop WP Form Builder plugin for WordPress is vulnerable to privilege escalation due to a missing capability check on the /wp-json/fluentform/v1/managers REST API endpoint in all versions up to, and including, 5.1.16. This makes it possible for unauthenticated attackers to grant users with Fluent Form management permissions which gives them access to all of the plugin's settings and features. This also makes it possible for unauthenticated attackers to delete manager accounts.

- [https://github.com/whale93/CVE-2024-2771-PoC](https://github.com/whale93/CVE-2024-2771-PoC) :  ![starts](https://img.shields.io/github/stars/whale93/CVE-2024-2771-PoC.svg) ![forks](https://img.shields.io/github/forks/whale93/CVE-2024-2771-PoC.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/Tolu12wani/Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution](https://github.com/Tolu12wani/Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution) :  ![starts](https://img.shields.io/github/stars/Tolu12wani/Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution.svg) ![forks](https://img.shields.io/github/forks/Tolu12wani/Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution.svg)


## CVE-2023-34039
 Aria Operations for Networks contains an Authentication Bypass vulnerability due to a lack of unique cryptographic key generation. A malicious actor with network access to Aria Operations for Networks could bypass SSH authentication to gain access to the Aria Operations for Networks CLI.

- [https://github.com/ayb-blc/metasploit-cve2023-34039-disclosure](https://github.com/ayb-blc/metasploit-cve2023-34039-disclosure) :  ![starts](https://img.shields.io/github/stars/ayb-blc/metasploit-cve2023-34039-disclosure.svg) ![forks](https://img.shields.io/github/forks/ayb-blc/metasploit-cve2023-34039-disclosure.svg)


## CVE-2023-0461
We recommend upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c

- [https://github.com/b1nhack/CVE-2023-0461](https://github.com/b1nhack/CVE-2023-0461) :  ![starts](https://img.shields.io/github/stars/b1nhack/CVE-2023-0461.svg) ![forks](https://img.shields.io/github/forks/b1nhack/CVE-2023-0461.svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/Sabecomoeh/CVE-2013-3900](https://github.com/Sabecomoeh/CVE-2013-3900) :  ![starts](https://img.shields.io/github/stars/Sabecomoeh/CVE-2013-3900.svg) ![forks](https://img.shields.io/github/forks/Sabecomoeh/CVE-2013-3900.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/SincIDK/CVE-2012-2982-Exploit-Script](https://github.com/SincIDK/CVE-2012-2982-Exploit-Script) :  ![starts](https://img.shields.io/github/stars/SincIDK/CVE-2012-2982-Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/SincIDK/CVE-2012-2982-Exploit-Script.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/LOCK-0N/CVE-2011-2523](https://github.com/LOCK-0N/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/LOCK-0N/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/LOCK-0N/CVE-2011-2523.svg)


## CVE-2003-0282
 Directory traversal vulnerability in UnZip 5.50 allows attackers to overwrite arbitrary files via invalid characters between two . (dot) characters, which are filtered and result in a ".." sequence.

- [https://github.com/sion-codin/cve-2003-0282](https://github.com/sion-codin/cve-2003-0282) :  ![starts](https://img.shields.io/github/stars/sion-codin/cve-2003-0282.svg) ![forks](https://img.shields.io/github/forks/sion-codin/cve-2003-0282.svg)

