# Update 2025-09-05
## CVE-2025-56803
 Figma Desktop for Windows version 125.6.5 contains a command injection vulnerability in the local plugin loader. An attacker can execute arbitrary OS commands by setting a crafted build field in the plugin's manifest.json. This field is passed to child_process.exec without validation, leading to possible RCE.

- [https://github.com/shinyColumn/CVE-2025-56803](https://github.com/shinyColumn/CVE-2025-56803) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56803.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56803.svg)


## CVE-2025-56608
 The SourceCodester Android application "Corona Virus Tracker App India" 1.0 uses MD5 for digest authentication in `OkHttpClientWrapper.java`. The `handleDigest()` function employs `MessageDigest.getInstance("MD5")` to hash credentials. MD5 is a broken cryptographic algorithm known to allow hash collisions. This makes the authentication mechanism vulnerable to replay, spoofing, or brute-force attacks, potentially leading to unauthorized access. The vulnerability corresponds to CWE-327 and aligns with OWASP M5: Insufficient Cryptography and MASVS MSTG-CRYPTO-4.

- [https://github.com/anonaninda/Aninda-security-advisories](https://github.com/anonaninda/Aninda-security-advisories) :  ![starts](https://img.shields.io/github/stars/anonaninda/Aninda-security-advisories.svg) ![forks](https://img.shields.io/github/forks/anonaninda/Aninda-security-advisories.svg)


## CVE-2025-56435
 SQL Injection vulnerability in FoxCMS v1.2.6 and before allows a remote attacker to execute arbitrary code via the. file /DataBackup.php and the operation on the parameter id.

- [https://github.com/Jingyi-u/-CVE-2025-56435](https://github.com/Jingyi-u/-CVE-2025-56435) :  ![starts](https://img.shields.io/github/stars/Jingyi-u/-CVE-2025-56435.svg) ![forks](https://img.shields.io/github/forks/Jingyi-u/-CVE-2025-56435.svg)


## CVE-2025-53694
 Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Sitecore Sitecore Experience Manager (XM), Sitecore Experience Platform (XP).This issue affects Sitecore Experience Manager (XM): from 9.2 through 10.4; Experience Platform (XP): from 9.2 through 10.4.

- [https://github.com/blueisbeautiful/CVE-2025-53694](https://github.com/blueisbeautiful/CVE-2025-53694) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg)


## CVE-2025-53693
 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') vulnerability in Sitecore Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Cache Poisoning.This issue affects Sitecore Experience Manager (XM): from 9.0 through 9.3, from 10.0 through 10.4; Experience Platform (XP): from 9.0 through 9.3, from 10.0 through 10.4.

- [https://github.com/blueisbeautiful/CVE-2025-53693](https://github.com/blueisbeautiful/CVE-2025-53693) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53693.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53693.svg)


## CVE-2025-53691
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Remote Code Execution (RCE).This issue affects Experience Manager (XM): from 9.0 through 9.3, from 10.0 through 10.4; Experience Platform (XP): from 9.0 through 9.3, from 10.0 through 10.4.

- [https://github.com/blueisbeautiful/CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53691.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg)


## CVE-2025-45805
 In phpgurukul Doctor Appointment Management System 1.0, an authenticated doctor user can inject arbitrary JavaScript code into their profile name. This payload is subsequently rendered without proper sanitization, when a user visits the website and selects the doctor to book an appointment.

- [https://github.com/mhsinj/CVE-2025-45805](https://github.com/mhsinj/CVE-2025-45805) :  ![starts](https://img.shields.io/github/stars/mhsinj/CVE-2025-45805.svg) ![forks](https://img.shields.io/github/forks/mhsinj/CVE-2025-45805.svg)


## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Sonoma 14.7.8, macOS Ventura 13.7.8, iPadOS 17.7.10, macOS Sequoia 15.6.1, iOS 18.6.2 and iPadOS 18.6.2. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.

- [https://github.com/PwnToday/CVE-2025-43300](https://github.com/PwnToday/CVE-2025-43300) :  ![starts](https://img.shields.io/github/stars/PwnToday/CVE-2025-43300.svg) ![forks](https://img.shields.io/github/forks/PwnToday/CVE-2025-43300.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/HOEUN-Visai/CVE-2025-27591-below-](https://github.com/HOEUN-Visai/CVE-2025-27591-below-) :  ![starts](https://img.shields.io/github/stars/HOEUN-Visai/CVE-2025-27591-below-.svg) ![forks](https://img.shields.io/github/forks/HOEUN-Visai/CVE-2025-27591-below-.svg)


## CVE-2025-27480
 Use after free in Remote Desktop Gateway Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/mrk336/CVE-2025-27480](https://github.com/mrk336/CVE-2025-27480) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-27480.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-27480.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/b0ySie7e/CVE-2025-24893](https://github.com/b0ySie7e/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/b0ySie7e/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/b0ySie7e/CVE-2025-24893.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/CEAlbez/CVE-2025-24813-PoC](https://github.com/CEAlbez/CVE-2025-24813-PoC) :  ![starts](https://img.shields.io/github/stars/CEAlbez/CVE-2025-24813-PoC.svg) ![forks](https://img.shields.io/github/forks/CEAlbez/CVE-2025-24813-PoC.svg)
- [https://github.com/Olabanji10/Apache-GOExploiter](https://github.com/Olabanji10/Apache-GOExploiter) :  ![starts](https://img.shields.io/github/stars/Olabanji10/Apache-GOExploiter.svg) ![forks](https://img.shields.io/github/forks/Olabanji10/Apache-GOExploiter.svg)


## CVE-2025-22131
 PhpSpreadsheet is a PHP library for reading and writing spreadsheet files. Cross-Site Scripting (XSS) vulnerability in the code which translates the XLSX file into a HTML representation and displays it in the response.

- [https://github.com/ZzN1NJ4/CVE-2025-22131-PoC](https://github.com/ZzN1NJ4/CVE-2025-22131-PoC) :  ![starts](https://img.shields.io/github/stars/ZzN1NJ4/CVE-2025-22131-PoC.svg) ![forks](https://img.shields.io/github/forks/ZzN1NJ4/CVE-2025-22131-PoC.svg)


## CVE-2025-20682
 In wlan AP driver, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation. Patch ID: WCNCR00416937; Issue ID: MSV-3445.

- [https://github.com/Reeadmon/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk](https://github.com/Reeadmon/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk) :  ![starts](https://img.shields.io/github/stars/Reeadmon/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg) ![forks](https://img.shields.io/github/forks/Reeadmon/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/j3r1ch0123/CVE-2025-9074](https://github.com/j3r1ch0123/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/j3r1ch0123/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/j3r1ch0123/CVE-2025-9074.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/harshitvarma05/CVE-2025-6019](https://github.com/harshitvarma05/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/harshitvarma05/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/harshitvarma05/CVE-2025-6019.svg)


## CVE-2025-5599
 A vulnerability classified as critical was found in PHPGurukul Student Result Management System 1.3. This vulnerability affects unknown code of the file /editmyexp.php. The manipulation of the argument emp1ctc leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Ocmenog/CVE-2025-55998](https://github.com/Ocmenog/CVE-2025-55998) :  ![starts](https://img.shields.io/github/stars/Ocmenog/CVE-2025-55998.svg) ![forks](https://img.shields.io/github/forks/Ocmenog/CVE-2025-55998.svg)


## CVE-2025-5252
 A vulnerability was found in PHPGurukul News Portal Project 4.1. It has been declared as critical. This vulnerability affects unknown code of the file /admin/edit-subadmin.php. The manipulation of the argument emailid leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/aydin5245/CVE-2025-5252-CVE-ivanti](https://github.com/aydin5245/CVE-2025-5252-CVE-ivanti) :  ![starts](https://img.shields.io/github/stars/aydin5245/CVE-2025-5252-CVE-ivanti.svg) ![forks](https://img.shields.io/github/forks/aydin5245/CVE-2025-5252-CVE-ivanti.svg)


## CVE-2025-5238
 The YITH WooCommerce Wishlist plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘id’ parameter in all versions up to, and including, 4.5.0 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/milamrk/CVE-2025-52389](https://github.com/milamrk/CVE-2025-52389) :  ![starts](https://img.shields.io/github/stars/milamrk/CVE-2025-52389.svg) ![forks](https://img.shields.io/github/forks/milamrk/CVE-2025-52389.svg)


## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.

- [https://github.com/ImBIOS/lab-cve-2025-3515](https://github.com/ImBIOS/lab-cve-2025-3515) :  ![starts](https://img.shields.io/github/stars/ImBIOS/lab-cve-2025-3515.svg) ![forks](https://img.shields.io/github/forks/ImBIOS/lab-cve-2025-3515.svg)


## CVE-2025-2082
The specific flaw exists within the VCSEC module. By manipulating the certificate response sent from the Tire Pressure Monitoring System (TPMS), an attacker can trigger an integer overflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the VCSEC module and send arbitrary messages to the vehicle CAN bus. Was ZDI-CAN-23800.

- [https://github.com/shirabo/cve-2025-2082-POV](https://github.com/shirabo/cve-2025-2082-POV) :  ![starts](https://img.shields.io/github/stars/shirabo/cve-2025-2082-POV.svg) ![forks](https://img.shields.io/github/forks/shirabo/cve-2025-2082-POV.svg)


## CVE-2025-0288
 Various Paragon Software products contain an arbitrary kernel memory vulnerability within biontdrv.sys, facilitated by the memmove function, which does not validate or sanitize user controlled input, allowing an attacker the ability to write arbitrary kernel memory and perform privilege escalation.

- [https://github.com/barhen12/CVE-2025-0288](https://github.com/barhen12/CVE-2025-0288) :  ![starts](https://img.shields.io/github/stars/barhen12/CVE-2025-0288.svg) ![forks](https://img.shields.io/github/forks/barhen12/CVE-2025-0288.svg)


## CVE-2024-32444
 Incorrect Privilege Assignment vulnerability in InspiryThemes RealHomes allows Privilege Escalation.This issue affects RealHomes: from n/a through 4.3.6.

- [https://github.com/rxerium/CVE-2024-32444](https://github.com/rxerium/CVE-2024-32444) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-32444.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-32444.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/ykhurshudyan-blip/CVE-2024-3094](https://github.com/ykhurshudyan-blip/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/ykhurshudyan-blip/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/ykhurshudyan-blip/CVE-2024-3094.svg)


## CVE-2023-37070
 Code Projects Hospital Information System 1.0 is vulnerable to Cross Site Scripting (XSS)

- [https://github.com/riteshs4hu/My-CVE](https://github.com/riteshs4hu/My-CVE) :  ![starts](https://img.shields.io/github/stars/riteshs4hu/My-CVE.svg) ![forks](https://img.shields.io/github/forks/riteshs4hu/My-CVE.svg)


## CVE-2023-37069
 Code-Projects Online Hospital Management System V1.0 is vulnerable to SQL Injection (SQLI) attacks, which allow an attacker to manipulate the SQL queries executed by the application. The application fails to properly validate user-supplied input in the login id and password fields during the login process, enabling an attacker to inject malicious SQL code.

- [https://github.com/riteshs4hu/My-CVE](https://github.com/riteshs4hu/My-CVE) :  ![starts](https://img.shields.io/github/stars/riteshs4hu/My-CVE.svg) ![forks](https://img.shields.io/github/forks/riteshs4hu/My-CVE.svg)


## CVE-2023-37068
 Code-Projects Gym Management System V1.0 allows remote attackers to execute arbitrary SQL commands via the login form, leading to unauthorized access and potential data manipulation. This vulnerability arises due to insufficient validation of user-supplied input in the username and password fields, enabling SQL Injection attacks.

- [https://github.com/riteshs4hu/My-CVE](https://github.com/riteshs4hu/My-CVE) :  ![starts](https://img.shields.io/github/stars/riteshs4hu/My-CVE.svg) ![forks](https://img.shields.io/github/forks/riteshs4hu/My-CVE.svg)

