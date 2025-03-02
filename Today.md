# Update 2025-03-02
## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.

- [https://github.com/rxerium/CVE-2025-26466](https://github.com/rxerium/CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26466.svg)
- [https://github.com/jhonnybonny/CVE-2025-26466](https://github.com/jhonnybonny/CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2025-26466.svg)
- [https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg)


## CVE-2025-26326
 A vulnerability in the remote connection complements of the NVDA (Nonvisual Desktop Access) 2024.4.1 and 2024.4.2 was identified, which allows an attacker to obtain total control of the remote system when guessing a weak password. The problem occurs because the complements accept any password typed by the user and do not have an additional authentication or checking mechanism by the computer that will be accessed. Tests indicate that over 1,000 systems use easy to guess passwords, many with less than 4 to 6 characters, including common sequences. This enables brute strength or attempt and error attacks on the part of malicious invaders. Vulnerability can be explored by a remote striker who knows or can guess the password used in the connection. As a result, the invader gets complete access to the affected system and can run commands, modify files and compromise user security.

- [https://github.com/azurejoga/CVE-2025-26326](https://github.com/azurejoga/CVE-2025-26326) :  ![starts](https://img.shields.io/github/stars/azurejoga/CVE-2025-26326.svg) ![forks](https://img.shields.io/github/forks/azurejoga/CVE-2025-26326.svg)


## CVE-2025-26263
 GeoVision ASManager Windows desktop application with the version 6.1.2.0 or less, is vulnerable to credentials disclosure due to improper memory handling in the ASManagerService.exe process.

- [https://github.com/DRAGOWN/CVE-2025-26263](https://github.com/DRAGOWN/CVE-2025-26263) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2025-26263.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2025-26263.svg)


## CVE-2025-25461
 A Stored Cross-Site Scripting (XSS) vulnerability exists in SeedDMS 6.0.29. A user or rogue admin with the "Add Category" permission can inject a malicious XSS payload into the category name field. When a document is subsequently associated with this category, the payload is stored on the server and rendered without proper sanitization or output encoding. This results in the XSS payload executing in the browser of any user who views the document.

- [https://github.com/RoNiXxCybSeC0101/CVE-2025-25461](https://github.com/RoNiXxCybSeC0101/CVE-2025-25461) :  ![starts](https://img.shields.io/github/stars/RoNiXxCybSeC0101/CVE-2025-25461.svg) ![forks](https://img.shields.io/github/forks/RoNiXxCybSeC0101/CVE-2025-25461.svg)


## CVE-2024-47051
  *  Path Traversal File Deletion: A Path Traversal vulnerability exists in the upload validation process. Due to improper handling of path components, an authenticated user can manipulate the file deletion process to delete arbitrary files on the host system.

- [https://github.com/mallo-m/CVE-2024-47051](https://github.com/mallo-m/CVE-2024-47051) :  ![starts](https://img.shields.io/github/stars/mallo-m/CVE-2024-47051.svg) ![forks](https://img.shields.io/github/forks/mallo-m/CVE-2024-47051.svg)


## CVE-2024-10605
 A vulnerability was found in code-projects Blood Bank Management System 1.0. It has been classified as problematic. This affects an unknown part of the file /file/request.php. The manipulation leads to cross-site request forgery. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xbeven/CVE-2024-10605](https://github.com/0xbeven/CVE-2024-10605) :  ![starts](https://img.shields.io/github/stars/0xbeven/CVE-2024-10605.svg) ![forks](https://img.shields.io/github/forks/0xbeven/CVE-2024-10605.svg)


## CVE-2024-10557
 A vulnerability has been found in code-projects Blood Bank Management System 1.0 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file /file/updateprofile.php. The manipulation leads to cross-site request forgery. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xbeven/CVE-2024-10557](https://github.com/0xbeven/CVE-2024-10557) :  ![starts](https://img.shields.io/github/stars/0xbeven/CVE-2024-10557.svg) ![forks](https://img.shields.io/github/forks/0xbeven/CVE-2024-10557.svg)


## CVE-2024-10448
 A vulnerability, which was classified as problematic, has been found in code-projects Blood Bank Management System 1.0. Affected by this issue is some unknown functionality of the file /file/delete.php. The manipulation of the argument bid leads to cross-site request forgery. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Other endpoints might be affected as well.

- [https://github.com/0xbeven/CVE-2024-10448](https://github.com/0xbeven/CVE-2024-10448) :  ![starts](https://img.shields.io/github/stars/0xbeven/CVE-2024-10448.svg) ![forks](https://img.shields.io/github/forks/0xbeven/CVE-2024-10448.svg)


## CVE-2024-5143
 A user with device administrative privileges can change existing SMTP server settings on the device, without having to re-enter SMTP server credentials.  By redirecting send-to-email traffic to the new server, the original SMTP server credentials may potentially be exposed.

- [https://github.com/0xbeven/CVE-2024-51435](https://github.com/0xbeven/CVE-2024-51435) :  ![starts](https://img.shields.io/github/stars/0xbeven/CVE-2024-51435.svg) ![forks](https://img.shields.io/github/forks/0xbeven/CVE-2024-51435.svg)


## CVE-2023-6199
 Book Stack version 23.10.2 allows filtering local files on the server. This is possible because the application is vulnerable to SSRF.

- [https://github.com/AbdrrahimDahmani/php_filter_chains_oracle_exploit_for_CVE-2023-6199](https://github.com/AbdrrahimDahmani/php_filter_chains_oracle_exploit_for_CVE-2023-6199) :  ![starts](https://img.shields.io/github/stars/AbdrrahimDahmani/php_filter_chains_oracle_exploit_for_CVE-2023-6199.svg) ![forks](https://img.shields.io/github/forks/AbdrrahimDahmani/php_filter_chains_oracle_exploit_for_CVE-2023-6199.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/z92g/CVE-2022-21661](https://github.com/z92g/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/z92g/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/z92g/CVE-2022-21661.svg)
- [https://github.com/purple-WL/wordpress-CVE-2022-21661](https://github.com/purple-WL/wordpress-CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/purple-WL/wordpress-CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/purple-WL/wordpress-CVE-2022-21661.svg)
- [https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection](https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg)
- [https://github.com/0x4E0x650x6F/Wordpress-cve-CVE-2022-21661](https://github.com/0x4E0x650x6F/Wordpress-cve-CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/0x4E0x650x6F/Wordpress-cve-CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/0x4E0x650x6F/Wordpress-cve-CVE-2022-21661.svg)
- [https://github.com/guestzz/CVE-2022-21661](https://github.com/guestzz/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/guestzz/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/guestzz/CVE-2022-21661.svg)
- [https://github.com/WellingtonEspindula/SSI-CVE-2022-21661](https://github.com/WellingtonEspindula/SSI-CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/WellingtonEspindula/SSI-CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/WellingtonEspindula/SSI-CVE-2022-21661.svg)
- [https://github.com/sealldeveloper/CVE-2022-21661-PoC](https://github.com/sealldeveloper/CVE-2022-21661-PoC) :  ![starts](https://img.shields.io/github/stars/sealldeveloper/CVE-2022-21661-PoC.svg) ![forks](https://img.shields.io/github/forks/sealldeveloper/CVE-2022-21661-PoC.svg)
- [https://github.com/daniel616/CVE-2022-21661-Demo](https://github.com/daniel616/CVE-2022-21661-Demo) :  ![starts](https://img.shields.io/github/stars/daniel616/CVE-2022-21661-Demo.svg) ![forks](https://img.shields.io/github/forks/daniel616/CVE-2022-21661-Demo.svg)
- [https://github.com/safe3s/CVE-2022-21661](https://github.com/safe3s/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/safe3s/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/safe3s/CVE-2022-21661.svg)
- [https://github.com/p4ncontomat3/CVE-2022-21661](https://github.com/p4ncontomat3/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/p4ncontomat3/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/p4ncontomat3/CVE-2022-21661.svg)
- [https://github.com/w0r1i0g1ht/CVE-2022-21661](https://github.com/w0r1i0g1ht/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/w0r1i0g1ht/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/w0r1i0g1ht/CVE-2022-21661.svg)
- [https://github.com/kittypurrnaz/cve-2022-21661](https://github.com/kittypurrnaz/cve-2022-21661) :  ![starts](https://img.shields.io/github/stars/kittypurrnaz/cve-2022-21661.svg) ![forks](https://img.shields.io/github/forks/kittypurrnaz/cve-2022-21661.svg)
- [https://github.com/CharonDefalt/WordPress--CVE-2022-21661](https://github.com/CharonDefalt/WordPress--CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/CharonDefalt/WordPress--CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/CharonDefalt/WordPress--CVE-2022-21661.svg)


## CVE-2019-1003030
 A sandbox bypass vulnerability exists in Jenkins Pipeline: Groovy Plugin 2.63 and earlier in pom.xml, src/main/java/org/jenkinsci/plugins/workflow/cps/CpsGroovyShell.java that allows attackers able to control pipeline scripts to execute arbitrary code on the Jenkins master JVM.

- [https://github.com/overgrowncarrot1/CVE-2019-1003030](https://github.com/overgrowncarrot1/CVE-2019-1003030) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/CVE-2019-1003030.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/CVE-2019-1003030.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/clarkvoss/telerik](https://github.com/clarkvoss/telerik) :  ![starts](https://img.shields.io/github/stars/clarkvoss/telerik.svg) ![forks](https://img.shields.io/github/forks/clarkvoss/telerik.svg)

