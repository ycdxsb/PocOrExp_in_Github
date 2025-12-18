# Update 2025-12-18
## CVE-2025-68116
 FileRise is a self-hosted web file manager / WebDAV server. Versions prior to 2.7.1 are vulnerable to Stored Cross-Site Scripting (XSS) due to unsafe handling of browser-renderable user uploads when served through the sharing and download endpoints. An attacker who can get a crafted SVG (primary) or HTML (secondary) file stored in a FileRise instance can cause JavaScript execution when a victim opens a generated share link (and in some cases via the direct download endpoint). This impacts share links (`/api/file/share.php`) and direct file access / download path (`/api/file/download.php`), depending on browser/content-type behavior. Version 2.7.1 fixes the issue.

- [https://github.com/x0root/CVE-2025-68116](https://github.com/x0root/CVE-2025-68116) :  ![starts](https://img.shields.io/github/stars/x0root/CVE-2025-68116.svg) ![forks](https://img.shields.io/github/forks/x0root/CVE-2025-68116.svg)


## CVE-2025-67780
 SpaceX Starlink Dish devices with firmware 2024.12.04.mr46620 (e.g., on Mini1_prod2) allow administrative actions via unauthenticated LAN gRPC requests, aka MARMALADE 2. The cross-origin policy can be bypassed by omitting a Referer header. In some cases, an attacker's ability to read tilt, rotation, and elevation data via gRPC can make it easier to infer the geographical location of the dish.

- [https://github.com/SteveAkawLabs/MARMALADE-2-CVE-2025-67780-Exploit](https://github.com/SteveAkawLabs/MARMALADE-2-CVE-2025-67780-Exploit) :  ![starts](https://img.shields.io/github/stars/SteveAkawLabs/MARMALADE-2-CVE-2025-67780-Exploit.svg) ![forks](https://img.shields.io/github/forks/SteveAkawLabs/MARMALADE-2-CVE-2025-67780-Exploit.svg)


## CVE-2025-66039
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. Versions are vulnerable to authentication bypass when the authentication type is set to "webserver." When providing an Authorization header with an arbitrary value, a session is associated with the target user regardless of valid credentials. This issue is fixed in versions 16.0.44 and 17.0.23.

- [https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025](https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025) :  ![starts](https://img.shields.io/github/stars/cyberleelawat/FreePBX-Multiple-CVEs-2025.svg) ![forks](https://img.shields.io/github/forks/cyberleelawat/FreePBX-Multiple-CVEs-2025.svg)


## CVE-2025-65427
 An issue was discovered in Dbit N300 T1 Pro Easy Setup Wireless Wi-Fi Router on firmware version V1.0.0 does not implement rate limiting to /api/login allowing attackers to brute force password enumerations.

- [https://github.com/kirubel-cve/CVE-2025-65427](https://github.com/kirubel-cve/CVE-2025-65427) :  ![starts](https://img.shields.io/github/stars/kirubel-cve/CVE-2025-65427.svg) ![forks](https://img.shields.io/github/forks/kirubel-cve/CVE-2025-65427.svg)


## CVE-2025-65319
 When using the attachment interaction functionality, Blue Mail 1.140.103 and below saves documents to a file system without a Mark-of-the-Web tag, which allows attackers to bypass the built-in file protection mechanisms of both Windows OS and third-party software.

- [https://github.com/bbaboha/CVE-2025-65318-and-CVE-2025-65319](https://github.com/bbaboha/CVE-2025-65318-and-CVE-2025-65319) :  ![starts](https://img.shields.io/github/stars/bbaboha/CVE-2025-65318-and-CVE-2025-65319.svg) ![forks](https://img.shields.io/github/forks/bbaboha/CVE-2025-65318-and-CVE-2025-65319.svg)


## CVE-2025-65318
 When using the attachment interaction functionality, Canary Mail 5.1.40 and below saves documents to a file system without a Mark-of-the-Web tag, which allows attackers to bypass the built-in file protection mechanisms of both Windows OS and third-party software.

- [https://github.com/bbaboha/CVE-2025-65318-and-CVE-2025-65319](https://github.com/bbaboha/CVE-2025-65318-and-CVE-2025-65319) :  ![starts](https://img.shields.io/github/stars/bbaboha/CVE-2025-65318-and-CVE-2025-65319.svg) ![forks](https://img.shields.io/github/forks/bbaboha/CVE-2025-65318-and-CVE-2025-65319.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/Z3YR0xX/CVE-2025-64459](https://github.com/Z3YR0xX/CVE-2025-64459) :  ![starts](https://img.shields.io/github/stars/Z3YR0xX/CVE-2025-64459.svg) ![forks](https://img.shields.io/github/forks/Z3YR0xX/CVE-2025-64459.svg)


## CVE-2025-61678
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. In versions prior to 16.0.92 for FreePBX 16 and versions prior to 17.0.6 for FreePBX 17, the Endpoint Manager module contains an authenticated arbitrary file upload vulnerability affecting the fwbrand parameter. The fwbrand parameter allows an attacker to change the file path. Combined, these issues can result in a webshell being uploaded. Authentication with a known username is required to exploit this vulnerability. Successful exploitation allows authenticated users to upload arbitrary files to attacker-controlled paths on the server, potentially leading to remote code execution. This issue has been patched in version 16.0.92 for FreePBX 16 and version 17.0.6 for FreePBX 17.

- [https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025](https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025) :  ![starts](https://img.shields.io/github/stars/cyberleelawat/FreePBX-Multiple-CVEs-2025.svg) ![forks](https://img.shields.io/github/forks/cyberleelawat/FreePBX-Multiple-CVEs-2025.svg)


## CVE-2025-61675
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. In versions prior to 16.0.92 for FreePBX 16 and versions prior to 17.0.6 for FreePBX 17, the Endpoint Manager module contains authenticated SQL injection vulnerabilities affecting multiple parameters in the basestation, model, firmware, and custom extension configuration functionality areas. Authentication with a known username is required to exploit these vulnerabilities. Successful exploitation allows authenticated users to execute arbitrary SQL queries against the database, potentially enabling access to sensitive data or modification of database contents. This issue has been patched in version 16.0.92 for FreePBX 16 and version 17.0.6 for FreePBX 17.

- [https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025](https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025) :  ![starts](https://img.shields.io/github/stars/cyberleelawat/FreePBX-Multiple-CVEs-2025.svg) ![forks](https://img.shields.io/github/forks/cyberleelawat/FreePBX-Multiple-CVEs-2025.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/Tarekhshaikh13/CVE-2025-55184](https://github.com/Tarekhshaikh13/CVE-2025-55184) :  ![starts](https://img.shields.io/github/stars/Tarekhshaikh13/CVE-2025-55184.svg) ![forks](https://img.shields.io/github/forks/Tarekhshaikh13/CVE-2025-55184.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/philparzer/nextjs-react2shell-detect](https://github.com/philparzer/nextjs-react2shell-detect) :  ![starts](https://img.shields.io/github/stars/philparzer/nextjs-react2shell-detect.svg) ![forks](https://img.shields.io/github/forks/philparzer/nextjs-react2shell-detect.svg)


## CVE-2025-54352
 WordPress 3.5 through 6.8.2 allows remote attackers to guess titles of private and draft posts via pingback.ping XML-RPC requests. NOTE: the Supplier is not changing this behavior.

- [https://github.com/crypcky/XML-RPC-Pingback-Vulnerability](https://github.com/crypcky/XML-RPC-Pingback-Vulnerability) :  ![starts](https://img.shields.io/github/stars/crypcky/XML-RPC-Pingback-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/crypcky/XML-RPC-Pingback-Vulnerability.svg)


## CVE-2025-31702
 A vulnerability exists in certain Dahua embedded products. Third-party malicious attacker with obtained normal user credentials could exploit the vulnerability to access certain data which are restricted to admin privileges, such as system-sensitive files through specific HTTP request. This may cause tampering with admin password, leading to privilege escalation. Systems with only admin account are not affected.

- [https://github.com/itres-labs/CVE-2025-31702](https://github.com/itres-labs/CVE-2025-31702) :  ![starts](https://img.shields.io/github/stars/itres-labs/CVE-2025-31702.svg) ![forks](https://img.shields.io/github/forks/itres-labs/CVE-2025-31702.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/lytianahkone-boop/cve-2025-25257](https://github.com/lytianahkone-boop/cve-2025-25257) :  ![starts](https://img.shields.io/github/stars/lytianahkone-boop/cve-2025-25257.svg) ![forks](https://img.shields.io/github/forks/lytianahkone-boop/cve-2025-25257.svg)


## CVE-2025-23339
cuobjdump.

- [https://github.com/SpiralBL0CK/ce-for-CVE-2025-23339](https://github.com/SpiralBL0CK/ce-for-CVE-2025-23339) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/ce-for-CVE-2025-23339.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/ce-for-CVE-2025-23339.svg)


## CVE-2025-6551
 A vulnerability was found in java-aodeng Hope-Boot 1.0.0 and classified as problematic. This issue affects the function Login of the file /src/main/java/com/hope/controller/WebController.java. The manipulation of the argument errorMsg leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Jainil-89/CVE-2025-65518](https://github.com/Jainil-89/CVE-2025-65518) :  ![starts](https://img.shields.io/github/stars/Jainil-89/CVE-2025-65518.svg) ![forks](https://img.shields.io/github/forks/Jainil-89/CVE-2025-65518.svg)


## CVE-2025-6527
 A vulnerability, which was classified as problematic, was found in 70mai M300 up to 20250611. Affected is an unknown function of the component Web Server. The manipulation leads to improper access controls. The attack can only be initiated within the local network. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/xh4vm/CVE-2025-65270](https://github.com/xh4vm/CVE-2025-65270) :  ![starts](https://img.shields.io/github/stars/xh4vm/CVE-2025-65270.svg) ![forks](https://img.shields.io/github/forks/xh4vm/CVE-2025-65270.svg)


## CVE-2025-6218
The specific flaw exists within the handling of file paths within archive files. A crafted file path can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-27198.

- [https://github.com/Hatchepsoute/sigma-rules](https://github.com/Hatchepsoute/sigma-rules) :  ![starts](https://img.shields.io/github/stars/Hatchepsoute/sigma-rules.svg) ![forks](https://img.shields.io/github/forks/Hatchepsoute/sigma-rules.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/NightBloodZ/CVE-2025-4123](https://github.com/NightBloodZ/CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/NightBloodZ/CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/NightBloodZ/CVE-2025-4123.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/o-sec/CVE-2024-48990](https://github.com/o-sec/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/o-sec/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/o-sec/CVE-2024-48990.svg)


## CVE-2024-43400
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. It is possible for a user without Script or Programming rights to craft a URL pointing to a page with arbitrary JavaScript. This requires social engineer to trick a user to follow the URL. This has been patched in XWiki 14.10.21, 15.5.5, 15.10.6 and 16.0.0.

- [https://github.com/rain321654/CVE-2024-43400](https://github.com/rain321654/CVE-2024-43400) :  ![starts](https://img.shields.io/github/stars/rain321654/CVE-2024-43400.svg) ![forks](https://img.shields.io/github/forks/rain321654/CVE-2024-43400.svg)


## CVE-2024-3922
 The Dokan Pro plugin for WordPress is vulnerable to SQL Injection via the 'code' parameter in all versions up to, and including, 3.10.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/truonghuuphuc/CVE-2024-3922-Poc](https://github.com/truonghuuphuc/CVE-2024-3922-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-3922-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-3922-Poc.svg)


## CVE-2024-3183
If a principal is compromised it means the attacker would be able to retrieve tickets encrypted to any principal, all of them being encrypted by their own key directly. By taking these tickets and salts offline, the attacker could run brute force attacks to find character strings able to decrypt tickets when combined to a principal salt (i.e. find the principal’s password).

- [https://github.com/Im10n/CVE-2024-3183-POC](https://github.com/Im10n/CVE-2024-3183-POC) :  ![starts](https://img.shields.io/github/stars/Im10n/CVE-2024-3183-POC.svg) ![forks](https://img.shields.io/github/forks/Im10n/CVE-2024-3183-POC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Nosie12/fire-wall-server](https://github.com/Nosie12/fire-wall-server) :  ![starts](https://img.shields.io/github/stars/Nosie12/fire-wall-server.svg) ![forks](https://img.shields.io/github/forks/Nosie12/fire-wall-server.svg)


## CVE-2022-0492
 A vulnerability was found in the Linux kernel’s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- [https://github.com/smallcat9612/CVE-2022-0492-Docker-Breakout-Checker-and-PoC](https://github.com/smallcat9612/CVE-2022-0492-Docker-Breakout-Checker-and-PoC) :  ![starts](https://img.shields.io/github/stars/smallcat9612/CVE-2022-0492-Docker-Breakout-Checker-and-PoC.svg) ![forks](https://img.shields.io/github/forks/smallcat9612/CVE-2022-0492-Docker-Breakout-Checker-and-PoC.svg)


## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

- [https://github.com/Richard1031/CVE-2017-0785-PoC](https://github.com/Richard1031/CVE-2017-0785-PoC) :  ![starts](https://img.shields.io/github/stars/Richard1031/CVE-2017-0785-PoC.svg) ![forks](https://img.shields.io/github/forks/Richard1031/CVE-2017-0785-PoC.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/Mitsu-bis/Eternal-Blue-CVE-2017-0144-THM-Write-Up](https://github.com/Mitsu-bis/Eternal-Blue-CVE-2017-0144-THM-Write-Up) :  ![starts](https://img.shields.io/github/stars/Mitsu-bis/Eternal-Blue-CVE-2017-0144-THM-Write-Up.svg) ![forks](https://img.shields.io/github/forks/Mitsu-bis/Eternal-Blue-CVE-2017-0144-THM-Write-Up.svg)


## CVE-2015-9238
 secure-compare 3.0.0 and below do not actually compare two strings properly. compare was actually comparing the first argument with itself, meaning the check passed for any two strings of the same length.

- [https://github.com/m0d0ri205/wargame-turkey_in_2](https://github.com/m0d0ri205/wargame-turkey_in_2) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/wargame-turkey_in_2.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/wargame-turkey_in_2.svg)

