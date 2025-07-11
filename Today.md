# Update 2025-07-11
## CVE-2025-52357
 Cross-Site Scripting (XSS) vulnerability exists in the ping diagnostic feature of FiberHome FD602GW-DX-R410 router (firmware V2.2.14), allowing an authenticated attacker to execute arbitrary JavaScript code in the context of the router s web interface. The vulnerability is triggered via user-supplied input in the ping form field, which fails to sanitize special characters. This can be exploited to hijack sessions or escalate privileges through social engineering or browser-based attacks.

- [https://github.com/wrathfulDiety/CVE-2025-52357](https://github.com/wrathfulDiety/CVE-2025-52357) :  ![starts](https://img.shields.io/github/stars/wrathfulDiety/CVE-2025-52357.svg) ![forks](https://img.shields.io/github/forks/wrathfulDiety/CVE-2025-52357.svg)


## CVE-2025-49719
 Improper input validation in SQL Server allows an unauthorized attacker to disclose information over a network.

- [https://github.com/HExploited/CVE-2025-49719-Exploit](https://github.com/HExploited/CVE-2025-49719-Exploit) :  ![starts](https://img.shields.io/github/stars/HExploited/CVE-2025-49719-Exploit.svg) ![forks](https://img.shields.io/github/forks/HExploited/CVE-2025-49719-Exploit.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/liamg/CVE-2025-48384](https://github.com/liamg/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/liamg/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/liamg/CVE-2025-48384.svg)
- [https://github.com/fishyyh/CVE-2025-48384](https://github.com/fishyyh/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/fishyyh/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/fishyyh/CVE-2025-48384.svg)
- [https://github.com/ppd520/CVE-2025-48384](https://github.com/ppd520/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/ppd520/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/ppd520/CVE-2025-48384.svg)
- [https://github.com/liamg/CVE-2025-48384-submodule](https://github.com/liamg/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/liamg/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/liamg/CVE-2025-48384-submodule.svg)
- [https://github.com/fishyyh/CVE-2025-48384-POC](https://github.com/fishyyh/CVE-2025-48384-POC) :  ![starts](https://img.shields.io/github/stars/fishyyh/CVE-2025-48384-POC.svg) ![forks](https://img.shields.io/github/forks/fishyyh/CVE-2025-48384-POC.svg)
- [https://github.com/kallydev/cve-2025-48384-hook](https://github.com/kallydev/cve-2025-48384-hook) :  ![starts](https://img.shields.io/github/stars/kallydev/cve-2025-48384-hook.svg) ![forks](https://img.shields.io/github/forks/kallydev/cve-2025-48384-hook.svg)


## CVE-2025-34085
 An unrestricted file upload vulnerability in the WordPress Simple File List plugin prior to version 4.2.3 allows unauthenticated remote attackers to achieve remote code execution. The plugin's upload endpoint (ee-upload-engine.php) restricts file uploads based on extension, but lacks proper validation after file renaming. An attacker can first upload a PHP payload disguised as a .png file, then use the plugin’s ee-file-engine.php rename functionality to change the extension to .php. This bypasses upload restrictions and results in the uploaded payload being executable on the server.

- [https://github.com/MrjHaxcore/CVE-2025-](https://github.com/MrjHaxcore/CVE-2025-) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2025-.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2025-.svg)


## CVE-2025-34077
 An authentication bypass vulnerability exists in the WordPress Pie Register plugin ≤ 3.7.1.4 that allows unauthenticated attackers to impersonate arbitrary users by submitting a crafted POST request to the login endpoint. By setting social_site=true and manipulating the user_id_social_site parameter, an attacker can generate a valid WordPress session cookie for any user ID, including administrators. Once authenticated, the attacker may exploit plugin upload functionality to install a malicious plugin containing arbitrary PHP code, resulting in remote code execution on the underlying server.

- [https://github.com/MrjHaxcore/CVE-2025-34077](https://github.com/MrjHaxcore/CVE-2025-34077) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2025-34077.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2025-34077.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/0xb0rn3/CVE-2025-32463-EXPLOIT](https://github.com/0xb0rn3/CVE-2025-32463-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/0xb0rn3/CVE-2025-32463-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/0xb0rn3/CVE-2025-32463-EXPLOIT.svg)


## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32023](https://github.com/B1ack4sh/Blackash-CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32023.svg)


## CVE-2025-21574
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Parser).  Supported versions that are affected are 8.0.0-8.0.41, 8.4.0-8.4.4 and  9.0.0-9.2.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/mdriaz009/CVE-2025-21574-Exploit](https://github.com/mdriaz009/CVE-2025-21574-Exploit) :  ![starts](https://img.shields.io/github/stars/mdriaz009/CVE-2025-21574-Exploit.svg) ![forks](https://img.shields.io/github/forks/mdriaz009/CVE-2025-21574-Exploit.svg)


## CVE-2025-6970
 The Events Manager – Calendar, Bookings, Tickets, and more! plugin for WordPress is vulnerable to time-based SQL Injection via the ‘orderby’ parameter in all versions up to, and including, 7.0.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2025-6970](https://github.com/RandomRobbieBF/CVE-2025-6970) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-6970.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-6970.svg)


## CVE-2025-6759
 Local Privilege escalation allows a low-privileged user to gain SYSTEM privileges in Windows Virtual Delivery Agent for CVAD and Citrix DaaS

- [https://github.com/olljanat/TestCitrixException](https://github.com/olljanat/TestCitrixException) :  ![starts](https://img.shields.io/github/stars/olljanat/TestCitrixException.svg) ![forks](https://img.shields.io/github/forks/olljanat/TestCitrixException.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ghostn4444/POC-CVE-2025-6554](https://github.com/ghostn4444/POC-CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/ghostn4444/POC-CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/POC-CVE-2025-6554.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/FrenzisRed/CVE-2025-5777](https://github.com/FrenzisRed/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/FrenzisRed/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/FrenzisRed/CVE-2025-5777.svg)


## CVE-2025-4507
 A vulnerability classified as critical has been found in Campcodes Online Food Ordering System 1.0. This affects an unknown part of the file /routers/add-item.php. The manipulation of the argument price leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/yogeswaran6383/CVE-2025-45072](https://github.com/yogeswaran6383/CVE-2025-45072) :  ![starts](https://img.shields.io/github/stars/yogeswaran6383/CVE-2025-45072.svg) ![forks](https://img.shields.io/github/forks/yogeswaran6383/CVE-2025-45072.svg)


## CVE-2024-42008
 A Cross-Site Scripting vulnerability in rcmail_action_mail_get-run() in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a malicious e-mail attachment served with a dangerous Content-Type header.

- [https://github.com/rpgsec/Roundcube-CVE-2024-42008-POC](https://github.com/rpgsec/Roundcube-CVE-2024-42008-POC) :  ![starts](https://img.shields.io/github/stars/rpgsec/Roundcube-CVE-2024-42008-POC.svg) ![forks](https://img.shields.io/github/forks/rpgsec/Roundcube-CVE-2024-42008-POC.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2022-0169
 The Photo Gallery by 10Web WordPress plugin before 1.6.0 does not validate and escape the bwg_tag_id_bwg_thumbnails_0 parameter before using it in a SQL statement via the bwg_frontend_data AJAX action (available to unauthenticated and authenticated users), leading to an unauthenticated SQL injection

- [https://github.com/X3RX3SSec/CVE-2022-0169](https://github.com/X3RX3SSec/CVE-2022-0169) :  ![starts](https://img.shields.io/github/stars/X3RX3SSec/CVE-2022-0169.svg) ![forks](https://img.shields.io/github/forks/X3RX3SSec/CVE-2022-0169.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/titusG85/SideWinder-Exploit](https://github.com/titusG85/SideWinder-Exploit) :  ![starts](https://img.shields.io/github/stars/titusG85/SideWinder-Exploit.svg) ![forks](https://img.shields.io/github/forks/titusG85/SideWinder-Exploit.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint](https://github.com/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint.svg)

