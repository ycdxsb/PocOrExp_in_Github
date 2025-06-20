# Update 2025-06-20
## CVE-2025-49619
 Skyvern through 0.1.85 is vulnerable to server-side template injection (SSTI) in the Prompt field of workflow blocks such as the Navigation v2 Block. Improper sanitization of Jinja2 template input allows authenticated users to inject crafted expressions that are evaluated on the server, leading to blind remote code execution (RCE).

- [https://github.com/cristibtz/CVE-2025-49619](https://github.com/cristibtz/CVE-2025-49619) :  ![starts](https://img.shields.io/github/stars/cristibtz/CVE-2025-49619.svg) ![forks](https://img.shields.io/github/forks/cristibtz/CVE-2025-49619.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/punitdarji/roundcube-cve-2025-49113](https://github.com/punitdarji/roundcube-cve-2025-49113) :  ![starts](https://img.shields.io/github/stars/punitdarji/roundcube-cve-2025-49113.svg) ![forks](https://img.shields.io/github/forks/punitdarji/roundcube-cve-2025-49113.svg)


## CVE-2025-46157
 An issue in EfroTech Time Trax v.1.0 allows a remote attacker to execute arbitrary code via the file attachment function in the leave request form

- [https://github.com/morphine009/CVE-2025-46157](https://github.com/morphine009/CVE-2025-46157) :  ![starts](https://img.shields.io/github/stars/morphine009/CVE-2025-46157.svg) ![forks](https://img.shields.io/github/forks/morphine009/CVE-2025-46157.svg)


## CVE-2025-33053
 External control of file name or path in WebDAV allows an unauthorized attacker to execute code over a network.

- [https://github.com/TheTorjanCaptain/CVE-2025-33053-Checker-PoC](https://github.com/TheTorjanCaptain/CVE-2025-33053-Checker-PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2025-33053-Checker-PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2025-33053-Checker-PoC.svg)
- [https://github.com/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept](https://github.com/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept) :  ![starts](https://img.shields.io/github/stars/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept.svg) ![forks](https://img.shields.io/github/forks/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept.svg)


## CVE-2025-32710
 Use after free in Windows Remote Desktop Services allows an unauthorized attacker to execute code over a network.

- [https://github.com/Sincan2/RCE-CVE-2025-32710](https://github.com/Sincan2/RCE-CVE-2025-32710) :  ![starts](https://img.shields.io/github/stars/Sincan2/RCE-CVE-2025-32710.svg) ![forks](https://img.shields.io/github/forks/Sincan2/RCE-CVE-2025-32710.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/CTY-Research-1/CVE-2025-32432-PoC](https://github.com/CTY-Research-1/CVE-2025-32432-PoC) :  ![starts](https://img.shields.io/github/stars/CTY-Research-1/CVE-2025-32432-PoC.svg) ![forks](https://img.shields.io/github/forks/CTY-Research-1/CVE-2025-32432-PoC.svg)


## CVE-2025-26198
 CloudClassroom-PHP-Project v.1.0 is vulnerable to SQL Injection in loginlinkadmin.php, allowing unauthenticated attackers to bypass authentication and gain administrative access. The application fails to properly sanitize user inputs before constructing SQL queries, enabling an attacker to manipulate database queries via specially crafted payloads

- [https://github.com/tansique-17/CVE-2025-26198](https://github.com/tansique-17/CVE-2025-26198) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-26198.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-26198.svg)


## CVE-2025-6220
 The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'save_options' function in all versions up to, and including, 3.5.12. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-6220](https://github.com/d0n601/CVE-2025-6220) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6220.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6220.svg)


## CVE-2025-4420
 The Vayu Blocks – Gutenberg Blocks for WordPress & WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘containerWidth’ parameter in all versions up to, and including, 1.3.1 due to a missing capability check on the vayu_blocks_option_panel_callback() function and insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Subscriber-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/IvanT7D3/CVE-2025-44203](https://github.com/IvanT7D3/CVE-2025-44203) :  ![starts](https://img.shields.io/github/stars/IvanT7D3/CVE-2025-44203.svg) ![forks](https://img.shields.io/github/forks/IvanT7D3/CVE-2025-44203.svg)


## CVE-2025-3248
code.

- [https://github.com/0xgh057r3c0n/CVE-2025-3248](https://github.com/0xgh057r3c0n/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-3248.svg)
- [https://github.com/imbas007/CVE-2025-3248](https://github.com/imbas007/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-3248.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/aninfosec/CVE-2025-1094](https://github.com/aninfosec/CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/aninfosec/CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/aninfosec/CVE-2025-1094.svg)


## CVE-2025-0133
For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.

- [https://github.com/wiseep/CVE-2025-0133](https://github.com/wiseep/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/wiseep/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/wiseep/CVE-2025-0133.svg)


## CVE-2023-26136
 Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode. This issue arises from the manner in which the objects are initialized.

- [https://github.com/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix](https://github.com/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix) :  ![starts](https://img.shields.io/github/stars/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix.svg) ![forks](https://img.shields.io/github/forks/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix.svg)


## CVE-2023-6401
 A vulnerability classified as problematic was found in NotePad++ up to 8.1. Affected by this vulnerability is an unknown functionality of the file dbghelp.exe. The manipulation leads to uncontrolled search path. An attack has to be approached locally. The identifier VDB-246421 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/mekitoci/CVE-2023-6401](https://github.com/mekitoci/CVE-2023-6401) :  ![starts](https://img.shields.io/github/stars/mekitoci/CVE-2023-6401.svg) ![forks](https://img.shields.io/github/forks/mekitoci/CVE-2023-6401.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/bchevCH/CVE-2023-0386](https://github.com/bchevCH/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/bchevCH/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/bchevCH/CVE-2023-0386.svg)


## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.

- [https://github.com/MuhammadWaseem29/cve-2022-41352](https://github.com/MuhammadWaseem29/cve-2022-41352) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/cve-2022-41352.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/cve-2022-41352.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/NanoTrash/hikvision_brute](https://github.com/NanoTrash/hikvision_brute) :  ![starts](https://img.shields.io/github/stars/NanoTrash/hikvision_brute.svg) ![forks](https://img.shields.io/github/forks/NanoTrash/hikvision_brute.svg)


## CVE-2019-16891
 Liferay Portal CE 6.2.5 allows remote command execution because of deserialization of a JSON payload.

- [https://github.com/hrxknight/CVE-2019-16891-Liferay-deserialization-RCE](https://github.com/hrxknight/CVE-2019-16891-Liferay-deserialization-RCE) :  ![starts](https://img.shields.io/github/stars/hrxknight/CVE-2019-16891-Liferay-deserialization-RCE.svg) ![forks](https://img.shields.io/github/forks/hrxknight/CVE-2019-16891-Liferay-deserialization-RCE.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/bayazid-bit/CVE-2019-15107](https://github.com/bayazid-bit/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/bayazid-bit/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/bayazid-bit/CVE-2019-15107.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/bayazid-bit/CVE-2019-11043-](https://github.com/bayazid-bit/CVE-2019-11043-) :  ![starts](https://img.shields.io/github/stars/bayazid-bit/CVE-2019-11043-.svg) ![forks](https://img.shields.io/github/forks/bayazid-bit/CVE-2019-11043-.svg)


## CVE-2018-25031
 Swagger UI 4.1.2 and earlier could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions. Note: This was originally claimed to be resolved in 4.1.3. However, third parties have indicated this is not resolved in 4.1.3 and even occurs in that version and possibly others.

- [https://github.com/rasinfosec/CVE-2018-25031](https://github.com/rasinfosec/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/rasinfosec/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/rasinfosec/CVE-2018-25031.svg)
- [https://github.com/h4ckt0m/CVE-2018-25031-test](https://github.com/h4ckt0m/CVE-2018-25031-test) :  ![starts](https://img.shields.io/github/stars/h4ckt0m/CVE-2018-25031-test.svg) ![forks](https://img.shields.io/github/forks/h4ckt0m/CVE-2018-25031-test.svg)


## CVE-2015-1578
 Multiple open redirect vulnerabilities in u5CMS before 3.9.4 allow remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the (1) pidvesa cookie to u5admin/pidvesa.php or (2) uri parameter to u5admin/meta2.php.

- [https://github.com/yaldobaoth/CVE-2015-1578-PoC](https://github.com/yaldobaoth/CVE-2015-1578-PoC) :  ![starts](https://img.shields.io/github/stars/yaldobaoth/CVE-2015-1578-PoC.svg) ![forks](https://img.shields.io/github/forks/yaldobaoth/CVE-2015-1578-PoC.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/lghost256/vsftpd234-exploit](https://github.com/lghost256/vsftpd234-exploit) :  ![starts](https://img.shields.io/github/stars/lghost256/vsftpd234-exploit.svg) ![forks](https://img.shields.io/github/forks/lghost256/vsftpd234-exploit.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2](https://github.com/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2) :  ![starts](https://img.shields.io/github/stars/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2.svg) ![forks](https://img.shields.io/github/forks/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2.svg)

