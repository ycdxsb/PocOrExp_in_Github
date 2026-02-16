# Update 2026-02-16
## CVE-2026-26335
 Calero VeraSMART versions prior to 2022 R1 use static ASP.NET/IIS machineKey values configured for the VeraSMART web application and stored in C:\\Program Files (x86)\\Veramark\\VeraSMART\\WebRoot\\web.config. An attacker who obtains these keys can craft a valid ASP.NET ViewState payload that passes integrity validation and is accepted by the application, resulting in server-side deserialization and remote code execution in the context of the IIS application.

- [https://github.com/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE](https://github.com/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE.svg)


## CVE-2026-25676
 The installer of M-Track Duo HD version 1.0.0 contains an issue with the DLL search path, which may lead to insecurely loading Dynamic Link Libraries. As a result, arbitrary code may be executed with administrator privileges.

- [https://github.com/Nexxus67/cve-2026-25676](https://github.com/Nexxus67/cve-2026-25676) :  ![starts](https://img.shields.io/github/stars/Nexxus67/cve-2026-25676.svg) ![forks](https://img.shields.io/github/forks/Nexxus67/cve-2026-25676.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/tiborscholtz/CVE-2026-24061](https://github.com/tiborscholtz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/tiborscholtz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/tiborscholtz/CVE-2026-24061.svg)


## CVE-2026-21533
 Improper privilege management in Windows Remote Desktop allows an authorized attacker to elevate privileges locally.

- [https://github.com/elvin31thai/CVE-2026-21533](https://github.com/elvin31thai/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/elvin31thai/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/elvin31thai/CVE-2026-21533.svg)
- [https://github.com/jenniferreire26/CVE-2026-21533](https://github.com/jenniferreire26/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/jenniferreire26/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/jenniferreire26/CVE-2026-21533.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS 26.3, tvOS 26.3, macOS Tahoe 26.3, visionOS 26.3, iOS 26.3 and iPadOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/kimblehardwoods/CVE-2026-20700](https://github.com/kimblehardwoods/CVE-2026-20700) :  ![starts](https://img.shields.io/github/stars/kimblehardwoods/CVE-2026-20700.svg) ![forks](https://img.shields.io/github/forks/kimblehardwoods/CVE-2026-20700.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/cybertechajju/CVE-2026-1357-POC](https://github.com/cybertechajju/CVE-2026-1357-POC) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2026-1357-POC.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2026-1357-POC.svg)


## CVE-2026-1306
 The midi-Synth plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type and file extension validation in the 'export' AJAX action in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible granted the attacker can obtain a valid nonce. The nonce is exposed in frontend JavaScript making it trivially accessible to unauthenticated attackers.

- [https://github.com/richardpaimu34/CVE-2026-1306](https://github.com/richardpaimu34/CVE-2026-1306) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-1306.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-1306.svg)


## CVE-2025-61638
This issue affects MediaWiki: from * before 1.39.14, 1.43.4, 1.44.1; Parsoid: from * before 0.16.6, 0.20.4, 0.21.1.

- [https://github.com/gui-ying233/CVE-2025-61638](https://github.com/gui-ying233/CVE-2025-61638) :  ![starts](https://img.shields.io/github/stars/gui-ying233/CVE-2025-61638.svg) ![forks](https://img.shields.io/github/forks/gui-ying233/CVE-2025-61638.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/malw0re/CVE-2025-49132-Mods](https://github.com/malw0re/CVE-2025-49132-Mods) :  ![starts](https://img.shields.io/github/stars/malw0re/CVE-2025-49132-Mods.svg) ![forks](https://img.shields.io/github/forks/malw0re/CVE-2025-49132-Mods.svg)


## CVE-2025-8572
 The Truelysell Core plugin for WordPress is vulnerable to privilege escalation in versions less than, or equal to, 1.8.7. This is due to insufficient validation of the user_role parameter during user registration. This makes it possible for unauthenticated attackers to create accounts with elevated privileges, including administrator access.

- [https://github.com/richardpaimu34/CVE-2025-8572](https://github.com/richardpaimu34/CVE-2025-8572) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2025-8572.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2025-8572.svg)


## CVE-2025-6575
 Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Dolusoft Omaspot allows Reflected XSS.This issue affects Omaspot: before 12.09.2025.

- [https://github.com/diegovargasj/CVE-2025-65753](https://github.com/diegovargasj/CVE-2025-65753) :  ![starts](https://img.shields.io/github/stars/diegovargasj/CVE-2025-65753.svg) ![forks](https://img.shields.io/github/forks/diegovargasj/CVE-2025-65753.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/JM00NJ/CVE-2025-6019-udisks2-XFS-Resize-TOCTOU-Privilege-Escalation](https://github.com/JM00NJ/CVE-2025-6019-udisks2-XFS-Resize-TOCTOU-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/JM00NJ/CVE-2025-6019-udisks2-XFS-Resize-TOCTOU-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/JM00NJ/CVE-2025-6019-udisks2-XFS-Resize-TOCTOU-Privilege-Escalation.svg)
- [https://github.com/MaxKappa/opensuse-leap-privesc-exploit](https://github.com/MaxKappa/opensuse-leap-privesc-exploit) :  ![starts](https://img.shields.io/github/stars/MaxKappa/opensuse-leap-privesc-exploit.svg) ![forks](https://img.shields.io/github/forks/MaxKappa/opensuse-leap-privesc-exploit.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/MaxKappa/opensuse-leap-privesc-exploit](https://github.com/MaxKappa/opensuse-leap-privesc-exploit) :  ![starts](https://img.shields.io/github/stars/MaxKappa/opensuse-leap-privesc-exploit.svg) ![forks](https://img.shields.io/github/forks/MaxKappa/opensuse-leap-privesc-exploit.svg)


## CVE-2025-2304
When a user wishes to change his password, the 'updated_ajax' method of the UsersController is called. The vulnerability stems from the use of the dangerous permit! method, which allows all parameters to pass through without any filtering.

- [https://github.com/MAEN1-prog/CVE-2025-2304](https://github.com/MAEN1-prog/CVE-2025-2304) :  ![starts](https://img.shields.io/github/stars/MAEN1-prog/CVE-2025-2304.svg) ![forks](https://img.shields.io/github/forks/MAEN1-prog/CVE-2025-2304.svg)
- [https://github.com/MAEN1-prog/maen1-prog.github.io](https://github.com/MAEN1-prog/maen1-prog.github.io) :  ![starts](https://img.shields.io/github/stars/MAEN1-prog/maen1-prog.github.io.svg) ![forks](https://img.shields.io/github/forks/MAEN1-prog/maen1-prog.github.io.svg)


## CVE-2025-1234
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/SimoesCTT/CVE-2025-1234-RSA-Key-Validation-Bypass](https://github.com/SimoesCTT/CVE-2025-1234-RSA-Key-Validation-Bypass) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CVE-2025-1234-RSA-Key-Validation-Bypass.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CVE-2025-1234-RSA-Key-Validation-Bypass.svg)


## CVE-2024-37383
 Roundcube Webmail before 1.5.7 and 1.6.x before 1.6.7 allows XSS via SVG animate attributes.

- [https://github.com/hyungin0505/CVE-2024-37383_PoC](https://github.com/hyungin0505/CVE-2024-37383_PoC) :  ![starts](https://img.shields.io/github/stars/hyungin0505/CVE-2024-37383_PoC.svg) ![forks](https://img.shields.io/github/forks/hyungin0505/CVE-2024-37383_PoC.svg)


## CVE-2023-42824
 The issue was addressed with improved checks. This issue is fixed in iOS 16.7.1 and iPadOS 16.7.1. A local attacker may be able to elevate their privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.6.

- [https://github.com/619555798/cve-2023-42824](https://github.com/619555798/cve-2023-42824) :  ![starts](https://img.shields.io/github/stars/619555798/cve-2023-42824.svg) ![forks](https://img.shields.io/github/forks/619555798/cve-2023-42824.svg)


## CVE-2023-20052
 This vulnerability is due to enabling XML entity substitution that may result in XML external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file that may be read by the ClamAV scanning process.

- [https://github.com/MOHITSINGHPAPOLA/CVE-2023-20052](https://github.com/MOHITSINGHPAPOLA/CVE-2023-20052) :  ![starts](https://img.shields.io/github/stars/MOHITSINGHPAPOLA/CVE-2023-20052.svg) ![forks](https://img.shields.io/github/forks/MOHITSINGHPAPOLA/CVE-2023-20052.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier  and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/scrt/cve-2022-42475](https://github.com/scrt/cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/scrt/cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/scrt/cve-2022-42475.svg)
- [https://github.com/0xhaggis/CVE-2022-42475](https://github.com/0xhaggis/CVE-2022-42475) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2022-42475.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2022-42475.svg)
- [https://github.com/P4x1s/CVE-2022-42475-RCE-POC](https://github.com/P4x1s/CVE-2022-42475-RCE-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2022-42475-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2022-42475-RCE-POC.svg)
- [https://github.com/Amir-hy/cve-2022-42475](https://github.com/Amir-hy/cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/Amir-hy/cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/Amir-hy/cve-2022-42475.svg)
- [https://github.com/Mustafa1986/cve-2022-42475-Fortinet](https://github.com/Mustafa1986/cve-2022-42475-Fortinet) :  ![starts](https://img.shields.io/github/stars/Mustafa1986/cve-2022-42475-Fortinet.svg) ![forks](https://img.shields.io/github/forks/Mustafa1986/cve-2022-42475-Fortinet.svg)
- [https://github.com/bryanster/ioc-cve-2022-42475](https://github.com/bryanster/ioc-cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/bryanster/ioc-cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/bryanster/ioc-cve-2022-42475.svg)
- [https://github.com/natceil/cve-2022-42475](https://github.com/natceil/cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/natceil/cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/natceil/cve-2022-42475.svg)


## CVE-2020-14144
 The git hook feature in Gitea 1.1.0 through 1.12.5 might allow for authenticated remote code execution in customer environments where the documentation was not understood (e.g., one viewpoint is that the dangerousness of this feature should be documented immediately above the ENABLE_GIT_HOOKS line in the config file). NOTE: The vendor has indicated this is not a vulnerability and states "This is a functionality of the software that is limited to a very limited subset of accounts. If you give someone the privilege to execute arbitrary code on your server, they can execute arbitrary code on your server. We provide very clear warnings to users around this functionality and what it provides.

- [https://github.com/Mohnad-AL-saif/Gitea-Git-Hooks-RCE-CVE-2020-14144-](https://github.com/Mohnad-AL-saif/Gitea-Git-Hooks-RCE-CVE-2020-14144-) :  ![starts](https://img.shields.io/github/stars/Mohnad-AL-saif/Gitea-Git-Hooks-RCE-CVE-2020-14144-.svg) ![forks](https://img.shields.io/github/forks/Mohnad-AL-saif/Gitea-Git-Hooks-RCE-CVE-2020-14144-.svg)


## CVE-2020-11022
 In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/okni2k/HW-Pyton-10](https://github.com/okni2k/HW-Pyton-10) :  ![starts](https://img.shields.io/github/stars/okni2k/HW-Pyton-10.svg) ![forks](https://img.shields.io/github/forks/okni2k/HW-Pyton-10.svg)


## CVE-2017-6736
   There are workarounds that address these vulnerabilities.

- [https://github.com/msztankowski/CiscoIOSSNMPToolkit](https://github.com/msztankowski/CiscoIOSSNMPToolkit) :  ![starts](https://img.shields.io/github/stars/msztankowski/CiscoIOSSNMPToolkit.svg) ![forks](https://img.shields.io/github/forks/msztankowski/CiscoIOSSNMPToolkit.svg)


## CVE-2014-4688
 pfSense before 2.1.4 allows remote authenticated users to execute arbitrary commands via (1) the hostname value to diag_dns.php in a Create Alias action, (2) the smartmonemail value to diag_smart.php, or (3) the database value to status_rrd_graph_img.php.

- [https://github.com/jaydenblair/CVE-2014-4688-pfsense](https://github.com/jaydenblair/CVE-2014-4688-pfsense) :  ![starts](https://img.shields.io/github/stars/jaydenblair/CVE-2014-4688-pfsense.svg) ![forks](https://img.shields.io/github/forks/jaydenblair/CVE-2014-4688-pfsense.svg)


## CVE-2009-3999
 Stack-based buffer overflow in goform/formExportDataLogs in HP Power Manager before 4.2.10 allows remote attackers to execute arbitrary code via a long fileName parameter.

- [https://github.com/afifudinmtop/CVE-2009-3999](https://github.com/afifudinmtop/CVE-2009-3999) :  ![starts](https://img.shields.io/github/stars/afifudinmtop/CVE-2009-3999.svg) ![forks](https://img.shields.io/github/forks/afifudinmtop/CVE-2009-3999.svg)


## CVE-2008-0600
 The vmsplice_to_pipe function in Linux kernel 2.6.17 through 2.6.24.1 does not validate a certain userspace pointer before dereference, which allows local users to gain root privileges via crafted arguments in a vmsplice system call, a different vulnerability than CVE-2008-0009 and CVE-2008-0010.

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/r0tn3x/CVE-2007-2447](https://github.com/r0tn3x/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/r0tn3x/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/r0tn3x/CVE-2007-2447.svg)

