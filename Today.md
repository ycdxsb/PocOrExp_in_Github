# Update 2025-07-17
## CVE-2025-53833
 LaRecipe is an application that allows users to create documentation with Markdown inside a Laravel app. Versions prior to 2.8.1 are vulnerable to Server-Side Template Injection (SSTI), which could potentially lead to Remote Code Execution (RCE) in vulnerable configurations. Attackers could execute arbitrary commands on the server, access sensitive environment variables, and/or escalate access depending on server configuration. Users are strongly advised to upgrade to version v2.8.1 or later to receive a patch.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-53833](https://github.com/B1ack4sh/Blackash-CVE-2025-53833) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53833.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53833.svg)


## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/tristanvandermeer/CVE-2025-49144-Test](https://github.com/tristanvandermeer/CVE-2025-49144-Test) :  ![starts](https://img.shields.io/github/stars/tristanvandermeer/CVE-2025-49144-Test.svg) ![forks](https://img.shields.io/github/forks/tristanvandermeer/CVE-2025-49144-Test.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/ECHO6789/CVE-2025-48384-submodule](https://github.com/ECHO6789/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/ECHO6789/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/ECHO6789/CVE-2025-48384-submodule.svg)


## CVE-2025-47981
 Heap-based buffer overflow in Windows SPNEGO Extended Negotiation allows an unauthorized attacker to execute code over a network.

- [https://github.com/detectrespondrepeat/CVE-2025-47981](https://github.com/detectrespondrepeat/CVE-2025-47981) :  ![starts](https://img.shields.io/github/stars/detectrespondrepeat/CVE-2025-47981.svg) ![forks](https://img.shields.io/github/forks/detectrespondrepeat/CVE-2025-47981.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/MohamedKarrab/CVE-2025-32463](https://github.com/MohamedKarrab/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/MohamedKarrab/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/MohamedKarrab/CVE-2025-32463.svg)
- [https://github.com/9Insomnie/CVE-2025-32463](https://github.com/9Insomnie/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/9Insomnie/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/9Insomnie/CVE-2025-32463.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591](https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591.svg)
- [https://github.com/DarksBlackSk/CVE-2025-27591](https://github.com/DarksBlackSk/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/DarksBlackSk/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/DarksBlackSk/CVE-2025-27591.svg)


## CVE-2025-23167
* This vulnerability affects only Node.js 20.x users prior to the `llhttp` v9 upgrade.

- [https://github.com/abhisek3122/CVE-2025-23167](https://github.com/abhisek3122/CVE-2025-23167) :  ![starts](https://img.shields.io/github/stars/abhisek3122/CVE-2025-23167.svg) ![forks](https://img.shields.io/github/forks/abhisek3122/CVE-2025-23167.svg)


## CVE-2025-7340
 The HT Contact Form Widget For Elementor Page Builder & Gutenberg Blocks & Form Builder. plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the temp_file_upload function in all versions up to, and including, 2.2.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-7340](https://github.com/Nxploited/CVE-2025-7340) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7340.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7340.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/SleepNotF0und/CVE-2025-5777](https://github.com/SleepNotF0und/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/SleepNotF0und/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/SleepNotF0und/CVE-2025-5777.svg)


## CVE-2025-5349
 Improper access control on the NetScaler Management Interface in NetScaler ADC and NetScaler Gateway

- [https://github.com/olimpiofreitas/CVE-2025-5349-Scanner](https://github.com/olimpiofreitas/CVE-2025-5349-Scanner) :  ![starts](https://img.shields.io/github/stars/olimpiofreitas/CVE-2025-5349-Scanner.svg) ![forks](https://img.shields.io/github/forks/olimpiofreitas/CVE-2025-5349-Scanner.svg)


## CVE-2025-2525
 The Streamit theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'st_Authentication_Controller::edit_profile' function in all versions up to, and including, 4.0.1. This makes it possible for authenticated attackers, with subscriber-level and above permissions, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/0xgh057r3c0n/CVE-2025-25257](https://github.com/0xgh057r3c0n/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-25257.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Skycritch/CVE-2024-4577](https://github.com/Skycritch/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Skycritch/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Skycritch/CVE-2024-4577.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/Micky1warrior/metabase-pre-auth-rce-poc](https://github.com/Micky1warrior/metabase-pre-auth-rce-poc) :  ![starts](https://img.shields.io/github/stars/Micky1warrior/metabase-pre-auth-rce-poc.svg) ![forks](https://img.shields.io/github/forks/Micky1warrior/metabase-pre-auth-rce-poc.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab](https://github.com/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab) :  ![starts](https://img.shields.io/github/stars/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab.svg) ![forks](https://img.shields.io/github/forks/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab.svg)


## CVE-2023-6063
 The WP Fastest Cache WordPress plugin before 1.2.2 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users.

- [https://github.com/incommatose/CVE-2023-6063-PoC](https://github.com/incommatose/CVE-2023-6063-PoC) :  ![starts](https://img.shields.io/github/stars/incommatose/CVE-2023-6063-PoC.svg) ![forks](https://img.shields.io/github/forks/incommatose/CVE-2023-6063-PoC.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS](https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS) :  ![starts](https://img.shields.io/github/stars/Rai2en/CVE-2023-4220-Chamilo-LMS.svg) ![forks](https://img.shields.io/github/forks/Rai2en/CVE-2023-4220-Chamilo-LMS.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab](https://github.com/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab) :  ![starts](https://img.shields.io/github/stars/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab.svg) ![forks](https://img.shields.io/github/forks/filippo-zullo98/phpMyAdmin-RCE-Exploit-Lab.svg)


## CVE-2022-25226
 ThinVNC version 1.0b1 allows an unauthenticated user to bypass the authentication process via 'http://thin-vnc:8080/cmd?cmd=connect' by obtaining a valid SID without any kind of authentication. It is possible to achieve code execution on the server by sending keyboard or mouse events to the server.

- [https://github.com/krill-x7/CVE-2022-25226](https://github.com/krill-x7/CVE-2022-25226) :  ![starts](https://img.shields.io/github/stars/krill-x7/CVE-2022-25226.svg) ![forks](https://img.shields.io/github/forks/krill-x7/CVE-2022-25226.svg)


## CVE-2021-40444
pstrongUPDATE/strong September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system./p

- [https://github.com/Bilal7864/Microsoft-Word](https://github.com/Bilal7864/Microsoft-Word) :  ![starts](https://img.shields.io/github/stars/Bilal7864/Microsoft-Word.svg) ![forks](https://img.shields.io/github/forks/Bilal7864/Microsoft-Word.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/deep-know/CVE-2021-4034](https://github.com/deep-know/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/deep-know/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/deep-know/CVE-2021-4034.svg)


## CVE-2016-0792
 Multiple unspecified API endpoints in Jenkins before 1.650 and LTS before 1.642.2 allow remote authenticated users to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.

- [https://github.com/gonn4cry/CVE-2016-0792](https://github.com/gonn4cry/CVE-2016-0792) :  ![starts](https://img.shields.io/github/stars/gonn4cry/CVE-2016-0792.svg) ![forks](https://img.shields.io/github/forks/gonn4cry/CVE-2016-0792.svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/malaya-m/cve-2013-3900-remediation-report](https://github.com/malaya-m/cve-2013-3900-remediation-report) :  ![starts](https://img.shields.io/github/stars/malaya-m/cve-2013-3900-remediation-report.svg) ![forks](https://img.shields.io/github/forks/malaya-m/cve-2013-3900-remediation-report.svg)

