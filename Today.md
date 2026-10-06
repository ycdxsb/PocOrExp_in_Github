# Update 2026-10-06
## CVE-2026-104991
 Phproject before 1.8.7 contains a missing object-level authorization vulnerability in the REST API issue endpoints (single_get, single_comments, single_comments_post) that allows authenticated API key holders to bypass the security.restrict_access confidentiality control by never invoking the allowAccess() authorization routine. Attackers can use a valid API key to read restricted issue contents and comments, including owner and author email addresses, and post unauthorized comments to issues they should not have access to.

- [https://github.com/wvllxe/CVE-2026-104991](https://github.com/wvllxe/CVE-2026-104991) :  ![starts](https://img.shields.io/github/stars/wvllxe/CVE-2026-104991.svg) ![forks](https://img.shields.io/github/forks/wvllxe/CVE-2026-104991.svg)


## CVE-2026-103355
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Unlimited Elements Unlimited Elements For Elementor (Free Widgets, Addons, Templates) unlimited-elements-for-elementor allows Blind SQL Injection.This issue affects Unlimited Elements For Elementor (Free Widgets, Addons, Templates): from n/a through 2.0.20.

- [https://github.com/Hassham1/CVE-2026-103355-unlimited-elements-sqli-poc](https://github.com/Hassham1/CVE-2026-103355-unlimited-elements-sqli-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-103355-unlimited-elements-sqli-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-103355-unlimited-elements-sqli-poc.svg)


## CVE-2026-96451
 Authorization Bypass Through User-Controlled Key vulnerability in Ultimate Member Ultimate Member ultimate-member allows Privilege Escalation.This issue affects Ultimate Member: from n/a through 2.13.1.

- [https://github.com/Nxploited/CVE-2026-96451](https://github.com/Nxploited/CVE-2026-96451) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-96451.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-96451.svg)


## CVE-2026-92084
 The The Beaver Builder Page Builder – Drag and Drop Website Builder plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 2.11.0.5. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes. Exploitation requires the target site to have a Beaver Builder page containing the Sidebar module populated with a widget that displays attacker-controllable text, such as the core Recent Comments widget, with comment moderation disabled or the attacker's comment approved.

- [https://github.com/Hassham1/CVE-2026-92084-beaver-builder-shortcode-poc](https://github.com/Hassham1/CVE-2026-92084-beaver-builder-shortcode-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-92084-beaver-builder-shortcode-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-92084-beaver-builder-shortcode-poc.svg)


## CVE-2026-88779
This issue affects ADC: before 14.1-73.41, before 13.1-64.28, before 14.1-73.41 FIPS, and before 13.1-37.282; Gateway: before 14.1-73.41 and before 13.1-64.28.

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)
- [https://github.com/orjanj/netscaler_threat_hunt_helper](https://github.com/orjanj/netscaler_threat_hunt_helper) :  ![starts](https://img.shields.io/github/stars/orjanj/netscaler_threat_hunt_helper.svg) ![forks](https://img.shields.io/github/forks/orjanj/netscaler_threat_hunt_helper.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/LETHAL-FORENSICS/Get-NetScalerTimeline](https://github.com/LETHAL-FORENSICS/Get-NetScalerTimeline) :  ![starts](https://img.shields.io/github/stars/LETHAL-FORENSICS/Get-NetScalerTimeline.svg) ![forks](https://img.shields.io/github/forks/LETHAL-FORENSICS/Get-NetScalerTimeline.svg)


## CVE-2026-83627
 The Hummingbird – Speed Optimization, Caching, Minify, Compress & CDN plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 3.21.0 via the log_msg() function in core/modules/class-page-cache.php. The page-cache debug log is written to wp-content/wphb-logs/page-caching-log.php, a directly web-accessible PHP file that is supposed to be protected by a leading '?php die(); ?' header. That header is guarded by class_exists( 'Filesystem' ), which can never match because class_exists() resolves string arguments in the global namespace while the class is Hummingbird\Core\Filesystem; when the log is created during a front-end request the header is therefore omitted entirely. get_cookies() then writes the raw name of any cookie matching the wphb_cache_ prefix into that file without sanitization. This makes it possible for unauthenticated attackers to write arbitrary PHP into the log file with a single anonymous request and execute it by requesting the file directly, resulting in full remote code execution. Exploitation requires the site administrator to have enabled Page Caching with the Debug Log option (non-default), and the log file to be created during a front-end request — a state reached by the plugin's own 'Clear logs' action, any cache flush, or unattended via the plugin's daily log-rotation cron, which can strip the protective header from an existing log file.

- [https://github.com/K52-ai/CVE-2026-83627](https://github.com/K52-ai/CVE-2026-83627) :  ![starts](https://img.shields.io/github/stars/K52-ai/CVE-2026-83627.svg) ![forks](https://img.shields.io/github/forks/K52-ai/CVE-2026-83627.svg)


## CVE-2026-65640
This issue affects all versions of WordPress. Version 7.0.4 has been released, containing a fix for the vulnerability, and as a courtesy to users on older branches the fix has been backported to all branches back to 4.7.

- [https://github.com/aufanfauzi/CVE-2026-65640](https://github.com/aufanfauzi/CVE-2026-65640) :  ![starts](https://img.shields.io/github/stars/aufanfauzi/CVE-2026-65640.svg) ![forks](https://img.shields.io/github/forks/aufanfauzi/CVE-2026-65640.svg)


## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.

- [https://github.com/rabakuku/CVE-2026-40281](https://github.com/rabakuku/CVE-2026-40281) :  ![starts](https://img.shields.io/github/stars/rabakuku/CVE-2026-40281.svg) ![forks](https://img.shields.io/github/forks/rabakuku/CVE-2026-40281.svg)


## CVE-2026-19632
 The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.3.1 via the 'trp_get_translations_regular' AJAX action. This makes it possible for unauthenticated attackers to extract the raw administrator password-reset URL — including the plaintext reset key and login parameters stored in the translation dictionary table — enabling full administrator account takeover. This vulnerability is only exploitable when automatic string saving is enabled (the default setting) and the target administrator's profile locale is set to a published secondary language, as these conditions cause the password-reset URL to be persisted as a translatable string in the secondary-language dictionary table.

- [https://github.com/TheJesterrrr/CVE-2026-19632](https://github.com/TheJesterrrr/CVE-2026-19632) :  ![starts](https://img.shields.io/github/stars/TheJesterrrr/CVE-2026-19632.svg) ![forks](https://img.shields.io/github/forks/TheJesterrrr/CVE-2026-19632.svg)


## CVE-2026-15911
 Confluent Kafka Python client's HashiCorp Vault KMS integration could allow a remote attacker to obtain sensitive information due to improper TLS certificate validation.

- [https://github.com/rahulreddykarne/CVE-2026-15911-Confluent_Kafka](https://github.com/rahulreddykarne/CVE-2026-15911-Confluent_Kafka) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-15911-Confluent_Kafka.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-15911-Confluent_Kafka.svg)


## CVE-2026-13247
 The Logo Slider – Logo Carousel, Client Logo Slider & Brand Showcase for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'lgx_tooltip_position' parameter in all versions up to, and including, 5.5 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/sifatnotes/-Recon-MySQL-SSH-ICA-CVE-2026-13247-Tomcat](https://github.com/sifatnotes/-Recon-MySQL-SSH-ICA-CVE-2026-13247-Tomcat) :  ![starts](https://img.shields.io/github/stars/sifatnotes/-Recon-MySQL-SSH-ICA-CVE-2026-13247-Tomcat.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/-Recon-MySQL-SSH-ICA-CVE-2026-13247-Tomcat.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/AdminHcat/CVE-2026-43499-5.15](https://github.com/AdminHcat/CVE-2026-43499-5.15) :  ![starts](https://img.shields.io/github/stars/AdminHcat/CVE-2026-43499-5.15.svg) ![forks](https://img.shields.io/github/forks/AdminHcat/CVE-2026-43499-5.15.svg)


## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/GiZcesi/HJregsvr32](https://github.com/GiZcesi/HJregsvr32) :  ![starts](https://img.shields.io/github/stars/GiZcesi/HJregsvr32.svg) ![forks](https://img.shields.io/github/forks/GiZcesi/HJregsvr32.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/JustThinkingHard/HID-Attack](https://github.com/JustThinkingHard/HID-Attack) :  ![starts](https://img.shields.io/github/stars/JustThinkingHard/HID-Attack.svg) ![forks](https://img.shields.io/github/forks/JustThinkingHard/HID-Attack.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nianfan555/PoC-Deployer-System](https://github.com/nianfan555/PoC-Deployer-System) :  ![starts](https://img.shields.io/github/stars/nianfan555/PoC-Deployer-System.svg) ![forks](https://img.shields.io/github/forks/nianfan555/PoC-Deployer-System.svg)


## CVE-2024-30088
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/repo4Chu/CVE-2024-30088__Windows-TOCTOU-exploit](https://github.com/repo4Chu/CVE-2024-30088__Windows-TOCTOU-exploit) :  ![starts](https://img.shields.io/github/stars/repo4Chu/CVE-2024-30088__Windows-TOCTOU-exploit.svg) ![forks](https://img.shields.io/github/forks/repo4Chu/CVE-2024-30088__Windows-TOCTOU-exploit.svg)


## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/mustafaakalin/CVE-2024-9465](https://github.com/mustafaakalin/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/mustafaakalin/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/mustafaakalin/CVE-2024-9465.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/s4m98/CVE-2023-23752](https://github.com/s4m98/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/s4m98/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/s4m98/CVE-2023-23752.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/gotr00t0day/CVE-2022-40684](https://github.com/gotr00t0day/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2022-40684.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/fulxey/CVE-2022-0543](https://github.com/fulxey/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/fulxey/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/fulxey/CVE-2022-0543.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/sandesh9978/CVE-2021-3156-Sudo-Checker](https://github.com/sandesh9978/CVE-2021-3156-Sudo-Checker) :  ![starts](https://img.shields.io/github/stars/sandesh9978/CVE-2021-3156-Sudo-Checker.svg) ![forks](https://img.shields.io/github/forks/sandesh9978/CVE-2021-3156-Sudo-Checker.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/K52-ai/CVE-2018-7600](https://github.com/K52-ai/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/K52-ai/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/K52-ai/CVE-2018-7600.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Vijishanmugavel/metasploitable2-vsftpd-cve-2011-2523](https://github.com/Vijishanmugavel/metasploitable2-vsftpd-cve-2011-2523) :  ![starts](https://img.shields.io/github/stars/Vijishanmugavel/metasploitable2-vsftpd-cve-2011-2523.svg) ![forks](https://img.shields.io/github/forks/Vijishanmugavel/metasploitable2-vsftpd-cve-2011-2523.svg)
- [https://github.com/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs](https://github.com/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs) :  ![starts](https://img.shields.io/github/stars/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs.svg) ![forks](https://img.shields.io/github/forks/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs](https://github.com/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs) :  ![starts](https://img.shields.io/github/stars/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs.svg) ![forks](https://img.shields.io/github/forks/sagarjain0456/Metasploit-Project-using-KaliLinux-plus-Metasploitable2-VMs.svg)

