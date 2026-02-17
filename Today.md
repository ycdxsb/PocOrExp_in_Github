# Update 2026-02-17
## CVE-2026-2144
 The Magic Login Mail or QR Code plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.05. This is due to the plugin storing the magic login QR code image with a predictable, static filename (QR_Code.png) in the publicly accessible WordPress uploads directory during the email sending process. The file is only deleted after wp_mail() completes, creating an exploitable race condition window. This makes it possible for unauthenticated attackers to trigger a login link request for any user, including administrators, and then exploit the race condition between QR code file creation and deletion to obtain the login URL encoded in the QR code, thereby gaining unauthorized access to the targeted user's account.

- [https://github.com/jermaine22sei/CVE-2026-2144-exploit](https://github.com/jermaine22sei/CVE-2026-2144-exploit) :  ![starts](https://img.shields.io/github/stars/jermaine22sei/CVE-2026-2144-exploit.svg) ![forks](https://img.shields.io/github/forks/jermaine22sei/CVE-2026-2144-exploit.svg)


## CVE-2026-1844
 The PixelYourSite PRO plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'pysTrafficSource' parameter and the 'pys_landing_page' parameter in all versions up to, and including, 12.4.0.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/adamshaikhma/CVE-2026-1844](https://github.com/adamshaikhma/CVE-2026-1844) :  ![starts](https://img.shields.io/github/stars/adamshaikhma/CVE-2026-1844.svg) ![forks](https://img.shields.io/github/forks/adamshaikhma/CVE-2026-1844.svg)


## CVE-2026-1490
 The Spam protection, Anti-Spam, FireWall by CleanTalk plugin for WordPress is vulnerable to unauthorized Arbitrary Plugin Installation due to an authorization bypass via reverse DNS (PTR record) spoofing on the 'checkWithoutToken' function in all versions up to, and including, 6.71. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated. Note: This is only exploitable on sites with an invalid API key.

- [https://github.com/comthompson30/CVE-2026-1490](https://github.com/comthompson30/CVE-2026-1490) :  ![starts](https://img.shields.io/github/stars/comthompson30/CVE-2026-1490.svg) ![forks](https://img.shields.io/github/forks/comthompson30/CVE-2026-1490.svg)


## CVE-2026-0745
 The User Language Switch plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 1.6.10 due to missing URL validation on the 'download_language()' function. This makes it possible for authenticated attackers, with Administrator-level access and above, to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services.

- [https://github.com/blackhatlegend/CVE-2026-0745](https://github.com/blackhatlegend/CVE-2026-0745) :  ![starts](https://img.shields.io/github/stars/blackhatlegend/CVE-2026-0745.svg) ![forks](https://img.shields.io/github/forks/blackhatlegend/CVE-2026-0745.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/RavinduRathnayaka/CVE-2025-55182-PoC](https://github.com/RavinduRathnayaka/CVE-2025-55182-PoC) :  ![starts](https://img.shields.io/github/stars/RavinduRathnayaka/CVE-2025-55182-PoC.svg) ![forks](https://img.shields.io/github/forks/RavinduRathnayaka/CVE-2025-55182-PoC.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/rippsec/CVE-2025-49132](https://github.com/rippsec/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/rippsec/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/rippsec/CVE-2025-49132.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/matesz44/CVE-2025-47812](https://github.com/matesz44/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/matesz44/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/matesz44/CVE-2025-47812.svg)


## CVE-2025-4517
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/AnimePrincess420/CVE-2025-4517-PoC](https://github.com/AnimePrincess420/CVE-2025-4517-PoC) :  ![starts](https://img.shields.io/github/stars/AnimePrincess420/CVE-2025-4517-PoC.svg) ![forks](https://img.shields.io/github/forks/AnimePrincess420/CVE-2025-4517-PoC.svg)
- [https://github.com/DesertDemons/CVE-2025-4138-4517-POC](https://github.com/DesertDemons/CVE-2025-4138-4517-POC) :  ![starts](https://img.shields.io/github/stars/DesertDemons/CVE-2025-4138-4517-POC.svg) ![forks](https://img.shields.io/github/forks/DesertDemons/CVE-2025-4138-4517-POC.svg)
- [https://github.com/StealthByte0/CVE-2025-4517-poc](https://github.com/StealthByte0/CVE-2025-4517-poc) :  ![starts](https://img.shields.io/github/stars/StealthByte0/CVE-2025-4517-poc.svg) ![forks](https://img.shields.io/github/forks/StealthByte0/CVE-2025-4517-poc.svg)
- [https://github.com/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass](https://github.com/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass) :  ![starts](https://img.shields.io/github/stars/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass.svg) ![forks](https://img.shields.io/github/forks/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass.svg)
- [https://github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData](https://github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2025-4517-POC-HTB-WingData.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2025-4517-POC-HTB-WingData.svg)


## CVE-2025-4330
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass](https://github.com/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass) :  ![starts](https://img.shields.io/github/stars/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass.svg) ![forks](https://img.shields.io/github/forks/0xDTC/CVE-2025-4517-tarfile-PATH_MAX-bypass.svg)


## CVE-2025-4138
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/DesertDemons/CVE-2025-4138-4517-POC](https://github.com/DesertDemons/CVE-2025-4138-4517-POC) :  ![starts](https://img.shields.io/github/stars/DesertDemons/CVE-2025-4138-4517-POC.svg) ![forks](https://img.shields.io/github/forks/DesertDemons/CVE-2025-4138-4517-POC.svg)
- [https://github.com/thefizzyfish/CVE-2025-4138_tarfile_filter_bypass](https://github.com/thefizzyfish/CVE-2025-4138_tarfile_filter_bypass) :  ![starts](https://img.shields.io/github/stars/thefizzyfish/CVE-2025-4138_tarfile_filter_bypass.svg) ![forks](https://img.shields.io/github/forks/thefizzyfish/CVE-2025-4138_tarfile_filter_bypass.svg)


## CVE-2024-34444
 Missing Authorization vulnerability in ThemePunch OHG Slider Revolution.This issue affects Slider Revolution: from n/a before 6.7.0.

- [https://github.com/dzmind2312/CVE-2024-34444-Exploit-Poc](https://github.com/dzmind2312/CVE-2024-34444-Exploit-Poc) :  ![starts](https://img.shields.io/github/stars/dzmind2312/CVE-2024-34444-Exploit-Poc.svg) ![forks](https://img.shields.io/github/forks/dzmind2312/CVE-2024-34444-Exploit-Poc.svg)


## CVE-2024-24590
 Deserialization of untrusted data can occur in versions 0.17.0 to 1.14.2 of the client SDK of Allegro AI’s ClearML platform, enabling a maliciously uploaded artifact to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/rippsec/CVE-2024-24590-ClearML-RCE-Exploit](https://github.com/rippsec/CVE-2024-24590-ClearML-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/rippsec/CVE-2024-24590-ClearML-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/rippsec/CVE-2024-24590-ClearML-RCE-Exploit.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/KelvinWin10/CVE-2017-7921-rewrite](https://github.com/KelvinWin10/CVE-2017-7921-rewrite) :  ![starts](https://img.shields.io/github/stars/KelvinWin10/CVE-2017-7921-rewrite.svg) ![forks](https://img.shields.io/github/forks/KelvinWin10/CVE-2017-7921-rewrite.svg)

