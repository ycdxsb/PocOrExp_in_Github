# Update 2026-08-14
## CVE-2026-73034
 DB-GPT v0.8.1 contains an unauthenticated path traversal vulnerability that allows remote attackers to write arbitrary files to any location on the server by injecting directory traversal sequences into the user_id HTTP header of the Python file-upload endpoint. Attackers can send a crafted multipart upload request with a traversal-poisoned user_id header to escape the intended upload directory and write attacker-controlled content to locations such as Python startup hooks, cron directories, or agent scripts, resulting in remote code execution.

- [https://github.com/Boreas37/CVE-2026-73034-PoC](https://github.com/Boreas37/CVE-2026-73034-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-73034-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-73034-PoC.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/0xBlackash/CVE-2026-72898](https://github.com/0xBlackash/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-72898.svg)


## CVE-2026-70376
 Pluck CMS's admin panel relies solely on a Referer-header comparison (requestedByTheSameDomain in data/inc/functions.admin.php, gating every admin.php action) for CSRF protection, with no per-request anti-CSRF token anywhere in the admin area.

- [https://github.com/IlhomjonR/PluckCMS-CSRF-RCE](https://github.com/IlhomjonR/PluckCMS-CSRF-RCE) :  ![starts](https://img.shields.io/github/stars/IlhomjonR/PluckCMS-CSRF-RCE.svg) ![forks](https://img.shields.io/github/forks/IlhomjonR/PluckCMS-CSRF-RCE.svg)


## CVE-2026-69263
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, the mitigation for CVE-2025-8943 blocked -y and --yes flags on npx, but packages/components/nodes/tools/MCP/core.ts denied only PATH, LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, and NODE_OPTIONS by exact environment-variable name. Because npm reads configuration from npm_config_* variables, setting npm_config_yes=true reproduced --yes behavior without using a blocked flag, causing npx to auto-install and execute the named package when a Custom MCP server launched. This issue is fixed in version 3.1.3.

- [https://github.com/leoelsolh/CVE-2026-69263](https://github.com/leoelsolh/CVE-2026-69263) :  ![starts](https://img.shields.io/github/stars/leoelsolh/CVE-2026-69263.svg) ![forks](https://img.shields.io/github/forks/leoelsolh/CVE-2026-69263.svg)


## CVE-2026-68398
call_rcu() does the same here without stalling the close() path.

- [https://github.com/aramosf/CVE-2026-68398](https://github.com/aramosf/CVE-2026-68398) :  ![starts](https://img.shields.io/github/stars/aramosf/CVE-2026-68398.svg) ![forks](https://img.shields.io/github/forks/aramosf/CVE-2026-68398.svg)


## CVE-2026-68138
unlinks under the same lock.

- [https://github.com/aramosf/CVE-2026-68138](https://github.com/aramosf/CVE-2026-68138) :  ![starts](https://img.shields.io/github/stars/aramosf/CVE-2026-68138.svg) ![forks](https://img.shields.io/github/forks/aramosf/CVE-2026-68138.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/ZildanZ/CVE-2026-64638](https://github.com/ZildanZ/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/ZildanZ/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/ZildanZ/CVE-2026-64638.svg)


## CVE-2026-64563
   __sys_recvfrom+0x1d4/0x2c0

- [https://github.com/guard-wait/CVE-2026-64563_EXP](https://github.com/guard-wait/CVE-2026-64563_EXP) :  ![starts](https://img.shields.io/github/stars/guard-wait/CVE-2026-64563_EXP.svg) ![forks](https://img.shields.io/github/forks/guard-wait/CVE-2026-64563_EXP.svg)


## CVE-2026-59827
 Metabase is an open-source business intelligence and embedded analytics tool. Prior to 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4, Metabase instances with an H2 database connection, including the default sample database, deserialize arbitrary Java objects returned in H2 native query result columns of type OTHER without validation, allowing an authenticated user who can run native H2 queries to execute code on the Metabase server. This issue is fixed in versions 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4.

- [https://github.com/Gutierre0x80/CVE-2026-59827](https://github.com/Gutierre0x80/CVE-2026-59827) :  ![starts](https://img.shields.io/github/stars/Gutierre0x80/CVE-2026-59827.svg) ![forks](https://img.shields.io/github/forks/Gutierre0x80/CVE-2026-59827.svg)


## CVE-2026-57858
 Cal.com Cal.diy versions 2.1.1 through 6.2.0 contain a stored cross-site scripting vulnerability in the BookingPageTagManager component that allows authenticated event owners to inject arbitrary JavaScript by supplying a malicious analytics tracking ID without sanitization. Attackers can close the inline script string literal with a crafted payload that executes in the browser of every visitor to the affected public booking page, enabling session cookie theft, forged authenticated requests, and wormable propagation by chaining with CSRF-able endpoints to persist payloads on additional events.

- [https://github.com/zylideum/CVE-2026-57858](https://github.com/zylideum/CVE-2026-57858) :  ![starts](https://img.shields.io/github/stars/zylideum/CVE-2026-57858.svg) ![forks](https://img.shields.io/github/forks/zylideum/CVE-2026-57858.svg)


## CVE-2026-54984
 Heap-based buffer overflow in Windows Imaging Component allows an unauthorized attacker to execute code locally.

- [https://github.com/kagancapar/CVE-2026-54984](https://github.com/kagancapar/CVE-2026-54984) :  ![starts](https://img.shields.io/github/stars/kagancapar/CVE-2026-54984.svg) ![forks](https://img.shields.io/github/forks/kagancapar/CVE-2026-54984.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/HORKimhab/CVE-2026-50656](https://github.com/HORKimhab/CVE-2026-50656) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-50656.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-50656.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/yora1928/CVE-2026-48908-by-yora](https://github.com/yora1928/CVE-2026-48908-by-yora) :  ![starts](https://img.shields.io/github/stars/yora1928/CVE-2026-48908-by-yora.svg) ![forks](https://img.shields.io/github/forks/yora1928/CVE-2026-48908-by-yora.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/hybLOVE/iqoo-temp-root](https://github.com/hybLOVE/iqoo-temp-root) :  ![starts](https://img.shields.io/github/stars/hybLOVE/iqoo-temp-root.svg) ![forks](https://img.shields.io/github/forks/hybLOVE/iqoo-temp-root.svg)
- [https://github.com/E-R-Butch/F9360-CVE43499](https://github.com/E-R-Butch/F9360-CVE43499) :  ![starts](https://img.shields.io/github/stars/E-R-Butch/F9360-CVE43499.svg) ![forks](https://img.shields.io/github/forks/E-R-Butch/F9360-CVE43499.svg)


## CVE-2026-41452
 Krayin CRM 2.2.4 contains a missing authentication vulnerability in the installer middleware that allows unauthenticated remote attackers to overwrite the primary administrator account by sending a crafted HTTP POST request with the X-Requested-With: XMLHttpRequest header to bypass the CanInstall middleware redirect check. Attackers can supply arbitrary name, email, and password values to the admin-config-setup endpoint, which performs an unauthenticated updateOrInsert targeting the hardcoded administrator user ID, enabling full administrative access to all CRM data.

- [https://github.com/Boreas37/CVE-2026-41452-PoC](https://github.com/Boreas37/CVE-2026-41452-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-41452-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-41452-PoC.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/matesz44/cve-2026-39987](https://github.com/matesz44/cve-2026-39987) :  ![starts](https://img.shields.io/github/stars/matesz44/cve-2026-39987.svg) ![forks](https://img.shields.io/github/forks/matesz44/cve-2026-39987.svg)


## CVE-2026-33267
Users are recommended to upgrade to version 9.2.15 or 10.1.4, which fixes the issue.

- [https://github.com/Boreas37/CVE-2026-33267-PoC](https://github.com/Boreas37/CVE-2026-33267-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-33267-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-33267-PoC.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Qengineering/RK35xx-CopyFail-Hotfix](https://github.com/Qengineering/RK35xx-CopyFail-Hotfix) :  ![starts](https://img.shields.io/github/stars/Qengineering/RK35xx-CopyFail-Hotfix.svg) ![forks](https://img.shields.io/github/forks/Qengineering/RK35xx-CopyFail-Hotfix.svg)


## CVE-2026-28956
 A memory corruption issue was addressed with improved input validation. This issue is fixed in iOS 26.5 and iPadOS 26.5, macOS Sequoia 15.7.7, macOS Sonoma 14.8.7, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. Processing a maliciously crafted media file may lead to unexpected app termination or corrupt process memory.

- [https://github.com/HORKimhab/CVE-2026-28956](https://github.com/HORKimhab/CVE-2026-28956) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-28956.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-28956.svg)


## CVE-2026-27344
 Missing Authorization vulnerability in inseriswiss inseri core inseri-core allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects inseri core: from n/a through = 1.0.5.

- [https://github.com/AC8999/CVE-2026-27344](https://github.com/AC8999/CVE-2026-27344) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2026-27344.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2026-27344.svg)


## CVE-2026-24031
 Dovecot SQL based authentication can be bypassed when auth_username_chars is cleared by admin. This vulnerability allows bypassing authentication for any user and user enumeration. Do not clear auth_username_chars. If this is not possible, install latest fixed version. No publicly available exploits are known.

- [https://github.com/aramosf/CVE-2026-24031](https://github.com/aramosf/CVE-2026-24031) :  ![starts](https://img.shields.io/github/stars/aramosf/CVE-2026-24031.svg) ![forks](https://img.shields.io/github/forks/aramosf/CVE-2026-24031.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/Knz-source/CVE-2026-23111-POC-noddlenpottato](https://github.com/Knz-source/CVE-2026-23111-POC-noddlenpottato) :  ![starts](https://img.shields.io/github/stars/Knz-source/CVE-2026-23111-POC-noddlenpottato.svg) ![forks](https://img.shields.io/github/forks/Knz-source/CVE-2026-23111-POC-noddlenpottato.svg)


## CVE-2026-17544
 Attacker-provided inputs to bccomp() could lead to an out-of-bounds write with stack and heap corruption in PHP versions from 8.4.* before 8.4.24 and from 8.5.* before 8.5.9.

- [https://github.com/Boreas37/CVE-2026-17544-PoC](https://github.com/Boreas37/CVE-2026-17544-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-17544-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-17544-PoC.svg)


## CVE-2026-14840
 The YOP Poll WordPress plugin before 7.0.6 does not validate the connection's origin IP address and instead trusts client-controlled forwarding headers when enforcing its per-IP vote restriction, allowing unauthenticated attackers to bypass the vote limit and cast unlimited votes on a public poll.

- [https://github.com/nullwhisper/CVE-2026-14840](https://github.com/nullwhisper/CVE-2026-14840) :  ![starts](https://img.shields.io/github/stars/nullwhisper/CVE-2026-14840.svg) ![forks](https://img.shields.io/github/forks/nullwhisper/CVE-2026-14840.svg)


## CVE-2026-14282
 The GoDAM – Organize WordPress Media Library & File Manager with Unlimited Folders for Images, Videos & more plugin for WordPress is vulnerable to arbitrary file uploads in versions up to, and including, 1.12.2. This is due to insufficient file type validation in the save_video_file() function hooked into WPForms' public wpforms_process_before_filter, which trusts the attacker-supplied multipart Content-Type header, preserves the original filename via wp_unique_filename(), and moves the raw upload with $wp_filesystem-move() into a web-served directory — bypassing wp_handle_upload()'s MIME/extension allowlist. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/nullwhisper/CVE-2026-14282](https://github.com/nullwhisper/CVE-2026-14282) :  ![starts](https://img.shields.io/github/stars/nullwhisper/CVE-2026-14282.svg) ![forks](https://img.shields.io/github/forks/nullwhisper/CVE-2026-14282.svg)


## CVE-2026-4440
 Out of bounds read and write in WebGL in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/Virgula0/CVE-2026-44402](https://github.com/Virgula0/CVE-2026-44402) :  ![starts](https://img.shields.io/github/stars/Virgula0/CVE-2026-44402.svg) ![forks](https://img.shields.io/github/forks/Virgula0/CVE-2026-44402.svg)


## CVE-2026-1710
 The WooPayments: Integrated WooCommerce Payments plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'save_upe_appearance_ajax' function in all versions up to, and including, 10.5.1. This makes it possible for unauthenticated attackers to update plugin settings.

- [https://github.com/686f6c61/POC-CopyEscape-CVE-2026-17106](https://github.com/686f6c61/POC-CopyEscape-CVE-2026-17106) :  ![starts](https://img.shields.io/github/stars/686f6c61/POC-CopyEscape-CVE-2026-17106.svg) ![forks](https://img.shields.io/github/forks/686f6c61/POC-CopyEscape-CVE-2026-17106.svg)


## CVE-2026-0075
 In multiple functions, there is a possible way to access the contacts database due to a SQL injection. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/QM4RS/CVE-2026-0075](https://github.com/QM4RS/CVE-2026-0075) :  ![starts](https://img.shields.io/github/stars/QM4RS/CVE-2026-0075.svg) ![forks](https://img.shields.io/github/forks/QM4RS/CVE-2026-0075.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-57052
 cJSON 1.5.0 through 1.7.18 allows out-of-bounds access via the decode_array_index_from_pointer function in cJSON_Utils.c, allowing remote attackers to bypass array bounds checking and access restricted data via malformed JSON pointer strings containing alphanumeric characters.

- [https://github.com/DhruvP2205/cjson-rust-port](https://github.com/DhruvP2205/cjson-rust-port) :  ![starts](https://img.shields.io/github/stars/DhruvP2205/cjson-rust-port.svg) ![forks](https://img.shields.io/github/forks/DhruvP2205/cjson-rust-port.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/Type010/cve-2025-21479-iqoo11pro](https://github.com/Type010/cve-2025-21479-iqoo11pro) :  ![starts](https://img.shields.io/github/stars/Type010/cve-2025-21479-iqoo11pro.svg) ![forks](https://img.shields.io/github/forks/Type010/cve-2025-21479-iqoo11pro.svg)


## CVE-2023-1698
 In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.

- [https://github.com/Chocapikk/CVE-2023-1698](https://github.com/Chocapikk/CVE-2023-1698) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-1698.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-1698.svg)

