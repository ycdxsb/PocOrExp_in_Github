# Update 2026-11-05
## CVE-2026-116512
 The Project Manager – AI Powered Project Management, Task Management, Kanban Board & Time Tracker plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.1.1 via the 'id' parameter parameter. This is due to unsanitized 'id' parameter value concatenated directly into the pipe-delimited validation rule string, which is then split and each token invoked as a dynamic PHP function with no allowlist check. This makes it possible for unauthenticated attackers to execute code on the server. This is exploitable by unauthenticated attackers because WordPress core executes the route argument's validate_callback inside WP_REST_Server::dispatch() before the route's permission_callback is invoked, meaning the Project_Manage_Capability authorization gate is never reached on the vulnerable code path.

- [https://github.com/0xCyp1337/CVE-2026-116512](https://github.com/0xCyp1337/CVE-2026-116512) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-116512.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-116512.svg)


## CVE-2026-112689
 An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, tvOS 27.2. An app may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/Lak453/CVE-2026-112689-poc](https://github.com/Lak453/CVE-2026-112689-poc) :  ![starts](https://img.shields.io/github/stars/Lak453/CVE-2026-112689-poc.svg) ![forks](https://img.shields.io/github/forks/Lak453/CVE-2026-112689-poc.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/Certbn/Brotli-Node.js-CVE-2026-111497-Broccoli2Shell-Node2Shell-HTTP2Shell-](https://github.com/Certbn/Brotli-Node.js-CVE-2026-111497-Broccoli2Shell-Node2Shell-HTTP2Shell-) :  ![starts](https://img.shields.io/github/stars/Certbn/Brotli-Node.js-CVE-2026-111497-Broccoli2Shell-Node2Shell-HTTP2Shell-.svg) ![forks](https://img.shields.io/github/forks/Certbn/Brotli-Node.js-CVE-2026-111497-Broccoli2Shell-Node2Shell-HTTP2Shell-.svg)


## CVE-2026-107406
  *  NetScaler ADC 13.1-FIPS before13.1-NDcPP 13.1-37.279

- [https://github.com/ApexBreach/CVE-2026-107406-Poc](https://github.com/ApexBreach/CVE-2026-107406-Poc) :  ![starts](https://img.shields.io/github/stars/ApexBreach/CVE-2026-107406-Poc.svg) ![forks](https://img.shields.io/github/forks/ApexBreach/CVE-2026-107406-Poc.svg)


## CVE-2026-106991
 hustoj =24.09.10 and =26.08.19 is vulnerable to Incorrect Access Control. Any registered user can delete, lock, or sticky any forum thread (including admins' announcements) via threadadmin.php. The thread branch only verifies login, never authorship or admin rights.

- [https://github.com/MX-Qulin/CVE-2026-106991](https://github.com/MX-Qulin/CVE-2026-106991) :  ![starts](https://img.shields.io/github/stars/MX-Qulin/CVE-2026-106991.svg) ![forks](https://img.shields.io/github/forks/MX-Qulin/CVE-2026-106991.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/schnied/cve-2026-98432-mitigation-iptables](https://github.com/schnied/cve-2026-98432-mitigation-iptables) :  ![starts](https://img.shields.io/github/stars/schnied/cve-2026-98432-mitigation-iptables.svg) ![forks](https://img.shields.io/github/forks/schnied/cve-2026-98432-mitigation-iptables.svg)
- [https://github.com/lowerpower/cve-2026-98432-mitigation](https://github.com/lowerpower/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/lowerpower/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/lowerpower/cve-2026-98432-mitigation.svg)
- [https://github.com/hdp1972be-svg/cve_2026_98432_guard](https://github.com/hdp1972be-svg/cve_2026_98432_guard) :  ![starts](https://img.shields.io/github/stars/hdp1972be-svg/cve_2026_98432_guard.svg) ![forks](https://img.shields.io/github/forks/hdp1972be-svg/cve_2026_98432_guard.svg)
- [https://github.com/zenjabba/cve-2026-98432-mitigation](https://github.com/zenjabba/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/zenjabba/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/zenjabba/cve-2026-98432-mitigation.svg)
- [https://github.com/luxagen/tester-linux-cve-2026-98432](https://github.com/luxagen/tester-linux-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/luxagen/tester-linux-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/luxagen/tester-linux-cve-2026-98432.svg)
- [https://github.com/muhammedemintombak/pardus21-cve-2026-98432](https://github.com/muhammedemintombak/pardus21-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/muhammedemintombak/pardus21-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/muhammedemintombak/pardus21-cve-2026-98432.svg)
- [https://github.com/mrjoshuap/ansible-ezcve](https://github.com/mrjoshuap/ansible-ezcve) :  ![starts](https://img.shields.io/github/stars/mrjoshuap/ansible-ezcve.svg) ![forks](https://img.shields.io/github/forks/mrjoshuap/ansible-ezcve.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/RMDycz/K80Pro-miro-CVE-2026-98260](https://github.com/RMDycz/K80Pro-miro-CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/RMDycz/K80Pro-miro-CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/RMDycz/K80Pro-miro-CVE-2026-98260.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/emc-kk/cve-2026-97229-lab](https://github.com/emc-kk/cve-2026-97229-lab) :  ![starts](https://img.shields.io/github/stars/emc-kk/cve-2026-97229-lab.svg) ![forks](https://img.shields.io/github/forks/emc-kk/cve-2026-97229-lab.svg)


## CVE-2026-92183
The specific flaw exists within the parsing of APNG files. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-29400.

- [https://github.com/CXu0630/CVE-2026-92183_GIMP_RCE_Proof-of-Concept](https://github.com/CXu0630/CVE-2026-92183_GIMP_RCE_Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/CXu0630/CVE-2026-92183_GIMP_RCE_Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/CXu0630/CVE-2026-92183_GIMP_RCE_Proof-of-Concept.svg)


## CVE-2026-80587
   is room, a DSS cannot be used with an MP_JOIN.

- [https://github.com/9technologygroup/cve-2026-80587-check](https://github.com/9technologygroup/cve-2026-80587-check) :  ![starts](https://img.shields.io/github/stars/9technologygroup/cve-2026-80587-check.svg) ![forks](https://img.shields.io/github/forks/9technologygroup/cve-2026-80587-check.svg)


## CVE-2026-59795
 In JetBrains TeamCity before 2026.1.2 stored XSS via unauthenticated agent registration was possible

- [https://github.com/JoakimBulow/CVE-2026-59795](https://github.com/JoakimBulow/CVE-2026-59795) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-59795.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-59795.svg)


## CVE-2026-58115
This could allow an unauthenticated remote attacker to create malicious flows through the HTTP interface in order to execute arbitrary code on the underlying server with maximum privileges.

- [https://github.com/foxcornlab/node-red-scanner](https://github.com/foxcornlab/node-red-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/node-red-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/node-red-scanner.svg)


## CVE-2026-54161
 Network UPS Tools is a collection of programs which provide a common interface for monitoring and administering UPS, PDU and SCD hardware. From 2.8.3 to 2.8.5, upsmon in clients/upsmon.c inserts the server-supplied ups.alarm value into shell commands executed by notify(), async_notify(), and wall(). When a monitored device reports an ALARM state and an operator has configured NOTIFYCMD with EXEC in NOTIFYFLAG ALARM, shell metacharacters in the alarm text are evaluated on POSIX or Windows and can execute arbitrary operating-system commands as the upsmon account, which is commonly root. An attacker can control the value through a malicious or compromised upsd, a man-in-the-middle on a plaintext upsd to upsmon connection, or a compromised UPS device whose driver supplies the alarm upstream of upsd; TLS between upsd and upsmon does not mitigate the compromised-device path. This vulnerability is fixed in 2.8.6.

- [https://github.com/ja-errorpro/CVE-2026-54161](https://github.com/ja-errorpro/CVE-2026-54161) :  ![starts](https://img.shields.io/github/stars/ja-errorpro/CVE-2026-54161.svg) ![forks](https://img.shields.io/github/forks/ja-errorpro/CVE-2026-54161.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/CodeLabWithOsman/HTB-Cohort](https://github.com/CodeLabWithOsman/HTB-Cohort) :  ![starts](https://img.shields.io/github/stars/CodeLabWithOsman/HTB-Cohort.svg) ![forks](https://img.shields.io/github/forks/CodeLabWithOsman/HTB-Cohort.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/CodeLabWithOsman/HTB-Cohort](https://github.com/CodeLabWithOsman/HTB-Cohort) :  ![starts](https://img.shields.io/github/stars/CodeLabWithOsman/HTB-Cohort.svg) ![forks](https://img.shields.io/github/forks/CodeLabWithOsman/HTB-Cohort.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/erlangparasu/mitigate_cve_2026_31431-sh](https://github.com/erlangparasu/mitigate_cve_2026_31431-sh) :  ![starts](https://img.shields.io/github/stars/erlangparasu/mitigate_cve_2026_31431-sh.svg) ![forks](https://img.shields.io/github/forks/erlangparasu/mitigate_cve_2026_31431-sh.svg)


## CVE-2026-20687
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 18.7.7 and iPadOS 18.7.7, iOS 26.4 and iPadOS 26.4, macOS Sequoia 15.7.5, macOS Tahoe 26.4, tvOS 26.4, watchOS 26.4. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/hidra0x/hidra](https://github.com/hidra0x/hidra) :  ![starts](https://img.shields.io/github/stars/hidra0x/hidra.svg) ![forks](https://img.shields.io/github/forks/hidra0x/hidra.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/mxxnknght/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks](https://github.com/mxxnknght/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks) :  ![starts](https://img.shields.io/github/stars/mxxnknght/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg) ![forks](https://img.shields.io/github/forks/mxxnknght/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg)
- [https://github.com/emc-kk/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/emc-kk/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/emc-kk/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/emc-kk/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)


## CVE-2026-8447
 IBM Langflow OSS 1.0.0 through 1.11.2 suffer from a stored cross-site scripting vulnerability in the Playground chat interface.

- [https://github.com/KOBUKOVUI/CVE-2026-84473](https://github.com/KOBUKOVUI/CVE-2026-84473) :  ![starts](https://img.shields.io/github/stars/KOBUKOVUI/CVE-2026-84473.svg) ![forks](https://img.shields.io/github/forks/KOBUKOVUI/CVE-2026-84473.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/1amBa7Man/Linux-copy-fail-CVE-2026-31431](https://github.com/1amBa7Man/Linux-copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/1amBa7Man/Linux-copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/1amBa7Man/Linux-copy-fail-CVE-2026-31431.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/origabriel/acb-giturl-cve2025](https://github.com/origabriel/acb-giturl-cve2025) :  ![starts](https://img.shields.io/github/stars/origabriel/acb-giturl-cve2025.svg) ![forks](https://img.shields.io/github/forks/origabriel/acb-giturl-cve2025.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/lucyz1125/CVE-2025-55182-Next.js-RCE](https://github.com/lucyz1125/CVE-2025-55182-Next.js-RCE) :  ![starts](https://img.shields.io/github/stars/lucyz1125/CVE-2025-55182-Next.js-RCE.svg) ![forks](https://img.shields.io/github/forks/lucyz1125/CVE-2025-55182-Next.js-RCE.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/origabriel/acb-giturl-cve2024-windows](https://github.com/origabriel/acb-giturl-cve2024-windows) :  ![starts](https://img.shields.io/github/stars/origabriel/acb-giturl-cve2024-windows.svg) ![forks](https://img.shields.io/github/forks/origabriel/acb-giturl-cve2024-windows.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/eunbyulaakash/CVE-2024-25600-FOR-PYTHON-3.8-AND-ABOVE](https://github.com/eunbyulaakash/CVE-2024-25600-FOR-PYTHON-3.8-AND-ABOVE) :  ![starts](https://img.shields.io/github/stars/eunbyulaakash/CVE-2024-25600-FOR-PYTHON-3.8-AND-ABOVE.svg) ![forks](https://img.shields.io/github/forks/eunbyulaakash/CVE-2024-25600-FOR-PYTHON-3.8-AND-ABOVE.svg)


## CVE-2022-23943
 Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and prior versions.

- [https://github.com/rwmicro/CVE-2022-23943](https://github.com/rwmicro/CVE-2022-23943) :  ![starts](https://img.shields.io/github/stars/rwmicro/CVE-2022-23943.svg) ![forks](https://img.shields.io/github/forks/rwmicro/CVE-2022-23943.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-33644
 An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longname, causing an out-of-bounds read.

- [https://github.com/nicklondal/libtar-CVE-2021-33644-followup](https://github.com/nicklondal/libtar-CVE-2021-33644-followup) :  ![starts](https://img.shields.io/github/stars/nicklondal/libtar-CVE-2021-33644-followup.svg) ![forks](https://img.shields.io/github/forks/nicklondal/libtar-CVE-2021-33644-followup.svg)


## CVE-2021-33643
 An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longlink, causing an out-of-bounds read.

- [https://github.com/nicklondal/libtar-CVE-2021-33644-followup](https://github.com/nicklondal/libtar-CVE-2021-33644-followup) :  ![starts](https://img.shields.io/github/stars/nicklondal/libtar-CVE-2021-33644-followup.svg) ![forks](https://img.shields.io/github/forks/nicklondal/libtar-CVE-2021-33644-followup.svg)


## CVE-2021-26085
 Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a Pre-Authorization Arbitrary File Read vulnerability in the /s/ endpoint. The affected versions are before version 7.4.10, and from version 7.5.0 before 7.12.3.

- [https://github.com/shadowartisanslash/Confluence-Desktop-2026](https://github.com/shadowartisanslash/Confluence-Desktop-2026) :  ![starts](https://img.shields.io/github/stars/shadowartisanslash/Confluence-Desktop-2026.svg) ![forks](https://img.shields.io/github/forks/shadowartisanslash/Confluence-Desktop-2026.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Nero22k/CVE-2021-4034](https://github.com/Nero22k/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Nero22k/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Nero22k/CVE-2021-4034.svg)


## CVE-2020-10135
 Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier may allow an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key.

- [https://github.com/pr0t31n/Aether-B](https://github.com/pr0t31n/Aether-B) :  ![starts](https://img.shields.io/github/stars/pr0t31n/Aether-B.svg) ![forks](https://img.shields.io/github/forks/pr0t31n/Aether-B.svg)


## CVE-2019-11478
 Jonathan Looney discovered that the TCP retransmission queue implementation in tcp_fragment in the Linux kernel could be fragmented when handling certain TCP Selective Acknowledgment (SACK) sequences. A remote attacker could use this to cause a denial of service. This has been fixed in stable kernel releases 4.4.182, 4.9.182, 4.14.127, 4.19.52, 5.1.11, and is fixed in commit f070ef2ac66716357066b683fb0baf55f8191a2e.

- [https://github.com/jinjucat/CVE-2019-11478](https://github.com/jinjucat/CVE-2019-11478) :  ![starts](https://img.shields.io/github/stars/jinjucat/CVE-2019-11478.svg) ![forks](https://img.shields.io/github/forks/jinjucat/CVE-2019-11478.svg)


## CVE-2019-9506
 The Bluetooth BR/EDR specification up to and including version 5.1 permits sufficiently low encryption key length and does not prevent an attacker from influencing the key length negotiation. This allows practical brute-force attacks (aka "KNOB") that can decrypt traffic and inject arbitrary ciphertext without the victim noticing.

- [https://github.com/pr0t31n/Aether-B](https://github.com/pr0t31n/Aether-B) :  ![starts](https://img.shields.io/github/stars/pr0t31n/Aether-B.svg) ![forks](https://img.shields.io/github/forks/pr0t31n/Aether-B.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/che3axujnya/cve-2018-16763](https://github.com/che3axujnya/cve-2018-16763) :  ![starts](https://img.shields.io/github/stars/che3axujnya/cve-2018-16763.svg) ![forks](https://img.shields.io/github/forks/che3axujnya/cve-2018-16763.svg)


## CVE-2009-4496
 Boa 0.94.14rc21 writes data to a log file without sanitizing non-printable characters, which might allow remote attackers to modify a window's title, or possibly execute arbitrary commands or overwrite files, via an HTTP request containing an escape sequence for a terminal emulator.

- [https://github.com/enriquenegri-cyberlaw/boa-webserver-log-escape-injection-cve-2009-4496](https://github.com/enriquenegri-cyberlaw/boa-webserver-log-escape-injection-cve-2009-4496) :  ![starts](https://img.shields.io/github/stars/enriquenegri-cyberlaw/boa-webserver-log-escape-injection-cve-2009-4496.svg) ![forks](https://img.shields.io/github/forks/enriquenegri-cyberlaw/boa-webserver-log-escape-injection-cve-2009-4496.svg)

