# Update 2026-05-19
## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/studiogangster/CVE-2026-46333](https://github.com/studiogangster/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/studiogangster/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/studiogangster/CVE-2026-46333.svg)
- [https://github.com/0xBlackash/CVE-2026-46333](https://github.com/0xBlackash/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46333.svg)
- [https://github.com/Aurillium/public-passwd](https://github.com/Aurillium/public-passwd) :  ![starts](https://img.shields.io/github/stars/Aurillium/public-passwd.svg) ![forks](https://img.shields.io/github/forks/Aurillium/public-passwd.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/tal7aouy/nginx-cve-2026-42945](https://github.com/tal7aouy/nginx-cve-2026-42945) :  ![starts](https://img.shields.io/github/stars/tal7aouy/nginx-cve-2026-42945.svg) ![forks](https://img.shields.io/github/forks/tal7aouy/nginx-cve-2026-42945.svg)
- [https://github.com/Renison-Gohel/CVE-2026-42945-NGINX-Rift](https://github.com/Renison-Gohel/CVE-2026-42945-NGINX-Rift) :  ![starts](https://img.shields.io/github/stars/Renison-Gohel/CVE-2026-42945-NGINX-Rift.svg) ![forks](https://img.shields.io/github/forks/Renison-Gohel/CVE-2026-42945-NGINX-Rift.svg)


## CVE-2026-35584
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. Prior to 1.8.212, the endpoint GET /thread/read/{conversation_id}/{thread_id} does not require authentication and does not validate whether the given thread_id belongs to the given conversation_id. This allows any unauthenticated attacker to mark any thread as read by passing arbitrary IDs, enumerate valid thread IDs via HTTP response codes (200 vs 404), and manipulate opened_at timestamps across conversations (IDOR). This vulnerability is fixed in 1.8.212.

- [https://github.com/Spoo1k/CVE-2026-35584](https://github.com/Spoo1k/CVE-2026-35584) :  ![starts](https://img.shields.io/github/stars/Spoo1k/CVE-2026-35584.svg) ![forks](https://img.shields.io/github/forks/Spoo1k/CVE-2026-35584.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Qengineering/RK35xx-CopyFail-Hotfix](https://github.com/Qengineering/RK35xx-CopyFail-Hotfix) :  ![starts](https://img.shields.io/github/stars/Qengineering/RK35xx-CopyFail-Hotfix.svg) ![forks](https://img.shields.io/github/forks/Qengineering/RK35xx-CopyFail-Hotfix.svg)


## CVE-2026-28956
 A memory corruption issue was addressed with improved input validation. This issue is fixed in iOS 26.5 and iPadOS 26.5, macOS Sequoia 15.7.7, macOS Sonoma 14.8.7, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. Processing a maliciously crafted media file may lead to unexpected app termination or corrupt process memory.

- [https://github.com/impost0r/CVE-2026-28956](https://github.com/impost0r/CVE-2026-28956) :  ![starts](https://img.shields.io/github/stars/impost0r/CVE-2026-28956.svg) ![forks](https://img.shields.io/github/forks/impost0r/CVE-2026-28956.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/xShadow-Here/CVE-2026-8181](https://github.com/xShadow-Here/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/xShadow-Here/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/xShadow-Here/CVE-2026-8181.svg)
- [https://github.com/rootdirective-sec/CVE-2026-8181-Lab](https://github.com/rootdirective-sec/CVE-2026-8181-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-8181-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-8181-Lab.svg)


## CVE-2026-3904
to avoid the potential crash in the nscd client.

- [https://github.com/AzhariRamadhan/CVE-2026-39047](https://github.com/AzhariRamadhan/CVE-2026-39047) :  ![starts](https://img.shields.io/github/stars/AzhariRamadhan/CVE-2026-39047.svg) ![forks](https://img.shields.io/github/forks/AzhariRamadhan/CVE-2026-39047.svg)


## CVE-2026-3643
 The Accessibly plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the REST API in all versions up to, and including, 3.0.3. The plugin registers REST API endpoints at `/otm-ac/v1/update-widget-options` and `/otm-ac/v1/update-app-config` with the `permission_callback` set to `__return_true`, which means no authentication or authorization check is performed. The `updateWidgetOptions()` function in `AdminApi.php` accepts user-supplied JSON data and passes it directly to `AccessiblyOptions::updateAppConfig()`, which saves it to the WordPress options table via `update_option()` without any sanitization or validation. The stored `widgetSrc` value is later retrieved by `AssetsManager::enqueueFrontendScripts()` and passed directly to `wp_enqueue_script()` as the script URL, causing it to be rendered as a `script` tag on every front-end page. This makes it possible for unauthenticated attackers to inject arbitrary JavaScript that executes for all site visitors by changing the `widgetSrc` option to point to a malicious external script.

- [https://github.com/kensh1k/CVE-2026-36438](https://github.com/kensh1k/CVE-2026-36438) :  ![starts](https://img.shields.io/github/stars/kensh1k/CVE-2026-36438.svg) ![forks](https://img.shields.io/github/forks/kensh1k/CVE-2026-36438.svg)


## CVE-2026-3629
 The Import and export users and customers plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 1.29.7. This is due to the 'save_extra_user_profile_fields' function not properly restricting which user meta keys can be updated via profile fields. The 'get_restricted_fields' method does not include sensitive meta keys such as 'wp_capabilities'. This makes it possible for unauthenticated attackers to escalate their privileges to Administrator by submitting a crafted registration request that sets the 'wp_capabilities' meta key. The vulnerability can only be exploited if the "Show fields in profile" setting is enabled and a CSV with a wp_capabilities column header has been previously imported.

- [https://github.com/PySecTools/CVE-2026-3629](https://github.com/PySecTools/CVE-2026-3629) :  ![starts](https://img.shields.io/github/stars/PySecTools/CVE-2026-3629.svg) ![forks](https://img.shields.io/github/forks/PySecTools/CVE-2026-3629.svg)


## CVE-2026-3567
 The RepairBuddy – Repair Shop CRM & Booking Plugin for WordPress is vulnerable to unauthorized access in all versions up to, and including, 4.1132. The plugin exposes two AJAX handlers that, when combined, allow any authenticated user to modify admin-level plugin settings. First, the wc_rb_get_fresh_nonce() function (registered via wp_ajax and wp_ajax_nopriv hooks) allows any user to generate a valid WordPress nonce for any arbitrary action name by simply providing the nonce_name parameter, with no capability checks. Second, the wc_rep_shop_settings_submission() function only verifies the nonce (wcrb_main_setting_nonce) but performs no current_user_can() capability check before updating 15+ plugin options via update_option(). This makes it possible for authenticated attackers, with subscriber-level access and above, to modify all plugin configuration settings including business name, email, logo, menu label, GDPR settings, and more by first minting a valid nonce via the wc_rb_get_fresh_nonce endpoint and then calling the settings submission handler.

- [https://github.com/sharma19d/CVE-2026-35678](https://github.com/sharma19d/CVE-2026-35678) :  ![starts](https://img.shields.io/github/stars/sharma19d/CVE-2026-35678.svg) ![forks](https://img.shields.io/github/forks/sharma19d/CVE-2026-35678.svg)


## CVE-2026-3102
 A vulnerability was determined in exiftool up to 13.49 on macOS. This issue affects the function SetMacOSTags of the file lib/Image/ExifTool/MacOS.pm of the component PNG File Parser. This manipulation of the argument DateTimeOriginal causes os command injection. The attack is possible to be carried out remotely. The exploit has been publicly disclosed and may be utilized. Upgrading to version 13.50 is capable of addressing this issue. Patch name: e9609a9bcc0d32bd252a709a562fb822d6dd86f7. Upgrading the affected component is recommended.

- [https://github.com/ErikDervishi03/CVE-2026-31024](https://github.com/ErikDervishi03/CVE-2026-31024) :  ![starts](https://img.shields.io/github/stars/ErikDervishi03/CVE-2026-31024.svg) ![forks](https://img.shields.io/github/forks/ErikDervishi03/CVE-2026-31024.svg)


## CVE-2026-0265
Cloud NGFW and Prisma Access® are not impacted by this vulnerability.

- [https://github.com/tstephens1080/palo-alto-cve-2026-0265-checker](https://github.com/tstephens1080/palo-alto-cve-2026-0265-checker) :  ![starts](https://img.shields.io/github/stars/tstephens1080/palo-alto-cve-2026-0265-checker.svg) ![forks](https://img.shields.io/github/forks/tstephens1080/palo-alto-cve-2026-0265-checker.svg)


## CVE-2025-59536
 Claude Code is an agentic coding tool. Versions before 1.0.111 were vulnerable to Code Injection due to a bug in the startup trust dialog implementation. Claude Code could be tricked to execute code contained in a project before the user accepted the startup trust dialog. Exploiting this requires a user to start Claude Code in an untrusted directory. Users on standard Claude Code auto-update will have received this fix automatically. Users performing manual updates are advised to update to the latest version. This issue is fixed in version 1.0.111.

- [https://github.com/tacdm/cve-2025-59536-poc](https://github.com/tacdm/cve-2025-59536-poc) :  ![starts](https://img.shields.io/github/stars/tacdm/cve-2025-59536-poc.svg) ![forks](https://img.shields.io/github/forks/tacdm/cve-2025-59536-poc.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/corey-farley/CVE-2025-59528-Flowise-RCE](https://github.com/corey-farley/CVE-2025-59528-Flowise-RCE) :  ![starts](https://img.shields.io/github/stars/corey-farley/CVE-2025-59528-Flowise-RCE.svg) ![forks](https://img.shields.io/github/forks/corey-farley/CVE-2025-59528-Flowise-RCE.svg)


## CVE-2025-21213
 Secure Boot Security Feature Bypass Vulnerability

- [https://github.com/Wack0/bitlocker-attacks](https://github.com/Wack0/bitlocker-attacks) :  ![starts](https://img.shields.io/github/stars/Wack0/bitlocker-attacks.svg) ![forks](https://img.shields.io/github/forks/Wack0/bitlocker-attacks.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/jimmexploit/CVE-2024-37054-PoC](https://github.com/jimmexploit/CVE-2024-37054-PoC) :  ![starts](https://img.shields.io/github/stars/jimmexploit/CVE-2024-37054-PoC.svg) ![forks](https://img.shields.io/github/forks/jimmexploit/CVE-2024-37054-PoC.svg)


## CVE-2024-20666
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/Wack0/bitlocker-attacks](https://github.com/Wack0/bitlocker-attacks) :  ![starts](https://img.shields.io/github/stars/Wack0/bitlocker-attacks.svg) ![forks](https://img.shields.io/github/forks/Wack0/bitlocker-attacks.svg)


## CVE-2023-2825
 An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.

- [https://github.com/Groppoxx/CVE-2023-2825-PoC](https://github.com/Groppoxx/CVE-2023-2825-PoC) :  ![starts](https://img.shields.io/github/stars/Groppoxx/CVE-2023-2825-PoC.svg) ![forks](https://img.shields.io/github/forks/Groppoxx/CVE-2023-2825-PoC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/trinetra-1308/PwnKit-](https://github.com/trinetra-1308/PwnKit-) :  ![starts](https://img.shields.io/github/stars/trinetra-1308/PwnKit-.svg) ![forks](https://img.shields.io/github/forks/trinetra-1308/PwnKit-.svg)


## CVE-2020-25042
 An arbitrary file upload issue exists in Mara CMS 7.5. In order to exploit this, an attacker must have a valid authenticated (admin/manager) session and make a codebase/dir.php?type=filenew request to upload PHP code to codebase/handler.php.

- [https://github.com/Groppoxx/CVE-2020-25042-PoC](https://github.com/Groppoxx/CVE-2020-25042-PoC) :  ![starts](https://img.shields.io/github/stars/Groppoxx/CVE-2020-25042-PoC.svg) ![forks](https://img.shields.io/github/forks/Groppoxx/CVE-2020-25042-PoC.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/arch1m3d/MiniPlasma-Detection](https://github.com/arch1m3d/MiniPlasma-Detection) :  ![starts](https://img.shields.io/github/stars/arch1m3d/MiniPlasma-Detection.svg) ![forks](https://img.shields.io/github/forks/arch1m3d/MiniPlasma-Detection.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Majaktech/apache-struts-cve-2017-5638-project](https://github.com/Majaktech/apache-struts-cve-2017-5638-project) :  ![starts](https://img.shields.io/github/stars/Majaktech/apache-struts-cve-2017-5638-project.svg) ![forks](https://img.shields.io/github/forks/Majaktech/apache-struts-cve-2017-5638-project.svg)

