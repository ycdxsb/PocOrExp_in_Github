# Update 2026-02-24
## CVE-2026-27579
 CollabPlatform is a full-stack, real-time doc collaboration platform. In all versions of CollabPlatform, the Appwrite project used by the application is misconfigured to allow arbitrary origins in CORS responses while also permitting credentialed requests. An attacker-controlled domain can issue authenticated cross-origin requests and read sensitive user account information, including email address, account identifiers, and MFA status. The issue did not have a fix at the time of publication.

- [https://github.com/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration](https://github.com/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/FrigateCaptain/openclaw_vulnerabilities_and_solutions](https://github.com/FrigateCaptain/openclaw_vulnerabilities_and_solutions) :  ![starts](https://img.shields.io/github/stars/FrigateCaptain/openclaw_vulnerabilities_and_solutions.svg) ![forks](https://img.shields.io/github/forks/FrigateCaptain/openclaw_vulnerabilities_and_solutions.svg)


## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.

- [https://github.com/CVEs-Labs/CVE-2026-22241](https://github.com/CVEs-Labs/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/CVEs-Labs/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/CVEs-Labs/CVE-2026-22241.svg)


## CVE-2026-2633
 The Gutenberg Blocks with AI by Kadence WP plugin for WordPress is vulnerable to Missing Authorization in all versions up to, and including, 3.6.1. This is due to a missing capability check in the `process_image_data_ajax_callback()` function which handles the `kadence_import_process_image_data` AJAX action. The function's authorization check via `verify_ajax_call()` only validates `edit_posts` capability but fails to check for the `upload_files` capability. This makes it possible for authenticated attackers, with Contributor-level access and above, to upload arbitrary images from remote URLs to the WordPress Media Library, bypassing the standard WordPress capability restriction that prevents Contributors from uploading files.

- [https://github.com/dxlerYT/CVE-2026-26331](https://github.com/dxlerYT/CVE-2026-26331) :  ![starts](https://img.shields.io/github/stars/dxlerYT/CVE-2026-26331.svg) ![forks](https://img.shields.io/github/forks/dxlerYT/CVE-2026-26331.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/hexissam/CVE-2026-1731](https://github.com/hexissam/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/hexissam/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/hexissam/CVE-2026-1731.svg)


## CVE-2025-69295
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in TeconceTheme Coven Core coven-core allows Blind SQL Injection.This issue affects Coven Core: from n/a through = 1.3.

- [https://github.com/hexissam/CVE-2025-69295](https://github.com/hexissam/CVE-2025-69295) :  ![starts](https://img.shields.io/github/stars/hexissam/CVE-2025-69295.svg) ![forks](https://img.shields.io/github/forks/hexissam/CVE-2025-69295.svg)


## CVE-2025-68668
 n8n is an open source workflow automation platform. From version 1.0.0 to before 2.0.0, a sandbox bypass vulnerability exists in the Python Code Node that uses Pyodide. An authenticated user with permission to create or modify workflows can exploit this vulnerability to execute arbitrary commands on the host system running n8n, using the same privileges as the n8n process. This issue has been patched in version 2.0.0. Workarounds for this issue involve disabling the Code Node by setting the environment variable NODES_EXCLUDE: "[\"n8n-nodes-base.code\"]", disabling Python support in the Code node by setting the environment variable N8N_PYTHON_ENABLED=false, which was introduced in n8n version 1.104.0, and configuring n8n to use the task runner based Python sandbox via the N8N_RUNNERS_ENABLED and N8N_NATIVE_PYTHON_RUNNER environment variables.

- [https://github.com/eshan014/Internship_project_02](https://github.com/eshan014/Internship_project_02) :  ![starts](https://img.shields.io/github/stars/eshan014/Internship_project_02.svg) ![forks](https://img.shields.io/github/forks/eshan014/Internship_project_02.svg)


## CVE-2025-67644
 LangGraph SQLite Checkpoint is an implementation of LangGraph CheckpointSaver that uses SQLite DB (both sync and async, via aiosqlite). Versions 3.0.0 and below are vulnerable to SQL injection through the checkpoint implementation. Checkpoint allows attackers to manipulate SQL queries through metadata filter keys, affecting applications that accept untrusted metadata filter keys (not just filter values) in checkpoint search operations. The _metadata_predicate() function constructs SQL queries by interpolating filter keys directly into f-strings without validation. This issue is fixed in version 3.0.1.

- [https://github.com/mbanyamer/CVE-2025-67644-LangGraph-3.0.1-SQLite-Checkpoint-SQL-Injection](https://github.com/mbanyamer/CVE-2025-67644-LangGraph-3.0.1-SQLite-Checkpoint-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-67644-LangGraph-3.0.1-SQLite-Checkpoint-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-67644-LangGraph-3.0.1-SQLite-Checkpoint-SQL-Injection.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-50738
 The Memos application, up to version v0.24.3, allows for the embedding of markdown images with arbitrary URLs. When a user views a memo containing such an image, their browser automatically fetches the image URL without explicit user consent or interaction beyond viewing the memo. This can be exploited by an attacker to disclose the viewing user's IP address, browser User-Agent string, and potentially other request-specific information to the attacker-controlled server, leading to information disclosure and user tracking.

- [https://github.com/tiemio/CVE-2025-50738-PoC](https://github.com/tiemio/CVE-2025-50738-PoC) :  ![starts](https://img.shields.io/github/stars/tiemio/CVE-2025-50738-PoC.svg) ![forks](https://img.shields.io/github/forks/tiemio/CVE-2025-50738-PoC.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/popyue/CVE-2025-47812](https://github.com/popyue/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/popyue/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/popyue/CVE-2025-47812.svg)


## CVE-2025-47181
 Improper link resolution before file access ('link following') in Microsoft Edge (Chromium-based) allows an authorized attacker to elevate privileges locally.

- [https://github.com/d3vn0mi/cve_2025_471812_poc](https://github.com/d3vn0mi/cve_2025_471812_poc) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/cve_2025_471812_poc.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/cve_2025_471812_poc.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit](https://github.com/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit) :  ![starts](https://img.shields.io/github/stars/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg) ![forks](https://img.shields.io/github/forks/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit](https://github.com/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit) :  ![starts](https://img.shields.io/github/stars/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg) ![forks](https://img.shields.io/github/forks/iOxsec/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg)


## CVE-2025-4138
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/d3vn0mi/cve_2025_4138_poc](https://github.com/d3vn0mi/cve_2025_4138_poc) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/cve_2025_4138_poc.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/cve_2025_4138_poc.svg)


## CVE-2025-2026
An authenticated remote attacker with web read-only privileges can exploit the vulnerable API to inject malicious input. Successful exploitation may cause the device to reboot, disrupting normal operations and causing a temporary denial of service.

- [https://github.com/magercode/List-CVE-2025-2026](https://github.com/magercode/List-CVE-2025-2026) :  ![starts](https://img.shields.io/github/stars/magercode/List-CVE-2025-2026.svg) ![forks](https://img.shields.io/github/forks/magercode/List-CVE-2025-2026.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/BLUEBERRYP1LL/CVE-2024-46987](https://github.com/BLUEBERRYP1LL/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/BLUEBERRYP1LL/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/BLUEBERRYP1LL/CVE-2024-46987.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/Pegasus0xx/CVE-2023-43208](https://github.com/Pegasus0xx/CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/Pegasus0xx/CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/Pegasus0xx/CVE-2023-43208.svg)


## CVE-2022-42703
 mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.

- [https://github.com/Squirre17/hbp-attack-demo](https://github.com/Squirre17/hbp-attack-demo) :  ![starts](https://img.shields.io/github/stars/Squirre17/hbp-attack-demo.svg) ![forks](https://img.shields.io/github/forks/Squirre17/hbp-attack-demo.svg)
- [https://github.com/Satheesh575555/linux-4.1.15_CVE-2022-42703](https://github.com/Satheesh575555/linux-4.1.15_CVE-2022-42703) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/linux-4.1.15_CVE-2022-42703.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/linux-4.1.15_CVE-2022-42703.svg)


## CVE-2022-42096
 Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via Post content.

- [https://github.com/bypazs/CVE-2022-42096](https://github.com/bypazs/CVE-2022-42096) :  ![starts](https://img.shields.io/github/stars/bypazs/CVE-2022-42096.svg) ![forks](https://img.shields.io/github/forks/bypazs/CVE-2022-42096.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)

