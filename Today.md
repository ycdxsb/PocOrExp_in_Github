# Update 2026-07-28
## CVE-2026-66012
 SiYuan before v3.7.2 contains a missing authorization vulnerability in the POST /mcp kernel endpoint, which is gated only by a general auth check (model.CheckAuth) with no admin-role or read-only enforcement. This exposes 31 MCP tools, including a file tool with list/read/write/delete/rename/copy actions across the entire workspace. When the Publish server is enabled in anonymous mode (Conf.Publish.Enable=true and Conf.Publish.Auth.Enable=false), the Publish reverse proxy attaches an anonymous RoleReader JWT to proxied requests, allowing a remote unauthenticated attacker to reach /mcp. The attacker can read conf/conf.json to extract accessAuthCode, api.token, and cookieKey in plaintext, write arbitrary files in the workspace, and plant a plugin into data/plugins/ that executes with nodeIntegration:true and no contextIsolation on the next desktop launch, leading to administrator takeover.

- [https://github.com/Hunt-Benito/siyuan-mcp-admin-takeover-cve-2026-66012-missing-authorization](https://github.com/Hunt-Benito/siyuan-mcp-admin-takeover-cve-2026-66012-missing-authorization) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/siyuan-mcp-admin-takeover-cve-2026-66012-missing-authorization.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/siyuan-mcp-admin-takeover-cve-2026-66012-missing-authorization.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/Debajyoti0-0/CVE-2026-64600](https://github.com/Debajyoti0-0/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/Debajyoti0-0/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/Debajyoti0-0/CVE-2026-64600.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/Dungsocool/CVE-2026-60137_CVE-2026-63030](https://github.com/Dungsocool/CVE-2026-60137_CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2026-60137_CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2026-60137_CVE-2026-63030.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/northsia/CVE-2026-60137-With-Skip-SSL](https://github.com/northsia/CVE-2026-60137-With-Skip-SSL) :  ![starts](https://img.shields.io/github/stars/northsia/CVE-2026-60137-With-Skip-SSL.svg) ![forks](https://img.shields.io/github/forks/northsia/CVE-2026-60137-With-Skip-SSL.svg)


## CVE-2026-58480
 Blocksy Companion Pro plugin for WordPress before 2.1.47 contains an unauthenticated arbitrary file upload vulnerability that allows attackers to upload executable files by bypassing extension validation in the save_attachments function exposed through the Advanced Reviews feature. Attackers can exploit the Custom Fonts extension's flawed strpos() substring check by uploading double-extension filenames such as shell.woff2.php, causing the validation to pass on the substring match while the web server executes the file as PHP, achieving remote code execution.

- [https://github.com/shinthink/CVE-2026-58480](https://github.com/shinthink/CVE-2026-58480) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-58480.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-58480.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/Procjevt/CVE-2026-58138](https://github.com/Procjevt/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/Procjevt/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/Procjevt/CVE-2026-58138.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/GlendonNotGlen/certighost-cve-2026-54121-slides](https://github.com/GlendonNotGlen/certighost-cve-2026-54121-slides) :  ![starts](https://img.shields.io/github/stars/GlendonNotGlen/certighost-cve-2026-54121-slides.svg) ![forks](https://img.shields.io/github/forks/GlendonNotGlen/certighost-cve-2026-54121-slides.svg)


## CVE-2026-53753
 Crawl4AI is an open-source LLM friendly web crawler & scraper. Prior to 0.8.7, the _safe_eval_expression() function in the computed fields feature uses an AST validator that only blocks attributes starting with underscore. Python generator and frame object attributes (gi_frame, f_back, f_builtins) do NOT start with underscore, enabling a complete sandbox escape to achieve arbitrary code execution. The attack requires no authentication (JWT disabled by default) and is triggered via POST /crawl with a crafted extraction schema. This vulnerability is fixed in 0.8.7.

- [https://github.com/0xEnc0der/CVE-2026-53753](https://github.com/0xEnc0der/CVE-2026-53753) :  ![starts](https://img.shields.io/github/stars/0xEnc0der/CVE-2026-53753.svg) ![forks](https://img.shields.io/github/forks/0xEnc0der/CVE-2026-53753.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU](https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU) :  ![starts](https://img.shields.io/github/stars/woshimaniubi8/CVE-2026-43499-root-KernelSU.svg) ![forks](https://img.shields.io/github/forks/woshimaniubi8/CVE-2026-43499-root-KernelSU.svg)
- [https://github.com/fusiondrive/CVE-2026-43499-S24U](https://github.com/fusiondrive/CVE-2026-43499-S24U) :  ![starts](https://img.shields.io/github/stars/fusiondrive/CVE-2026-43499-S24U.svg) ![forks](https://img.shields.io/github/forks/fusiondrive/CVE-2026-43499-S24U.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/CerberusMrXi/cPanel-WHM-CVE-2026-41940-auth-bypass-exploit](https://github.com/CerberusMrXi/cPanel-WHM-CVE-2026-41940-auth-bypass-exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/cPanel-WHM-CVE-2026-41940-auth-bypass-exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/cPanel-WHM-CVE-2026-41940-auth-bypass-exploit.svg)


## CVE-2026-41179
 Rclone is a command-line program to sync files and directories to and from different cloud storage providers. Starting in version 1.48.0 and prior to version 1.73.5, the RC endpoint `operations/fsinfo` is exposed without `AuthRequired: true` and accepts attacker-controlled `fs` input. Because `rc.GetFs(...)` supports inline backend definitions, an unauthenticated attacker can instantiate an attacker-controlled backend on demand. For the WebDAV backend, `bearer_token_command` is executed during backend initialization, making single-request unauthenticated local command execution possible on reachable RC deployments without global HTTP authentication. Version 1.73.5 patches the issue.

- [https://github.com/s-vx/CVE-2026-41179](https://github.com/s-vx/CVE-2026-41179) :  ![starts](https://img.shields.io/github/stars/s-vx/CVE-2026-41179.svg) ![forks](https://img.shields.io/github/forks/s-vx/CVE-2026-41179.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/kinryulabs/rootpacket-cve-2026-31431](https://github.com/kinryulabs/rootpacket-cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/kinryulabs/rootpacket-cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/kinryulabs/rootpacket-cve-2026-31431.svg)


## CVE-2026-15981
 The SAML Single Sign On – SSO Login plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 5.4.4. This is due to the mo_saml_validate_signature() function performing a loose boolean check on the raw tri-state integer returned by PHP's openssl_verify(), causing an error return value of -1 to be evaluated as truthy and therefore treated as a successful signature verification. This makes it possible for unauthenticated attackers to log in as any existing WordPress user, including administrators, by submitting a crafted SAMLResponse containing an attacker-controlled NameID and a deliberately malformed signature value that triggers an OpenSSL processing error — bypassing verification entirely and resulting in wp_set_auth_cookie() being called for the targeted account.

- [https://github.com/Nxploited/CVE-2026-15981](https://github.com/Nxploited/CVE-2026-15981) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-15981.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-15981.svg)


## CVE-2026-15158
 The Blocksy Companion plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.1.46 via the save_attachments function. This is due to the Custom Fonts extension registering a wp_check_filetype_and_ext filter that approves any filename containing .woff2 or .ttf as a substring via strpos() rather than validating that those strings appear as the final extension via PATHINFO_EXTENSION — allowing double-extension filenames such as shell.woff2.php to pass MIME validation and be handled as permitted font files. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible. This vulnerability is only exploitable when the premium version of the plugin (blocksy-companion-pro) is installed with both the WooCommerce Extra (Advanced Reviews) and Custom Fonts extensions active; the free blocksy-companion plugin does not contain the vulnerable code paths.

- [https://github.com/shinthink/CVE-2026-58480](https://github.com/shinthink/CVE-2026-58480) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-58480.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-58480.svg)


## CVE-2026-10818
 The WPForms Pro plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.10.1.1 via the ajax_chunk_upload_finalize function. This is due to the file type validation occurring after chunk metadata and file contents have already been written to disk, and the assembled file not being deleted upon validation failure. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.

- [https://github.com/Nxploited/CVE-2026-10818](https://github.com/Nxploited/CVE-2026-10818) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-10818.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-10818.svg)


## CVE-2026-4861
 A weakness has been identified in Wavlink WL-NU516U1 260227. This vulnerability affects the function ftext of the file /cgi-bin/nas.cgi. This manipulation of the argument Content-Length causes stack-based buffer overflow. The attack can be initiated remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/HORKimhab/CVE-2026-4861](https://github.com/HORKimhab/CVE-2026-4861) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-4861.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-4861.svg)


## CVE-2026-3306
 An improper authorization vulnerability was identified in GitHub Enterprise Server that allowed a user with read access to a repository and write access to a project to modify issue and pull request metadata through the project. When adding an item to a project that already existed, column value updates were applied without verifying the actor's repository write permissions. This vulnerability was reported via the GitHub Bug Bounty program and has been fixed in GitHub Enterprise Server versions 3.14.24, 3.15.19, 3.16.15, 3.17.12, 3.18.6 and 3.19.3.

- [https://github.com/darrocarocatest-sys/pv2-victim](https://github.com/darrocarocatest-sys/pv2-victim) :  ![starts](https://img.shields.io/github/stars/darrocarocatest-sys/pv2-victim.svg) ![forks](https://img.shields.io/github/forks/darrocarocatest-sys/pv2-victim.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/Saied25/fix-react2shell-next](https://github.com/Saied25/fix-react2shell-next) :  ![starts](https://img.shields.io/github/stars/Saied25/fix-react2shell-next.svg) ![forks](https://img.shields.io/github/forks/Saied25/fix-react2shell-next.svg)
- [https://github.com/Mayca369/CVE-2025-55182](https://github.com/Mayca369/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Mayca369/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Mayca369/CVE-2025-55182.svg)


## CVE-2025-62215
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/nullxall/cve-2025-62215-exploit-poc](https://github.com/nullxall/cve-2025-62215-exploit-poc) :  ![starts](https://img.shields.io/github/stars/nullxall/cve-2025-62215-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/nullxall/cve-2025-62215-exploit-poc.svg)


## CVE-2025-32711
 Ai command injection in M365 Copilot allows an unauthorized attacker to disclose information over a network.

- [https://github.com/vikasudasi/exfil-scan](https://github.com/vikasudasi/exfil-scan) :  ![starts](https://img.shields.io/github/stars/vikasudasi/exfil-scan.svg) ![forks](https://img.shields.io/github/forks/vikasudasi/exfil-scan.svg)


## CVE-2025-2945
This issue affects pgAdmin 4: before 9.2.

- [https://github.com/Udayveer17/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-](https://github.com/Udayveer17/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-) :  ![starts](https://img.shields.io/github/stars/Udayveer17/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-.svg) ![forks](https://img.shields.io/github/forks/Udayveer17/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/kxom9ks/CVE-2024-27198-TeamCity](https://github.com/kxom9ks/CVE-2024-27198-TeamCity) :  ![starts](https://img.shields.io/github/stars/kxom9ks/CVE-2024-27198-TeamCity.svg) ![forks](https://img.shields.io/github/forks/kxom9ks/CVE-2024-27198-TeamCity.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/yuimamur/CVE-2024-4367-hands-on](https://github.com/yuimamur/CVE-2024-4367-hands-on) :  ![starts](https://img.shields.io/github/stars/yuimamur/CVE-2024-4367-hands-on.svg) ![forks](https://img.shields.io/github/forks/yuimamur/CVE-2024-4367-hands-on.svg)
- [https://github.com/yuimamur/CVE-2024-4367-hands-on-01](https://github.com/yuimamur/CVE-2024-4367-hands-on-01) :  ![starts](https://img.shields.io/github/stars/yuimamur/CVE-2024-4367-hands-on-01.svg) ![forks](https://img.shields.io/github/forks/yuimamur/CVE-2024-4367-hands-on-01.svg)


## CVE-2024-1813
 The Simple Job Board plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 2.11.0 via deserialization of untrusted input in the job_board_applicant_list_columns_value function. This makes it possible for unauthenticated attackers to inject a PHP Object. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code when a submitted job application is viewed.

- [https://github.com/MobetaSec/CVE-2024-1813-POC](https://github.com/MobetaSec/CVE-2024-1813-POC) :  ![starts](https://img.shields.io/github/stars/MobetaSec/CVE-2024-1813-POC.svg) ![forks](https://img.shields.io/github/forks/MobetaSec/CVE-2024-1813-POC.svg)


## CVE-2024-0582
 A memory leak flaw was found in the Linux kernel’s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/nanabingies/CVE-2024-0582](https://github.com/nanabingies/CVE-2024-0582) :  ![starts](https://img.shields.io/github/stars/nanabingies/CVE-2024-0582.svg) ![forks](https://img.shields.io/github/forks/nanabingies/CVE-2024-0582.svg)

