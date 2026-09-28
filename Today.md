# Update 2026-09-28
## CVE-2026-97163
 Joomla Extension - lomart.fr - Unauthenticated remote code installation in UP plugin extension 5.0.0-5.2.0, 6.0.0-6.0.29

- [https://github.com/murrez/CVE-2026-97163](https://github.com/murrez/CVE-2026-97163) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-97163.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-97163.svg)
- [https://github.com/qeize/cve-2026-97163-payload](https://github.com/qeize/cve-2026-97163-payload) :  ![starts](https://img.shields.io/github/stars/qeize/cve-2026-97163-payload.svg) ![forks](https://img.shields.io/github/forks/qeize/cve-2026-97163-payload.svg)


## CVE-2026-97161
 Joomla Extension - lomart.fr - Various path traversal / file access vectors in UP plugin extension 5.0.0-5.2.0, 6.0.0-6.0.29

- [https://github.com/murrez/CVE-2026-97161](https://github.com/murrez/CVE-2026-97161) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-97161.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-97161.svg)


## CVE-2026-97160
 Joomla Extension - lomart.fr - Authenticated, privileged PHP command injection in UP plugin extension 5.0.0-5.2.0, 6.0.0-6.0.29

- [https://github.com/murrez/CVE-2026-97160](https://github.com/murrez/CVE-2026-97160) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-97160.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-97160.svg)


## CVE-2026-94132
 Joomla Extension - acymailing.com - Remote Code Execution vulnerability in mailbox action feature in AcyMailing Enterprise extension  11.1.0 - MIME parts of incoming emails were saved to media/com_acym/upload/ with no extension check, so anyone who could email the monitored mailbox could write a PHP file into the web root.

- [https://github.com/murrez/CVE-2026-94132](https://github.com/murrez/CVE-2026-94132) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-94132.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-94132.svg)


## CVE-2026-94130
 Joomla Extension - joomlaboat.com - Unauthenticated SQL injection in YouTube Gallery extension  5.7.3 - An SQL injection vulnerability in video search functionality and sorting allowed attackers to inject SQL commands in read queries.

- [https://github.com/murrez/CVE-2026-94130](https://github.com/murrez/CVE-2026-94130) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-94130.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-94130.svg)


## CVE-2026-93834
 A use-after-free vulnerability was found in QEMU's 9pfs subsystem. A race condition between the main thread and a worker thread when processing concurrent Tlcreate and Twalk requests allows a malicious guest user to craft a fid path containing stale heap data, bypassing directory traversal restrictions and escaping the shared directory boundary. This can lead to arbitrary host file read/write and code execution (VM escape) as the QEMU process user.

- [https://github.com/suominen/CVE-2026-93834](https://github.com/suominen/CVE-2026-93834) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-93834.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-93834.svg)


## CVE-2026-93485
The Unauthenticated Stored XSS vulnerability in the WordPress core can be reproduced on a default WordPress installation. Comment moderation is disabled by default, and the requirement for commenters to have a previously approved comment can be bypassed.

- [https://github.com/686f6c61/POC-WP-CORE-CVE-2026-93485](https://github.com/686f6c61/POC-WP-CORE-CVE-2026-93485) :  ![starts](https://img.shields.io/github/stars/686f6c61/POC-WP-CORE-CVE-2026-93485.svg) ![forks](https://img.shields.io/github/forks/686f6c61/POC-WP-CORE-CVE-2026-93485.svg)


## CVE-2026-90817
 An unauthenticated Remote Code Execution vulnerability was found in the survey passthrough routing and Data Import processing logic, in which a malicious user could potentially exploit it by manipulating HTTP requests to access an unintended controller route from a public survey context and by supplying a crafted file-path/stream parameter during import handling. If successfully exploited, this could allow the attacker to remotely execute arbitrary code on the REDCap server. The attacker does not have to be authenticated in order to exploit this, but exploitation requires knowledge of a valid public survey hash. This vulnerability exists in REDCap 13.3.0 and higher.

- [https://github.com/Farih123/CVE-2026-90817](https://github.com/Farih123/CVE-2026-90817) :  ![starts](https://img.shields.io/github/stars/Farih123/CVE-2026-90817.svg) ![forks](https://img.shields.io/github/forks/Farih123/CVE-2026-90817.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/rwxrwxs/CVE-2026-87902](https://github.com/rwxrwxs/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/rwxrwxs/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/rwxrwxs/CVE-2026-87902.svg)
- [https://github.com/itskill-jp/wordpress-upgrade-check](https://github.com/itskill-jp/wordpress-upgrade-check) :  ![starts](https://img.shields.io/github/stars/itskill-jp/wordpress-upgrade-check.svg) ![forks](https://img.shields.io/github/forks/itskill-jp/wordpress-upgrade-check.svg)


## CVE-2026-86060
path involving usernames that begin with a prohibited character, allowing for the trusted RouterOS policy mask to be changed, leading to privilege escalation. Exploitation requires an unauthenticated SSH session to reach the RouterOS login helper.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/HackSpeak/CVE-2026-67279](https://github.com/HackSpeak/CVE-2026-67279) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-67279.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-67279.svg)


## CVE-2026-82901
 The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Arbitrary File Upload due to insufficient file type validation in the 'uacf7_wpcf7_mail_components' function in all versions up to, and including, 3.5.50. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: This is only exploitable when the plugin's PDF Generator module is enabled, which is disabled by default.

- [https://github.com/murrez/CVE-2026-82901](https://github.com/murrez/CVE-2026-82901) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-82901.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-82901.svg)


## CVE-2026-75650
 Adobe Commerce is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability that could result in arbitrary code execution in the context of the current user. An attacker could exploit this vulnerability to execute arbitrary code. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/abraxas/CVE-2026-75650](https://github.com/abraxas/CVE-2026-75650) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-75650.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-75650.svg)


## CVE-2026-67279
 RouterOS SSH enters the connection protocol after a client-requested rekey even though user authentication was never attempted, allowing an unauthenticated client to open a session channel and send an exec request. On affected builds the server dispatches the command, enabling unauthenticated creation, overwrite, and reconstruction of files in the RouterOS managed file namespace, including support files containing configuration and diagnostic data.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/HackSpeak/CVE-2026-67279](https://github.com/HackSpeak/CVE-2026-67279) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-67279.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-67279.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/k4ntux/COWSlip](https://github.com/k4ntux/COWSlip) :  ![starts](https://img.shields.io/github/stars/k4ntux/COWSlip.svg) ![forks](https://img.shields.io/github/forks/k4ntux/COWSlip.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/qingle009/opace6-cve-2026-64560](https://github.com/qingle009/opace6-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/qingle009/opace6-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/qingle009/opace6-cve-2026-64560.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/langz337/CVE-2026-63030](https://github.com/langz337/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/langz337/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/langz337/CVE-2026-63030.svg)


## CVE-2026-61500
 Rejetto HFS 3.0.0 through 3.2.0 derives its session-cookie signing key from the non-cryptographic Math.random() generator and discloses outputs of the same generator to unauthenticated clients during login. A remote attacker can collect a small number of login responses, reconstruct the generator's state, recover the signing key, and forge a valid administrator session cookie, leading to full administrative access and remote code execution via the server_code configuration feature.

- [https://github.com/aramosf/CVE-2026-61500](https://github.com/aramosf/CVE-2026-61500) :  ![starts](https://img.shields.io/github/stars/aramosf/CVE-2026-61500.svg) ![forks](https://img.shields.io/github/forks/aramosf/CVE-2026-61500.svg)


## CVE-2026-52782
 OpenProject is open-source, web-based project management software. Prior to 17.3.3 and 17.4.1, there is an IDOR through /projects/A/settings/project_storages/A_ps_id via PATCH parameter "storages_project_storage[project_folder_id]" leads to Access to Unauthorized Resources. A project-admin in one project can hijack the managed Nextcloud or OneDrive folder of another project on the same storage by writing the victim project's project_folder_id into the attacker's Storages::ProjectStorage row. The next managed-folder sync overwrites the ACL on the referenced folder with the attacker project's user list. This vulnerability is fixed in 17.3.3 and 17.4.1.

- [https://github.com/abraxas/CVE-2026-52782](https://github.com/abraxas/CVE-2026-52782) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-52782.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-52782.svg)


## CVE-2026-48356
 Adobe Commerce is affected by an Unrestricted Upload of File with Dangerous Type vulnerability that could result in arbitrary code execution in the context of the current user, potentially gaining elevated access or control over the victim's account or session. Exploitation of this issue requires user interaction in that a victim must visit a maliciously crafted URL or interact with a compromised web page. Scope is changed.

- [https://github.com/abraxas/CVE-2026-48356](https://github.com/abraxas/CVE-2026-48356) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-48356.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-48356.svg)


## CVE-2026-43786
 This issue was addressed with additional entitlement checks. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An app may be able to gain root privileges.

- [https://github.com/0xBlackash/CVE-2026-43786](https://github.com/0xBlackash/CVE-2026-43786) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43786.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43786.svg)


## CVE-2026-43682
 The issue was addressed with improved memory handling. This issue is fixed in macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6. A remote user may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/petermalone/CVE-2026-43682](https://github.com/petermalone/CVE-2026-43682) :  ![starts](https://img.shields.io/github/stars/petermalone/CVE-2026-43682.svg) ![forks](https://img.shields.io/github/forks/petermalone/CVE-2026-43682.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/pyyyc/honor-6.12.38-43499-research](https://github.com/pyyyc/honor-6.12.38-43499-research) :  ![starts](https://img.shields.io/github/stars/pyyyc/honor-6.12.38-43499-research.svg) ![forks](https://img.shields.io/github/forks/pyyyc/honor-6.12.38-43499-research.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/hitechcloud-vietnam/cve-2026-41940-PoC](https://github.com/hitechcloud-vietnam/cve-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/hitechcloud-vietnam/cve-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/hitechcloud-vietnam/cve-2026-41940-PoC.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/1posix/CVE-2026-41089-POC](https://github.com/1posix/CVE-2026-41089-POC) :  ![starts](https://img.shields.io/github/stars/1posix/CVE-2026-41089-POC.svg) ![forks](https://img.shields.io/github/forks/1posix/CVE-2026-41089-POC.svg)


## CVE-2026-29053
 Ghost is a Node.js content management system. From version 0.7.2 to 6.19.0, specifically crafted malicious themes can execute arbitrary code on the server running Ghost. This issue has been patched in version 6.19.1.

- [https://github.com/K3ysTr0K3R/CVE-2026-29053](https://github.com/K3ysTr0K3R/CVE-2026-29053) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-29053.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-29053.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/wvverez/CVE-2026-23744](https://github.com/wvverez/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2026-23744.svg)


## CVE-2026-22599
 Strapi is an open source headless content management system. In versions on the 4.x branch prior to 4.26.1 and on the 5.x branch prior to 5.33.2, a database-query injection vulnerability existed in the Strapi Content-Type Builder write API. An authenticated administrator could inject arbitrary database statements through the `column.defaultTo` attribute when creating or modifying a content type. Setting `defaultTo` as a tuple `[value, { isRaw: true }]` caused the value to be passed directly into Knex's `db.connection.raw()` during schema migration without sanitization, allowing arbitrary statement execution at the database layer. Depending on the database engine, this enabled arbitrary file read via database utility functions, denial of service via forced server crash on schema-migration error, and on engines that permit external program execution, remote code execution against the database server. The patch in versions 4.26.1 and 5.33.2 addresses this by restricting all Content-Type Builder write APIs to development mode only. Production deployments running v5.33.2 or later return 404 for requests against `/content-type-builder/content-types` and related endpoints, removing the network-reachable attack surface entirely.

- [https://github.com/abraxas/CVE-2026-22599](https://github.com/abraxas/CVE-2026-22599) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-22599.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-22599.svg)


## CVE-2026-18143
 The Request a Quote for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.9.2 via the `afrfq_submit_quote_via_popup()` function. This is due to missing file extension and MIME type validation in the popup upload handler, which uses the raw attacker-supplied filename directly as the destination for `move_uploaded_file()`. This makes it possible for unauthenticated attackers to upload executable files, such as PHP files, to a web-accessible temporary RFQ upload directory when a public quote rule with the multi-page popup flow is enabled.

- [https://github.com/murrez/CVE-2026-18143](https://github.com/murrez/CVE-2026-18143) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-18143.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-18143.svg)


## CVE-2026-15583
 A confused-deputy flaw in Grafana MCP Server allows an unauthenticated remote attacker to exfiltrate the server's environment-configured Grafana service-account token by supplying a crafted X-Grafana-URL request header. This also enables SSRF against arbitrary internal services, including cloud metadata endpoints.

- [https://github.com/abraxas/CVE-2026-15583](https://github.com/abraxas/CVE-2026-15583) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-15583.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-15583.svg)


## CVE-2026-14281
 The Automation Web Platform – Notifications and OTP for WooCommerce, Advanced Country Code plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.8.6. This is due to missing permission enforcement on the publicly accessible REST route `POST /wp-json/wawp/v1/signup/op` and the absence of a key allowlist in the `finish_registration_logic` function, which copies the attacker-controlled `wawp_custom_fields` parameter directly into `update_user_meta()` — allowing sensitive meta keys such as `wp_capabilities` and `wp_user_level` to be set by the caller. This makes it possible for unauthenticated attackers to register a new account with the administrator role and gain full administrative access to the site. When OTP verification is enabled at signup, the OTP session token (`otp_transient`) is returned in plaintext in the HTTP response body, and the `handle_magic_link_request()` handler marks that token as verified on any unauthenticated GET request containing it without ever checking the OTP code value — making the OTP step trivially bypassable with no inbox or SMS access required.

- [https://github.com/langz337/CVE-2026-14281](https://github.com/langz337/CVE-2026-14281) :  ![starts](https://img.shields.io/github/stars/langz337/CVE-2026-14281.svg) ![forks](https://img.shields.io/github/forks/langz337/CVE-2026-14281.svg)


## CVE-2026-13249
An attacker could potentially exploit this vulnerability, leading to the execution of malicious files and commands. Honeywell also recommends updating to the most recent firmware version, Honeywell PD45 Industrial Printer firmware F10.22.030745, which includes a fix for this vulnerability.

- [https://github.com/murrez/CVE-2026-13249](https://github.com/murrez/CVE-2026-13249) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-13249.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-13249.svg)


## CVE-2026-6532
 Kismet protocol dissector crash in Wireshark 4.6.0 to 4.6.4 and 4.4.0 to 4.4.14 allows denial of service

- [https://github.com/rahulreddykarne/CVE-2026-65320-fastcore](https://github.com/rahulreddykarne/CVE-2026-65320-fastcore) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-65320-fastcore.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-65320-fastcore.svg)


## CVE-2026-5783
This issue affects CityPLus: before V24.29750.1.0.

- [https://github.com/rahulreddykarne/CVE-2026-57836-Confluent_Kafka](https://github.com/rahulreddykarne/CVE-2026-57836-Confluent_Kafka) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-57836-Confluent_Kafka.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-57836-Confluent_Kafka.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/maniakh/CVE-2026-31431---Copy-Fail-PoC](https://github.com/maniakh/CVE-2026-31431---Copy-Fail-PoC) :  ![starts](https://img.shields.io/github/stars/maniakh/CVE-2026-31431---Copy-Fail-PoC.svg) ![forks](https://img.shields.io/github/forks/maniakh/CVE-2026-31431---Copy-Fail-PoC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/0o176/CVE-2024-37054_PoC_HTB_SmartHire](https://github.com/0o176/CVE-2024-37054_PoC_HTB_SmartHire) :  ![starts](https://img.shields.io/github/stars/0o176/CVE-2024-37054_PoC_HTB_SmartHire.svg) ![forks](https://img.shields.io/github/forks/0o176/CVE-2024-37054_PoC_HTB_SmartHire.svg)


## CVE-2023-41080
The vulnerability is limited to the ROOT (default) web application.

- [https://github.com/sotiak/CVE-2023-41080](https://github.com/sotiak/CVE-2023-41080) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2023-41080.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2023-41080.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard and the Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-right and right-to-left characters, the visual order of tokens may be different from their logical order. Additionally, control characters needed to fully support the requirements of bidirectional text can further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such that the ordering of tokens perceived by human reviewers does not match what will be processed by a compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.

- [https://github.com/sotiak/CVE-2021-42574](https://github.com/sotiak/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-42574.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)


## CVE-2020-14008
 Zoho ManageEngine Applications Manager 14710 and before allows an authenticated admin user to upload a vulnerable jar in a specific location, which leads to remote code execution.

- [https://github.com/raflesiait/CVE-2020-14008](https://github.com/raflesiait/CVE-2020-14008) :  ![starts](https://img.shields.io/github/stars/raflesiait/CVE-2020-14008.svg) ![forks](https://img.shields.io/github/forks/raflesiait/CVE-2020-14008.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/linusboz12345-sys/cve-2020-0796-scanner](https://github.com/linusboz12345-sys/cve-2020-0796-scanner) :  ![starts](https://img.shields.io/github/stars/linusboz12345-sys/cve-2020-0796-scanner.svg) ![forks](https://img.shields.io/github/forks/linusboz12345-sys/cve-2020-0796-scanner.svg)

