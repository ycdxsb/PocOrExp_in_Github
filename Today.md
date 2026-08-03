# Update 2026-08-03
## CVE-2026-67595
 VaahCMS versions 2.0.0 through 2.3.4 contain a malicious obfuscated JavaScript payload embedded in the Blade template responsible for rendering security OTP emails, allowing remote attackers to execute unauthorized code in any browser that renders the affected email template with JavaScript enabled. The payload establishes a WebSocket connection to a hardcoded command-and-control endpoint, installs a password-field keylogger using MutationObserver to capture dynamically added inputs, scrapes WhatsApp Web DOM content, and accepts remote commands to redirect or overwrite the rendered page.

- [https://github.com/IlhomjonR/CVE-2026-67595](https://github.com/IlhomjonR/CVE-2026-67595) :  ![starts](https://img.shields.io/github/stars/IlhomjonR/CVE-2026-67595.svg) ![forks](https://img.shields.io/github/forks/IlhomjonR/CVE-2026-67595.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/0xBlackash/CVE-2026-64531](https://github.com/0xBlackash/CVE-2026-64531) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-64531.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-64531.svg)
- [https://github.com/suominen/ovswrap](https://github.com/suominen/ovswrap) :  ![starts](https://img.shields.io/github/stars/suominen/ovswrap.svg) ![forks](https://img.shields.io/github/forks/suominen/ovswrap.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/michael-kanda/Wp2shell-ioc-scanner](https://github.com/michael-kanda/Wp2shell-ioc-scanner) :  ![starts](https://img.shields.io/github/stars/michael-kanda/Wp2shell-ioc-scanner.svg) ![forks](https://img.shields.io/github/forks/michael-kanda/Wp2shell-ioc-scanner.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/michael-kanda/Wp2shell-ioc-scanner](https://github.com/michael-kanda/Wp2shell-ioc-scanner) :  ![starts](https://img.shields.io/github/stars/michael-kanda/Wp2shell-ioc-scanner.svg) ![forks](https://img.shields.io/github/forks/michael-kanda/Wp2shell-ioc-scanner.svg)


## CVE-2026-53576
 Kestra is an open-source, event-driven orchestration platform. Prior to 1.0.45 and 1.3.21, the authentication filter for the REST API (@Filter("/api/v1/**")) treats any request whose path ends in /configs as the public instance-config endpoint and forwards it without a credential check. kestra addresses its resources by URL path segments that the caller chooses (/api/v1/{tenant}/flows/{namespace}, /api/v1/{tenant}/executions/{namespace}/{id}, /api/v1/{tenant}/namespaces/{namespace}/kv/{key}). An anonymous caller picks the literal configs as the final segment, and the request bypasses Basic-Auth entirely. Because the bypass reaches the flow-create and execution-trigger routes, an unauthenticated caller creates a flow containing a Shell or Process task and runs it. The task executes as root inside the kestra container. The official docker-compose.yml mounts /var/run/docker.sock, so root in the container reaches the host Docker daemon. This vulnerability is fixed in 1.0.45 and 1.3.21.

- [https://github.com/TamatahYT/CVE-2026-53576](https://github.com/TamatahYT/CVE-2026-53576) :  ![starts](https://img.shields.io/github/stars/TamatahYT/CVE-2026-53576.svg) ![forks](https://img.shields.io/github/forks/TamatahYT/CVE-2026-53576.svg)


## CVE-2026-53366
paged path, so remove the stale comment describing that old arithmetic.

- [https://github.com/suominen/ipv6_frag_escape](https://github.com/suominen/ipv6_frag_escape) :  ![starts](https://img.shields.io/github/stars/suominen/ipv6_frag_escape.svg) ![forks](https://img.shields.io/github/forks/suominen/ipv6_frag_escape.svg)


## CVE-2026-53362
case, remove the MSG_SPLICE_PAGES exception from the negative copy check.

- [https://github.com/suominen/ipv6_frag_escape](https://github.com/suominen/ipv6_frag_escape) :  ![starts](https://img.shields.io/github/stars/suominen/ipv6_frag_escape.svg) ![forks](https://img.shields.io/github/forks/suominen/ipv6_frag_escape.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/suominen/januscape](https://github.com/suominen/januscape) :  ![starts](https://img.shields.io/github/stars/suominen/januscape.svg) ![forks](https://img.shields.io/github/forks/suominen/januscape.svg)


## CVE-2026-46316
the behavior is unchanged when only one context runs.

- [https://github.com/suominen/itscape](https://github.com/suominen/itscape) :  ![starts](https://img.shields.io/github/stars/suominen/itscape.svg) ![forks](https://img.shields.io/github/forks/suominen/itscape.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/suominen/cifswitch](https://github.com/suominen/cifswitch) :  ![starts](https://img.shields.io/github/stars/suominen/cifswitch.svg) ![forks](https://img.shields.io/github/forks/suominen/cifswitch.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/yellowkeybitlocker/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/yellowkeybitlocker/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/yellowkeybitlocker/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/yellowkeybitlocker/YellowKey-Bitlocker-CVE-2026-45585.svg)
- [https://github.com/Aqua1214/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/Aqua1214/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/Aqua1214/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/Aqua1214/YellowKey-Bitlocker-CVE-2026-45585.svg)


## CVE-2026-43502
lifetime rules without changing the normal queued completion path.

- [https://github.com/suominen/pintheft](https://github.com/suominen/pintheft) :  ![starts](https://img.shields.io/github/stars/suominen/pintheft.svg) ![forks](https://img.shields.io/github/forks/suominen/pintheft.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/suominen/CVE-2026-43284](https://github.com/suominen/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-43284.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/1ndevelopment/CVE-2026-43499-S26](https://github.com/1ndevelopment/CVE-2026-43499-S26) :  ![starts](https://img.shields.io/github/stars/1ndevelopment/CVE-2026-43499-S26.svg) ![forks](https://img.shields.io/github/forks/1ndevelopment/CVE-2026-43499-S26.svg)
- [https://github.com/CatXiaoShi/cve-2026-43499](https://github.com/CatXiaoShi/cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/CatXiaoShi/cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CatXiaoShi/cve-2026-43499.svg)
- [https://github.com/fusiondrive/CVE-2026-43499-A36](https://github.com/fusiondrive/CVE-2026-43499-A36) :  ![starts](https://img.shields.io/github/stars/fusiondrive/CVE-2026-43499-A36.svg) ![forks](https://img.shields.io/github/forks/fusiondrive/CVE-2026-43499-A36.svg)
- [https://github.com/veygax/HORiZonstack](https://github.com/veygax/HORiZonstack) :  ![starts](https://img.shields.io/github/stars/veygax/HORiZonstack.svg) ![forks](https://img.shields.io/github/forks/veygax/HORiZonstack.svg)
- [https://github.com/suominen/ghostlock](https://github.com/suominen/ghostlock) :  ![starts](https://img.shields.io/github/stars/suominen/ghostlock.svg) ![forks](https://img.shields.io/github/forks/suominen/ghostlock.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/suominen/pintheft](https://github.com/suominen/pintheft) :  ![starts](https://img.shields.io/github/stars/suominen/pintheft.svg) ![forks](https://img.shields.io/github/forks/suominen/pintheft.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/Kill1234545/CVE-2026-41940](https://github.com/Kill1234545/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Kill1234545/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Kill1234545/CVE-2026-41940.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)


## CVE-2026-15964
 The Single Sign On For TNG plugin for WordPress is vulnerable to Authentication Bypass via unauthenticated password reset in all versions up to, and including, 2.0.0. This is due to the `ssoprocess_ajax()` function — registered on `wp_ajax_nopriv_ssoprocess_ajax` and therefore reachable without authentication — accepting an attacker-supplied `email` parameter with the `setnewpassword` operation and calling `reset_password()` on the resolved account without any ownership token, email confirmation link, or capability check. The sole guard is a call to `check_ajax_referer()`, which provides no authorization barrier because the `ssoajaxnonce` nonce is publicly broadcast on every front-end page via `wp_localize_script()` into the `SSOPWDREQUIREMENT` JavaScript object; since WordPress computes nonces for logged-out visitors against a shared anonymous session context, any unauthenticated visitor can scrape a valid nonce from the homepage and use it to authenticate the request. This makes it possible for unauthenticated attackers to change the password of any WordPress account, including administrator accounts, enabling complete site takeover.

- [https://github.com/Instructor-Admin/CVE-2026-15964-PoC](https://github.com/Instructor-Admin/CVE-2026-15964-PoC) :  ![starts](https://img.shields.io/github/stars/Instructor-Admin/CVE-2026-15964-PoC.svg) ![forks](https://img.shields.io/github/forks/Instructor-Admin/CVE-2026-15964-PoC.svg)


## CVE-2026-14483
 The Realtyna Organic IDX plugin + WPL Real Estate plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 5.2.0 via the upload function. This is due to missing file type validation in the upload function, combined with a publicly accessible I/O endpoint authenticated solely by static, plugin-seeded API credentials that are identical across all installations. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible. The WPL I/O service endpoint is registered on the public WordPress init hook with no WordPress capability check, and the required api_key and api_secret values are static defaults seeded by the plugin's own SQL migration files, meaning any unauthenticated attacker who knows these publicly documented defaults can reach and exploit the vulnerable upload path.

- [https://github.com/MadExploits/CVE-2026-14483](https://github.com/MadExploits/CVE-2026-14483) :  ![starts](https://img.shields.io/github/stars/MadExploits/CVE-2026-14483.svg) ![forks](https://img.shields.io/github/forks/MadExploits/CVE-2026-14483.svg)


## CVE-2026-14361
 The consul-template library before version 0.42.1 is vulnerable to a path redirection issue in the writeToFile template helper that may allow template output to be written outside the intended directory or to overwrite an existing file. This vulnerability (CVE-2026-14361) is fixed in consul-template 0.42.1.

- [https://github.com/0xmrma/CVE-2026-14361](https://github.com/0xmrma/CVE-2026-14361) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-14361.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-14361.svg)


## CVE-2026-13158
 The Everest Toolkit WordPress plugin through 1.2.3 does not validate the type of files uploaded during demo-content import (the WordPress file-type test is disabled), allowing high-privilege users (Administrator by default, including non-super-admin site administrators on multisite) to upload executable PHP files to the uploads directory.

- [https://github.com/MinhHK68/CVE-2026-13158](https://github.com/MinhHK68/CVE-2026-13158) :  ![starts](https://img.shields.io/github/stars/MinhHK68/CVE-2026-13158.svg) ![forks](https://img.shields.io/github/forks/MinhHK68/CVE-2026-13158.svg)


## CVE-2026-13157
 The  Demo Import WordPress plugin through 1.1.3 does not validate the type of files uploaded during demo-content import (the WordPress file-type test is disabled), allowing high-privilege users (Administrator by default, including non-super-admin site administrators on multisite) to upload executable PHP files to the uploads directory.

- [https://github.com/MinhHK68/CVE-2026-13157](https://github.com/MinhHK68/CVE-2026-13157) :  ![starts](https://img.shields.io/github/stars/MinhHK68/CVE-2026-13157.svg) ![forks](https://img.shields.io/github/forks/MinhHK68/CVE-2026-13157.svg)


## CVE-2026-13152
 The Custom Fields Account Registration For Woocommerce WordPress plugin before 1.4 does not prevent its custom registration fields from writing to the user capabilities meta key on sites that use a non-default database table prefix, so an unauthenticated user who registers an account can be granted the administrator role when a correspondingly named field has been configured.

- [https://github.com/MinhHK68/CVE-2026-13152](https://github.com/MinhHK68/CVE-2026-13152) :  ![starts](https://img.shields.io/github/stars/MinhHK68/CVE-2026-13152.svg) ![forks](https://img.shields.io/github/forks/MinhHK68/CVE-2026-13152.svg)


## CVE-2026-12478
 The fix for CVE-2026-0716 (commit 6ff7ef0, libsoup 3.6.6) placed the integer overflow guard inside the if (masked) block, leaving unmasked server-to-client frames unprotected. A malicious WebSocket server can send a crafted unmasked frame with a payload length near UINT64_MAX to trigger an OOB read in a libsoup-based client when max_incoming_payload_size is set to 0.

- [https://github.com/Popy21/security-research](https://github.com/Popy21/security-research) :  ![starts](https://img.shields.io/github/stars/Popy21/security-research.svg) ![forks](https://img.shields.io/github/forks/Popy21/security-research.svg)


## CVE-2026-10702
 JIT miscompilation in the JavaScript Engine: JIT component. This vulnerability was fixed in Firefox 151.0.3.

- [https://github.com/raihants/cve-2026-10702](https://github.com/raihants/cve-2026-10702) :  ![starts](https://img.shields.io/github/stars/raihants/cve-2026-10702.svg) ![forks](https://img.shields.io/github/forks/raihants/cve-2026-10702.svg)


## CVE-2026-9833
 The Tag Groups is the Advanced Way to Display Your Taxonomy Terms WordPress plugin before 2.2.0 does not properly escape one of its AJAX parameters before reflecting it in the response body served with an HTML content type, allowing unauthenticated attackers to execute arbitrary JavaScript in the browser of a logged-in user with `edit_pages` capability (Editor or higher) who is tricked into following a crafted link.

- [https://github.com/aj2108/CVE-2026-9833](https://github.com/aj2108/CVE-2026-9833) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-9833.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-9833.svg)


## CVE-2026-8239
 Concrete CMS 9.5.0 and below is vulnerable to IDOR. The '/ccm/frontend/conversations/get_rating' endpoint confirms existence and returns rating score for any message by ID. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 6.3 with Vector CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N. Thanks Tristan Madani for reporting.

- [https://github.com/aj2108/CVE-2026-8239](https://github.com/aj2108/CVE-2026-8239) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-8239.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-8239.svg)


## CVE-2026-8237
 Concrete CMS 9.5.0 and below is vulnerable to IDOR. The `/ccm/frontend/conversations/message_detail` endpoint returns the full content of any conversation message. An unauthenticated attacker can enumerate all conversation messages, including messages from restricted pages, member-only areas, and the moderation queue. File attachments with download URLs are also exposed. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 6.3 with Vector CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N. Thanks Eldudareeno for reporting.

- [https://github.com/aj2108/CVE-2026-8237](https://github.com/aj2108/CVE-2026-8237) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-8237.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-8237.svg)


## CVE-2026-5362
This issue affects pimcore: v12.3.3.

- [https://github.com/7h30th3r0n3/CVE-2026-53625-GLPI-PoC](https://github.com/7h30th3r0n3/CVE-2026-53625-GLPI-PoC) :  ![starts](https://img.shields.io/github/stars/7h30th3r0n3/CVE-2026-53625-GLPI-PoC.svg) ![forks](https://img.shields.io/github/forks/7h30th3r0n3/CVE-2026-53625-GLPI-PoC.svg)


## CVE-2026-5237
 A security flaw has been discovered in itsourcecode Payroll Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /manage_user.php of the component Parameter Handler. Performing a manipulation of the argument ID results in sql injection. The attack is possible to be carried out remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/RichardKabuto/CVE-2026-52370](https://github.com/RichardKabuto/CVE-2026-52370) :  ![starts](https://img.shields.io/github/stars/RichardKabuto/CVE-2026-52370.svg) ![forks](https://img.shields.io/github/forks/RichardKabuto/CVE-2026-52370.svg)


## CVE-2026-5195
 A flaw has been found in code-projects Student Membership System 1.0. This issue affects some unknown processing of the component User Registration Handler. Executing a manipulation can lead to sql injection. The attack can be launched remotely.

- [https://github.com/envincion1991-cmyk/CVE-2026-51954](https://github.com/envincion1991-cmyk/CVE-2026-51954) :  ![starts](https://img.shields.io/github/stars/envincion1991-cmyk/CVE-2026-51954.svg) ![forks](https://img.shields.io/github/forks/envincion1991-cmyk/CVE-2026-51954.svg)


## CVE-2026-5061
 The consul-template library before version 0.42.0 is vulnerable to a sandbox path bypass in the file template helper that may allow reading an out-of-sandbox file. This vulnerability (CVE-2026-5061) is fixed in consul-template 0.42.0.

- [https://github.com/0xmrma/CVE-2026-5061](https://github.com/0xmrma/CVE-2026-5061) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-5061.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-5061.svg)


## CVE-2025-69212
 OpenSTAManager is an open source management software for technical assistance and invoicing. In 2.9.8 and earlier, a critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.

- [https://github.com/liaomilk/CVE-2025-69212-for-myself](https://github.com/liaomilk/CVE-2025-69212-for-myself) :  ![starts](https://img.shields.io/github/stars/liaomilk/CVE-2025-69212-for-myself.svg) ![forks](https://img.shields.io/github/forks/liaomilk/CVE-2025-69212-for-myself.svg)


## CVE-2025-68937
 Forgejo before 13.0.2 allows attackers to write to unintended files, and possibly obtain server shell access, because of mishandling of out-of-repository symlink destinations for template repositories. This is also fixed for 11 LTS in 11.0.7 and later.

- [https://github.com/Scratchappy/CVE-2025-68937](https://github.com/Scratchappy/CVE-2025-68937) :  ![starts](https://img.shields.io/github/stars/Scratchappy/CVE-2025-68937.svg) ![forks](https://img.shields.io/github/forks/Scratchappy/CVE-2025-68937.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/TeteREN/CVE-2025-57819-RCE](https://github.com/TeteREN/CVE-2025-57819-RCE) :  ![starts](https://img.shields.io/github/stars/TeteREN/CVE-2025-57819-RCE.svg) ![forks](https://img.shields.io/github/forks/TeteREN/CVE-2025-57819-RCE.svg)


## CVE-2025-31207
 A logic issue was addressed with improved checks. This issue is fixed in iOS 18.5 and iPadOS 18.5. An app may be able to enumerate a user's installed apps.

- [https://github.com/kolbicz/AppEnumGuard](https://github.com/kolbicz/AppEnumGuard) :  ![starts](https://img.shields.io/github/stars/kolbicz/AppEnumGuard.svg) ![forks](https://img.shields.io/github/forks/kolbicz/AppEnumGuard.svg)


## CVE-2025-10897
 The WooCommerce Designer Pro theme for WordPress is vulnerable to arbitrary file read in all versions up to, and including, 1.9.28. This makes it possible for unauthenticated attackers to read arbitrary files on the server, which can expose DB credentials when the wp-config.php file is read.

- [https://github.com/error-inside/CVE-2025-10897](https://github.com/error-inside/CVE-2025-10897) :  ![starts](https://img.shields.io/github/stars/error-inside/CVE-2025-10897.svg) ![forks](https://img.shields.io/github/forks/error-inside/CVE-2025-10897.svg)


## CVE-2024-40422
 The snapshot_path parameter in the /api/get-browser-snapshot endpoint in stitionai devika v1 is susceptible to a path traversal attack. An attacker can manipulate the snapshot_path parameter to traverse directories and access sensitive files on the server. This can potentially lead to unauthorized access to critical system files and compromise the confidentiality and integrity of the system.

- [https://github.com/alpernae/CVE-2024-40422](https://github.com/alpernae/CVE-2024-40422) :  ![starts](https://img.shields.io/github/stars/alpernae/CVE-2024-40422.svg) ![forks](https://img.shields.io/github/forks/alpernae/CVE-2024-40422.svg)

