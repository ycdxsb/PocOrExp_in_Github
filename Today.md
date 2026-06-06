# Update 2026-06-06
## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/Koshmare-Blossom/CIFSwitch-go](https://github.com/Koshmare-Blossom/CIFSwitch-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/CIFSwitch-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/CIFSwitch-go.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/ChanderManiPandey2022/Yellow-Key-Check](https://github.com/ChanderManiPandey2022/Yellow-Key-Check) :  ![starts](https://img.shields.io/github/stars/ChanderManiPandey2022/Yellow-Key-Check.svg) ![forks](https://img.shields.io/github/forks/ChanderManiPandey2022/Yellow-Key-Check.svg)


## CVE-2026-45247
 Mirasvit Full Page Cache Warmer for Magento 2 before version 1.11.12 contains a PHP object injection vulnerability that allows unauthenticated attackers to achieve remote code execution by supplying a crafted serialized PHP object in the CacheWarmer cookie. Attackers can exploit the unrestricted call to PHP's native unserialize() function combined with gadget chains available in Magento and its dependencies to execute arbitrary code on the server.

- [https://github.com/HORKimhab/CVE-2026-45247](https://github.com/HORKimhab/CVE-2026-45247) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-45247.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-45247.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/simota/nginx-rift-scanner](https://github.com/simota/nginx-rift-scanner) :  ![starts](https://img.shields.io/github/stars/simota/nginx-rift-scanner.svg) ![forks](https://img.shields.io/github/forks/simota/nginx-rift-scanner.svg)


## CVE-2026-42588
Users are recommended to upgrade to version 5.19.7 or 6.2.6, which fixes the issue.

- [https://github.com/strivepan/ActiveMQ-cve-2026-42588-scanner-gui](https://github.com/strivepan/ActiveMQ-cve-2026-42588-scanner-gui) :  ![starts](https://img.shields.io/github/stars/strivepan/ActiveMQ-cve-2026-42588-scanner-gui.svg) ![forks](https://img.shields.io/github/forks/strivepan/ActiveMQ-cve-2026-42588-scanner-gui.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/TwoSevenOneT/CVE-2026-41096-Attack-Surface](https://github.com/TwoSevenOneT/CVE-2026-41096-Attack-Surface) :  ![starts](https://img.shields.io/github/stars/TwoSevenOneT/CVE-2026-41096-Attack-Surface.svg) ![forks](https://img.shields.io/github/forks/TwoSevenOneT/CVE-2026-41096-Attack-Surface.svg)


## CVE-2026-35906
 An undocumented debug CGI endpoint in T3 Technology CPE models T625Pro v1.0.07, T6825G v1.0.03 allows unauthenticated attackers to execute arbitrary system commands as root via supplying a crafted HTTP query string.

- [https://github.com/PwnOnu/T3-Technology-CPE-Advisories](https://github.com/PwnOnu/T3-Technology-CPE-Advisories) :  ![starts](https://img.shields.io/github/stars/PwnOnu/T3-Technology-CPE-Advisories.svg) ![forks](https://img.shields.io/github/forks/PwnOnu/T3-Technology-CPE-Advisories.svg)


## CVE-2026-35905
 T3 Technology CPE models T625Pro v1.0.07, T6825G v1.0.03, and T7281 v1.0.03 were discovered to contain a hardcoded password for root access under the "superadmin" account.

- [https://github.com/PwnOnu/T3-Technology-CPE-Advisories](https://github.com/PwnOnu/T3-Technology-CPE-Advisories) :  ![starts](https://img.shields.io/github/stars/PwnOnu/T3-Technology-CPE-Advisories.svg) ![forks](https://img.shields.io/github/forks/PwnOnu/T3-Technology-CPE-Advisories.svg)


## CVE-2026-35904
 Incorrect access control in the web management interface of T3 Technology CPE models T625Pro v1.0.07, T6825G v1.0.03, and T7281 v1.0.03 allows unauthorized attackers to enable the Telnet service via sending a crafted request to a vulnerable CGI component.

- [https://github.com/PwnOnu/T3-Technology-CPE-Advisories](https://github.com/PwnOnu/T3-Technology-CPE-Advisories) :  ![starts](https://img.shields.io/github/stars/PwnOnu/T3-Technology-CPE-Advisories.svg) ![forks](https://img.shields.io/github/forks/PwnOnu/T3-Technology-CPE-Advisories.svg)


## CVE-2026-34234
 CtrlPanel is open-source billing software for hosting providers. In versions 1.1.1 and prior, the web-based installer (public/installer/index.php) is vulnerable to unauthenticated Remote Code Execution (RCE) because it performs the install.lock check only after including and executing form handler files, leaving installer endpoints reachable on already-installed instances. The handlers also pass unsanitized user input directly into shell commands, allowing an attacker to submit crafted requests that execute arbitrary commands on the server. The vulnerability stems from two combined weaknesses: (1) premature form handler execution before the lock file gate, and (2) unsafe use of user input in shell command construction. This issue is reported to be actively exploited in the wild. The issue has been fixed in version 1.2.0.

- [https://github.com/rootdirective-sec/CVE-2026-34234-Lab](https://github.com/rootdirective-sec/CVE-2026-34234-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-34234-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-34234-Lab.svg)


## CVE-2026-33829
 Exposure of sensitive information to an unauthorized actor in Windows Snipping Tool allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/tiffanykarihi23/CVE-2026-33829](https://github.com/tiffanykarihi23/CVE-2026-33829) :  ![starts](https://img.shields.io/github/stars/tiffanykarihi23/CVE-2026-33829.svg) ![forks](https://img.shields.io/github/forks/tiffanykarihi23/CVE-2026-33829.svg)


## CVE-2026-33147
 GMT is an open source collection of command-line tools for manipulating geographic and Cartesian data sets. In versions from 6.6.0 and prior, a stack-based buffer overflow vulnerability was identified in the gmt_remote_dataset_id function within src/gmt_remote.c. This issue occurs when a specially crafted long string is passed as a dataset identifier (e.g., via the which module), leading to a crash or potential arbitrary code execution. This issue has been patched via commit 0ad2b49.

- [https://github.com/Kanwar-Azlan/Stack-Based-Buffer-Overflow](https://github.com/Kanwar-Azlan/Stack-Based-Buffer-Overflow) :  ![starts](https://img.shields.io/github/stars/Kanwar-Azlan/Stack-Based-Buffer-Overflow.svg) ![forks](https://img.shields.io/github/forks/Kanwar-Azlan/Stack-Based-Buffer-Overflow.svg)


## CVE-2026-32662
 Development and test API endpoints are present that mirror production functionality.

- [https://github.com/xf-secops/CVE-2026-32662](https://github.com/xf-secops/CVE-2026-32662) :  ![starts](https://img.shields.io/github/stars/xf-secops/CVE-2026-32662.svg) ![forks](https://img.shields.io/github/forks/xf-secops/CVE-2026-32662.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Pithase/asm-copyfail](https://github.com/Pithase/asm-copyfail) :  ![starts](https://img.shields.io/github/stars/Pithase/asm-copyfail.svg) ![forks](https://img.shields.io/github/forks/Pithase/asm-copyfail.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/avivyap/CVE-2026-23744](https://github.com/avivyap/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/avivyap/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/avivyap/CVE-2026-23744.svg)


## CVE-2026-23631
 Redis is an in-memory data structure store. In all versions of redis-server with Lua scripting, an authenticated attacker can exploit the master-replica synchronization mechanism to trigger a use-after-free on replicas where replica-read-only is disabled or can be disabled, which may lead to remote code execution. A workaround is to prevent users from executing Lua scripts or avoid using replicas where replica-read-only is disabled. This is patched in version 8.6.3.

- [https://github.com/HORKimhab/CVE-2026-23631](https://github.com/HORKimhab/CVE-2026-23631) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-23631.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-23631.svg)


## CVE-2026-23479
 Redis is an in-memory data structure store. In redis-server from 7.2.0 until 8.6.3, the unblock client flow does not handle an error return from `processCommandAndResetClient` when re-executing a blocked command. If a blocked client is evicted during this flow, an authenticated attacker can trigger a use-after-free that may lead to remote code execution. This has been patched in version 8.6.3.

- [https://github.com/pduggusa/redis-cve-2026-23479-check](https://github.com/pduggusa/redis-cve-2026-23479-check) :  ![starts](https://img.shields.io/github/stars/pduggusa/redis-cve-2026-23479-check.svg) ![forks](https://img.shields.io/github/forks/pduggusa/redis-cve-2026-23479-check.svg)


## CVE-2026-8732
 The WP Maps Pro plugin for WordPress is vulnerable to Privilege Escalation via Administrator Account Creation in all versions up to, and including, 6.1.0. This is due to the wpgmp_temp_access_ajax AJAX action being registered with wp_ajax_nopriv_ and protected only by a nonce check using the fc-call-nonce nonce, which is publicly embedded into every frontend page via wp_localize_script as the nonce field of the wpgmp_local JavaScript object, rendering the check ineffective as an access control mechanism. This makes it possible for unauthenticated attackers to invoke the wpgmp_temp_access_support handler with check_temp=false, which unconditionally creates a new WordPress user with the hardcoded role of administrator via wp_insert_user() and returns a magic login URL that, when visited, calls wp_set_auth_cookie() to fully authenticate the attacker as the newly created administrator, resulting in complete site takeover.

- [https://github.com/zycoder0day/CVE-2026-8732](https://github.com/zycoder0day/CVE-2026-8732) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-8732.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-8732.svg)
- [https://github.com/Diznev/CVE-2026-8732-EXPLOIT](https://github.com/Diznev/CVE-2026-8732-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/Diznev/CVE-2026-8732-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/Diznev/CVE-2026-8732-EXPLOIT.svg)


## CVE-2026-8389
 JIT miscompilation in the JavaScript Engine: JIT component. This vulnerability was fixed in Firefox 150.0.3.

- [https://github.com/crixpwn/CVE-2026-8389](https://github.com/crixpwn/CVE-2026-8389) :  ![starts](https://img.shields.io/github/stars/crixpwn/CVE-2026-8389.svg) ![forks](https://img.shields.io/github/forks/crixpwn/CVE-2026-8389.svg)


## CVE-2026-6815
 An arbitrary file write vulnerability exists in Casdoor's Local File System storage provider. Due to insufficient path sanitization, an authenticated attacker with administrative privileges can perform a Path Traversal attack to create or overwrite arbitrary files anywhere on the host filesystem, bypassing the application's intended storage sandbox.

- [https://github.com/danilo-dellorco/CVE-2026-6815](https://github.com/danilo-dellorco/CVE-2026-6815) :  ![starts](https://img.shields.io/github/stars/danilo-dellorco/CVE-2026-6815.svg) ![forks](https://img.shields.io/github/forks/danilo-dellorco/CVE-2026-6815.svg)


## CVE-2026-5076
 The ARMember Premium plugin for WordPress is vulnerable to an insecure password reset mechanism in all versions up to, and including, 7.3.1. The plugin stores a plaintext copy of the password reset key in the `arm_reset_password_key` user meta field when a user requests a password reset. This is in addition to the hashed key that WordPress core stores securely in `wp_users.user_activation_key`. The plaintext key stored in `wp_usermeta` can be used with the plugin's custom `armrp` reset action to set a new password for any user. Combined with another vulnerability such as SQL Injection (CVE-2026-5073, CVE-2026-5074), this makes it possible for unauthenticated attackers to extract the plaintext reset key and take over any user account, including administrators.

- [https://github.com/zycoder0day/CVE-2026-5076](https://github.com/zycoder0day/CVE-2026-5076) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-5076.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-5076.svg)


## CVE-2026-5014
 A vulnerability was found in elecV2 elecV2P up to 3.8.3. The affected element is the function path.join of the file /log/ of the component Wildcard Handler. The manipulation results in path traversal. The attack may be performed from remote. The exploit has been made public and could be used. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/MuhammedHussein17/libheif-cve-2026-50142](https://github.com/MuhammedHussein17/libheif-cve-2026-50142) :  ![starts](https://img.shields.io/github/stars/MuhammedHussein17/libheif-cve-2026-50142.svg) ![forks](https://img.shields.io/github/forks/MuhammedHussein17/libheif-cve-2026-50142.svg)


## CVE-2026-4997
 A security flaw has been discovered in Sinaptik AI PandasAI up to 3.0.0. This affects the function is_sql_query_safe of the file pandasai/helpers/sql_sanitizer.py. Performing a manipulation results in path traversal. The attack may be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/mrx-arafat/CVE-2026-49975-POC](https://github.com/mrx-arafat/CVE-2026-49975-POC) :  ![starts](https://img.shields.io/github/stars/mrx-arafat/CVE-2026-49975-POC.svg) ![forks](https://img.shields.io/github/forks/mrx-arafat/CVE-2026-49975-POC.svg)


## CVE-2026-4881
 In affected versions of Octopus Server, permissions were not checked correctly resulting in any authenticated user being able to make server level changes using a certain API endpoint despite receiving an error.

- [https://github.com/7alen7/CVE-2026-48813-POC](https://github.com/7alen7/CVE-2026-48813-POC) :  ![starts](https://img.shields.io/github/stars/7alen7/CVE-2026-48813-POC.svg) ![forks](https://img.shields.io/github/forks/7alen7/CVE-2026-48813-POC.svg)


## CVE-2026-4742
This issue affects liteide: before x38.4.

- [https://github.com/Galaxy-sc/CVE-2026-47423-dompurify-xss-detector](https://github.com/Galaxy-sc/CVE-2026-47423-dompurify-xss-detector) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-47423-dompurify-xss-detector.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-47423-dompurify-xss-detector.svg)


## CVE-2026-3743
 A flaw has been found in YiFang CMS 2.0.5. This affects the function update of the file app/db/admin/D_singlePageGroup.php. Executing a manipulation of the argument Name can lead to cross site scripting. It is possible to launch the attack remotely. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/diao111111/CVE-2026-37432](https://github.com/diao111111/CVE-2026-37432) :  ![starts](https://img.shields.io/github/stars/diao111111/CVE-2026-37432.svg) ![forks](https://img.shields.io/github/forks/diao111111/CVE-2026-37432.svg)


## CVE-2026-3180
 The Contest Gallery – Upload & Vote Photos, Media, Sell with PayPal & Stripe plugin for WordPress is vulnerable to blind SQL Injection via the ‘cgLostPasswordEmail’ and the ’cgl_mail’ parameter in all versions up to, and including, 28.1.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. The vulnerability's ’cgLostPasswordEmail’ parameter was patched in version 28.1.4, and the ’cgl_mail’ parameter was patched in version 28.1.5.

- [https://github.com/cardosource/cve-2026-3180](https://github.com/cardosource/cve-2026-3180) :  ![starts](https://img.shields.io/github/stars/cardosource/cve-2026-3180.svg) ![forks](https://img.shields.io/github/forks/cardosource/cve-2026-3180.svg)


## CVE-2026-3050
 A flaw has been found in horilla-opensource horilla up to 1.0.2. Impacted is an unknown function of the file static/assets/js/global.js of the component Leads Module. This manipulation of the argument Notes causes cross site scripting. The attack is possible to be carried out remotely. The exploit has been published and may be used. Upgrading to version 1.0.3 is recommended to address this issue. Patch name: fc5c8e55988e89273012491b5f097b762b474546. It is suggested to upgrade the affected component.

- [https://github.com/dharmstm/CVE-2026-30503-OpenKM-6.3.12-Stored-XSS](https://github.com/dharmstm/CVE-2026-30503-OpenKM-6.3.12-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/dharmstm/CVE-2026-30503-OpenKM-6.3.12-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/dharmstm/CVE-2026-30503-OpenKM-6.3.12-Stored-XSS.svg)
- [https://github.com/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS](https://github.com/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS.svg)


## CVE-2026-2655
 A vulnerability was detected in ChaiScript up to 6.1.0. The impacted element is the function chaiscript::str_less::operator of the file include/chaiscript/chaiscript_defines.hpp. The manipulation results in use after free. The attack requires a local approach. The attack requires a high level of complexity. The exploitability is regarded as difficult. The exploit is now public and may be used. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/horrister/axios-supply-chain-cve-2026-26555](https://github.com/horrister/axios-supply-chain-cve-2026-26555) :  ![starts](https://img.shields.io/github/stars/horrister/axios-supply-chain-cve-2026-26555.svg) ![forks](https://img.shields.io/github/forks/horrister/axios-supply-chain-cve-2026-26555.svg)


## CVE-2026-2586
 An authenticated Remote Code Execution (RCE) vulnerability was identified in GlassFish's Administration Console. A user with access to the panel can send crafted requests that allow the execution of arbitrary operating system commands with the privileges of the application service user.

- [https://github.com/DeepSecurityResearch/CVE-2026-2586](https://github.com/DeepSecurityResearch/CVE-2026-2586) :  ![starts](https://img.shields.io/github/stars/DeepSecurityResearch/CVE-2026-2586.svg) ![forks](https://img.shields.io/github/forks/DeepSecurityResearch/CVE-2026-2586.svg)


## CVE-2026-2256
 A command injection vulnerability in ModelScope's ms-agent versions v1.6.0rc1 and earlier exists, allowing an attacker to execute arbitrary operating system commands through crafted prompt-derived input.

- [https://github.com/mruniversity/CVE-2026-2256-](https://github.com/mruniversity/CVE-2026-2256-) :  ![starts](https://img.shields.io/github/stars/mruniversity/CVE-2026-2256-.svg) ![forks](https://img.shields.io/github/forks/mruniversity/CVE-2026-2256-.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/fredevsec/CVE-2026-0073](https://github.com/fredevsec/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/fredevsec/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/fredevsec/CVE-2026-0073.svg)


## CVE-2025-65640
 Cross Site Scripting (XSS) vulnerability in the "Task in Progress / Recent" page in Arket Globe Document Intelligence 5.0.0.559 due to improper sanitization of user input in text fields when creating a new document. Specifically, when an authenticated attacker submits data containing JavaScript code within these fields, the application fails to properly sanitize or escape the content. As a result, the injected script is executed when the page is rendered, allowing the attacker to execute arbitrary JavaScript in the context of other users' browsers who view the affected page.

- [https://github.com/vincenzo-emanuele/CVE-2025-65640](https://github.com/vincenzo-emanuele/CVE-2025-65640) :  ![starts](https://img.shields.io/github/stars/vincenzo-emanuele/CVE-2025-65640.svg) ![forks](https://img.shields.io/github/forks/vincenzo-emanuele/CVE-2025-65640.svg)


## CVE-2025-58807
 Cross-Site Request Forgery (CSRF) vulnerability in Dsingh Purge Varnish Cache purge-varnish allows Stored XSS.This issue affects Purge Varnish Cache: from n/a through = 2.6.

- [https://github.com/erikharden/purge-varnish-csrf-advisory](https://github.com/erikharden/purge-varnish-csrf-advisory) :  ![starts](https://img.shields.io/github/stars/erikharden/purge-varnish-csrf-advisory.svg) ![forks](https://img.shields.io/github/forks/erikharden/purge-varnish-csrf-advisory.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2024-1698
 The NotificationX – Best FOMO, Social Proof, WooCommerce Sales Popup & Notification Bar Plugin With Elementor plugin for WordPress is vulnerable to SQL Injection via the 'type' parameter in all versions up to, and including, 2.8.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Dhananjayasj/CVE-2024-1698-NotificationX-WordPress-Plugin-SQL-Injection-to-Admin-Credential-Extraction](https://github.com/Dhananjayasj/CVE-2024-1698-NotificationX-WordPress-Plugin-SQL-Injection-to-Admin-Credential-Extraction) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/CVE-2024-1698-NotificationX-WordPress-Plugin-SQL-Injection-to-Admin-Credential-Extraction.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/CVE-2024-1698-NotificationX-WordPress-Plugin-SQL-Injection-to-Admin-Credential-Extraction.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/Shcesama/cve-2023-4863-analysis](https://github.com/Shcesama/cve-2023-4863-analysis) :  ![starts](https://img.shields.io/github/stars/Shcesama/cve-2023-4863-analysis.svg) ![forks](https://img.shields.io/github/forks/Shcesama/cve-2023-4863-analysis.svg)


## CVE-2022-46395
 An issue was discovered in the Arm Mali GPU Kernel Driver. A non-privileged user can make improper GPU processing operations to gain access to already freed memory. This affects Midgard r0p0 through r32p0, Bifrost r0p0 through r41p0 before r42p0, Valhall r19p0 through r41p0 before r42p0, and Avalon r41p0 before r42p0.

- [https://github.com/Gao-Zuin/cve-2022-46395-qemu](https://github.com/Gao-Zuin/cve-2022-46395-qemu) :  ![starts](https://img.shields.io/github/stars/Gao-Zuin/cve-2022-46395-qemu.svg) ![forks](https://img.shields.io/github/forks/Gao-Zuin/cve-2022-46395-qemu.svg)


## CVE-2021-35042
 Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.

- [https://github.com/vutiendat323/INT14107_CVE-2021-35042](https://github.com/vutiendat323/INT14107_CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/vutiendat323/INT14107_CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/vutiendat323/INT14107_CVE-2021-35042.svg)


## CVE-2020-16898
pThe update addresses the vulnerability by correcting how the Windows TCP/IP stack handles ICMPv6 Router Advertisement packets./p

- [https://github.com/aricooper/suricata-script](https://github.com/aricooper/suricata-script) :  ![starts](https://img.shields.io/github/stars/aricooper/suricata-script.svg) ![forks](https://img.shields.io/github/forks/aricooper/suricata-script.svg)


## CVE-2020-0022
 In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715

- [https://github.com/it4ch1-007/poc_cve_2020_0022](https://github.com/it4ch1-007/poc_cve_2020_0022) :  ![starts](https://img.shields.io/github/stars/it4ch1-007/poc_cve_2020_0022.svg) ![forks](https://img.shields.io/github/forks/it4ch1-007/poc_cve_2020_0022.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/H4R335HR/vsftpd-234-backdoor](https://github.com/H4R335HR/vsftpd-234-backdoor) :  ![starts](https://img.shields.io/github/stars/H4R335HR/vsftpd-234-backdoor.svg) ![forks](https://img.shields.io/github/forks/H4R335HR/vsftpd-234-backdoor.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/mishaqdev/cve-2010-2075-analysis](https://github.com/mishaqdev/cve-2010-2075-analysis) :  ![starts](https://img.shields.io/github/stars/mishaqdev/cve-2010-2075-analysis.svg) ![forks](https://img.shields.io/github/forks/mishaqdev/cve-2010-2075-analysis.svg)


## CVE-2010-0832
 pam_motd (aka the MOTD module) in libpam-modules before 1.1.0-2ubuntu1.1 in PAM on Ubuntu 9.10 and libpam-modules before 1.1.1-2ubuntu5 in PAM on Ubuntu 10.04 LTS allows local users to change the ownership of arbitrary files via a symlink attack on .cache in a user's home directory, related to "user file stamps" and the motd.legal-notice file.

- [https://github.com/R3fr4kt/Popcorn-TJNULL-OSCP-](https://github.com/R3fr4kt/Popcorn-TJNULL-OSCP-) :  ![starts](https://img.shields.io/github/stars/R3fr4kt/Popcorn-TJNULL-OSCP-.svg) ![forks](https://img.shields.io/github/forks/R3fr4kt/Popcorn-TJNULL-OSCP-.svg)

