# Update 2026-09-10
## CVE-2026-85625
 sift (sift.js) 17.1.3 enumerates query keys with for...in, which walks the object prototype chain, and dispatches any matched operator key including $where. The $where operation compiles a string value into a function using new Function unless CSP_ENABLED is set (not set by default). As a result, if a prototype-pollution primitive elsewhere in the process sets Object.prototype.$where to a malicious string, even benign filter calls such as sift({}) execute arbitrary JavaScript. Additionally, passing an untrusted query object containing a string $where directly to sift results in code execution under the default configuration.

- [https://github.com/lgranadoi/sift-hardened](https://github.com/lgranadoi/sift-hardened) :  ![starts](https://img.shields.io/github/stars/lgranadoi/sift-hardened.svg) ![forks](https://img.shields.io/github/forks/lgranadoi/sift-hardened.svg)


## CVE-2026-85046
 Type confusion in V8 in Google Chrome prior to 152.0.7977.82 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SneakyNachos/CVE-2026-85046-who-put-the-silverback-guerilla-in-the-wasm](https://github.com/SneakyNachos/CVE-2026-85046-who-put-the-silverback-guerilla-in-the-wasm) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-85046-who-put-the-silverback-guerilla-in-the-wasm.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-85046-who-put-the-silverback-guerilla-in-the-wasm.svg)
- [https://github.com/atiilla/CVE-2026-85046](https://github.com/atiilla/CVE-2026-85046) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-85046.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-85046.svg)


## CVE-2026-84118
 Use-after-free in the JavaScript: GC component. This vulnerability was fixed in Firefox 155, Firefox ESR 153.2, Thunderbird 155, and Thunderbird 153.2.

- [https://github.com/SneakyNachos/CVE-2026-84118-who-labeled-the-crit-as-a-high](https://github.com/SneakyNachos/CVE-2026-84118-who-labeled-the-crit-as-a-high) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-84118-who-labeled-the-crit-as-a-high.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-84118-who-labeled-the-crit-as-a-high.svg)


## CVE-2026-83549
 Post-authentication Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands, resulting in remote code execution.

- [https://github.com/HORKimhab/CVE-2026-83548-CVE-2026-83549](https://github.com/HORKimhab/CVE-2026-83548-CVE-2026-83549) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-83548-CVE-2026-83549.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-83548-CVE-2026-83549.svg)


## CVE-2026-83548
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. A remote unauthenticated attacker could potentially exploit this vulnerability to gain unauthorized access to sensitive functionality and perform unauthorized operations.

- [https://github.com/HORKimhab/CVE-2026-83548-CVE-2026-83549](https://github.com/HORKimhab/CVE-2026-83548-CVE-2026-83549) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-83548-CVE-2026-83549.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-83548-CVE-2026-83549.svg)


## CVE-2026-82222
This issue affects GiveWP: from n/a through 4.16.7.1.

- [https://github.com/GhostlyrootB2H/CVE-2026-82222](https://github.com/GhostlyrootB2H/CVE-2026-82222) :  ![starts](https://img.shields.io/github/stars/GhostlyrootB2H/CVE-2026-82222.svg) ![forks](https://img.shields.io/github/forks/GhostlyrootB2H/CVE-2026-82222.svg)


## CVE-2026-78838
 A reflected cross-site scripting (XSS) vulnerability in the grid_datasource.php component of AppNitro MachForm v30 allows attackers to execute arbitrary Javascript in the context of the victim's browser via injecting a crafted payload into the filter[filters][0][field] parameter.

- [https://github.com/nabeelmkhan/CVE-2026-78838](https://github.com/nabeelmkhan/CVE-2026-78838) :  ![starts](https://img.shields.io/github/stars/nabeelmkhan/CVE-2026-78838.svg) ![forks](https://img.shields.io/github/forks/nabeelmkhan/CVE-2026-78838.svg)


## CVE-2026-78837
 A SQL injection vulnerability in the ap_form_{id} parameter in AppNitro MachForm v30 allows attackers to access sensitive database information via a crafted SQL statement.

- [https://github.com/nabeelmkhan/CVE-2026-78837](https://github.com/nabeelmkhan/CVE-2026-78837) :  ![starts](https://img.shields.io/github/stars/nabeelmkhan/CVE-2026-78837.svg) ![forks](https://img.shields.io/github/forks/nabeelmkhan/CVE-2026-78837.svg)


## CVE-2026-75650
 Adobe Commerce is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability that could result in arbitrary code execution in the context of the current user. An attacker could exploit this vulnerability to execute arbitrary code. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/dinosn/cve-2026-75650-magento-validation-lab](https://github.com/dinosn/cve-2026-75650-magento-validation-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-75650-magento-validation-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-75650-magento-validation-lab.svg)
- [https://github.com/disrex-group/stylesmuggler-adobe-patches](https://github.com/disrex-group/stylesmuggler-adobe-patches) :  ![starts](https://img.shields.io/github/stars/disrex-group/stylesmuggler-adobe-patches.svg) ![forks](https://img.shields.io/github/forks/disrex-group/stylesmuggler-adobe-patches.svg)
- [https://github.com/disrex-group/stylesmuggler-adobe-patches-mageos](https://github.com/disrex-group/stylesmuggler-adobe-patches-mageos) :  ![starts](https://img.shields.io/github/stars/disrex-group/stylesmuggler-adobe-patches-mageos.svg) ![forks](https://img.shields.io/github/forks/disrex-group/stylesmuggler-adobe-patches-mageos.svg)


## CVE-2026-74239
 XenForo before 2.3.13 contains a path traversal vulnerability in the style archive importer on Windows deployments that allows authenticated non-super administrators with style permissions to write arbitrary files outside the intended extraction directory by using backslash-based traversal sequences in ZIP member names. Attackers can craft a malicious ZIP archive with backslash path separators that bypass forward-slash validation to write arbitrary bytes to any web-server-writable path, including the public web root, achieving persistent code execution as the web-server account.

- [https://github.com/BomboBombone/CVE-2026-74239](https://github.com/BomboBombone/CVE-2026-74239) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-74239.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-74239.svg)


## CVE-2026-73321
 XenForo before 2.3.13 contains an uncontrolled recursion vulnerability in the BBCode parser that allows authenticated attackers to cause persistent denial of service by submitting a post with deeply nested BBCode tags. Attackers can craft a single malicious post with sufficient nesting depth to exceed PHP's stack limit, causing fatal errors that repeatedly terminate PHP-FPM workers for all visitors rendering the affected thread.

- [https://github.com/BomboBombone/CVE-2026-73321](https://github.com/BomboBombone/CVE-2026-73321) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73321.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73321.svg)


## CVE-2026-73320
 XenForo before 2.3.13 contains an unauthenticated information disclosure vulnerability that allows unauthenticated attackers to retrieve private unfurl records by supplying predictable auto-increment primary key IDs to the unfurl endpoint. Attackers can enumerate or predict result IDs and query the endpoint without any session, user, or visibility checks to obtain rendered preview HTML, original URLs, and query strings from private conversations and other restricted content.

- [https://github.com/BomboBombone/CVE-2026-73320](https://github.com/BomboBombone/CVE-2026-73320) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73320.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73320.svg)


## CVE-2026-73319
 XenForo before 2.3.13 contains a cross-site scripting vulnerability in the dynamic redirect handler that allows unauthenticated attackers to execute arbitrary JavaScript in the board origin by crafting a malicious javascript: URI that bypasses host validation. Attackers can embed the board hostname in the URI authority component and use percent-encoded newlines to evade server-side filters, causing authenticated users who perform a Follow action to execute attacker-supplied JavaScript in their browser.

- [https://github.com/BomboBombone/CVE-2026-73319](https://github.com/BomboBombone/CVE-2026-73319) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73319.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73319.svg)


## CVE-2026-73318
 XenForo before 2.3.13 contains a missing authorization vulnerability in the force-agreement controller that allows any ACP administrator to access and submit force-agreement forms regardless of their assigned permissions. Attackers can bypass the option permission declared in the navigation configuration to update the global policy last-updated timestamp, forcing all users to re-agree to the privacy policy or terms of service.

- [https://github.com/BomboBombone/CVE-2026-73318](https://github.com/BomboBombone/CVE-2026-73318) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73318.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73318.svg)


## CVE-2026-73317
 XenForo before 2.3.13 contains a missing authorization vulnerability in the ACP cache-rebuild dispatcher that allows limited administrators with only the rebuildCache permission to perform unauthorized approval queue actions by supplying an arbitrary job class and actor user ID in the POST body. Attackers can invoke the approval queue job under any user identity to approve queued user registrations without holding the required approval-queue or moderator permissions, causing the moderation log to attribute actions to an impersonated account.

- [https://github.com/BomboBombone/CVE-2026-73317](https://github.com/BomboBombone/CVE-2026-73317) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73317.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73317.svg)


## CVE-2026-73316
 XenForo before 2.3.13 contains a payment replay vulnerability in the PayPal REST payment provider that allows attackers to process the same webhook payload multiple times by exploiting a missing duplicate transaction ID check. Attackers can replay a valid webhook payload to trigger duplicate payment events, resulting in repeated subscription activations and unauthorized account upgrades.

- [https://github.com/BomboBombone/CVE-2026-73316](https://github.com/BomboBombone/CVE-2026-73316) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73316.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73316.svg)


## CVE-2026-73315
 XenForo before 2.3.13 contains a server-side request forgery vulnerability in the PayPal REST webhook handler that allows unauthenticated attackers to cause the server to make outbound HTTP requests to arbitrary destinations by supplying a crafted certificate URL in webhook headers without scheme, hostname, or allowlist validation. Attackers can submit a crafted POST to the PayPal webhook callback endpoint to reach internal network resources including cloud instance metadata services, potentially disclosing IAM credentials or enabling secondary internal service exploitation.

- [https://github.com/BomboBombone/CVE-2026-73315](https://github.com/BomboBombone/CVE-2026-73315) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73315.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73315.svg)


## CVE-2026-73314
 XenForo before 2.3.13 contains a signature verification logic error in the PayPal REST webhook handler that allows unauthenticated attackers to bypass payment signature validation by submitting a webhook request with an unsupported auth_algo header value. When the algorithm cannot be mapped to a supported hash function, the verification function incorrectly returns true instead of failing, causing the caller to treat the fabricated request as verified and process the payment event without a valid PayPal signature.

- [https://github.com/BomboBombone/CVE-2026-73314](https://github.com/BomboBombone/CVE-2026-73314) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73314.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73314.svg)


## CVE-2026-73313
 XenForo before 2.3.13 contains a multi-factor authentication bypass vulnerability in the passkey TFA provider that allows an authenticated attacker to complete login as another user by submitting their own registered passkey credential during the WebAuthn assertion step. The passkey verification path performs a global credential lookup without validating that the matched credential belongs to the user whose login is pending, enabling an attacker who knows a target account's password to sign the challenge with their own passkey and bypass multi-factor authentication on both public forum and ACP login paths.

- [https://github.com/BomboBombone/CVE-2026-73313](https://github.com/BomboBombone/CVE-2026-73313) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73313.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73313.svg)


## CVE-2026-73312
 XenForo before 2.3.13 contains a refresh token replay vulnerability that allows attackers to reuse a refresh token multiple times by exploiting the failure to mark tokens as consumed when the parent access token has expired. Attackers can repeatedly submit the same refresh token to generate additional independent token pairs, achieving persistent unauthorized access for the token's full lifetime.

- [https://github.com/BomboBombone/CVE-2026-73312](https://github.com/BomboBombone/CVE-2026-73312) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73312.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73312.svg)


## CVE-2026-73311
 XenForo before 2.3.13 contains an OAuth2 authorization code reuse vulnerability that allows attackers to obtain unauthorized token pairs by submitting a previously used authorization code. Attackers can exploit the failure to invalidate or mark authorization codes as consumed after initial token issuance to receive an independent token pair for the same user and scopes, bypassing the single-use guarantee of the OAuth2 authorization code flow.

- [https://github.com/BomboBombone/CVE-2026-73311](https://github.com/BomboBombone/CVE-2026-73311) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73311.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73311.svg)


## CVE-2026-73310
 XenForo before 2.3.13 contains an authorization flaw in the OAuth2 token endpoint that allows attackers controlling any allowlisted redirect URI to bypass redirect URI binding by submitting a different allowlisted URI than the one recorded at authorization time. Attackers can exchange an intercepted authorization code using a mismatched redirect URI to steal OAuth2 tokens from intercepted authorization flows.

- [https://github.com/BomboBombone/CVE-2026-73310](https://github.com/BomboBombone/CVE-2026-73310) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73310.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73310.svg)


## CVE-2026-73309
 XenForo before 2.3.13 contains an authentication bypass vulnerability in the OAuth2 token endpoint that allows unauthenticated attackers to obtain valid token pairs by submitting empty values for client_secret and code_verifier parameters. Attackers can exploit PHP truthy evaluation logic, which treats empty strings as false and skips client secret validation and PKCE code verifier validation, to exchange a valid authorization code for a token pair without proving client identity or holding the PKCE commitment.

- [https://github.com/BomboBombone/CVE-2026-73309](https://github.com/BomboBombone/CVE-2026-73309) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-73309.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-73309.svg)


## CVE-2026-72744
 Nuxt versions = 4.4.7 and  4.5.1, and = 3.21.7 and  3.21.10, contain an information disclosure vulnerability in the development server's Chrome DevTools workspace endpoint (GET /.well-known/appspecific/com.chrome.devtools.json). The endpoint's local-request gate (isLocalDevRequest) is header-based and trusts the attacker-supplied Host header rather than the connected peer address. When the dev server is bound to a network-reachable interface (e.g. nuxt dev --host) and experimental.chromeDevtoolsProjectSettings is enabled (the default), an unauthenticated attacker on the LAN can send a request with a spoofed Host header and no browser-specific headers (Sec-Fetch-Site, Origin, Referer) to retrieve the project's absolute filesystem root path (rootDir) and a persistent per-project workspace UUID. Production builds are unaffected. Fixed in 4.5.1 and 3.21.10.

- [https://github.com/Saku0512/CVE-2026-72744-poc](https://github.com/Saku0512/CVE-2026-72744-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-72744-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-72744-poc.svg)


## CVE-2026-69451
 Use after free in Windows Management Instrumentation allows an authorized attacker to elevate privileges over a network.

- [https://github.com/fj016/CVE-2026-69451-PoC](https://github.com/fj016/CVE-2026-69451-PoC) :  ![starts](https://img.shields.io/github/stars/fj016/CVE-2026-69451-PoC.svg) ![forks](https://img.shields.io/github/forks/fj016/CVE-2026-69451-PoC.svg)


## CVE-2026-63077
 In JetBrains TeamCity before 2026.1.3, 2025.11.7 unauthenticated remote code execution was possible via the agent polling protocol

- [https://github.com/unveiledhistory49/teamcity-cve-2026-63077-remediation](https://github.com/unveiledhistory49/teamcity-cve-2026-63077-remediation) :  ![starts](https://img.shields.io/github/stars/unveiledhistory49/teamcity-cve-2026-63077-remediation.svg) ![forks](https://img.shields.io/github/forks/unveiledhistory49/teamcity-cve-2026-63077-remediation.svg)


## CVE-2026-59903
 Netty is an asynchronous, event-driven network application framework. Prior to 4.1.137.Final and 4.2.17.Final, io.netty.handler.codec.http.cors.CorsHandler setVaryHeader replaces application Vary headers such as Authorization or Cookie with Origin, allowing a caching proxy or CDN to reuse authenticated responses across users and disclose sensitive information. This issue is fixed in versions 4.1.137.Final and 4.2.17.Final.

- [https://github.com/xiaoqiMikko/netty-http-check](https://github.com/xiaoqiMikko/netty-http-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/netty-http-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/netty-http-check.svg)


## CVE-2026-57811
 Improper Control of Generation of Code ('Code Injection') vulnerability in Realtyna Realtyna Organic IDX plugin real-estate-listing-realtyna-wpl allows Remote Code Inclusion.This issue affects Realtyna Organic IDX plugin: from n/a through = 5.2.0.

- [https://github.com/0xCyp1337/CVE-2026-57811](https://github.com/0xCyp1337/CVE-2026-57811) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-57811.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-57811.svg)


## CVE-2026-52307
 An authenticated stored cross-site scripting (XSS) vulnerability in the Column Management component of ClassCMS 1CMS v5.6 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the title field.

- [https://github.com/linan-OO/CVE-2026-52307](https://github.com/linan-OO/CVE-2026-52307) :  ![starts](https://img.shields.io/github/stars/linan-OO/CVE-2026-52307.svg) ![forks](https://img.shields.io/github/forks/linan-OO/CVE-2026-52307.svg)


## CVE-2026-45033
 GitHub Copilot CLI brings AI-powered coding assistance directly to your command line. Prior to 1.0.43, a  security vulnerability has been identified in GitHub Copilot CLI where a malicious bare git repository nested inside a project directory can achieve arbitrary code execution when the agent performs git operations. By exploiting git's automatic bare repository discovery during directory traversal, an attacker can set core.fsmonitor or other executable config keys to run arbitrary commands without user awareness or approval. The vulnerability arises because git's core.fsmonitor config key (and 15+ similar keys such as core.hookspath, diff.external, merge.tool, etc.) can specify arbitrary shell commands that git will execute as part of normal operations like status, diff, or rev-parse. This vulnerability is fixed in 1.0.43.

- [https://github.com/soemoescode/guardskill](https://github.com/soemoescode/guardskill) :  ![starts](https://img.shields.io/github/stars/soemoescode/guardskill.svg) ![forks](https://img.shields.io/github/forks/soemoescode/guardskill.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/R0rt1z2/GhostLock](https://github.com/R0rt1z2/GhostLock) :  ![starts](https://img.shields.io/github/stars/R0rt1z2/GhostLock.svg) ![forks](https://img.shields.io/github/forks/R0rt1z2/GhostLock.svg)


## CVE-2026-40369
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/dbgbgtf1/cve-2026-40369-exploit](https://github.com/dbgbgtf1/cve-2026-40369-exploit) :  ![starts](https://img.shields.io/github/stars/dbgbgtf1/cve-2026-40369-exploit.svg) ![forks](https://img.shields.io/github/forks/dbgbgtf1/cve-2026-40369-exploit.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/Th3Purge/CVE-2026-39987](https://github.com/Th3Purge/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/Th3Purge/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/Th3Purge/CVE-2026-39987.svg)


## CVE-2026-33870
 Netty is an asynchronous, event-driven network application framework. In versions prior to 4.1.132.Final and 4.2.10.Final, Netty incorrectly parses quoted strings in HTTP/1.1 chunked transfer encoding extension values, enabling request smuggling attacks. Versions 4.1.132.Final and 4.2.10.Final fix the issue.

- [https://github.com/xiaoqiMikko/netty-http-check](https://github.com/xiaoqiMikko/netty-http-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/netty-http-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/netty-http-check.svg)


## CVE-2026-30225
 OliveTin gives access to predefined shell commands from a web interface. Prior to version 3000.11.1, an authentication context confusion vulnerability in RestartAction allows a low‑privileged authenticated user to execute actions they are not permitted to run. RestartAction constructs a new internal connect.Request without preserving the original caller’s authentication headers or cookies. When this synthetic request is passed to StartAction, the authentication resolver falls back to the guest user. If the guest account has broader permissions than the authenticated caller, this results in privilege escalation and unauthorized command execution. This vulnerability allows a low‑privileged authenticated user to bypass ACL restrictions and execute arbitrary configured shell actions. This issue has been patched in version 3000.11.1.

- [https://github.com/hackerking24/CVE-2026-30225-OliveTin-RCE](https://github.com/hackerking24/CVE-2026-30225-OliveTin-RCE) :  ![starts](https://img.shields.io/github/stars/hackerking24/CVE-2026-30225-OliveTin-RCE.svg) ![forks](https://img.shields.io/github/forks/hackerking24/CVE-2026-30225-OliveTin-RCE.svg)


## CVE-2026-29782
 OpenSTAManager is an open source management software for technical assistance and invoicing. Prior to version 2.10.2, the oauth2.php file in OpenSTAManager is an unauthenticated endpoint ($skip_permissions = true). It loads a record from the zz_oauth2 table using the attacker-controlled GET parameter state, and during the OAuth2 configuration flow calls unserialize() on the access_token field without any class restriction. This issue has been patched in version 2.10.2.

- [https://github.com/hackerking24/CVE-2026-29782-OpenSTAManager-RCE](https://github.com/hackerking24/CVE-2026-29782-OpenSTAManager-RCE) :  ![starts](https://img.shields.io/github/stars/hackerking24/CVE-2026-29782-OpenSTAManager-RCE.svg) ![forks](https://img.shields.io/github/forks/hackerking24/CVE-2026-29782-OpenSTAManager-RCE.svg)


## CVE-2026-19949
 The All-in-One WP Migration and Backup plugin for WordPress is vulnerable to SQL Injection via archive restore functionality in all versions up to, and including, 7.109 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. This can be leveraged to obtain the ai1wm_secret_key when a site administrator performs an archive restore and achieve remote code execution once able to leverage the ai1wm_secret_key value.

- [https://github.com/686f6c61/POC-AIOWPM-CVE-2026-19949](https://github.com/686f6c61/POC-AIOWPM-CVE-2026-19949) :  ![starts](https://img.shields.io/github/stars/686f6c61/POC-AIOWPM-CVE-2026-19949.svg) ![forks](https://img.shields.io/github/forks/686f6c61/POC-AIOWPM-CVE-2026-19949.svg)


## CVE-2026-10795
 The UpdraftPlus: WP Backup & Migration Plugin plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 1.26.4 via the UpdraftPlus_Remote_Communications_V2::wp_loaded function. This is due to insufficient validation of the remote communications message format, where signature verification can be bypassed and unchecked decryption return values collapse to a predictable all-zero encryption key. This makes it possible for unauthenticated attackers to forge arbitrary RPC commands and run them as the connected administrator, such as uploading and activating a malicious plugin, which ultimately leads to remote code execution.

- [https://github.com/HORKimhab/CVE-2026-10795](https://github.com/HORKimhab/CVE-2026-10795) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-10795.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-10795.svg)


## CVE-2026-8732
 The WP Maps Pro plugin for WordPress is vulnerable to Privilege Escalation via Administrator Account Creation in all versions up to, and including, 6.1.0. This is due to the wpgmp_temp_access_ajax AJAX action being registered with wp_ajax_nopriv_ and protected only by a nonce check using the fc-call-nonce nonce, which is publicly embedded into every frontend page via wp_localize_script as the nonce field of the wpgmp_local JavaScript object, rendering the check ineffective as an access control mechanism. This makes it possible for unauthenticated attackers to invoke the wpgmp_temp_access_support handler with check_temp=false, which unconditionally creates a new WordPress user with the hardcoded role of administrator via wp_insert_user() and returns a magic login URL that, when visited, calls wp_set_auth_cookie() to fully authenticate the attacker as the newly created administrator, resulting in complete site takeover.

- [https://github.com/fientix/CVE-2026-8732-PoC](https://github.com/fientix/CVE-2026-8732-PoC) :  ![starts](https://img.shields.io/github/stars/fientix/CVE-2026-8732-PoC.svg) ![forks](https://img.shields.io/github/forks/fientix/CVE-2026-8732-PoC.svg)


## CVE-2026-8069
 PredatorSense version 3.00.3136 to 3.00.3196 contain Local Privilege Escalation (LPE) vulnerability.The program exposes a Windows Named Pipe that uses a custom protocol to invoke internal functions. However, this Named Pipe is misconfigured, allowing any authenticated local user to execute arbitrary code with NT AUTHORITY\SYSTEM privileges and to delete arbitrary files with SYSTEM privileges. By leveraging this, an attacker can execute arbitrary code on the target system with elevated privileges.

- [https://github.com/S1eezer/CVE-2026-8069](https://github.com/S1eezer/CVE-2026-8069) :  ![starts](https://img.shields.io/github/stars/S1eezer/CVE-2026-8069.svg) ![forks](https://img.shields.io/github/forks/S1eezer/CVE-2026-8069.svg)


## CVE-2026-7727
 A vulnerability was determined in Shandong Hoteam Software PDM Product Data Management System up to 8.3.9. This affects the function GetQueryMachineGridOnePageData of the file /Base/BaseService.asmx/DataService. This manipulation of the argument SortOrder causes sql injection. The attack can be initiated remotely. Upgrading to version 8.3.10 is able to mitigate this issue. You should upgrade the affected component.

- [https://github.com/Morzan6/CVE-2026-77276-PoC](https://github.com/Morzan6/CVE-2026-77276-PoC) :  ![starts](https://img.shields.io/github/stars/Morzan6/CVE-2026-77276-PoC.svg) ![forks](https://img.shields.io/github/forks/Morzan6/CVE-2026-77276-PoC.svg)


## CVE-2026-2931
 The Amelia Booking plugin for WordPress is vulnerable to Insecure Direct Object References in versions up to, and including, 9.1.2. This is due to the plugin providing user-controlled access to objects, letting a user bypass authorization and access system resources. This makes it possible for authenticated attackers with customer-level permissions or above to change user passwords and potentially take over administrator accounts. The vulnerability is in the pro plugin, which has the same slug.

- [https://github.com/htrxuan/hdwebmobile-booking-appointments](https://github.com/htrxuan/hdwebmobile-booking-appointments) :  ![starts](https://img.shields.io/github/stars/htrxuan/hdwebmobile-booking-appointments.svg) ![forks](https://img.shields.io/github/forks/htrxuan/hdwebmobile-booking-appointments.svg)


## CVE-2026-0001
This issue affects Bifrost GPU Kernel Driver: from r41p0 through r49p5, from r50p0 through r51p0, from r54p1 through r54p2; Valhall GPU Kernel Driver: from r41p0 through r49p5, from r50p0 through r54p3, r55p0; Arm 5th Gen GPU Architecture Kernel Driver: from r41p0 through r49p5, from r50p0 through r54p3, r55p0.

- [https://github.com/HORKimhab/CVE-2026-0001](https://github.com/HORKimhab/CVE-2026-0001) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-0001.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-0001.svg)
- [https://github.com/sohanbhowmik/cyberthreat_DBSproject](https://github.com/sohanbhowmik/cyberthreat_DBSproject) :  ![starts](https://img.shields.io/github/stars/sohanbhowmik/cyberthreat_DBSproject.svg) ![forks](https://img.shields.io/github/forks/sohanbhowmik/cyberthreat_DBSproject.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/r3vpwnx/CVE-2025-58434](https://github.com/r3vpwnx/CVE-2025-58434) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/CVE-2025-58434.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/CVE-2025-58434.svg)


## CVE-2025-47981
 Heap-based buffer overflow in Windows SPNEGO Extended Negotiation allows an unauthorized attacker to execute code over a network.

- [https://github.com/HKenzoKimura/CVE-2025-47981](https://github.com/HKenzoKimura/CVE-2025-47981) :  ![starts](https://img.shields.io/github/stars/HKenzoKimura/CVE-2025-47981.svg) ![forks](https://img.shields.io/github/forks/HKenzoKimura/CVE-2025-47981.svg)


## CVE-2025-20701
 In the Airoha Bluetooth audio SDK, there is a possible way to pair Bluetooth audio device without user consent. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/x0jac0b0x/skullcandy-dime3-cve-2025-20701](https://github.com/x0jac0b0x/skullcandy-dime3-cve-2025-20701) :  ![starts](https://img.shields.io/github/stars/x0jac0b0x/skullcandy-dime3-cve-2025-20701.svg) ![forks](https://img.shields.io/github/forks/x0jac0b0x/skullcandy-dime3-cve-2025-20701.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/r3vpwnx/CVE-2025-8110](https://github.com/r3vpwnx/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/CVE-2025-8110.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2024-36114
 Aircompressor is a library with ports of the Snappy, LZO, LZ4, and Zstandard compression algorithms to Java. All decompressor implementations of Aircompressor (LZ4, LZO, Snappy, Zstandard) can crash the JVM for certain input, and in some cases also leak the content of other memory of the Java process (which could contain sensitive information). When decompressing certain data, the decompressors try to access memory outside the bounds of the given byte arrays or byte buffers. Because Aircompressor uses the JDK class `sun.misc.Unsafe` to speed up memory access, no additional bounds checks are performed and this has similar security consequences as out-of-bounds access in C or C++, namely it can lead to non-deterministic behavior or crash the JVM. Users should update to Aircompressor 0.27 or newer where these issues have been fixed. When decompressing data from untrusted users, this can be exploited for a denial-of-service attack by crashing the JVM, or to leak other sensitive information from the Java process. There are no known workarounds for this issue.

- [https://github.com/SerpstatGlobal/ClickHouse-Native-JDBC](https://github.com/SerpstatGlobal/ClickHouse-Native-JDBC) :  ![starts](https://img.shields.io/github/stars/SerpstatGlobal/ClickHouse-Native-JDBC.svg) ![forks](https://img.shields.io/github/forks/SerpstatGlobal/ClickHouse-Native-JDBC.svg)


## CVE-2024-3196
 A vulnerability was found in MailCleaner up to 2023.03.14. It has been declared as critical. This vulnerability affects the function getStats/Services_silentDump/Services_stopStartMTA/Config_saveDateTime/Config_hostid/Logs_StartGetStat/dumpConfiguration of the component SOAP Service. The manipulation leads to os command injection. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-262312.

- [https://github.com/gmh5225/CVE-2024-31969](https://github.com/gmh5225/CVE-2024-31969) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2024-31969.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2024-31969.svg)


## CVE-2022-4140
 The Welcart e-Commerce WordPress plugin before 2.8.5 does not validate user input before using it to output the content of a file, which could allow unauthenticated attacker to read arbitrary files on the server

- [https://github.com/anirbala98/CVE-2022-4140](https://github.com/anirbala98/CVE-2022-4140) :  ![starts](https://img.shields.io/github/stars/anirbala98/CVE-2022-4140.svg) ![forks](https://img.shields.io/github/forks/anirbala98/CVE-2022-4140.svg)


## CVE-2022-2869
 libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw could cause a crash or potentially further exploitation.

- [https://github.com/halahajyahia/CVE-2022-2869-detector](https://github.com/halahajyahia/CVE-2022-2869-detector) :  ![starts](https://img.shields.io/github/stars/halahajyahia/CVE-2022-2869-detector.svg) ![forks](https://img.shields.io/github/forks/halahajyahia/CVE-2022-2869-detector.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/samirchapagain/metasploit-lab-report](https://github.com/samirchapagain/metasploit-lab-report) :  ![starts](https://img.shields.io/github/stars/samirchapagain/metasploit-lab-report.svg) ![forks](https://img.shields.io/github/forks/samirchapagain/metasploit-lab-report.svg)


## CVE-2010-4221
 Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.

- [https://github.com/diegslva/cve-2010-4221-lab](https://github.com/diegslva/cve-2010-4221-lab) :  ![starts](https://img.shields.io/github/stars/diegslva/cve-2010-4221-lab.svg) ![forks](https://img.shields.io/github/forks/diegslva/cve-2010-4221-lab.svg)

