# Update 2026-05-18
## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/KaraZajac/CHARON](https://github.com/KaraZajac/CHARON) :  ![starts](https://img.shields.io/github/stars/KaraZajac/CHARON.svg) ![forks](https://img.shields.io/github/forks/KaraZajac/CHARON.svg)


## CVE-2026-45672
 Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to 0.8.12, the /api/v1/utils/code/execute endpoint executes arbitrary Python code via Jupyter for any verified user, even when the admin has set ENABLE_CODE_EXECUTION=false. The feature gate is not enforced on the API endpoint — the configuration says "disabled" but code still executes. This vulnerability is fixed in 0.8.12.

- [https://github.com/CryptReaper12/CVE-2026-45672](https://github.com/CryptReaper12/CVE-2026-45672) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-45672.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-45672.svg)


## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/fabriziosalmi/tanstack-compromise-checker](https://github.com/fabriziosalmi/tanstack-compromise-checker) :  ![starts](https://img.shields.io/github/stars/fabriziosalmi/tanstack-compromise-checker.svg) ![forks](https://img.shields.io/github/forks/fabriziosalmi/tanstack-compromise-checker.svg)
- [https://github.com/digi4care/shai-scan](https://github.com/digi4care/shai-scan) :  ![starts](https://img.shields.io/github/stars/digi4care/shai-scan.svg) ![forks](https://img.shields.io/github/forks/digi4care/shai-scan.svg)


## CVE-2026-45091
 sealed-env is a cross-stack, zero-trust secret management library for Node.js and Java/Spring Boot. In sealed-env enterprise mode, versions 0.1.0-alpha.1 through 0.1.0-alpha.3 embedded the operator's literal TOTP secret in the JWS payload of every minted unseal token. JWS payload is base64-encoded JSON, NOT encrypted. Any party who could observe a minted token (CI build logs, container env dumps, kubectl describe pod, Sentry/Rollbar stack traces, log aggregators) could decode the payload and extract the TOTP secret in plaintext. This vulnerability is fixed in 0.1.0-alpha.4.

- [https://github.com/HORKimhab/CVE-2026-45091](https://github.com/HORKimhab/CVE-2026-45091) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-45091.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-45091.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dinosn/CVE-2026-44578](https://github.com/dinosn/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-44578.svg)
- [https://github.com/0xBlackash/CVE-2026-44578](https://github.com/0xBlackash/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-44578.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/whosfault/CVE-2026-43284](https://github.com/whosfault/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/whosfault/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/whosfault/CVE-2026-43284.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/sibersan/web-server-audit_CVE-2026-42945](https://github.com/sibersan/web-server-audit_CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/sibersan/web-server-audit_CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/sibersan/web-server-audit_CVE-2026-42945.svg)
- [https://github.com/dinosn/cve-2026-42945-nginx32-lab](https://github.com/dinosn/cve-2026-42945-nginx32-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-42945-nginx32-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-42945-nginx32-lab.svg)
- [https://github.com/MateusVerass/nGixshell](https://github.com/MateusVerass/nGixshell) :  ![starts](https://img.shields.io/github/stars/MateusVerass/nGixshell.svg) ![forks](https://img.shields.io/github/forks/MateusVerass/nGixshell.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/ByteWraith1/CVE-2026-41096](https://github.com/ByteWraith1/CVE-2026-41096) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-41096.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-41096.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/NathanHimself/CVE-2026-38526-PoC](https://github.com/NathanHimself/CVE-2026-38526-PoC) :  ![starts](https://img.shields.io/github/stars/NathanHimself/CVE-2026-38526-PoC.svg) ![forks](https://img.shields.io/github/forks/NathanHimself/CVE-2026-38526-PoC.svg)


## CVE-2026-34473
 Unauthenticated DoS in ZTE H8102E, H168N, H167A, H199A, H288A, H198A, H267A, H267N, H268A, H388X, H196A, H369A, H268N, H208N, H367N, H181A, and H196Q. A denial-of-service condition can be triggered against the router's web interface by sending an oversized application/x-www-form-urlencoded POST body. After triggering, the management interface may become unresponsive until the device is rebooted. This may affect any firmware version prior to 2022 (reporter observation). The supplier stated that devices are not vulnerable since 2021-03-23; operator firmware may vary.

- [https://github.com/minanagehsalalma/cve-2026-34473-unauthenticated-dos-zte-routers](https://github.com/minanagehsalalma/cve-2026-34473-unauthenticated-dos-zte-routers) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/cve-2026-34473-unauthenticated-dos-zte-routers.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/cve-2026-34473-unauthenticated-dos-zte-routers.svg)


## CVE-2026-25940
 jsPDF is a library to generate PDFs in JavaScript. Prior to 4.2.0, user control of properties and methods of the Acroform module allows users to inject arbitrary PDF objects, such as JavaScript actions. If given the possibility to pass unsanitized input to one of the following property, a user can inject arbitrary PDF objects, such as JavaScript actions, which are executed when the victim hovers over the radio option. The vulnerability has been fixed in jsPDF@4.2.0. As a workaround, sanitize user input before passing it to the vulnerable API members.

- [https://github.com/open-flaw/CVE-2026-25940](https://github.com/open-flaw/CVE-2026-25940) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2026-25940.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2026-25940.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/sibersan/apache_audit_cve-2026-23918](https://github.com/sibersan/apache_audit_cve-2026-23918) :  ![starts](https://img.shields.io/github/stars/sibersan/apache_audit_cve-2026-23918.svg) ![forks](https://img.shields.io/github/forks/sibersan/apache_audit_cve-2026-23918.svg)


## CVE-2026-21717
This vulnerability affects **20.x, 22.x, 24.x, and 25.x**.

- [https://github.com/open-flaw/CVE-2026-21717](https://github.com/open-flaw/CVE-2026-21717) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2026-21717.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2026-21717.svg)


## CVE-2026-21710
* This vulnerability affects all Node.js HTTP servers on **20.x, 22.x, 24.x, and v25.x**

- [https://github.com/open-flaw/CVE-2026-21710](https://github.com/open-flaw/CVE-2026-21710) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2026-21710.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2026-21710.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/whattheslime/CVE-2026-8181](https://github.com/whattheslime/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/whattheslime/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/whattheslime/CVE-2026-8181.svg)
- [https://github.com/Jenderal92/CVE-2026-8181](https://github.com/Jenderal92/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-8181.svg)


## CVE-2026-6857
 A flaw was found in camel-infinispan. This vulnerability involves unsafe deserialization in the ProtoStream remote aggregation repository. A remote attacker with low privileges could exploit this by sending specially crafted data, leading to arbitrary code execution. This allows the attacker to gain full control over the affected system, impacting its confidentiality, integrity, and availability.

- [https://github.com/HORKimhab/CVE-2026-6857](https://github.com/HORKimhab/CVE-2026-6857) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-6857.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-6857.svg)


## CVE-2026-6433
 The Custom css-js-php WordPress plugin through 2.0.7 does not properly sanitize user input before using it in a SQL query, and the result is passed to eval(), allowing unauthenticated users to execute arbitrary PHP code on the server.

- [https://github.com/murrez/CVE-2026-6433](https://github.com/murrez/CVE-2026-6433) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-6433.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-6433.svg)


## CVE-2026-4882
 The User Registration Advanced Fields plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'URAF_AJAX::method_upload' function in all versions up to, and including, 1.6.20. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability can only be exploited if a "Profile Picture" field is added to the form.

- [https://github.com/xShadow-Here/CVE-2026-4882](https://github.com/xShadow-Here/CVE-2026-4882) :  ![starts](https://img.shields.io/github/stars/xShadow-Here/CVE-2026-4882.svg) ![forks](https://img.shields.io/github/forks/xShadow-Here/CVE-2026-4882.svg)


## CVE-2026-3643
 The Accessibly plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the REST API in all versions up to, and including, 3.0.3. The plugin registers REST API endpoints at `/otm-ac/v1/update-widget-options` and `/otm-ac/v1/update-app-config` with the `permission_callback` set to `__return_true`, which means no authentication or authorization check is performed. The `updateWidgetOptions()` function in `AdminApi.php` accepts user-supplied JSON data and passes it directly to `AccessiblyOptions::updateAppConfig()`, which saves it to the WordPress options table via `update_option()` without any sanitization or validation. The stored `widgetSrc` value is later retrieved by `AssetsManager::enqueueFrontendScripts()` and passed directly to `wp_enqueue_script()` as the script URL, causing it to be rendered as a `script` tag on every front-end page. This makes it possible for unauthenticated attackers to inject arbitrary JavaScript that executes for all site visitors by changing the `widgetSrc` option to point to a malicious external script.

- [https://github.com/vtrmK/CVE-2026-36436-Public-Reference-Pack](https://github.com/vtrmK/CVE-2026-36436-Public-Reference-Pack) :  ![starts](https://img.shields.io/github/stars/vtrmK/CVE-2026-36436-Public-Reference-Pack.svg) ![forks](https://img.shields.io/github/forks/vtrmK/CVE-2026-36436-Public-Reference-Pack.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/xqi1337/poc-CVE-2026-0073](https://github.com/xqi1337/poc-CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/xqi1337/poc-CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/xqi1337/poc-CVE-2026-0073.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/im-nymii/CVE-2025-59528](https://github.com/im-nymii/CVE-2025-59528) :  ![starts](https://img.shields.io/github/stars/im-nymii/CVE-2025-59528.svg) ![forks](https://img.shields.io/github/forks/im-nymii/CVE-2025-59528.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/vincent-vbg/CVE-2025-58434-PoC](https://github.com/vincent-vbg/CVE-2025-58434-PoC) :  ![starts](https://img.shields.io/github/stars/vincent-vbg/CVE-2025-58434-PoC.svg) ![forks](https://img.shields.io/github/forks/vincent-vbg/CVE-2025-58434-PoC.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/open-flaw/CVE-2025-49844](https://github.com/open-flaw/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2025-49844.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/V0idW1re/HTB-Pterodactyl-Writeup](https://github.com/V0idW1re/HTB-Pterodactyl-Writeup) :  ![starts](https://img.shields.io/github/stars/V0idW1re/HTB-Pterodactyl-Writeup.svg) ![forks](https://img.shields.io/github/forks/V0idW1re/HTB-Pterodactyl-Writeup.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/r3vpwnx/CVE-2025-24367](https://github.com/r3vpwnx/CVE-2025-24367) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/CVE-2025-24367.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/CVE-2025-24367.svg)


## CVE-2025-23061
 Mongoose before 8.9.5 can improperly use a nested $where filter with a populate() match, leading to search injection. NOTE: this issue exists because of an incomplete fix for CVE-2024-53900.

- [https://github.com/open-flaw/CVE-2025-23061](https://github.com/open-flaw/CVE-2025-23061) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2025-23061.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2025-23061.svg)


## CVE-2025-20362
 This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests. An attacker could exploit this vulnerability by sending crafted HTTP requests to a targeted web server on a device. A successful exploit could allow the attacker to access a restricted URL without authentication.

- [https://github.com/curtishoughton/CVE-2025-20362-Cisco-Scanner](https://github.com/curtishoughton/CVE-2025-20362-Cisco-Scanner) :  ![starts](https://img.shields.io/github/stars/curtishoughton/CVE-2025-20362-Cisco-Scanner.svg) ![forks](https://img.shields.io/github/forks/curtishoughton/CVE-2025-20362-Cisco-Scanner.svg)


## CVE-2025-20333
 This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests. An attacker with valid VPN user credentials could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute arbitrary code as root, possibly resulting in the complete compromise of the affected device.

- [https://github.com/curtishoughton/Cisco-ASA-CVE-2025-20333-Scanner](https://github.com/curtishoughton/Cisco-ASA-CVE-2025-20333-Scanner) :  ![starts](https://img.shields.io/github/stars/curtishoughton/Cisco-ASA-CVE-2025-20333-Scanner.svg) ![forks](https://img.shields.io/github/forks/curtishoughton/Cisco-ASA-CVE-2025-20333-Scanner.svg)


## CVE-2025-12758
 Versions of the package validator before 13.15.22 are vulnerable to Incomplete Filtering of One or More Instances of Special Elements in the isLength() function that does not take into account Unicode variation selectors (\uFE0F, \uFE0E) appearing in a sequence which lead to improper string length calculation. This can lead to an application using isLength for input validation accepting strings significantly longer than intended, resulting in issues like data truncation in databases, buffer overflows in other system components, or denial-of-service.

- [https://github.com/open-flaw/CVE-2025-12758](https://github.com/open-flaw/CVE-2025-12758) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2025-12758.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2025-12758.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/V0idW1re/HTB-Pterodactyl-Writeup](https://github.com/V0idW1re/HTB-Pterodactyl-Writeup) :  ![starts](https://img.shields.io/github/stars/V0idW1re/HTB-Pterodactyl-Writeup.svg) ![forks](https://img.shields.io/github/forks/V0idW1re/HTB-Pterodactyl-Writeup.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/V0idW1re/HTB-Pterodactyl-Writeup](https://github.com/V0idW1re/HTB-Pterodactyl-Writeup) :  ![starts](https://img.shields.io/github/stars/V0idW1re/HTB-Pterodactyl-Writeup.svg) ![forks](https://img.shields.io/github/forks/V0idW1re/HTB-Pterodactyl-Writeup.svg)


## CVE-2024-42327
 A non-admin user account on the Zabbix frontend with the default User role, or with any other role that gives API access can exploit this vulnerability. An SQLi exists in the CUser class in the addRelatedObjects function, this function is being called from the CUser.get function which is available for every user who has API access.

- [https://github.com/fellipefelix06/Zabbix-CVE-2024-42327](https://github.com/fellipefelix06/Zabbix-CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/fellipefelix06/Zabbix-CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/fellipefelix06/Zabbix-CVE-2024-42327.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/ben-slates/CVE-2024-37054](https://github.com/ben-slates/CVE-2024-37054) :  ![starts](https://img.shields.io/github/stars/ben-slates/CVE-2024-37054.svg) ![forks](https://img.shields.io/github/forks/ben-slates/CVE-2024-37054.svg)


## CVE-2024-0519
 Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Insaida/cve-2024-0519-rca-research](https://github.com/Insaida/cve-2024-0519-rca-research) :  ![starts](https://img.shields.io/github/stars/Insaida/cve-2024-0519-rca-research.svg) ![forks](https://img.shields.io/github/forks/Insaida/cve-2024-0519-rca-research.svg)


## CVE-2023-36561
 Azure DevOps Server Elevation of Privilege Vulnerability

- [https://github.com/sechmyn/cicd44-gh](https://github.com/sechmyn/cicd44-gh) :  ![starts](https://img.shields.io/github/stars/sechmyn/cicd44-gh.svg) ![forks](https://img.shields.io/github/forks/sechmyn/cicd44-gh.svg)


## CVE-2023-33538
 TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a command injection vulnerability via the component /userRpm/WlanNetworkRpm .

- [https://github.com/eev4n/tplink-osci](https://github.com/eev4n/tplink-osci) :  ![starts](https://img.shields.io/github/stars/eev4n/tplink-osci.svg) ![forks](https://img.shields.io/github/forks/eev4n/tplink-osci.svg)


## CVE-2023-26360
 Adobe ColdFusion versions 2018 Update 15 (and earlier) and 2021 Update 5 (and earlier) are affected by an Improper Access Control vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue does not require user interaction.

- [https://github.com/joaoaugustom/Adobe_ColdFusion_RCE_Unauthenticated](https://github.com/joaoaugustom/Adobe_ColdFusion_RCE_Unauthenticated) :  ![starts](https://img.shields.io/github/stars/joaoaugustom/Adobe_ColdFusion_RCE_Unauthenticated.svg) ![forks](https://img.shields.io/github/forks/joaoaugustom/Adobe_ColdFusion_RCE_Unauthenticated.svg)


## CVE-2023-23946
 Git, a revision control system, is vulnerable to path traversal prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8. By feeding a crafted input to `git apply`, a path outside the working tree can be overwritten as the user who is running `git apply`. A fix has been prepared and will appear in v2.39.2, v2.38.4, v2.37.6, v2.36.5, v2.35.7, v2.34.7, v2.33.7, v2.32.6, v2.31.7, and v2.30.8. As a workaround, use `git apply --stat` to inspect a patch before applying; avoid applying one that creates a symbolic link and then creates a file beyond the symbolic link.

- [https://github.com/tralsesec/CVE-2023-23946](https://github.com/tralsesec/CVE-2023-23946) :  ![starts](https://img.shields.io/github/stars/tralsesec/CVE-2023-23946.svg) ![forks](https://img.shields.io/github/forks/tralsesec/CVE-2023-23946.svg)


## CVE-2023-20052
 This vulnerability is due to enabling XML entity substitution that may result in XML external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file that may be read by the ClamAV scanning process.

- [https://github.com/tralsesec/CVE-2023-20052](https://github.com/tralsesec/CVE-2023-20052) :  ![starts](https://img.shields.io/github/stars/tralsesec/CVE-2023-20052.svg) ![forks](https://img.shields.io/github/forks/tralsesec/CVE-2023-20052.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Gopartner/realme-c53-unlock-root](https://github.com/Gopartner/realme-c53-unlock-root) :  ![starts](https://img.shields.io/github/stars/Gopartner/realme-c53-unlock-root.svg) ![forks](https://img.shields.io/github/forks/Gopartner/realme-c53-unlock-root.svg)


## CVE-2022-33171
 The findOne function in TypeORM before 0.3.0 can either be supplied with a string or a FindOneOptions object. When input to the function is a user-controlled parsed JSON object, supplying a crafted FindOneOptions instead of an id string leads to SQL injection. NOTE: the vendor's position is that the user's application is responsible for input validation

- [https://github.com/open-flaw/CVE-2022-33171](https://github.com/open-flaw/CVE-2022-33171) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2022-33171.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2022-33171.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/rakutentech/jndi-ldap-test-server](https://github.com/rakutentech/jndi-ldap-test-server) :  ![starts](https://img.shields.io/github/stars/rakutentech/jndi-ldap-test-server.svg) ![forks](https://img.shields.io/github/forks/rakutentech/jndi-ldap-test-server.svg)


## CVE-2021-33393
 lfs/backup in IPFire 2.25-core155 does not ensure that /var/ipfire/backup/bin/backup.pl is owned by the root account. It might be owned by an unprivileged account, which could potentially be used to install a Trojan horse backup.pl script that is later executed by root. Similar problems with the ownership/permissions of other files may be present as well.

- [https://github.com/joaoaugustom/IPFire_2.25_RCE_Authenticated](https://github.com/joaoaugustom/IPFire_2.25_RCE_Authenticated) :  ![starts](https://img.shields.io/github/stars/joaoaugustom/IPFire_2.25_RCE_Authenticated.svg) ![forks](https://img.shields.io/github/forks/joaoaugustom/IPFire_2.25_RCE_Authenticated.svg)


## CVE-2020-8158
 Prototype pollution vulnerability in the TypeORM package  0.2.25 may allow attackers to add or modify Object properties leading to further denial of service or SQL injection attacks.

- [https://github.com/open-flaw/CVE-2020-8158](https://github.com/open-flaw/CVE-2020-8158) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2020-8158.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2020-8158.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/curtishoughton/CVE-2020-3452-Cisco-Python-Scanner](https://github.com/curtishoughton/CVE-2020-3452-Cisco-Python-Scanner) :  ![starts](https://img.shields.io/github/stars/curtishoughton/CVE-2020-3452-Cisco-Python-Scanner.svg) ![forks](https://img.shields.io/github/forks/curtishoughton/CVE-2020-3452-Cisco-Python-Scanner.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/z3ena/Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities](https://github.com/z3ena/Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/z3ena/Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/z3ena/Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities.svg)
- [https://github.com/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE](https://github.com/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE) :  ![starts](https://img.shields.io/github/stars/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE.svg) ![forks](https://img.shields.io/github/forks/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/abanop22333/Steel-Mountain-TryHackMe-Walkthrough-Windows-Privilege-Escalation-HFS-RCE](https://github.com/abanop22333/Steel-Mountain-TryHackMe-Walkthrough-Windows-Privilege-Escalation-HFS-RCE) :  ![starts](https://img.shields.io/github/stars/abanop22333/Steel-Mountain-TryHackMe-Walkthrough-Windows-Privilege-Escalation-HFS-RCE.svg) ![forks](https://img.shields.io/github/forks/abanop22333/Steel-Mountain-TryHackMe-Walkthrough-Windows-Privilege-Escalation-HFS-RCE.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001) :  ![starts](https://img.shields.io/github/stars/Jhatchi/NexaCorp-DFIR-INC-2026-001.svg) ![forks](https://img.shields.io/github/forks/Jhatchi/NexaCorp-DFIR-INC-2026-001.svg)

