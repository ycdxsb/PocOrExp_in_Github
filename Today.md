# Update 2026-06-03
## CVE-2026-48208
Please note that ((OTRS)) Community Edition 6.x and before are vulnerable. Products based on the ((OTRS)) Community Edition also very likely to be affected

- [https://github.com/Habuon/CVE-2026-48208](https://github.com/Habuon/CVE-2026-48208) :  ![starts](https://img.shields.io/github/stars/Habuon/CVE-2026-48208.svg) ![forks](https://img.shields.io/github/forks/Habuon/CVE-2026-48208.svg)


## CVE-2026-48188
Products based on the ((OTRS)) Community Edition also very likely to be affected

- [https://github.com/Habuon/CVE-2026-48188](https://github.com/Habuon/CVE-2026-48188) :  ![starts](https://img.shields.io/github/stars/Habuon/CVE-2026-48188.svg) ![forks](https://img.shields.io/github/forks/Habuon/CVE-2026-48188.svg)


## CVE-2026-45659
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/daniel30padd/CVE-2026-45659](https://github.com/daniel30padd/CVE-2026-45659) :  ![starts](https://img.shields.io/github/stars/daniel30padd/CVE-2026-45659.svg) ![forks](https://img.shields.io/github/forks/daniel30padd/CVE-2026-45659.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/alexadvanced95/yellowkey-bitlocker](https://github.com/alexadvanced95/yellowkey-bitlocker) :  ![starts](https://img.shields.io/github/stars/alexadvanced95/yellowkey-bitlocker.svg) ![forks](https://img.shields.io/github/forks/alexadvanced95/yellowkey-bitlocker.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/BS2010-AirborneTroops/NEXT-SSRF](https://github.com/BS2010-AirborneTroops/NEXT-SSRF) :  ![starts](https://img.shields.io/github/stars/BS2010-AirborneTroops/NEXT-SSRF.svg) ![forks](https://img.shields.io/github/forks/BS2010-AirborneTroops/NEXT-SSRF.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/josephfelix/CVE-2026-42945-nginx-rift](https://github.com/josephfelix/CVE-2026-42945-nginx-rift) :  ![starts](https://img.shields.io/github/stars/josephfelix/CVE-2026-42945-nginx-rift.svg) ![forks](https://img.shields.io/github/forks/josephfelix/CVE-2026-42945-nginx-rift.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/0xABCD01/CVE-2026-41089](https://github.com/0xABCD01/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/0xABCD01/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/0xABCD01/CVE-2026-41089.svg)


## CVE-2026-33320
 Dasel is a command-line tool and library for querying, modifying, and transforming data structures. Starting in version 3.0.0 and prior to version 3.3.1, Dasel's YAML reader allows an attacker who can supply YAML for processing to trigger extreme CPU and memory consumption. The issue is in the library's own `UnmarshalYAML` implementation, which manually resolves alias nodes by recursively following `yaml.Node.Alias` pointers without any expansion budget, bypassing go-yaml v4's built-in alias expansion limit. Version 3.3.2 contains a patch for the issue.

- [https://github.com/rotavori/dasel-melange-apko](https://github.com/rotavori/dasel-melange-apko) :  ![starts](https://img.shields.io/github/stars/rotavori/dasel-melange-apko.svg) ![forks](https://img.shields.io/github/forks/rotavori/dasel-melange-apko.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/lucastran05/CVE-2026-29000](https://github.com/lucastran05/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/lucastran05/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/lucastran05/CVE-2026-29000.svg)


## CVE-2026-27886
 Strapi is an open source headless content management system. Strapi versions starting in 4.0.0 and prior to 5.37.0 did not sufficiently sanitize query parameters when filtering content via relational fields. An unauthenticated attacker could use the `where` query parameter on any publicly-accessible content-type with an `updatedBy` (or other admin-relation) field to perform a boolean-oracle attack against private fields on the joined `admin_users` table, including the `resetPasswordToken` field. Extracting an admin reset token via this oracle made full administrative account takeover possible without authentication. When a filter such as `where[updatedBy][resetPasswordToken][$startsWith]=a` was applied to a public Content API endpoint, the underlying query generation performed a `LEFT JOIN` against the `admin_users` table and emitted a `WHERE` clause referencing the joined column. The query parameter sanitization layer did not block operator chains that traversed into relational target schemas the caller had no read permission on, allowing the response count to be used as a one-bit oracle on any admin-table field. The patch in version 5.37.0 introduces explicit query-parameter sanitization at the controller and service boundary via three new primitives: `strictParam`, `addQueryParams`, and `addBodyParams`. Operator chains that traverse into restricted relational targets are now rejected before reaching the database.

- [https://github.com/EvtDanya/CVE-2026-27886](https://github.com/EvtDanya/CVE-2026-27886) :  ![starts](https://img.shields.io/github/stars/EvtDanya/CVE-2026-27886.svg) ![forks](https://img.shields.io/github/forks/EvtDanya/CVE-2026-27886.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/ahmadsadeeq/TelnetdBypass-](https://github.com/ahmadsadeeq/TelnetdBypass-) :  ![starts](https://img.shields.io/github/stars/ahmadsadeeq/TelnetdBypass-.svg) ![forks](https://img.shields.io/github/forks/ahmadsadeeq/TelnetdBypass-.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/afifudinmtop/MCPJam-Inspector-1.4.2-Remote-Code-Execution-CVE-2026-23744](https://github.com/afifudinmtop/MCPJam-Inspector-1.4.2-Remote-Code-Execution-CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/afifudinmtop/MCPJam-Inspector-1.4.2-Remote-Code-Execution-CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/afifudinmtop/MCPJam-Inspector-1.4.2-Remote-Code-Execution-CVE-2026-23744.svg)


## CVE-2026-20982
 Path traversal in ShortcutService prior to SMR Feb-2026 Release 1 allows privileged local attacker to create file with system privilege.

- [https://github.com/Vikramaditya015/samsung-android-lpe](https://github.com/Vikramaditya015/samsung-android-lpe) :  ![starts](https://img.shields.io/github/stars/Vikramaditya015/samsung-android-lpe.svg) ![forks](https://img.shields.io/github/forks/Vikramaditya015/samsung-android-lpe.svg)


## CVE-2026-20981
 Improper input validation in FacAtFunction prior to SMR Feb-2026 Release 1 allows privileged physical attacker to execute arbitrary command with system privilege.

- [https://github.com/Vikramaditya015/samsung-android-lpe](https://github.com/Vikramaditya015/samsung-android-lpe) :  ![starts](https://img.shields.io/github/stars/Vikramaditya015/samsung-android-lpe.svg) ![forks](https://img.shields.io/github/forks/Vikramaditya015/samsung-android-lpe.svg)


## CVE-2026-20980
 Improper input validation in PACM prior to SMR Feb-2026 Release 1 allows physical attacker to execute arbitrary commands.

- [https://github.com/Vikramaditya015/samsung-android-lpe](https://github.com/Vikramaditya015/samsung-android-lpe) :  ![starts](https://img.shields.io/github/stars/Vikramaditya015/samsung-android-lpe.svg) ![forks](https://img.shields.io/github/forks/Vikramaditya015/samsung-android-lpe.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/0xBlackash/CVE-2026-20841](https://github.com/0xBlackash/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20841.svg)


## CVE-2026-10290
 A weakness has been identified in code-projects Hotel and Tourism Reservation System 1.0. The affected element is an unknown function of the file tour.php of the component GET Parameter Handler. Executing a manipulation of the argument tour can lead to sql injection. The attack can be launched remotely. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/Xmyronn/CVE-2026-10290-SQLI](https://github.com/Xmyronn/CVE-2026-10290-SQLI) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-10290-SQLI.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-10290-SQLI.svg)


## CVE-2026-10289
 A security flaw has been discovered in code-projects Hotel and Tourism Reservation System 1.0. Impacted is an unknown function of the file /ht/tour.php. Performing a manipulation of the argument name /email /people /number results in cross site scripting. The attack can be initiated remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/Xmyronn/CVE-2026-10289-XSS](https://github.com/Xmyronn/CVE-2026-10289-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-10289-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-10289-XSS.svg)


## CVE-2026-10288
 A vulnerability was identified in code-projects Hotel and Tourism Reservation System 1.0. This issue affects the function password_verify of the file /admin/login.php of the component Admin Login. Such manipulation of the argument Password leads to improper authentication. It is possible to launch the attack remotely. The exploit is publicly available and might be used.

- [https://github.com/Xmyronn/CVE-2026-10288-AUTH-BYPASS](https://github.com/Xmyronn/CVE-2026-10288-AUTH-BYPASS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-10288-AUTH-BYPASS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-10288-AUTH-BYPASS.svg)


## CVE-2026-10243
 A security vulnerability has been detected in code-projects Smart Parking System 1.0. Affected is an unknown function of the component Admin Endpoint. Such manipulation leads to missing authentication. It is possible to launch the attack remotely. The exploit has been disclosed publicly and may be used. Multiple endpoints are affected.

- [https://github.com/Xmyronn/CVE-2026-10243-AUTH](https://github.com/Xmyronn/CVE-2026-10243-AUTH) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-10243-AUTH.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-10243-AUTH.svg)


## CVE-2026-9560
 Privilege escalation via background service of OpenVPN Connect 3.5.1 through 3.8.1 on macOS allows attackers to execute arbitrary commands with elevated privileges via local IPC channel

- [https://github.com/HORKimhab/CVE-2026-9560](https://github.com/HORKimhab/CVE-2026-9560) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-9560.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-9560.svg)


## CVE-2026-8732
 The WP Maps Pro plugin for WordPress is vulnerable to Privilege Escalation via Administrator Account Creation in all versions up to, and including, 6.1.0. This is due to the wpgmp_temp_access_ajax AJAX action being registered with wp_ajax_nopriv_ and protected only by a nonce check using the fc-call-nonce nonce, which is publicly embedded into every frontend page via wp_localize_script as the nonce field of the wpgmp_local JavaScript object, rendering the check ineffective as an access control mechanism. This makes it possible for unauthenticated attackers to invoke the wpgmp_temp_access_support handler with check_temp=false, which unconditionally creates a new WordPress user with the hardcoded role of administrator via wp_insert_user() and returns a magic login URL that, when visited, calls wp_set_auth_cookie() to fully authenticate the attacker as the newly created administrator, resulting in complete site takeover.

- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-8732-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-8732-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-8732-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-8732-POC.svg)
- [https://github.com/HORKimhab/CVE-2026-8732](https://github.com/HORKimhab/CVE-2026-8732) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-8732.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-8732.svg)


## CVE-2026-3600
 The Investi plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'investi-announcements-accordion' shortcode's 'maximum-num-years' attribute in all versions up to, and including, 1.0.26. This is due to insufficient input sanitization and output escaping on user-supplied shortcode attributes. Specifically, the 'maximum-num-years' attribute value is read directly from shortcode attributes and interpolated into a double-quoted HTML attribute without any escaping (no esc_attr(), htmlspecialchars(), or similar). This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/K3ysTr0K3R/CVE-2026-3600](https://github.com/K3ysTr0K3R/CVE-2026-3600) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-3600.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-3600.svg)


## CVE-2026-2291
 dnsmasqs extract_name() function can be abused to cause a heap buffer overflow, allowing an attacker to inject false DNS cache entries, which could result in DNS lookups to redirect to an attacker-controlled IP address, or to cause a DoS.

- [https://github.com/JianrongXiao-Linksys/dnsmasq-cve-2026](https://github.com/JianrongXiao-Linksys/dnsmasq-cve-2026) :  ![starts](https://img.shields.io/github/stars/JianrongXiao-Linksys/dnsmasq-cve-2026.svg) ![forks](https://img.shields.io/github/forks/JianrongXiao-Linksys/dnsmasq-cve-2026.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/Mr-Robot-LP/CVE-2026-0257](https://github.com/Mr-Robot-LP/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/Mr-Robot-LP/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/Mr-Robot-LP/CVE-2026-0257.svg)
- [https://github.com/jennydokumi30/CVE-2026-0257](https://github.com/jennydokumi30/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/jennydokumi30/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/jennydokumi30/CVE-2026-0257.svg)
- [https://github.com/bolubey/CVE-2026-0257](https://github.com/bolubey/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/bolubey/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/bolubey/CVE-2026-0257.svg)


## CVE-2025-70849
 Arbitrary File Upload in podinfo thru 6.9.0 allows unauthenticated attackers to upload arbitrary files via crafted POST request to the /store endpoint. The application renders uploaded content without a restrictive Content-Security-Policy (CSP) or adequate Content-Type validation, leading to Stored Cross-Site Scripting (XSS).

- [https://github.com/HORKimhab/CVE-2025-70849](https://github.com/HORKimhab/CVE-2025-70849) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-70849.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-70849.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-66212
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in the Dynamic Proxy Configuration Filename handling allows users with application/service management permissions to execute arbitrary commands as root on managed servers. Proxy configuration filenames are passed to shell commands without proper escaping, enabling full remote code execution. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-66211
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in PostgreSQL Init Script Filename handling allows users with application/service management permissions to execute arbitrary commands as root on managed servers. PostgreSQL initialization script filenames are passed to shell commands without proper validation, enabling full remote code execution. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/SuriyaBoon/HackTheBox-Silentium](https://github.com/SuriyaBoon/HackTheBox-Silentium) :  ![starts](https://img.shields.io/github/stars/SuriyaBoon/HackTheBox-Silentium.svg) ![forks](https://img.shields.io/github/forks/SuriyaBoon/HackTheBox-Silentium.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/SuriyaBoon/HackTheBox-Silentium](https://github.com/SuriyaBoon/HackTheBox-Silentium) :  ![starts](https://img.shields.io/github/stars/SuriyaBoon/HackTheBox-Silentium.svg) ![forks](https://img.shields.io/github/forks/SuriyaBoon/HackTheBox-Silentium.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Jenderal92/CVE-2025-55182-React2shell](https://github.com/Jenderal92/CVE-2025-55182-React2shell) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2025-55182-React2shell.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2025-55182-React2shell.svg)


## CVE-2025-40536
 SolarWinds Web Help Desk was found to be susceptible to a security control bypass vulnerability that if exploited, could allow an unauthenticated attacker to gain access to certain restricted functionality.

- [https://github.com/victoriaalicex/CVE-2025-40536-Analysis](https://github.com/victoriaalicex/CVE-2025-40536-Analysis) :  ![starts](https://img.shields.io/github/stars/victoriaalicex/CVE-2025-40536-Analysis.svg) ![forks](https://img.shields.io/github/forks/victoriaalicex/CVE-2025-40536-Analysis.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/JTMH37/Apache-Tomcat-CVE-2025-24813-Lab](https://github.com/JTMH37/Apache-Tomcat-CVE-2025-24813-Lab) :  ![starts](https://img.shields.io/github/stars/JTMH37/Apache-Tomcat-CVE-2025-24813-Lab.svg) ![forks](https://img.shields.io/github/forks/JTMH37/Apache-Tomcat-CVE-2025-24813-Lab.svg)


## CVE-2025-11391
 The PPOM – Product Addons & Custom Fields for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image cropper functionality in all versions up to, and including, 33.0.15. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. While the vulnerable code is in the free version, this only affected users with the paid version of the software installed and activated.

- [https://github.com/r3db34rdh4x/CVE-2025-11391](https://github.com/r3db34rdh4x/CVE-2025-11391) :  ![starts](https://img.shields.io/github/stars/r3db34rdh4x/CVE-2025-11391.svg) ![forks](https://img.shields.io/github/forks/r3db34rdh4x/CVE-2025-11391.svg)
- [https://github.com/moritakaaz/CVE-2025-11391](https://github.com/moritakaaz/CVE-2025-11391) :  ![starts](https://img.shields.io/github/stars/moritakaaz/CVE-2025-11391.svg) ![forks](https://img.shields.io/github/forks/moritakaaz/CVE-2025-11391.svg)


## CVE-2025-8671
 A mismatch caused by client-triggered server-sent stream resets between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may result in excessive server resource consumption leading to denial-of-service (DoS).  By opening streams and then rapidly triggering the server to reset them—using malformed frames or flow control errors—an attacker can exploit incorrect stream accounting. Streams reset by the server are considered closed at the protocol level, even though backend processing continues. This allows a client to cause the server to handle an unbounded number of concurrent streams on a single connection. This CVE will be updated as affected product details are released.

- [https://github.com/ayushghatkar8080/MadeYouReset_Tester](https://github.com/ayushghatkar8080/MadeYouReset_Tester) :  ![starts](https://img.shields.io/github/stars/ayushghatkar8080/MadeYouReset_Tester.svg) ![forks](https://img.shields.io/github/forks/ayushghatkar8080/MadeYouReset_Tester.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/SuriyaBoon/HackTheBox-Silentium](https://github.com/SuriyaBoon/HackTheBox-Silentium) :  ![starts](https://img.shields.io/github/stars/SuriyaBoon/HackTheBox-Silentium.svg) ![forks](https://img.shields.io/github/forks/SuriyaBoon/HackTheBox-Silentium.svg)


## CVE-2025-6389
 The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 8.3 via the sneeit_articles_pagination_callback() function. This is due to the function accepting user input and then passing that through call_user_func(). This makes it possible for unauthenticated attackers to execute code on the server which can be leveraged to inject backdoors or, for example, create new administrative user accounts.

- [https://github.com/AivarSaar/blackash-cve-2025-6389](https://github.com/AivarSaar/blackash-cve-2025-6389) :  ![starts](https://img.shields.io/github/stars/AivarSaar/blackash-cve-2025-6389.svg) ![forks](https://img.shields.io/github/forks/AivarSaar/blackash-cve-2025-6389.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/AvidanMaatuk/CVE-2024-38063](https://github.com/AvidanMaatuk/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/AvidanMaatuk/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/AvidanMaatuk/CVE-2024-38063.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/P4rC3L/Global-Protect_VPN_Vuln](https://github.com/P4rC3L/Global-Protect_VPN_Vuln) :  ![starts](https://img.shields.io/github/stars/P4rC3L/Global-Protect_VPN_Vuln.svg) ![forks](https://img.shields.io/github/forks/P4rC3L/Global-Protect_VPN_Vuln.svg)


## CVE-2023-39325
 A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive server resource consumption. While the total number of requests is bounded by the http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound the number of simultaneously executing handler goroutines to the stream concurrency limit (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2 for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the Server.MaxConcurrentStreams setting and the ConfigureServer function.

- [https://github.com/eilam-cell/cve-test-coredns-fork](https://github.com/eilam-cell/cve-test-coredns-fork) :  ![starts](https://img.shields.io/github/stars/eilam-cell/cve-test-coredns-fork.svg) ![forks](https://img.shields.io/github/forks/eilam-cell/cve-test-coredns-fork.svg)


## CVE-2023-26083
 Memory leak vulnerability in Mali GPU Kernel Driver in Midgard GPU Kernel Driver all versions from r6p0 - r32p0, Bifrost GPU Kernel Driver all versions from r0p0 - r42p0, Valhall GPU Kernel Driver all versions from r19p0 - r42p0, and Avalon GPU Kernel Driver all versions from r41p0 - r42p0 allows a non-privileged user to make valid GPU processing operations that expose sensitive kernel metadata.

- [https://github.com/Noverisp3/CVE-2023-26083](https://github.com/Noverisp3/CVE-2023-26083) :  ![starts](https://img.shields.io/github/stars/Noverisp3/CVE-2023-26083.svg) ![forks](https://img.shields.io/github/forks/Noverisp3/CVE-2023-26083.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.

- [https://github.com/anupamojha-eng/sentinel-transitive-cve-demo](https://github.com/anupamojha-eng/sentinel-transitive-cve-demo) :  ![starts](https://img.shields.io/github/stars/anupamojha-eng/sentinel-transitive-cve-demo.svg) ![forks](https://img.shields.io/github/forks/anupamojha-eng/sentinel-transitive-cve-demo.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/code-msga/HikvisionExploiter_fixed](https://github.com/code-msga/HikvisionExploiter_fixed) :  ![starts](https://img.shields.io/github/stars/code-msga/HikvisionExploiter_fixed.svg) ![forks](https://img.shields.io/github/forks/code-msga/HikvisionExploiter_fixed.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/DakerQirszh/cve-2021-3156](https://github.com/DakerQirszh/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/DakerQirszh/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/DakerQirszh/cve-2021-3156.svg)


## CVE-2017-8798
 Integer signedness error in MiniUPnP MiniUPnPc v1.4.20101221 through v2.0 allows remote attackers to cause a denial of service or possibly have unspecified other impact.

- [https://github.com/not-tlynch/home-network-security-assessment](https://github.com/not-tlynch/home-network-security-assessment) :  ![starts](https://img.shields.io/github/stars/not-tlynch/home-network-security-assessment.svg) ![forks](https://img.shields.io/github/forks/not-tlynch/home-network-security-assessment.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/R3fr4kt/Shocker-TJNULL-OSCP-](https://github.com/R3fr4kt/Shocker-TJNULL-OSCP-) :  ![starts](https://img.shields.io/github/stars/R3fr4kt/Shocker-TJNULL-OSCP-.svg) ![forks](https://img.shields.io/github/forks/R3fr4kt/Shocker-TJNULL-OSCP-.svg)


## CVE-2011-3192
 The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.

- [https://github.com/Karma4488/cve-2011-3192](https://github.com/Karma4488/cve-2011-3192) :  ![starts](https://img.shields.io/github/stars/Karma4488/cve-2011-3192.svg) ![forks](https://img.shields.io/github/forks/Karma4488/cve-2011-3192.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/nitinsukthe/OpenVAS-Vulnerability-Assessment---Incident-Response](https://github.com/nitinsukthe/OpenVAS-Vulnerability-Assessment---Incident-Response) :  ![starts](https://img.shields.io/github/stars/nitinsukthe/OpenVAS-Vulnerability-Assessment---Incident-Response.svg) ![forks](https://img.shields.io/github/forks/nitinsukthe/OpenVAS-Vulnerability-Assessment---Incident-Response.svg)

