# Update 2026-05-24
## CVE-2026-45584
 Heap-based buffer overflow in Microsoft Defender allows an unauthorized attacker to execute code over a network.

- [https://github.com/96613686/CVE-2026-45584](https://github.com/96613686/CVE-2026-45584) :  ![starts](https://img.shields.io/github/stars/96613686/CVE-2026-45584.svg) ![forks](https://img.shields.io/github/forks/96613686/CVE-2026-45584.svg)


## CVE-2026-45498
 Microsoft Defender Denial of Service Vulnerability

- [https://github.com/ridhinva/defender-vulnerability-scanner](https://github.com/ridhinva/defender-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/defender-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/defender-vulnerability-scanner.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/Koshmare-Blossom/DirtyFrag-go](https://github.com/Koshmare-Blossom/DirtyFrag-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/DirtyFrag-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/DirtyFrag-go.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/0xBlackash/CVE-2026-43494](https://github.com/0xBlackash/CVE-2026-43494) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43494.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43494.svg)
- [https://github.com/Koshmare-Blossom/PinTheft-go](https://github.com/Koshmare-Blossom/PinTheft-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/PinTheft-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/PinTheft-go.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/Koshmare-Blossom/DirtyFrag-go](https://github.com/Koshmare-Blossom/DirtyFrag-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/DirtyFrag-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/DirtyFrag-go.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/F2u0a0d3/CVE-2026-42945-nginx-rift-poc](https://github.com/F2u0a0d3/CVE-2026-42945-nginx-rift-poc) :  ![starts](https://img.shields.io/github/stars/F2u0a0d3/CVE-2026-42945-nginx-rift-poc.svg) ![forks](https://img.shields.io/github/forks/F2u0a0d3/CVE-2026-42945-nginx-rift-poc.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/ridhinva/litellm-scanner](https://github.com/ridhinva/litellm-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/litellm-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/litellm-scanner.svg)


## CVE-2026-41901
 Thymeleaf is a server-side Java template engine for web and standalone environments. Prior to 3.1.5.RELEASE, a security bypass vulnerability exists in the expression execution mechanisms of Thymeleaf. Although the library provides mechanisms to avoid the execution of potentially dangerous expressions in some specific sandboxed (restricted) contexts, it fails to properly neutralize specific constructs that allow this kind of expressions to be executed. If an application developer passes to the template engine unsanitized variables that contain such expressions, and these values are used in sandboxed contexts inside the templates, these expressions can be executed achieving Server-Side Template Injection (SSTI). This vulnerability is fixed in 3.1.5.RELEASE.

- [https://github.com/HORKimhab/CVE-2026-41901](https://github.com/HORKimhab/CVE-2026-41901) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-41901.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-41901.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/ridhinva/defender-vulnerability-scanner](https://github.com/ridhinva/defender-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/defender-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/defender-vulnerability-scanner.svg)


## CVE-2026-40369
 Untrusted pointer dereference in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/piffd0s/ntoskrnl-metadata](https://github.com/piffd0s/ntoskrnl-metadata) :  ![starts](https://img.shields.io/github/stars/piffd0s/ntoskrnl-metadata.svg) ![forks](https://img.shields.io/github/forks/piffd0s/ntoskrnl-metadata.svg)


## CVE-2026-36228
 Buffer Overflow vulnerability in Easy Chat Server 3.1 allows a remote attacker to obtain sensitive information and execute arbitrary code via the chat message functionality

- [https://github.com/NullByte8080/CVE-2026-36228](https://github.com/NullByte8080/CVE-2026-36228) :  ![starts](https://img.shields.io/github/stars/NullByte8080/CVE-2026-36228.svg) ![forks](https://img.shields.io/github/forks/NullByte8080/CVE-2026-36228.svg)


## CVE-2026-36227
 Directory Traversal vulnerability in Easy Chat Server 3.1 allows a remote attacker to obtain sensitive information and execute arbitrary code via the UserName parameter

- [https://github.com/NullByte8080/CVE-2026-36227](https://github.com/NullByte8080/CVE-2026-36227) :  ![starts](https://img.shields.io/github/stars/NullByte8080/CVE-2026-36227.svg) ![forks](https://img.shields.io/github/forks/NullByte8080/CVE-2026-36227.svg)


## CVE-2026-36226
 Cross Site Scripting vulnerability in Advantech WebAccess/SCADA 8.0-2015.08.16 allows a remote attacker to obtain sensitive information via the decryption field in the Create New Project User component

- [https://github.com/NullByte8080/CVE-2026-36226](https://github.com/NullByte8080/CVE-2026-36226) :  ![starts](https://img.shields.io/github/stars/NullByte8080/CVE-2026-36226.svg) ![forks](https://img.shields.io/github/forks/NullByte8080/CVE-2026-36226.svg)


## CVE-2026-34926
This vulnerability is only exploitable on the on-premise version of Apex One and a potential attacker must have access to the Apex One Server and already obtained administrative credentials to the server via some other method to exploit this vulnerability.

- [https://github.com/HORKimhab/CVE-2026-34926](https://github.com/HORKimhab/CVE-2026-34926) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-34926.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-34926.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/r3nsi15/CVE-2026-33017-langflow-rce](https://github.com/r3nsi15/CVE-2026-33017-langflow-rce) :  ![starts](https://img.shields.io/github/stars/r3nsi15/CVE-2026-33017-langflow-rce.svg) ![forks](https://img.shields.io/github/forks/r3nsi15/CVE-2026-33017-langflow-rce.svg)


## CVE-2026-31802
 node-tar is a full-featured Tar for Node.js. Prior to version 7.5.11, tar (npm) can be tricked into creating a symlink that points outside the extraction directory by using a drive-relative symlink target such as C:../../../target.txt, which enables file overwrite outside cwd during normal tar.x() extraction. This vulnerability is fixed in 7.5.11.

- [https://github.com/ridhinva/npm-tar-traversal-scanner](https://github.com/ridhinva/npm-tar-traversal-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/npm-tar-traversal-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/npm-tar-traversal-scanner.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/Koshmare-Blossom/DirtyDecrypt-go](https://github.com/Koshmare-Blossom/DirtyDecrypt-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/DirtyDecrypt-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/DirtyDecrypt-go.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Aurillium/RootRemover](https://github.com/Aurillium/RootRemover) :  ![starts](https://img.shields.io/github/stars/Aurillium/RootRemover.svg) ![forks](https://img.shields.io/github/forks/Aurillium/RootRemover.svg)
- [https://github.com/waltrone1/copyfail-safe-check](https://github.com/waltrone1/copyfail-safe-check) :  ![starts](https://img.shields.io/github/stars/waltrone1/copyfail-safe-check.svg) ![forks](https://img.shields.io/github/forks/waltrone1/copyfail-safe-check.svg)


## CVE-2026-27886
 Strapi is an open source headless content management system. Strapi versions starting in 4.0.0 and prior to 5.37.0 did not sufficiently sanitize query parameters when filtering content via relational fields. An unauthenticated attacker could use the `where` query parameter on any publicly-accessible content-type with an `updatedBy` (or other admin-relation) field to perform a boolean-oracle attack against private fields on the joined `admin_users` table, including the `resetPasswordToken` field. Extracting an admin reset token via this oracle made full administrative account takeover possible without authentication. When a filter such as `where[updatedBy][resetPasswordToken][$startsWith]=a` was applied to a public Content API endpoint, the underlying query generation performed a `LEFT JOIN` against the `admin_users` table and emitted a `WHERE` clause referencing the joined column. The query parameter sanitization layer did not block operator chains that traversed into relational target schemas the caller had no read permission on, allowing the response count to be used as a one-bit oracle on any admin-table field. The patch in version 5.37.0 introduces explicit query-parameter sanitization at the controller and service boundary via three new primitives: `strictParam`, `addQueryParams`, and `addBodyParams`. Operator chains that traverse into restricted relational targets are now rejected before reaching the database.

- [https://github.com/BishopFox/CVE-2026-27886-check](https://github.com/BishopFox/CVE-2026-27886-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-27886-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-27886-check.svg)


## CVE-2026-20223
This vulnerability is due to insufficient validation and authentication when accessing REST API endpoints. An attacker could exploit this vulnerability if they are able to send a crafted API request to an affected endpoint. A successful exploit could allow the attacker to read sensitive information and make configuration changes across tenant boundaries with the privileges of the&nbsp;Site Admin user.&nbsp;

- [https://github.com/HORKimhab/CVE-2026-20223](https://github.com/HORKimhab/CVE-2026-20223) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-20223.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-20223.svg)


## CVE-2026-20182
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to the affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.

- [https://github.com/portbuster1337/CVE-2026-20182](https://github.com/portbuster1337/CVE-2026-20182) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-20182.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-20182.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/ridhinva/CVE-2026-9082](https://github.com/ridhinva/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/ridhinva/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/ridhinva/CVE-2026-9082.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/x48ps/CVE-2026-8181](https://github.com/x48ps/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/x48ps/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/x48ps/CVE-2026-8181.svg)
- [https://github.com/Yucaerin/CVE-2026-8181](https://github.com/Yucaerin/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2026-8181.svg)
- [https://github.com/BastianXploited/CVE-2026-8181-mass](https://github.com/BastianXploited/CVE-2026-8181-mass) :  ![starts](https://img.shields.io/github/stars/BastianXploited/CVE-2026-8181-mass.svg) ![forks](https://img.shields.io/github/forks/BastianXploited/CVE-2026-8181-mass.svg)


## CVE-2026-5843
Any container on the Docker network can trigger this by calling the model-runner.docker.internal API to pull a malicious model from an attacker-controlled OCI registry and request inference.

- [https://github.com/davidrxchester/CVE-2026-5843](https://github.com/davidrxchester/CVE-2026-5843) :  ![starts](https://img.shields.io/github/stars/davidrxchester/CVE-2026-5843.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/CVE-2026-5843.svg)


## CVE-2026-5817
Any container on the Docker network can trigger this by calling the model-runner.docker.internal API to pull a malicious model and request inference.

- [https://github.com/gouldnicholas/CVE-2026-5817-PoC](https://github.com/gouldnicholas/CVE-2026-5817-PoC) :  ![starts](https://img.shields.io/github/stars/gouldnicholas/CVE-2026-5817-PoC.svg) ![forks](https://img.shields.io/github/forks/gouldnicholas/CVE-2026-5817-PoC.svg)


## CVE-2026-5281
 Use after free in Dawn in Google Chrome prior to 146.0.7680.178 allowed a remote attacker who had compromised the renderer process to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/anansi2safe/CVE-2026-5281](https://github.com/anansi2safe/CVE-2026-5281) :  ![starts](https://img.shields.io/github/stars/anansi2safe/CVE-2026-5281.svg) ![forks](https://img.shields.io/github/forks/anansi2safe/CVE-2026-5281.svg)


## CVE-2026-5118
 The Divi Form Builder plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 5.1.2. This is due to the plugin accepting a user-controlled 'role' parameter from POST data during user registration without validating it against the form's configured default_user_role setting. This makes it possible for unauthenticated attackers to create administrator accounts by tampering with the role parameter during registration.

- [https://github.com/Yucaerin/CVE-2026-5118](https://github.com/Yucaerin/CVE-2026-5118) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2026-5118.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2026-5118.svg)


## CVE-2026-3854
 An improper neutralization of special elements vulnerability was identified in GitHub Enterprise Server that allowed an attacker with push access to a repository to achieve remote code execution on the instance. During a git push operation, user-supplied push option values were not properly sanitized before being included in internal service headers. Because the internal header format used a delimiter character that could also appear in user input, an attacker could inject additional metadata fields through crafted push option values. This vulnerability was reported via the GitHub Bug Bounty program and has been fixed in GitHub Enterprise Server versions 3.14.25, 3.15.20, 3.16.16, 3.17.13, 3.18.7 and 3.19.4.

- [https://github.com/ridhinva/CVE-2026-3854-GHE-RCE](https://github.com/ridhinva/CVE-2026-3854-GHE-RCE) :  ![starts](https://img.shields.io/github/stars/ridhinva/CVE-2026-3854-GHE-RCE.svg) ![forks](https://img.shields.io/github/forks/ridhinva/CVE-2026-3854-GHE-RCE.svg)


## CVE-2026-3102
 A vulnerability was determined in exiftool up to 13.49 on macOS. This issue affects the function SetMacOSTags of the file lib/Image/ExifTool/MacOS.pm of the component PNG File Parser. This manipulation of the argument DateTimeOriginal causes os command injection. The attack is possible to be carried out remotely. The exploit has been publicly disclosed and may be utilized. Upgrading to version 13.50 is capable of addressing this issue. Patch name: e9609a9bcc0d32bd252a709a562fb822d6dd86f7. Upgrading the affected component is recommended.

- [https://github.com/HORKimhab/CVE-2026-3102](https://github.com/HORKimhab/CVE-2026-3102) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-3102.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-3102.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/ridhinva/CVE-2026-1731-BeyondTrust-RCE](https://github.com/ridhinva/CVE-2026-1731-BeyondTrust-RCE) :  ![starts](https://img.shields.io/github/stars/ridhinva/CVE-2026-1731-BeyondTrust-RCE.svg) ![forks](https://img.shields.io/github/forks/ridhinva/CVE-2026-1731-BeyondTrust-RCE.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/ridhinva/CVE-2026-0300-PANOS-RCE](https://github.com/ridhinva/CVE-2026-0300-PANOS-RCE) :  ![starts](https://img.shields.io/github/stars/ridhinva/CVE-2026-0300-PANOS-RCE.svg) ![forks](https://img.shields.io/github/forks/ridhinva/CVE-2026-0300-PANOS-RCE.svg)


## CVE-2026-0265
Cloud NGFW and Prisma Access® are not impacted by this vulnerability.

- [https://github.com/BishopFox/CVE-2026-0265-check](https://github.com/BishopFox/CVE-2026-0265-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-0265-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-0265-check.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/ridhinva/CVE-2026-0073-ADBD-Bypass](https://github.com/ridhinva/CVE-2026-0073-ADBD-Bypass) :  ![starts](https://img.shields.io/github/stars/ridhinva/CVE-2026-0073-ADBD-Bypass.svg) ![forks](https://img.shields.io/github/forks/ridhinva/CVE-2026-0073-ADBD-Bypass.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/Lennonxlz/react2shell-ultimate](https://github.com/Lennonxlz/react2shell-ultimate) :  ![starts](https://img.shields.io/github/stars/Lennonxlz/react2shell-ultimate.svg) ![forks](https://img.shields.io/github/forks/Lennonxlz/react2shell-ultimate.svg)


## CVE-2025-55423
 A command injection vulnerability exists in the upnp_relay() function in multiple ipTIME router models because the controlURL value used to pass port-forwarding information to an upper router is passed to system() without proper validation or sanitization, allowing OS command injection.

- [https://github.com/logis11/CVE-2025-55423-analysis-and-reproduction](https://github.com/logis11/CVE-2025-55423-analysis-and-reproduction) :  ![starts](https://img.shields.io/github/stars/logis11/CVE-2025-55423-analysis-and-reproduction.svg) ![forks](https://img.shields.io/github/forks/logis11/CVE-2025-55423-analysis-and-reproduction.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/VeilVulp/RscScan-cve-2025-55182](https://github.com/VeilVulp/RscScan-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/VeilVulp/RscScan-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/VeilVulp/RscScan-cve-2025-55182.svg)


## CVE-2025-50165
 Untrusted pointer dereference in Microsoft Graphics Component allows an unauthorized attacker to execute code over a network.

- [https://github.com/FelineKeeper/CVE-2025-50165-Windows-Graphics-Component-RCE](https://github.com/FelineKeeper/CVE-2025-50165-Windows-Graphics-Component-RCE) :  ![starts](https://img.shields.io/github/stars/FelineKeeper/CVE-2025-50165-Windows-Graphics-Component-RCE.svg) ![forks](https://img.shields.io/github/forks/FelineKeeper/CVE-2025-50165-Windows-Graphics-Component-RCE.svg)


## CVE-2025-46822
 OsamaTaher/Java-springboot-codebase is a collection of Java and Spring Boot code snippets, applications, and projects. Prior to commit c835c6f7799eacada4c0fc77e0816f250af01ad2, insufficient path traversal mechanisms make absolute path traversal possible. This vulnerability allows unauthorized access to sensitive internal files. Commit c835c6f7799eacada4c0fc77e0816f250af01ad2 contains a patch for the issue.

- [https://github.com/HORKimhab/CVE-2025-46822](https://github.com/HORKimhab/CVE-2025-46822) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-46822.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-46822.svg)


## CVE-2025-34291
 Langflow versions up to and including 1.6.9 contain a chained vulnerability that enables account takeover and remote code execution. An overly permissive CORS configuration (allow_origins='*' with allow_credentials=True) combined with a refresh token cookie configured as SameSite=None allows a malicious webpage to perform cross-origin requests that include credentials and successfully call the refresh endpoint. An attacker-controlled origin can therefore obtain fresh access_token / refresh_token pairs for a victim session. Obtained tokens permit access to authenticated endpoints — including built-in code-execution functionality — allowing the attacker to execute arbitrary code and achieve full system compromise.

- [https://github.com/ridhinva/CVE-2025-34291-Langflow-Scanner](https://github.com/ridhinva/CVE-2025-34291-Langflow-Scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/CVE-2025-34291-Langflow-Scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/CVE-2025-34291-Langflow-Scanner.svg)


## CVE-2024-12537
 In version 0.3.32 of open-webui/open-webui, the absence of authentication mechanisms allows any unauthenticated attacker to access the `api/v1/utils/code/format` endpoint. If a malicious actor sends a POST request with an excessively high volume of content, the server could become completely unresponsive. This could lead to severe performance issues, causing the server to become unresponsive or experience significant degradation, ultimately resulting in service interruptions for legitimate users.

- [https://github.com/fineman999/POC_CVE-2024-12537](https://github.com/fineman999/POC_CVE-2024-12537) :  ![starts](https://img.shields.io/github/stars/fineman999/POC_CVE-2024-12537.svg) ![forks](https://img.shields.io/github/forks/fineman999/POC_CVE-2024-12537.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/vuducmanhno100-cloud/CVE-2024-6387](https://github.com/vuducmanhno100-cloud/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/vuducmanhno100-cloud/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/vuducmanhno100-cloud/CVE-2024-6387.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/OpsCipher/CVE-2022-0543](https://github.com/OpsCipher/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/OpsCipher/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/OpsCipher/CVE-2022-0543.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/jyothsna-Git007/CMS-Made-Simple-2.2.10---SQL-Injection](https://github.com/jyothsna-Git007/CMS-Made-Simple-2.2.10---SQL-Injection) :  ![starts](https://img.shields.io/github/stars/jyothsna-Git007/CMS-Made-Simple-2.2.10---SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/jyothsna-Git007/CMS-Made-Simple-2.2.10---SQL-Injection.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/shadowedcreds/CVE-2019-6447](https://github.com/shadowedcreds/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/shadowedcreds/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/shadowedcreds/CVE-2019-6447.svg)


## CVE-2018-13379
 An Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.

- [https://github.com/Instructor-Admin/Multi-threaded-mass-exploiter-CVE-2018-13379-POC](https://github.com/Instructor-Admin/Multi-threaded-mass-exploiter-CVE-2018-13379-POC) :  ![starts](https://img.shields.io/github/stars/Instructor-Admin/Multi-threaded-mass-exploiter-CVE-2018-13379-POC.svg) ![forks](https://img.shields.io/github/forks/Instructor-Admin/Multi-threaded-mass-exploiter-CVE-2018-13379-POC.svg)

