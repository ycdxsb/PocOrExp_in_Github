# Update 2026-10-14
## CVE-2026-108269
 Remote Attestation TLS Clients provides multi-language utilities for verifying attested TLS connections. Prior to 0.5.0, the Rust and Go RA-TLS challenge verifiers accepted quote ReportData that was bound to the certificate public key and client nonce but not to the active TLS session before permitting application traffic. An attacker who obtained an enclave TLS private key could relay a genuine quote onto another connection, causing the clients to accept an attacker-terminated connection as the attested enclave. This issue is fixed in 0.5.0.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-108268
 Enclave OS Virtual runs container workloads inside confidential virtual machines with end-to-end attestation. Prior to tdx-v0.2.43 and tdx-gpu-v0.6.27, the TDX/GPU RA-TLS certificate issuer placed the certificate public-key hash and client nonce in quote ReportData but omitted a value bound to the active TLS session. An attacker who obtained an enclave TLS private key could relay a genuine quote onto another connection, causing a relying party to accept an attacker-terminated connection as the attested enclave. This issue is fixed in tdx-v0.2.43 and tdx-gpu-v0.6.27.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-108267
 Privasys Go is a maintained fork of the Go programming language that adds RA-TLS support to crypto/tls. Prior to privasys-v0.5.1-go1.26.5, challenge-mode RA-TLS certificates bound quote ReportData to the certificate public key and client nonce but not to the active TLS session. An attacker who obtained an enclave TLS private key could relay a genuine quote onto another connection, causing a relying party to accept a handshake terminated by the attacker as an attested enclave connection. This issue is fixed in privasys-v0.5.1-go1.26.5.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-108266
 Privasys rustls is a maintained fork of the rustls TLS library that adds RA-TLS challenge and channel-binding support. Prior to privasys-v0.8.1, the fork emitted RA-TLS challenge certificates whose quote ReportData was bound to the certificate public key and client nonce but not to the active TLS session. An attacker who obtained an enclave TLS private key could relay a genuine quote onto another connection, causing a relying party to accept an attacker-terminated connection as the attested enclave. This issue is fixed in privasys-v0.8.1.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-108265
 Enclave OS Mini is a Rust-based runtime for confidential applications inside Intel SGX enclaves. Prior to wasm-v0.40.0, the SGX runtime's RA-TLS challenge certificate path placed the certificate public-key hash and client nonce in quote ReportData but omitted a value bound to the active TLS session. An attacker who obtained an enclave TLS private key could relay a genuine quote onto another connection, causing a relying party to accept an attacker-terminated connection as the attested enclave. This issue is fixed in wasm-v0.40.0.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-104084
 SmarterMail before build 9777 contains a privilege escalation vulnerability where JWT access and refresh tokens embed a role claim at issuance that is not revalidated against the account's current role when redeemed through POST /api/v1/auth/refresh-token. Attackers who capture a refresh token issued before an administrator demotion, or a demoted user whose session was not actively polling at the time of demotion, can replay the stale token to obtain a new access token retaining the higher-privilege role (such as DomainAdmin or SysAdmin) until natural token expiry.

- [https://github.com/eev4n/smartermail](https://github.com/eev4n/smartermail) :  ![starts](https://img.shields.io/github/stars/eev4n/smartermail.svg) ![forks](https://img.shields.io/github/forks/eev4n/smartermail.svg)


## CVE-2026-104083
 SmarterMail before build 9777 contains a stored mutation cross-site scripting vulnerability that allows remote attackers to inject executable script by placing payloads inside a style element nested within MathML foreign content (mathmtextmglyph), which the custom HTML sanitizer treats as inert CDATA text but browsers reparse as live markup. Attackers can deliver a crafted calendar (iCal) message containing an img src=x onerror=... payload that executes automatically in the recipient's webmail session at /interface/message-iframe when the message is opened, enabling script execution and data exfiltration unconstrained by the interface's permissive Content-Security-Policy.

- [https://github.com/eev4n/smartermail](https://github.com/eev4n/smartermail) :  ![starts](https://img.shields.io/github/stars/eev4n/smartermail.svg) ![forks](https://img.shields.io/github/forks/eev4n/smartermail.svg)


## CVE-2026-104082
 SmarterMail before build 9777 contains a remote code execution vulnerability that allows an attacker holding a SysAdmin-scoped access token to bypass the Volume Mount script-directory containment control by provisioning a new mail domain with an arbitrary FileStore root path inside the trusted Scripts directory via the domain-put endpoint. Attackers can disclose the Scripts path through the AddOrUpdateMount endpoint, clear the upload extension blacklist via the global-mail endpoint, then upload a malicious script through the ordinary mail file-storage upload API so that saving a CommandMount triggers RunScript before validation, resulting in a reverse shell executing as the SmarterMail service account with SYSTEM-level privileges.

- [https://github.com/eev4n/smartermail](https://github.com/eev4n/smartermail) :  ![starts](https://img.shields.io/github/stars/eev4n/smartermail.svg) ![forks](https://img.shields.io/github/forks/eev4n/smartermail.svg)


## CVE-2026-103889
 The 3D Product configurator for WooCommerce plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 2.16.2 via the 'xpv_image' parameter parameter. This is due to missing authentication and nonce checks on the wp_loaded handler combined with no sanitization of the xpv_image POST parameter before it is echoed unescaped into a Dompdf-rendered HTML template with PHP execution enabled. This makes it possible for unauthenticated attackers to execute code on the server. The only nonce and authentication check in the handler is entirely enclosed in a block comment with no replacement, making the endpoint reachable via a single unauthenticated POST to any URL on the site.

- [https://github.com/kayes817/CVE-2026-103889](https://github.com/kayes817/CVE-2026-103889) :  ![starts](https://img.shields.io/github/stars/kayes817/CVE-2026-103889.svg) ![forks](https://img.shields.io/github/forks/kayes817/CVE-2026-103889.svg)


## CVE-2026-102255
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. By abusing this path, a remote unauthenticated attacker could potentially exploit this vulnerability to direct the appliance to issue requests on their behalf and reach internal functionality and perform unauthorized operations.

- [https://github.com/HORKimhab/CVE-2026-102255](https://github.com/HORKimhab/CVE-2026-102255) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-102255.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-102255.svg)
- [https://github.com/techupdate24/sonicwall-sma-1000-cve-2026-102255](https://github.com/techupdate24/sonicwall-sma-1000-cve-2026-102255) :  ![starts](https://img.shields.io/github/stars/techupdate24/sonicwall-sma-1000-cve-2026-102255.svg) ![forks](https://img.shields.io/github/forks/techupdate24/sonicwall-sma-1000-cve-2026-102255.svg)


## CVE-2026-100835
 Contrast before 1.16.0 is susceptible to remote attestation relay attacks. Contrast accepted any TEE attestation report that verified correctly and contained the expected firmware patch levels and software measurements, regardless of which machine produced it, so attestation was not bound to specific, physically trusted hardware. An attacker who can both intercept network traffic between the CLI and the Coordinator (or between the Coordinator and an attested component) and forge reports or extract secrets from any single TEE machine under their physical control can relay such a report to impersonate a Contrast Coordinator or a Contrast workload, defeating identity verification in Contrast's attested TLS (aTLS).

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-100833
 Contrast (edgelesssys/contrast) versions 1.14.0 before 1.23.1 generate runtime policies that fail to detect all container image substitutions. A bad rebase during a Kata Containers update accidentally introduced an `allow_storage` rule that accepts storage entries using the `image_guest_pull` driver without verifying the image digest. An attacker with access to the Kata agent API — for example, a Kubernetes cluster administrator in Contrast's threat model — can therefore substitute a container image with an exploit payload, provided the substituted image satisfies the remaining policy rules, undermining the confidential container's integrity guarantees.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-92956
 vm2 versions 3.10.1 through 3.11.6 contain a sandbox escape reachable from a default `new VM()` sandbox when running on Node.js 26. WebAssembly.compileStreaming and WebAssembly.instantiateStreaming can produce a raw host-realm Promise that rejects with a host-realm error object; by controlling Symbol.species via Promise.prototype.finally, sandbox code receives that raw host error, walks from the host error constructor to the host Function constructor, and recovers the real host `process` object, gaining host Node.js capabilities (e.g. access to host modules such as fs) in the context of the process running the sandbox. No NodeVM, require permission, host object injection, or otherwise unsafe configuration is required. This is a bypass of the fix for GHSA-6j2x-vhqr-qr7q, which removed the JSPI entry points WebAssembly.promising and WebAssembly.Suspending. The issue is fixed in 3.11.7.

- [https://github.com/AraxyAI/CVE-2026-92956__vm2__test__20261012](https://github.com/AraxyAI/CVE-2026-92956__vm2__test__20261012) :  ![starts](https://img.shields.io/github/stars/AraxyAI/CVE-2026-92956__vm2__test__20261012.svg) ![forks](https://img.shields.io/github/forks/AraxyAI/CVE-2026-92956__vm2__test__20261012.svg)


## CVE-2026-91737
 Use after free in PDF in Google Chrome prior to 153.0.8010.47 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/sm1ee/CVE-2026-91737](https://github.com/sm1ee/CVE-2026-91737) :  ![starts](https://img.shields.io/github/stars/sm1ee/CVE-2026-91737.svg) ![forks](https://img.shields.io/github/forks/sm1ee/CVE-2026-91737.svg)


## CVE-2026-91136
 The Divi Plus plugin for WordPress is vulnerable to Arbitrary File Read in versions up to, and including, 2.4.0 via the 'svg_image' parameter of the /wp-json/elicus/v1/dipl-modules/svg-animator REST endpoint. This is due to the endpoint's permission callback (SVGAnimatorController::index_permission) returning true unconditionally combined with insufficient validation of the 'svg_image' input — sanitize_text_field() and esc_html() do not restrict filesystem paths, the file:// stream wrapper, or arbitrary URLs — before it is passed to file_get_contents() (with a wp_remote_get() fallback) and the raw response body is returned in the JSON 'html' field. This makes it possible for unauthenticated attackers to read arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/fl0ydsec/CVE-2026-91136](https://github.com/fl0ydsec/CVE-2026-91136) :  ![starts](https://img.shields.io/github/stars/fl0ydsec/CVE-2026-91136.svg) ![forks](https://img.shields.io/github/forks/fl0ydsec/CVE-2026-91136.svg)


## CVE-2026-85097
 The Bricksforge plugin for WordPress is vulnerable to unauthenticated arbitrary file upload in versions up to, and including, 3.1.8.9. This is due to insufficient validation of the attacker-controlled URL field in the 'temporaryFileUploads' parameter during form submission. An unauthenticated attacker can first obtain a valid nonce via the bricksforge_regenerate_nonce AJAX endpoint, then upload a GIF/PHP polyglot file to the temporary upload directory where MIME type validation is correctly performed. Subsequently, the attacker can submit a form with a crafted 'temporaryFileUploads' parameter where the server-side file path points to the validated GIF file, but the attacker-controlled url field ends with a .php extension. This makes it possible for unauthenticated attackers to upload and execute arbitrary PHP code on the server.

- [https://github.com/tc4dy/CVE-2026-85097-Toolkit](https://github.com/tc4dy/CVE-2026-85097-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-85097-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-85097-Toolkit.svg)


## CVE-2026-84411
 The web management service in affected RouterOS versions contains an integer underflow in its HTTP request body handling that is reachable before authentication. This can be leveraged by an unauthenticated network attacker to achieve arbitrary code execution as root, or to cause a denial of service, using a single crafted request.

- [https://github.com/Apiratchai/CVE-2026-84411-reproduction](https://github.com/Apiratchai/CVE-2026-84411-reproduction) :  ![starts](https://img.shields.io/github/stars/Apiratchai/CVE-2026-84411-reproduction.svg) ![forks](https://img.shields.io/github/forks/Apiratchai/CVE-2026-84411-reproduction.svg)


## CVE-2026-84251
 The click5 CRM add-on to Ninja Forms WordPress plugin through 1.0.1 does not have authorisation and CSRF checks when updating options via a REST endpoint, and does not ensure that the option to be updated belongs to the click5 CRM add-on to Ninja Forms WordPress plugin through 1.0.1. As a result, unauthenticated attackers could change arbitrary blog options, allowing them to create a new administrator account and take over the site.

- [https://github.com/Exploit-Kun/CVE-2026-84251](https://github.com/Exploit-Kun/CVE-2026-84251) :  ![starts](https://img.shields.io/github/stars/Exploit-Kun/CVE-2026-84251.svg) ![forks](https://img.shields.io/github/forks/Exploit-Kun/CVE-2026-84251.svg)


## CVE-2026-79987
 A remote, authenticated, non-admin Craft CMS Control Panel user with only the accessCp permission can execute operating system commands as the PHP web worker.

- [https://github.com/y3g1/CraftCMS-CVE-2026-79987](https://github.com/y3g1/CraftCMS-CVE-2026-79987) :  ![starts](https://img.shields.io/github/stars/y3g1/CraftCMS-CVE-2026-79987.svg) ![forks](https://img.shields.io/github/forks/y3g1/CraftCMS-CVE-2026-79987.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/honghyewon29/CVE-2026-66066](https://github.com/honghyewon29/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/honghyewon29/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/honghyewon29/CVE-2026-66066.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL](https://github.com/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL](https://github.com/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-63030-CVE-2026-60137-WP2SHELL.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/sinhalese-congocopal6379/YellowKey-BitLocker-CVE-2026-45585](https://github.com/sinhalese-congocopal6379/YellowKey-BitLocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/sinhalese-congocopal6379/YellowKey-BitLocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/sinhalese-congocopal6379/YellowKey-BitLocker-CVE-2026-45585.svg)
- [https://github.com/sinhalese-congocopal6379/sinhalese-congocopal6379.github.io](https://github.com/sinhalese-congocopal6379/sinhalese-congocopal6379.github.io) :  ![starts](https://img.shields.io/github/stars/sinhalese-congocopal6379/sinhalese-congocopal6379.github.io.svg) ![forks](https://img.shields.io/github/forks/sinhalese-congocopal6379/sinhalese-congocopal6379.github.io.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/YUE546/IQOO-neo7-ghostlock-43499](https://github.com/YUE546/IQOO-neo7-ghostlock-43499) :  ![starts](https://img.shields.io/github/stars/YUE546/IQOO-neo7-ghostlock-43499.svg) ![forks](https://img.shields.io/github/forks/YUE546/IQOO-neo7-ghostlock-43499.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/pyroceper/copy-fail-CVE-2026-31431](https://github.com/pyroceper/copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pyroceper/copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pyroceper/copy-fail-CVE-2026-31431.svg)


## CVE-2026-13078
 A vulnerability was discovered in MongoDB Server where the server-side MozJS scripting engine unconditionally registered a module loading hook that enables JavaScript calls to read arbitrary files from the host filesystem using the mongod process's privileges. An authenticated user could exploit this through crafted aggregation pipeline commands to read sensitive files accessible to the MongoDB server process.

- [https://github.com/0xad3m/CVE-2026-13078-POC](https://github.com/0xad3m/CVE-2026-13078-POC) :  ![starts](https://img.shields.io/github/stars/0xad3m/CVE-2026-13078-POC.svg) ![forks](https://img.shields.io/github/forks/0xad3m/CVE-2026-13078-POC.svg)


## CVE-2026-10951
 Use after free in Autofill in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xgh0stri13y/CVE-2026-109519](https://github.com/0xgh0stri13y/CVE-2026-109519) :  ![starts](https://img.shields.io/github/stars/0xgh0stri13y/CVE-2026-109519.svg) ![forks](https://img.shields.io/github/forks/0xgh0stri13y/CVE-2026-109519.svg)


## CVE-2026-9586
 An unauthenticated SQL injection vulnerability exists in Sangoma Switchvox SMB Edition 8.3 (104997). The /pa endpoint processes XML content beginning with PolycomIPPhone and directly concatenates the user-controlled PhoneIP value into PostgreSQL queries without sanitization or parameterization. An unauthenticated remote attacker can execute arbitrary SQL statements against the backend PostgreSQL database using a single crafted request, including database operations and remote code execution.

- [https://github.com/fromABUV/CVE-2026-9586_POC_EXPLOIT](https://github.com/fromABUV/CVE-2026-9586_POC_EXPLOIT) :  ![starts](https://img.shields.io/github/stars/fromABUV/CVE-2026-9586_POC_EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/fromABUV/CVE-2026-9586_POC_EXPLOIT.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/Riftweld/langflow-cve-2026-9198](https://github.com/Riftweld/langflow-cve-2026-9198) :  ![starts](https://img.shields.io/github/stars/Riftweld/langflow-cve-2026-9198.svg) ![forks](https://img.shields.io/github/forks/Riftweld/langflow-cve-2026-9198.svg)


## CVE-2026-6475
 Symlink following in PostgreSQL pg_basebackup plain format and in pg_rewind allows an origin superuser to overwrite local files, e.g. /var/lib/postgres/.bashrc, that hijack the operating system account.  It will remain the case that starting the server after these commands implicitly trusts the origin superuser, due to features like shared_preload_libraries.  Hence, the attack has practical implications only if one takes relevant action between these commands and server start, like moving the files to a different VM or snapshotting the VM.  Versions before PostgreSQL 18.4, 17.10, 16.14, 15.18, and 14.23 are affected.

- [https://github.com/abraxas/postgres-basebackup-symlink](https://github.com/abraxas/postgres-basebackup-symlink) :  ![starts](https://img.shields.io/github/stars/abraxas/postgres-basebackup-symlink.svg) ![forks](https://img.shields.io/github/forks/abraxas/postgres-basebackup-symlink.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/ctn-Qvo/CVE-2026-43499-so-build](https://github.com/ctn-Qvo/CVE-2026-43499-so-build) :  ![starts](https://img.shields.io/github/stars/ctn-Qvo/CVE-2026-43499-so-build.svg) ![forks](https://img.shields.io/github/forks/ctn-Qvo/CVE-2026-43499-so-build.svg)


## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.

- [https://github.com/alinpfan/CVE-2026-3888-PoC](https://github.com/alinpfan/CVE-2026-3888-PoC) :  ![starts](https://img.shields.io/github/stars/alinpfan/CVE-2026-3888-PoC.svg) ![forks](https://img.shields.io/github/forks/alinpfan/CVE-2026-3888-PoC.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/l0lsuit/CVE-2025-32432-craftcms-rce](https://github.com/l0lsuit/CVE-2025-32432-craftcms-rce) :  ![starts](https://img.shields.io/github/stars/l0lsuit/CVE-2025-32432-craftcms-rce.svg) ![forks](https://img.shields.io/github/forks/l0lsuit/CVE-2025-32432-craftcms-rce.svg)


## CVE-2025-31324
 SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.

- [https://github.com/harisandhusingh-cmyk/cs50-cve-2025-31324-analysis](https://github.com/harisandhusingh-cmyk/cs50-cve-2025-31324-analysis) :  ![starts](https://img.shields.io/github/stars/harisandhusingh-cmyk/cs50-cve-2025-31324-analysis.svg) ![forks](https://img.shields.io/github/forks/harisandhusingh-cmyk/cs50-cve-2025-31324-analysis.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC](https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg)


## CVE-2025-1122
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.

- [https://github.com/ts2023dev/exploit-docs](https://github.com/ts2023dev/exploit-docs) :  ![starts](https://img.shields.io/github/stars/ts2023dev/exploit-docs.svg) ![forks](https://img.shields.io/github/forks/ts2023dev/exploit-docs.svg)
- [https://github.com/ts2023dev/RMASmoke-v2](https://github.com/ts2023dev/RMASmoke-v2) :  ![starts](https://img.shields.io/github/stars/ts2023dev/RMASmoke-v2.svg) ![forks](https://img.shields.io/github/forks/ts2023dev/RMASmoke-v2.svg)


## CVE-2025-0133
For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.

- [https://github.com/Inteleon404/CVE-2025-0133](https://github.com/Inteleon404/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/Inteleon404/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/Inteleon404/CVE-2025-0133.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/ghs053020-stack/cve-2024-21626](https://github.com/ghs053020-stack/cve-2024-21626) :  ![starts](https://img.shields.io/github/stars/ghs053020-stack/cve-2024-21626.svg) ![forks](https://img.shields.io/github/forks/ghs053020-stack/cve-2024-21626.svg)


## CVE-2021-1905
 Possible use after free due to improper handling of memory mapping of multiple processes simultaneously. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

- [https://github.com/Gonvar/kgsl-1905-msm8953](https://github.com/Gonvar/kgsl-1905-msm8953) :  ![starts](https://img.shields.io/github/stars/Gonvar/kgsl-1905-msm8953.svg) ![forks](https://img.shields.io/github/forks/Gonvar/kgsl-1905-msm8953.svg)


## CVE-2019-5420
 A remote code execution vulnerability in development mode Rails 5.2.2.1, 6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.

- [https://github.com/5t1ck/rails-doubletap-py](https://github.com/5t1ck/rails-doubletap-py) :  ![starts](https://img.shields.io/github/stars/5t1ck/rails-doubletap-py.svg) ![forks](https://img.shields.io/github/forks/5t1ck/rails-doubletap-py.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View 5.2.2.1, 5.1.6.2, 5.0.7.2, 4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/5t1ck/rails-doubletap-py](https://github.com/5t1ck/rails-doubletap-py) :  ![starts](https://img.shields.io/github/stars/5t1ck/rails-doubletap-py.svg) ![forks](https://img.shields.io/github/forks/5t1ck/rails-doubletap-py.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/ddiazcr/home-soc-lab](https://github.com/ddiazcr/home-soc-lab) :  ![starts](https://img.shields.io/github/stars/ddiazcr/home-soc-lab.svg) ![forks](https://img.shields.io/github/forks/ddiazcr/home-soc-lab.svg)

