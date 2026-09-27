# Update 2026-09-27
## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/rafabd1/VectorFreed](https://github.com/rafabd1/VectorFreed) :  ![starts](https://img.shields.io/github/stars/rafabd1/VectorFreed.svg) ![forks](https://img.shields.io/github/forks/rafabd1/VectorFreed.svg)


## CVE-2026-96512
 A flaw was found in sudo. When sudoers rules use NOTBEFORE or NOTAFTER time-based access restrictions with timestamps that omit the trailing 'Z' timezone indicator, the time evaluation relies on the TZ environment variable inherited from the calling user. Because sudo is a setuid-root program, an unprivileged local user can set TZ to an extreme timezone offset to shift the authorization window by up to approximately 25 hours, causing expired rules to be treated as valid. This allows the user to execute commands outside the intended time window. Authentication is not bypassed; only the time-based authorization check is affected.

- [https://github.com/abraxas/CVE-2026-96512](https://github.com/abraxas/CVE-2026-96512) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-96512.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-96512.svg)
- [https://github.com/Ermensonx/sudotimewarp-cve-2026-96512-](https://github.com/Ermensonx/sudotimewarp-cve-2026-96512-) :  ![starts](https://img.shields.io/github/stars/Ermensonx/sudotimewarp-cve-2026-96512-.svg) ![forks](https://img.shields.io/github/forks/Ermensonx/sudotimewarp-cve-2026-96512-.svg)


## CVE-2026-93485
The Unauthenticated Stored XSS vulnerability in the WordPress core can be reproduced on a default WordPress installation. Comment moderation is disabled by default, and the requirement for commenters to have a previously approved comment can be bypassed.

- [https://github.com/DeathShotXD/Comment2Shell](https://github.com/DeathShotXD/Comment2Shell) :  ![starts](https://img.shields.io/github/stars/DeathShotXD/Comment2Shell.svg) ![forks](https://img.shields.io/github/forks/DeathShotXD/Comment2Shell.svg)


## CVE-2026-93399
 The Bookly plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 28.2 via the 'bookly_get_form_id', 'bookly_render_complete', 'bookly_add_to_calendar' and 'bookly_rollback_order' AJAX actions. This is due to the 'bookly_get_form_id' handler blindly storing the attacker-controlled 'order_id' from the submitted form_data into a new booking session, which the 'bookly_render_complete' handler then trusts to look up and return the corresponding Order's secret token without verifying that the current session created that order. This makes it possible for unauthenticated attackers to enumerate sequential order IDs, disclose other customers' order tokens, retrieve calendar/appointment information via 'bookly_add_to_calendar' and permanently delete arbitrary non-completed bookings via 'bookly_rollback_order', which cascade-deletes the customer_appointment and (when no other customers are attached) the underlying appointment.

- [https://github.com/murrez/CVE-2026-93399](https://github.com/murrez/CVE-2026-93399) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-93399.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-93399.svg)


## CVE-2026-89055
 The Customer Reviews for WooCommerce plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 5.120.0. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for unauthenticated attackers to permanently delete arbitrary attachments from the Media Library — including administrator-owned product images, logos, and documents — by injecting their IDs into a review that is later trashed and purged. Exploitation requires a public review-form link (a 13-hex formId distributed to customers via e-mail), which exposes the nonce needed to reach the handler without any WordPress account or session.

- [https://github.com/murrez/CVE-2026-89055](https://github.com/murrez/CVE-2026-89055) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-89055.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-89055.svg)


## CVE-2026-88877
 Traefik is a HTTP reverse proxy and load balancer. In versions = v3.7.0 and = v3.7.11, the Kubernetes ingress-nginx provider mishandles Ingresses that carry both an authentication annotation and the nginx.ingress.kubernetes.io/from-to-www-redirect annotation. For such Ingresses the provider creates an additional 'sibling' router that matches on the host alone, carries only the RedirectRegex middleware, and still points at the parent router's protected backend service. Because RedirectRegex is not a terminal handler, a request its pattern does not match is forwarded to the backend, and because the redirect pattern only accepts a numeric port while Traefik's host matcher canonicalizes the authority via net.SplitHostPort, a request with a non-numeric or empty port (for example 'Host: www.example.com:x') selects the sibling router, misses the redirect, and is proxied to the protected backend with none of the Ingress's annotation-derived middlewares applied. This discards not only authentication (e.g. BasicAuth) but every annotation-derived middleware, including source-IP allowlisting. Traefik v2 and v3 releases before v3.7.0 are not affected. The issue is fixed in v3.7.12.

- [https://github.com/pwnVader/CVE-2026-88877-PoC-pwnVader](https://github.com/pwnVader/CVE-2026-88877-PoC-pwnVader) :  ![starts](https://img.shields.io/github/stars/pwnVader/CVE-2026-88877-PoC-pwnVader.svg) ![forks](https://img.shields.io/github/forks/pwnVader/CVE-2026-88877-PoC-pwnVader.svg)


## CVE-2026-87915
 The Popup Maker – Boost Sales, Conversions, Optins, Subscribers with the Ultimate WP Popup Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via values[Name] Parameter in all versions up to, and including, 1.24.0 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. The wp_kses sanitization applied on output is insufficient in this context because HTML entities within allowed attribute values survive normalization intact and are later evaluated by the jQuery(link.attr('href')) sink in wp-admin/js/common.js when a contextual help tab anchor is clicked.

- [https://github.com/pwnVader/CVE-2026-87915-PoC-pwnVader](https://github.com/pwnVader/CVE-2026-87915-PoC-pwnVader) :  ![starts](https://img.shields.io/github/stars/pwnVader/CVE-2026-87915-PoC-pwnVader.svg) ![forks](https://img.shields.io/github/forks/pwnVader/CVE-2026-87915-PoC-pwnVader.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/crowsec-edtech/CVE-2026-87902](https://github.com/crowsec-edtech/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/crowsec-edtech/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/crowsec-edtech/CVE-2026-87902.svg)
- [https://github.com/SVTagan/WP-CVE-2026-87902](https://github.com/SVTagan/WP-CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/SVTagan/WP-CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/SVTagan/WP-CVE-2026-87902.svg)
- [https://github.com/pwnVader/CVE-2026-87902-PoC-pwnVader](https://github.com/pwnVader/CVE-2026-87902-PoC-pwnVader) :  ![starts](https://img.shields.io/github/stars/pwnVader/CVE-2026-87902-PoC-pwnVader.svg) ![forks](https://img.shields.io/github/forks/pwnVader/CVE-2026-87902-PoC-pwnVader.svg)


## CVE-2026-86350
Users are recommended to upgrade to version 11.0.26, 10.1.60 or 9.0.122, which fix the issue.

- [https://github.com/abraxas/CVE-2026-86350](https://github.com/abraxas/CVE-2026-86350) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-86350.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-86350.svg)


## CVE-2026-86060
path involving usernames that begin with a prohibited character, allowing for the trusted RouterOS policy mask to be changed, leading to privilege escalation. Exploitation requires an unauthenticated SSH session to reach the RouterOS login helper.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/gagaltotal/CVE-2026-mikrotik-poc](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-mikrotik-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-mikrotik-poc.svg)


## CVE-2026-67279
 RouterOS SSH enters the connection protocol after a client-requested rekey even though user authentication was never attempted, allowing an unauthenticated client to open a session channel and send an exec request. On affected builds the server dispatches the command, enabling unauthenticated creation, overwrite, and reconstruction of files in the RouterOS managed file namespace, including support files containing configuration and diagnostic data.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/gagaltotal/CVE-2026-mikrotik-poc](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-mikrotik-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-mikrotik-poc.svg)


## CVE-2026-67276
 RouterOS does not compare the complete RSA public key when matching an SSH authentication request to an authorized user key, checking the key type and modulus but omitting the exponent. Because signature verification uses the client-supplied key, an attacker knowing an authorized RSA modulus can supply a key with exponent one, forge a valid signature, and open an SSH command channel as the target user without the private key.This issue affects only 7.x branch was fixed in versions: 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/gagaltotal/CVE-2026-mikrotik-poc](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-mikrotik-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-mikrotik-poc.svg)


## CVE-2026-65660
 Improper control of generation of code ('code injection') in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/ShadowForge-Cyber/CVE-2026-65660-Poc](https://github.com/ShadowForge-Cyber/CVE-2026-65660-Poc) :  ![starts](https://img.shields.io/github/stars/ShadowForge-Cyber/CVE-2026-65660-Poc.svg) ![forks](https://img.shields.io/github/forks/ShadowForge-Cyber/CVE-2026-65660-Poc.svg)
- [https://github.com/HORKimhab/CVE-2026-65660](https://github.com/HORKimhab/CVE-2026-65660) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-65660.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-65660.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/a23bc/op13-cve-2026-64560](https://github.com/a23bc/op13-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/a23bc/op13-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/a23bc/op13-cve-2026-64560.svg)
- [https://github.com/Wangs-official/opace6-cve-2026-64560](https://github.com/Wangs-official/opace6-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/Wangs-official/opace6-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/Wangs-official/opace6-cve-2026-64560.svg)
- [https://github.com/Become-ILLUSORY/cve-2026-64560-a16](https://github.com/Become-ILLUSORY/cve-2026-64560-a16) :  ![starts](https://img.shields.io/github/stars/Become-ILLUSORY/cve-2026-64560-a16.svg) ![forks](https://img.shields.io/github/forks/Become-ILLUSORY/cve-2026-64560-a16.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/z3rodayhacks/CVE-2026-63030-CVE-2026-60137](https://github.com/z3rodayhacks/CVE-2026-63030-CVE-2026-60137) :  ![starts](https://img.shields.io/github/stars/z3rodayhacks/CVE-2026-63030-CVE-2026-60137.svg) ![forks](https://img.shields.io/github/forks/z3rodayhacks/CVE-2026-63030-CVE-2026-60137.svg)


## CVE-2026-62062
This issue affects Elementor Website Builder: from n/a through 4.3.1.

- [https://github.com/abraxas/CVE-2026-62062](https://github.com/abraxas/CVE-2026-62062) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-62062.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-62062.svg)


## CVE-2026-61732
 Decepticon is an autonomous hacking agent for red teams. Versions prior to 1.1.17 wrap web crawl results — the output of agent reconnaissance against target services — into LLM messages without neutralizing ChatML special-token literals. Under the BYOK (Bring Your Own Key) deployment model, users configure their own LLM credentials to any OpenAI-compatible endpoint. Most open-source and self-deployed model providers (vLLM, SGLang, Ollama, LM Studio, text-generation-webui, etc.) do not filter special-token literals from user content in their default configurations. Those literals are parsed into structural role-boundary token IDs, meaning an attacker string planted in a target web page forges a new operator turn the model treats as authoritative, bypassing Decepticon's agent guardrails and resulting in arbitrary command execution inside the Kali Linux sandbox. Version 1.1.17 patches the issue.

- [https://github.com/InertFluid/cve-2026-61732-lab](https://github.com/InertFluid/cve-2026-61732-lab) :  ![starts](https://img.shields.io/github/stars/InertFluid/cve-2026-61732-lab.svg) ![forks](https://img.shields.io/github/forks/InertFluid/cve-2026-61732-lab.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/z3rodayhacks/CVE-2026-63030-CVE-2026-60137](https://github.com/z3rodayhacks/CVE-2026-63030-CVE-2026-60137) :  ![starts](https://img.shields.io/github/stars/z3rodayhacks/CVE-2026-63030-CVE-2026-60137.svg) ![forks](https://img.shields.io/github/forks/z3rodayhacks/CVE-2026-63030-CVE-2026-60137.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/yym8538/CVE-2026-60004](https://github.com/yym8538/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-60004.svg)


## CVE-2026-59310
 VMware vCenter contains a directory traversal vulnerability in the Syslog server. A malicious actor with network access to vCenter may exploit this issue to execute arbitrary code.

- [https://github.com/ChinaRan0/CVE-2026-59310-POC](https://github.com/ChinaRan0/CVE-2026-59310-POC) :  ![starts](https://img.shields.io/github/stars/ChinaRan0/CVE-2026-59310-POC.svg) ![forks](https://img.shields.io/github/forks/ChinaRan0/CVE-2026-59310-POC.svg)


## CVE-2026-53629
 GLPI is a free asset and IT management software package. From 9.4.0 until 10.0.26 and 11.0.8, an attacker with the READ right on logs can craft a URL for the history tab that injects attacker-controlled values into a database query. This permits SQL injection through the history tab endpoint. This issue is fixed in versions 11.0.8 and 10.0.26.

- [https://github.com/5kr1pt/glpi-logbleed](https://github.com/5kr1pt/glpi-logbleed) :  ![starts](https://img.shields.io/github/stars/5kr1pt/glpi-logbleed.svg) ![forks](https://img.shields.io/github/forks/5kr1pt/glpi-logbleed.svg)


## CVE-2026-53625
 GLPI is a free asset and IT management software package. From 0.70 until 10.0.26 and 11.0.8, a technician can manipulate the authtype value through the API to change another user's authentication method. Under configurations using the legacy API REST interface or SSO logins, this can change a super-administrator's authentication method and enable account takeover. This issue is fixed in versions 11.0.8 and 10.0.26.

- [https://github.com/7h30th3r0n3/CVE-2026-53625-GLPI-PoC](https://github.com/7h30th3r0n3/CVE-2026-53625-GLPI-PoC) :  ![starts](https://img.shields.io/github/stars/7h30th3r0n3/CVE-2026-53625-GLPI-PoC.svg) ![forks](https://img.shields.io/github/forks/7h30th3r0n3/CVE-2026-53625-GLPI-PoC.svg)


## CVE-2026-53576
 Kestra is an open-source, event-driven orchestration platform. Prior to 1.0.45 and 1.3.21, the authentication filter for the REST API (@Filter("/api/v1/**")) treats any request whose path ends in /configs as the public instance-config endpoint and forwards it without a credential check. kestra addresses its resources by URL path segments that the caller chooses (/api/v1/{tenant}/flows/{namespace}, /api/v1/{tenant}/executions/{namespace}/{id}, /api/v1/{tenant}/namespaces/{namespace}/kv/{key}). An anonymous caller picks the literal configs as the final segment, and the request bypasses Basic-Auth entirely. Because the bypass reaches the flow-create and execution-trigger routes, an unauthenticated caller creates a flow containing a Shell or Process task and runs it. The task executes as root inside the kestra container. The official docker-compose.yml mounts /var/run/docker.sock, so root in the container reaches the host Docker daemon. This vulnerability is fixed in 1.0.45 and 1.3.21.

- [https://github.com/AtlasVector/Kestra-cve-2026-53576](https://github.com/AtlasVector/Kestra-cve-2026-53576) :  ![starts](https://img.shields.io/github/stars/AtlasVector/Kestra-cve-2026-53576.svg) ![forks](https://img.shields.io/github/forks/AtlasVector/Kestra-cve-2026-53576.svg)


## CVE-2026-51773
 An issue in the VMware datastore driver of OpenStack glance_store. When an authenticated attacker provides a maliciously crafted image location URI pointing to an external server, the _retry_request function fails to validate the destination host before attaching sensitive authentication headers.

- [https://github.com/sadandbset/CVE-2026-51772-CVE-2026-51773](https://github.com/sadandbset/CVE-2026-51772-CVE-2026-51773) :  ![starts](https://img.shields.io/github/stars/sadandbset/CVE-2026-51772-CVE-2026-51773.svg) ![forks](https://img.shields.io/github/forks/sadandbset/CVE-2026-51772-CVE-2026-51773.svg)


## CVE-2026-51772
 A Server-Side Request Forgery (SSRF) vulnerability exists in the Image API (v2) of OpenStack Glance. When the show_multiple_locations configuration option is enabled in glance-api.conf, an authenticated attacker can manipulate the locations attribute of an image in the queued state by sending a crafted HTTP PATCH request

- [https://github.com/sadandbset/CVE-2026-51772-CVE-2026-51773](https://github.com/sadandbset/CVE-2026-51772-CVE-2026-51773) :  ![starts](https://img.shields.io/github/stars/sadandbset/CVE-2026-51772-CVE-2026-51773.svg) ![forks](https://img.shields.io/github/forks/sadandbset/CVE-2026-51772-CVE-2026-51773.svg)


## CVE-2026-49975
This issue affects Apache HTTP Server: from 2.4.17 through 2.4.67.

- [https://github.com/yym8538/CVE-2026-49975](https://github.com/yym8538/CVE-2026-49975) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-49975.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-49975.svg)


## CVE-2026-48842
 Roundcube Webmail 1.6.x before 1.6.16 and 1.7.x before 1.7.1 has Pre-authentication SQL injection in the virtuser_query plugin via a preg_replace() backslash escape bypass.

- [https://github.com/murrez/CVE-2026-48842](https://github.com/murrez/CVE-2026-48842) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-48842.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-48842.svg)


## CVE-2026-46595
 Previously, CVE-2024-45337 fixed an authorization bypass for misused ssh server configurations; if any other type of callback is passed other than public key, then the source-address validation would be skipped.

- [https://github.com/sdodson/CVE-2026-46595-proof](https://github.com/sdodson/CVE-2026-46595-proof) :  ![starts](https://img.shields.io/github/stars/sdodson/CVE-2026-46595-proof.svg) ![forks](https://img.shields.io/github/forks/sdodson/CVE-2026-46595-proof.svg)


## CVE-2026-43687
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27 and iPadOS 27, macOS Golden Gate 27, macOS Tahoe 26.7, tvOS 27, visionOS 27, watchOS 27. Connecting to a malicious NFS server may disclose kernel memory.

- [https://github.com/jvidhan/cve-2026-43687](https://github.com/jvidhan/cve-2026-43687) :  ![starts](https://img.shields.io/github/stars/jvidhan/cve-2026-43687.svg) ![forks](https://img.shields.io/github/forks/jvidhan/cve-2026-43687.svg)


## CVE-2026-40897
 Math.js is an extensive math library for JavaScript and Node.js. From 13.1.1 to before 15.2.0, a vulnerability allowed executing arbitrary JavaScript via the expression parser of mathjs. You can be affected when you have an application where users can evaluate arbitrary expressions using the mathjs expression parser. This vulnerability is fixed in 15.2.0.

- [https://github.com/yym8538/CVE-2026-40897](https://github.com/yym8538/CVE-2026-40897) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-40897.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-40897.svg)


## CVE-2026-34220
 MikroORM is a TypeScript ORM for Node.js based on Data Mapper, Unit of Work and Identity Map patterns. Prior to versions 6.6.10 and 7.0.6, there is a SQL injection vulnerability when specially crafted objects are interpreted as raw SQL query fragments. This issue has been patched in versions 6.6.10 and 7.0.6.

- [https://github.com/yym8538/CVE-2026-34220](https://github.com/yym8538/CVE-2026-34220) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-34220.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-34220.svg)


## CVE-2026-33634
 Trivy is a security scanner. On March 19, 2026, a threat actor used compromised credentials to publish a malicious Trivy v0.69.4 release, force-push 76 of 77 version tags in `aquasecurity/trivy-action` to credential-stealing malware, and replace all 7 tags in `aquasecurity/setup-trivy` with malicious commits. This incident is a continuation of the supply chain attack that began in late February 2026. Following the initial disclosure on March 1, credential rotation was performed but was not atomic (not all credentials were revoked simultaneously). The attacker could have use a valid token to exfiltrate newly rotated secrets during the rotation window (which lasted a few days). This could have allowed the attacker to retain access and execute the March 19 attack. Affected components include the `aquasecurity/trivy` Go / Container image version 0.69.4, the `aquasecurity/trivy-action` GitHub Action versions 0.0.1 – 0.34.2 (76/77), and the`aquasecurity/setup-trivy` GitHub Action versions 0.2.0 – 0.2.6, prior to the recreation of 0.2.6 with a safe commit. Known safe versions include versions 0.69.2 and 0.69.3 of the Trivy binary, version 0.35.0 of trivy-action, and version 0.2.6 of setup-trivy. Additionally, take other mitigations to ensure the safety of secrets. If there is any possibility that a compromised version ran in one's environment, all secrets accessible to affected pipelines must be treated as exposed and rotated immediately. Check whether one's organization pulled or executed Trivy v0.69.4 from any source. Remove any affected artifacts immediately. Review all workflows using `aquasecurity/trivy-action` or `aquasecurity/setup-trivy`. Those who referenced a version tag rather than a full commit SHA should check workflow run logs from March 19–20, 2026 for signs of compromise. Look for repositories named `tpcp-docs` in one's GitHub organization. The presence of such a repository may indicate that the fallback exfiltration mechanism was triggered and secrets were successfully stolen. Pin GitHub Actions to full, immutable commit SHA hashes, don't use mutable version tags.

- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-33634](https://github.com/joaovicdev/EXPLOIT-CVE-2026-33634) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-33634.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-33634.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/yym8538/CVE-2026-33017](https://github.com/yym8538/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-33017.svg)


## CVE-2026-30951
 Sequelize is a Node.js ORM tool. Prior to 6.37.8, there is SQL injection via unescaped cast type in JSON/JSONB where clause processing. The _traverseJSON() function splits JSON path keys on :: to extract a cast type, which is interpolated raw into CAST(... AS type) SQL. An attacker who controls JSON object keys can inject arbitrary SQL and exfiltrate data from any table. This vulnerability is fixed in 6.37.8.

- [https://github.com/yym8538/CVE-2026-30951](https://github.com/yym8538/CVE-2026-30951) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-30951.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-30951.svg)


## CVE-2026-28326
 SolarWinds Access Rights Manager was reported to be affected by an unauthenticated remote code execution vulnerability. The issue stems from a hardcoded static key.

- [https://github.com/BishopFox/CVE-2026-28326-check](https://github.com/BishopFox/CVE-2026-28326-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-28326-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-28326-check.svg)


## CVE-2026-26980
 Ghost is a Node.js content management system. Versions 3.24.0 through 6.19.0 allow unauthenticated attackers to perform arbitrary reads from the database. This issue has been fixed in version 6.19.1.

- [https://github.com/yym8538/CVE-2026-26980](https://github.com/yym8538/CVE-2026-26980) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-26980.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-26980.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/yym8538/CVE-2026-25253](https://github.com/yym8538/CVE-2026-25253) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-25253.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-25253.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/yym8538/CVE-2026-21858](https://github.com/yym8538/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-21858.svg)


## CVE-2026-20896
 Gitea Docker image versions up to and including 1.26.2 use REVERSE_PROXY_TRUSTED_PROXIES=* by default, allowing any source IP to impersonate a user when reverse-proxy authentication headers such as X-WEBAUTH-USER are enabled.

- [https://github.com/yym8538/CVE-2026-20896](https://github.com/yym8538/CVE-2026-20896) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-20896.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-20896.svg)


## CVE-2026-17089
 The Events Manager – Calendar, Bookings, Tickets, and more! plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'header_format' parameter in all versions up to, and including, 7.4.0.1 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link. The shortcode entry point sanitizes 'header_format' via wp_kses(), but the unauthenticated 'search_events_grouped' AJAX action bypasses this sanitization entirely, leaving the parameter unsanitized before it is echoed into the HTML body in output_grouped().

- [https://github.com/pwnVader/CVE-2026-17089-PoC-pwnVader](https://github.com/pwnVader/CVE-2026-17089-PoC-pwnVader) :  ![starts](https://img.shields.io/github/stars/pwnVader/CVE-2026-17089-PoC-pwnVader.svg) ![forks](https://img.shields.io/github/forks/pwnVader/CVE-2026-17089-PoC-pwnVader.svg)


## CVE-2026-16764
 A vulnerability was identified in OWASP DefectDojo 2.59.0. This issue affects the function UserSerializer of the file dojo/api_v2/serializers.py of the component API/Web. Such manipulation of the argument is_staff leads to improper privilege management. The attack may be performed from remote. The exploit is publicly available and might be used. Upgrading to version 2.58.3 and 3.0.0 is capable of addressing this issue. The name of the patch is 68a272f299d096249fd3ba9c2676bf69012857bf. It is advisable to upgrade the affected component. 2.59.0 was not intended to be released and has been removed.

- [https://github.com/hakaioffsec/CVE-2026-16764](https://github.com/hakaioffsec/CVE-2026-16764) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-16764.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-16764.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/yym8538/CVE-2026-16723](https://github.com/yym8538/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-16723.svg)


## CVE-2026-14281
 The Automation Web Platform – Notifications and OTP for WooCommerce, Advanced Country Code plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.8.6. This is due to missing permission enforcement on the publicly accessible REST route `POST /wp-json/wawp/v1/signup/op` and the absence of a key allowlist in the `finish_registration_logic` function, which copies the attacker-controlled `wawp_custom_fields` parameter directly into `update_user_meta()` — allowing sensitive meta keys such as `wp_capabilities` and `wp_user_level` to be set by the caller. This makes it possible for unauthenticated attackers to register a new account with the administrator role and gain full administrative access to the site. When OTP verification is enabled at signup, the OTP session token (`otp_transient`) is returned in plaintext in the HTTP response body, and the `handle_magic_link_request()` handler marks that token as verified on any unauthenticated GET request containing it without ever checking the OTP code value — making the OTP step trivially bypassable with no inbox or SMS access required.

- [https://github.com/murrez/CVE-2026-14281](https://github.com/murrez/CVE-2026-14281) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-14281.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-14281.svg)


## CVE-2026-5430
Successful exploitation of this vulnerability may result in unauthorized access to the system, including the potential compromise of administrative accounts and full account takeover. The CVSS score is adjusted to 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) in single-tenant deployments, reflecting that the impact is contained within a single security authority boundary.

- [https://github.com/abraxas/CVE-2026-5430](https://github.com/abraxas/CVE-2026-5430) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-5430.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-5430.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/yym8538/CVE-2026-5027](https://github.com/yym8538/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-5027.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/RELIHR/CVE-2026-43499](https://github.com/RELIHR/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/RELIHR/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/RELIHR/CVE-2026-43499.svg)
- [https://github.com/AthBe1337/CVE-2026-43499-poc](https://github.com/AthBe1337/CVE-2026-43499-poc) :  ![starts](https://img.shields.io/github/stars/AthBe1337/CVE-2026-43499-poc.svg) ![forks](https://img.shields.io/github/forks/AthBe1337/CVE-2026-43499-poc.svg)


## CVE-2026-0603
 A flaw was found in Hibernate. A remote attacker with low privileges could exploit a second-order SQL injection vulnerability by providing specially crafted, unsanitized non-alphanumeric characters in the ID column when the InlineIdsOrClauseBuilder is used. This could lead to sensitive information disclosure, such as reading system files, and allow for data manipulation or deletion within the application's database, resulting in an application level denial of service.

- [https://github.com/yym8538/CVE-2026-0603](https://github.com/yym8538/CVE-2026-0603) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2026-0603.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2026-0603.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/drcrypterdotru/Apache-GOExploiter](https://github.com/drcrypterdotru/Apache-GOExploiter) :  ![starts](https://img.shields.io/github/stars/drcrypterdotru/Apache-GOExploiter.svg) ![forks](https://img.shields.io/github/forks/drcrypterdotru/Apache-GOExploiter.svg)
- [https://github.com/yym8538/CVE-2025-24813](https://github.com/yym8538/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/yym8538/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/yym8538/CVE-2025-24813.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/mohamedbrek/SOC336-CVE-2025-21298-Investigation](https://github.com/mohamedbrek/SOC336-CVE-2025-21298-Investigation) :  ![starts](https://img.shields.io/github/stars/mohamedbrek/SOC336-CVE-2025-21298-Investigation.svg) ![forks](https://img.shields.io/github/forks/mohamedbrek/SOC336-CVE-2025-21298-Investigation.svg)


## CVE-2025-9974
 The unified WEBUI application of the ONT/Beacon device contains an input handling flaw that allows authenticated users to trigger unintended system-level command execution. Due to insufficient validation of user-supplied data, a low-privileged authenticated attacker may be able to execute arbitrary commands on the underlying ONT/Beacon operating system, potentially impacting the confidentiality, integrity, and availability of the device.

- [https://github.com/HORKimhab/CVE-2025-9974](https://github.com/HORKimhab/CVE-2025-9974) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-9974.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-9974.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-4396
 The Relevanssi – A Better Search plugin for WordPress is vulnerable to time-based SQL Injection via the cats and tags query parameters in all versions up to, and including, 4.24.4 (Free) and = 2.27.5 (Premium) due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries to already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Nefhara/CVE-2025-4396](https://github.com/Nefhara/CVE-2025-4396) :  ![starts](https://img.shields.io/github/stars/Nefhara/CVE-2025-4396.svg) ![forks](https://img.shields.io/github/forks/Nefhara/CVE-2025-4396.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/so1icitx/CVE-2024-25600](https://github.com/so1icitx/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/so1icitx/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/so1icitx/CVE-2024-25600.svg)


## CVE-2024-3651
 A vulnerability was identified in the kjd/idna library, specifically within the `idna.encode()` function, affecting version 3.6. The issue arises from the function's handling of crafted input strings, which can lead to quadratic complexity and consequently, a denial of service condition. This vulnerability is triggered by a crafted input that causes the `idna.encode()` function to process the input with considerable computational load, significantly increasing the processing time in a quadratic manner relative to the input size.

- [https://github.com/redhat-tssc-tmm/CVE-2024-3651-exploit](https://github.com/redhat-tssc-tmm/CVE-2024-3651-exploit) :  ![starts](https://img.shields.io/github/stars/redhat-tssc-tmm/CVE-2024-3651-exploit.svg) ![forks](https://img.shields.io/github/forks/redhat-tssc-tmm/CVE-2024-3651-exploit.svg)


## CVE-2023-25690
Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

- [https://github.com/roshanrajbanshi/cve-2023-25690-smuggler](https://github.com/roshanrajbanshi/cve-2023-25690-smuggler) :  ![starts](https://img.shields.io/github/stars/roshanrajbanshi/cve-2023-25690-smuggler.svg) ![forks](https://img.shields.io/github/forks/roshanrajbanshi/cve-2023-25690-smuggler.svg)


## CVE-2022-26923
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/Nefhara/CVE-2022-26923](https://github.com/Nefhara/CVE-2022-26923) :  ![starts](https://img.shields.io/github/stars/Nefhara/CVE-2022-26923.svg) ![forks](https://img.shields.io/github/forks/Nefhara/CVE-2022-26923.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-](https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-) :  ![starts](https://img.shields.io/github/stars/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg) ![forks](https://img.shields.io/github/forks/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg)
- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-](https://github.com/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-) :  ![starts](https://img.shields.io/github/stars/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-.svg) ![forks](https://img.shields.io/github/forks/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/wvverez/CVE-2020-24186](https://github.com/wvverez/CVE-2020-24186) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2020-24186.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2020-24186.svg)


## CVE-2020-6857
 CarbonFTP v1.4 uses insecure proprietary password encryption with a hard-coded weak encryption key. The key for local FTP server passwords is hard-coded in the binary.

- [https://github.com/Nefhara/CVE-2020-6857](https://github.com/Nefhara/CVE-2020-6857) :  ![starts](https://img.shields.io/github/stars/Nefhara/CVE-2020-6857.svg) ![forks](https://img.shields.io/github/forks/Nefhara/CVE-2020-6857.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/so1icitx/CVE-2019-9053](https://github.com/so1icitx/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/so1icitx/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/so1icitx/CVE-2019-9053.svg)


## CVE-2018-15877
 The Plainview Activity Monitor plugin before 20180826 for WordPress is vulnerable to OS command injection via shell metacharacters in the ip parameter of a wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools request.

- [https://github.com/firasotoom85-droid/wp-plainview-auth-RCE-broken-cookie-to-session-fix](https://github.com/firasotoom85-droid/wp-plainview-auth-RCE-broken-cookie-to-session-fix) :  ![starts](https://img.shields.io/github/stars/firasotoom85-droid/wp-plainview-auth-RCE-broken-cookie-to-session-fix.svg) ![forks](https://img.shields.io/github/forks/firasotoom85-droid/wp-plainview-auth-RCE-broken-cookie-to-session-fix.svg)


## CVE-2018-0202
 clamscan in ClamAV before 0.99.4 contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to improper input validation checking mechanisms when handling Portable Document Format (.pdf) files sent to an affected device. An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted .pdf file to an affected device. This action could cause an out-of-bounds read when ClamAV scans the malicious file, allowing the attacker to cause a DoS condition. This concerns pdf_parse_array and pdf_parse_string in libclamav/pdfng.c. Cisco Bug IDs: CSCvh91380, CSCvh91400.

- [https://github.com/automateforceai/CVE-2018-0202](https://github.com/automateforceai/CVE-2018-0202) :  ![starts](https://img.shields.io/github/stars/automateforceai/CVE-2018-0202.svg) ![forks](https://img.shields.io/github/forks/automateforceai/CVE-2018-0202.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/drcrypterdotru/PHPUnit-GoScan](https://github.com/drcrypterdotru/PHPUnit-GoScan) :  ![starts](https://img.shields.io/github/stars/drcrypterdotru/PHPUnit-GoScan.svg) ![forks](https://img.shields.io/github/forks/drcrypterdotru/PHPUnit-GoScan.svg)


## CVE-2017-3730
 In OpenSSL 1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a DHE or ECDHE key exchange then this can result in the client attempting to dereference a NULL pointer leading to a client crash. This could be exploited in a Denial of Service attack.

- [https://github.com/HavocParasite/CVE-2017-3730](https://github.com/HavocParasite/CVE-2017-3730) :  ![starts](https://img.shields.io/github/stars/HavocParasite/CVE-2017-3730.svg) ![forks](https://img.shields.io/github/forks/HavocParasite/CVE-2017-3730.svg)


## CVE-2012-2459
 Unspecified vulnerability in bitcoind and Bitcoin-Qt before 0.4.6, 0.5.x before 0.5.5, 0.6.0.x before 0.6.0.7, and 0.6.x before 0.6.2 allows remote attackers to cause a denial of service (block-processing outage and incorrect block count) via unknown behavior on a Bitcoin network.

- [https://github.com/condeDeveloper/arvore-merkle](https://github.com/condeDeveloper/arvore-merkle) :  ![starts](https://img.shields.io/github/stars/condeDeveloper/arvore-merkle.svg) ![forks](https://img.shields.io/github/forks/condeDeveloper/arvore-merkle.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/delmag138/NovaShyld_Task_3](https://github.com/delmag138/NovaShyld_Task_3) :  ![starts](https://img.shields.io/github/stars/delmag138/NovaShyld_Task_3.svg) ![forks](https://img.shields.io/github/forks/delmag138/NovaShyld_Task_3.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/rushikesh-a-bhujbal/CVE-2007-2447](https://github.com/rushikesh-a-bhujbal/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/rushikesh-a-bhujbal/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/rushikesh-a-bhujbal/CVE-2007-2447.svg)

