# Update 2026-07-15
## CVE-2026-57830
 The Joomla extension Helix Ultimate is vulnerable to an unauthenticated arbitrary file deletion.

- [https://github.com/Is4yev/CVE-2026-57830](https://github.com/Is4yev/CVE-2026-57830) :  ![starts](https://img.shields.io/github/stars/Is4yev/CVE-2026-57830.svg) ![forks](https://img.shields.io/github/forks/Is4yev/CVE-2026-57830.svg)


## CVE-2026-57829
 The Joomla extension Helix Ultimate is vulnerable to an unauthenticated stored XSS.

- [https://github.com/Is4yev/CVE-2026-57829](https://github.com/Is4yev/CVE-2026-57829) :  ![starts](https://img.shields.io/github/stars/Is4yev/CVE-2026-57829.svg) ![forks](https://img.shields.io/github/forks/Is4yev/CVE-2026-57829.svg)


## CVE-2026-56291
 The Joomla extension Balbooa Forms is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/0xdenis77/CVE-2026-56291](https://github.com/0xdenis77/CVE-2026-56291) :  ![starts](https://img.shields.io/github/stars/0xdenis77/CVE-2026-56291.svg) ![forks](https://img.shields.io/github/forks/0xdenis77/CVE-2026-56291.svg)
- [https://github.com/shinthink/CVE-2026-56291](https://github.com/shinthink/CVE-2026-56291) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-56291.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-56291.svg)
- [https://github.com/rimbadirgantara/CVE-2026-56291.yaml](https://github.com/rimbadirgantara/CVE-2026-56291.yaml) :  ![starts](https://img.shields.io/github/stars/rimbadirgantara/CVE-2026-56291.yaml.svg) ![forks](https://img.shields.io/github/forks/rimbadirgantara/CVE-2026-56291.yaml.svg)


## CVE-2026-53805
 NVIDIA Spatial Intelligence Lab's (SIL) GEN3C contains an unauthenticated remote code execution vulnerability in the inference API server where the /request-inference and /seed-model endpoints deserialize raw HTTP request bodies using Python's pickle.loads() without authentication or input validation. Attackers can supply a crafted payload containing a __reduce__ gadget to the inference API port to achieve remote code execution as the inference process.

- [https://github.com/HORKimhab/CVE-2026-53805](https://github.com/HORKimhab/CVE-2026-53805) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-53805.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-53805.svg)


## CVE-2026-49049
 The Helix3 plugin for Joomla exposes an ajax handler task, that allows unauthenticated attackers to delete arbitrary files, write arbitrary JSON files and update template parameters.

- [https://github.com/ExDev994/CVE-2026-49049](https://github.com/ExDev994/CVE-2026-49049) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-49049.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-49049.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/amnsecurity/CVE-2026-48907-Joomla-JCE-RCE](https://github.com/amnsecurity/CVE-2026-48907-Joomla-JCE-RCE) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2026-48907-Joomla-JCE-RCE.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2026-48907-Joomla-JCE-RCE.svg)


## CVE-2026-46529
 Atril Document Viewer is the default document reader of the MATE desktop environment for Linux. A single-click remote code execution vulnerability in versions prior to 1.26.3 and 1.28.4 allows an attacker to achieve arbitrary code execution as the user by tricking them into clicking a link inside a malicious PDF document. The PDF can be packaged as a polyglot file that is simultaneously a valid PDF and a valid ELF shared library, making the attack a single-file, single-click, configuration-independent RCE on stock atril installations. The root cause is `shell/ev-application.c:ev_spawn`, which builds a command line from attacker-controlled PDF link-destination fields without applying `g_shell_quote`. The cmdline is then handed to `g_app_info_create_from_commandline`, which shell-parses it back into argv — splitting any embedded `--gtk-module=PATH` into a separate argv element. GTK then `dlopen()`s the path during init, running any `__attribute__((constructor))` it finds. Versions 1.26.3 and 1.28.4 contain a patch for the issue. This is the same defect class as CVE-2023-51698 (CBT `--checkpoint-action` injection in `comics-document.c`, fixed in 1.6.2) but in a different code path (`shell/ev-application.c`) that the original patch did not touch.

- [https://github.com/amnsecurity/CVE-2026-46529-Atril-PDF-RCE](https://github.com/amnsecurity/CVE-2026-46529-Atril-PDF-RCE) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2026-46529-Atril-PDF-RCE.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2026-46529-Atril-PDF-RCE.svg)


## CVE-2026-46456
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix adds an inbound HeaderFilterStrategy rule to Sqs2HeaderFilterStrategy that filters the Camel header namespace case-insensitively on inbound mapping, so sender-supplied Camel* / camel* headers are no longer copied into the Exchange. For deployments that cannot upgrade immediately, strip the Camel control headers from inbound messages before they reach any downstream producer (for example removeHeaders('Camel*') and removeHeaders('camel*') at the start of the route), and restrict who may send to the consumed SQS queue by applying least-privilege sqs:SendMessage permissions on the queue resource policy.

- [https://github.com/oscerd/CVE-2026-46456](https://github.com/oscerd/CVE-2026-46456) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46456.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46456.svg)


## CVE-2026-46455
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix makes KeycloakSecurityHelper.parseAndVerifyAccessToken include the TokenVerifier.IS_ACTIVE check so that expired or not-yet-valid access tokens are rejected, aligning the helper with Keycloak's default check set. For deployments that cannot upgrade immediately, enforce token expiration outside the helper - for example validate the access token's exp/nbf claims in the route before trusting it, keep Keycloak access-token lifetimes short, and ensure any upstream gateway or resource server also validates the token validity window.

- [https://github.com/oscerd/CVE-2026-46455](https://github.com/oscerd/CVE-2026-46455) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46455.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46455.svg)


## CVE-2026-46454
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix implements a HeaderFilterStrategy in the camel-cometd binding (a long-standing TODO in the code) that filters the Camel header namespace case-insensitively on inbound mapping, so client-supplied Camel* / camel* headers are no longer copied into the Exchange. For deployments that cannot upgrade immediately, strip the Camel control headers from inbound CometD messages before they reach any downstream producer (for example removeHeaders('Camel*') and removeHeaders('camel*') at the start of the route), and install an explicit Bayeux SecurityPolicy on the CometdComponent so that only authenticated clients can publish.

- [https://github.com/oscerd/CVE-2026-46454](https://github.com/oscerd/CVE-2026-46454) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46454.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46454.svg)


## CVE-2026-46453
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix renames the camel-elasticsearch-rest-client Exchange header constant string values (ID, SEARCH_QUERY, INDEX_SETTINGS, INDEX_NAME, OPERATION) to carry the Camel prefix (CamelElasticsearchId, CamelElasticsearchSearchQuery, CamelElasticsearchIndexSettings, CamelElasticsearchIndexName, CamelElasticsearchOperation) so that they are blocked by the inbound HttpHeaderFilterStrategy; the Java field names are unchanged. For deployments that cannot upgrade immediately, strip the affected headers from untrusted inbound messages before they reach the producer (for example removeHeader('SEARCH_QUERY'), removeHeader('OPERATION'), removeHeader('INDEX_NAME'), removeHeader('INDEX_SETTINGS') and removeHeader('ID') in front of the elasticsearch-rest-client endpoint), or apply a custom HeaderFilterStrategy that blocks these names.

- [https://github.com/oscerd/CVE-2026-46453](https://github.com/oscerd/CVE-2026-46453) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46453.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46453.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/First-John/cve_2026_frag_family_fix](https://github.com/First-John/cve_2026_frag_family_fix) :  ![starts](https://img.shields.io/github/stars/First-John/cve_2026_frag_family_fix.svg) ![forks](https://img.shields.io/github/forks/First-John/cve_2026_frag_family_fix.svg)


## CVE-2026-43867
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.18.x LTS releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, restrict write access to the AWS Secrets Manager secret that holds the camel-pqc key metadata so that only the application’s own identity holds secretsmanager:PutSecretValue on it (least-privilege IAM), and keep the PQC key material in a secret separate from any data that less-trusted principals can write.

- [https://github.com/oscerd/CVE-2026-43867](https://github.com/oscerd/CVE-2026-43867) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-43867.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-43867.svg)


## CVE-2026-43724
 The issue was addressed with improved input sanitization. This issue is fixed in iOS 26.5.2 and iPadOS 26.5.2, macOS Tahoe 26.5.2. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/impost0r/Rie](https://github.com/impost0r/Rie) :  ![starts](https://img.shields.io/github/stars/impost0r/Rie.svg) ![forks](https://img.shields.io/github/forks/impost0r/Rie.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/First-John/cve_2026_frag_family_fix](https://github.com/First-John/cve_2026_frag_family_fix) :  ![starts](https://img.shields.io/github/stars/First-John/cve_2026_frag_family_fix.svg) ![forks](https://img.shields.io/github/forks/First-John/cve_2026_frag_family_fix.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Yakayna/SpringPeace](https://github.com/Yakayna/SpringPeace) :  ![starts](https://img.shields.io/github/stars/Yakayna/SpringPeace.svg) ![forks](https://img.shields.io/github/forks/Yakayna/SpringPeace.svg)
- [https://github.com/CakesTwix/Android-CVE-2026-43499](https://github.com/CakesTwix/Android-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/CakesTwix/Android-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CakesTwix/Android-CVE-2026-43499.svg)
- [https://github.com/Bartixxx32/CVE-2026-43499-OnePlus15](https://github.com/Bartixxx32/CVE-2026-43499-OnePlus15) :  ![starts](https://img.shields.io/github/stars/Bartixxx32/CVE-2026-43499-OnePlus15.svg) ![forks](https://img.shields.io/github/forks/Bartixxx32/CVE-2026-43499-OnePlus15.svg)
- [https://github.com/Thiasap/oppo-pgem10-ghostlock](https://github.com/Thiasap/oppo-pgem10-ghostlock) :  ![starts](https://img.shields.io/github/stars/Thiasap/oppo-pgem10-ghostlock.svg) ![forks](https://img.shields.io/github/forks/Thiasap/oppo-pgem10-ghostlock.svg)
- [https://github.com/joehquak/Mi8E5-Unlocker-by-CVE-2026-43499](https://github.com/joehquak/Mi8E5-Unlocker-by-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/joehquak/Mi8E5-Unlocker-by-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/joehquak/Mi8E5-Unlocker-by-CVE-2026-43499.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/First-John/cve_2026_frag_family_fix](https://github.com/First-John/cve_2026_frag_family_fix) :  ![starts](https://img.shields.io/github/stars/First-John/cve_2026_frag_family_fix.svg) ![forks](https://img.shields.io/github/forks/First-John/cve_2026_frag_family_fix.svg)


## CVE-2026-40047
Users are recommended to upgrade to a release that contains the CAMEL-23212 fix. On the mainline the fix is included from Apache Camel 4.19.0 (and later releases such as 4.20.0). For users on the 4.18.x LTS releases stream, upgrade to 4.18.3. The fix replaces the denylist with a strict allowlist of recognized `docling` CLI flags (rejecting any unrecognized flag, and rejecting producer-managed flags such as the output-directory flags), defensively rejects shell metacharacters in argument values, and normalizes path-like values with Path.normalize() before validating them so that traversal sequences which bypass a literal `../` check are detected. As defence in depth, route authors should avoid mapping untrusted message content into the `CamelDoclingCustomArguments` header and the path-bearing headers, and should strip Camel-internal headers from messages that arrive from untrusted producers.

- [https://github.com/amnsecurity/CVE-2026-40047-Apache-Camel-Docling-Injection](https://github.com/amnsecurity/CVE-2026-40047-Apache-Camel-Docling-Injection) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2026-40047-Apache-Camel-Docling-Injection.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2026-40047-Apache-Camel-Docling-Injection.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/Qurclinc/CVE-2026-38526](https://github.com/Qurclinc/CVE-2026-38526) :  ![starts](https://img.shields.io/github/stars/Qurclinc/CVE-2026-38526.svg) ![forks](https://img.shields.io/github/forks/Qurclinc/CVE-2026-38526.svg)
- [https://github.com/CerberusMrXi/KrayinCRM-RCE-Exploit-CVE-2026-38526](https://github.com/CerberusMrXi/KrayinCRM-RCE-Exploit-CVE-2026-38526) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/KrayinCRM-RCE-Exploit-CVE-2026-38526.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/KrayinCRM-RCE-Exploit-CVE-2026-38526.svg)


## CVE-2026-35204
 Helm is a package manager for Charts for Kubernetes. From 4.0.0 to 4.1.3, a specially crafted Helm plugin, when installed or updated, will cause Helm to write the contents of the plugin to an arbitrary filesystem location. To prevent this, validate that the plugin.yaml of the Helm plugin does not include a version: field containing POSIX dot-dot path separators ie. "/../". This vulnerability is fixed in 4.1.4.

- [https://github.com/amnsecurity/CVE-2026-35204-Helm-Plugin-Traversal](https://github.com/amnsecurity/CVE-2026-35204-Helm-Plugin-Traversal) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2026-35204-Helm-Plugin-Traversal.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2026-35204-Helm-Plugin-Traversal.svg)


## CVE-2026-34048
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to 4.0.0-beta.471, terminal websocket bootstrap routes only check authentication and do not enforce terminal authorization, allowing a low-privileged team member to connect to terminal routes and execute commands on team servers. This issue is fixed in version 4.0.0-beta.471.

- [https://github.com/0xmrma/CVE-2026-34048](https://github.com/0xmrma/CVE-2026-34048) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-34048.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-34048.svg)


## CVE-2026-27495
 n8n is an open source workflow automation platform. Prior to versions 2.10.1, 2.9.3, and 1.123.22, an authenticated user with permission to create or modify workflows could exploit a vulnerability in the JavaScript Task Runner sandbox to execute arbitrary code outside the sandbox boundary. On instances using internal Task Runners (default runner mode), this could result in full compromise of the n8n host. On instances using external Task Runners, the attacker might gain access to or impact other task executed on the Task Runner. Task Runners must be enabled using `N8N_RUNNERS_ENABLED=true`. The issue has been fixed in n8n versions 2.10.1, 2.9.3, and 1.123.22. Users should upgrade to one of these versions or later to remediate the vulnerability. If upgrading is not immediately possible, administrators should consider the following temporary mitigations. Limit workflow creation and editing permissions to fully trusted users only, and/or use external runner mode (`N8N_RUNNERS_MODE=external`) to limit the blast radius. These workarounds do not fully remediate the risk and should only be used as short-term mitigation measures.

- [https://github.com/DexSemon/CVE-2026-27495](https://github.com/DexSemon/CVE-2026-27495) :  ![starts](https://img.shields.io/github/stars/DexSemon/CVE-2026-27495.svg) ![forks](https://img.shields.io/github/forks/DexSemon/CVE-2026-27495.svg)


## CVE-2026-23415
Fix by adding rcu to __mpol_put().

- [https://github.com/addman2/uaf-exploit-cve-2026-23415](https://github.com/addman2/uaf-exploit-cve-2026-23415) :  ![starts](https://img.shields.io/github/stars/addman2/uaf-exploit-cve-2026-23415.svg) ![forks](https://img.shields.io/github/forks/addman2/uaf-exploit-cve-2026-23415.svg)


## CVE-2026-6307
 Type Confusion in Turbofan in Google Chrome prior to 147.0.7727.101 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/amnsecurity/CVE-2026-6307-Chrome-V8-Sandbox-Escape](https://github.com/amnsecurity/CVE-2026-6307-Chrome-V8-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2026-6307-Chrome-V8-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2026-6307-Chrome-V8-Sandbox-Escape.svg)


## CVE-2026-6230
 The Tainacan plugin for WordPress is vulnerable to time-based blind SQL Injection via the 'geoquery' parameter in all versions up to and including 1.0.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE](https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE) :  ![starts](https://img.shields.io/github/stars/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg) ![forks](https://img.shields.io/github/forks/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg)


## CVE-2026-5549
 . The attack can be launched remotely. The exploit has been publicly disclosed and may be utilized.

- [https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE](https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE) :  ![starts](https://img.shields.io/github/stars/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg) ![forks](https://img.shields.io/github/forks/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg)


## CVE-2026-5118
 The Divi Form Builder plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 5.1.2. This is due to the plugin accepting a user-controlled 'role' parameter from POST data during user registration without validating it against the form's configured default_user_role setting. This makes it possible for unauthenticated attackers to create administrator accounts by tampering with the role parameter during registration.

- [https://github.com/1beelze/CVE-2026-5118](https://github.com/1beelze/CVE-2026-5118) :  ![starts](https://img.shields.io/github/stars/1beelze/CVE-2026-5118.svg) ![forks](https://img.shields.io/github/forks/1beelze/CVE-2026-5118.svg)


## CVE-2026-3621
 IBM WebSphere Application Server - Liberty 17.0.0.3 through 26.0.0.4 IBM WebSphere Application Server Liberty is vulnerable to identity spoofing under limited conditions when an application is deployed without authentication and authorization configured.

- [https://github.com/amnsecurity/CVE-2026-36214-osTicket-XSS](https://github.com/amnsecurity/CVE-2026-36214-osTicket-XSS) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2026-36214-osTicket-XSS.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2026-36214-osTicket-XSS.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/Saturate/CVE-2025-55182-react2shell](https://github.com/Saturate/CVE-2025-55182-react2shell) :  ![starts](https://img.shields.io/github/stars/Saturate/CVE-2025-55182-react2shell.svg) ![forks](https://img.shields.io/github/forks/Saturate/CVE-2025-55182-react2shell.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/sentinel-aidefense/CVE-2025-33073](https://github.com/sentinel-aidefense/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2025-33073.svg)


## CVE-2025-31207
 A logic issue was addressed with improved checks. This issue is fixed in iOS 18.5 and iPadOS 18.5. An app may be able to enumerate a user's installed apps.

- [https://github.com/iCrazeiOS/AppEnumFix](https://github.com/iCrazeiOS/AppEnumFix) :  ![starts](https://img.shields.io/github/stars/iCrazeiOS/AppEnumFix.svg) ![forks](https://img.shields.io/github/forks/iCrazeiOS/AppEnumFix.svg)


## CVE-2025-21293
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/Dashlane04/threat-simlab](https://github.com/Dashlane04/threat-simlab) :  ![starts](https://img.shields.io/github/stars/Dashlane04/threat-simlab.svg) ![forks](https://img.shields.io/github/forks/Dashlane04/threat-simlab.svg)


## CVE-2024-52046
Note: The FtpServer, SSHd and Vysper sub-project are not affected by this issue.

- [https://github.com/amnsecurity/CVE-2024-52046-Apache-MINA-RCE](https://github.com/amnsecurity/CVE-2024-52046-Apache-MINA-RCE) :  ![starts](https://img.shields.io/github/stars/amnsecurity/CVE-2024-52046-Apache-MINA-RCE.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/CVE-2024-52046-Apache-MINA-RCE.svg)


## CVE-2024-40453
 squirrellyjs squirrelly v9.0.0 and fixed in v.9.0.1 was discovered to contain a code injection vulnerability via the component options.varName.

- [https://github.com/surajpandeyp/CVE-2024-40453](https://github.com/surajpandeyp/CVE-2024-40453) :  ![starts](https://img.shields.io/github/stars/surajpandeyp/CVE-2024-40453.svg) ![forks](https://img.shields.io/github/forks/surajpandeyp/CVE-2024-40453.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/Kushiro45/metabase-cve-2023-38646](https://github.com/Kushiro45/metabase-cve-2023-38646) :  ![starts](https://img.shields.io/github/stars/Kushiro45/metabase-cve-2023-38646.svg) ![forks](https://img.shields.io/github/forks/Kushiro45/metabase-cve-2023-38646.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/AdityaBhatt3010/Room-Walkthrough-Billing](https://github.com/AdityaBhatt3010/Room-Walkthrough-Billing) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/Room-Walkthrough-Billing.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/Room-Walkthrough-Billing.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols.  CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/Giangdurian/CVE-2023-25157-GeoServer-SQLi-Lab](https://github.com/Giangdurian/CVE-2023-25157-GeoServer-SQLi-Lab) :  ![starts](https://img.shields.io/github/stars/Giangdurian/CVE-2023-25157-GeoServer-SQLi-Lab.svg) ![forks](https://img.shields.io/github/forks/Giangdurian/CVE-2023-25157-GeoServer-SQLi-Lab.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/seal-sec-demo-2/JavaScript-Example](https://github.com/seal-sec-demo-2/JavaScript-Example) :  ![starts](https://img.shields.io/github/stars/seal-sec-demo-2/JavaScript-Example.svg) ![forks](https://img.shields.io/github/forks/seal-sec-demo-2/JavaScript-Example.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.

- [https://github.com/seal-sec-demo-2/Java-Example](https://github.com/seal-sec-demo-2/Java-Example) :  ![starts](https://img.shields.io/github/stars/seal-sec-demo-2/Java-Example.svg) ![forks](https://img.shields.io/github/forks/seal-sec-demo-2/Java-Example.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/M4rrow/CVE-2021-3129](https://github.com/M4rrow/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/M4rrow/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/M4rrow/CVE-2021-3129.svg)


## CVE-2020-11023
 In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing option elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/asoka666/Cve-2020-11023](https://github.com/asoka666/Cve-2020-11023) :  ![starts](https://img.shields.io/github/stars/asoka666/Cve-2020-11023.svg) ![forks](https://img.shields.io/github/forks/asoka666/Cve-2020-11023.svg)


## CVE-2019-9702
 Symantec Endpoint Encryption, prior to SEE 11.3.0, may be susceptible to a privilege escalation vulnerability, which is a type of issue that allows a user to gain elevated access to resources that are normally protected at lower access levels.

- [https://github.com/DavidCarliez/CVE-2019-9702_Symantec_Encryption_Desktop_LPE_PoC](https://github.com/DavidCarliez/CVE-2019-9702_Symantec_Encryption_Desktop_LPE_PoC) :  ![starts](https://img.shields.io/github/stars/DavidCarliez/CVE-2019-9702_Symantec_Encryption_Desktop_LPE_PoC.svg) ![forks](https://img.shields.io/github/forks/DavidCarliez/CVE-2019-9702_Symantec_Encryption_Desktop_LPE_PoC.svg)


## CVE-2017-16043
 Shout is an IRC client. Because the `/topic` command in messages is unescaped, attackers have the ability to inject HTML scripts that will run in the victim's browser. Affects shout =0.44.0 =0.49.3.

- [https://github.com/CQ-Tools/CVE-2017-16043-unfixed](https://github.com/CQ-Tools/CVE-2017-16043-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16043-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16043-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16043-fixed](https://github.com/CQ-Tools/CVE-2017-16043-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16043-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16043-fixed.svg)
- [https://github.com/ossf-cve-benchmark/CVE-2017-16043](https://github.com/ossf-cve-benchmark/CVE-2017-16043) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16043.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16043.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/MK-ULTRA-project-monarch/CVE-2017-7921-Writeup-2026](https://github.com/MK-ULTRA-project-monarch/CVE-2017-7921-Writeup-2026) :  ![starts](https://img.shields.io/github/stars/MK-ULTRA-project-monarch/CVE-2017-7921-Writeup-2026.svg) ![forks](https://img.shields.io/github/forks/MK-ULTRA-project-monarch/CVE-2017-7921-Writeup-2026.svg)


## CVE-2014-9173
 SQL injection vulnerability in view.php in the Google Doc Embedder plugin before 2.5.15 for WordPress allows remote attackers to execute arbitrary SQL commands via the gpid parameter.

- [https://github.com/ratiros01/CVE-2014-9173](https://github.com/ratiros01/CVE-2014-9173) :  ![starts](https://img.shields.io/github/stars/ratiros01/CVE-2014-9173.svg) ![forks](https://img.shields.io/github/forks/ratiros01/CVE-2014-9173.svg)


## CVE-2014-7920
 mediaserver in Android 2.2 through 5.x before 5.1 allows attackers to gain privileges.  NOTE: This is a different vulnerability than CVE-2014-7921.

- [https://github.com/laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921) :  ![starts](https://img.shields.io/github/stars/laginimaineb/cve-2014-7920-7921.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/cve-2014-7920-7921.svg)
- [https://github.com/Vinc3nt4H/cve-2014-7920-7921_update](https://github.com/Vinc3nt4H/cve-2014-7920-7921_update) :  ![starts](https://img.shields.io/github/stars/Vinc3nt4H/cve-2014-7920-7921_update.svg) ![forks](https://img.shields.io/github/forks/Vinc3nt4H/cve-2014-7920-7921_update.svg)


## CVE-2014-7169
 GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271.

- [https://github.com/Kushiro45/shellshock-poc-cve-2014-7169](https://github.com/Kushiro45/shellshock-poc-cve-2014-7169) :  ![starts](https://img.shields.io/github/stars/Kushiro45/shellshock-poc-cve-2014-7169.svg) ![forks](https://img.shields.io/github/forks/Kushiro45/shellshock-poc-cve-2014-7169.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/IndiQuarks/vsftpd-cve-2011-2523-lab](https://github.com/IndiQuarks/vsftpd-cve-2011-2523-lab) :  ![starts](https://img.shields.io/github/stars/IndiQuarks/vsftpd-cve-2011-2523-lab.svg) ![forks](https://img.shields.io/github/forks/IndiQuarks/vsftpd-cve-2011-2523-lab.svg)
- [https://github.com/solomonhenry-afk/vsftpd-cve-2011-2523-detection-signature](https://github.com/solomonhenry-afk/vsftpd-cve-2011-2523-detection-signature) :  ![starts](https://img.shields.io/github/stars/solomonhenry-afk/vsftpd-cve-2011-2523-detection-signature.svg) ![forks](https://img.shields.io/github/forks/solomonhenry-afk/vsftpd-cve-2011-2523-detection-signature.svg)
- [https://github.com/Orevic21/wazuh-home-soc](https://github.com/Orevic21/wazuh-home-soc) :  ![starts](https://img.shields.io/github/stars/Orevic21/wazuh-home-soc.svg) ![forks](https://img.shields.io/github/forks/Orevic21/wazuh-home-soc.svg)

