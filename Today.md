# Update 2026-10-02
## CVE-2026-103446
This issue affects MediaWiki WikiLambda extension: 1.46.

- [https://github.com/BomboBombone/CVE-2026-103446](https://github.com/BomboBombone/CVE-2026-103446) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103446.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103446.svg)


## CVE-2026-103445
This issue affects MediaWiki Page_Forms extension: 1.46, 1.45, and 1.43.

- [https://github.com/BomboBombone/CVE-2026-103445](https://github.com/BomboBombone/CVE-2026-103445) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103445.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103445.svg)


## CVE-2026-103442
This issue affects MediaWiki CentralAuth extension: 1.46, 1.45, and 1.43.

- [https://github.com/BomboBombone/CVE-2026-103442](https://github.com/BomboBombone/CVE-2026-103442) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103442.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103442.svg)


## CVE-2026-103441
This issue affects MediaWiki Wikibase extension: 1.46, 1.45, and 1.43.

- [https://github.com/BomboBombone/CVE-2026-103441](https://github.com/BomboBombone/CVE-2026-103441) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103441.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103441.svg)


## CVE-2026-103440
This issue affects MediaWiki PageTriage extension: 1.46, 1.45, and 1.43.

- [https://github.com/BomboBombone/CVE-2026-103440](https://github.com/BomboBombone/CVE-2026-103440) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103440.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103440.svg)


## CVE-2026-103437
This issue affects MediaWiki ReadingLists extension: 1.46 and 1.45.

- [https://github.com/BomboBombone/CVE-2026-103437](https://github.com/BomboBombone/CVE-2026-103437) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103437.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103437.svg)


## CVE-2026-102427
 Joomla Extension - ordasoft.com - Unauthenticated Remote Code Execution in OrdaSoft Joomla CCK  8.3.16 - site/uploader.php is reached through the component’s normal frontend routing (task=getContent), a task with no authentication or ACL check anywhere in the dispatch chain. The handler validates the uploaded file’s content with a real magic-byte MIME check, but the extension allow-list that would otherwise restrict the saved file’s extension was present in the source and commented out. The saved file’s extension was taken directly from the attacker-supplied filename with no validation, and the file was written to a path directly under the Joomla web root that is executed by the PHP handler. An image/PHP polyglot, a file whose header bytes satisfy the MIME check with PHP source appended after, passed the content check while carrying a .php extension of the attacker’s choosing.

- [https://github.com/murrez/CVE-2026-102427](https://github.com/murrez/CVE-2026-102427) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-102427.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-102427.svg)


## CVE-2026-102425
 Joomla Extension - balbooa.com - Unauthenticated RCE via field shortcode injection in Balbooa Forms  2.4.3.4 - Balbooa Forms supports administrator-defined PHP code which runs after a public form submission. The feature also supports form-field shortcodes inside that PHP. Before calling `eval()`, the component replaces each shortcode with the raw value submitted by the visitor, leading to an RCE vector. A public form must use the product's optional PHP-after-submission action and interpolate an attacker-controlled field shortcode inside a double-quoted PHP string to be vulnerable.

- [https://github.com/murrez/CVE-2026-102425](https://github.com/murrez/CVE-2026-102425) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-102425.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-102425.svg)


## CVE-2026-97347
 The Post Views Stats Counter plugin for WordPress is vulnerable to Stored Cross-Site Scripting via User-Agent Header in all versions up to, and including, 1.1.7 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. The plugin's only input filter is a substring blacklist for known bot signatures (e.g. 'bot', 'spider', 'crawler'), which can be trivially bypassed by crafting a User-Agent payload that omits those strings.

- [https://github.com/JailBr3ak/CVE-2026-97347](https://github.com/JailBr3ak/CVE-2026-97347) :  ![starts](https://img.shields.io/github/stars/JailBr3ak/CVE-2026-97347.svg) ![forks](https://img.shields.io/github/forks/JailBr3ak/CVE-2026-97347.svg)


## CVE-2026-96760
 Authlib (v1.7.2 and below) contains a signature verification bypass vulnerability. The JsonWebSignature.deserialize_json() method accepts a JSON Serialization JWS object and returns the payload as successfully verified without checking for a signature and without requiring a cryptographic key.

- [https://github.com/uziii2208/CVE-2026-96760](https://github.com/uziii2208/CVE-2026-96760) :  ![starts](https://img.shields.io/github/stars/uziii2208/CVE-2026-96760.svg) ![forks](https://img.shields.io/github/forks/uziii2208/CVE-2026-96760.svg)


## CVE-2026-94545
 Satori is a library to convert HTML and CSS to SVG. Starting in version 0.0.27 and prior to version 0.33.5, Satori does not properly escape certain values before including them in generated SVG output. This can allow crafted values to be interpreted as SVG markup. The impact depends on how the generated SVG is consumed. Version 0.33.5 contains a patch. No complete workaround exists besides upgrading. Applications that cannot immediately upgrade should not render attacker-controlled content with Satori.

- [https://github.com/EQSTLab/CVE-2026-94545](https://github.com/EQSTLab/CVE-2026-94545) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-94545.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-94545.svg)
- [https://github.com/MRdark-ops/CVE-2026-94545-](https://github.com/MRdark-ops/CVE-2026-94545-) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-94545-.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-94545-.svg)
- [https://github.com/HORKimhab/CVE-2026-94545](https://github.com/HORKimhab/CVE-2026-94545) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-94545.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-94545.svg)
- [https://github.com/Hassham1/CVE-2026-94545-nextjs-og-poc](https://github.com/Hassham1/CVE-2026-94545-nextjs-og-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-94545-nextjs-og-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-94545-nextjs-og-poc.svg)
- [https://github.com/mhtsec/CVE-2026-94545](https://github.com/mhtsec/CVE-2026-94545) :  ![starts](https://img.shields.io/github/stars/mhtsec/CVE-2026-94545.svg) ![forks](https://img.shields.io/github/forks/mhtsec/CVE-2026-94545.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/craigsblackie/cve-2026-88771-netscaler](https://github.com/craigsblackie/cve-2026-88771-netscaler) :  ![starts](https://img.shields.io/github/stars/craigsblackie/cve-2026-88771-netscaler.svg) ![forks](https://img.shields.io/github/forks/craigsblackie/cve-2026-88771-netscaler.svg)


## CVE-2026-87004
 Tugtainer is a self-hosted app for automating updates of Docker containers. Prior to version 1.31.3, when the OIDC login flow completes, backend/modules/auth/providers/auth_oidc_provider.py decodes the id_token returned by the identity provider's token endpoint using jose.jwt.get_unverified_claims() instead of jwt.decode(). This skips signature verification, audience (aud) validation, issuer (iss) validation, and expiry (exp) checking entirely. The extracted claims (email/sub/preferred_username) are then used directly as the user_id for the resulting Tugtainer session. This issue has been patched in version 1.31.3.

- [https://github.com/squeeze440/tugtainer-PoC](https://github.com/squeeze440/tugtainer-PoC) :  ![starts](https://img.shields.io/github/stars/squeeze440/tugtainer-PoC.svg) ![forks](https://img.shields.io/github/forks/squeeze440/tugtainer-PoC.svg)


## CVE-2026-86595
This issue affects enVision: before 260655.

- [https://github.com/Hasanuyarrr/CVE-2026-86595-Iron-Mountain-enVision-EBYSde-Kimlik-Dogrulamal-SQL-Enjeksiyonu-Zafiyeti](https://github.com/Hasanuyarrr/CVE-2026-86595-Iron-Mountain-enVision-EBYSde-Kimlik-Dogrulamal-SQL-Enjeksiyonu-Zafiyeti) :  ![starts](https://img.shields.io/github/stars/Hasanuyarrr/CVE-2026-86595-Iron-Mountain-enVision-EBYSde-Kimlik-Dogrulamal-SQL-Enjeksiyonu-Zafiyeti.svg) ![forks](https://img.shields.io/github/forks/Hasanuyarrr/CVE-2026-86595-Iron-Mountain-enVision-EBYSde-Kimlik-Dogrulamal-SQL-Enjeksiyonu-Zafiyeti.svg)


## CVE-2026-85706
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.7 before 18.11.12, 19.0 before 19.0.9, 19.1 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an unauthenticated user could have read arbitrary files from the GitLab server due to improper path confinement and missing authentication enforcement in the repository commits API.

- [https://github.com/wuyou6956-glitch/cve-2026-85706](https://github.com/wuyou6956-glitch/cve-2026-85706) :  ![starts](https://img.shields.io/github/stars/wuyou6956-glitch/cve-2026-85706.svg) ![forks](https://img.shields.io/github/forks/wuyou6956-glitch/cve-2026-85706.svg)


## CVE-2026-80444
This issue affects AVESİS: from 202608201331 before 202608240351.

- [https://github.com/Hasanuyarrr/CVE-2026-80444-Avesis-Uygulamasinda-Open-Redirect-Zafiyeti](https://github.com/Hasanuyarrr/CVE-2026-80444-Avesis-Uygulamasinda-Open-Redirect-Zafiyeti) :  ![starts](https://img.shields.io/github/stars/Hasanuyarrr/CVE-2026-80444-Avesis-Uygulamasinda-Open-Redirect-Zafiyeti.svg) ![forks](https://img.shields.io/github/forks/Hasanuyarrr/CVE-2026-80444-Avesis-Uygulamasinda-Open-Redirect-Zafiyeti.svg)


## CVE-2026-76570
 Joomla Extension - joomcode.com - Unauthenticated SQL injection in read and write queries in JCTables  1.21.1 - The front-end CRUD API controller performs no Joomla token validation and no authentication check on any task. Table names, column names, and values are taken directly from request parameters and concatenated into SQL queries, allowing SQLi for reading and writing queries.

- [https://github.com/murrez/CVE-2026-76570](https://github.com/murrez/CVE-2026-76570) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-76570.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-76570.svg)


## CVE-2026-76504
This vulnerability is due to improper handling of URI encoding in an HTTP request, which allows the request to bypass an authentication rule that is intended to restrict access to a specific API endpoint. An attacker could exploit this vulnerability by sending a crafted HTTP request to the API of the affected system. A successful exploit could allow the attacker to bypass authentication and gain access to the API as the admin user.

- [https://github.com/ShadowForge-Cyber/CVE-2026-76504-Proof-of-concept](https://github.com/ShadowForge-Cyber/CVE-2026-76504-Proof-of-concept) :  ![starts](https://img.shields.io/github/stars/ShadowForge-Cyber/CVE-2026-76504-Proof-of-concept.svg) ![forks](https://img.shields.io/github/forks/ShadowForge-Cyber/CVE-2026-76504-Proof-of-concept.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/0xBlackash/CVE-2026-73570](https://github.com/0xBlackash/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-73570.svg)


## CVE-2026-72018
check before the memcpy to reject such requests with -EINVAL.

- [https://github.com/0xBlackash/CVE-2026-72018](https://github.com/0xBlackash/CVE-2026-72018) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-72018.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-72018.svg)


## CVE-2026-62308
 Tugtainer is a self-hosted app for automating updates of Docker containers. Prior to version 1.30.6, Tugtainer allows an authenticated user to make the backend server send outbound HTTP requests to arbitrary user-supplied URLs through the notification test endpoint. The /settings/test_notification endpoint accepts a urls field and passes it directly to Apprise without restricting protocols, hostnames, localhost addresses, private IP ranges, or cloud metadata addresses. This can be abused as an authenticated blind server-side request forgery (SSRF). This issue has been patched in version 1.30.6.

- [https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE](https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE) :  ![starts](https://img.shields.io/github/stars/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg) ![forks](https://img.shields.io/github/forks/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg)


## CVE-2026-55494
 Tugtainer is a self-hosted app for automating updates of Docker containers. Prior to version 1.30.4, Tugtainer Agent allows unauthenticated access to Docker management APIs when AGENT_SECRET is not configured. The Agent uses request signatures to protect its API routes. However, in agent/auth.py, the signature verification function returns successfully if Config.AGENT_SECRET is empty. This causes protected Agent APIs to become accessible without authentication. This issue has been patched in version 1.30.4.

- [https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE](https://github.com/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE) :  ![starts](https://img.shields.io/github/stars/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg) ![forks](https://img.shields.io/github/forks/4qu4r1um/tugtainer-1.30.2-CVE-2026-55494-and-CVE-2026-62308-to-RCE.svg)


## CVE-2026-52993
skb.  If it does, reassign *headbuf for later freeing operations.

- [https://github.com/CaptainAI-Labs/CaptainAI-LPE-CVE-2026-52993](https://github.com/CaptainAI-Labs/CaptainAI-LPE-CVE-2026-52993) :  ![starts](https://img.shields.io/github/stars/CaptainAI-Labs/CaptainAI-LPE-CVE-2026-52993.svg) ![forks](https://img.shields.io/github/forks/CaptainAI-Labs/CaptainAI-LPE-CVE-2026-52993.svg)


## CVE-2026-48611
 Improper authentication checks in the OAuth implementation allow account hijacking even when OAuth is not configured or enabled leading to unauthorized access in default installations.

- [https://github.com/lxdwnpiper/CVE-2026-48611-phpBB](https://github.com/lxdwnpiper/CVE-2026-48611-phpBB) :  ![starts](https://img.shields.io/github/stars/lxdwnpiper/CVE-2026-48611-phpBB.svg) ![forks](https://img.shields.io/github/forks/lxdwnpiper/CVE-2026-48611-phpBB.svg)


## CVE-2026-48121
 @langchain/langgraph-checkpoint-mongodb provides a LangGraph.js CheckpointSaver implementation that uses MongoDB for storage. Versions 1.3.0 and below are vulnerable to NoSQL injection: checkpoint identifiers (thread_id, checkpoint_ns, checkpoint_id) from config.configurable are passed into MongoDB find() queries in MongoDBSaver.getTuple() without type enforcement. If an attacker supplies an object payload (such as MongoDB operators $gt or $ne) instead of a string, it can be interpreted as a query operator, bypassing thread scoping and leaking checkpoints, including pending writes, across tenants. Applications are at risk if they forward untrusted input into config.configurable without coercing it to strings or validating it against a schema, particularly in multi-tenant or user-isolated setups. Apps that only use server-issued, string-typed identifiers with schema validation rejecting non-string fields are not affected. This issue has been fixed in version 1.3.1.

- [https://github.com/decker757/cs440-langgraph-nosql-demo](https://github.com/decker757/cs440-langgraph-nosql-demo) :  ![starts](https://img.shields.io/github/stars/decker757/cs440-langgraph-nosql-demo.svg) ![forks](https://img.shields.io/github/forks/decker757/cs440-langgraph-nosql-demo.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/shubhampathak65/CVE-2026-43499](https://github.com/shubhampathak65/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/shubhampathak65/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/shubhampathak65/CVE-2026-43499.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/wuyou6956-glitch/CVE-2026-41096-POC](https://github.com/wuyou6956-glitch/CVE-2026-41096-POC) :  ![starts](https://img.shields.io/github/stars/wuyou6956-glitch/CVE-2026-41096-POC.svg) ![forks](https://img.shields.io/github/forks/wuyou6956-glitch/CVE-2026-41096-POC.svg)


## CVE-2026-31857
 Craft is a content management system (CMS). Prior to 5.9.9 and 4.17.4, a Remote Code Execution vulnerability exists in the Craft CMS 5 conditions system. The BaseElementSelectConditionRule::getElementIds() method passes user-controlled string input through renderObjectTemplate() -- an unsandboxed Twig rendering function with escaping disabled. Any authenticated Control Panel user (including non-admin roles such as Author or Editor) can achieve full RCE by sending a crafted condition rule via standard element listing endpoints. This vulnerability requires no admin privileges, no special permissions beyond basic control panel access, and bypasses all production hardening settings (allowAdminChanges: false, devMode: false, enableTwigSandbox: true). Users should update to the patched 5.9.9 or 4.17.4 release to mitigate the issue.

- [https://github.com/0Asylum/CVE-2026-31857](https://github.com/0Asylum/CVE-2026-31857) :  ![starts](https://img.shields.io/github/stars/0Asylum/CVE-2026-31857.svg) ![forks](https://img.shields.io/github/forks/0Asylum/CVE-2026-31857.svg)


## CVE-2026-26026
 GLPI is a free asset and IT management software package. From 11.0.0 to before 11.0.6, template injection by an administrator lead to RCE. This vulnerability is fixed in 11.0.6.

- [https://github.com/wuyou6956-glitch/CVE-2026-26026-PoC](https://github.com/wuyou6956-glitch/CVE-2026-26026-PoC) :  ![starts](https://img.shields.io/github/stars/wuyou6956-glitch/CVE-2026-26026-PoC.svg) ![forks](https://img.shields.io/github/forks/wuyou6956-glitch/CVE-2026-26026-PoC.svg)


## CVE-2026-18783
This issue affects Trex MES: through 2026-09-29.

- [https://github.com/Hasanuyarrr/CVE-2026-18783-TREX-MES-Uygulamalarinda-Yetkisiz-Nesne-Erisimi](https://github.com/Hasanuyarrr/CVE-2026-18783-TREX-MES-Uygulamalarinda-Yetkisiz-Nesne-Erisimi) :  ![starts](https://img.shields.io/github/stars/Hasanuyarrr/CVE-2026-18783-TREX-MES-Uygulamalarinda-Yetkisiz-Nesne-Erisimi.svg) ![forks](https://img.shields.io/github/forks/Hasanuyarrr/CVE-2026-18783-TREX-MES-Uygulamalarinda-Yetkisiz-Nesne-Erisimi.svg)


## CVE-2026-18782
This issue affects Trex MES: through 2026-09-29.

- [https://github.com/Hasanuyarrr/CVE-2026-18782-TREX-MES-Uygulamalarinda-SQL-Zafiyeti](https://github.com/Hasanuyarrr/CVE-2026-18782-TREX-MES-Uygulamalarinda-SQL-Zafiyeti) :  ![starts](https://img.shields.io/github/stars/Hasanuyarrr/CVE-2026-18782-TREX-MES-Uygulamalarinda-SQL-Zafiyeti.svg) ![forks](https://img.shields.io/github/forks/Hasanuyarrr/CVE-2026-18782-TREX-MES-Uygulamalarinda-SQL-Zafiyeti.svg)


## CVE-2026-18143
 The Request a Quote for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.9.2 via the `afrfq_submit_quote_via_popup()` function. This is due to missing file extension and MIME type validation in the popup upload handler, which uses the raw attacker-supplied filename directly as the destination for `move_uploaded_file()`. This makes it possible for unauthenticated attackers to upload executable files, such as PHP files, to a web-accessible temporary RFQ upload directory when a public quote rule with the multi-page popup flow is enabled.

- [https://github.com/ghannyxploit404/CVE-2026-18143](https://github.com/ghannyxploit404/CVE-2026-18143) :  ![starts](https://img.shields.io/github/stars/ghannyxploit404/CVE-2026-18143.svg) ![forks](https://img.shields.io/github/forks/ghannyxploit404/CVE-2026-18143.svg)


## CVE-2026-12227
 The Visual Composer Website Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 45.16.0 via the `vcv-template` parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/MRdark-ops/CVE-2026-12227](https://github.com/MRdark-ops/CVE-2026-12227) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-12227.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-12227.svg)


## CVE-2026-10297
 A vulnerability was identified in itsourcecode Fees Management System 1.0. This affects an unknown part of the file /manage_course.php. The manipulation of the argument ID leads to sql injection. It is possible to initiate the attack remotely. The exploit is publicly available and might be used.

- [https://github.com/BomboBombone/CVE-2026-102973](https://github.com/BomboBombone/CVE-2026-102973) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-102973.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-102973.svg)
- [https://github.com/BomboBombone/CVE-2026-102975](https://github.com/BomboBombone/CVE-2026-102975) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-102975.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-102975.svg)
- [https://github.com/BomboBombone/CVE-2026-102971](https://github.com/BomboBombone/CVE-2026-102971) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-102971.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-102971.svg)


## CVE-2026-10260
 A vulnerability was detected in CodeAstro Online Job Portal 1.0. The impacted element is an unknown function of the file /admin/jobs-admins/delete-jobs.php. Performing a manipulation of the argument ID results in sql injection. It is possible to initiate the attack remotely. The exploit is now public and may be used.

- [https://github.com/d4kw1n/CVE-2026-102607-ZoneMinder](https://github.com/d4kw1n/CVE-2026-102607-ZoneMinder) :  ![starts](https://img.shields.io/github/stars/d4kw1n/CVE-2026-102607-ZoneMinder.svg) ![forks](https://img.shields.io/github/forks/d4kw1n/CVE-2026-102607-ZoneMinder.svg)


## CVE-2026-9115
 Insufficient policy enforcement in Service Worker in Google Chrome on prior to 148.0.7778.179 allowed a remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/sl4x0/autheo-cve-2026-91159-poc](https://github.com/sl4x0/autheo-cve-2026-91159-poc) :  ![starts](https://img.shields.io/github/stars/sl4x0/autheo-cve-2026-91159-poc.svg) ![forks](https://img.shields.io/github/forks/sl4x0/autheo-cve-2026-91159-poc.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup](https://github.com/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup) :  ![starts](https://img.shields.io/github/stars/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup.svg) ![forks](https://img.shields.io/github/forks/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup.svg)


## CVE-2026-1668
 The web interface on multiple Omada switches does not adequately validate certain external inputs, which may lead to out-of-bound memory access when processing crafted requests.  Under specific conditions, this flaw may result in unintended command execution.brAn unauthenticated attacker with network access to the affected interface may cause memory corruption, service instability, or information disclosure.  Successful exploitation may allow remote code execution or denial-of-service.

- [https://github.com/wuyou6956-glitch/cve-2026-1668-poc](https://github.com/wuyou6956-glitch/cve-2026-1668-poc) :  ![starts](https://img.shields.io/github/stars/wuyou6956-glitch/cve-2026-1668-poc.svg) ![forks](https://img.shields.io/github/forks/wuyou6956-glitch/cve-2026-1668-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/Amoru-Bek/CVE-2025-59528-Poc](https://github.com/Amoru-Bek/CVE-2025-59528-Poc) :  ![starts](https://img.shields.io/github/stars/Amoru-Bek/CVE-2025-59528-Poc.svg) ![forks](https://img.shields.io/github/forks/Amoru-Bek/CVE-2025-59528-Poc.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/2t8a/CVE-2025-49132](https://github.com/2t8a/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/2t8a/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/2t8a/CVE-2025-49132.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/Minseo9503/cve-2025-30208](https://github.com/Minseo9503/cve-2025-30208) :  ![starts](https://img.shields.io/github/stars/Minseo9503/cve-2025-30208.svg) ![forks](https://img.shields.io/github/forks/Minseo9503/cve-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/vulnace/CVE-2025-29927](https://github.com/vulnace/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/vulnace/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/vulnace/CVE-2025-29927.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2023-3776
We recommend upgrading past commit 0323bce598eea038714f941ce2b22541c46d488f.

- [https://github.com/Sakura999999999/CVE-2023-3776_repro](https://github.com/Sakura999999999/CVE-2023-3776_repro) :  ![starts](https://img.shields.io/github/stars/Sakura999999999/CVE-2023-3776_repro.svg) ![forks](https://img.shields.io/github/forks/Sakura999999999/CVE-2023-3776_repro.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis](https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis) :  ![starts](https://img.shields.io/github/stars/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg) ![forks](https://img.shields.io/github/forks/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)
- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-31805
 The fix issued for CVE-2020-17530 was incomplete. So from Apache Struts 2.0.0 to 2.5.29, still some of the tag’s attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security degradation.

- [https://github.com/nth347/struts2-CVE-2021-31805](https://github.com/nth347/struts2-CVE-2021-31805) :  ![starts](https://img.shields.io/github/stars/nth347/struts2-CVE-2021-31805.svg) ![forks](https://img.shields.io/github/forks/nth347/struts2-CVE-2021-31805.svg)


## CVE-2021-26085
 Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a Pre-Authorization Arbitrary File Read vulnerability in the /s/ endpoint. The affected versions are before version 7.4.10, and from version 7.5.0 before 7.12.3.

- [https://github.com/heidarodarkfire158/Confluence-Desktop-2026](https://github.com/heidarodarkfire158/Confluence-Desktop-2026) :  ![starts](https://img.shields.io/github/stars/heidarodarkfire158/Confluence-Desktop-2026.svg) ![forks](https://img.shields.io/github/forks/heidarodarkfire158/Confluence-Desktop-2026.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/cchiaravalentini/CVE-2021-3129](https://github.com/cchiaravalentini/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/cchiaravalentini/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/cchiaravalentini/CVE-2021-3129.svg)


## CVE-2020-17530
 Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.

- [https://github.com/nth347/struts2-CVE-2020-17530](https://github.com/nth347/struts2-CVE-2020-17530) :  ![starts](https://img.shields.io/github/stars/nth347/struts2-CVE-2020-17530.svg) ![forks](https://img.shields.io/github/forks/nth347/struts2-CVE-2020-17530.svg)


## CVE-2020-14008
 Zoho ManageEngine Applications Manager 14710 and before allows an authenticated admin user to upload a vulnerable jar in a specific location, which leads to remote code execution.

- [https://github.com/raflesiait/CVE-2020-14008_ManageEngine](https://github.com/raflesiait/CVE-2020-14008_ManageEngine) :  ![starts](https://img.shields.io/github/stars/raflesiait/CVE-2020-14008_ManageEngine.svg) ![forks](https://img.shields.io/github/forks/raflesiait/CVE-2020-14008_ManageEngine.svg)


## CVE-2013-2251
 Apache Struts 2.0.0 through 2.3.15 allows remote attackers to execute arbitrary OGNL expressions via a parameter with a crafted (1) action:, (2) redirect:, or (3) redirectAction: prefix.

- [https://github.com/nth347/struts2-CVE-2013-2251](https://github.com/nth347/struts2-CVE-2013-2251) :  ![starts](https://img.shields.io/github/stars/nth347/struts2-CVE-2013-2251.svg) ![forks](https://img.shields.io/github/forks/nth347/struts2-CVE-2013-2251.svg)

