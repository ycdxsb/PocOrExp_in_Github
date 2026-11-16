# Update 2026-11-16
## CVE-2026-129254
 A flaw has been found in Opixido OCMS up to b7c15660aba83d96677c1a9abaa69c082a24f21c. This impacts an unknown function of the file admin/TUI/index.php of the component Admin TUI. This manipulation of the argument img causes cross site scripting. The attack can be initiated remotely. The exploit has been published and may be used. Continious delivery with rolling releases is used by this product. Therefore, no version details of affected nor updated releases are available. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Usama-Hanif131/CVE-2026-129254](https://github.com/Usama-Hanif131/CVE-2026-129254) :  ![starts](https://img.shields.io/github/stars/Usama-Hanif131/CVE-2026-129254.svg) ![forks](https://img.shields.io/github/forks/Usama-Hanif131/CVE-2026-129254.svg)


## CVE-2026-128046
 OpenMage magento-lts 20.17.0 before 20.18.2 and 21.0.0-beta1 before 21.0.0-beta3 contains an unrestricted file upload vulnerability because the general/file/protected_extensions blocklist omits phar, php8, and phps. Unauthenticated attackers can upload a .phar file through a product File custom option to a predictable media/custom_options path and request it directly to execute code on servers that map .phar to PHP and serve that directory.

- [https://github.com/googlesky/CVE-2026-128046](https://github.com/googlesky/CVE-2026-128046) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128046.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128046.svg)


## CVE-2026-128027
 FrankenPHP Docker images before 1.1.11 were rebuilt only when new base image tags were created, so security fixes that Alpine, PHP, and Go applied under existing tags were not propagated. Remote attackers could exploit known flaws in the stale system libraries, such as CVE-2025-15467 in libcrypto3, to execute code.

- [https://github.com/googlesky/CVE-2026-128027](https://github.com/googlesky/CVE-2026-128027) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128027.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128027.svg)


## CVE-2026-128014
 FrankenPHP standalone static binaries 1.8.0 before 1.13.2 bundle the PHP brotli extension statically linked with Brotli 1.2.0, whose decoder contains an out-of-bounds write (CVE-2026-111497). Unauthenticated remote attackers can send crafted data to applications that pass it to brotli_uncompress_add() to crash the entire FrankenPHP process, and possibly cause memory disclosure or code execution.

- [https://github.com/googlesky/CVE-2026-128014](https://github.com/googlesky/CVE-2026-128014) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128014.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128014.svg)


## CVE-2026-126937
 Zipline before 4.6.5 contains a TOCTOU race condition in the POST /api/setup endpoint that allows unauthenticated attackers to create multiple SUPERADMIN accounts by racing concurrent requests before the firstSetup flag is reset. Attackers can send simultaneous requests with spoofed X-Forwarded-For headers during the argon2 hashing window to gain full administrative control of the instance.

- [https://github.com/googlesky/CVE-2026-126937](https://github.com/googlesky/CVE-2026-126937) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126937.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126937.svg)


## CVE-2026-126837
 A validation flaw in the DNS SRV host discovery of the MongoDB Node.js driver may cause the driver to connect to a host outside the expected domain. For a mongodb+srv:// connection string, the driver checks each host name in the DNS SRV response against the domain of the connection string. The driver then builds the connection address from the original name, in which certain characters end the host name early. An unauthenticated party who can forge or change the DNS SRV response may redirect the connection to a host of their choice. TLS does not prevent this, because the driver verifies the server certificate against the redirected host name. This may result in unintended disclosure of application data and authentication credentials, and in altered query results. Applications that use mongodb:// connection strings are not affected.

- [https://github.com/googlesky/CVE-2026-126837](https://github.com/googlesky/CVE-2026-126837) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126837.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126837.svg)


## CVE-2026-126539
 Directus before 12.1.0 contains an authorization bypass vulnerability that allows unauthenticated attackers to skip permission checks by sending a failed auth message on public-mode WebSocket connections. Attackers can send an invalid token so handleAuthRequest sets accountability to null, then read, create, update or delete records in any user-defined collection.

- [https://github.com/fixedbyreboot/CVE-2026-126539-POC](https://github.com/fixedbyreboot/CVE-2026-126539-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-126539-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-126539-POC.svg)


## CVE-2026-126473
 OpenEMR before 8.4.0 contains OAuth scope canonicalization and containment flaws that allow unauthenticated attackers to obtain unapproved system-level FHIR access. Attackers can register a colon-form system:Patient.read client that bypasses approval, then request unregistered system/Patient.write scope to read, modify, and create Patient records.

- [https://github.com/googlesky/CVE-2026-126473](https://github.com/googlesky/CVE-2026-126473) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126473.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126473.svg)


## CVE-2026-126274
 NocoDB before 2026.08.0 contains a stored cross-site scripting vulnerability that allows authenticated Creator users to inject script by embedding markup in column or table titles. The Delete.vue confirmation dialog renders these titles through an unescaped innerHTML binding, executing script when a victim deletes an external-source table to steal session tokens from localStorage.

- [https://github.com/googlesky/CVE-2026-126274](https://github.com/googlesky/CVE-2026-126274) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126274.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126274.svg)


## CVE-2026-126273
 NocoDB before 2026.09.0 contains a privilege escalation vulnerability in initAdminFromEnv.ts that silently skips super-admin bootstrap when the admin password environment variable is empty. Unauthenticated attackers can call the public signup endpoint first on a fresh instance to receive Creator and Super Admin roles, gaining full administrative control.

- [https://github.com/googlesky/CVE-2026-126273](https://github.com/googlesky/CVE-2026-126273) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126273.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126273.svg)


## CVE-2026-126269
 NocoDB before 2026.09.0 contains a stored cross-site scripting vulnerability that allows authenticated Editor users to execute scripts by storing crafted attachment MIME types like text/html;image/png. Attackers can write the value through the records API so the /dltemp signed URL serves HTML inline, stealing session tokens from localStorage to impersonate victims.

- [https://github.com/googlesky/CVE-2026-126269](https://github.com/googlesky/CVE-2026-126269) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126269.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126269.svg)


## CVE-2026-126173
 The AutomatorWP Pro plugin for WordPress' webhook addon is vulnerable to authorization bypass in all versions up to, and including, 1.4.4. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for unauthenticated attackers to reset the password of any WordPress account, including administrators, resulting in full account takeover. This is only exploitable when an administrator has configured an automation pairing a Receive Webhook trigger — with an 'Is the user ID' field — to an Update-User action whose User ID field is left blank and whose Password field is mapped to the webhook password tag, which is a documented, supported plugin configuration.

- [https://github.com/im0xfay/CVE-2026-126173](https://github.com/im0xfay/CVE-2026-126173) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-126173.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-126173.svg)


## CVE-2026-125855
 Deserialization of Untrusted Data vulnerability in Elextensions ELEX WordPress HelpDesk & Customer Ticketing System elex-helpdesk-customer-support-ticket-system allows Object Injection.This issue affects ELEX WordPress HelpDesk & Customer Ticketing System: from n/a through 3.3.9.

- [https://github.com/im0xfay/CVE-2026-125855](https://github.com/im0xfay/CVE-2026-125855) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-125855.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-125855.svg)


## CVE-2026-125440
 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in Cristián Lávaque s2Member s2member allows Code Injection.This issue affects s2Member: from n/a through 261106.

- [https://github.com/yozturk0/CVE-2026-125440](https://github.com/yozturk0/CVE-2026-125440) :  ![starts](https://img.shields.io/github/stars/yozturk0/CVE-2026-125440.svg) ![forks](https://img.shields.io/github/forks/yozturk0/CVE-2026-125440.svg)


## CVE-2026-124429
 Craft CMS from 5.0.0 before 5.11.2 contains a privilege escalation vulnerability that allows unauthenticated public registrants to reclaim deactivated non-admin accounts while retaining their direct permissions. Attackers can register using a deactivated account, set a new password, and inherit permissions stored in userpermissions_users, enabling privileged account takeover when email verification is disabled.

- [https://github.com/fixedbyreboot/CVE-2026-115934-POC](https://github.com/fixedbyreboot/CVE-2026-115934-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-115934-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-115934-POC.svg)


## CVE-2026-124427
 Craft CMS from 5.0.0 before 5.11.2 contains an authorization bypass vulnerability that allows anonymous GraphQL clients to read out-of-scope section entries via prev/next fields. Attackers can chain next hops from one visible in-scope entry to enumerate entries and read titles, slugs, and custom-field content from withheld sections.

- [https://github.com/fixedbyreboot/CVE-2026-115934-POC](https://github.com/fixedbyreboot/CVE-2026-115934-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-115934-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-115934-POC.svg)


## CVE-2026-124194
 Product ui does not warn user of unsafe actions in Microsoft Office Outlook allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/aminaljabre77-collab/outlook-ntlm-leak-investigation](https://github.com/aminaljabre77-collab/outlook-ntlm-leak-investigation) :  ![starts](https://img.shields.io/github/stars/aminaljabre77-collab/outlook-ntlm-leak-investigation.svg) ![forks](https://img.shields.io/github/forks/aminaljabre77-collab/outlook-ntlm-leak-investigation.svg)


## CVE-2026-124021
 Control Web Panel (CWP) before webpanel_version 1.30.6 contains an authorization bypass vulnerability in the validate() function of api/v1/index.php that allows attackers holding a password-recovery token and a predictable legacy signature to obtain valid remote-API authorization without a proper API key. Attackers can exploit this flaw via the POST /cronjobsusers/ endpoint to add arbitrary cron commands and achieve command execution as the affected hosting account, and can also abuse the same token to access global account-list and account-detail routes exposing usernames, contact emails, and password hashes.

- [https://github.com/fixedbyreboot/CVE-2026-124020-POC](https://github.com/fixedbyreboot/CVE-2026-124020-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-124020-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-124020-POC.svg)


## CVE-2026-124020
 Control Web Panel (CWP) before webpanel_version 1.30.6 contains a host header injection vulnerability that allows unauthenticated attackers to manipulate the password-recovery reset URL by injecting the HTTP Host header into the /v1/lostpass/ route's token generation process. Attackers can lure an automated mail-security scanner into visiting the poisoned reset link to exfiltrate the live recovery token, replay it at /login/index.php?acc=newpass to set a new password, and subsequently abuse the File Manager and Crontab modules to achieve command execution as the targeted hosting account.

- [https://github.com/fixedbyreboot/CVE-2026-124020-POC](https://github.com/fixedbyreboot/CVE-2026-124020-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-124020-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-124020-POC.svg)


## CVE-2026-124002
 XWEB EVO versions 5.2.3 through before 5.7.0 contains a pre-authentication OS command injection vulnerability that allows unauthenticated remote attackers to execute arbitrary OS commands by injecting shell metacharacters into the username field of login.lua, cleanout.lua, or api.lua before the password check occurs. Attackers can exploit this flaw combined with the setuid-root wlua interpreter to execute commands with root privileges, achieving full system compromise. This product line reached it's end of service date in March 2026.

- [https://github.com/fixedbyreboot/CVE-2026-124002-POC](https://github.com/fixedbyreboot/CVE-2026-124002-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-124002-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-124002-POC.svg)


## CVE-2026-123790
 ComfyUI-Easy-Use version 1.3.6 contains a path traversal vulnerability in the `save_preview()` handler for POST `/easyuse/save/{name}`. The handler checks the source directory before appending a user-supplied filename and allows the request to select the `custom_nodes` directory as a copy destination. An unauthenticated attacker who can reach the ComfyUI server can overwrite an installed custom node’s Python entry point with an uploaded file. When ComfyUI restarts and loads the modified node, the attacker’s code runs with the privileges of the ComfyUI process.

- [https://github.com/lng255639-cpu/comfyui-easyuse-cve-check-en](https://github.com/lng255639-cpu/comfyui-easyuse-cve-check-en) :  ![starts](https://img.shields.io/github/stars/lng255639-cpu/comfyui-easyuse-cve-check-en.svg) ![forks](https://img.shields.io/github/forks/lng255639-cpu/comfyui-easyuse-cve-check-en.svg)
- [https://github.com/lng255639-cpu/comfyui-easyuse-cve-check](https://github.com/lng255639-cpu/comfyui-easyuse-cve-check) :  ![starts](https://img.shields.io/github/stars/lng255639-cpu/comfyui-easyuse-cve-check.svg) ![forks](https://img.shields.io/github/forks/lng255639-cpu/comfyui-easyuse-cve-check.svg)


## CVE-2026-119618
Affected releases of mod_h2 from GitHub: from 2.0.8 through 2.0.42.

- [https://github.com/d4ytox/CVE-2026-119618](https://github.com/d4ytox/CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2026-119618.svg)
- [https://github.com/terminat0r7031/CVE-2026-119618](https://github.com/terminat0r7031/CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/terminat0r7031/CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/terminat0r7031/CVE-2026-119618.svg)
- [https://github.com/QCG5OLF5ZU9L2W/CVE-2026-119618-YARA](https://github.com/QCG5OLF5ZU9L2W/CVE-2026-119618-YARA) :  ![starts](https://img.shields.io/github/stars/QCG5OLF5ZU9L2W/CVE-2026-119618-YARA.svg) ![forks](https://img.shields.io/github/forks/QCG5OLF5ZU9L2W/CVE-2026-119618-YARA.svg)
- [https://github.com/matarturo/apache-mod-http2-scanner](https://github.com/matarturo/apache-mod-http2-scanner) :  ![starts](https://img.shields.io/github/stars/matarturo/apache-mod-http2-scanner.svg) ![forks](https://img.shields.io/github/forks/matarturo/apache-mod-http2-scanner.svg)


## CVE-2026-119077
 The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.3.9 via the 'form (specifically the attacker-controlled ticket_label field inside the url-encoded form string)' parameter parameter. This is due to missing server-side authentication and the absence of a class allowlist on deserialization, with the only guard being a nonce publicly emitted on any page carrying the [wsdesk_support] shortcode. This makes it possible for unauthenticated attackers to execute code on the server. A successful exploit requires a single anonymous GET to any public page carrying the [wsdesk_support] shortcode to harvest the publicly emitted wsdesk_nonce value, after which a single unauthenticated POST completes the attack.

- [https://github.com/im0xfay/CVE-2026-125855](https://github.com/im0xfay/CVE-2026-125855) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-125855.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-125855.svg)


## CVE-2026-117551
 Joomla Extension - jdownloads.com - RCE through file upload in jDownloads  4.1.8 -  Insufficient validation of frontend thumbnail uploads allowed users with upload permission to place executable files on the server. This results in PHP code execution.

- [https://github.com/fixedbyreboot/CVE-2026-117551-POC](https://github.com/fixedbyreboot/CVE-2026-117551-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-117551-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-117551-POC.svg)


## CVE-2026-116779
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia_presence_handle_sip_i_message() split the To user of an inbound SIP MESSAGE on a plus sign and treated the left side as a chat protocol selector. Selecting the api chat proto reached switch_api_execute(), allowing a peer whose MESSAGE was accepted to run FreeSWITCH API commands, including operating-system command sinks, with the daemon's privileges. Inbound chat is enabled on the stock internal and external profiles, and any authenticated profile account is sufficient; stock directory users without password material can also remove that barrier in affected configurations. The flaw permits configuration and credential disclosure, arbitrary call control, and command execution, and exploitation has been observed in the wild. This issue is fixed in version 1.11.3.

- [https://github.com/al4n4n/CVE-2026-116779](https://github.com/al4n4n/CVE-2026-116779) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-116779.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-116779.svg)
- [https://github.com/DeathShotXD/SIP2Shell](https://github.com/DeathShotXD/SIP2Shell) :  ![starts](https://img.shields.io/github/stars/DeathShotXD/SIP2Shell.svg) ![forks](https://img.shields.io/github/forks/DeathShotXD/SIP2Shell.svg)


## CVE-2026-115934
If you cannot update immediately, you can block front-end requests with %5Battribute%5D and [attribute] anywhere in the query string as a temporary mitigation.

- [https://github.com/fixedbyreboot/CVE-2026-115934-POC](https://github.com/fixedbyreboot/CVE-2026-115934-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-115934-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-115934-POC.svg)


## CVE-2026-114713
 The labeled-response module in UnrealIRCd 6.0.0 before 6.2.7.1 does not escape the IRCv3 "label" message tag when echoing it into replies, which allows any user on a network with two or more linked servers to inject server-to-server commands that are executed with server authority.

- [https://github.com/Sable-Research/CVE-2026-114713](https://github.com/Sable-Research/CVE-2026-114713) :  ![starts](https://img.shields.io/github/stars/Sable-Research/CVE-2026-114713.svg) ![forks](https://img.shields.io/github/forks/Sable-Research/CVE-2026-114713.svg)
- [https://github.com/fixedbyreboot/CVE-2026-114713-POC](https://github.com/fixedbyreboot/CVE-2026-114713-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-114713-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-114713-POC.svg)
- [https://github.com/foxcornlab/unrealircd-scanner](https://github.com/foxcornlab/unrealircd-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/unrealircd-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/unrealircd-scanner.svg)


## CVE-2026-114552
The specific flaw exists within the implementation of the parseObjectResponse method. The issue results from the lack of proper restriction of XML External Entity (XXE) references. An attacker can leverage this vulnerability to disclose information in the context of the service account. Was ZDI-CAN-29137.

- [https://github.com/RossKeddy/CVE-2026-114552](https://github.com/RossKeddy/CVE-2026-114552) :  ![starts](https://img.shields.io/github/stars/RossKeddy/CVE-2026-114552.svg) ![forks](https://img.shields.io/github/forks/RossKeddy/CVE-2026-114552.svg)


## CVE-2026-112652
 A logic issue was addressed with improved state management. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, visionOS 27.2. An malicious app may be able to bypass certificate validation.

- [https://github.com/FAHAD21313/cve-2026-112652-secpolicy-research](https://github.com/FAHAD21313/cve-2026-112652-secpolicy-research) :  ![starts](https://img.shields.io/github/stars/FAHAD21313/cve-2026-112652-secpolicy-research.svg) ![forks](https://img.shields.io/github/forks/FAHAD21313/cve-2026-112652-secpolicy-research.svg)


## CVE-2026-112611
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Processing a maliciously crafted PDF file may lead to memory corruption.

- [https://github.com/hkl1593246852-del/CVE-2026-112611](https://github.com/hkl1593246852-del/CVE-2026-112611) :  ![starts](https://img.shields.io/github/stars/hkl1593246852-del/CVE-2026-112611.svg) ![forks](https://img.shields.io/github/forks/hkl1593246852-del/CVE-2026-112611.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/googlesky/CVE-2026-128014](https://github.com/googlesky/CVE-2026-128014) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128014.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128014.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/sahmsec/CVE-2026-109618-PHP2SHELL](https://github.com/sahmsec/CVE-2026-109618-PHP2SHELL) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-109618-PHP2SHELL.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-109618-PHP2SHELL.svg)


## CVE-2026-105857
 Payload is a free and open source headless content management system. In @payloadcms/plugin-form-builder versions before 3.90.0 and canary versions before 4.0.0-canary.34, an attacker can craft a form submission that executes code remotely on the server. This issue is fixed in versions 3.90.0 and 4.0.0-canary.34.

- [https://github.com/fixedbyreboot/CVE-2026-105857-POC](https://github.com/fixedbyreboot/CVE-2026-105857-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-105857-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-105857-POC.svg)


## CVE-2026-105677
 Ghost is a Node.js content management system. From 6.10.3 until 6.64.0, a vulnerability in how Ghost loads theme translation files allowed an authenticated Administrator to execute arbitrary code on the server via a crafted theme. This issue is fixed in version 6.64.0.

- [https://github.com/fixedbyreboot/CVE-2026-105642-POC](https://github.com/fixedbyreboot/CVE-2026-105642-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-105642-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-105642-POC.svg)


## CVE-2026-105642
 Ghost is a Node.js content management system. From 6.56.0 until 6.67.0, an image processing library bundled with Ghost contained a vulnerability in its SVG handling. Any staff user, including Contributors, could create a bookmark card for an attacker-controlled website, resulting in arbitrary commands being run on the Ghost server. This issue is fixed in version 6.67.0.

- [https://github.com/fixedbyreboot/CVE-2026-105642-POC](https://github.com/fixedbyreboot/CVE-2026-105642-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-105642-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-105642-POC.svg)


## CVE-2026-105211
 ZITADEL before 4.17.1 contains an authentication bypass vulnerability in Login V2 that allows unauthenticated attackers to take over accounts by obtaining OTP codes via the returnCode delivery type. Attackers knowing a login name of a victim with OTP-Email and OTP-SMS enrolled can read both codes from server-action responses to gain MFA-authenticated sessions, including administrator takeover.

- [https://github.com/fixedbyreboot/CVE-2026-105211-POC](https://github.com/fixedbyreboot/CVE-2026-105211-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-105211-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-105211-POC.svg)


## CVE-2026-102895
 GPUStack is an open-source GPU cluster manager for AI model serving and GPU instance provisioning. Prior to 2.2.0, get_current_user in gpustack/api/auth.py treated a loopback request source as the built-in administrator when force_auth_localhost was false, which was the default. A remote request could appear to originate from 127.0.0.1 because client_ip_getter accepted a same-host reverse proxy peer or a client-supplied X-GPUStack-Real-IP loopback value. The bypass allowed unauthenticated administrative access, including user and model changes, persistent administrator API-key creation, disclosure of worker and cloud-provider secrets, and code execution through POST /v2/inference-backends/from-yaml. Exploitation was observed in the wild against a 2.1.1 deployment. This issue is fixed in version 2.2.0.

- [https://github.com/fixedbyreboot/CVE-2026-102895-POC](https://github.com/fixedbyreboot/CVE-2026-102895-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-102895-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-102895-POC.svg)


## CVE-2026-102894
 GPUStack is an open-source GPU cluster manager for AI model serving and GPU instance provisioning. From 0.7.1 until 2.2.2, the /auth/saml/callback endpoint decoded SAML XML, used its NameID and attributes to resolve or provision a user, and minted a gpustack_session JWT without calling OneLogin_Saml2_Auth.process_response to verify the signature, issuer, audience, destination, or time conditions. Any network client could submit an identity for an existing user, including an administrator, or provision a new non-administrator account, even when SAML was not configured. Response and Assertion identifiers were not consumed, so captured signed responses could also be replayed. This issue is fixed in version 2.2.2.

- [https://github.com/fixedbyreboot/CVE-2026-102895-POC](https://github.com/fixedbyreboot/CVE-2026-102895-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-102895-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-102895-POC.svg)


## CVE-2026-101107
 An OS command Injection issue exists in Air Terminal 6 provided by SoftBank Corp. Arbitrary commands may be executed with the root privilege by a user who can log in to the web management console of the affected product.

- [https://github.com/code-raisan/CVE-2026-101107-PoC-SBA6RCE-SAFETY](https://github.com/code-raisan/CVE-2026-101107-PoC-SBA6RCE-SAFETY) :  ![starts](https://img.shields.io/github/stars/code-raisan/CVE-2026-101107-PoC-SBA6RCE-SAFETY.svg) ![forks](https://img.shields.io/github/forks/code-raisan/CVE-2026-101107-PoC-SBA6RCE-SAFETY.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/jonrazta89/OneSamAKAGhostKey](https://github.com/jonrazta89/OneSamAKAGhostKey) :  ![starts](https://img.shields.io/github/stars/jonrazta89/OneSamAKAGhostKey.svg) ![forks](https://img.shields.io/github/forks/jonrazta89/OneSamAKAGhostKey.svg)
- [https://github.com/linux-tools/Shark-Root-Folk_for_VIVO_Y500i](https://github.com/linux-tools/Shark-Root-Folk_for_VIVO_Y500i) :  ![starts](https://img.shields.io/github/stars/linux-tools/Shark-Root-Folk_for_VIVO_Y500i.svg) ![forks](https://img.shields.io/github/forks/linux-tools/Shark-Root-Folk_for_VIVO_Y500i.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/wa6n3r/cve-2026-97229](https://github.com/wa6n3r/cve-2026-97229) :  ![starts](https://img.shields.io/github/stars/wa6n3r/cve-2026-97229.svg) ![forks](https://img.shields.io/github/forks/wa6n3r/cve-2026-97229.svg)


## CVE-2026-96349
 Unauthenticated Remote Code Execution (RCE) in SiteSkite = 2.1.8 versions.

- [https://github.com/1xPwn/exploit-CVE-2026-96349](https://github.com/1xPwn/exploit-CVE-2026-96349) :  ![starts](https://img.shields.io/github/stars/1xPwn/exploit-CVE-2026-96349.svg) ![forks](https://img.shields.io/github/forks/1xPwn/exploit-CVE-2026-96349.svg)


## CVE-2026-76954
 An improper neutralization of special elements used in an SQL command vulnerability in the Auth API in Synology DiskStation Manager (DSM) before 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, and 7.4.1-90080-1 allows remote attackers to read or write arbitrary files and conduct denial-of-service attacks.

- [https://github.com/googlesky/CVE-2026-76954](https://github.com/googlesky/CVE-2026-76954) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-76954.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-76954.svg)


## CVE-2026-74756
Version 3.9.1 onward sets a random credential by default on unprotected webadmin endpoints to prevent this while retain convenience.

- [https://github.com/fixedbyreboot/CVE-2026-74756-POC](https://github.com/fixedbyreboot/CVE-2026-74756-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-74756-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-74756-POC.svg)


## CVE-2026-73574
 In Zimbra Collaboration before 10.1.17, a local file inclusion (LFI) vulnerability exists in the Zimbra Classic Web Client due to improper validation of the fu request parameter. An unauthenticated attacker can exploit this vulnerability by supplying a crafted path, potentially allowing unauthorized disclosure of protected files, such as WEB-INF/web.xml, within the web application directory. This occurs in the Forward servlet.

- [https://github.com/fixedbyreboot/CVE-2026-73574-POC](https://github.com/fixedbyreboot/CVE-2026-73574-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-73574-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-73574-POC.svg)


## CVE-2026-68982
Users are advised to upgrade to apache-airflow 3.4.0 or later, in which the worker claims the callback through the Execution API, validating the token, before running it.

- [https://github.com/im0xfay/CVE-2026-68982](https://github.com/im0xfay/CVE-2026-68982) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-68982.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-68982.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/Sulisong/OnePlus16-Jailbreak](https://github.com/Sulisong/OnePlus16-Jailbreak) :  ![starts](https://img.shields.io/github/stars/Sulisong/OnePlus16-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/Sulisong/OnePlus16-Jailbreak.svg)


## CVE-2026-62253
 Homer is open source telecom observability software. Prior to version 11.0.283, both JWT middleware functions (`JWTMiddleware` and `JWTMiddlewareV4`) immediately return `next(c)` when `jwtSecret == ""`. The JWT secret defaults to an empty string. On a default installation, all protected API endpoints under `/api/v1`, `/api/v3`, and `/api/v4` are completely unauthenticated. Version 11.0.283 patches the issue.

- [https://github.com/fixedbyreboot/CVE-2026-62253-POC](https://github.com/fixedbyreboot/CVE-2026-62253-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-62253-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-62253-POC.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/Ayataaki/CVE_2026_46331](https://github.com/Ayataaki/CVE_2026_46331) :  ![starts](https://img.shields.io/github/stars/Ayataaki/CVE_2026_46331.svg) ![forks](https://img.shields.io/github/forks/Ayataaki/CVE_2026_46331.svg)


## CVE-2026-42530
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Udyz/CVE-2026-42530](https://github.com/Udyz/CVE-2026-42530) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-42530.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-42530.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/Arnau029/CVE-2026-39987-PoC](https://github.com/Arnau029/CVE-2026-39987-PoC) :  ![starts](https://img.shields.io/github/stars/Arnau029/CVE-2026-39987-PoC.svg) ![forks](https://img.shields.io/github/forks/Arnau029/CVE-2026-39987-PoC.svg)


## CVE-2026-27975
 Ajenti is a Linux and BSD modular server admin panel. Prior to version 2.2.13, an unauthenticated user could gain access to a server to execute arbitrary code on this server. This is fixed in the version 2.2.13.

- [https://github.com/fixedbyreboot/CVE-2026-27975-POC](https://github.com/fixedbyreboot/CVE-2026-27975-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-27975-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-27975-POC.svg)


## CVE-2026-25262
 Memory corruption while processing a crafted ELF file in the Primary Bootloader.

- [https://github.com/shuumaku/programmers](https://github.com/shuumaku/programmers) :  ![starts](https://img.shields.io/github/stars/shuumaku/programmers.svg) ![forks](https://img.shields.io/github/forks/shuumaku/programmers.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/debugactiveprocess/MaldocTrace](https://github.com/debugactiveprocess/MaldocTrace) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/MaldocTrace.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/MaldocTrace.svg)


## CVE-2026-21385
 Memory corruption while using alignments for memory allocation.

- [https://github.com/fancyzll/qualcomm-vulnerability-scanner](https://github.com/fancyzll/qualcomm-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/fancyzll/qualcomm-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/fancyzll/qualcomm-vulnerability-scanner.svg)


## CVE-2026-11176
 Inappropriate implementation in Media in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/jayeshpuri/CVE-2026-111760](https://github.com/jayeshpuri/CVE-2026-111760) :  ![starts](https://img.shields.io/github/stars/jayeshpuri/CVE-2026-111760.svg) ![forks](https://img.shields.io/github/forks/jayeshpuri/CVE-2026-111760.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/1Nightlovel/CVE-2026-109619](https://github.com/1Nightlovel/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109619.svg)


## CVE-2026-3764
 A vulnerability was determined in SourceCodester Client Database Management System 1.0. The impacted element is an unknown function of the file /superadmin_user_update.php. This manipulation causes improper authorization. The attack can be initiated remotely. The exploit has been publicly disclosed and may be utilized.

- [https://github.com/umair9747/CVE-2026-37640-tenda-hg21-telnet-backdoor](https://github.com/umair9747/CVE-2026-37640-tenda-hg21-telnet-backdoor) :  ![starts](https://img.shields.io/github/stars/umair9747/CVE-2026-37640-tenda-hg21-telnet-backdoor.svg) ![forks](https://img.shields.io/github/forks/umair9747/CVE-2026-37640-tenda-hg21-telnet-backdoor.svg)
- [https://github.com/umair9747/CVE-2026-37641-tenda-hg21-factory-endpoints](https://github.com/umair9747/CVE-2026-37641-tenda-hg21-factory-endpoints) :  ![starts](https://img.shields.io/github/stars/umair9747/CVE-2026-37641-tenda-hg21-factory-endpoints.svg) ![forks](https://img.shields.io/github/forks/umair9747/CVE-2026-37641-tenda-hg21-factory-endpoints.svg)
- [https://github.com/umair9747/CVE-2026-37643-tenda-hg21-omcishell-rce](https://github.com/umair9747/CVE-2026-37643-tenda-hg21-omcishell-rce) :  ![starts](https://img.shields.io/github/stars/umair9747/CVE-2026-37643-tenda-hg21-omcishell-rce.svg) ![forks](https://img.shields.io/github/forks/umair9747/CVE-2026-37643-tenda-hg21-omcishell-rce.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/LiliNothere/CVE-2026-109618](https://github.com/LiliNothere/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/LiliNothere/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/LiliNothere/CVE-2026-109618.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-30065
Users are recommended to upgrade to version 1.15.1, which fixes the issue.

- [https://github.com/zha0/CVE-2025-30065](https://github.com/zha0/CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/zha0/CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/zha0/CVE-2025-30065.svg)


## CVE-2025-23419
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/przemyslawbryzek/CVE-2025-23419](https://github.com/przemyslawbryzek/CVE-2025-23419) :  ![starts](https://img.shields.io/github/stars/przemyslawbryzek/CVE-2025-23419.svg) ![forks](https://img.shields.io/github/forks/przemyslawbryzek/CVE-2025-23419.svg)


## CVE-2025-15467
OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.

- [https://github.com/googlesky/CVE-2026-128027](https://github.com/googlesky/CVE-2026-128027) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128027.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128027.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/Kokila-Chandramohan/cups-cve-2024-47176](https://github.com/Kokila-Chandramohan/cups-cve-2024-47176) :  ![starts](https://img.shields.io/github/stars/Kokila-Chandramohan/cups-cve-2024-47176.svg) ![forks](https://img.shields.io/github/forks/Kokila-Chandramohan/cups-cve-2024-47176.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/SeVen-777777/cve-2024-4367-poc](https://github.com/SeVen-777777/cve-2024-4367-poc) :  ![starts](https://img.shields.io/github/stars/SeVen-777777/cve-2024-4367-poc.svg) ![forks](https://img.shields.io/github/forks/SeVen-777777/cve-2024-4367-poc.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/junhye-park/homework-sequelize-cve-2023-25813](https://github.com/junhye-park/homework-sequelize-cve-2023-25813) :  ![starts](https://img.shields.io/github/stars/junhye-park/homework-sequelize-cve-2023-25813.svg) ![forks](https://img.shields.io/github/forks/junhye-park/homework-sequelize-cve-2023-25813.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/HanaBouikni/Log4Shell-Incident-Report-CVE-2021-44228](https://github.com/HanaBouikni/Log4Shell-Incident-Report-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/HanaBouikni/Log4Shell-Incident-Report-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/HanaBouikni/Log4Shell-Incident-Report-CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/HanaBouikni/AppArmor-Simulation-CVE-2021-3156](https://github.com/HanaBouikni/AppArmor-Simulation-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/HanaBouikni/AppArmor-Simulation-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/HanaBouikni/AppArmor-Simulation-CVE-2021-3156.svg)
- [https://github.com/HanaBouikni/Volatility3-Forensics-Incident-Response](https://github.com/HanaBouikni/Volatility3-Forensics-Incident-Response) :  ![starts](https://img.shields.io/github/stars/HanaBouikni/Volatility3-Forensics-Incident-Response.svg) ![forks](https://img.shields.io/github/forks/HanaBouikni/Volatility3-Forensics-Incident-Response.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/debugactiveprocess/MaldocTrace](https://github.com/debugactiveprocess/MaldocTrace) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/MaldocTrace.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/MaldocTrace.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/Bri2327/vulnerables](https://github.com/Bri2327/vulnerables) :  ![starts](https://img.shields.io/github/stars/Bri2327/vulnerables.svg) ![forks](https://img.shields.io/github/forks/Bri2327/vulnerables.svg)

