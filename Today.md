# Update 2026-10-04
## CVE-2026-104356
 PictShare before version 3.7.1 contains a weak randomness vulnerability where the getRandomString() function uses the non-cryptographic rand() PRNG to generate the delete_code authorization token in src/inc/core.php. Attackers can predict or infer the PRNG state to guess valid delete_code values and perform unauthorized deletion of hosted files without needing to read the code from the info endpoint.

- [https://github.com/wvllxe/CVE-2026-104356-pictshare-weak-delete-code](https://github.com/wvllxe/CVE-2026-104356-pictshare-weak-delete-code) :  ![starts](https://img.shields.io/github/stars/wvllxe/CVE-2026-104356-pictshare-weak-delete-code.svg) ![forks](https://img.shields.io/github/forks/wvllxe/CVE-2026-104356-pictshare-weak-delete-code.svg)


## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/techupdate24/fortimail-zero-day-cve-2026-104286](https://github.com/techupdate24/fortimail-zero-day-cve-2026-104286) :  ![starts](https://img.shields.io/github/stars/techupdate24/fortimail-zero-day-cve-2026-104286.svg) ![forks](https://img.shields.io/github/forks/techupdate24/fortimail-zero-day-cve-2026-104286.svg)


## CVE-2026-104051
 PictShare before 3.7.1 contains an information disclosure vulnerability that allows unauthenticated attackers to obtain the secret delete_code and uploader metadata by calling the API::info() endpoint which returns the complete raw metadata object without a field whitelist. Attackers can use the publicly visible file hash to retrieve the delete_code via the info API and then invoke the delete API to permanently delete arbitrary files, while also exposing uploader IP, User Agent, remote port, and SHA-1 hash, resulting in loss of content integrity, availability, and uploader privacy.

- [https://github.com/wvllxe/CVE-2026-104051-pictshare-info-disclosure](https://github.com/wvllxe/CVE-2026-104051-pictshare-info-disclosure) :  ![starts](https://img.shields.io/github/stars/wvllxe/CVE-2026-104051-pictshare-info-disclosure.svg) ![forks](https://img.shields.io/github/forks/wvllxe/CVE-2026-104051-pictshare-info-disclosure.svg)


## CVE-2026-103922
 Capacitor is a cross-platform native runtime for web applications. From 6.0.0 until 6.2.2, 7.6.9, 8.3.5, 8.4.3, and 8.5.1, the Android and iOS WebView navigation guard validates a target URL's host and scheme but not its path, allowing a victim who activates an untrusted link to navigate a frame to /_capacitor_http_interceptor_. The native proxy can fetch an attacker-selected URL and return the response as a document at the application's own origin, allowing script in that response to access same-origin storage, cookies, and registered Capacitor plugin capabilities. Applications remain affected when CapacitorHttp is disabled because affected releases serve the proxy path regardless of that setting. This issue is fixed in versions 6.2.2, 7.6.9, 8.3.5, 8.4.3, and 8.5.1.

- [https://github.com/techupdate24/capacitor-flaw-cve-2026-103922](https://github.com/techupdate24/capacitor-flaw-cve-2026-103922) :  ![starts](https://img.shields.io/github/stars/techupdate24/capacitor-flaw-cve-2026-103922.svg) ![forks](https://img.shields.io/github/forks/techupdate24/capacitor-flaw-cve-2026-103922.svg)


## CVE-2026-103752
 Unauthenticated Privilege Escalation in Authorizer = 3.15.3 versions.

- [https://github.com/anoxhunterdump-ctrl/CVE-2026-103752-Authorizer-Privilege-Escalation](https://github.com/anoxhunterdump-ctrl/CVE-2026-103752-Authorizer-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/anoxhunterdump-ctrl/CVE-2026-103752-Authorizer-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/anoxhunterdump-ctrl/CVE-2026-103752-Authorizer-Privilege-Escalation.svg)


## CVE-2026-102268
 PyJWT is a Python implementation of JSON Web Token standards. Prior to 2.14.0, is_pem_format in jwt/utils.py is affected because is_pem_format does not recognize every PEM representation accepted by the cryptography loader. This occurs when an application mixes HMAC and asymmetric algorithms and supplies a mutated public-key PEM as raw key bytes. As a result, HMACAlgorithm.prepare_key treats the unrecognized asymmetric public key as an HMAC secret. Consequently, an attacker who knows the public key can forge authenticated HMAC tokens. This issue is fixed in version 2.14.0.

- [https://github.com/covepseng/cve-2026-102268-poc](https://github.com/covepseng/cve-2026-102268-poc) :  ![starts](https://img.shields.io/github/stars/covepseng/cve-2026-102268-poc.svg) ![forks](https://img.shields.io/github/forks/covepseng/cve-2026-102268-poc.svg)


## CVE-2026-100520
 Laranode versions before 1.2.1 contain a path traversal vulnerability in the POST /filemanager/upload-file endpoint that allows authenticated users to write arbitrary files outside their home directory. Attackers can supply directory traversal sequences in the path parameter to write PHP files into other tenants' web roots and execute code as those tenants.

- [https://github.com/wvllxe/CVE-2026-100520-laranode-path-traversal](https://github.com/wvllxe/CVE-2026-100520-laranode-path-traversal) :  ![starts](https://img.shields.io/github/stars/wvllxe/CVE-2026-100520-laranode-path-traversal.svg) ![forks](https://img.shields.io/github/forks/wvllxe/CVE-2026-100520-laranode-path-traversal.svg)


## CVE-2026-94541
 The WPMobile.App – Android and iOS App Builder plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 11.82 This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for unauthenticated attackers to exfiltrate password-reset URLs for arbitrary users, including administrators, mirrored into the push queue by the mail-to-push feature, and use those URLs to take over the targeted accounts. This exploit chain requires the plugin's mail-to-push feature (wpmobile_auto_mail=1) to be enabled, as that setting is what causes outbound WordPress password-reset emails — including the reset URL and key — to be mirrored into the push row queue where they become accessible to the attacker.

- [https://github.com/anoxhunterdump-ctrl/CVE-2026-94541-WPMobileApp-AuthBypass](https://github.com/anoxhunterdump-ctrl/CVE-2026-94541-WPMobileApp-AuthBypass) :  ![starts](https://img.shields.io/github/stars/anoxhunterdump-ctrl/CVE-2026-94541-WPMobileApp-AuthBypass.svg) ![forks](https://img.shields.io/github/forks/anoxhunterdump-ctrl/CVE-2026-94541-WPMobileApp-AuthBypass.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/Scyrix-LLC/CVE-2026-88773](https://github.com/Scyrix-LLC/CVE-2026-88773) :  ![starts](https://img.shields.io/github/stars/Scyrix-LLC/CVE-2026-88773.svg) ![forks](https://img.shields.io/github/forks/Scyrix-LLC/CVE-2026-88773.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/orjanj/netscaler_threat_hunt_helper](https://github.com/orjanj/netscaler_threat_hunt_helper) :  ![starts](https://img.shields.io/github/stars/orjanj/netscaler_threat_hunt_helper.svg) ![forks](https://img.shields.io/github/forks/orjanj/netscaler_threat_hunt_helper.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/orjanj/netscaler_threat_hunt_helper](https://github.com/orjanj/netscaler_threat_hunt_helper) :  ![starts](https://img.shields.io/github/stars/orjanj/netscaler_threat_hunt_helper.svg) ![forks](https://img.shields.io/github/forks/orjanj/netscaler_threat_hunt_helper.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/decalage2/detect_CVE-2026-86950](https://github.com/decalage2/detect_CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/decalage2/detect_CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/decalage2/detect_CVE-2026-86950.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/Meniben/redmi14c-pond-cve-2026-64560](https://github.com/Meniben/redmi14c-pond-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/Meniben/redmi14c-pond-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/Meniben/redmi14c-pond-cve-2026-64560.svg)


## CVE-2026-63292
Users are recommended to upgrade to version 2.4.69, which fixes this issue.

- [https://github.com/0xBlackash/CVE-2026-63292](https://github.com/0xBlackash/CVE-2026-63292) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-63292.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-63292.svg)


## CVE-2026-57973
 Time-of-check time-of-use (toctou) race condition in Windows Subsystem for Linux allows an authorized attacker to perform tampering locally.

- [https://github.com/riddhimaan-sth404/CVE-2026-57973](https://github.com/riddhimaan-sth404/CVE-2026-57973) :  ![starts](https://img.shields.io/github/stars/riddhimaan-sth404/CVE-2026-57973.svg) ![forks](https://img.shields.io/github/forks/riddhimaan-sth404/CVE-2026-57973.svg)


## CVE-2026-56129
 Generic IO & Memory Access driver for PCs provided by TOSHIBA CORPORATION and Dynabook Inc. exposes its IOCTL with insufficient access control. A logged-in user with no administrative privilege may access physical memory.

- [https://github.com/valium007/CVE-2026-56129](https://github.com/valium007/CVE-2026-56129) :  ![starts](https://img.shields.io/github/stars/valium007/CVE-2026-56129.svg) ![forks](https://img.shields.io/github/forks/valium007/CVE-2026-56129.svg)


## CVE-2026-55559
 Yamcs is a mission control framework. Prior to 5.12.8 and 5.13.2, Yamcs inserts templateArgs from POST /api/instances and PATCH /api/instances/{instance} into YAML through VarStatement.append in yamcs-core/src/main/java/org/yamcs/templating/VarStatement.java without YAML-context escaping. The rendered configuration is parsed by YamcsServer.createInstance and loaded by YamcsServerInstance, allowing an attacker to inject a services entry for org.yamcs.ProcessRunner. Deployments without security.yaml expose the operation through the guest superuser, while secured deployments require SystemPrivilege.CreateInstances. Successful exploitation executes commands as the Yamcs service account. This issue is fixed in versions 5.12.8 and 5.13.2.

- [https://github.com/MRdark-ops/CVE-2026-55559](https://github.com/MRdark-ops/CVE-2026-55559) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-55559.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-55559.svg)


## CVE-2026-45805
 Penpot is an open-source design tool for design and code collaboration. Prior to 2.15.0, Penpot MCP's mcp/packages/server/src/ReplServer.ts bound the ReplServer to 0.0.0.0:4403 and exposed an unauthenticated /execute endpoint that passed the code field to PluginBridge.executePluginTask(), allowing anyone on the network to execute JavaScript on the server. This issue is fixed in version 2.15.0.

- [https://github.com/overgrowncarrot1/PenPot-RCE](https://github.com/overgrowncarrot1/PenPot-RCE) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/PenPot-RCE.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/PenPot-RCE.svg)


## CVE-2026-44011
 Craft CMS is a content management system (CMS). From 4.0.0 to before 4.17.12 and 5.9.18, Craft CMS which contains an input-handling flaw in a Yii object creation path that let any authenticated user inject malicious configuration and execute arbitrary commands on the server. The request-controlled condition field layouts data is converted into a live FieldLayout object without a Component::cleanseConfig() boundary. Because Craft configures models before parent::__construct(), attacker-controlled special config keys can take effect during object creation, and FieldLayout initialization then triggers a same-request event. This vulnerability is fixed in 4.17.12 and 5.9.18.

- [https://github.com/0xyngtg/CraftCMS-CVE-2026-44011-PoC-RCE](https://github.com/0xyngtg/CraftCMS-CVE-2026-44011-PoC-RCE) :  ![starts](https://img.shields.io/github/stars/0xyngtg/CraftCMS-CVE-2026-44011-PoC-RCE.svg) ![forks](https://img.shields.io/github/forks/0xyngtg/CraftCMS-CVE-2026-44011-PoC-RCE.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/zenyxx-xd/RootMyVivo-Exploit](https://github.com/zenyxx-xd/RootMyVivo-Exploit) :  ![starts](https://img.shields.io/github/stars/zenyxx-xd/RootMyVivo-Exploit.svg) ![forks](https://img.shields.io/github/forks/zenyxx-xd/RootMyVivo-Exploit.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/ankitrawatgit/DirtyFrag-Android-Root-Jailbreak](https://github.com/ankitrawatgit/DirtyFrag-Android-Root-Jailbreak) :  ![starts](https://img.shields.io/github/stars/ankitrawatgit/DirtyFrag-Android-Root-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/ankitrawatgit/DirtyFrag-Android-Root-Jailbreak.svg)


## CVE-2026-42589
 Gotenberg is a Docker-powered stateless API for PDF files. Prior to 8.31.0, Gotenberg's /forms/pdfengines/metadata/write HTTP endpoint accepts a JSON metadata object and passes its keys directly to ExifTool via the go-exiftool library. No validation is performed on key characters. A \n embedded in a JSON key splits the ExifTool stdin stream into a new argument line, allowing an attacker to inject arbitrary ExifTool flags — including -if, which evaluates Perl expressions. This achieves unauthenticated OS command execution in a single HTTP request. The response is HTTP 200 with a valid PDF, making the attack transparent to basic monitoring. This vulnerability is fixed in 8.31.0.

- [https://github.com/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC](https://github.com/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC.svg)


## CVE-2026-42322
 Piwigo is a full featured open source photo gallery application for the web. Prior to 16.4.0, admin/themes_standard_pages.php validates uploaded logo content by MIME type but reuses the attacker-controlled extension from std_pgs_logo when constructing the stored filename. An authenticated administrator can upload image content with a server-executable final extension, causing the file to be placed in the web-accessible logo directory and executed when requested if the web server handles that extension. This can permit arbitrary command execution, data disclosure, modification, persistence, and service disruption. This vulnerability is fixed in 16.4.0.

- [https://github.com/LipeOzyy/CVE-2026-42322](https://github.com/LipeOzyy/CVE-2026-42322) :  ![starts](https://img.shields.io/github/stars/LipeOzyy/CVE-2026-42322.svg) ![forks](https://img.shields.io/github/forks/LipeOzyy/CVE-2026-42322.svg)


## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.

- [https://github.com/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC](https://github.com/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-42589xCVE-2026-40281-PoC.svg)
- [https://github.com/MRdark-ops/CVE-2026-40281-exploit](https://github.com/MRdark-ops/CVE-2026-40281-exploit) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-40281-exploit.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-40281-exploit.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/Th3Purge/CVE-2026-39987](https://github.com/Th3Purge/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/Th3Purge/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/Th3Purge/CVE-2026-39987.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/sec17br/CVE-2026-31431-Copy-Fail](https://github.com/sec17br/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/sec17br/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/sec17br/CVE-2026-31431-Copy-Fail.svg)


## CVE-2026-24301
 Improper neutralization of special elements used in a command ('command injection') in Microsoft Copilot allows an unauthorized attacker to disclose information over a network.

- [https://github.com/CSOAI-ORG/memory-poisoning-axis](https://github.com/CSOAI-ORG/memory-poisoning-axis) :  ![starts](https://img.shields.io/github/stars/CSOAI-ORG/memory-poisoning-axis.svg) ![forks](https://img.shields.io/github/forks/CSOAI-ORG/memory-poisoning-axis.svg)


## CVE-2026-19660
 The Divi Membership plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 2.3.0. The `process_paypal_callback` function, hooked to the `init` action, accepts a base64-encoded `paypal_param` GET parameter with no IPN validation, no cryptographic signature check, no ownership verification, and no nonce, allowing it to trust an entirely attacker-controlled user ID value that is passed directly to `wp_set_current_user()` and `wp_set_auth_cookie()`. This makes it possible for unauthenticated attackers to log in as any existing WordPress user — including administrators — by supplying an arbitrary user ID in the `paypal_param` GET parameter, resulting in full site takeover. The vulnerability is further compounded by the fact that the PayPal gateway class is instantiated unconditionally regardless of whether PayPal is enabled or configured, ensuring the vulnerable hook is always registered on every front-end request.

- [https://github.com/murrez/CVE-2026-19660](https://github.com/murrez/CVE-2026-19660) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-19660.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-19660.svg)


## CVE-2026-19553
isn't supplied.

- [https://github.com/abraxas/cve-2026-19553-wrap-bio](https://github.com/abraxas/cve-2026-19553-wrap-bio) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-19553-wrap-bio.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-19553-wrap-bio.svg)


## CVE-2026-19445
the lifetime of the server. TLS clients are not affected.

- [https://github.com/abraxas/cve-2026-19445-sni-uaf](https://github.com/abraxas/cve-2026-19445-sni-uaf) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-19445-sni-uaf.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-19445-sni-uaf.svg)


## CVE-2026-15989
 The Super Forms – Drag & Drop Form Builder plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3.316. This is due to the Register & Login add-on's before_email_success_msg() function whitelisting the client-submitted 'role' key and copying it into the user-data array that is passed directly to wp_insert_user(), without validating the submitted role against the administrator-configured register_user_role, without an allow-list, and without any current_user_can() capability check. This makes it possible for unauthenticated attackers to register a new account with the Administrator role by injecting role=administrator into the data submitted to any published Super Forms registration form (register_login_action='register').

- [https://github.com/fl0ydsec/CVE-2026-15989](https://github.com/fl0ydsec/CVE-2026-15989) :  ![starts](https://img.shields.io/github/stars/fl0ydsec/CVE-2026-15989.svg) ![forks](https://img.shields.io/github/forks/fl0ydsec/CVE-2026-15989.svg)


## CVE-2026-14378
 The DevKit Pro plugin for WordPress is vulnerable to Authentication Bypass Leading to Administrator Account Takeover in all versions up to, and including, 2.3.0 This is due to the `revert_switch` handler trusting the attacker-controlled `original_user_id` cookie as the privileged identity: `verify_nonce_and_capability()` incorrectly checks the `manage_options` capability on the user identified by the cookie rather than on the actual requester via `current_user_can()`, while the switch-back form and a valid session-bound nonce are emitted publicly via `wp_footer` to any visitor — including unauthenticated users — whenever that cookie is present. This makes it possible for unauthenticated attackers to set the `original_user_id` cookie to any administrator's user ID, collect the rendered nonce, and POST it back to the `revert_switch` handler, causing `wp_set_auth_cookie()` to be called with the administrator's ID and granting the attacker a full administrator-level authenticated session and complete site takeover.

- [https://github.com/murrez/CVE-2026-14378](https://github.com/murrez/CVE-2026-14378) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-14378.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-14378.svg)
- [https://github.com/anoxhunterdump-ctrl/CVE-2026-14378-DevKit-Pro-Auth-Bypass](https://github.com/anoxhunterdump-ctrl/CVE-2026-14378-DevKit-Pro-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/anoxhunterdump-ctrl/CVE-2026-14378-DevKit-Pro-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/anoxhunterdump-ctrl/CVE-2026-14378-DevKit-Pro-Auth-Bypass.svg)


## CVE-2026-10228
 A vulnerability was found in raisulislamg4 student_management_system_by_php up to 310d950e09013d5133c6b9210aff9444382d16d1. The impacted element is an unknown function of the file admission_form_check.php. The manipulation of the argument Message results in cross site scripting. The attack can be executed remotely. The exploit has been made public and could be used. This product implements a rolling release for ongoing delivery, which means version information for affected or updated releases is unavailable. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/Ahmed-Elmahgob/POC-CVE-2026-102282](https://github.com/Ahmed-Elmahgob/POC-CVE-2026-102282) :  ![starts](https://img.shields.io/github/stars/Ahmed-Elmahgob/POC-CVE-2026-102282.svg) ![forks](https://img.shields.io/github/forks/Ahmed-Elmahgob/POC-CVE-2026-102282.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/timgad794/Abducted-HTB-Writeup](https://github.com/timgad794/Abducted-HTB-Writeup) :  ![starts](https://img.shields.io/github/stars/timgad794/Abducted-HTB-Writeup.svg) ![forks](https://img.shields.io/github/forks/timgad794/Abducted-HTB-Writeup.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/inforcqb/CVE-2026-43499-pja110](https://github.com/inforcqb/CVE-2026-43499-pja110) :  ![starts](https://img.shields.io/github/stars/inforcqb/CVE-2026-43499-pja110.svg) ![forks](https://img.shields.io/github/forks/inforcqb/CVE-2026-43499-pja110.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/insomnisec/Detections-CVE-2026-31431](https://github.com/insomnisec/Detections-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/insomnisec/Detections-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/insomnisec/Detections-CVE-2026-31431.svg)


## CVE-2026-1048
 A weakness has been identified in LigeroSmart up to 6.1.26. Impacted is an unknown function of the file /otrs/index.pl?Action=AgentTicketZoom. This manipulation of the argument TicketID causes cross site scripting. It is possible to initiate the attack remotely. The exploit has been made available to the public and could be used for attacks. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/KiwKNR/CVE-2026-104826](https://github.com/KiwKNR/CVE-2026-104826) :  ![starts](https://img.shields.io/github/stars/KiwKNR/CVE-2026-104826.svg) ![forks](https://img.shields.io/github/forks/KiwKNR/CVE-2026-104826.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-45737
 An issue in NetEase (Hangzhou) Network Co., Ltd NeacSafe64 Driver before v1.0.0.8 allows attackers to escalate privileges via sending crafted IOCTL commands to the NeacSafe64.sys component.

- [https://github.com/Shinn-Home/CVE-2025-45737](https://github.com/Shinn-Home/CVE-2025-45737) :  ![starts](https://img.shields.io/github/stars/Shinn-Home/CVE-2025-45737.svg) ![forks](https://img.shields.io/github/forks/Shinn-Home/CVE-2025-45737.svg)


## CVE-2025-24801
 GLPI is a free asset and IT management software package. An authenticated user can upload and force the execution of *.php files located on the GLPI server. This vulnerability is fixed in 10.0.18.

- [https://github.com/kevenpanchal/CVE-2025-24801-GLPI-10.0.17-and-prior-Authenticated-RCE](https://github.com/kevenpanchal/CVE-2025-24801-GLPI-10.0.17-and-prior-Authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/kevenpanchal/CVE-2025-24801-GLPI-10.0.17-and-prior-Authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/kevenpanchal/CVE-2025-24801-GLPI-10.0.17-and-prior-Authenticated-RCE.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/longg66/cve-2025-21479_iqooneo7speed](https://github.com/longg66/cve-2025-21479_iqooneo7speed) :  ![starts](https://img.shields.io/github/stars/longg66/cve-2025-21479_iqooneo7speed.svg) ![forks](https://img.shields.io/github/forks/longg66/cve-2025-21479_iqooneo7speed.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/rszqx/CVE-2024-9465](https://github.com/rszqx/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/rszqx/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/rszqx/CVE-2024-9465.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-](https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-) :  ![starts](https://img.shields.io/github/stars/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg) ![forks](https://img.shields.io/github/forks/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)
- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/r0otk3r/CVE-2021-41773](https://github.com/r0otk3r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2017-12561
 A remote code execution vulnerability in HPE intelligent Management Center (iMC) PLAT version Plat 7.3 E0504P4 and earlier was found.

- [https://github.com/parapapinho/CVE-2017-12561](https://github.com/parapapinho/CVE-2017-12561) :  ![starts](https://img.shields.io/github/stars/parapapinho/CVE-2017-12561.svg) ![forks](https://img.shields.io/github/forks/parapapinho/CVE-2017-12561.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/Th3Purge/CVE-2017-7921-Exploit](https://github.com/Th3Purge/CVE-2017-7921-Exploit) :  ![starts](https://img.shields.io/github/stars/Th3Purge/CVE-2017-7921-Exploit.svg) ![forks](https://img.shields.io/github/forks/Th3Purge/CVE-2017-7921-Exploit.svg)


## CVE-2016-1555
 (1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute arbitrary commands.

- [https://github.com/0xd3mr/netgear_wnap320-firmware-reversing](https://github.com/0xd3mr/netgear_wnap320-firmware-reversing) :  ![starts](https://img.shields.io/github/stars/0xd3mr/netgear_wnap320-firmware-reversing.svg) ![forks](https://img.shields.io/github/forks/0xd3mr/netgear_wnap320-firmware-reversing.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/mujtaba815/metasploitable2-php-cgi-exploit](https://github.com/mujtaba815/metasploitable2-php-cgi-exploit) :  ![starts](https://img.shields.io/github/stars/mujtaba815/metasploitable2-php-cgi-exploit.svg) ![forks](https://img.shields.io/github/forks/mujtaba815/metasploitable2-php-cgi-exploit.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Spidey1919/vsftpd-2.3.4-rce-assessment](https://github.com/Spidey1919/vsftpd-2.3.4-rce-assessment) :  ![starts](https://img.shields.io/github/stars/Spidey1919/vsftpd-2.3.4-rce-assessment.svg) ![forks](https://img.shields.io/github/forks/Spidey1919/vsftpd-2.3.4-rce-assessment.svg)

