# Update 2026-08-21
## CVE-2026-73072
 Vim is an open source, command line text editor. Prior to 9.2.0846, set_sofo() in src/spellfile.c reuses sl_sal_first[] without resetting values left by set_sal_first(), so a crafted spell file containing an SN_SAL section before an SN_SOFO section causes under-counted mapping lists and attacker-influenced writes beyond a heap allocation. This issue is fixed in version 9.2.0846.

- [https://github.com/HORKimhab/CVE-2026-73072](https://github.com/HORKimhab/CVE-2026-73072) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-73072.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-73072.svg)


## CVE-2026-68083
removed.

- [https://github.com/TurtleARM/ksmbrace](https://github.com/TurtleARM/ksmbrace) :  ![starts](https://img.shields.io/github/stars/TurtleARM/ksmbrace.svg) ![forks](https://img.shields.io/github/forks/TurtleARM/ksmbrace.svg)


## CVE-2026-67919
 An issue in Halo 2.25.4 allows a remote attacker to execute arbitrary code via the PluginEndpoint.java, installFromUri method, and DefaultPluginApplicationContextFactory components

- [https://github.com/k0nnect/halo-cve-2026-67919](https://github.com/k0nnect/halo-cve-2026-67919) :  ![starts](https://img.shields.io/github/stars/k0nnect/halo-cve-2026-67919.svg) ![forks](https://img.shields.io/github/forks/k0nnect/halo-cve-2026-67919.svg)


## CVE-2026-64849
 MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. Prior to 3.15.0, the unauthenticated POST /api/2.0/mlflow/webhooks/{id}/test endpoint calls _validate_webhook_url() in mlflow/utils/validation.py only for the original URL while mlflow/webhooks/delivery.py follows redirects and re-resolves the hostname without pinning the validated address, allowing attackers to reach internal or cloud metadata services and receive response_status and response_body. This issue is fixed in version 3.15.0.

- [https://github.com/BiuTrap/CVE-2026-64849](https://github.com/BiuTrap/CVE-2026-64849) :  ![starts](https://img.shields.io/github/stars/BiuTrap/CVE-2026-64849.svg) ![forks](https://img.shields.io/github/forks/BiuTrap/CVE-2026-64849.svg)
- [https://github.com/zavisco/CVE-2026-64849.yaml](https://github.com/zavisco/CVE-2026-64849.yaml) :  ![starts](https://img.shields.io/github/stars/zavisco/CVE-2026-64849.yaml.svg) ![forks](https://img.shields.io/github/forks/zavisco/CVE-2026-64849.yaml.svg)


## CVE-2026-64564
branch can never reuse a freed transport.

- [https://github.com/0xdeadroot/SCTPhantom-CVE-2026-64564](https://github.com/0xdeadroot/SCTPhantom-CVE-2026-64564) :  ![starts](https://img.shields.io/github/stars/0xdeadroot/SCTPhantom-CVE-2026-64564.svg) ![forks](https://img.shields.io/github/forks/0xdeadroot/SCTPhantom-CVE-2026-64564.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-](https://github.com/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-) :  ![starts](https://img.shields.io/github/stars/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-.svg) ![forks](https://img.shields.io/github/forks/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-.svg)


## CVE-2026-61241
 Vulnerability in the Oracle Internet Directory product of Oracle Fusion Middleware (component: OID LDAP Server).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via LDAP to compromise Oracle Internet Directory.  While the vulnerability is in Oracle Internet Directory, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle Internet Directory. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/Godliveanton/CVE-2026-61241](https://github.com/Godliveanton/CVE-2026-61241) :  ![starts](https://img.shields.io/github/stars/Godliveanton/CVE-2026-61241.svg) ![forks](https://img.shields.io/github/forks/Godliveanton/CVE-2026-61241.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-](https://github.com/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-) :  ![starts](https://img.shields.io/github/stars/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-.svg) ![forks](https://img.shields.io/github/forks/TranDongA3/POC-CVE-2026-63030-CVE-2026-60137-.svg)


## CVE-2026-56848
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/open-flaw/CVE-2026-56848](https://github.com/open-flaw/CVE-2026-56848) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2026-56848.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2026-56848.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/L0u7r3/certighost](https://github.com/L0u7r3/certighost) :  ![starts](https://img.shields.io/github/stars/L0u7r3/certighost.svg) ![forks](https://img.shields.io/github/forks/L0u7r3/certighost.svg)


## CVE-2026-53959
 4gaBoards is a boards system for realtime project management. Prior to 3.3.9, 4gaBoards allows any authenticated user to enumerate account information for every user through GET /api/users and retrieve arbitrary accounts through GET /api/users/:id. The users/index and users/show actions rely only on the default is-authenticated policy in server/config/policies.js, and server/api/controllers/users/index.js returns the result of sails.helpers.users.getMany() without requester-specific authorization or response sanitization. Responses expose email, phone, organization, name, isAdmin, ssoGoogleEmail, ssoGithubEmail, and other SSO-linked email fields, including data for administrators. This enables instance-wide user enumeration, privacy loss, and targeted phishing reconnaissance. This issue is fixed in version 3.3.9.

- [https://github.com/anirbala98/CVE-2026-53959](https://github.com/anirbala98/CVE-2026-53959) :  ![starts](https://img.shields.io/github/stars/anirbala98/CVE-2026-53959.svg) ![forks](https://img.shields.io/github/forks/anirbala98/CVE-2026-53959.svg)


## CVE-2026-53547
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. Prior to 2.3.2, the POST /database/export endpoint creates a user export that includes the global settings table even though the rest of the export is user-scoped. The settings table contains reset_code_ and temp_reset_token_ password-reset artifacts, allowing a low-privileged authenticated user to recover another local account's reset code and complete the normal password-reset flow. Successful exploitation results in local-user account takeover and administrative compromise when the victim is an administrator. This issue is fixed in version 2.3.2.

- [https://github.com/GabrielHA12/Termix-research](https://github.com/GabrielHA12/Termix-research) :  ![starts](https://img.shields.io/github/stars/GabrielHA12/Termix-research.svg) ![forks](https://img.shields.io/github/forks/GabrielHA12/Termix-research.svg)


## CVE-2026-53365
but was pre-existing.

- [https://github.com/HackSpeak/CVE-2026-53365](https://github.com/HackSpeak/CVE-2026-53365) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-53365.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-53365.svg)


## CVE-2026-47858
Spring Tools for VSCode / Cursor / Theia: 2.2.0 and earlier

- [https://github.com/realstatus/CVE-2026-47858](https://github.com/realstatus/CVE-2026-47858) :  ![starts](https://img.shields.io/github/stars/realstatus/CVE-2026-47858.svg) ![forks](https://img.shields.io/github/forks/realstatus/CVE-2026-47858.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/mobilehackinglab/ghostlock-a17](https://github.com/mobilehackinglab/ghostlock-a17) :  ![starts](https://img.shields.io/github/stars/mobilehackinglab/ghostlock-a17.svg) ![forks](https://img.shields.io/github/forks/mobilehackinglab/ghostlock-a17.svg)
- [https://github.com/xrzcc/s26-m1q-ghostlock-selinux](https://github.com/xrzcc/s26-m1q-ghostlock-selinux) :  ![starts](https://img.shields.io/github/stars/xrzcc/s26-m1q-ghostlock-selinux.svg) ![forks](https://img.shields.io/github/forks/xrzcc/s26-m1q-ghostlock-selinux.svg)
- [https://github.com/oopnv70-lab/ghostlock-honor-aak-probe](https://github.com/oopnv70-lab/ghostlock-honor-aak-probe) :  ![starts](https://img.shields.io/github/stars/oopnv70-lab/ghostlock-honor-aak-probe.svg) ![forks](https://img.shields.io/github/forks/oopnv70-lab/ghostlock-honor-aak-probe.svg)
- [https://github.com/virtualesp/SpringPeace](https://github.com/virtualesp/SpringPeace) :  ![starts](https://img.shields.io/github/stars/virtualesp/SpringPeace.svg) ![forks](https://img.shields.io/github/forks/virtualesp/SpringPeace.svg)
- [https://github.com/zychen027/CVE-2026-43499_HW-CLT-AL01](https://github.com/zychen027/CVE-2026-43499_HW-CLT-AL01) :  ![starts](https://img.shields.io/github/stars/zychen027/CVE-2026-43499_HW-CLT-AL01.svg) ![forks](https://img.shields.io/github/forks/zychen027/CVE-2026-43499_HW-CLT-AL01.svg)
- [https://github.com/XiaoBaiLovesStirring/ghostlock-custom](https://github.com/XiaoBaiLovesStirring/ghostlock-custom) :  ![starts](https://img.shields.io/github/stars/XiaoBaiLovesStirring/ghostlock-custom.svg) ![forks](https://img.shields.io/github/forks/XiaoBaiLovesStirring/ghostlock-custom.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/cyber-niz/Dirty-Frag](https://github.com/cyber-niz/Dirty-Frag) :  ![starts](https://img.shields.io/github/stars/cyber-niz/Dirty-Frag.svg) ![forks](https://img.shields.io/github/forks/cyber-niz/Dirty-Frag.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/lanicer/cve-2026-41940-PoC](https://github.com/lanicer/cve-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/lanicer/cve-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/lanicer/cve-2026-41940-PoC.svg)
- [https://github.com/Rosemary1337/CVE-2026-41940](https://github.com/Rosemary1337/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Rosemary1337/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Rosemary1337/CVE-2026-41940.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/jelasin/CVE-2026-41089](https://github.com/jelasin/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/jelasin/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/jelasin/CVE-2026-41089.svg)


## CVE-2026-40179
 Prometheus is an open-source monitoring system and time series database. Versions 3.0 through 3.5.1 and 3.6.0 through 3.11.1 have stored cross-site scripting vulnerabilities in multiple components of the Prometheus web UI where metric names and label values are injected into innerHTML without escaping. In both the Mantine UI and old React UI, chart tooltips on the Graph page render metric names containing HTML/JavaScript without sanitization. In the old React UI, the Metric Explorer fuzzy search results use dangerouslySetInnerHTML without escaping, and heatmap cell tooltips interpolate le label values without sanitization. With Prometheus v3.x defaulting to UTF-8 metric and label name validation, characters like , , and " are now valid in metric names and labels. An attacker who can inject metrics via a compromised scrape target, remote write, or OTLP receiver endpoint can execute arbitrary JavaScript in the browser of any Prometheus user who views the metric in the Graph UI, potentially enabling configuration exfiltration, data deletion, or Prometheus shutdown depending on enabled flags. This issue has been fixed in versions 3.5.2 and 3.11.2. If developers are unable to immediately update, the following workarounds are recommended: ensure that the remote write receiver (--web.enable-remote-write-receiver) and the OTLP receiver (--web.enable-otlp-receiver) are not exposed to untrusted sources; verify that all scrape targets are trusted and not under attacker control; avoid enabling admin or mutating API endpoints (e.g., --web.enable-admin-api or --web.enable-lifecycle) in environments where untrusted data may be ingested; and refrain from clicking untrusted links, particularly those containing functions such as label_replace, as they may generate poisoned label names and values.

- [https://github.com/bsdrip/CVE-2026-40179-PoC](https://github.com/bsdrip/CVE-2026-40179-PoC) :  ![starts](https://img.shields.io/github/stars/bsdrip/CVE-2026-40179-PoC.svg) ![forks](https://img.shields.io/github/forks/bsdrip/CVE-2026-40179-PoC.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/K3ysTr0K3R/CVE-2026-39987](https://github.com/K3ysTr0K3R/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-39987.svg)


## CVE-2026-34486
Users are recommended to upgrade to version 11.0.21, 10.1.54 or 9.0.117, which fix the issue.

- [https://github.com/CypherHippie/CVE-2026-34486---unauthenticated-RCE-via-Java-deserialization](https://github.com/CypherHippie/CVE-2026-34486---unauthenticated-RCE-via-Java-deserialization) :  ![starts](https://img.shields.io/github/stars/CypherHippie/CVE-2026-34486---unauthenticated-RCE-via-Java-deserialization.svg) ![forks](https://img.shields.io/github/forks/CypherHippie/CVE-2026-34486---unauthenticated-RCE-via-Java-deserialization.svg)


## CVE-2026-31717
to validate the identity of the requester during SMB2_CREATE (DHnC).

- [https://github.com/TurtleARM/ksmbrace](https://github.com/TurtleARM/ksmbrace) :  ![starts](https://img.shields.io/github/stars/TurtleARM/ksmbrace.svg) ![forks](https://img.shields.io/github/forks/TurtleARM/ksmbrace.svg)


## CVE-2026-23479
 Redis is an in-memory data structure store. In redis-server from 7.2.0 until 8.6.3, the unblock client flow does not handle an error return from `processCommandAndResetClient` when re-executing a blocked command. If a blocked client is evicted during this flow, an authenticated attacker can trigger a use-after-free that may lead to remote code execution. This has been patched in version 8.6.3.

- [https://github.com/HackSpeak/CVE-2026-23479](https://github.com/HackSpeak/CVE-2026-23479) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-23479.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-23479.svg)


## CVE-2026-19598
 The Pods – Custom Content Types and Fields plugin for WordPress is vulnerable to Privilege Escalation via Authorization Bypass in all versions up to, and including, 3.3.9. The vulnerability exists because the pods_admin AJAX router funnels every access check — including the method allowlist, nonce verification, login enforcement, and capability gate — through pods_error(), which under the JSON meta-box-loader compatibility path only writes failures to the PHP error log and returns false instead of terminating the request, rendering all guards ineffective.  This makes it possible for unauthenticated attackers to escalate their privileges to Administrator or overwrite the password of any user account, including the site owner's, enabling complete site takeover, or perform another administrator action.

- [https://github.com/DeadExpl0it/CVE-2026-19598-PoC](https://github.com/DeadExpl0it/CVE-2026-19598-PoC) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2026-19598-PoC.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2026-19598-PoC.svg)


## CVE-2026-19478
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an unauthenticated user to remotely modify or delete public projects and user data via a GraphQL directive.

- [https://github.com/renzi25031469/CVE-2026-19478](https://github.com/renzi25031469/CVE-2026-19478) :  ![starts](https://img.shields.io/github/stars/renzi25031469/CVE-2026-19478.svg) ![forks](https://img.shields.io/github/forks/renzi25031469/CVE-2026-19478.svg)


## CVE-2026-18504
 fastify is a fast and low overhead web framework for Node.js. Versions of fastify before 5.12.1 are affected by a schema validation bypass when a request body schema targets a root primitive value. When the schema validates a top-level primitive such as an integer, Ajv can coerce a JSON string into the expected type during validation, but Fastify does not replace the root request body with the coerced value, so the route handler receives the original unvalidated string. As a result, a request that should have failed validation can reach application logic with a value that does not satisfy the schema, which can undermine integrity and access-control checks that rely on the validated type. Users should upgrade to fastify 5.12.1, which fixes the mismatch. No known workarounds are available.

- [https://github.com/HORKimhab/CVE-2026-18504-CVE-2026-16732](https://github.com/HORKimhab/CVE-2026-18504-CVE-2026-16732) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-18504-CVE-2026-16732.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-18504-CVE-2026-16732.svg)


## CVE-2026-16732
 fastify is a fast and low overhead web framework for Node.js. Impact: the fix for CVE-2026-3635 added a guard on the forwarded-header reads used to derive the request host, protocol, hostname, ip, and ips values, checking the connecting address. That guard closes the IP, CIDR, and custom-function forms of trustProxy correctly, because those forms compile to predicates that inspect the connecting address. The hop-count form, where trustProxy is set to a number, compiles to a predicate that structurally ignores the address, so the guard is always satisfied for any hop count of one or more. Applications configured with a numeric trustProxy value, such as trustProxy set to 1 for a single reverse proxy, remain vulnerable: an attacker who can reach the Fastify origin directly, bypassing the front-facing proxy, can spoof the forwarded request fields exactly as in the unpatched version. The impact class matches the parent CVE-2026-3635, including host injection in generated URLs, HTTPS-enforcement bypass, secure-cookie and CSRF-origin bypass, and host-based routing and cache poisoning. Affected versions are fastify from 5.8.3 up to but not including 5.12.1. Patches: patched in fastify 5.12.1, where the numeric form of trustProxy is disabled at runtime and removed from the TypeScript type union. Workarounds: migrate to an IP, CIDR, or custom-function trustProxy value that validates the connecting address, and ensure the Fastify origin is only reachable through the trusted proxy chain.

- [https://github.com/HORKimhab/CVE-2026-18504-CVE-2026-16732](https://github.com/HORKimhab/CVE-2026-18504-CVE-2026-16732) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-18504-CVE-2026-16732.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-18504-CVE-2026-16732.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/Superman-L/CVE-2026-16723](https://github.com/Superman-L/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/Superman-L/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/Superman-L/CVE-2026-16723.svg)


## CVE-2026-15748
 The Forminator Forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.56.1 via the handle_file_upload function. This is due to insufficient file type validation in handle_file_upload, where the dangerous-extension blocklist performs exact-key matching that is bypassed by pipe-alternative MIME type keys, combined with a public submission handler that trusts attacker-controlled upload field configuration injected via a forged Select field value. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.

- [https://github.com/ubaydev/CVE-2026-15748](https://github.com/ubaydev/CVE-2026-15748) :  ![starts](https://img.shields.io/github/stars/ubaydev/CVE-2026-15748.svg) ![forks](https://img.shields.io/github/forks/ubaydev/CVE-2026-15748.svg)


## CVE-2026-7607
 A security vulnerability has been detected in TRENDnet TEW-821DAP 1.12B01. Impacted is the function auto_update_firmware of the component Firmware Udpate. The manipulation of the argument str leads to buffer overflow. The attack may be initiated remotely. The vendor explains: "That firmware version will only work on our hardware version v1.xR. We have already EOL that product 8 years ago and are no longer selling". This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/ozcanpng/CVE-2026-76071](https://github.com/ozcanpng/CVE-2026-76071) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-76071.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-76071.svg)
- [https://github.com/ozcanpng/CVE-2026-76070](https://github.com/ozcanpng/CVE-2026-76070) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-76070.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-76070.svg)


## CVE-2026-2329
 An unauthenticated stack-based buffer overflow vulnerability exists in the HTTP API endpoint /cgi-bin/api.values.get. A remote attacker can leverage this vulnerability to achieve unauthenticated remote code execution (RCE) with root privileges on a target device. The vulnerability affects all six device models in the series: GXP1610, GXP1615, GXP1620, GXP1625, GXP1628, and GXP1630.

- [https://github.com/VivianUba/grandstream-cve-2026-2329-analysis](https://github.com/VivianUba/grandstream-cve-2026-2329-analysis) :  ![starts](https://img.shields.io/github/stars/VivianUba/grandstream-cve-2026-2329-analysis.svg) ![forks](https://img.shields.io/github/forks/VivianUba/grandstream-cve-2026-2329-analysis.svg)


## CVE-2026-0828
 Kernel driver ProcessMonitorDriver.sys in Safetica's endpoint client x64 , versions 10.5.75.0 and 11.11.4.0, allows unprivileged user to abuse IOCTL path and terminate protected system processes.

- [https://github.com/Hika-sec/Terminator_Killer](https://github.com/Hika-sec/Terminator_Killer) :  ![starts](https://img.shields.io/github/stars/Hika-sec/Terminator_Killer.svg) ![forks](https://img.shields.io/github/forks/Hika-sec/Terminator_Killer.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/MattiaCervelli/CVE-2025-24893_Analysis](https://github.com/MattiaCervelli/CVE-2025-24893_Analysis) :  ![starts](https://img.shields.io/github/stars/MattiaCervelli/CVE-2025-24893_Analysis.svg) ![forks](https://img.shields.io/github/forks/MattiaCervelli/CVE-2025-24893_Analysis.svg)


## CVE-2025-24799
 GLPI is a free asset and IT management software package. An unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 10.0.18.

- [https://github.com/Rosemary1337/CVE-2025-24799](https://github.com/Rosemary1337/CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/Rosemary1337/CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/Rosemary1337/CVE-2025-24799.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/reaizuguo/vivo_iqoo_neo_9_root_research_on_CVE-2025-21479](https://github.com/reaizuguo/vivo_iqoo_neo_9_root_research_on_CVE-2025-21479) :  ![starts](https://img.shields.io/github/stars/reaizuguo/vivo_iqoo_neo_9_root_research_on_CVE-2025-21479.svg) ![forks](https://img.shields.io/github/forks/reaizuguo/vivo_iqoo_neo_9_root_research_on_CVE-2025-21479.svg)
- [https://github.com/Qingizi7/cve-2025-21479_iqooneo8](https://github.com/Qingizi7/cve-2025-21479_iqooneo8) :  ![starts](https://img.shields.io/github/stars/Qingizi7/cve-2025-21479_iqooneo8.svg) ![forks](https://img.shields.io/github/forks/Qingizi7/cve-2025-21479_iqooneo8.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/Rosemary1337/CVE-2025-6934](https://github.com/Rosemary1337/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/Rosemary1337/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/Rosemary1337/CVE-2025-6934.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2024-28116
 Grav is an open-source, flat-file content management system. Grav CMS prior to version 1.7.45 is vulnerable to a Server-Side Template Injection (SSTI), which allows any authenticated user (editor permissions are sufficient) to execute arbitrary code on the remote server bypassing the existing security sandbox. Version 1.7.45 contains a patch for this issue.

- [https://github.com/bebarossi/grav-cve-2024-28116](https://github.com/bebarossi/grav-cve-2024-28116) :  ![starts](https://img.shields.io/github/stars/bebarossi/grav-cve-2024-28116.svg) ![forks](https://img.shields.io/github/forks/bebarossi/grav-cve-2024-28116.svg)


## CVE-2024-8069
 Limited remote code execution with privilege of a NetworkService Account access in Citrix Session Recording if the attacker is an authenticated user on the same intranet as the session recording server

- [https://github.com/HORKimhab/CVE-2024-8068-CVE-2024-8069](https://github.com/HORKimhab/CVE-2024-8068-CVE-2024-8069) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2024-8068-CVE-2024-8069.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2024-8068-CVE-2024-8069.svg)


## CVE-2024-8068
 Privilege escalation to NetworkService Account access in Citrix Session Recording when an attacker is an authenticated user in the same Windows Active Directory domain as the session recording server domain

- [https://github.com/HORKimhab/CVE-2024-8068-CVE-2024-8069](https://github.com/HORKimhab/CVE-2024-8068-CVE-2024-8069) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2024-8068-CVE-2024-8069.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2024-8068-CVE-2024-8069.svg)


## CVE-2024-1086
We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/Vedantk6403/KOOBE-Guard](https://github.com/Vedantk6403/KOOBE-Guard) :  ![starts](https://img.shields.io/github/stars/Vedantk6403/KOOBE-Guard.svg) ![forks](https://img.shields.io/github/forks/Vedantk6403/KOOBE-Guard.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/stefanotractor/activemq-cve-2023-46604-lab](https://github.com/stefanotractor/activemq-cve-2023-46604-lab) :  ![starts](https://img.shields.io/github/stars/stefanotractor/activemq-cve-2023-46604-lab.svg) ![forks](https://img.shields.io/github/forks/stefanotractor/activemq-cve-2023-46604-lab.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)
- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/raviprajapati-it/active-directory-penetration-testing](https://github.com/raviprajapati-it/active-directory-penetration-testing) :  ![starts](https://img.shields.io/github/stars/raviprajapati-it/active-directory-penetration-testing.svg) ![forks](https://img.shields.io/github/forks/raviprajapati-it/active-directory-penetration-testing.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/andreamammano89-maker/CVE-2021-42013_821311](https://github.com/andreamammano89-maker/CVE-2021-42013_821311) :  ![starts](https://img.shields.io/github/stars/andreamammano89-maker/CVE-2021-42013_821311.svg) ![forks](https://img.shields.io/github/forks/andreamammano89-maker/CVE-2021-42013_821311.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/dbgee/CVE-2021-44228](https://github.com/dbgee/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/dbgee/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/dbgee/CVE-2021-44228.svg)
- [https://github.com/IAmNewbieZ/CVE-2021-44228](https://github.com/IAmNewbieZ/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/IAmNewbieZ/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/IAmNewbieZ/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/dr4xp/pwnkit-helper](https://github.com/dr4xp/pwnkit-helper) :  ![starts](https://img.shields.io/github/stars/dr4xp/pwnkit-helper.svg) ![forks](https://img.shields.io/github/forks/dr4xp/pwnkit-helper.svg)


## CVE-2020-9496
 XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03

- [https://github.com/cyber-niz/CVE-2020-9496](https://github.com/cyber-niz/CVE-2020-9496) :  ![starts](https://img.shields.io/github/stars/cyber-niz/CVE-2020-9496.svg) ![forks](https://img.shields.io/github/forks/cyber-niz/CVE-2020-9496.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/0xbinder/CVE_2019_2215](https://github.com/0xbinder/CVE_2019_2215) :  ![starts](https://img.shields.io/github/stars/0xbinder/CVE_2019_2215.svg) ![forks](https://img.shields.io/github/forks/0xbinder/CVE_2019_2215.svg)
- [https://github.com/Begitdj/cve-2019-2215-markw](https://github.com/Begitdj/cve-2019-2215-markw) :  ![starts](https://img.shields.io/github/stars/Begitdj/cve-2019-2215-markw.svg) ![forks](https://img.shields.io/github/forks/Begitdj/cve-2019-2215-markw.svg)

