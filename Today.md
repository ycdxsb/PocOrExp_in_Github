# Update 2026-10-22
## CVE-2026-113468
 The payment notification endpoint for PayPal accepts incoming data without verifying that it comes from the payment provider. Any site visitor can overwrite the stored payment notification of an order that is still awaiting payment with arbitrary content. This requires a page that contains the shop's order plugin. Orders that are already paid are not affected.

- [https://github.com/yuwkaaa/CVE-2026-113468](https://github.com/yuwkaaa/CVE-2026-113468) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-113468.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-113468.svg)


## CVE-2026-112195
 A flaw has been found in FusionPBX up to 5.4.4/5.5.7/5.6.5. The affected element is an unknown function of the file app/dialplans/resources/classes/dialplan.php of the component Dialplan Editor. Executing a manipulation can lead to os command injection. The attack can be executed remotely. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/jasonbernier/Dialplan-Escape-RCE](https://github.com/jasonbernier/Dialplan-Escape-RCE) :  ![starts](https://img.shields.io/github/stars/jasonbernier/Dialplan-Escape-RCE.svg) ![forks](https://img.shields.io/github/forks/jasonbernier/Dialplan-Escape-RCE.svg)


## CVE-2026-112071
 The order cancellation function accepts an order identifier from the request and acts on that order without checking that the caller owns it. Any site visitor can set orders that are still awaiting payment to "canceled". This requires a page that contains the shop's order plugin. Orders that are already paid are not affected.

- [https://github.com/yuwkaaa/CVE-2026-112071](https://github.com/yuwkaaa/CVE-2026-112071) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-112071.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-112071.svg)


## CVE-2026-111058
 Mercury is a Python framework for sharing Jupyter notebooks as web applications and dashboards. Prior to 3.2.6, default tokenless deployments allow anonymous clients to create Jupyter kernels and send execute_request messages containing arbitrary Python. The endpoint blocklist does not cover /api/kernels, and the websocket wrapper previously tracked idle activity without authorizing executable messages. This issue is fixed in version 3.2.6.

- [https://github.com/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce](https://github.com/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce.svg)


## CVE-2026-111057
 Mercury is a Python framework for sharing Jupyter notebooks as web applications and dashboards. From 3.0.0 until 3.2.4, a missing comma in BLOCKED_PATTERNS concatenates the /lab and /api/terminals regular-expression literals. Requests to /api/terminals therefore bypass the anonymous endpoint blocklist and reach Jupyter Server's terminal API. An unauthenticated attacker can use the resulting interactive operating-system shell to execute commands and access data available to the Mercury process. This issue is fixed in version 3.2.4.

- [https://github.com/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce](https://github.com/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-111058-CVE-2026-111057-mercury-rce.svg)


## CVE-2026-107692
 The War Thunder game client transmits its authentication bearer token (auth_jwt) in the very first data packet after the TCP handshake, using only LZ4 compression rather than encryption. An attacker positioned on the network path can passively intercept and decompress this packet to reveal the plaintext JSON payload. This vulnerability allows for temporary authenticated impersonation, enabling an attacker to access game services and certain user data (such as email address and displayed phone number) as the affected user. While this allows for unauthorized access to gameplay, it does not facilitate full account takeover, as it cannot be used to modify account security settings, change passwords, bypass two-factor authentication for account management, or access financial information.

- [https://github.com/thewhatdohe/CVE-2026-107692](https://github.com/thewhatdohe/CVE-2026-107692) :  ![starts](https://img.shields.io/github/stars/thewhatdohe/CVE-2026-107692.svg) ![forks](https://img.shields.io/github/forks/thewhatdohe/CVE-2026-107692.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/horizon3ai/CVE-2026-106173](https://github.com/horizon3ai/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2026-106173.svg)
- [https://github.com/0xBlackash/CVE-2026-106173](https://github.com/0xBlackash/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-106173.svg)


## CVE-2026-105810
configuration, and disrupt device availability.

- [https://github.com/M0ud4/CVE-2026-105810](https://github.com/M0ud4/CVE-2026-105810) :  ![starts](https://img.shields.io/github/stars/M0ud4/CVE-2026-105810.svg) ![forks](https://img.shields.io/github/forks/M0ud4/CVE-2026-105810.svg)


## CVE-2026-105484
 A security vulnerability has been detected in TOTOLINK X6000R 9.4.0cu.652_B20230116. The impacted element is the function firmware_check of the file /cgi-bin/cstecgi.cgi of the component UploadFirmwareFile Handler. Such manipulation of the argument file_name leads to os command injection. The attack may be performed from remote.

- [https://github.com/xiaobai718-ab/CVE-2026-105484](https://github.com/xiaobai718-ab/CVE-2026-105484) :  ![starts](https://img.shields.io/github/stars/xiaobai718-ab/CVE-2026-105484.svg) ![forks](https://img.shields.io/github/forks/xiaobai718-ab/CVE-2026-105484.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/sqzer-x/cve-2026-99999-scanner](https://github.com/sqzer-x/cve-2026-99999-scanner) :  ![starts](https://img.shields.io/github/stars/sqzer-x/cve-2026-99999-scanner.svg) ![forks](https://img.shields.io/github/forks/sqzer-x/cve-2026-99999-scanner.svg)
- [https://github.com/01luyicheng/CVE-2026-99999-exploit](https://github.com/01luyicheng/CVE-2026-99999-exploit) :  ![starts](https://img.shields.io/github/stars/01luyicheng/CVE-2026-99999-exploit.svg) ![forks](https://img.shields.io/github/forks/01luyicheng/CVE-2026-99999-exploit.svg)
- [https://github.com/01luyicheng/CVE-2026-99999-analysis](https://github.com/01luyicheng/CVE-2026-99999-analysis) :  ![starts](https://img.shields.io/github/stars/01luyicheng/CVE-2026-99999-analysis.svg) ![forks](https://img.shields.io/github/forks/01luyicheng/CVE-2026-99999-analysis.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/yanoo1222/CVE-2026-98260-android](https://github.com/yanoo1222/CVE-2026-98260-android) :  ![starts](https://img.shields.io/github/stars/yanoo1222/CVE-2026-98260-android.svg) ![forks](https://img.shields.io/github/forks/yanoo1222/CVE-2026-98260-android.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/ChrisLPJones/plex2shell-check](https://github.com/ChrisLPJones/plex2shell-check) :  ![starts](https://img.shields.io/github/stars/ChrisLPJones/plex2shell-check.svg) ![forks](https://img.shields.io/github/forks/ChrisLPJones/plex2shell-check.svg)


## CVE-2026-93300
 The EventON - Subscriber plugin for WordPress is vulnerable to generic SQL Injection via the 'email' parameter in all versions up to, and including, 1.4.5 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Datxzzz/CVE-2026-93300](https://github.com/Datxzzz/CVE-2026-93300) :  ![starts](https://img.shields.io/github/stars/Datxzzz/CVE-2026-93300.svg) ![forks](https://img.shields.io/github/forks/Datxzzz/CVE-2026-93300.svg)


## CVE-2026-92162
 Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. Prior to version 1.18.1, on systems where at least one OCI remote is configured (most common on Fedora systems), a malicious local user in an active local session could use a crafted architecture name to trick the `flatpak-system-helper` process into creating a root-owned directory tree with contents determined by the OCI remote, plus a root-owned `lock` file and `icons` directory, outside the intended root directory. If this vulnerability is combined with other vulnerabilities also fixed in 1.18.1, the combination can lead to local root privilege escalation. This particular vulnerability is not believed to be exploitable if there are no OCI remotes configured (common on non-Fedora systems). Version 1.18.1 patches the issue.

- [https://github.com/0xSemizzz/CVE-2026-92162](https://github.com/0xSemizzz/CVE-2026-92162) :  ![starts](https://img.shields.io/github/stars/0xSemizzz/CVE-2026-92162.svg) ![forks](https://img.shields.io/github/forks/0xSemizzz/CVE-2026-92162.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/Lutfifakee-Project/CVE-2026-87902](https://github.com/Lutfifakee-Project/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-87902.svg)


## CVE-2026-87690
 The Metasploit Framework post module post/apple_ios/gather/ios_image_gather is affected by a relative path traversal vulnerability (CWE-22). The module interpolates file names taken from a Meterpreter directory listing — data fully controlled by a hostile or tampered iOS device — directly into the local destination path passed to client.fs.file.download_file(), with no sanitization. The underlying stdapi sink (lib/rex/post/meterpreter/extensions/stdapi/fs/file.rb) writes to whatever path is supplied, so a listing entry such as ../../msfconsole.rc escapes the intended ~/.msf4/loot/random directory and overwrites ~/.msf4/msfconsole.rc, a resource file that every msfconsole invocation automatically executes at startup (lib/msf/ui/console/driver.rb:196). An attacker-controlled device that lures an operator into running this gather module achieves an arbitrary file write as the operator; because the written msfconsole.rc can load a second written file (a Ruby plugin whose top-level code runs on require), this converts into persistent code execution and an interactive shell as the operator (frequently root) on the pentester's workstation at the next console launch. The same traversal was previously fixed upstream in the recursive downloader (stdapi/fs/dir.rb scrubs separators); this module omitted the equivalent scrub. The fix applies the same separator scrub (or File.basename) to listing entries before building the local path.

- [https://github.com/h00die/CVE-2026-87690-POC](https://github.com/h00die/CVE-2026-87690-POC) :  ![starts](https://img.shields.io/github/stars/h00die/CVE-2026-87690-POC.svg) ![forks](https://img.shields.io/github/forks/h00die/CVE-2026-87690-POC.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/jpdagostin0/CVE-2026-86950-POC](https://github.com/jpdagostin0/CVE-2026-86950-POC) :  ![starts](https://img.shields.io/github/stars/jpdagostin0/CVE-2026-86950-POC.svg) ![forks](https://img.shields.io/github/forks/jpdagostin0/CVE-2026-86950-POC.svg)


## CVE-2026-85314
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The MimeMultipart data format now applies the header filter on unmarshal, closing the path CVE-2026-46584 left open. For deployments that cannot upgrade immediately, strip the namespace after the data format with removeHeaders("mail.smtp*") before any mail producer.

- [https://github.com/oscerd/CVE-2026-85314](https://github.com/oscerd/CVE-2026-85314) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85314.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85314.svg)


## CVE-2026-85313
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. enableCORS no longer grants credentials to an origin the operator did not name. A deployment that relied on any origin being accepted must now list its origins explicitly. For deployments that cannot upgrade immediately, configure the CrossOriginFilter parameters explicitly rather than relying on what enableCORS installs, naming the allowed origins.

- [https://github.com/oscerd/CVE-2026-85313](https://github.com/oscerd/CVE-2026-85313) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85313.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85313.svg)


## CVE-2026-85312
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The header is now consulted only for a saga service that actually uses it, rather than on every exchange. For deployments that cannot upgrade immediately, strip the header at the trust boundary with removeHeaders("Long-Running-Action") on every consumer that accepts messages from an untrusted sender.

- [https://github.com/oscerd/CVE-2026-85312](https://github.com/oscerd/CVE-2026-85312) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85312.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85312.svg)


## CVE-2026-85301
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. An absent iss claim is now treated as a validation failure rather than as a reason to skip the check. For deployments that cannot upgrade immediately, ensure the introspection endpoint returns the iss claim, and that it serves exactly one issuer.

- [https://github.com/oscerd/CVE-2026-85301](https://github.com/oscerd/CVE-2026-85301) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85301.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85301.svg)


## CVE-2026-85300
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Key material is now written with owner-only permissions. For deployments that cannot upgrade immediately, place the key directory on a path only the service account can traverse, and tighten the process umask. Key material already written with permissive permissions should be treated as exposed and rotated.

- [https://github.com/oscerd/CVE-2026-85300](https://github.com/oscerd/CVE-2026-85300) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85300.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85300.svg)


## CVE-2026-85296
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Per-request signing keys are now confined to the request being processed in ResponseMDN. For deployments that cannot upgrade immediately, run a separate Camel context per trading partner so that no signing material is shared between them.

- [https://github.com/oscerd/CVE-2026-85296](https://github.com/oscerd/CVE-2026-85296) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85296.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85296.svg)


## CVE-2026-85260
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. logPhi now defaults to false and is honoured on the paths that previously ignored it. This is a changed default: a deployment that relied on payload logging must now set logPhi=true explicitly. Because the upgrade guide for a change like this lives on the main branch only, operators upgrading within the 4.18.x or 4.22.x lines should treat this advisory as the notice of that change. For deployments that cannot upgrade immediately, set logPhi=false and be aware that two paths will continue to log payload content until the fix is applied; restrict access to the logs accordingly.

- [https://github.com/oscerd/CVE-2026-85260](https://github.com/oscerd/CVE-2026-85260) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85260.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85260.svg)


## CVE-2026-78250
 A vulnerability was identified in bytebot-ai bytebot 0.0.1. The affected element is an unknown function of the component Agent Execution Workflow. Such manipulation leads to infinite loop. The attack may be performed from remote. The exploit is publicly available and might be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/n1kat/forkybot_AI](https://github.com/n1kat/forkybot_AI) :  ![starts](https://img.shields.io/github/stars/n1kat/forkybot_AI.svg) ![forks](https://img.shields.io/github/forks/n1kat/forkybot_AI.svg)


## CVE-2026-72867
 Dokploy is a free, self-hostable Platform as a Service (PaaS). From 0.29.3 until 0.29.13, the incomplete fix for CVE-2026-45628 leaves packages/server/src/db/schema/compose.ts branch fields without server-side validation, allowing a direct compose.update request to store a malicious customGitBranch, branch, gitlabBranch, bitbucketBranch, or giteaBranch. A low-privileged authenticated user can trigger compose.deploy, which passes the stored branch to shell-based Git clone commands in packages/server/src/utils/providers/git.ts, github.ts, gitlab.ts, bitbucket.ts, and gitea.ts, resulting in arbitrary host command execution. This issue is fixed in version 0.29.13.

- [https://github.com/Lulztigre/CVE-2026-72867](https://github.com/Lulztigre/CVE-2026-72867) :  ![starts](https://img.shields.io/github/stars/Lulztigre/CVE-2026-72867.svg) ![forks](https://img.shields.io/github/forks/Lulztigre/CVE-2026-72867.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/alisalive/xss2shell](https://github.com/alisalive/xss2shell) :  ![starts](https://img.shields.io/github/stars/alisalive/xss2shell.svg) ![forks](https://img.shields.io/github/forks/alisalive/xss2shell.svg)
- [https://github.com/OFRPurpose/poc-cve-2026-64638](https://github.com/OFRPurpose/poc-cve-2026-64638) :  ![starts](https://img.shields.io/github/stars/OFRPurpose/poc-cve-2026-64638.svg) ![forks](https://img.shields.io/github/forks/OFRPurpose/poc-cve-2026-64638.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/Yunnijian/OnePlus16-Jailbreak](https://github.com/Yunnijian/OnePlus16-Jailbreak) :  ![starts](https://img.shields.io/github/stars/Yunnijian/OnePlus16-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/Yunnijian/OnePlus16-Jailbreak.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/Lutfifakee-Project/wp2shell](https://github.com/Lutfifakee-Project/wp2shell) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/wp2shell.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/wp2shell.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/fahise/cve-2026-62911](https://github.com/fahise/cve-2026-62911) :  ![starts](https://img.shields.io/github/stars/fahise/cve-2026-62911.svg) ![forks](https://img.shields.io/github/forks/fahise/cve-2026-62911.svg)


## CVE-2026-44714
 The bitcoinj library is a Java implementation of the Bitcoin protocol. Prior to 0.17.1, ScriptExecution.correctlySpends() contains two fast-path verification bugs for standard P2PKH and native P2WPKH spends in core/src/main/java/org/bitcoinj/script/ScriptExecution.java. In both branches, bitcoinj verifies an attacker-controlled signature/public-key pair but fails to verify that the public key is the one committed to by the output being spent. As a result, any attacker keypair can satisfy bitcoinj's local verification for arbitrary P2PKH and P2WPKH outputs. This vulnerability is fixed in 0.17.1.

- [https://github.com/dntaskmehow/BABEF](https://github.com/dntaskmehow/BABEF) :  ![starts](https://img.shields.io/github/stars/dntaskmehow/BABEF.svg) ![forks](https://img.shields.io/github/forks/dntaskmehow/BABEF.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/Lutfifakee-Project/CVE-2026-41940](https://github.com/Lutfifakee-Project/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-41940.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/Lutfifakee-Project/CVE-2026-41651](https://github.com/Lutfifakee-Project/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-41651.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/dntaskmehow/MARABUSE-](https://github.com/dntaskmehow/MARABUSE-) :  ![starts](https://img.shields.io/github/stars/dntaskmehow/MARABUSE-.svg) ![forks](https://img.shields.io/github/forks/dntaskmehow/MARABUSE-.svg)


## CVE-2026-35273
 Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Updates Environment Management). Supported versions that are affected are 8.61 and 8.62. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PeopleTools. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/rayo0009/CVE-2026-35273-Oracle-PeopleSoft-PeopleTools-Zero-Day-](https://github.com/rayo0009/CVE-2026-35273-Oracle-PeopleSoft-PeopleTools-Zero-Day-) :  ![starts](https://img.shields.io/github/stars/rayo0009/CVE-2026-35273-Oracle-PeopleSoft-PeopleTools-Zero-Day-.svg) ![forks](https://img.shields.io/github/forks/rayo0009/CVE-2026-35273-Oracle-PeopleSoft-PeopleTools-Zero-Day-.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/dntaskmehow/NEO-DEFENDER](https://github.com/dntaskmehow/NEO-DEFENDER) :  ![starts](https://img.shields.io/github/stars/dntaskmehow/NEO-DEFENDER.svg) ![forks](https://img.shields.io/github/forks/dntaskmehow/NEO-DEFENDER.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/Lutfifakee-Project/CVE-2026-31635](https://github.com/Lutfifakee-Project/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-31635.svg)


## CVE-2026-24332
 Discord through 2026-01-16 allows gathering information about whether a user's client state is Invisible (and not actually offline) because the response to a WebSocket API request includes the user in the presences array (with "status": "offline"), whereas offline users are omitted from the presences array. This is arguably inconsistent with the UI description of Invisible as "You will appear offline." NOTE: a third-party report suggests that this was remediated later in 2026.

- [https://github.com/LinkMakesMods/invisible-detector](https://github.com/LinkMakesMods/invisible-detector) :  ![starts](https://img.shields.io/github/stars/LinkMakesMods/invisible-detector.svg) ![forks](https://img.shields.io/github/forks/LinkMakesMods/invisible-detector.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/wvverez/CVE-2026-23744](https://github.com/wvverez/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2026-23744.svg)


## CVE-2026-10809
 A security flaw has been discovered in itsourcecode Fees Management System 1.0. This impacts an unknown function of the file /manage_user.php. The manipulation of the argument ID results in sql injection. The attack can be executed remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/ExDev994/CVE-2026-108097](https://github.com/ExDev994/CVE-2026-108097) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-108097.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-108097.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/0xN7y/CVE-2026-31431](https://github.com/0xN7y/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/0xN7y/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/0xN7y/CVE-2026-31431.svg)
- [https://github.com/Lutfifakee-Project/CVE-2026-31431](https://github.com/Lutfifakee-Project/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-31431.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-31324
 SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.

- [https://github.com/CyberGramps007/CYB-403](https://github.com/CyberGramps007/CYB-403) :  ![starts](https://img.shields.io/github/stars/CyberGramps007/CYB-403.svg) ![forks](https://img.shields.io/github/forks/CyberGramps007/CYB-403.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/kur0bai/CVE-2025-8110](https://github.com/kur0bai/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/kur0bai/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/kur0bai/CVE-2025-8110.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/jonbondani/CVE-2025-5548](https://github.com/jonbondani/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/jonbondani/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/jonbondani/CVE-2025-5548.svg)


## CVE-2025-5243
This issue affects Information Portal: before 13.06.2025.

- [https://github.com/ersinerenler/CVE-2025-5243-SMG-Software-Information-Portal-Arbitrary-File-Upload-Vulnerability](https://github.com/ersinerenler/CVE-2025-5243-SMG-Software-Information-Portal-Arbitrary-File-Upload-Vulnerability) :  ![starts](https://img.shields.io/github/stars/ersinerenler/CVE-2025-5243-SMG-Software-Information-Portal-Arbitrary-File-Upload-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/CVE-2025-5243-SMG-Software-Information-Portal-Arbitrary-File-Upload-Vulnerability.svg)


## CVE-2024-43499
 .NET and Visual Studio Denial of Service Vulnerability

- [https://github.com/saisarathbb/firetv-clean-root](https://github.com/saisarathbb/firetv-clean-root) :  ![starts](https://img.shields.io/github/stars/saisarathbb/firetv-clean-root.svg) ![forks](https://img.shields.io/github/forks/saisarathbb/firetv-clean-root.svg)


## CVE-2024-11142
NOTE: According to the vendor, fixing process is still ongoing for v4.05.

- [https://github.com/ersinerenler/CVE-2024-11142-Gosoft-Proticaret-E-Commerce-CSRF-Vulnerability](https://github.com/ersinerenler/CVE-2024-11142-Gosoft-Proticaret-E-Commerce-CSRF-Vulnerability) :  ![starts](https://img.shields.io/github/stars/ersinerenler/CVE-2024-11142-Gosoft-Proticaret-E-Commerce-CSRF-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/CVE-2024-11142-Gosoft-Proticaret-E-Commerce-CSRF-Vulnerability.svg)


## CVE-2023-46582
 SQL injection vulnerability in Inventory Management v.1.0 allows a local attacker to execute arbitrary SQL commands via the id paramter in the deleteProduct.php component.

- [https://github.com/ersinerenler/Code-Projects-Inventory-Management-1.0](https://github.com/ersinerenler/Code-Projects-Inventory-Management-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/Code-Projects-Inventory-Management-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/Code-Projects-Inventory-Management-1.0.svg)


## CVE-2023-46580
 Cross-Site Scripting (XSS) vulnerability in Inventory Management V1.0 allows attackers to execute arbitrary code via the pname parameter of the editProduct.php component.

- [https://github.com/ersinerenler/Code-Projects-Inventory-Management-1.0](https://github.com/ersinerenler/Code-Projects-Inventory-Management-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/Code-Projects-Inventory-Management-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/Code-Projects-Inventory-Management-1.0.svg)


## CVE-2023-46026
 Cross Site Scripting (XSS) vulnerability in profile.php in phpgurukul Teacher Subject Allocation Management System 1.0 allows attackers to run arbitrary code via the 'adminname' and 'email' parameters.

- [https://github.com/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0](https://github.com/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0.svg)


## CVE-2023-46024
 SQL Injection vulnerability in index.php in phpgurukul Teacher Subject Allocation Management System 1.0 allows attackers to run arbitrary SQL commands and obtain sensitive information via the 'searchdata' parameter.

- [https://github.com/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0](https://github.com/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/PHPGurukul-Teacher-Subject-Allocation-Management-System-1.0.svg)


## CVE-2023-46023
 SQL injection vulnerability in addTask.php in Code-Projects Simple Task List 1.0 allows attackers to obtain sensitive information via the 'status' parameter.

- [https://github.com/ersinerenler/Code-Projects-Simple-Task-List-1.0](https://github.com/ersinerenler/Code-Projects-Simple-Task-List-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/Code-Projects-Simple-Task-List-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/Code-Projects-Simple-Task-List-1.0.svg)


## CVE-2023-46022
 SQL Injection vulnerability in delete.php in Code-Projects Blood Bank 1.0 allows attackers to run arbitrary SQL commands via the 'bid' parameter.

- [https://github.com/ersinerenler/Code-Projects-Blood-Bank-1.0](https://github.com/ersinerenler/Code-Projects-Blood-Bank-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/Code-Projects-Blood-Bank-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/Code-Projects-Blood-Bank-1.0.svg)


## CVE-2023-46014
 SQL Injection vulnerability in hospitalLogin.php in Code-Projects Blood Bank 1.0 allows attackers to run arbitrary SQL commands via 'hemail' and 'hpassword' parameters.

- [https://github.com/ersinerenler/Code-Projects-Blood-Bank-1.0](https://github.com/ersinerenler/Code-Projects-Blood-Bank-1.0) :  ![starts](https://img.shields.io/github/stars/ersinerenler/Code-Projects-Blood-Bank-1.0.svg) ![forks](https://img.shields.io/github/forks/ersinerenler/Code-Projects-Blood-Bank-1.0.svg)


## CVE-2023-24329
 An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.

- [https://github.com/UpWguyy/CVE-2023-24329-PoC](https://github.com/UpWguyy/CVE-2023-24329-PoC) :  ![starts](https://img.shields.io/github/stars/UpWguyy/CVE-2023-24329-PoC.svg) ![forks](https://img.shields.io/github/forks/UpWguyy/CVE-2023-24329-PoC.svg)


## CVE-2023-3460
 The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.

- [https://github.com/ollie-blue/CVE_2023_3460](https://github.com/ollie-blue/CVE_2023_3460) :  ![starts](https://img.shields.io/github/stars/ollie-blue/CVE_2023_3460.svg) ![forks](https://img.shields.io/github/forks/ollie-blue/CVE_2023_3460.svg)


## CVE-2022-3509
 A parsing issue similar to CVE-2022-3171, but with textformat in protobuf-java core and lite versions prior to 3.21.7, 3.20.3, 3.19.6 and 3.16.3 can lead to a denial of service attack. Inputs containing multiple instances of non-repeated embedded messages with repeated or unknown fields causes objects to be converted back-n-forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. We recommend updating to the versions mentioned above.

- [https://github.com/toluwanimidurosomo/CYB-401-](https://github.com/toluwanimidurosomo/CYB-401-) :  ![starts](https://img.shields.io/github/stars/toluwanimidurosomo/CYB-401-.svg) ![forks](https://img.shields.io/github/forks/toluwanimidurosomo/CYB-401-.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/layee27/JIMOH-ABDULLAHI](https://github.com/layee27/JIMOH-ABDULLAHI) :  ![starts](https://img.shields.io/github/stars/layee27/JIMOH-ABDULLAHI.svg) ![forks](https://img.shields.io/github/forks/layee27/JIMOH-ABDULLAHI.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/kilokite/old-phone-temp-root](https://github.com/kilokite/old-phone-temp-root) :  ![starts](https://img.shields.io/github/stars/kilokite/old-phone-temp-root.svg) ![forks](https://img.shields.io/github/forks/kilokite/old-phone-temp-root.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/fahise/cve-2018-16763](https://github.com/fahise/cve-2018-16763) :  ![starts](https://img.shields.io/github/stars/fahise/cve-2018-16763.svg) ![forks](https://img.shields.io/github/forks/fahise/cve-2018-16763.svg)

