# Update 2026-11-27
## CVE-2026-137084
 NodeBB 4.12.0 before 4.16.4 contains an execution after redirect vulnerability in the Intents.create controller that allows unauthenticated attackers to trigger ActivityPub note ingestion. Attackers can send GET requests to /intents/create with a remote note URI in the toPid parameter to inject federated content as local topics and posts.

- [https://github.com/googlesky/CVE-2026-137084](https://github.com/googlesky/CVE-2026-137084) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137084.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137084.svg)


## CVE-2026-137077
 FreeRDP before 3.33.0 contains a heap out-of-bounds write in h264_context_reset() in libfreerdp/codec/h264.c, which stores new dimensions before the YUV planes are reallocated. Remote peers can trigger surface height increases so avc420_compress() writes taller frames past undersized luma and chroma planes, corrupting heap memory or crashing the process.

- [https://github.com/googlesky/CVE-2026-137077](https://github.com/googlesky/CVE-2026-137077) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137077.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137077.svg)


## CVE-2026-137065
 Chatwoot before 4.20.0 contains an authorization bypass vulnerability that allows account administrators to attach integration hooks to other accounts' inboxes by supplying a foreign inbox_id. Attackers can create a Dialogflow hook referencing a victim inbox, leaving its new conversations stuck as pending awaiting a bot, and enumerate inbox IDs to disclose inbox names.

- [https://github.com/googlesky/CVE-2026-137065](https://github.com/googlesky/CVE-2026-137065) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137065.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137065.svg)


## CVE-2026-136412
 OpenResty stream-lua-nginx-module before 0.0.20rc4 contains a use-after-free vulnerability that allows remote peers to trigger access to freed memory when a receiveuntil() pattern iterator is garbage-collected while still referenced by the socket. Attackers can interrupt or close the cosocket connection so later reads or socket closure use the stale pattern pointer, crashing or corrupting the nginx worker.

- [https://github.com/googlesky/CVE-2026-136412](https://github.com/googlesky/CVE-2026-136412) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136412.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136412.svg)


## CVE-2026-136411
 BusyBox through 1.38.0 contains an absolute path traversal vulnerability in tftpd that allows unauthenticated remote attackers to access files outside any intended directory when started without a DIR argument. Attackers can send RRQ or WRQ packets with file names beginning with '/' to read sensitive files like /etc/shadow or overwrite files, typically as root.

- [https://github.com/googlesky/CVE-2026-136411](https://github.com/googlesky/CVE-2026-136411) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136411.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136411.svg)


## CVE-2026-136404
 ntop n2n supernode 3.0 through 3.1.1 contains a stack-based buffer overflow vulnerability that allows remote unauthenticated attackers to leak memory and execute code by sending an untrusted 16-bit auth token_size in REGISTER_SUPER_NAK datagrams. Attackers can register an edge in a chosen community, then send an oversized token_size to leak stack canaries and pointers, overwrite the return address, or crash the supernode.

- [https://github.com/googlesky/CVE-2026-136404](https://github.com/googlesky/CVE-2026-136404) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136404.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136404.svg)


## CVE-2026-136139
 A vulnerability was determined in Zefan-Cai R-KV up to 6715468b9872442be72e5c97322e4d9c9a2abf55. This impacts the function _shard_files of the file FlashInfer/rkv/loader.py of the component FlashInfer weight loader. This manipulation of the argument weight_map causes path traversal. The attack can be initiated remotely. The exploit has been publicly disclosed and may be utilized. Continious delivery with rolling releases is used by this product. Therefore, no version details of affected nor updated releases are available. Patch name: 0fdff6ed12b58ad4c33aab5a63f66e04555cafb6. To fix this issue, it is recommended to deploy a patch. The vendor was contacted early, responded in a very professional manner and quickly released a fixed version of the affected product.

- [https://github.com/googlesky/CVE-2026-136139](https://github.com/googlesky/CVE-2026-136139) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136139.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136139.svg)


## CVE-2026-136134
 A flaw has been found in mealie-recipes Mealie up to 3.29.0. Affected is the function get of the file mealie/pkgs/i18n/provider_factory.py of the component I18n Locale Provider. Executing a manipulation of the argument Accept-Language can lead to path traversal. It is possible to launch the attack remotely. The exploit has been published and may be used. Upgrading to version 3.30.0 is able to address this issue. This patch is called 4d074185d0dd1bb2dada7a4470bd04bd91227040. It is advisable to upgrade the affected component.

- [https://github.com/googlesky/CVE-2026-136134](https://github.com/googlesky/CVE-2026-136134) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136134.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136134.svg)


## CVE-2026-135818
 A vulnerability was identified in Dispatcharr up to 0.32.0. Affected by this issue is the function get_permissions of the component VODLogoViewSet/M3UAccountViewSet. Such manipulation leads to incorrect authorization. The attack may be launched remotely. Upgrading to version 0.33.0 can resolve this issue. The name of the patch is ac7a23cc584761b88f8d87dd8ac3688426024ed8. It is recommended to upgrade the affected component.

- [https://github.com/googlesky/CVE-2026-135818](https://github.com/googlesky/CVE-2026-135818) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135818.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135818.svg)


## CVE-2026-135817
 A vulnerability was determined in beenuar AiSOC up to 17.0.0. Affected by this vulnerability is an unknown functionality of the component AuditMiddleware. This manipulation causes improper verification of cryptographic signature. The attack may be initiated remotely. Upgrading to version 17.1.0 addresses this issue. Patch name: 8f2224299124010536ff0e3ebcd9efb0149af26c. Upgrading the affected component is recommended.

- [https://github.com/googlesky/CVE-2026-135817](https://github.com/googlesky/CVE-2026-135817) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135817.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135817.svg)


## CVE-2026-135746
 An off-by-one error in String::WriteOneByte() in Samsung lwnode can cause a one-byte out-of-bounds write when copying a UTF-16 string

- [https://github.com/googlesky/CVE-2026-135746](https://github.com/googlesky/CVE-2026-135746) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135746.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135746.svg)


## CVE-2026-135691
 Open5GS WebUI through 2.8.0 contains an incorrect authorization vulnerability in webui/server/routes/db.js that allows authenticated user-role accounts to modify the Account model. Attackers can send PATCH /api/db/Account/username setting roles to admin, overwrite password hashes, delete accounts, and read hashes to gain full administrative control.

- [https://github.com/googlesky/CVE-2026-135691](https://github.com/googlesky/CVE-2026-135691) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135691.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135691.svg)


## CVE-2026-135472
 open62541 1.5.0 through 1.5.10 contains a use-after-free and double free vulnerability in the lookupRefType() function in src/util/ua_util.c that allows attackers to corrupt the heap of the server process by supplying a RelativePath string resolved through UA_RelativePath_parseWithServer(). When the path names a ReferenceType with a string or GUID NodeId, the function returns a shallow copy of the browse result's NodeId and frees its identifier, causing the identifier to be freed a second time when the parsed path is cleared, which attackers can exploit to crash the server process.

- [https://github.com/googlesky/CVE-2026-135472](https://github.com/googlesky/CVE-2026-135472) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135472.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135472.svg)


## CVE-2026-135445
 MediaInfoLib before 26.10 contains a divide-by-zero vulnerability in TimeCode::FromString() that allows attackers to crash applications by supplying hour-unit timestamps with fewer than three fractional digits. Attackers can craft a TTML file whose begin or end attribute contains such a timestamp, causing MediaInfo or embedding applications to crash with SIGFPE when opened.

- [https://github.com/googlesky/CVE-2026-135445](https://github.com/googlesky/CVE-2026-135445) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135445.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135445.svg)


## CVE-2026-135444
 MediaInfoLib before 26.10 contains an out-of-bounds read vulnerability in File_Mpegv::Streams_Fill() that allows attackers to read adjacent memory via an uninitialized chroma_format index. Attackers can craft media files that reach Streams_Fill() before Synched_Init(), crashing MediaInfo or embedding applications and possibly exposing static memory in parser output.

- [https://github.com/googlesky/CVE-2026-135444](https://github.com/googlesky/CVE-2026-135444) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135444.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135444.svg)


## CVE-2026-135441
 MediaInfoLib before 26.10 contains an uninitialized pointer dereference vulnerability because the File_Mpeg4_Descriptors constructor leaves the IsCmaf pointer holding stale heap contents. Attackers can supply a crafted MP4 file with an AAC/USAC decoder specific descriptor so File_Usac::Streams_Finish_Conformance_Profile dereferences an invalid address, crashing the application.

- [https://github.com/googlesky/CVE-2026-135441](https://github.com/googlesky/CVE-2026-135441) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135441.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135441.svg)


## CVE-2026-135440
 MediaInfoLib before 26.10 contains a heap use-after-free vulnerability in the Vorbis setup header parser that allows attackers to trigger reads of freed memory via crafted files. Attackers can supply a crafted Ogg/Vorbis file that makes File_Vorbis::Setup() return early without BS_End_LE(), leaving a stale bitstream pointer that causes crashes or heap disclosure.

- [https://github.com/googlesky/CVE-2026-135440](https://github.com/googlesky/CVE-2026-135440) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135440.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135440.svg)


## CVE-2026-135300
 Pomerium from 0.30.0 before 0.34.0 contains an authentication bypass vulnerability in the MCP token endpoint that skips client secret verification for client_secret_basic clients. Attackers holding an intercepted authorization code or refresh token can redeem it at /.pomerium/mcp/token with any secret to obtain the victim's access tokens.

- [https://github.com/googlesky/CVE-2026-135300](https://github.com/googlesky/CVE-2026-135300) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135300.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135300.svg)


## CVE-2026-135295
 FontForge through 20251009 contains a heap out-of-bounds write vulnerability in PcfReadEncodingsNames() that allows attackers to corrupt memory via negative glyph indices from truncated PCF encodings tables. Attackers can supply a crafted .pcf file imported through the GUI or scripting Import() command to write before the encs array, causing crashes or potential code execution.

- [https://github.com/googlesky/CVE-2026-135295](https://github.com/googlesky/CVE-2026-135295) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135295.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135295.svg)


## CVE-2026-135294
 LibreCAD through 2.2.1.6 contains a heap-based out-of-bounds write vulnerability in RS_FilterDXF1::readFileInBuffer() caused by unvalidated truncation of the 64-bit file size. Attackers can persuade users to open a crafted DXF file sized 0xFFFFFFF8 bytes, writing a NUL byte before an 8-byte buffer to corrupt heap metadata and crash the application.

- [https://github.com/googlesky/CVE-2026-135294](https://github.com/googlesky/CVE-2026-135294) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135294.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135294.svg)


## CVE-2026-135290
 OpenCV through 4.14.0 and 5.0.0 through 5.1.0 contains an infinite loop vulnerability in YAMLParser::parse that allows attackers to cause denial of service via crafted YAML dash lines. Attackers can supply YAML files with a non-separator '-' line after the first document, opened through cv::FileStorage, to hang the thread at full CPU.

- [https://github.com/googlesky/CVE-2026-135290](https://github.com/googlesky/CVE-2026-135290) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135290.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135290.svg)


## CVE-2026-135288
 AIOStreams 2.9.0 through 2.38.1 contains an information disclosure vulnerability in makeRequest() that leaks the internal secret header by matching URLs against INTERNAL_URL using a string-prefix check. Attackers can supply a custom addon manifest URL or redirect to a prefix-matching host or port to capture the secret and directly call internal addon routes.

- [https://github.com/googlesky/CVE-2026-135288](https://github.com/googlesky/CVE-2026-135288) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135288.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135288.svg)


## CVE-2026-135213
 Worklenz before 3.4.3 contains an insecure direct object reference vulnerability in GET /api/v1/activity-logs/:id that allows authenticated users to read other teams' task activity logs because it lacks the verifyTaskAccess middleware. Attackers who know another team's task UUID can retrieve reporter and assignee names and avatars plus the full timeline of status, priority, label and estimation changes.

- [https://github.com/googlesky/CVE-2026-135213](https://github.com/googlesky/CVE-2026-135213) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135213.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135213.svg)


## CVE-2026-135212
 AiSOC before 23.6.1 contains a missing authorization vulnerability in the agents service that allows authenticated users to read other tenants' investigation runs by supplying their run_id. Attackers can query GET /api/v1/investigations/{run_id}, report variants, the WebSocket stream, or agent-runs routes to obtain audit logs, forensic output, and incident reports.

- [https://github.com/googlesky/CVE-2026-135212](https://github.com/googlesky/CVE-2026-135212) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135212.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135212.svg)


## CVE-2026-135208
 Kerberos Agent before 3.14.4 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge administrator tokens because JWTMiddleWare() falls back to the hard-coded key TOBECHANGED. Attackers can sign HS256 tokens with arbitrary username and role claims to access /api and /config routes, exposing RTSP, ONVIF, Hub and encryption keys, rewriting configuration, and stopping the camera.

- [https://github.com/googlesky/CVE-2026-135208](https://github.com/googlesky/CVE-2026-135208) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135208.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135208.svg)


## CVE-2026-135165
 CISO Assistant before 4.2.3 contains a denial of service vulnerability that allows unauthenticated attackers to block all logins by exhausting a shared rate limit keyed on the frontend server IP. Attackers can send a low sustained rate of failed login attempts through the SvelteKit frontend to exhaust the django-allauth per-address budget, locking out every user.

- [https://github.com/googlesky/CVE-2026-135165](https://github.com/googlesky/CVE-2026-135165) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135165.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135165.svg)


## CVE-2026-135164
 Formance Ledger 2.2.0-beta.3 before 2.4.18 contains an SQL injection vulnerability that allows remote API callers to execute SQL by supplying unvalidated account expand values. Attackers can inject comment-separated SQL through the expand query parameter or base64 pagination cursor to run queries with the ledger database role's privileges.

- [https://github.com/googlesky/CVE-2026-135164](https://github.com/googlesky/CVE-2026-135164) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135164.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135164.svg)


## CVE-2026-135163
 Okou API before 1.762.0 contains a missing authentication vulnerability in its Microsoft Teams, legacy Slack, and GitHub App integration OAuth flows that trusts caller-supplied userId and orgId values. Unauthenticated attackers who know a member's identifiers can complete the flow with their own external account to bind that identity or installation to the victim's Okou user and organization.

- [https://github.com/googlesky/CVE-2026-135163](https://github.com/googlesky/CVE-2026-135163) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135163.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135163.svg)


## CVE-2026-135162
 Sim 0.5.61 before 0.9.41 contains an incorrect authorization vulnerability that allows write-level workspace members to change workflow MCP server visibility without admin permission. Attackers can set isPublic via POST or PATCH to /api/mcp/workflow-servers, exposing deployed workflows to unauthenticated invocation through /api/mcp/serve.

- [https://github.com/googlesky/CVE-2026-135162](https://github.com/googlesky/CVE-2026-135162) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135162.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135162.svg)


## CVE-2026-135158
 Windmill 1.607.0 before 1.819.0 contains an authorization bypass vulnerability that allows workspace members to resume or cancel suspended flows in other workspaces by abusing the jobs_u/resume and jobs_u/cancel endpoints. Attackers can mint a resume signature for an arbitrary job id via their own workspace's job_signature endpoint to approve or cancel another workspace's suspended flow steps.

- [https://github.com/googlesky/CVE-2026-135158](https://github.com/googlesky/CVE-2026-135158) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135158.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135158.svg)


## CVE-2026-135157
 Future AGI before 1.51.0 contains an authentication bypass vulnerability in ACSView.post that allows authenticated members of any organization to take over accounts in other organizations by asserting arbitrary e-mail addresses. Attackers can register a controlled identity provider through IDPUploadViews to obtain sessions as cross-tenant users, and can modify or delete other organizations' identity-provider configurations.

- [https://github.com/googlesky/CVE-2026-135157](https://github.com/googlesky/CVE-2026-135157) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135157.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135157.svg)


## CVE-2026-135150
  3.8.15 does not set it, allowing the same impersonation without path manipulation when pre-authentication is enabled. This bypasses the fix for CVE-2026-120753.

- [https://github.com/abraxas/cve-2026-135150-lab](https://github.com/abraxas/cve-2026-135150-lab) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-135150-lab.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-135150-lab.svg)


## CVE-2026-135090
 A vulnerability was determined in humhub lets-meet up to 1.2.1. Affected by this vulnerability is the function NewInviteNotification::html of the file notifications/NewInviteNotification.php of the component Notification Rendering. Executing a manipulation can lead to cross site scripting. The attack may be performed from remote. The exploit has been publicly disclosed and may be utilized. Upgrading to version 1.2.2 addresses this issue. This patch is called 6c82534ffcb90e74229671a76caef1a8285c5190. Upgrading the affected component is advised.

- [https://github.com/googlesky/CVE-2026-135090](https://github.com/googlesky/CVE-2026-135090) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135090.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135090.svg)


## CVE-2026-135089
 A vulnerability was found in humhub questions up to 1.1.5. Affected is an unknown function of the file widgets/views/answer.php of the component QA Module. Performing a manipulation of the argument displayName results in cross site scripting. The attack is possible to be carried out remotely. The exploit has been made public and could be used. Upgrading to version 1.1.6 is able to address this issue. The patch is named cdc39878ba457ca71271c1ec3cf05fe025e3e9fc. It is recommended to upgrade the affected component.

- [https://github.com/googlesky/CVE-2026-135089](https://github.com/googlesky/CVE-2026-135089) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135089.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135089.svg)


## CVE-2026-134401
 Improper input validation in Variations in Google Chrome prior to 158.0.8127.88 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/Mahgal/chrome-sandbox-check](https://github.com/Mahgal/chrome-sandbox-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/chrome-sandbox-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/chrome-sandbox-check.svg)


## CVE-2026-134262
 Admidio 5.0.0 before 5.0.18 contains a stored cross-site scripting vulnerability that allows role administrators to inject JavaScript by placing quote-breaking payloads in role names rendered unencoded in the data-message attribute in modules/profile/roles_functions.php. Attackers can execute scripts when a full administrator views an affected profile page, stealing the CSRF token to assign themselves the Administrator role.

- [https://github.com/ShoIsMyName/CVE-2026-134262](https://github.com/ShoIsMyName/CVE-2026-134262) :  ![starts](https://img.shields.io/github/stars/ShoIsMyName/CVE-2026-134262.svg) ![forks](https://img.shields.io/github/forks/ShoIsMyName/CVE-2026-134262.svg)


## CVE-2026-134023
 TastyIgniter is an open-source online ordering, table reservation, and restaurant management system. Prior to 4.2.0, checkResetPasswordCode() in src/Auth/Models/User.php compares a submitted reset code with the stored 42-character token using a normal string comparison, which can return after the first differing byte instead of taking constant time. The password-reset flow exposes this comparison to remote requests, but the endpoint is rate-limited to six requests per minute per IP, and the advisory reports no live exploit or practical token-recovery demonstration. Recovering a high-entropy reset code through the constrained timing signal could permit an unauthorized password reset. This issue is fixed in version 4.2.0.

- [https://github.com/googlesky/CVE-2026-134023](https://github.com/googlesky/CVE-2026-134023) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134023.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134023.svg)


## CVE-2026-134022
 TastyIgniter is an open-source online ordering, table reservation, and restaurant management system. Prior to 4.2.0, the User extension’s onRequestResetPassword() handler in src/Http/Controllers/Login.php calls resetPassword() and mailSendResetPasswordRequest() only when an account matches. The resulting database write and reset-email send take longer than the nonexistent-account path despite the endpoint returning the same response, allowing timing measurements against a production deployment using a synchronous queue and real SMTP transport to disclose valid staff or customer email addresses. The advisory’s local log-mailer test showed no measurable timing difference, so the signal depends on mail configuration and is useful for follow-on phishing or credential stuffing rather than direct account access. This issue is fixed in version 4.2.0.

- [https://github.com/googlesky/CVE-2026-134022](https://github.com/googlesky/CVE-2026-134022) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134022.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134022.svg)


## CVE-2026-134021
 TastyIgniter is an open-source online ordering, table reservation, and restaurant management system. Prior to 4.3.1, the Mollie payment notification handler in src/Payments/Mollie.php, processNotifyUrl(), uses a payment ID supplied with the notification to retrieve a paid transaction but does not verify that the transaction's order reference matches the order identified by the notification URL or that the transaction amount matches the order total. An ordinary customer can use a paid Mollie transaction from one order to cause a different, higher-value order to be marked paid without paying its full price. The endpoint is intentionally unauthenticated so Mollie's servers can reach it, and the request's order hash alone does not bind the fetched payment to that order. This issue is fixed in version 4.3.1.

- [https://github.com/googlesky/CVE-2026-134021](https://github.com/googlesky/CVE-2026-134021) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134021.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134021.svg)


## CVE-2026-133632
 In astro-airflow-mcp 0.5.0 through 0.9.1, the af CLI and the MCP server send telemetry from a Python subprocess that can import modules from the current working directory. If a user runs an af command or an MCP tool call from inside a project that contains an attacker-supplied json.py, that file runs with the user's privileges. Users who only run the tool in projects they trust are not affected. Fixed in 0.9.2; in earlier versions, setting AF_TELEMETRY_DISABLED=1 prevents it.

- [https://github.com/googlesky/CVE-2026-133632](https://github.com/googlesky/CVE-2026-133632) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133632.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133632.svg)


## CVE-2026-133455
 AutoGPT is a workflow automation platform for creating, deploying, and managing continuous artificial intelligence agents. Prior to 0.9.0, nested tools invoked by OrchestratorBlock bypass the main execution queue and are charged only after succeeding, but post-run billing still refunds a failed tool's catalogue price as a presumed pre-flight charge. Any authenticated customer can trigger failed nested calls to add uncharged credits to their balance and fund later executions using the operator's credentials. This issue is fixed in version 0.9.0.

- [https://github.com/googlesky/CVE-2026-133455](https://github.com/googlesky/CVE-2026-133455) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133455.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133455.svg)


## CVE-2026-132270
 AutoGPT is a workflow automation platform for creating, deploying, and managing continuous artificial intelligence agents. In versions 0.7.1 through 0.8.4, AutoPilot prices block calls using model-supplied input but executes them with the server-resolved credential. Supplying a syntactically valid placeholder credential causes the price rule to evaluate to zero, skipping both the balance check and debit while still running paid blocks on the operator's credential. This issue is fixed in version 0.9.0.

- [https://github.com/googlesky/CVE-2026-132270](https://github.com/googlesky/CVE-2026-132270) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132270.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132270.svg)


## CVE-2026-131827
The specific flaw exists within the main IPC endpoint exposed by the RustDesk service. The issue results from the lack of authorization prior to allowing access to functionality. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-34805.

- [https://github.com/googlesky/CVE-2026-131827](https://github.com/googlesky/CVE-2026-131827) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-131827.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-131827.svg)


## CVE-2026-130178
 AutoGPT is a workflow automation platform for creating, deploying, and managing continuous artificial intelligence agents. In versions 0.7.1 through 0.8.4, an incomplete IPv6 blocklist in AutoGPT's outbound SSRF protection allows authenticated users to reach local or private network services. Specifically, _is_ip_blocked and BLOCKED_IP_NETWORKS in autogpt_platform/backend/backend/util/request.py fail to reject the IPv6 unspecified address :: (which connects to ::1 on Linux) as well as 6to4, NAT64, Teredo, and deprecated IPv4-compatible IPv6 encodings. An attacker can pass :: directly to blocks/sql_query_block.py or blocks/email_block.py, or point URL-fetching blocks, web fetch, MCP servers, webhooks, or OAuth at a hostname whose AAAA record resolves to ::. On backends run directly on a host, this exposes unauthenticated internal RPC services and databases listening on ::1, though the default Docker Compose and single-container deployments bind internal services to IPv4 only. This issue is fixed in version 0.9.0.

- [https://github.com/googlesky/CVE-2026-130178](https://github.com/googlesky/CVE-2026-130178) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130178.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130178.svg)


## CVE-2026-129830
 When the rsyslog's `imuxsock` is parsing the TAG field from a message with a accepted shorter timestamp, the cursor used to read the message fields and the remaining message length to be read are left in a inconsistent state in relation to the content in the raw message, leading the module to read one byte past the end of the buffer holding the message.

- [https://github.com/googlesky/CVE-2026-129830](https://github.com/googlesky/CVE-2026-129830) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129830.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129830.svg)


## CVE-2026-129024
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Everest Forms Everest Forms everest-forms allows Path Traversal.This issue affects Everest Forms: from n/a through 3.6.4.

- [https://github.com/kanokwut/CVE-2026-129024-poc](https://github.com/kanokwut/CVE-2026-129024-poc) :  ![starts](https://img.shields.io/github/stars/kanokwut/CVE-2026-129024-poc.svg) ![forks](https://img.shields.io/github/forks/kanokwut/CVE-2026-129024-poc.svg)


## CVE-2026-125812
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in WP Media WP Rocket wp-rocket allows Path Traversal.This issue affects WP Rocket: from n/a before 3.24.2.

- [https://github.com/joshuavanderpoll/CVE-2026-125812](https://github.com/joshuavanderpoll/CVE-2026-125812) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-125812.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-125812.svg)


## CVE-2026-125396
 Ghostscript before 10.08.0 contains a -dSAFER bypass vulnerability in the .putgstringcopy procedure in gs_fonts.ps, which calls the privileged .forceput operator without checking operand types. Attackers can supply crafted PostScript or PDF documents that trigger a type error, recover .forceput via a custom error handler, and cause a use-after-free across save/restore to execute arbitrary code.

- [https://github.com/DeathShotXD/Upload2Shell](https://github.com/DeathShotXD/Upload2Shell) :  ![starts](https://img.shields.io/github/stars/DeathShotXD/Upload2Shell.svg) ![forks](https://img.shields.io/github/forks/DeathShotXD/Upload2Shell.svg)
- [https://github.com/Luscious8/Upload2shell](https://github.com/Luscious8/Upload2shell) :  ![starts](https://img.shields.io/github/stars/Luscious8/Upload2shell.svg) ![forks](https://img.shields.io/github/forks/Luscious8/Upload2shell.svg)
- [https://github.com/vatansingh677-a11y/Upload2shell](https://github.com/vatansingh677-a11y/Upload2shell) :  ![starts](https://img.shields.io/github/stars/vatansingh677-a11y/Upload2shell.svg) ![forks](https://img.shields.io/github/forks/vatansingh677-a11y/Upload2shell.svg)


## CVE-2026-124851
 An information disclosure vulnerability in Zstandard versions 1.5.1 through 1.5.7 allows specially crafted compressed data to expose the contents of an internal buffer through decompressed output. The buffer is 64 KiB in the default configuration and may contain uninitialized memory or literals from earlier decompressions performed using the same decompression context. An attacker who can submit compressed data and observe the resulting output can recover the buffer's contents.

- [https://github.com/suominen/CVE-2026-124851](https://github.com/suominen/CVE-2026-124851) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-124851.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-124851.svg)


## CVE-2026-123529
 Vikunja before 2.7.1 contains a stored CSS injection vulnerability that allows authenticated users with project write access to inject arbitrary CSS via unsanitized table-cell data-background-color attributes. Attackers can store crafted task descriptions or comments to render full-viewport phishing overlays or force zero-click outbound background-image requests that deanonymize viewers.

- [https://github.com/r1alfarraj/vulnerability-research](https://github.com/r1alfarraj/vulnerability-research) :  ![starts](https://img.shields.io/github/stars/r1alfarraj/vulnerability-research.svg) ![forks](https://img.shields.io/github/forks/r1alfarraj/vulnerability-research.svg)


## CVE-2026-123528
 Vikunja before 2.7.1 contains an insufficient session expiration vulnerability that allows holders of revoked access tokens to keep authenticating because SetupTokenMiddleware skips session and account-status checks. Attackers with a stolen token can, after logout, password reset, or account disabling, mint OAuth sessions via /oauth/authorize or tk_ API tokens for persistent access.

- [https://github.com/r1alfarraj/vulnerability-research](https://github.com/r1alfarraj/vulnerability-research) :  ![starts](https://img.shields.io/github/stars/r1alfarraj/vulnerability-research.svg) ![forks](https://img.shields.io/github/forks/r1alfarraj/vulnerability-research.svg)


## CVE-2026-123214
 Joomla! Core - [20261111] - Core - Missing authentication in web installer in Joomla 4.0.0-5.4.10, 6.0.0-6.2.0 - The web installer remains usable on an installed site as long as the installation folder exists, allowing unauthenticated users to rewrite the configuration.

- [https://github.com/b3tar00t/joomsday](https://github.com/b3tar00t/joomsday) :  ![starts](https://img.shields.io/github/stars/b3tar00t/joomsday.svg) ![forks](https://img.shields.io/github/forks/b3tar00t/joomsday.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/ghackdeveloper-dotcom/CVE-2026-123158-sshhole](https://github.com/ghackdeveloper-dotcom/CVE-2026-123158-sshhole) :  ![starts](https://img.shields.io/github/stars/ghackdeveloper-dotcom/CVE-2026-123158-sshhole.svg) ![forks](https://img.shields.io/github/forks/ghackdeveloper-dotcom/CVE-2026-123158-sshhole.svg)
- [https://github.com/K3ysTr0K3R/CVE-2026-123158](https://github.com/K3ysTr0K3R/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-123158.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/CaptainAI-Labs/CVE-2026-123007](https://github.com/CaptainAI-Labs/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/CaptainAI-Labs/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/CaptainAI-Labs/CVE-2026-123007.svg)


## CVE-2026-120213
 @fastify/http-proxy is a Fastify plugin that proxies HTTP requests to an upstream server under a configured prefix. In versions 9.0.0 through 11.6.5, when an application uses parameterized prefix and rewritePrefix options to pin clients to a fixed upstream path, the plugin substitutes URL-decoded route parameters into rewritePrefix without re-encoding them. A parameter value that encodes a path separator together with a fragment or query delimiter therefore decodes into real separators and delimiters that inject extra upstream path segments and strip the mandatory suffix the rewritePrefix was meant to enforce, without using any dot-dot traversal. An unauthenticated remote attacker can use this to reach upstream locations outside the intended prefix, leading to path-restriction bypass and, depending on the upstream, server-side request forgery or authorization bypass in the proxied service. The issue is fixed in @fastify/http-proxy 11.6.6, and users should upgrade to 11.6.6 or later. There is no workaround other than upgrading.

- [https://github.com/Panelv4/CVE-Research-Dhairya-Sharma](https://github.com/Panelv4/CVE-Research-Dhairya-Sharma) :  ![starts](https://img.shields.io/github/stars/Panelv4/CVE-Research-Dhairya-Sharma.svg) ![forks](https://img.shields.io/github/forks/Panelv4/CVE-Research-Dhairya-Sharma.svg)


## CVE-2026-119776
  *  or ensure through firewall configuration that only packets with link-local or multicast destination addresses are accepted on input for IPv6 protocol 89 (OSPF). Note that checking the source address is insufficient, as some routers may (unexpectedly) forward packets with global-scoped IPv6 destination addresses even if they have link-local source addresses.

- [https://github.com/joomo-enterprises/frr-fixed](https://github.com/joomo-enterprises/frr-fixed) :  ![starts](https://img.shields.io/github/stars/joomo-enterprises/frr-fixed.svg) ![forks](https://img.shields.io/github/forks/joomo-enterprises/frr-fixed.svg)


## CVE-2026-117518
 @fastify/reply-from is a Fastify plugin that forwards requests to an upstream HTTP server. In versions up to and including 12.8.0, the plugin validated proxy paths against forward-slash dot-segments only and then built the target with the WHATWG URL parser, which normalizes a backslash and its percent-encoded form to a forward slash on the http, https, ws, and wss schemes. A path that uses backslash dot-segments therefore bypasses the traversal check and resolves to a different upstream path, so an application that scopes proxying to an upstream prefix, or relies on route guards in front of the forwarding call, can have an unauthenticated request escape the intended prefix and reach other upstream endpoints. The resulting access to unintended upstream resources is primarily a confidentiality impact with limited integrity impact. The issue is fixed in @fastify/reply-from 12.8.1, where the path is normalized and any segment resolving to a single or double dot, along with control characters and ambiguous whitespace, is rejected before the URL is constructed, and users should upgrade to 12.8.1 or later. There is no workaround other than upgrading.

- [https://github.com/Panelv4/CVE-Research-Dhairya-Sharma](https://github.com/Panelv4/CVE-Research-Dhairya-Sharma) :  ![starts](https://img.shields.io/github/stars/Panelv4/CVE-Research-Dhairya-Sharma.svg) ![forks](https://img.shields.io/github/forks/Panelv4/CVE-Research-Dhairya-Sharma.svg)


## CVE-2026-116592
 undici is an HTTP client for Node.js. In versions 7.30.1 and 8.12.2 through 8.12.3, when an originless Agent composes the redirect and shared cache interceptors, undici decides whether to store the final response under the original request key by inspecting only the final redirect hop, which bypasses the earlier fix for CVE-2026-109829 that compared only the initial and final origins. A redirect that bounces through an untrusted origin and returns to the trusted origin is still cached under the trusted key, an intermediate hop's Vary is dropped so a response that varies on Authorization or Cookie can be served to a different user, and an intermediate hop's no-cache or default-uncacheable status is ignored so a non-storable redirect is laundered into a cacheable entry. An attacker who controls a redirect target from a trusted URL can poison the cached entry for that URL or have a private, per-user response served to a later caller. The issue is fixed in undici 7.30.2 and 8.12.4, and users should upgrade to one of those versions or later. As a workaround, compose the interceptors as cache then redirect, use per-origin dispatchers and cache stores, or disable shared caching on redirect-capable requests.

- [https://github.com/Panelv4/CVE-Research-Dhairya-Sharma](https://github.com/Panelv4/CVE-Research-Dhairya-Sharma) :  ![starts](https://img.shields.io/github/stars/Panelv4/CVE-Research-Dhairya-Sharma.svg) ![forks](https://img.shields.io/github/forks/Panelv4/CVE-Research-Dhairya-Sharma.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/victorlarrubia/Java4Shell](https://github.com/victorlarrubia/Java4Shell) :  ![starts](https://img.shields.io/github/stars/victorlarrubia/Java4Shell.svg) ![forks](https://img.shields.io/github/forks/victorlarrubia/Java4Shell.svg)
- [https://github.com/nu1170r007/java4shell](https://github.com/nu1170r007/java4shell) :  ![starts](https://img.shields.io/github/stars/nu1170r007/java4shell.svg) ![forks](https://img.shields.io/github/forks/nu1170r007/java4shell.svg)
- [https://github.com/jburgess-r7/java4shell-teamcity-poc](https://github.com/jburgess-r7/java4shell-teamcity-poc) :  ![starts](https://img.shields.io/github/stars/jburgess-r7/java4shell-teamcity-poc.svg) ![forks](https://img.shields.io/github/forks/jburgess-r7/java4shell-teamcity-poc.svg)


## CVE-2026-107784
 On Windows, the tarfile "tar" and "data" extraction filters did not reject member names or link targets that have a drive but no root, such as "C:foo". When extracting to a relative destination, such a member was written to the current working directory of that drive instead of the destination, and a symbolic link with such a target pointed outside the destination. The filters now refuse these member names and link targets with AbsolutePathError and AbsoluteLinkError.

- [https://github.com/googlesky/CVE-2026-107784](https://github.com/googlesky/CVE-2026-107784) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-107784.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-107784.svg)


## CVE-2026-103406
 An Improper Neutralization of Special Elements used in an OS Command vulnerability in the AutomatedProvisioner in Juniper Networks Session Smart Conductor allows a remote attacker to execute arbitrary commands as root via a specially crafted salt minion ID.

- [https://github.com/Sable-Research/CVE-2026-103406-Analysis](https://github.com/Sable-Research/CVE-2026-103406-Analysis) :  ![starts](https://img.shields.io/github/stars/Sable-Research/CVE-2026-103406-Analysis.svg) ![forks](https://img.shields.io/github/forks/Sable-Research/CVE-2026-103406-Analysis.svg)
- [https://github.com/Frostmoon39206/CVE-2026-103406-PoC](https://github.com/Frostmoon39206/CVE-2026-103406-PoC) :  ![starts](https://img.shields.io/github/stars/Frostmoon39206/CVE-2026-103406-PoC.svg) ![forks](https://img.shields.io/github/forks/Frostmoon39206/CVE-2026-103406-PoC.svg)


## CVE-2026-99491
desynchronization.

- [https://github.com/ChaYeWuu/prague-CVE-2026-99491](https://github.com/ChaYeWuu/prague-CVE-2026-99491) :  ![starts](https://img.shields.io/github/stars/ChaYeWuu/prague-CVE-2026-99491.svg) ![forks](https://img.shields.io/github/forks/ChaYeWuu/prague-CVE-2026-99491.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/k-o-n-t-o-r/sm-s936b-cve-2026-98260](https://github.com/k-o-n-t-o-r/sm-s936b-cve-2026-98260) :  ![starts](https://img.shields.io/github/stars/k-o-n-t-o-r/sm-s936b-cve-2026-98260.svg) ![forks](https://img.shields.io/github/forks/k-o-n-t-o-r/sm-s936b-cve-2026-98260.svg)


## CVE-2026-92018
 Sandbox escape in the DOM: Core & HTML component. This vulnerability was fixed in Firefox 156, Firefox ESR 115.41, Firefox ESR 140.16, Firefox ESR 153.3, Thunderbird 156, Thunderbird 140.16, and Thunderbird 153.3.

- [https://github.com/0x4lter/firefox-sandbox-escape-cve-2026-92018](https://github.com/0x4lter/firefox-sandbox-escape-cve-2026-92018) :  ![starts](https://img.shields.io/github/stars/0x4lter/firefox-sandbox-escape-cve-2026-92018.svg) ![forks](https://img.shields.io/github/forks/0x4lter/firefox-sandbox-escape-cve-2026-92018.svg)


## CVE-2026-81419
 Nmap before 7.992 contains an infinite loop vulnerability in the LSUpdate.parse function of the NSE ospf.lua library, which does not advance when it reads an LSA header with a zero length. An attacker on the same layer 2 segment can send a single spoofed, unauthenticated OSPF LS Update packet, causing a permanent 100% CPU hang of the Nmap process as soon as broadcast-ospf2-discover.nse captures it.

- [https://github.com/googlesky/CVE-2026-81419](https://github.com/googlesky/CVE-2026-81419) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-81419.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-81419.svg)


## CVE-2026-77918
 Gogs through 0.14.4 contains an information disclosure vulnerability that allows authenticated users to view private forks by querying fork listings without per-fork read checks. Attackers with read access to a private base repository can call GET /api/v1/repos/{owner}/{repo}/forks or the Forks web handler to obtain other users' private fork owners, names, descriptions and clone URLs.

- [https://github.com/googlesky/CVE-2026-77918](https://github.com/googlesky/CVE-2026-77918) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77918.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77918.svg)


## CVE-2026-77806
 SPIP before 4.4.21 allows unauthenticated remote attackers to execute arbitrary code, as exploited in the wild in August 2026. This is related to code injection via an X-Spip-Filtre HTTP request header that is mishandled by analyse_resultat_skel.

- [https://github.com/K3ysTr0K3R/CVE-2026-77806](https://github.com/K3ysTr0K3R/CVE-2026-77806) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-77806.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-77806.svg)


## CVE-2026-77230
 Camunda 8.8.0 before 8.8.47, 8.9.0 before 8.9.29, 8.10.0 before 8.10.10, and 8.11.0-alpha1 contain an insecure deserialization vulnerability in the persistent web session feature, which stores session attributes as Java-serialized data in secondary storage and deserializes them via an ObjectInputStream without an ObjectInputFilter. Attackers with write access to the web session index, such as an unauthenticated Elasticsearch cluster deployed via Camunda's docker-compose files, can plant a crafted serialized object and trigger deserialization by presenting a matching session cookie, which combined with a gadget chain like the bundled Commons Collections 3.1-RC1 library can lead to code execution as the Camunda service account.

- [https://github.com/googlesky/CVE-2026-77230](https://github.com/googlesky/CVE-2026-77230) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77230.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77230.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass](https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass) :  ![starts](https://img.shields.io/github/stars/M4xSec/wp2shell-Exploit-Waf-Bypass.svg) ![forks](https://img.shields.io/github/forks/M4xSec/wp2shell-Exploit-Waf-Bypass.svg)
- [https://github.com/QGQ123-qwq/CVE-2026-63030-poc](https://github.com/QGQ123-qwq/CVE-2026-63030-poc) :  ![starts](https://img.shields.io/github/stars/QGQ123-qwq/CVE-2026-63030-poc.svg) ![forks](https://img.shields.io/github/forks/QGQ123-qwq/CVE-2026-63030-poc.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass](https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass) :  ![starts](https://img.shields.io/github/stars/M4xSec/wp2shell-Exploit-Waf-Bypass.svg) ![forks](https://img.shields.io/github/forks/M4xSec/wp2shell-Exploit-Waf-Bypass.svg)


## CVE-2026-52806
 Gogs is an open source self-hosted Git service. Prior to 0.14.3, Gogs allows authenticated users to achieve Remote Code Execution (RCE) on the server by creating a pull request with a specially crafted branch name that injects the --exec flag into the git rebase command during the "Rebase before merging" merge operation. This vulnerability is fixed in 0.14.3.

- [https://github.com/portbuster1337/CVE-2026-52806](https://github.com/portbuster1337/CVE-2026-52806) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-52806.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-52806.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/K3ysTr0K3R/CVE-2026-48907](https://github.com/K3ysTr0K3R/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-48907.svg)


## CVE-2026-47156
 MantisBT is an open source bug tracker. Versions 2.28.3 and earlier contain a critical authentication bypass in the SOAP API's mci_check_login() function. Any user knowing any valid cookie_string can authenticate as any other user (knowing their username), including the administrator, without knowing the target's password. The vulnerability is exploitable with zero prior access on default MantisBT installations because self-registration is enabled by default ($g_allow_signup = ON). A self-registered user can use their own cookie_string (readable from their browser's MANTIS_STRING_COOKIE cookie after login) to impersonate the administrator via the SOAP API. The REST API is NOT affected. The REST API's AuthMiddleware derives the username server-side from the API token or session cookie, so the username cannot be spoofed. The Web UI is NOT affected. The Web UI authenticates via PHP session cookies (PHPSESSID) and validates the MANTIS_STRING_COOKIE against the logged-in user through auth_is_cookie_valid(). The username is derived server-side from the cookie, not supplied by the client. Version 2.28.4 contains a patch. No known workarounds are available.

- [https://github.com/kanokwut/CVE-2026-47156-incomplete-fix-poc](https://github.com/kanokwut/CVE-2026-47156-incomplete-fix-poc) :  ![starts](https://img.shields.io/github/stars/kanokwut/CVE-2026-47156-incomplete-fix-poc.svg) ![forks](https://img.shields.io/github/forks/kanokwut/CVE-2026-47156-incomplete-fix-poc.svg)


## CVE-2026-46376
 FreePBX is an open source IP PBX. From 15.0.42 to before 16.0.45 and 17.0.7, unauthenticated users may be able to access the User Control Panel (UCP) using hard-coded initial template credentials if these were not immediately changed by the Administrator who enabled UCP. Authenticated access to ACP is required for the initial setup of UCP generic templates, but after that, without further steps by the admin, unauthenticated users may be able to gain access. This vulnerability is fixed in 16.0.45 and 17.0.7.

- [https://github.com/portbuster1337/CVE-2026-46376](https://github.com/portbuster1337/CVE-2026-46376) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-46376.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-46376.svg)


## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/ghapvharmo/gha-lab-b113cc39e8](https://github.com/ghapvharmo/gha-lab-b113cc39e8) :  ![starts](https://img.shields.io/github/stars/ghapvharmo/gha-lab-b113cc39e8.svg) ![forks](https://img.shields.io/github/forks/ghapvharmo/gha-lab-b113cc39e8.svg)


## CVE-2026-44359
 Meshtastic is an open source mesh networking solution. Prior to version 2.7.21.1370b23, the Meshtastic GitHub repository's main_matrix.yml workflow is triggered by pull_request_target  and multiple jobs check out the attacker's fork code and execute it with access to repository secrets and elevated GITHUB_TOKEN permissions. No approval gate exists. Pull requests from external users with author_association: "NONE" triggered the CI workflow automatically. The workflow directly executes attacker-controlled files from the fork checkout. This issue could have resulted in supply chain compromise, self-hosted runner compromise, and/or repository takeover for the repo. This issue is separate from GHSA-6mwm-v2vv-pp96, which addressed a command injection via github.head_ref in the setup job of the same workflow. That fix correctly moved to environment variables. However, the more critical fork checkout vulnerability across the check, build, and build-debian-src jobs was not addressed. Version 2.7.21.1370b23 contains a patch for thie issue.

- [https://github.com/ghapvharmo/pwn-ci-matrix-src](https://github.com/ghapvharmo/pwn-ci-matrix-src) :  ![starts](https://img.shields.io/github/stars/ghapvharmo/pwn-ci-matrix-src.svg) ![forks](https://img.shields.io/github/forks/ghapvharmo/pwn-ci-matrix-src.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/tingao/debian-on-s23-ultra](https://github.com/tingao/debian-on-s23-ultra) :  ![starts](https://img.shields.io/github/stars/tingao/debian-on-s23-ultra.svg) ![forks](https://img.shields.io/github/forks/tingao/debian-on-s23-ultra.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/zwanski2019/cPanelSniper](https://github.com/zwanski2019/cPanelSniper) :  ![starts](https://img.shields.io/github/stars/zwanski2019/cPanelSniper.svg) ![forks](https://img.shields.io/github/forks/zwanski2019/cPanelSniper.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/K3ysTr0K3R/CVE-2026-39987](https://github.com/K3ysTr0K3R/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-39987.svg)


## CVE-2026-39816
 The optional extension component TinkerpopClientService is missing the Restricted annotation with the Execute Code Required Permission in Apache NiFi 2.0.0-M1 through 2.8.0. The TinkerpopClientService supports configuration of ByteCode Submission for the Script Submission Type, enabling Groovy Script execution in the service prior to submitting the query. The missing Restricted annotation allows users without the Execute Code Permission to configure the Service in installations that use fine-grained authorization and have the optional TinkerpopClientService installed. Apache NiFi installations that do not have the nifi-other-graph-services-nar installed are not subject to this vulnerability. Upgrading to Apache NiFi 2.9.0 is the recommended mitigation.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-34486
Users are recommended to upgrade to version 11.0.21, 10.1.54 or 9.0.117, which fix the issue.

- [https://github.com/punitdarji/tomcat-cve-2026-34486](https://github.com/punitdarji/tomcat-cve-2026-34486) :  ![starts](https://img.shields.io/github/stars/punitdarji/tomcat-cve-2026-34486.svg) ![forks](https://img.shields.io/github/forks/punitdarji/tomcat-cve-2026-34486.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/K3ysTr0K3R/CVE-2026-34197](https://github.com/K3ysTr0K3R/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-34197.svg)


## CVE-2026-33712
 Typebot is a chatbot builder tool. In versions 3.15.2 and prior, the preview chat endpoint (POST /api/v1/typebots/{typebotId}/preview/startChat) allows unauthenticated users to achieve Server-Side Request Forgery (SSRF) by supplying a custom typebot definition with server-side code blocks. The fetch function exposed inside the isolated-vm sandbox calls Node.js native fetch without the SSRF validation (validateHttpReqUrl) that protects the HTTP Request block. This bypasses all SSRF mitigations added after GHSA-8gq9-rw7v-3jpr. Exploitation of this unauthenticated SSRF vulnerability can lead to cloud credential theft, internal network access and data exfiltration for any self-hosted Typebot deployments and hosted services. This issue has been fixed in version 3.16.0.

- [https://github.com/portbuster1337/CVE-2026-33712](https://github.com/portbuster1337/CVE-2026-33712) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-33712.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-33712.svg)


## CVE-2026-33137
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. XWiki Platform is a generic wiki platform. In versions starting with 15.10.6 and prior to 18.1.0-rc-1, 17.10.3, 17.4.9, and 16.10.17, the POST /wikis/{wikiName} API executes a XAR import without performing any authentication or authorization checks, allowing an unauthenticated attacker to create or update documents in the target wiki. This vulnerability has been patched in XWiki 16.10.17, 17.4.9, 17.10.3, 18.0.1 and 18.1.0-rc-1.

- [https://github.com/portbuster1337/CVE-2026-33137](https://github.com/portbuster1337/CVE-2026-33137) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-33137.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-33137.svg)


## CVE-2026-32604
 Spinnaker is an open source, multi-cloud continuous delivery platform. In versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2, a bad actor can execute arbitrary commands very simply on the clouddriver pods. This can expose credentials, remove files, or inject resources easily. Versions 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2 contain a patch. As a workaround, disable the gitrepo artifact types.

- [https://github.com/K3ysTr0K3R/CVE-2026-32604](https://github.com/K3ysTr0K3R/CVE-2026-32604) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-32604.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-32604.svg)


## CVE-2026-31816
 Budibase is a low code platform for creating internal tools, workflows, and admin panels. In 3.31.4 and earlier, the Budibase server's authorized() middleware that protects every server-side API endpoint can be completely bypassed by appending a webhook path pattern to the query string of any request. The isWebhookEndpoint() function uses an unanchored regex that tests against ctx.request.url, which in Koa includes the full URL with query parameters. When the regex matches, the authorized() middleware immediately calls return next(), skipping all authentication, authorization, role checks, and CSRF protection. This means a completely unauthenticated, remote attacker can access any server-side API endpoint by simply appending ?/webhooks/trigger (or any webhook pattern variant) to the URL.

- [https://github.com/K3ysTr0K3R/CVE-2026-31816](https://github.com/K3ysTr0K3R/CVE-2026-31816) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-31816.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-31816.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/M4xSec/CVE-2026-31431-RCE-Exploit](https://github.com/M4xSec/CVE-2026-31431-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/M4xSec/CVE-2026-31431-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/M4xSec/CVE-2026-31431-RCE-Exploit.svg)
- [https://github.com/erlangparasu/mitigate_cve_2026_31431-sh](https://github.com/erlangparasu/mitigate_cve_2026_31431-sh) :  ![starts](https://img.shields.io/github/stars/erlangparasu/mitigate_cve_2026_31431-sh.svg) ![forks](https://img.shields.io/github/forks/erlangparasu/mitigate_cve_2026_31431-sh.svg)


## CVE-2026-29053
 Ghost is a Node.js content management system. From version 0.7.2 to 6.19.0, specifically crafted malicious themes can execute arbitrary code on the server running Ghost. This issue has been patched in version 6.19.1.

- [https://github.com/K3ysTr0K3R/CVE-2026-29053](https://github.com/K3ysTr0K3R/CVE-2026-29053) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-29053.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-29053.svg)


## CVE-2026-27771
 Gitea versions up to and including 1.26.1 have insufficient permission checks for Composer package source links, which can expose private or internal package source information.

- [https://github.com/portbuster1337/CVE-2026-27771](https://github.com/portbuster1337/CVE-2026-27771) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-27771.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-27771.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/franckferman/CVE-2026-24061](https://github.com/franckferman/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE-2026-24061.svg)
- [https://github.com/K3ysTr0K3R/CVE-2026-24061](https://github.com/K3ysTr0K3R/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-24061.svg)
- [https://github.com/punitdarji/telnetd-cve-2026-24061](https://github.com/punitdarji/telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/punitdarji/telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/punitdarji/telnetd-cve-2026-24061.svg)


## CVE-2026-20182
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to the affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.

- [https://github.com/portbuster1337/CVE-2026-20182](https://github.com/portbuster1337/CVE-2026-20182) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-20182.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-20182.svg)


## CVE-2026-19478
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an unauthenticated user to remotely modify or delete public projects and user data via a GraphQL directive.

- [https://github.com/punitdarji/Gitlab-CVE-2026-19478](https://github.com/punitdarji/Gitlab-CVE-2026-19478) :  ![starts](https://img.shields.io/github/stars/punitdarji/Gitlab-CVE-2026-19478.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Gitlab-CVE-2026-19478.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-16668
The fix is to bound the skip: thread a recursion-depth counter through zcbor_any_skip() (or have zcbor_map_decode_bulk() reject values nested beyond a small constant) and fail once the limit is exceeded — equivalently, take the bounded-skip implementation from upstream zcbor.

- [https://github.com/googlesky/CVE-2026-16668](https://github.com/googlesky/CVE-2026-16668) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-16668.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-16668.svg)


## CVE-2026-16665
(Truncated. The full description is in the advisory: https://github.com/mcu-tools/mcuboot/security/advisories/GHSA-cr9j-p626-pwcc)

- [https://github.com/googlesky/CVE-2026-16665](https://github.com/googlesky/CVE-2026-16665) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-16665.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-16665.svg)


## CVE-2026-16663
On releases before v2.0.0 (v1.9.0 and v1.10.0) the destination is a file-scope static uint8_t buf[SOC_FLASH_ERASE_BLK_SZ] in .bss rather than the stack VLA described above — the code then lived in boot/zephyr/single_loader.c, before commit c9fa6088 relocated it to boot/boot_serial/src/boot_serial_encryption.c and changed the buffer's storage class. The out-of-bounds write is equally real and equally pre-authentication on those releases, but it corrupts adjacent static data rather than the stack, so a stack-smashing proof of concept written against a current release will not reproduce as-is there.

- [https://github.com/googlesky/CVE-2026-16663](https://github.com/googlesky/CVE-2026-16663) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-16663.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-16663.svg)


## CVE-2026-13216
The fix replaces the compiled-out assert with a runtime range check rejecting cap_len outside [sizeof(struct virtio_pci_cap), cap_struct_size] before any arithmetic or copy.

- [https://github.com/lxdwnpiper/CVE-2026-132165-Drupal](https://github.com/lxdwnpiper/CVE-2026-132165-Drupal) :  ![starts](https://img.shields.io/github/stars/lxdwnpiper/CVE-2026-132165-Drupal.svg) ![forks](https://img.shields.io/github/forks/lxdwnpiper/CVE-2026-132165-Drupal.svg)
- [https://github.com/ashrafzaryouh/CVE-2026-132165](https://github.com/ashrafzaryouh/CVE-2026-132165) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-132165.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-132165.svg)
- [https://github.com/malloryai/cve-2026-132165-drupal-installer-check](https://github.com/malloryai/cve-2026-132165-drupal-installer-check) :  ![starts](https://img.shields.io/github/stars/malloryai/cve-2026-132165-drupal-installer-check.svg) ![forks](https://img.shields.io/github/forks/malloryai/cve-2026-132165-drupal-installer-check.svg)


## CVE-2026-13192
 In Progress® Telerik® UI for AJAX prior to v2026.2.708, insufficient validation of content submitted to the RadEditor PDF export feature may allow an authenticated attacker to trigger server-side requests to arbitrary hosts, resulting in outbound network connections and potential exposure of Windows authentication credentials.

- [https://github.com/kristupasp/CVE-2026-131924](https://github.com/kristupasp/CVE-2026-131924) :  ![starts](https://img.shields.io/github/stars/kristupasp/CVE-2026-131924.svg) ![forks](https://img.shields.io/github/forks/kristupasp/CVE-2026-131924.svg)


## CVE-2026-12390
 In AzeoTech DAQFactory versions 21.1 and prior, a Type Confusion vulnerability can be exploited by an attacker using specially crafted .ctl files which can result in code execution.

- [https://github.com/Hann1bl3L3ct3r/CVE-2026-123903](https://github.com/Hann1bl3L3ct3r/CVE-2026-123903) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-123903.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-123903.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/franckferman/CVE-2026-109619](https://github.com/franckferman/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE-2026-109619.svg)
- [https://github.com/franckferman/CVE-2026-109618](https://github.com/franckferman/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE-2026-109618.svg)
- [https://github.com/MorphingYU/CVE-2026-109619](https://github.com/MorphingYU/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109619.svg)


## CVE-2026-10701
 Incorrect boundary conditions in the Graphics: Text component. This vulnerability was fixed in Firefox 151.0.3.

- [https://github.com/ashrafzaryouh/CVE-2026-10701](https://github.com/ashrafzaryouh/CVE-2026-10701) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-10701.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-10701.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/K3ysTr0K3R/CVE-2026-9198](https://github.com/K3ysTr0K3R/CVE-2026-9198) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-9198.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-9198.svg)


## CVE-2026-7474
 HashiCorp Nomad and Nomad Enterprise prior to 2.0.1 are vulnerable to code execution on the client host through a path traversal attack. This vulnerability (CVE-2026-7474) is fixed in Nomad 2.0.1, 1.11.5 and 1.10.11.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-5006
This vulnerability, CVE-2026-5006, was fixed in Vault Community Edition 2.0.4 and Vault Enterprise 2.0.4, 1.21.9, 1.20.14, and 1.19.20.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-4152
The specific flaw exists within the parsing of JP2 files. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-28863.

- [https://github.com/oliv4s/CVE-2026-41528](https://github.com/oliv4s/CVE-2026-41528) :  ![starts](https://img.shields.io/github/stars/oliv4s/CVE-2026-41528.svg) ![forks](https://img.shields.io/github/forks/oliv4s/CVE-2026-41528.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)
- [https://github.com/Gr-1m/CVE-2026-31431](https://github.com/Gr-1m/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2026-31431.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)
- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)


## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.

- [https://github.com/K3ysTr0K3R/CVE-2026-0920](https://github.com/K3ysTr0K3R/CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-0920.svg)


## CVE-2025-67906
 In MISP before 2.5.28, app/View/Elements/Workflows/executionPath.ctp allows XSS in the workflow execution path.

- [https://github.com/franckferman/CVE-2025-67906](https://github.com/franckferman/CVE-2025-67906) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE-2025-67906.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE-2025-67906.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/K3ysTr0K3R/CVE-2025-57819](https://github.com/K3ysTr0K3R/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2025-57819.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/M4xSec/CVE-2025-55182-React2Shell-RCE-Shell](https://github.com/M4xSec/CVE-2025-55182-React2Shell-RCE-Shell) :  ![starts](https://img.shields.io/github/stars/M4xSec/CVE-2025-55182-React2Shell-RCE-Shell.svg) ![forks](https://img.shields.io/github/forks/M4xSec/CVE-2025-55182-React2Shell-RCE-Shell.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2025-32463-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2025-32463-EXPLOIT.svg)


## CVE-2025-26326
 A vulnerability was identified in the NVDA Remote (version 2.6.4) and Tele NVDA Remote (version 2025.3.3) remote connection add-ons, which allows an attacker to obtain total control of the remote system by guessing a weak password. The problem occurs because these add-ons accept any password entered by the user and do not have an additional authentication or computer verification mechanism. Tests indicate that more than 1,000 systems use easy-to-guess passwords, many with less than 4 to 6 characters, including common sequences. This allows brute force attacks or trial-and-error attempts by malicious invaders. The vulnerability can be exploited by a remote attacker who knows or can guess the password used in the connection. As a result, the attacker gains complete access to the affected system and can execute commands, modify files, and compromise user security.

- [https://github.com/azurejoga/CVE-2025-26326](https://github.com/azurejoga/CVE-2025-26326) :  ![starts](https://img.shields.io/github/stars/azurejoga/CVE-2025-26326.svg) ![forks](https://img.shields.io/github/forks/azurejoga/CVE-2025-26326.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/DAEMON-404/PoC-CVE-2025-24071](https://github.com/DAEMON-404/PoC-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/DAEMON-404/PoC-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/DAEMON-404/PoC-CVE-2025-24071.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2025-5360
 A vulnerability classified as critical was found in Campcodes Online Hospital Management System 1.0. This vulnerability affects unknown code of the file /book-appointment.php. The manipulation of the argument doctor leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/phor3nsic/CVE-2025-53607](https://github.com/phor3nsic/CVE-2025-53607) :  ![starts](https://img.shields.io/github/stars/phor3nsic/CVE-2025-53607.svg) ![forks](https://img.shields.io/github/forks/phor3nsic/CVE-2025-53607.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/punitdarji/Grafana-cve-2025-4123](https://github.com/punitdarji/Grafana-cve-2025-4123) :  ![starts](https://img.shields.io/github/stars/punitdarji/Grafana-cve-2025-4123.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Grafana-cve-2025-4123.svg)


## CVE-2025-2825
 DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2025-31161. Reason: This Record is a reservation duplicate of CVE-2025-31161. Notes: All CVE users should reference CVE-2025-31161 instead of this Record. All references and descriptions in this Record have been removed to prevent accidental usage.

- [https://github.com/punitdarji/crushftp-CVE-2025-2825](https://github.com/punitdarji/crushftp-CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/punitdarji/crushftp-CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/punitdarji/crushftp-CVE-2025-2825.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/punitdarji/Ivanti-CVE-2025-0282](https://github.com/punitdarji/Ivanti-CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/punitdarji/Ivanti-CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Ivanti-CVE-2025-0282.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/azurejoga/CVE-2024-6387-how-to-fix](https://github.com/azurejoga/CVE-2024-6387-how-to-fix) :  ![starts](https://img.shields.io/github/stars/azurejoga/CVE-2024-6387-how-to-fix.svg) ![forks](https://img.shields.io/github/forks/azurejoga/CVE-2024-6387-how-to-fix.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/artnet82/CVE-2024-4577](https://github.com/artnet82/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/artnet82/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/artnet82/CVE-2024-4577.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/khaidoan04/CVE-2024-3400-Wazuh-ML-Detection](https://github.com/khaidoan04/CVE-2024-3400-Wazuh-ML-Detection) :  ![starts](https://img.shields.io/github/stars/khaidoan04/CVE-2024-3400-Wazuh-ML-Detection.svg) ![forks](https://img.shields.io/github/forks/khaidoan04/CVE-2024-3400-Wazuh-ML-Detection.svg)


## CVE-2024-2473
 The WPS Hide Login plugin for WordPress is vulnerable to Login Page Disclosure in all versions up to, and including, 1.9.15.2. This is due to a bypass that is created when the 'action=postpass' parameter is supplied. This makes it possible for attackers to easily discover any login page that may have been hidden by the plugin.

- [https://github.com/M4xSec/CVE-2024-2473](https://github.com/M4xSec/CVE-2024-2473) :  ![starts](https://img.shields.io/github/stars/M4xSec/CVE-2024-2473.svg) ![forks](https://img.shields.io/github/forks/M4xSec/CVE-2024-2473.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/Bthn-celik/cve-2023-4863-analysis](https://github.com/Bthn-celik/cve-2023-4863-analysis) :  ![starts](https://img.shields.io/github/stars/Bthn-celik/cve-2023-4863-analysis.svg) ![forks](https://img.shields.io/github/forks/Bthn-celik/cve-2023-4863-analysis.svg)


## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112](https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/M4xSec/Apache-APISIX-CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/M4xSec/Apache-APISIX-CVE-2022-24112.svg)


## CVE-2021-33644
 An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longname, causing an out-of-bounds read.

- [https://github.com/nilondal/libtar-CVE-2021-33644-followup](https://github.com/nilondal/libtar-CVE-2021-33644-followup) :  ![starts](https://img.shields.io/github/stars/nilondal/libtar-CVE-2021-33644-followup.svg) ![forks](https://img.shields.io/github/forks/nilondal/libtar-CVE-2021-33644-followup.svg)


## CVE-2021-33200
 kernel/bpf/verifier.c in the Linux kernel through 5.12.7 enforces incorrect limits for pointer arithmetic operations, aka CID-bb01a1bba579. This can be abused to perform out-of-bounds reads and writes in kernel memory, leading to local privilege escalation to root. In particular, there is a corner case where the off reg causes a masking direction change, which then results in an incorrect final aux-alu_limit.

- [https://github.com/d4ytox/CVE-2021-33200](https://github.com/d4ytox/CVE-2021-33200) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2021-33200.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2021-33200.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/00xAuto/dbutil-2-3-CVE-2021-21551-Documentation](https://github.com/00xAuto/dbutil-2-3-CVE-2021-21551-Documentation) :  ![starts](https://img.shields.io/github/stars/00xAuto/dbutil-2-3-CVE-2021-21551-Documentation.svg) ![forks](https://img.shields.io/github/forks/00xAuto/dbutil-2-3-CVE-2021-21551-Documentation.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/LaurenceBDavid/CVE-2021-3493](https://github.com/LaurenceBDavid/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/LaurenceBDavid/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/LaurenceBDavid/CVE-2021-3493.svg)


## CVE-2020-35749
 Directory traversal vulnerability in class-simple_job_board_resume_download_handler.php in the Simple Board Job plugin 2.9.3 and earlier for WordPress allows remote attackers to read arbitrary files via the sjb_file parameter to wp-admin/post.php.

- [https://github.com/M4xSec/Wordpress-CVE-2020-35749](https://github.com/M4xSec/Wordpress-CVE-2020-35749) :  ![starts](https://img.shields.io/github/stars/M4xSec/Wordpress-CVE-2020-35749.svg) ![forks](https://img.shields.io/github/forks/M4xSec/Wordpress-CVE-2020-35749.svg)


## CVE-2020-20277
 There are multiple unauthenticated directory traversal vulnerabilities in different FTP commands in uftpd FTP server versions 2.7 to 2.10 due to improper implementation of a chroot jail in common.c's compose_abspath function that can be abused to read or write to arbitrary files on the filesystem, leak process memory, or potentially lead to remote code execution.

- [https://github.com/decoyishere/CVE-2020-20277-PoC](https://github.com/decoyishere/CVE-2020-20277-PoC) :  ![starts](https://img.shields.io/github/stars/decoyishere/CVE-2020-20277-PoC.svg) ![forks](https://img.shields.io/github/forks/decoyishere/CVE-2020-20277-PoC.svg)


## CVE-2019-16098
 The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

- [https://github.com/Fl0sec/RTCore64-CVE-2019-16098](https://github.com/Fl0sec/RTCore64-CVE-2019-16098) :  ![starts](https://img.shields.io/github/stars/Fl0sec/RTCore64-CVE-2019-16098.svg) ![forks](https://img.shields.io/github/forks/Fl0sec/RTCore64-CVE-2019-16098.svg)


## CVE-2019-15231
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2019-15107. Reason: This candidate is a duplicate of CVE-2019-15107. Notes: All CVE users should reference CVE-2019-15107 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage

- [https://github.com/wizardy0ga/THM-Source-CVE-2019-15231](https://github.com/wizardy0ga/THM-Source-CVE-2019-15231) :  ![starts](https://img.shields.io/github/stars/wizardy0ga/THM-Source-CVE-2019-15231.svg) ![forks](https://img.shields.io/github/forks/wizardy0ga/THM-Source-CVE-2019-15231.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/wizardy0ga/THM-Vulnerability_Capstone-CVE-2018-16763](https://github.com/wizardy0ga/THM-Vulnerability_Capstone-CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/wizardy0ga/THM-Vulnerability_Capstone-CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/wizardy0ga/THM-Vulnerability_Capstone-CVE-2018-16763.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/nullbyter19/cve-2018-10933](https://github.com/nullbyter19/cve-2018-10933) :  ![starts](https://img.shields.io/github/stars/nullbyter19/cve-2018-10933.svg) ![forks](https://img.shields.io/github/forks/nullbyter19/cve-2018-10933.svg)


## CVE-2016-0287
 IBM i Access 7.1 on Windows allows local users to discover registry passwords via unspecified vectors.

- [https://github.com/nullbyter19/cve-2016-0287](https://github.com/nullbyter19/cve-2016-0287) :  ![starts](https://img.shields.io/github/stars/nullbyter19/cve-2016-0287.svg) ![forks](https://img.shields.io/github/forks/nullbyter19/cve-2016-0287.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/wizardy0ga/THM-Steel_Mountain-CVE-2014-6287](https://github.com/wizardy0ga/THM-Steel_Mountain-CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/wizardy0ga/THM-Steel_Mountain-CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/wizardy0ga/THM-Steel_Mountain-CVE-2014-6287.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/wizardy0ga/CVE_2012-2982](https://github.com/wizardy0ga/CVE_2012-2982) :  ![starts](https://img.shields.io/github/stars/wizardy0ga/CVE_2012-2982.svg) ![forks](https://img.shields.io/github/forks/wizardy0ga/CVE_2012-2982.svg)

