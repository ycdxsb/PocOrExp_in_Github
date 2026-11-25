# Update 2026-11-25
## CVE-2026-135055
 A flaw was found in the GLib DMA-BUF path of WebKitGTK. The UIProcess trusted fds.size() as the DMA-BUF plane count when handling AcceleratedBackingStore::DidCreateDMABufBuffer and copied offsets and strides without verifying that those vectors had the same length. A compromised WebProcess can send mismatched vector lengths, causing an out-of-bounds read in the privileged UIProcess. This can disclose UIProcess memory and crash the UIProcess, and may be used as part of a Web Content sandbox-escape chain.

- [https://github.com/googlesky/CVE-2026-135055](https://github.com/googlesky/CVE-2026-135055) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135055.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135055.svg)


## CVE-2026-134935
 The dell-xps-touchpad-haptics package before 1.0.0-4 for Omarchy allows local users to change ownership of a root-owned file by making their own .config/omarchy/dell-haptic.conf file a symlink to that target file.

- [https://github.com/googlesky/CVE-2026-134935](https://github.com/googlesky/CVE-2026-134935) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134935.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134935.svg)


## CVE-2026-134840
 HumHub before 1.19.4 contains a missing authorization vulnerability in GroupController actionNewMemberSearch and actionAdminUserSearch, which skip the checkGroupAccess check. A manager of any single group can query admin-user-search and new-member-search with another group's id parameter to enumerate members, including administrators.

- [https://github.com/googlesky/CVE-2026-134840](https://github.com/googlesky/CVE-2026-134840) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134840.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134840.svg)


## CVE-2026-134839
 Linkwarden before 2.17.0 contains an incorrect authorization vulnerability in the archive upload handler that allows collection members with only add permission to modify other users' links. Attackers can send POST requests to /api/v1/archives/linkId to replace another user's stored screenshot, PDF, readable, or HTML archive with attacker-supplied content.

- [https://github.com/googlesky/CVE-2026-134839](https://github.com/googlesky/CVE-2026-134839) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134839.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134839.svg)


## CVE-2026-134838
 Weblate before 2026.11 contains an account takeover vulnerability in the reset_password view that allows unauthenticated attackers to reset victim passwords by abusing case-insensitive Unicode e-mail matching. Attackers controlling a lookalike mailbox using a dotless i or other case-folding variant receive the victim's reset link, since it is sent to the typed address, and set a new password.

- [https://github.com/googlesky/CVE-2026-134838](https://github.com/googlesky/CVE-2026-134838) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134838.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134838.svg)


## CVE-2026-134837
 Frappe before 15.126.0 and 16.x before 16.55.0 contains a prototype pollution vulnerability that allows Dashboard Manager users to pollute Object.prototype by storing __proto__ keys in Dashboard Chart custom_options. When any user, including administrators, views a dashboard rendering the chart, Object.assign merges attacker properties into Object.prototype, altering Frappe desk client behavior for that session.

- [https://github.com/googlesky/CVE-2026-134837](https://github.com/googlesky/CVE-2026-134837) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134837.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134837.svg)


## CVE-2026-134836
 Dashy 4.0.0 before 4.9.12 contains a credential disclosure vulnerability in isLocalRequest that attaches user credentials to lookalike hosts due to prefix-only origin checks. Attackers can lure logged-in users to a crafted ?config= link pointing to a lookalike host, capturing bearer tokens or HTTP auth headers to read configuration and stored API keys, or modify them when the victim is an admin.

- [https://github.com/googlesky/CVE-2026-134836](https://github.com/googlesky/CVE-2026-134836) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134836.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134836.svg)


## CVE-2026-134835
 Langfuse before 4.82.0 contains a server-side request forgery vulnerability that allows organization admins to target internal hosts by setting the GitHub Enterprise SSO baseUrl, which skips outbound-URL validation. Attackers can point baseUrl to loopback, RFC1918, or cloud metadata addresses so user sign-ins trigger server requests carrying stored OAuth client credentials.

- [https://github.com/googlesky/CVE-2026-134835](https://github.com/googlesky/CVE-2026-134835) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134835.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134835.svg)


## CVE-2026-134834
 Tandoor Recipes before 2.7.4 contains a path traversal vulnerability in Nextcloud.get_file that allows authenticated recipe editors to write and delete files by using unsanitized recipe names in temporary paths. Attackers can set a recipe name containing ../ segments via PATCH /api/recipe/pk/ and request /api/get_recipe_file/pk/ to overwrite and remove .pdf files outside the temporary directory.

- [https://github.com/googlesky/CVE-2026-134834](https://github.com/googlesky/CVE-2026-134834) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134834.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134834.svg)


## CVE-2026-134833
 RSSHub before 2026.11.01-8521.e529e9b contains a domain validation bypass in the javdb routes that allows unauthenticated attackers to capture the operator's JAVDB_SESSION cookie. Attackers can pass an absolute javdb.com URL in the category parameter and set the domain query to a host they control, causing processItems to send the _jdb_session cookie there.

- [https://github.com/googlesky/CVE-2026-134833](https://github.com/googlesky/CVE-2026-134833) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134833.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134833.svg)


## CVE-2026-134832
 Vim 9.2.0405 before 9.2.1352 contains a security bypass vulnerability in expand_tag_fname() that allows attackers to evade 'tagsecure' URL checks by escaping URLs in tags file entries. Attackers can supply a crafted tags file in a cloned repository so that jumping to a tag makes netrw fetch an attacker-controlled URL leaking environment variable values.

- [https://github.com/googlesky/CVE-2026-134832](https://github.com/googlesky/CVE-2026-134832) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134832.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134832.svg)


## CVE-2026-134831
 Chatwoot before 4.20.0 contains an information disclosure vulnerability that allows unauthenticated attackers to read unpublished help center articles through the public portal API. Attackers can request archived articles by slug via the ArticlesController show actions or read draft translations exposed through associated_articles in article JSON responses.

- [https://github.com/googlesky/CVE-2026-134831](https://github.com/googlesky/CVE-2026-134831) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134831.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134831.svg)


## CVE-2026-134830
 Casdoor before 4.27.1 contains an uncontrolled resource consumption vulnerability in decodeSamlMessage that allows unauthenticated attackers to exhaust memory by sending unbounded DEFLATE-compressed SAML messages. Attackers can send a small, highly compressed SAMLRequest or SAMLResponse to the /api/saml/logout/:owner/:application endpoint, which inflates to gigabytes and crashes or stalls the server.

- [https://github.com/googlesky/CVE-2026-134830](https://github.com/googlesky/CVE-2026-134830) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134830.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134830.svg)


## CVE-2026-134829
 Umami 3.3.0 before 3.5.0 contains a race condition in two-factor authentication attempt limiting that allows attackers holding a user's password to bypass lockout. Attackers can send many concurrent POST requests to /api/2fa/verify that pass checkRateLimit before recordFailedAttempt runs, brute-forcing TOTP or backup codes beyond the five-attempt limit.

- [https://github.com/googlesky/CVE-2026-134829](https://github.com/googlesky/CVE-2026-134829) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134829.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134829.svg)


## CVE-2026-134828
 Penpot 2.18.0 before 2.19.1 contains a stored cross-site scripting vulnerability in the sanitize-svg function that allows authenticated users to bypass filtering through unescaped re-serialization. Attackers with file edit permission can upload SVGs using entity-encoded or CDATA-wrapped markup or attribute quote breakouts to execute JavaScript in the Penpot origin when victims open them.

- [https://github.com/googlesky/CVE-2026-134828](https://github.com/googlesky/CVE-2026-134828) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134828.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134828.svg)


## CVE-2026-134827
 Lightdash before 3.212.0 contains an insufficiently protected credentials vulnerability in getGitlabInstallationRepoReadAccess that sends the organization GitLab app token to unverified hosts. Project developers can set the dbt connection host_domain to an attacker-controlled server and capture the token when the AI agent reads the repository, gaining access to every reachable repository.

- [https://github.com/googlesky/CVE-2026-134827](https://github.com/googlesky/CVE-2026-134827) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134827.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134827.svg)


## CVE-2026-134825
 Gradio 6.27.0 before 6.32.0 contains an authentication bypass vulnerability in gradio/history.py that allows remote unauthenticated attackers to use the operator's locally saved Hugging Face token by sending a forged Host: localhost header. When ssr_mode is enabled, requests proxied through the local Node SSR server pass the loopback check, letting attackers call run history endpoints to list buckets, read records and assets, and write buckets under the operator's account.

- [https://github.com/googlesky/CVE-2026-134825](https://github.com/googlesky/CVE-2026-134825) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134825.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134825.svg)


## CVE-2026-134824
 Nektos act 0.2.92 before 0.2.98 contains a link following vulnerability that allows malicious repositories to read host files by setting --eventpath in an untrusted project .actrc to a symlink. Attackers can commit an event.json symlink pointing to files like ~/.ssh/id_rsa, which act copies into the job container as GITHUB_EVENT_PATH for workflow steps to exfiltrate.

- [https://github.com/googlesky/CVE-2026-134824](https://github.com/googlesky/CVE-2026-134824) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134824.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134824.svg)


## CVE-2026-134823
 Kitty 0.43.0 before 0.51.0 contains a terminal escape sequence injection vulnerability that allows attackers to emit escape sequences by crafting malicious file or archive member names. When a victim highlights such an entry in the choose-files kitten preview panel, unsanitized names are written raw, enabling OSC 52 clipboard overwrites, OSC 8 links, window title changes, or screen spoofing.

- [https://github.com/googlesky/CVE-2026-134823](https://github.com/googlesky/CVE-2026-134823) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134823.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134823.svg)


## CVE-2026-134822
 Sustainsys.Saml2 before 1.0.4 and 2.x before 2.11.1 contains an improper signature verification vulnerability that allows attackers to tamper with signed parameters by exploiting mis-parsing in CheckSignature() of Saml2RedirectBinding.cs. Attackers can append data after an extra '=' in RelayState of an intercepted or replayed Redirect-binding message, causing applications to trust the tampered value.

- [https://github.com/googlesky/CVE-2026-134822](https://github.com/googlesky/CVE-2026-134822) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134822.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134822.svg)


## CVE-2026-134821
 Gunicorn 25.2.0 before 27.0.0 contains a memory exhaustion vulnerability in the pure-Python ASGI HTTP/1 parser that buffers protocol lines without size limits. Unauthenticated remote attackers can send request lines, headers, chunk-size lines or trailers lacking CRLF to grow worker memory and consume CPU, causing denial of service.

- [https://github.com/googlesky/CVE-2026-134821](https://github.com/googlesky/CVE-2026-134821) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134821.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134821.svg)


## CVE-2026-134820
 Gunicorn 25.2.0 before 27.0.0 contains an HTTP request smuggling vulnerability in the pure-Python ASGI parser that allows unauthenticated remote attackers to desynchronize request framing by sending malformed framing headers. Attackers can send whitespace-padded Transfer-Encoding or Content-Length headers, signed Content-Length values, or invalid chunk terminators to smuggle requests past front-end proxies to the ASGI application.

- [https://github.com/googlesky/CVE-2026-134820](https://github.com/googlesky/CVE-2026-134820) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134820.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134820.svg)


## CVE-2026-134818
 oasdiff 1.24.0 before 1.34.1 fails to enforce --allow-external-refs=false when --open is used, because the recordingReader() capture reader in load/capture.go never applies the external-reference policy. Attackers supplying an untrusted OpenAPI spec can use external $ref values to read local files or trigger HTTP requests, with contents uploaded in the review bundle.

- [https://github.com/googlesky/CVE-2026-134818](https://github.com/googlesky/CVE-2026-134818) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134818.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134818.svg)


## CVE-2026-134817
 mcp-server-kubernetes before 4.2.0 contains an argument injection vulnerability that allows remote MCP clients to inject kubectl flags by supplying dash-prefixed values as positional operands in tools such as exec_in_pod, kubectl_patch, and kubectl_logs. Attackers connected over SSE or Streamable HTTP transport can supply values like --filename to make kubectl read files from the server host, bypassing file-read restrictions.

- [https://github.com/googlesky/CVE-2026-134817](https://github.com/googlesky/CVE-2026-134817) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134817.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134817.svg)


## CVE-2026-134816
 sigstore-js @sigstore/oci before 0.8.0 contains a credential exposure vulnerability that leaks registry credentials by replaying OAuth2 password-grant request bodies on cross-origin 307 or 308 redirects. Attackers who can make a trusted token service redirect to their host via open redirect or compromise receive the username and password POSTed by RegistryClient.

- [https://github.com/googlesky/CVE-2026-134816](https://github.com/googlesky/CVE-2026-134816) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134816.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134816.svg)


## CVE-2026-134815
 simple-git before 4.1.0 contains an argument injection vulnerability that allows attackers to bypass the allowUnsafePack guard by supplying the --exec option to non-push git operations. Attackers who influence arguments passed to listRemote() or raw() can inject --exec for ls-remote, archive, fetch-pack or send-pack to execute commands on the host.

- [https://github.com/googlesky/CVE-2026-134815](https://github.com/googlesky/CVE-2026-134815) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134815.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134815.svg)


## CVE-2026-134814
 binary-parser before 2.3.1 contains a code injection vulnerability that allows attackers controlling parser definitions to inject JavaScript through string-typed options passed unvalidated by Context.generateOption(). Attackers can supply crafted length, lengthInBytes, key, tag, offset, or namely() alias values to execute arbitrary JavaScript in the Node.js process when the parser is compiled.

- [https://github.com/googlesky/CVE-2026-134814](https://github.com/googlesky/CVE-2026-134814) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134814.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134814.svg)
- [https://github.com/abraxas/cve-2026-134814-binary-parser-option-injection](https://github.com/abraxas/cve-2026-134814-binary-parser-option-injection) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-134814-binary-parser-option-injection.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-134814-binary-parser-option-injection.svg)


## CVE-2026-134808
 Gogs before 0.14.4 on Windows contains a path equivalence vulnerability in isRepositoryGitPath that allows authenticated users with write access to bypass .git directory protection using NTFS aliases. Attackers can create, rename or upload files via aliases like git~1 or .git::$INDEX_ALLOCATION to overwrite .git/config or hooks and execute commands as the Gogs process.

- [https://github.com/googlesky/CVE-2026-134808](https://github.com/googlesky/CVE-2026-134808) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134808.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134808.svg)


## CVE-2026-134805
 Zipline before 4.8.3 contains a server-side request forgery vulnerability that allows authenticated OIDC users to make the server fetch arbitrary URLs via the userinfo picture claim. Attackers who control their picture claim at the identity provider can force fetchToDataURL() to request internal or cloud-metadata URLs and read responses from their stored avatar.

- [https://github.com/googlesky/CVE-2026-134805](https://github.com/googlesky/CVE-2026-134805) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134805.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134805.svg)


## CVE-2026-134804
 Portainer 2.39.0 before 2.39.9, 2.40.0 before 2.45.4, and 3.0.0 before 3.1.0 contains an authorization bypass vulnerability that allows Standard users to access other users' containers via the WebSocket attach and exec endpoints. Attackers with shared environment access can use leaked container or exec IDs to hijack sessions over /api/websocket/attach or /api/websocket/exec, gaining interactive root shells.

- [https://github.com/googlesky/CVE-2026-134804](https://github.com/googlesky/CVE-2026-134804) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134804.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134804.svg)


## CVE-2026-134802
 VoidAuth before 1.19.2 contains an access control bypass vulnerability that allows authenticated users to evade stricter ProxyAuth domain rules by sending percent-encoded path separators. Attackers can request paths with encoded slashes, backslashes, semicolons, or dot segments that match a broader rule, reaching restricted paths once the reverse proxy or backend decodes them.

- [https://github.com/googlesky/CVE-2026-134802](https://github.com/googlesky/CVE-2026-134802) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134802.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134802.svg)


## CVE-2026-134753
 dsniff through 2.5a2 contains an integer underflow in decode_sniffer() in decode_sniffer.c that allows unauthenticated remote attackers to write past the global obuf buffer. Attackers can send a UDP datagram to port 2001 on a monitored segment with a 4096-byte string, disabling base64_pton bounds checks to corrupt memory and crash dsniff.

- [https://github.com/cveForge/CVE-2026-134753](https://github.com/cveForge/CVE-2026-134753) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134753.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134753.svg)


## CVE-2026-134732
 A flaw has been found in Open Asset Import Library Assimp up to 6.0.5. This affects the function ASEImporter::InternReadFile of the file code/AssetLib/ASE/ASELoader.cpp of the component ASE File Importer. This manipulation causes out-of-bounds write. The attack is possible to be carried out remotely. The exploit has been published and may be used. Upgrading to version 6.0.6 mitigates this issue. Patch name: 7ccc44a338dcdcc81023484388126ab1a8250e94. You should upgrade the affected component.

- [https://github.com/googlesky/CVE-2026-134732](https://github.com/googlesky/CVE-2026-134732) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-134732.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-134732.svg)


## CVE-2026-134704
 OpenShot Video Editor (openshot-qt) through 4.1.1 contains an unsafe deserialization vulnerability in ProjectDataStore.load() and read_legacy_project_file() that passes non-JSON project files to pickle.load() without restriction. Attackers can trick users into opening a crafted .osp project file containing a pickle __reduce__ gadget to execute code with the user's privileges.

- [https://github.com/cveForge/CVE-2026-134704](https://github.com/cveForge/CVE-2026-134704) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134704.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134704.svg)


## CVE-2026-134694
 Gammapy through 2.1 contains a code injection vulnerability in WcsGeom.from_header() that passes the WCSSHAPE FITS header card to eval(). Attackers can supply a crafted .fits file with a Python expression in WCSSHAPE, executing code as the user who loads it via Map.read().

- [https://github.com/cveForge/CVE-2026-134694](https://github.com/cveForge/CVE-2026-134694) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134694.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134694.svg)


## CVE-2026-134679
 WeddingShare through 1.8.2 contains a missing authorization vulnerability in the anonymous MediaViewerController.GalleryItem action that allows unauthenticated attackers to retrieve item upload paths without the gallery secret key. Attackers can enumerate sequential integer item ids to learn paths and uploader names, then download photos and videos from key-protected galleries served as static files.

- [https://github.com/cveForge/CVE-2026-134679](https://github.com/cveForge/CVE-2026-134679) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134679.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134679.svg)


## CVE-2026-134654
 Mailflare before 48957fb contains a host header injection vulnerability in the password-reset request handler that allows unauthenticated attackers to poison reset links when APP_URL is unset. Attackers can submit a reset request for a victim's email with a malicious Host header, capturing the single-use token when the victim clicks the link to take over the account.

- [https://github.com/cveForge/CVE-2026-134654](https://github.com/cveForge/CVE-2026-134654) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134654.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134654.svg)


## CVE-2026-134623
 A flaw has been found in Microweber up to 2.0.20. This impacts the function UserManager::make_logged of the file src/MicroweberPackages/App/Http/Controllers/ApiController.php of the component Generic API Dispatcher. This manipulation causes improper access controls. Remote exploitation of the attack is possible. The exploit has been published and may be used. Upgrading to version 2.0.21 will fix this issue. Patch name: e639d26e61b989b100f8b6f6bb78c0cecca79b99. You should upgrade the affected component.

- [https://github.com/cveForge/CVE-2026-134623](https://github.com/cveForge/CVE-2026-134623) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134623.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134623.svg)


## CVE-2026-134543
 A flaw has been found in jprocms up to 1.7.7. Affected is the function StrUtil.format of the component Database Backup Module. Executing a manipulation of the argument host/port/username/password/dbName can lead to os command injection. The attack can be launched remotely. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/cveForge/CVE-2026-134543](https://github.com/cveForge/CVE-2026-134543) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134543.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134543.svg)


## CVE-2026-134541
 A vulnerability was detected in Surya2Developer Online Shopping System 1.0. This impacts an unknown function of the file product.php of the component GET Parameter Handler. Performing a manipulation of the argument p results in sql injection. The attack can be initiated remotely. The exploit is now public and may be used. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/cveForge/CVE-2026-134541](https://github.com/cveForge/CVE-2026-134541) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134541.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134541.svg)


## CVE-2026-133968
 monailabel (aka MONAI Label) before 0.8.6 allows directory traversal, with resultant remote code execution, via the image parameter to the PUT /datastore/image endpoint, as exploited in the wild starting in September 2026.

- [https://github.com/cveForge/CVE-2026-133968](https://github.com/cveForge/CVE-2026-133968) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133968.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133968.svg)


## CVE-2026-133493
 A vulnerability was identified in D-Link DIR-600L 2.17b02. Affected is the function genacgi_main of the file gena.cgi of the component GENA Handler. Such manipulation leads to os command injection. The attack can be launched remotely. The exploit is publicly available and might be used.

- [https://github.com/cveForge/CVE-2026-133493](https://github.com/cveForge/CVE-2026-133493) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133493.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133493.svg)


## CVE-2026-133469
 XO (Xen Orchestra) is a solution to visualize, manage, backup and delegate your XCP-ng (or XenServer) infrastructure. Prior to 6.9.2 and 6.10.1, REST cookie parsing turns authenticationToken=j:%7B%7D into {}. REST authentication passes that object to the XO token provider without requiring a string. The token collection treats {} as an unfiltered lookup and returns its first token; the provider authenticates as that token's owner if it is unexpired. The authenticated /rest/v0/users/me/authentication_tokens route then returns reusable login token IDs. This vulnerability is actively exploited in the wild. This vulnerability is fixed in 6.9.2 and 6.10.1.

- [https://github.com/googlesky/CVE-2026-133469](https://github.com/googlesky/CVE-2026-133469) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133469.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133469.svg)


## CVE-2026-133430
 A flaw was found in Keycloak. This vulnerability allows an authenticated remote attacker to cause a denial of service by terminating active sessions of arbitrary users. When processing Security Assertion Markup Language (SAML) documents that lack a root signature, Keycloak accepts the request as long as any assertion within the document is signed, without verifying its context or placement. An attacker holding a validly signed assertion can embed it into an unsigned logout request for another user, causing Keycloak to accept the forged request and terminate the victim's session.

- [https://github.com/cveForge/CVE-2026-133430](https://github.com/cveForge/CVE-2026-133430) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133430.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133430.svg)


## CVE-2026-133325
Users are recommended to switch to TLS 1.2 and TLS-PSK or upgrade to version 11.0.30, 10.1.63 or 9.0.125 (when released), which fix the issue.

- [https://github.com/cveForge/CVE-2026-133325](https://github.com/cveForge/CVE-2026-133325) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133325.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133325.svg)


## CVE-2026-133235
 Tandoor Recipes before 2.7.4 contains a server-side request forgery vulnerability that allows space admins to reach internal hosts because Nextcloud.get_client builds WebDAV clients from Storage.url without calling safe_request. Attackers can create a NEXTCLOUD storage via POST /api/storage/ pointing at internal hosts, import a file, then call GET /api/get_recipe_file/id/ to read internal service or cloud metadata responses.

- [https://github.com/cveForge/CVE-2026-133235](https://github.com/cveForge/CVE-2026-133235) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133235.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133235.svg)


## CVE-2026-133234
 Stoatchat before 0.16.5 contains an unbounded JXL image decoding vulnerability in revolt_files decode_image that allows unauthenticated attackers to exhaust memory via the january /proxy endpoint. Attackers can request a small hosted JXL file declaring 12000x12000 pixels through /proxy to trigger huge allocations, OOM-killing january and denying proxy and embed service.

- [https://github.com/cveForge/CVE-2026-133234](https://github.com/cveForge/CVE-2026-133234) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133234.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133234.svg)


## CVE-2026-133185
 Goproxy before 1.9.4 contains a weak key generation vulnerability in NewCounterEncryptorRandFromKey that derives RSA and Ed25519 leaf certificate private keys from public data due to misuse of hash.Sum. Attackers with the CA certificate and one observed leaf certificate can regenerate that host's leaf private key and impersonate the host to clients trusting the proxy CA.

- [https://github.com/cveForge/CVE-2026-133185](https://github.com/cveForge/CVE-2026-133185) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133185.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133185.svg)


## CVE-2026-133173
 WatchAlert 2.0.0 through 3.9.20 contains an insecure direct object reference vulnerability in the /api/w8t/datasource/dataSourceGet endpoint that lets authenticated users read other tenants' datasources because lookups omit tenant_id filtering. Tenant members with datasource view permission can request another tenant's datasource ID to obtain basic auth passwords, AWS and Alibaba Cloud keys, and Kubernetes kubeconfigs.

- [https://github.com/cveForge/CVE-2026-133173](https://github.com/cveForge/CVE-2026-133173) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133173.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133173.svg)


## CVE-2026-133172
 Cozy Cloud cozy-stack 1.6.62 before 1.6.69 contains an authorization bypass vulnerability in the shared-drive move handler that allows authenticated users to access other instances' files. Attackers owning a shared drive can name another instance's domain and any directory ID as the move source to copy and delete the victim's file tree.

- [https://github.com/cveForge/CVE-2026-133172](https://github.com/cveForge/CVE-2026-133172) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133172.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133172.svg)


## CVE-2026-133168
 OFFIS DCMTK 3.7.1 contains a heap buffer overflow vulnerability in togglePlanarConfiguration8 and togglePlanarConfiguration16 in djcodece.cc, which compute row offsets using rows instead of columns. Attackers can supply a crafted color-by-plane DICOM image with more rows than columns that is compressed with the true-lossless JPEG codec to corrupt heap memory, causing crashes and potentially code execution.

- [https://github.com/cveForge/CVE-2026-133168](https://github.com/cveForge/CVE-2026-133168) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133168.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133168.svg)


## CVE-2026-133117
 WebToffee Product Feed before 2.4.4 for WordPress contains a use of hard-coded cryptographic key vulnerability that allows unauthenticated attackers to bypass the URL-cron signature check by computing a valid hash using the publicly known constant salt embedded in the plugin source. Attackers can send forged GET requests with attacker-controlled parameters to the unauthenticated init-hooked endpoint to repeatedly trigger product-feed generation, causing CPU/database resource exhaustion and overwriting of the generated feed file.

- [https://github.com/cveForge/CVE-2026-133117](https://github.com/cveForge/CVE-2026-133117) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133117.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133117.svg)


## CVE-2026-133114
 Caddy – WooCommerce Side Cart & Free Shipping Bar plugin for WordPress 3.0.0 before 3.2.1 contains a missing authorization vulnerability in the saved-items/add REST endpoint that exposes non-public product data. Authenticated attackers with Subscriber-level access can enumerate product_id values to read names, prices, images and stock status of private, draft, hidden and password-protected products.

- [https://github.com/cveForge/CVE-2026-133114](https://github.com/cveForge/CVE-2026-133114) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133114.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133114.svg)


## CVE-2026-133113
 Gogs through 0.14.4 contains an authorization bypass vulnerability that allows collaborators with write access to push to protected branches by merging pull requests. Because MergePullRequest skips branch protection checks and PullRequest.Merge omits hook environment variables, attackers can merge commits into branches restricted to allowlisted users.

- [https://github.com/cveForge/CVE-2026-133113](https://github.com/cveForge/CVE-2026-133113) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133113.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133113.svg)


## CVE-2026-132825
 Ruby before 3.3.14, 3.4.13, and 4.0.10 has a heap-based buffer overflow during case conversion. One byte can be written outside a buffer for, for example, ISO-8859-1 or Windows-1252.

- [https://github.com/ashrafzaryouh/CVE-2026-132825](https://github.com/ashrafzaryouh/CVE-2026-132825) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-132825.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-132825.svg)


## CVE-2026-132779
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/suominen/CVE-2026-132779](https://github.com/suominen/CVE-2026-132779) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-132779.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-132779.svg)


## CVE-2026-130648
 WWBN AVideo from 6.5 contains a stored cross-site scripting vulnerability that allows users with upload permission to inject script by submitting a javascript: scheme videoLink for embed videos. The unvalidated URL is rendered into an iframe src in videoEmbeded.php and PlayerSkins.php, executing for viewers including administrators and enabling creation of new administrator accounts.

- [https://github.com/cveForge/CVE-2026-130648](https://github.com/cveForge/CVE-2026-130648) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-130648.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-130648.svg)


## CVE-2026-129975
 A flaw was found in gpgme. When processing crafted input, an early return following memory reallocation can leave internal buffer pointers referencing previously freed memory, resulting in a double-free condition during cleanup. A remote attacker could exploit this vulnerability to corrupt process memory, potentially leading to arbitrary code execution or a Denial of Service (DoS) crash.

- [https://github.com/techdevfun/gpgme2shell](https://github.com/techdevfun/gpgme2shell) :  ![starts](https://img.shields.io/github/stars/techdevfun/gpgme2shell.svg) ![forks](https://img.shields.io/github/forks/techdevfun/gpgme2shell.svg)


## CVE-2026-129496
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/evenomn/CVE-2026-129496](https://github.com/evenomn/CVE-2026-129496) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-129496.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-129496.svg)
- [https://github.com/cveForge/CVE-2026-129496](https://github.com/cveForge/CVE-2026-129496) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129496.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129496.svg)


## CVE-2026-129474
This issue affects PHP versions 8.5.* before 8.5.13.

- [https://github.com/cveForge/CVE-2026-129474](https://github.com/cveForge/CVE-2026-129474) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129474.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129474.svg)


## CVE-2026-129448
Users who cannot upgrade right away should set "enabledForExtensions" to "false" in WEB-INF/web.xml, or remove the "/roller-services/xmlrpc" servlet mapping, and restart Roller. Disabling XML-RPC in the administration UI is not enough, because older versions deserialize the request before checking that setting.

- [https://github.com/cveForge/CVE-2026-129448](https://github.com/cveForge/CVE-2026-129448) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129448.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129448.svg)


## CVE-2026-129289
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/cveForge/CVE-2026-129289](https://github.com/cveForge/CVE-2026-129289) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129289.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129289.svg)


## CVE-2026-129223
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, WordNet Synset.tree and acyclic_tree traverse relation graphs through recursive utility helpers without a depth bound. Exploitation requires the host application to load an attacker-influenced custom or foreign WordNet-format lexical resource; no relation in NLTK's bundled WordNet 3.0 corpus reaches the crash threshold. An excessively deep relation graph in such a resource can exceed the Python recursion limit and terminate the traversal or request worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129223](https://github.com/googlesky/CVE-2026-129223) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129223.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129223.svg)


## CVE-2026-129222
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, DependencyGraph.tree and DependencyGraph.triples walk parsed dependency edges through unbounded Python recursion and do not use a working cycle or depth guard. A crafted CoNLL or Malt-TAB dependency file containing a sufficiently long chain can raise RecursionError when the documented traversal APIs are called, aborting the current worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129222](https://github.com/googlesky/CVE-2026-129222) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129222.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129222.svg)


## CVE-2026-129221
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, nltk.classify.weka.ARFF_Formatter writes attacker-controlled class labels into the Weka ARFF @ATTRIBUTE '-label-' declaration without safely formatting the label tokens. Crafted labels can alter the generated ARFF schema or records, corrupting classifier input and causing integrity loss or processing failure. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129221](https://github.com/googlesky/CVE-2026-129221) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129221.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129221.svg)


## CVE-2026-129175
 U.S Department of the Interior Unstable Slope Management Program allows an unauthenticated user to inject unauthorized SQL commands that allow the attacker to gain root access and complete control over the database. Fixed on or around 2026-10-19.

- [https://github.com/cveForge/CVE-2026-129175](https://github.com/cveForge/CVE-2026-129175) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129175.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129175.svg)


## CVE-2026-129073
 Authentication Bypass Using an Alternate Path or Channel vulnerability in miniOrange miniorange otp verification miniorange-otp-verification allows Authentication Abuse.This issue affects miniorange otp verification: from n/a through 5.6.1.

- [https://github.com/cveForge/CVE-2026-129073](https://github.com/cveForge/CVE-2026-129073) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129073.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129073.svg)


## CVE-2026-129056
 Incorrect Privilege Assignment vulnerability in Paul Ryan Authorizer authorizer allows Privilege Escalation.This issue affects Authorizer: from n/a before 3.17.2.

- [https://github.com/cveForge/CVE-2026-129056](https://github.com/cveForge/CVE-2026-129056) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129056.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129056.svg)


## CVE-2026-129043
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Tribulant Software Newsletters newsletters-lite allows SQL Injection.This issue affects Newsletters: from n/a through 4.18.2.

- [https://github.com/cveForge/CVE-2026-129043](https://github.com/cveForge/CVE-2026-129043) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129043.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129043.svg)


## CVE-2026-129039
 Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsletters-lite allows Object Injection.This issue affects Newsletters: from n/a through 4.18.2.

- [https://github.com/cveForge/CVE-2026-129039](https://github.com/cveForge/CVE-2026-129039) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129039.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129039.svg)


## CVE-2026-129024
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Everest Forms Everest Forms everest-forms allows Path Traversal.This issue affects Everest Forms: from n/a through 3.6.4.

- [https://github.com/kanokwut/everest-forms-signature-delete-poc](https://github.com/kanokwut/everest-forms-signature-delete-poc) :  ![starts](https://img.shields.io/github/stars/kanokwut/everest-forms-signature-delete-poc.svg) ![forks](https://img.shields.io/github/forks/kanokwut/everest-forms-signature-delete-poc.svg)


## CVE-2026-128140
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.6.7 until 3.10.4, nltk.downloader follows collection membership without tracking already visited collection nodes. A self-referencing or mutually referencing collection index can therefore make the package-closure walk loop indefinitely while its queue and memory usage grow, denying service when a victim processes the attacker-influenced index. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-128140](https://github.com/googlesky/CVE-2026-128140) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128140.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128140.svg)


## CVE-2026-128139
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.6 to 3.10.3, XMLCorpusView._read_xml_fragment accumulates 1 KiB blocks and repeatedly applies whole-buffer XML validation while a comment or CDATA terminator remains ahead. A large comment in an attacker-controlled corpus file causes quadratic CPU consumption through documented XML corpus readers across the affected range. On 3.6 and 3.9.2, a large CDATA section incurs the quadratic scan before rejection, while on 3.10.3 both comment and CDATA documents are read successfully. This vulnerability is fixed in 3.10.4.

- [https://github.com/googlesky/CVE-2026-128139](https://github.com/googlesky/CVE-2026-128139) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128139.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128139.svg)


## CVE-2026-128138
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.10.3 until 3.10.4, the NLTK 3.10.3 JVM hardening validates Java launcher tokens in the options channel but appends the caller-controlled cmd sequence without requiring its first token to be a main class. Supplying -jar or an @argfile through nltk.internals.java or StanfordSegmenter.java_class can therefore execute attacker-selected Java bytecode without the unsafe-JAR opt-in. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-128138](https://github.com/googlesky/CVE-2026-128138) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128138.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128138.svg)


## CVE-2026-128137
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.9.4 until 3.10.4, NLTK corpus-reader path pointers and view methods validate a requested relative path without consistently resolving intermediate directory symlinks against the reader's scoped root. A local attacker who can place such a symlink can make abspaths or words reach a readable file outside the corpus root and disclose its contents. On releases with pathsec enforcement, the file must remain inside a global NLTK allowed root; version 3.9.4 has enforcement disabled and permits a broader escape. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-128137](https://github.com/googlesky/CVE-2026-128137) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128137.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128137.svg)


## CVE-2026-128136
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.10.0 until 3.10.4, allowlisted_pickle_load keys dangerous NumPy globals by export name, allowing submodule-local numpy.lib file input/output callables to evade the denylist under the broad module allowance used by TransitionParser. A crafted pickle can invoke recfromtxt to read a local file or open_memmap to create or truncate an attacker-selected file when a victim loads an untrusted model. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-128136](https://github.com/googlesky/CVE-2026-128136) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128136.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128136.svg)


## CVE-2026-128134
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, nltk.parse.dependencygraph.dot2img resolves the Graphviz dot executable through PATH but invokes the resulting absolute executable without routing through spawn_trusted, so resolve_trusted_executable ownership and writability validation and safe_env loader environment scrubbing do not run. A local low-privileged attacker who can write to a directory on a POSIX victim's PATH can plant or replace dot, and code executes as the victim when dot2img is called directly or DependencyGraph.repr_svg renders a graph. The current-working-directory-only bare-name vector is blocked and is not this vulnerability; this issue is the residual writable absolute PATH element bypass after CVE-2026-78680. This issue is fixed in version 3.10.4.

- [https://github.com/cveForge/CVE-2026-128134](https://github.com/cveForge/CVE-2026-128134) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-128134.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-128134.svg)


## CVE-2026-126979
The specific flaw exists within the HomeKit Accessory Protocol service, which listens on TCP port 8080 by default. When parsing pairing requests, the process does not properly validate user-supplied data, which can result in an integer underflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the device. Was ZDI-CAN-28332.

- [https://github.com/cveForge/CVE-2026-126978](https://github.com/cveForge/CVE-2026-126978) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-126978.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-126978.svg)


## CVE-2026-126978
The specific flaw exists within the HomeKit Accessory Protocol service, which listens on TCP port 8080 by default. When parsing pairing requests, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length, heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device. Was ZDI-CAN-28434.

- [https://github.com/cveForge/CVE-2026-126978](https://github.com/cveForge/CVE-2026-126978) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-126978.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-126978.svg)


## CVE-2026-126967
The specific flaw exists within the FileStorageController class. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to execute code in the context of SYSTEM. Was ZDI-CAN-30742.

- [https://github.com/cveForge/CVE-2026-126967](https://github.com/cveForge/CVE-2026-126967) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-126967.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-126967.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/ashrafzaryouh/CVE-2026-126714](https://github.com/ashrafzaryouh/CVE-2026-126714) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-126714.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-126714.svg)


## CVE-2026-126657
 A flaw was found in QEMU's NBD block driver. A malicious NBD server can send an incomplete structured read reply marked as done, causing QEMU to return uninitialized host heap memory to the guest VM, resulting in host memory disclosure.

- [https://github.com/googlesky/CVE-2026-126657](https://github.com/googlesky/CVE-2026-126657) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126657.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126657.svg)


## CVE-2026-125683
 A flaw was found in QEMU's NBD server. A remote attacker can crash qemu-nbd, qemu-storage-daemon, or qemu-system by sending NBD_OPT_SET_META_CONTEXT or NBD_OPT_LIST_META_CONTEXT with a declared option length exceeding the actual payload, triggering an assertion failure and denial of service.

- [https://github.com/googlesky/CVE-2026-125683](https://github.com/googlesky/CVE-2026-125683) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-125683.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-125683.svg)


## CVE-2026-125396
 Ghostscript before 10.08.0 contains a -dSAFER bypass vulnerability in the .putgstringcopy procedure in gs_fonts.ps, which calls the privileged .forceput operator without checking operand types. Attackers can supply crafted PostScript or PDF documents that trigger a type error, recover .forceput via a custom error handler, and cause a use-after-free across save/restore to execute arbitrary code.

- [https://github.com/ashrafzaryouh/CVE-2026-125396](https://github.com/ashrafzaryouh/CVE-2026-125396) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-125396.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-125396.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ashrafzaryouh/CVE-2026-125350](https://github.com/ashrafzaryouh/CVE-2026-125350) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-125350.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-125350.svg)
- [https://github.com/cveForge/CVE-2026-125350](https://github.com/cveForge/CVE-2026-125350) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-125350.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-125350.svg)


## CVE-2026-125283
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-125283](https://github.com/cveForge/CVE-2026-125283) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-125283.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-125283.svg)


## CVE-2026-124559
 A flaw was found in QEMU's NBD server. A remote attacker can crash a multi-export NBD server process by exploiting stale metadata export state during an extended BLOCK_STATUS request, resulting in an assertion failure and denial of service.

- [https://github.com/googlesky/CVE-2026-124559](https://github.com/googlesky/CVE-2026-124559) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-124559.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-124559.svg)


## CVE-2026-124194
 Product ui does not warn user of unsafe actions in Microsoft Office Outlook allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/cveForge/CVE-2026-124194](https://github.com/cveForge/CVE-2026-124194) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-124194.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-124194.svg)


## CVE-2026-124020
 Control Web Panel (CWP) before webpanel_version 1.30.6 contains a host header injection vulnerability that allows unauthenticated attackers to manipulate the password-recovery reset URL by injecting the HTTP Host header into the /v1/lostpass/ route's token generation process. Attackers can lure an automated mail-security scanner into visiting the poisoned reset link to exfiltrate the live recovery token, replay it at /login/index.php?acc=newpass to set a new password, and subsequently abuse the File Manager and Crontab modules to achieve command execution as the targeted hosting account.

- [https://github.com/cveForge/CVE-2026-124020](https://github.com/cveForge/CVE-2026-124020) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-124020.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-124020.svg)


## CVE-2026-123890
Telco Cloud Platform 3.0, 4.x, 5.0.x, 5.1.x, 5.2 and Telco Cloud Infrastructure 3.0 are also affected (see KB463116).

- [https://github.com/dinosn/CVE-2026-123890](https://github.com/dinosn/CVE-2026-123890) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-123890.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-123890.svg)
- [https://github.com/cveForge/CVE-2026-123890](https://github.com/cveForge/CVE-2026-123890) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123890.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123890.svg)


## CVE-2026-123886
In that case, a remote attacker can execute arbitrary code in the application, and repeated requests can exhaust memory through the unbounded expression cache.

- [https://github.com/googlesky/CVE-2026-123886](https://github.com/googlesky/CVE-2026-123886) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-123886.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-123886.svg)


## CVE-2026-123640
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-123640](https://github.com/cveForge/CVE-2026-123640) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123640.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123640.svg)


## CVE-2026-123634
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-123634](https://github.com/cveForge/CVE-2026-123634) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123634.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123634.svg)


## CVE-2026-123633
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/tc4dy/CVE-2026-123633-PoC-Toolkit](https://github.com/tc4dy/CVE-2026-123633-PoC-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-123633-PoC-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-123633-PoC-Toolkit.svg)
- [https://github.com/cveForge/CVE-2026-123633](https://github.com/cveForge/CVE-2026-123633) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123633.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123633.svg)
- [https://github.com/cveForge/CVE-2026-123640](https://github.com/cveForge/CVE-2026-123640) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123640.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123640.svg)


## CVE-2026-123488
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection vulnerability in the element search endpoint because the attribute parameter is concatenated into the query unsanitized and emulated PDO prepares allow stacked statements. Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.

- [https://github.com/ashrafzaryouh/CVE-2026-123488](https://github.com/ashrafzaryouh/CVE-2026-123488) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-123488.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-123488.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/ashrafzaryouh/CVE-2026-123158](https://github.com/ashrafzaryouh/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-123158.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ashrafzaryouh/CVE-2026-123007](https://github.com/ashrafzaryouh/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-123007.svg)
- [https://github.com/cveForge/CVE-2026-123007](https://github.com/cveForge/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123007.svg)
- [https://github.com/Agampreet-Singh/Nginx2root-lab](https://github.com/Agampreet-Singh/Nginx2root-lab) :  ![starts](https://img.shields.io/github/stars/Agampreet-Singh/Nginx2root-lab.svg) ![forks](https://img.shields.io/github/forks/Agampreet-Singh/Nginx2root-lab.svg)


## CVE-2026-122247
 Budibase is an open-source low-code platform. Prior to 3.50.0, the public POST /api/global/users/init endpoint on a self-hosted single-tenant deployment accepts an attacker-controlled tenantId and evaluates checkAnyUserExists() in the selected tenant database instead of the legitimate default tenant. An unauthenticated attacker can select an unused tenant namespace to bypass the one-time initialization guard, causing packages/worker/src/api/controllers/global/users.ts to create a tenant-specific CouchDB database and a global-administrator document without a session or CSRF token. Repeating this operation with unique tenant identifiers can exhaust datastore resources and leave latent privileged records. The created administrator cannot log into the default tenant while multi-tenancy remains disabled, which limits the immediate impact to persistent writes, denial of service, and records that may become usable during later multi-tenant operation or migration. This issue is fixed in versions 3.50.0 and 4.0.0.

- [https://github.com/googlesky/CVE-2026-122247](https://github.com/googlesky/CVE-2026-122247) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122247.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122247.svg)


## CVE-2026-121810
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-121810](https://github.com/cveForge/CVE-2026-121810) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-121810.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-121810.svg)


## CVE-2026-121529
 A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7, FortiClientWindows 7.4.0 through 7.4.7, FortiClientWindows 7.2.0 through 7.2.14, FortiClientWindowsPAM 7.4.7, FortiClientWindowsPAM 7.2.14 may allow an unauthorized remote attacker to execute unauthorized code or commands. Successful exploitation requires interaction with the victim.

- [https://github.com/ashrafzaryouh/CVE-2026-121529](https://github.com/ashrafzaryouh/CVE-2026-121529) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-121529.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-121529.svg)


## CVE-2026-121480
 Insufficient authorization in personal notification rules in Checkmk 2.5.0p20, 2.4.0p41 and 2.3.0 (EOL) allows authenticated users to receive notifications for hosts and services they are not a contact of by defining broad personal notification rules.

- [https://github.com/googlesky/CVE-2026-121480](https://github.com/googlesky/CVE-2026-121480) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-121480.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-121480.svg)


## CVE-2026-121385
 The User Registration Aide WordPress plugin through 1.5.3.8 does not verify the current password or a reset token before changing a user's password, allowing unauthenticated attackers who know a user's username and email address to change the password of any account, including administrators, and take it over.

- [https://github.com/cveForge/CVE-2026-121385](https://github.com/cveForge/CVE-2026-121385) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-121385.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-121385.svg)


## CVE-2026-120993
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-120993](https://github.com/cveForge/CVE-2026-120993) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120993.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120993.svg)


## CVE-2026-120967
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-120967](https://github.com/cveForge/CVE-2026-120967) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120967.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120967.svg)


## CVE-2026-120681
 The Mang Board plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 2.4.7. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for unauthenticated attackers to delete any board post — including administrator-owned content — along with its associated comments and file links. A nonce sufficient to pass the initial nonce check is publicly exposed on any board listing page, meaning no prior authentication or privileged access is required to initiate the exploit.

- [https://github.com/cveForge/CVE-2026-120681](https://github.com/cveForge/CVE-2026-120681) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120681.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120681.svg)


## CVE-2026-120539
 The Restrictions for BuddyPress plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.5.4 This is due to the plugin splicing the attacker-controlled request URI into a PHP expression inside a double-quoted string and evaluating it with eval(). Because PHP interpolates double-quoted strings, a payload of the form {${...}} in the URL path is executed during interpolation, so no quote breakout is required and WordPress' slashing does not mitigate it. This makes it possible for unauthenticated attackers to execute arbitrary code on the server with a single GET request. The affected conditions ship enabled by default and are evaluated before any logged-in check, so no plugin configuration is needed; the site must have BuddyPress and Paid Memberships Pro active alongside this plugin.

- [https://github.com/cveForge/CVE-2026-120539](https://github.com/cveForge/CVE-2026-120539) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120539.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120539.svg)
- [https://github.com/foxcornlab/buddypress-restrictions-scanner](https://github.com/foxcornlab/buddypress-restrictions-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/buddypress-restrictions-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/buddypress-restrictions-scanner.svg)


## CVE-2026-119958
 Out-of-bounds write in Windows LDAP - Lightweight Directory Access Protocol allows an unauthorized attacker to execute code over a network.

- [https://github.com/cveForge/CVE-2026-119958](https://github.com/cveForge/CVE-2026-119958) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119958.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119958.svg)


## CVE-2026-119618
Affected releases of mod_h2 from GitHub: from 2.0.8 through 2.0.42.

- [https://github.com/cveForge/CVE-2026-119618](https://github.com/cveForge/CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119618.svg)


## CVE-2026-119258
 The Swipe WordPress plugin through 1.4 does not properly authenticate a login request before issuing a WordPress session cookie, allowing unauthenticated attackers to log in as an existing user, including an administrator, when that user has an active app session.

- [https://github.com/cveForge/CVE-2026-119258](https://github.com/cveForge/CVE-2026-119258) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119258.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119258.svg)


## CVE-2026-119179
 A flaw in the connection management layer of the MongoDB Node.js driver can leave a pooled network connection in the pool for reuse while data from an earlier operation is still outstanding on it. In applications that enable an optional client-side operation timeout, an unauthenticated party that can send ordinary requests to the application may cause database replies to be paired with the wrong requests. This may result in unintended disclosure of other users' records, incorrect operation results being returned, and failures of legitimate requests.

- [https://github.com/cveForge/CVE-2026-119179](https://github.com/cveForge/CVE-2026-119179) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119179.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119179.svg)


## CVE-2026-119077
 The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.3.9 via the 'form (specifically the attacker-controlled ticket_label field inside the url-encoded form string)' parameter parameter. This is due to missing server-side authentication and the absence of a class allowlist on deserialization, with the only guard being a nonce publicly emitted on any page carrying the [wsdesk_support] shortcode. This makes it possible for unauthenticated attackers to execute code on the server. A successful exploit requires a single anonymous GET to any public page carrying the [wsdesk_support] shortcode to harvest the publicly emitted wsdesk_nonce value, after which a single unauthenticated POST completes the attack.

- [https://github.com/v0nx6/CVE-2026-119077](https://github.com/v0nx6/CVE-2026-119077) :  ![starts](https://img.shields.io/github/stars/v0nx6/CVE-2026-119077.svg) ![forks](https://img.shields.io/github/forks/v0nx6/CVE-2026-119077.svg)


## CVE-2026-119073
 The Live Composer  WordPress plugin before 2.1.23 does not escape a pagination setting supplied through its post-listing module shortcodes before outputting it in an HTML attribute, allowing users with the Contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Shashi552/CVE-2026-119073](https://github.com/Shashi552/CVE-2026-119073) :  ![starts](https://img.shields.io/github/stars/Shashi552/CVE-2026-119073.svg) ![forks](https://img.shields.io/github/forks/Shashi552/CVE-2026-119073.svg)


## CVE-2026-118899
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-118899](https://github.com/cveForge/CVE-2026-118899) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-118899.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-118899.svg)


## CVE-2026-118028
Note: Tomcat 11.0.28 was not released

- [https://github.com/cveForge/CVE-2026-118028](https://github.com/cveForge/CVE-2026-118028) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-118028.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-118028.svg)


## CVE-2026-117517
Note: Tomcat 11.0.28 was not released

- [https://github.com/cveForge/CVE-2026-117517](https://github.com/cveForge/CVE-2026-117517) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-117517.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-117517.svg)


## CVE-2026-116779
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia_presence_handle_sip_i_message() split the To user of an inbound SIP MESSAGE on a plus sign and treated the left side as a chat protocol selector. Selecting the api chat proto reached switch_api_execute(), allowing a peer whose MESSAGE was accepted to run FreeSWITCH API commands, including operating-system command sinks, with the daemon's privileges. Inbound chat is enabled on the stock internal and external profiles, and any authenticated profile account is sufficient; stock directory users without password material can also remove that barrier in affected configurations. The flaw permits configuration and credential disclosure, arbitrary call control, and command execution, and exploitation has been observed in the wild. This issue is fixed in version 1.11.3.

- [https://github.com/ashrafzaryouh/CVE-2026-116779](https://github.com/ashrafzaryouh/CVE-2026-116779) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-116779.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-116779.svg)


## CVE-2026-116561
Note: Tomcat 11.0.28 was not released

- [https://github.com/cveForge/CVE-2026-116561](https://github.com/cveForge/CVE-2026-116561) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-116561.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-116561.svg)


## CVE-2026-116448
 Dell PowerStore SDNAS contains an OS Command Injection vulnerability that could allow an attacker with internal network access to execute arbitrary commands as root on the NAS node.

- [https://github.com/cveForge/CVE-2026-116448](https://github.com/cveForge/CVE-2026-116448) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-116448.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-116448.svg)


## CVE-2026-116442
 Dell PowerStore SDNAS contains an authentication-bypass-by-replay vulnerability in the NAS NDMP service that could allow a network attacker to gain backup and restore control of the appliance.

- [https://github.com/cveForge/CVE-2026-116442](https://github.com/cveForge/CVE-2026-116442) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-116442.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-116442.svg)


## CVE-2026-115560
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/cveForge/CVE-2026-115560](https://github.com/cveForge/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-115560.svg)


## CVE-2026-115232
Please note that the language bindings for C/C++ and Python (including the iceoryx2-ffi-c crate) are not published to crates.io since they are a local development dependency.

- [https://github.com/googlesky/CVE-2026-115232](https://github.com/googlesky/CVE-2026-115232) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115232.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115232.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-114938](https://github.com/ashrafzaryouh/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-114938.svg)
- [https://github.com/cveForge/CVE-2026-114938](https://github.com/cveForge/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-114938.svg)


## CVE-2026-114595
 In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocated with an incorrect size. Subsequent handling of attacker supplied data may result in memory corruption, denial of service, or potential remote code execution.

- [https://github.com/ashrafzaryouh/CVE-2026-114595](https://github.com/ashrafzaryouh/CVE-2026-114595) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-114595.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-114595.svg)


## CVE-2026-114516
 Etherpad is a real-time collaborative editor. From 1.8.14 until 3.3.3, the pre-authentication /static/* plugin asset handler in src/node/utils/Minify.ts performs a backslash-to-forward-slash conversion after src/node/utils/sanitizePathname.ts has completed its POSIX path checks. On POSIX systems the sanitizer correctly treats backslashes as ordinary filename bytes, but the later conversion turns encoded backslash-separated parent-directory segments into traversal components without revalidation or containment. The expressPreSession registration and the always-present ep_etherpad-lite core pseudo-plugin make this path reachable without credentials, allowing a remote attacker to read any file available to the Etherpad process. Disclosed configuration or environment secrets can expose administrator credentials, after which the administrator plugin installer can provide in-process code execution and full server compromise. This issue is fixed in version 3.3.3.

- [https://github.com/googlesky/CVE-2026-114516](https://github.com/googlesky/CVE-2026-114516) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-114516.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-114516.svg)
- [https://github.com/cveForge/CVE-2026-114516](https://github.com/cveForge/CVE-2026-114516) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-114516.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-114516.svg)


## CVE-2026-114469
 Out-of-bounds read can crash git-apply(1) when binary patch inflates to very large size

- [https://github.com/googlesky/CVE-2026-114469](https://github.com/googlesky/CVE-2026-114469) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-114469.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-114469.svg)


## CVE-2026-114467
 Out-of-bounds write possible in Git when git-merge(1) used on tag with more than two GPG signatures

- [https://github.com/googlesky/CVE-2026-114467](https://github.com/googlesky/CVE-2026-114467) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-114467.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-114467.svg)


## CVE-2026-114466
 Arbitrary data can be read or written through git-fast-import(1) and git-fast-export(1) features not marked unsafe

- [https://github.com/googlesky/CVE-2026-114466](https://github.com/googlesky/CVE-2026-114466) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-114466.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-114466.svg)


## CVE-2026-114202
Security Update for ASUS Control Center Express Agent  ' section on the ASUS Security Advisory for more information.

- [https://github.com/cveForge/CVE-2026-114202](https://github.com/cveForge/CVE-2026-114202) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-114202.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-114202.svg)


## CVE-2026-113910
 A memory initialization issue was addressed with improved memory handling. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, tvOS 27.2, visionOS 27.2, watchOS 27.2. An app may be able to disclose kernel memory.

- [https://github.com/ecc521/CVE-2026-113910](https://github.com/ecc521/CVE-2026-113910) :  ![starts](https://img.shields.io/github/stars/ecc521/CVE-2026-113910.svg) ![forks](https://img.shields.io/github/forks/ecc521/CVE-2026-113910.svg)


## CVE-2026-113425
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/cveForge/CVE-2026-113425](https://github.com/cveForge/CVE-2026-113425) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-113425.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-113425.svg)


## CVE-2026-113408
 Path traversal in Git allows writing to arbitrary file via cloning and committing to bad repository

- [https://github.com/googlesky/CVE-2026-113408](https://github.com/googlesky/CVE-2026-113408) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-113408.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-113408.svg)


## CVE-2026-112554
 An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. An app may be able to cause unexpected system termination or read kernel memory.

- [https://github.com/ecc521/CVE-2026-112554](https://github.com/ecc521/CVE-2026-112554) :  ![starts](https://img.shields.io/github/stars/ecc521/CVE-2026-112554.svg) ![forks](https://img.shields.io/github/forks/ecc521/CVE-2026-112554.svg)


## CVE-2026-111760
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. Prior to 2.50.2, 2.51.3, 2.52.1, 2.53.1, 2.54.1, 2.55.1, and 2.56.1, an attacker-controlled repository hosted by the attacker rather than on a normal forge site can exploit git clone --recurse-submodules by causing Git to overwrite a submodule gitfile with a symbolic link. The symbolic link can point to a directory containing attacker-controlled Git configuration or hooks, allowing those hooks or configuration to execute code on the cloning user's system. The issue requires the recursive-submodule option, and users should avoid cloning repositories from untrusted sources. This issue is fixed in versions 2.50.2, 2.51.3, 2.52.1, 2.53.1, 2.54.1, 2.55.1, and 2.56.1.

- [https://github.com/googlesky/CVE-2026-111760](https://github.com/googlesky/CVE-2026-111760) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-111760.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-111760.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/ashrafzaryouh/CVE-2026-111497](https://github.com/ashrafzaryouh/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-111497.svg)
- [https://github.com/cveForge/CVE-2026-111497](https://github.com/cveForge/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-111497.svg)


## CVE-2026-110960
 The Auth Armor  WordPress plugin through 1.0.3 does not require authentication on several handlers available to logged-out users, which leak the site's stored API credentials and allow an unauthenticated attacker to reset an administrator's enrollment and take over that administrator account.

- [https://github.com/cveForge/CVE-2026-110960](https://github.com/cveForge/CVE-2026-110960) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-110960.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-110960.svg)


## CVE-2026-110912
 In DragonFly BSD through 6.4.2 before 4bb22ff, the ARP input handlers arpintr() and in_arpinput() (sys/netinet/if_ether.c) do not validate the hardware address length (ar_hln) and protocol address length (ar_pln) fields of incoming ARP packets. in_arpreply() then uses these attacker-controlled values as memcpy lengths when copying from kernel buffers that are only 6 and 4 bytes long, resulting in an out-of-bounds read of kernel heap and stack memory that is copied into the ARP reply sent back to the requester. An unauthenticated attacker on the adjacent network can use a single crafted ARP request to disclose up to roughly 250 bytes of each type of kernel memory, including kernel pointers. This is expected to be fixed in the 6.6 stable release when that is available.

- [https://github.com/ashrafzaryouh/CVE-2026-110912](https://github.com/ashrafzaryouh/CVE-2026-110912) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-110912.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-110912.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/Ethen1212/php2shell-CVE-2026-109618](https://github.com/Ethen1212/php2shell-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Ethen1212/php2shell-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/php2shell-CVE-2026-109618.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0, FortiSIEM 7.4 all versions, FortiSIEM 7.3 all versions, FortiSIEM 7.2 all versions, FortiSIEM 7.1 all versions, FortiSIEM 7.0 all versions may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/ashrafzaryouh/CVE-2026-106173](https://github.com/ashrafzaryouh/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-106173.svg)


## CVE-2026-104129
 pREST (PostgreSQL REST) is an API that delivers an application on top of a Postgres database. Prior to 2.4.0, the vulnerable parameter is _groupby, handled by GroupByClause in adapters/postgres/postgres.go. adapters/postgres/postgres.go uses the weaker isSafeSQLExpression check for this function-expression branch instead of the stricter single-field validator used for _select. That check validates only the outer function name against a 13-function allowlist and permits nested subqueries, trailing UNION syntax, and inner pg_ functions. controllers/crud.go concatenates the GROUP BY expression while parameterizing only WHERE values, allowing attacker-controlled SQL structure into the clause. Default configuration permits unauthenticated access; a restricted installation may require a low-privilege table reader. UNION-based extraction requires compatible column counts and types and was not verified end to end, but a delay-producing function can cause denial of service without that alignment. This issue is fixed in 2.4.0.

- [https://github.com/googlesky/CVE-2026-104129](https://github.com/googlesky/CVE-2026-104129) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104129.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104129.svg)


## CVE-2026-104099
 Fabio is an HTTP(S) and TCP router for deploying applications managed by consul. Prior to 1.7.3, route/table.go selects targets using raw req.URL.Path, while proxy/http_proxy.go applies per-route ACL and basic-auth checks to the selected target and forwards the raw path to the origin. Dot-segment, encoded-dot, or repeated-slash variants can fall through to a less restrictive route that reaches the same backend; the backend then normalizes the path and serves the protected resource without the configured access controls. A less restrictive fallback route must reach the same backend; without one, the request returns 404. This issue is fixed in version 1.7.3.

- [https://github.com/googlesky/CVE-2026-104099](https://github.com/googlesky/CVE-2026-104099) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104099.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104099.svg)
- [https://github.com/cveForge/CVE-2026-104099](https://github.com/cveForge/CVE-2026-104099) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-104099.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-104099.svg)


## CVE-2026-103035
 TeamPass is a self-hosted collaborative password manager. Prior to 3.2.1.2, the update_folder action in app/sources/folders.queries.php allowed an authenticated, non-read-only user to re-parent a folder without checking whether the target folder or submitted parentId belonged to the caller's user-accessible_folders set. Selecting a personal folder as the new parent passed the personal-folder guard and set personal_folder on the target, transferring the credential subtree into the attacker's accessible space after the next login and hiding it from the organization, including administrators. The change exposed credential labels, logins, URLs, email addresses, and descriptions, while sharekey-protected passwords remained protected; hiding the subtree also denied other users access. This issue is fixed in version 3.2.1.2.

- [https://github.com/googlesky/CVE-2026-103035](https://github.com/googlesky/CVE-2026-103035) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-103035.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-103035.svg)


## CVE-2026-103026
 Paymenter is a free and open-source webshop solution for management of hosting services. Prior to 1.5.7, the HasConfirmation trait in app/Livewire/Traits/HasConfirmation.php, included by app/Livewire/Component.php across 36 client-facing Livewire components, exposed executeConfirmedAction as a public action that invoked any component method accepted by method_exists. The action could call inherited InteractsWithProperties::fill(), whose data_set() writes arbitrary public properties, including state marked with #[Locked] and dotted paths into hydrated Eloquent models. Depending on the methods and properties exposed by an individual component, an unauthenticated caller could use this path to bypass intended authorization and modify server-side state intended to be immutable or protected from client-side manipulation. This issue is fixed in version 1.5.7.

- [https://github.com/googlesky/CVE-2026-103026](https://github.com/googlesky/CVE-2026-103026) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-103026.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-103026.svg)


## CVE-2026-102945
 Aether Project AMF supports termination of NAS signalling, NAS ciphering & integrity protection, registration management, connection management, mobility management, access authentication and authorization, security context management. Prior to 3.1.6, a malformed NGAP PathSwitchRequest can contain a UESecurityCapabilities information element whose extensible APER bit-string representation has no bytes even though decoding reports no error. In ngap/handler.go, HandlePathSwitchRequest checks only whether the element is present before six index-zero reads of its encryption and integrity algorithm fields, causing an unrecovered panic in the NGAP receive goroutine and terminating the AMF. The described attacker is a rogue or compromised gNB on the N2 interface and additionally needs a registered UE's AMF-UE-NGAP-ID; a bare over-the-air UE cannot trigger the issue. This issue is fixed in version 3.1.6.

- [https://github.com/googlesky/CVE-2026-102945](https://github.com/googlesky/CVE-2026-102945) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-102945.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-102945.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-101767](https://github.com/ashrafzaryouh/CVE-2026-101767) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-101767.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-101767.svg)


## CVE-2026-101034
 An attacker who obtained the hardcoded key could decrypt domain/service account passwords, task run-as credentials, and sysprep passwords stored in or transmitted by GSS Deployment Server installation.

- [https://github.com/k3nundrum/CVE-2026-101034](https://github.com/k3nundrum/CVE-2026-101034) :  ![starts](https://img.shields.io/github/stars/k3nundrum/CVE-2026-101034.svg) ![forks](https://img.shields.io/github/forks/k3nundrum/CVE-2026-101034.svg)


## CVE-2026-100397
 Rucio is a scientific data management framework. From 1.14.0 until 35.9.1, 38.6.1, 40.4.2, and 41.1.1, validate_auth_token in lib/rucio/core/authentication.py does not distinguish short-lived SSH challenge nonces from authentication tokens stored in the same token table. An unauthenticated attacker can request /auth/ssh_challenge_token for an arbitrary account by supplying X-Rucio-Account, then present the returned X-Rucio-SSH-Challenge-Token as X-Rucio-Auth-Token to authenticate to other API endpoints as that account, including an administrative account. This issue is fixed in versions 35.9.1, 38.6.1, 40.4.2, and 41.1.1.

- [https://github.com/cveForge/CVE-2026-100397](https://github.com/cveForge/CVE-2026-100397) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-100397.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-100397.svg)


## CVE-2026-99310
list.

- [https://github.com/cveForge/CVE-2026-99310](https://github.com/cveForge/CVE-2026-99310) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-99310.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-99310.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/ashrafzaryouh/CVE-2026-98432](https://github.com/ashrafzaryouh/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-98432.svg)
- [https://github.com/cveForge/CVE-2026-98432](https://github.com/cveForge/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-98432.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-97798](https://github.com/ashrafzaryouh/CVE-2026-97798) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-97798.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-97798.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/cveForge/CVE-2026-96889](https://github.com/cveForge/CVE-2026-96889) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-96889.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-96889.svg)


## CVE-2026-95839
 containerd is an open-source container runtime. From 2.2.0 until 2.2.10, 2.3.7, and 2.4.2, image manifest processing through the transfer service can encounter a child descriptor containing the io.containerd.manifest.subject annotation and a malformed digest. Pulling or importing such an image, including through a default CRI PullImage request, can trigger an unrecovered panic and crash the containerd daemon. In Kubernetes, kubelet retries can repeatedly trigger the crash and disrupt container operations on the worker node. This issue is fixed in versions 2.2.10, 2.3.7, and 2.4.2.

- [https://github.com/googlesky/CVE-2026-95839](https://github.com/googlesky/CVE-2026-95839) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-95839.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-95839.svg)


## CVE-2026-95787
 Vulnerabilities in the PAPI protocol of AOS-10 could allow an unauthenticated remote attacker to circumvent existing authentication controls. Successful exploitation could allow an attacker to gain administrative access, modify system configurations, and access or manipulate sensitive data.

- [https://github.com/cveForge/CVE-2026-95787](https://github.com/cveForge/CVE-2026-95787) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-95787.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-95787.svg)


## CVE-2026-95517
Note: Tomcat 11.0.28 was not released

- [https://github.com/cveForge/CVE-2026-95517](https://github.com/cveForge/CVE-2026-95517) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-95517.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-95517.svg)


## CVE-2026-94567
 NukeViet CMS is a multi Content Management System. Prior to 4.5.12 and 4.6.02, an attacker with access to an SVG upload flow can hide a script element in an internal DTD entity. NukeViet\Files\Upload::check_svg_tmpfile() loads the document without entity expansion, leaving a DOMEntityReference, and sanitize_svg_dom() inspects only element nodes, while browsers expand the entity when the stored file is served as image/svg+xml. The SVG path also returned before verify_image() and preserved the original bytes, so the hidden script reached disk unchanged. Guest comment attachments make the upload unauthenticated only when a module's comment feature is open to the All or Guest group and allowattachcomm is enabled; module administrators can also use the file manager, allowing same-origin script execution in an administrator's session. This issue is fixed in versions 4.5.12 and 4.6.02.

- [https://github.com/cveForge/CVE-2026-94567](https://github.com/cveForge/CVE-2026-94567) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-94567.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-94567.svg)


## CVE-2026-94565
 NukeViet CMS is a multi Content Management System. From the 3.x release line until 4.6.01, an unauthenticated visitor can submit a Contact module message containing an event-handler attribute prefixed by a slash. NukeViet\Core\Request::filterTags() tokenizes attributes using only ASCII spaces, so it sees /onerror and misses the ^on denylist, while the browser treats the slash as a separator and activates onerror. The message is stored and rendered without output encoding in the administration panel, which lacks a Content Security Policy, allowing same-origin JavaScript execution when an administrator opens the message. This issue is fixed in version 4.6.01.

- [https://github.com/cveForge/CVE-2026-94565](https://github.com/cveForge/CVE-2026-94565) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-94565.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-94565.svg)


## CVE-2026-93485
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Automattic WordPress wordpress allows DOM-Based XSS.This issue affects WordPress: from n/a through 7.1.

- [https://github.com/ashrafzaryouh/CVE-2026-93485](https://github.com/ashrafzaryouh/CVE-2026-93485) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-93485.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-93485.svg)


## CVE-2026-92182
The specific flaw exists within the XMLRPC endpoint. The issue results from incorrect authorization prior to allowing access to functionality. An attacker can leverage this vulnerability to execute code within the context of the root. Was ZDI-CAN-32353.

- [https://github.com/cveForge/CVE-2026-92182](https://github.com/cveForge/CVE-2026-92182) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-92182.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-92182.svg)


## CVE-2026-90817
 An unauthenticated Remote Code Execution vulnerability was found in the survey passthrough routing and Data Import processing logic, in which a malicious user could potentially exploit it by manipulating HTTP requests to access an unintended controller route from a public survey context and by supplying a crafted file-path/stream parameter during import handling. If successfully exploited, this could allow the attacker to remotely execute arbitrary code on the REDCap server. The attacker does not have to be authenticated in order to exploit this, but exploitation requires knowledge of a valid public survey hash. This vulnerability exists in REDCap 13.3.0 and higher.

- [https://github.com/cveForge/CVE-2026-90817](https://github.com/cveForge/CVE-2026-90817) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-90817.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-90817.svg)


## CVE-2026-90436
As Axis 1 has been EOL we recommend you migrate to a different SOAP engine, such as Apache Axis 2/Java. Alternatively you could use a build of Axis with the patch from https://github.com/apache/axis-axis1-java/commit/41f3b4e8d04e310ca81f86b92630ab2c11d608bd applied. The Apache Axis project does not expect to create an Axis 1.x release fixing this problem.

- [https://github.com/cveForge/CVE-2026-90436](https://github.com/cveForge/CVE-2026-90436) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-90436.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-90436.svg)


## CVE-2026-87977
 IBM Guardium Data Protection 12.2 is vulnerable to SQL injection in the edge-controller component. An unauthenticated remote attacker could exploit this vulnerability to access or modify sensitive database information.

- [https://github.com/cveForge/CVE-2026-87977](https://github.com/cveForge/CVE-2026-87977) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-87977.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-87977.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/cveForge/CVE-2026-87902](https://github.com/cveForge/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-87902.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 18.7.11 and iPadOS 18.7.11, iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/ashrafzaryouh/CVE-2026-86950](https://github.com/ashrafzaryouh/CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-86950.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code locally.

- [https://github.com/ashrafzaryouh/CVE-2026-83844](https://github.com/ashrafzaryouh/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-83844.svg)


## CVE-2026-83817
 CodeWhale is a DeepSeek and MiMo coding agent for the terminal. Prior to 0.9.0, DEFAULT_AUTOMATION_AUTO_APPROVE caused AutomationRecord::task_auto_approve to resolve an omitted setting to true, and the automation_create schema advertised the same insecure default. enqueue_run_task converted that omission into an explicit true value, bypassing the safer task-path fallback and selecting ApprovalMode::Bypass for each scheduled run. After a user approved creation of an apparently benign recurring automation, subsequent executions could silently authorize mutating tools without a human present, and an automation created with shell access could repeatedly execute commands. This issue is fixed in version 0.9.0.

- [https://github.com/googlesky/CVE-2026-83817](https://github.com/googlesky/CVE-2026-83817) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-83817.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-83817.svg)


## CVE-2026-83816
 CodeWhale is a DeepSeek and MiMo coding agent for the terminal. Prior to 0.9.0, the ExecShellTool::approval_requirement_for path used is_parallel_readonly_command to downgrade commands to automatic approval based on a flag-stripped command allowlist. The allowlist treated fd, rg, and git grep as read-only even when fd -x or fd --exec, rg --pre, or git grep --open-files-in-pager selected an external program. registered_tool_approval_required returned without displaying a prompt for that automatic classification, and the later command-safety check also treated the base utilities as safe. Attacker-controlled content that influenced an agent tool call could therefore cause arbitrary program execution on the developer host without the approval promised by the default interactive profile, resulting in unauthorized access, modification, or disruption. This issue is fixed in version 0.9.0.

- [https://github.com/googlesky/CVE-2026-83816](https://github.com/googlesky/CVE-2026-83816) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-83816.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-83816.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/ashrafzaryouh/CVE-2026-81000](https://github.com/ashrafzaryouh/CVE-2026-81000) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-81000.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-81000.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/ashrafzaryouh/CVE-2026-80844](https://github.com/ashrafzaryouh/CVE-2026-80844) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-80844.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-80844.svg)


## CVE-2026-80188
 The BuddyBoss Addons plugin for WordPress is vulnerable to Authentication Bypass leading to Account Takeover in versions up to, and including, 1.2.1. This is due to the Social Login REST endpoint trusting unverified Apple and Facebook identity-token claims and linking an attacker-controlled provider identifier to an existing WordPress user selected by the token’s email claim. This makes it possible for unauthenticated attackers who know a user’s email address to associate their provider identity with that account, including administrator accounts, and subsequently authenticate as the victim. Successful exploitation requires the BuddyBoss Platform plugin to be installed and active, with the Social Login module and selected provider enabled and configured. On sites with the separate BuddyBoss App JWT component, the vulnerable REST request can return an application token immediately.

- [https://github.com/cveForge/CVE-2026-80188](https://github.com/cveForge/CVE-2026-80188) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-80188.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-80188.svg)


## CVE-2026-77882
 A deserialization of untrusted data vulnerability was discovered in Lenovo System Update that could allow a local authenticated user to execute code with elevated privileges.

- [https://github.com/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873](https://github.com/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873) :  ![starts](https://img.shields.io/github/stars/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873.svg) ![forks](https://img.shields.io/github/forks/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873.svg)


## CVE-2026-77873
 An improper permissions vulnerability was reported in Lenovo System Update that could allow a local authenticated user to execute code with elevated privileges.

- [https://github.com/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873](https://github.com/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873) :  ![starts](https://img.shields.io/github/stars/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873.svg) ![forks](https://img.shields.io/github/forks/ForefrontITSecurityServices/CVE-2026-77882-CVE-2026-77873.svg)


## CVE-2026-77382
 falcon-rust is a Rust implementation of the Falcon post-quantum signature scheme. Prior to 0.2.0, the discrete-Gaussian sampler in src/samplerz.rs evaluates approx_exp, ber_exp, and sampler_z acceptance probabilities with FixedPoint64 values having only 32 fractional bits. The scaling in approx_exp quantizes its input and limits relative precision to about 2^-33, below Falcon's required bound, causing reference known-answer vectors to diverge and invalidating the proof assumption that secret-dependent signature and key distributions are negligibly close to the ideal discrete Gaussian. This is a cryptographic-soundness defect and no practical key-recovery attack has been demonstrated. This issue is fixed in version 0.2.0.

- [https://github.com/googlesky/CVE-2026-77382](https://github.com/googlesky/CVE-2026-77382) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77382.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77382.svg)


## CVE-2026-77380
 Bolt is a fully open source, adaptable platform for building and running modern websites. Prior to 6.1.5, the /bolt/async/upload-url and /bolt/async/embed endpoints validate only a submitted URL before fetching it server-side. The fetchers then follow redirects without revalidating each destination, allowing an authenticated user to bypass UrlSafetyChecker and cause the server to request internal or cloud-metadata addresses. This issue is fixed in version 6.1.5.

- [https://github.com/googlesky/CVE-2026-77380](https://github.com/googlesky/CVE-2026-77380) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77380.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77380.svg)


## CVE-2026-77379
 Bolt is a fully open source, adaptable platform for building and running modern websites. Prior to 6.1.4, the public Relation API lacks an access-control filter. Unauthenticated users can query its REST endpoints and GraphQL endpoints to discover metadata about unpublished, draft, and viewless content. This issue is fixed in version 6.1.4.

- [https://github.com/googlesky/CVE-2026-77379](https://github.com/googlesky/CVE-2026-77379) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77379.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77379.svg)


## CVE-2026-77377
 Bolt is a fully open source, adaptable platform for building and running modern websites. Prior to 6.1.4, the authenticated URL-upload endpoint and authenticated embed endpoint fetch user-supplied URLs server-side without protection against internal targets, allowing an attacker with the applicable backend permission to cause the Bolt server to request those targets. This issue is fixed in version 6.1.4.

- [https://github.com/googlesky/CVE-2026-77377](https://github.com/googlesky/CVE-2026-77377) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77377.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77377.svg)


## CVE-2026-77376
 Bolt is a fully open source, adaptable platform for building and running modern websites. Prior to 6.1.4, LoginFormAuthenticator accepts unsafe destinations for the login success redirect and login failure redirect. An attacker can direct a user to an attacker-controlled domain after authentication succeeds or fails, enabling phishing and potential token theft. This issue is fixed in version 6.1.4.

- [https://github.com/googlesky/CVE-2026-77376](https://github.com/googlesky/CVE-2026-77376) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77376.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77376.svg)


## CVE-2026-77369
 Daptin is a GraphQL/JSON-API headless CMS. From 0.11.4 until 0.12.30, the generic GET /yjs/:documentName WebSocket route in InitializeYjsResources requires a session but does not authorize the database resource selected by a typename.referenceId.columnName room name. The YJS initial-content provider then reads the selected file.* column without CanRead or CanUpdate checks, and bidirectional synchronization allows a low-privileged authenticated user to read or modify restricted row content. Unauthenticated requests are rejected, and standalone non-canonical room names remain shared-by-name rooms. This issue is fixed in version 0.12.30.

- [https://github.com/googlesky/CVE-2026-77369](https://github.com/googlesky/CVE-2026-77369) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77369.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77369.svg)
- [https://github.com/cveForge/CVE-2026-77369](https://github.com/cveForge/CVE-2026-77369) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-77369.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-77369.svg)


## CVE-2026-77367
 Daptin is a GraphQL/JSON-API headless CMS. Prior to 0.12.30, the generic GET /api/{entity} list endpoint accepts attacker-controlled sort values in PaginatedFindAllWithoutFilters in server/resource/resource_findallpaginated.go without validating the requested column against the table schema. The code uses those values for SELECT and ORDER BY identifier construction, so an embedded identifier quote can terminate the quoted identifier and make the remainder parse as SQL, allowing an unauthenticated attacker to extract unauthorized table data through blind or error-based behavior or repeatedly trigger query failures. This issue is fixed in version 0.12.30.

- [https://github.com/googlesky/CVE-2026-77367](https://github.com/googlesky/CVE-2026-77367) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77367.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77367.svg)
- [https://github.com/cveForge/CVE-2026-77367](https://github.com/cveForge/CVE-2026-77367) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-77367.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-77367.svg)


## CVE-2026-77312
 Flyto2 Core is an execution kernel for automation and AI-agent workflows. Prior to 2.26.8, the earlier CVE-2026-67429 remediation applied validate_path_with_env_config() to only a hand-picked set of file-writing modules, leaving data.csv.write in src/core/modules/atomic/data/csv_write.py, data.json_to_csv in src/core/modules/atomic/data/json_to_csv.py, file.copy in src/core/modules/atomic/file/copy.py, and file.move in src/core/modules/atomic/file/move.py outside the FLYTO_SANDBOX_DIR confinement boundary. The advisory also identifies unguarded modules across the broader data.*, file.*, and report-writer families. data.csv.write relies on a .. substring denylist that does not reject absolute paths, while the other named modules accept caller-controlled output or destination paths without the canonical guard. A caller able to execute modules or recipes can therefore write attacker-controlled content outside the configured sandbox, potentially overwriting application code, recipes, startup files, scheduled-task files, or authorization files and gaining code execution on the host. This issue is fixed in version 2.26.8.

- [https://github.com/googlesky/CVE-2026-77312](https://github.com/googlesky/CVE-2026-77312) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77312.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77312.svg)
- [https://github.com/cveForge/CVE-2026-77312](https://github.com/cveForge/CVE-2026-77312) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-77312.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-77312.svg)


## CVE-2026-77309
 AIT GUI provides a framework for building custom websites for real-time telemetry monitoring, commanding, and other mission operations. From 1.0.0 until 2.5.1, POST /tlm/query in ait/gui/__init__.py writes attacker-controlled field data to fields_in.txt, and its no-PCAP error path can abort before deleting that file. The unauthenticated POST /script/run route accepts a scriptPath that resolves outside ScriptRoot, reads the selected file, and executes it as Python. A network-reachable attacker can obtain the ordinary session cookie without credentials, combine the two routes, and execute arbitrary Python code with the AIT-GUI server process privileges. This issue is fixed in version 2.5.1.

- [https://github.com/googlesky/CVE-2026-77309](https://github.com/googlesky/CVE-2026-77309) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77309.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77309.svg)


## CVE-2026-76466
Note: Cisco Expressway Series refers to Cisco Expressway Core (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

- [https://github.com/cveForge/CVE-2026-76466](https://github.com/cveForge/CVE-2026-76466) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-76466.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-76466.svg)


## CVE-2026-76461
This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the attacker to execute arbitrary SQL statements, leading to command execution with root privileges on the underlying operating system.

- [https://github.com/ashrafzaryouh/CVE-2026-76461](https://github.com/ashrafzaryouh/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-76461.svg)


## CVE-2026-75521
 Miren Runtime provides the runtime component for the Miren application platform. Prior to 0.11.1, the QUIC/HTTP3 RPC server on the default port 8443 uses tls.RequestClientCert and does not verify that presented certificates chain to the configured cluster certificate authority. The RPC authenticators derive a caller identity from PeerCertificates[0].Subject.CommonName without requiring a non-empty VerifiedChains value, and certificate identities bypass all RBAC checks. A network attacker who can reach the listener can present a self-signed certificate with an issuer distinguished name matching the public cluster CA subject and gain cluster superuser access, allowing disclosure, modification, or disruption of applications, sandboxes, disks, credentials, and other managed resources. This issue is fixed in version 0.11.1.

- [https://github.com/cveForge/CVE-2026-75521](https://github.com/cveForge/CVE-2026-75521) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-75521.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-75521.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/ashrafzaryouh/CVE-2026-74469](https://github.com/ashrafzaryouh/CVE-2026-74469) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-74469.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-74469.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/ashrafzaryouh/CVE-2026-73570](https://github.com/ashrafzaryouh/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-73570.svg)


## CVE-2026-73296
 Microsoft UFO open-source framework for intelligent automation across devices and platforms. Prior to 3.0.8, create_mobile_data_collection_server and create_mobile_action_server in ufo/client/mcp/http_servers/mobile_mcp_server.py exposed Streamable HTTP MCP services on TCP ports 8020 and 8021 without authentication, allowing an unauthenticated remote attacker to invoke capture_screenshot, get_ui_tree, tap, swipe, type_text, launch_app, press_key, and click_control against an ADB-connected Android device, disclose screen and device data, and modify device state. This issue is fixed in version 3.0.8.

- [https://github.com/ashrafzaryouh/CVE-2026-73296](https://github.com/ashrafzaryouh/CVE-2026-73296) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-73296.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-73296.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/ashrafzaryouh/CVE-2026-72898](https://github.com/ashrafzaryouh/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-72898.svg)


## CVE-2026-72018
check before the memcpy to reject such requests with -EINVAL.

- [https://github.com/ashrafzaryouh/CVE-2026-72018](https://github.com/ashrafzaryouh/CVE-2026-72018) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-72018.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-72018.svg)


## CVE-2026-71481
 ALTCHA PHP is a lightweight PHP library for creating and verifying ALTCHA challenges. From 2.0.0 until 2.0.3, the verifySolution method skips HMAC signature verification when a challenge payload omits the signature field, even when hmacSignatureSecret is configured. An attacker can remove the signature, supply attacker-selected low-difficulty challenge parameters, solve the resulting proof of work, and submit a payload that verifies successfully, bypassing the CAPTCHA control. This issue is fixed in version 2.0.3.

- [https://github.com/cveForge/CVE-2026-71481](https://github.com/cveForge/CVE-2026-71481) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-71481.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-71481.svg)


## CVE-2026-69158
 Atomic Server is an open source headless CMS and real-time database. Prior to 0.40.3, unauthenticated requests to /bookmark can supply a url that server/src/plugins/bookmark.rs passes through fetch_data to fetch_body. Endpoint dispatch in lib/src/db.rs invokes the handler before check_read, and lib/src/client/helpers.rs previously checked only that the URL began with HTTP, without restricting loopback, private, link-local, DNS-rebinding, or redirect targets. The handler reflects fetched content in returned resource fields, making this a full-response server-side request forgery that can expose internal services and plain-GET cloud metadata. The short request timeout limits slow targets, and metadata services requiring a separate token request are outside the demonstrated GET-only path. This issue is fixed in version 0.40.3.

- [https://github.com/cveForge/CVE-2026-69158](https://github.com/cveForge/CVE-2026-69158) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-69158.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-69158.svg)


## CVE-2026-69157
 Atomic Server is an open source headless CMS and real-time database. From 0.29.0 to 0.40.2, Atomic Server provisions a well-known /setup invite with write enabled, the Drive root as its target, and usagesLeft set to one. construct_invite_redirect in server/src/plugins/invite.rs discards the redeemer identity, so an unauthenticated request containing an attacker-controlled public-key can create a new Agent and grant it write access to the entire Drive. On a fresh, unclaimed deployment, this permits reading, modifying, or deleting resources, changing permissions, and creating or altering Agents. No complete fixed version was verified as of this review.

- [https://github.com/cveForge/CVE-2026-69157](https://github.com/cveForge/CVE-2026-69157) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-69157.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-69157.svg)


## CVE-2026-69156
 Atomic Server is an open source headless CMS and real-time database. From 0.30.0 until 0.40.3, the Commit application path in lib/src/commit.rs allows an authenticated Agent to assign the server-managed internalId property to an owned resource without character validation. The /download handler in server/src/handlers/download.rs passes that value to filesystem path construction and NamedFile::open without sanitization, containment validation, or a File-class check, so traversal or absolute paths can read files available to the server process. Reading the server configuration can expose the root Agent private key and allow root impersonation with full read, write, and delete access to server data. This issue is fixed in version 0.40.3.

- [https://github.com/cveForge/CVE-2026-69156](https://github.com/cveForge/CVE-2026-69156) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-69156.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-69156.svg)


## CVE-2026-68791
 Incorrect authorization in Azure Machine Learning allows an unauthorized attacker to disclose information over a network.

- [https://github.com/cveForge/CVE-2026-68791](https://github.com/cveForge/CVE-2026-68791) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-68791.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-68791.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/ashrafzaryouh/CVE-2026-68121](https://github.com/ashrafzaryouh/CVE-2026-68121) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-68121.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-68121.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/ashrafzaryouh/CVE-2026-66066](https://github.com/ashrafzaryouh/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-66066.svg)


## CVE-2026-65094
 NVIDIA VIRTIO-Net for Bluefield contains a vulnerability in Virtio-Net where a VM user may cause a Write-What-Where condition by crafted message. A successful exploit of this vulnerability may lead to Code Execution in Virtio-Net scope.

- [https://github.com/cveForge/CVE-2026-65094](https://github.com/cveForge/CVE-2026-65094) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-65094.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-65094.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/ashrafzaryouh/CVE-2026-64638](https://github.com/ashrafzaryouh/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-64638.svg)
- [https://github.com/secplayground/CVE-2026-64638-scanner-and-exploit](https://github.com/secplayground/CVE-2026-64638-scanner-and-exploit) :  ![starts](https://img.shields.io/github/stars/secplayground/CVE-2026-64638-scanner-and-exploit.svg) ![forks](https://img.shields.io/github/forks/secplayground/CVE-2026-64638-scanner-and-exploit.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/ashrafzaryouh/CVE-2026-64600](https://github.com/ashrafzaryouh/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-64600.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/ashrafzaryouh/CVE-2026-64531](https://github.com/ashrafzaryouh/CVE-2026-64531) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-64531.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-64531.svg)


## CVE-2026-63292
Users are recommended to upgrade to version 2.4.69, which fixes this issue.

- [https://github.com/ashrafzaryouh/CVE-2026-63292](https://github.com/ashrafzaryouh/CVE-2026-63292) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-63292.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-63292.svg)


## CVE-2026-63129
 mssql-mcp-core is the shared library that powers MSSQL MCP servers. Prior to core and server 0.6.0 and reader and writer 0.5.0, multiple database tools interpolate caller-controlled identifiers and predicates into T-SQL batches passed to Request.query() while parameterizing only data values. update_data, delete_data, insert_data, execute_transaction, create_table, create_index, and drop_table accept unsafe tableName, column, index, schema, or free-form whereClause input, while reader-tier list_databases interpolates stateFilter without runtime allowlist enforcement. Row-count and preview queries execute before confirmUpdate or confirmDelete, allowing malicious arguments to bypass confirmation and maxRows controls and execute stacked DDL or DML, read or destroy data, and potentially run operating-system commands when the SQL login is privileged and xp_cmdshell is enabled. This issue is fixed in core and server version 0.6.0 and reader and writer version 0.5.0.

- [https://github.com/cveForge/CVE-2026-63129](https://github.com/cveForge/CVE-2026-63129) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-63129.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-63129.svg)


## CVE-2026-63072
modules are affected by this CVE.

- [https://github.com/ashrafzaryouh/CVE-2026-63072](https://github.com/ashrafzaryouh/CVE-2026-63072) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-63072.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-63072.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/ashrafzaryouh/CVE-2026-63030](https://github.com/ashrafzaryouh/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-63030.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/her3ticAVI/CVE-2026-62911](https://github.com/her3ticAVI/CVE-2026-62911) :  ![starts](https://img.shields.io/github/stars/her3ticAVI/CVE-2026-62911.svg) ![forks](https://img.shields.io/github/forks/her3ticAVI/CVE-2026-62911.svg)


## CVE-2026-60206
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via SAML to compromise Oracle WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-60206](https://github.com/ashrafzaryouh/CVE-2026-60206) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-60206.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-60206.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/ashrafzaryouh/CVE-2026-60004](https://github.com/ashrafzaryouh/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-60004.svg)


## CVE-2026-59988
 django-docutils provides reStructuredText support for Django. Prior to 0.30.0, public rendering paths including publish_doctree, publish_html_from_source, publish_html_from_doctree, publish_parts_from_doctree, the {% rst %} template tag, the rst template filter, DocutilsTemplates, and DocutilsView pass lower-trust reStructuredText to Docutils without disabling file_insertion_enabled, raw_enabled, ambient docutils.conf processing, or unsafe URI schemes and without consistently sanitizing doctrees. An attacker who can influence rendered reStructuredText can use include or csv-table directives to read local files or cause server-side URL requests, or use raw HTML and unsafe URI output to inject stored script-capable content. Applications that render only trusted static reStructuredText are not affected unless attackers can influence it. This issue is fixed in version 0.30.0.

- [https://github.com/googlesky/CVE-2026-59988](https://github.com/googlesky/CVE-2026-59988) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-59988.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-59988.svg)


## CVE-2026-59442
In that case, a remote user may be able to retrieve documents they should not have access to, and the same filter used for a delete operation may remove documents outside the intended scope.

- [https://github.com/googlesky/CVE-2026-59442](https://github.com/googlesky/CVE-2026-59442) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-59442.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-59442.svg)


## CVE-2026-59340
Any application that processes PDFs from untrusted sources (document upload, email attachment processing, RAG ingestion, web crawling) using either affected reader is impacted.

- [https://github.com/googlesky/CVE-2026-59340](https://github.com/googlesky/CVE-2026-59340) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-59340.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-59340.svg)


## CVE-2026-58882
 In decodeWapPdu of WapPushOverSms.java, there is a possible out of bounds read due to an integer overflow. This could lead to a remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/warsecurity/-CVE-2026-58882](https://github.com/warsecurity/-CVE-2026-58882) :  ![starts](https://img.shields.io/github/stars/warsecurity/-CVE-2026-58882.svg) ![forks](https://img.shields.io/github/forks/warsecurity/-CVE-2026-58882.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/ashrafzaryouh/CVE-2026-58138](https://github.com/ashrafzaryouh/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-58138.svg)


## CVE-2026-55621
 Incus is a system container and virtual machine manager. Prior to version 7.2.0, missing authorization checks exist for custom volume copying where an attacker knowing the name of a project that they don't have access to and the name of a custom volume in that project can copy the custom volume to a new project. This issue could allow an attacker to access secrets in custom volumes they are not authorized to access. Version 7.2.0 patches the issue.

- [https://github.com/googlesky/CVE-2026-55621](https://github.com/googlesky/CVE-2026-55621) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-55621.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-55621.svg)


## CVE-2026-55450
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, unauthenticated users can upload any amount of data to the server without any limitations. No need for any prior knowledge, only network access to Langflow. This can lead to space exhaustion on the server. In addition, in the response, the absolute path of the uploaded file is reported to the attacker, which is an information leak that can assist in chaining other primitives. This vulnerability is fixed in 1.9.1.

- [https://github.com/ashrafzaryouh/CVE-2026-55450](https://github.com/ashrafzaryouh/CVE-2026-55450) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-55450.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-55450.svg)


## CVE-2026-55200
 libssh2 1.11.1, fixed in commit 97acf3d, contains an out-of-bounds write vulnerability in ssh2_transport_read() that fails to enforce upper bounds on packet_length field. Remote attackers can send crafted SSH packets with excessively large packet_length values to corrupt heap memory and achieve remote code execution.

- [https://github.com/ashrafzaryouh/CVE-2026-55200](https://github.com/ashrafzaryouh/CVE-2026-55200) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-55200.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-55200.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/ashrafzaryouh/CVE-2026-54121](https://github.com/ashrafzaryouh/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-54121.svg)


## CVE-2026-53921
 odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. Prior to version 25.12, odhcpd's DHCPv6 IA response handler writes past the end of a fixed 512-byte stack buffer (pdbuf) when a single DHCPv6 REQUEST carries enough IA options to nearly exhaust the reply space. Two independent overflow sites exist in the same call chain, both reachable from the network via a single unauthenticated UDP packet. odhcpd runs as root on OpenWrt; embedded targets often lack stack canaries and ASLR, making code execution realistic. This issue has been patched in version 25.12.

- [https://github.com/ashrafzaryouh/CVE-2026-53921](https://github.com/ashrafzaryouh/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-53921.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/ashrafzaryouh/CVE-2026-53359](https://github.com/ashrafzaryouh/CVE-2026-53359) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-53359.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-53359.svg)


## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/ashrafzaryouh/CVE-2026-50751](https://github.com/ashrafzaryouh/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-50751.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/ashrafzaryouh/CVE-2026-50656](https://github.com/ashrafzaryouh/CVE-2026-50656) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-50656.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-50656.svg)


## CVE-2026-50229
Users are recommended to upgrade to version 11.0.23, 10.1.56 or 9.0.119, which fix the issue.

- [https://github.com/zero-trace7/CVE-2026-50229](https://github.com/zero-trace7/CVE-2026-50229) :  ![starts](https://img.shields.io/github/stars/zero-trace7/CVE-2026-50229.svg) ![forks](https://img.shields.io/github/forks/zero-trace7/CVE-2026-50229.svg)


## CVE-2026-49952
 Discuz! X5.0 releases 20260320 through 20260501 contains an authentication bypass vulnerability that allows unauthenticated remote attackers to gain unauthorized access to database backup and restore functionality by exploiting a shared cryptographic key between UCenter integration and the database backup API exposed by dbbak.php. Attackers can inject a crafted payload through the username parameter during login to abuse the encryption oracle in logging_ctl::logging_more(), obtain a legitimately signed token, and use it to bypass authorization for database export and import operations, with the additional ability to trigger a race condition to impersonate arbitrary users.

- [https://github.com/caviar-dynamo/CVE-2026-49952](https://github.com/caviar-dynamo/CVE-2026-49952) :  ![starts](https://img.shields.io/github/stars/caviar-dynamo/CVE-2026-49952.svg) ![forks](https://img.shields.io/github/forks/caviar-dynamo/CVE-2026-49952.svg)


## CVE-2026-49869
 Kestra is an open-source, event-driven orchestration platform. Prior to 1.0.45 and 1.3.21, AuthenticationFilter in Kestra OSS uses request.getPath().endsWith("/configs") to whitelist the public configuration endpoint from Basic Auth. Because the check is a suffix match rather than an exact path match, any API path whose last segment is configs bypasses authentication entirely. An unauthenticated remote attacker can exploit this to create and execute arbitrary workflows without credentials. Because Kestra ships with script execution plugins (plugin-script-shell, plugin-script-python, etc.) enabled by default, this directly results in unauthenticated Remote Code Execution as root inside the Kestra worker container.  This vulnerability is fixed in 1.0.45 and 1.3.21.

- [https://github.com/cveForge/CVE-2026-49869](https://github.com/cveForge/CVE-2026-49869) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-49869.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-49869.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/ashrafzaryouh/CVE-2026-48908](https://github.com/ashrafzaryouh/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-48908.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/ashrafzaryouh/CVE-2026-48907](https://github.com/ashrafzaryouh/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-48907.svg)


## CVE-2026-48356
 Adobe Commerce is affected by an Unrestricted Upload of File with Dangerous Type vulnerability that could result in arbitrary code execution in the context of the current user, potentially gaining elevated access or control over the victim's account or session. Exploitation of this issue requires user interaction in that a victim must visit a maliciously crafted URL or interact with a compromised web page. Scope is changed.

- [https://github.com/cveForge/CVE-2026-48356](https://github.com/cveForge/CVE-2026-48356) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-48356.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-48356.svg)


## CVE-2026-47884
Spring Framework 5.2.25.RELEASE and earlier

- [https://github.com/cveForge/CVE-2026-47884](https://github.com/cveForge/CVE-2026-47884) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-47884.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-47884.svg)


## CVE-2026-47729
 Squid is a caching proxy for the Web. Prior to 7.6, due to an improper validation of syntactic correctness of input in the FTP gateway (src/clients/FtpGateway.cc), Squid is vulnerable to an out-of-bounds read: when a listing entry date in the TypeA or TypeB directory-listing formats is not followed by a filename, parsing was not restricted to the input buffer, so a trusted client accessing a misbehaving FTP server through Squid's gateway feature could read memory from random unrelated transactions. This issue is fixed in version 7.6.

- [https://github.com/ashrafzaryouh/CVE-2026-47729](https://github.com/ashrafzaryouh/CVE-2026-47729) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-47729.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-47729.svg)


## CVE-2026-47156
 MantisBT is an open source bug tracker. Versions 2.28.3 and earlier contain a critical authentication bypass in the SOAP API's mci_check_login() function. Any user knowing any valid cookie_string can authenticate as any other user (knowing their username), including the administrator, without knowing the target's password. The vulnerability is exploitable with zero prior access on default MantisBT installations because self-registration is enabled by default ($g_allow_signup = ON). A self-registered user can use their own cookie_string (readable from their browser's MANTIS_STRING_COOKIE cookie after login) to impersonate the administrator via the SOAP API. The REST API is NOT affected. The REST API's AuthMiddleware derives the username server-side from the API token or session cookie, so the username cannot be spoofed. The Web UI is NOT affected. The Web UI authenticates via PHP session cookies (PHPSESSID) and validates the MANTIS_STRING_COOKIE against the logged-in user through auth_is_cookie_valid(). The username is derived server-side from the cookie, not supplied by the client. Version 2.28.4 contains a patch. No known workarounds are available.

- [https://github.com/kanokwut/mantisbt-soap-cookie-case-collision-poc](https://github.com/kanokwut/mantisbt-soap-cookie-case-collision-poc) :  ![starts](https://img.shields.io/github/stars/kanokwut/mantisbt-soap-cookie-case-collision-poc.svg) ![forks](https://img.shields.io/github/forks/kanokwut/mantisbt-soap-cookie-case-collision-poc.svg)


## CVE-2026-46817
 Vulnerability in the Oracle Payments product of Oracle E-Business Suite (component: File Transmission).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Payments.  Successful attacks of this vulnerability can result in takeover of Oracle Payments. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-46817](https://github.com/ashrafzaryouh/CVE-2026-46817) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46817.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46817.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/ashrafzaryouh/CVE-2026-46333](https://github.com/ashrafzaryouh/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46333.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/ashrafzaryouh/CVE-2026-46331](https://github.com/ashrafzaryouh/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46331.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/ashrafzaryouh/CVE-2026-46300](https://github.com/ashrafzaryouh/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46300.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/ashrafzaryouh/CVE-2026-46243](https://github.com/ashrafzaryouh/CVE-2026-46243) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46243.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46243.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/ashrafzaryouh/CVE-2026-46242](https://github.com/ashrafzaryouh/CVE-2026-46242) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46242.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46242.svg)


## CVE-2026-45829
 A pre-authentication, code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/{tenant}/databases/{db}/collections endpoint.

- [https://github.com/ashrafzaryouh/CVE-2026-45829](https://github.com/ashrafzaryouh/CVE-2026-45829) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-45829.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-45829.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/ashrafzaryouh/CVE-2026-45585](https://github.com/ashrafzaryouh/CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-45585.svg)


## CVE-2026-45447
issue, as the affected code is outside the OpenSSL FIPS module boundary.

- [https://github.com/ashrafzaryouh/CVE-2026-45447](https://github.com/ashrafzaryouh/CVE-2026-45447) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-45447.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-45447.svg)


## CVE-2026-45374
 CodeWhale is a DeepSeek + MiMo coding agent in terminal. Prior to 0.8.26, the task_create tool spawns durable sub-agents that inherit two insecure defaults, allow_shell defaults to true (config.rs:1499: self.allow_shell.unwrap_or(true)) and auto_approve defaults to true (task_manager.rs:297: auto_approve: Some(true)). When a user approves a task_create call (which requires ApprovalRequirement::Required), they approve what appears to be a benign work prompt. However, the spawned sub-agent silently receives unrestricted, unapproved shell access. This vulnerability is fixed in 0.8.26.

- [https://github.com/googlesky/CVE-2026-83817](https://github.com/googlesky/CVE-2026-83817) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-83817.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-83817.svg)


## CVE-2026-45325
 Gestor de Oferta is a web application for managing mobility service offerings. Prior to 20260509.0340.15, @tmlmobilidade/utils has a prototype pollution vulnerability in setValueAtPath() in packages/utils/src/generic/value-at-path.ts because unsafe path segments are not blocked. This issue is fixed in version 20260509.0340.15.

- [https://github.com/googlesky/CVE-2026-45325](https://github.com/googlesky/CVE-2026-45325) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-45325.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-45325.svg)


## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/7starL/CVE-2026-45321-Tanstack](https://github.com/7starL/CVE-2026-45321-Tanstack) :  ![starts](https://img.shields.io/github/stars/7starL/CVE-2026-45321-Tanstack.svg) ![forks](https://img.shields.io/github/forks/7starL/CVE-2026-45321-Tanstack.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/ashrafzaryouh/CVE-2026-44578](https://github.com/ashrafzaryouh/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-44578.svg)


## CVE-2026-44277
 A improper access control vulnerability in Fortinet FortiAuthenticator 8.0.2, FortiAuthenticator 8.0.0, FortiAuthenticator 6.6.0 through 6.6.8, FortiAuthenticator 6.5.0 through 6.5.6, FortiAuthenticator 6.4.0 through 6.4.10 may allow attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/ashrafzaryouh/CVE-2026-44277](https://github.com/ashrafzaryouh/CVE-2026-44277) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-44277.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-44277.svg)


## CVE-2026-43786
 This issue was addressed with additional entitlement checks. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An app may be able to gain root privileges.

- [https://github.com/ashrafzaryouh/CVE-2026-43786](https://github.com/ashrafzaryouh/CVE-2026-43786) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43786.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43786.svg)


## CVE-2026-43503
so segments drawing frags from frag_list members carry the marker.

- [https://github.com/ashrafzaryouh/CVE-2026-43503](https://github.com/ashrafzaryouh/CVE-2026-43503) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43503.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43503.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ashrafzaryouh/CVE-2026-43499](https://github.com/ashrafzaryouh/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43499.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/ashrafzaryouh/CVE-2026-43494](https://github.com/ashrafzaryouh/CVE-2026-43494) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43494.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43494.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/ashrafzaryouh/CVE-2026-43284](https://github.com/ashrafzaryouh/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43284.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ashrafzaryouh/CVE-2026-42945](https://github.com/ashrafzaryouh/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42945.svg)
- [https://github.com/cveForge/CVE-2026-42945](https://github.com/cveForge/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-42945.svg)


## CVE-2026-42569
 phpVMS is a PHP application to run and simulate an airline. Prior to version 7.0.6, a critical vulnerability in phpVMS allowed unauthenticated access to a legacy import feature. This issue has been patched in version 7.0.6.

- [https://github.com/ashrafzaryouh/CVE-2026-42569](https://github.com/ashrafzaryouh/CVE-2026-42569) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42569.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42569.svg)


## CVE-2026-42530
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ashrafzaryouh/CVE-2026-42530](https://github.com/ashrafzaryouh/CVE-2026-42530) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42530.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42530.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/ashrafzaryouh/CVE-2026-42208](https://github.com/ashrafzaryouh/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42208.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/ashrafzaryouh/CVE-2026-41940](https://github.com/ashrafzaryouh/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41940.svg)
- [https://github.com/cveForge/CVE-2026-41940](https://github.com/cveForge/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-41940.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/ashrafzaryouh/CVE-2026-41651](https://github.com/ashrafzaryouh/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41651.svg)


## CVE-2026-41462
 ProjeQtor versions 7.0 through 12.4.3 contain an unauthenticated SQL injection vulnerability in the login functionality where the login variable is directly concatenated into a SQL query without parameterization or sanitization. Attackers can inject arbitrary SQL expressions through the username field at the authentication endpoint to create privileged accounts, read sensitive data, and execute operating system commands if the database user has elevated permissions.

- [https://github.com/ashrafzaryouh/CVE-2026-41462](https://github.com/ashrafzaryouh/CVE-2026-41462) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41462.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41462.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-41091](https://github.com/ashrafzaryouh/CVE-2026-41091) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41091.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41091.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/ashrafzaryouh/CVE-2026-41089](https://github.com/ashrafzaryouh/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41089.svg)


## CVE-2026-40487
 Postiz is an AI social media scheduling tool. Prior to version 2.21.6, a file upload validation bypass allows any authenticated user to upload arbitrary HTML, SVG, or other executable file types to the server by spoofing the `Content-Type` header. The uploaded files are then served by nginx with a Content-Type derived from their original extension (`text/html`, `image/svg+xml`), enabling Stored Cross-Site Scripting (XSS) in the context of the application's origin. This can lead to session riding, account takeover, and full compromise of other users' accounts. Version 2.21.6 contains a fix.

- [https://github.com/ashrafzaryouh/CVE-2026-42208](https://github.com/ashrafzaryouh/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42208.svg)


## CVE-2026-40369
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-40369](https://github.com/ashrafzaryouh/CVE-2026-40369) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-40369.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-40369.svg)


## CVE-2026-40217
 LiteLLM through 2026-04-08 allows remote attackers to execute arbitrary code via bytecode rewriting at the /guardrails/test_custom_code URI.

- [https://github.com/cveForge/CVE-2026-40217](https://github.com/cveForge/CVE-2026-40217) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-40217.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-40217.svg)


## CVE-2026-40175
 Axios is a promise based HTTP client for the browser and Node.js. Versions prior to 1.15.0 and 0.3.1 are vulnerable to a specific gadget-style attack chain in which prototype pollution in a third-party dependency may be leveraged to inject unsanitized header values into outbound requests. This vulnerability is fixed in 1.15.0 and 0.3.1.

- [https://github.com/ashrafzaryouh/CVE-2026-40175](https://github.com/ashrafzaryouh/CVE-2026-40175) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-40175.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-40175.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/ashrafzaryouh/CVE-2026-39987](https://github.com/ashrafzaryouh/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-39987.svg)


## CVE-2026-39813
 A path traversal: '../filedir' vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8 may allow attacker to escalation of privilege via specially crafted HTTP requests.

- [https://github.com/ashrafzaryouh/CVE-2026-39813](https://github.com/ashrafzaryouh/CVE-2026-39813) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-39813.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-39813.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/ashrafzaryouh/CVE-2026-39808](https://github.com/ashrafzaryouh/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-39808.svg)
- [https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-35616
 A improper access control vulnerability in Fortinet FortiClientEMS 7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/ashrafzaryouh/CVE-2026-35616](https://github.com/ashrafzaryouh/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-35616.svg)


## CVE-2026-35273
 Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Updates Environment Management). Supported versions that are affected are 8.61 and 8.62. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PeopleTools. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-35273](https://github.com/ashrafzaryouh/CVE-2026-35273) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-35273.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-35273.svg)


## CVE-2026-34724
 Zammad is a web based open source helpdesk/customer support system. Prior to 7.0.1, a server-side template injection vulnerability  which leads to RCE via AI Agent exists. Impact is limited to environments where an attacker can control or influence type_enrichment_data (typically high-privilege administrative configuration). This vulnerability is fixed in 7.0.1.

- [https://github.com/ashrafzaryouh/CVE-2026-34724](https://github.com/ashrafzaryouh/CVE-2026-34724) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-34724.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-34724.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/ashrafzaryouh/CVE-2026-34197](https://github.com/ashrafzaryouh/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-34197.svg)


## CVE-2026-34156
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to version 2.0.28, NocoBase's Workflow Script Node executes user-supplied JavaScript inside a Node.js vm sandbox with a custom require allowlist (controlled by WORKFLOW_SCRIPT_MODULES env var). However, the console object passed into the sandbox context exposes host-realm WritableWorkerStdio stream objects via console._stdout and console._stderr. An authenticated attacker can traverse the prototype chain to escape the sandbox and achieve Remote Code Execution as root. This issue has been patched in version 2.0.28.

- [https://github.com/ashrafzaryouh/CVE-2026-34156](https://github.com/ashrafzaryouh/CVE-2026-34156) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-34156.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-34156.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-33825](https://github.com/ashrafzaryouh/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-33825.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/RockKingdom/CVE-2026-33439-Python-PoC](https://github.com/RockKingdom/CVE-2026-33439-Python-PoC) :  ![starts](https://img.shields.io/github/stars/RockKingdom/CVE-2026-33439-Python-PoC.svg) ![forks](https://img.shields.io/github/forks/RockKingdom/CVE-2026-33439-Python-PoC.svg)


## CVE-2026-33203
 SiYuan is a personal knowledge management system. Prior to version 3.6.2, the SiYuan kernel WebSocket server accepts unauthenticated connections when a specific "auth keepalive" query parameter is present. After connection, incoming messages are parsed using unchecked type assertions on attacker-controlled JSON. A remote attacker can send malformed messages that trigger a runtime panic, potentially crashing the kernel process and causing denial of service. Version 3.6.2 fixes the issue.

- [https://github.com/googlesky/CVE-2026-33203](https://github.com/googlesky/CVE-2026-33203) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-33203.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-33203.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/ashrafzaryouh/CVE-2026-33017](https://github.com/ashrafzaryouh/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-33017.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/ashrafzaryouh/CVE-2026-32475](https://github.com/ashrafzaryouh/CVE-2026-32475) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-32475.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-32475.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/ashrafzaryouh/CVE-2026-31635](https://github.com/ashrafzaryouh/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-31635.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/ashrafzaryouh/CVE-2026-31431](https://github.com/ashrafzaryouh/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-31431.svg)
- [https://github.com/erlangparasu/mitigate_cve_2026_31431-sh](https://github.com/erlangparasu/mitigate_cve_2026_31431-sh) :  ![starts](https://img.shields.io/github/stars/erlangparasu/mitigate_cve_2026_31431-sh.svg) ![forks](https://img.shields.io/github/forks/erlangparasu/mitigate_cve_2026_31431-sh.svg)


## CVE-2026-31402
correct response on the original request.

- [https://github.com/ashrafzaryouh/CVE-2026-31402](https://github.com/ashrafzaryouh/CVE-2026-31402) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-31402.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-31402.svg)


## CVE-2026-29204
 Insufficient ownership check in `clientarea.php` allows an authenticated client area user to submit requests using another user’s `addonId` without any ownership validation leading to unauthorized access to the victim's account.

- [https://github.com/cveForge/CVE-2026-29204](https://github.com/cveForge/CVE-2026-29204) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-29204.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-29204.svg)


## CVE-2026-28289
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. A patch bypass vulnerability for CVE-2026-27636 in FreeScout 1.8.206 and earlier allows any authenticated user with file upload permissions to achieve Remote Code Execution (RCE) on the server by uploading a malicious .htaccess file using a zero-width space character prefix to bypass the security check. The vulnerability exists in the sanitizeUploadedFileName() function in app/Http/Helper.php. The function contains a Time-of-Check to Time-of-Use (TOCTOU) flaw where the dot-prefix check occurs before sanitization removes invisible characters. This vulnerability is fixed in 1.8.207.

- [https://github.com/ashrafzaryouh/CVE-2026-28289](https://github.com/ashrafzaryouh/CVE-2026-28289) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-28289.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-28289.svg)


## CVE-2026-27876
- 12.4.0 (inclusive) to 12.4.2 (exclusive): 12.4.2 has the fix. 13.0.0 and above also have the fix: no v13 release is affected.

- [https://github.com/ashrafzaryouh/CVE-2026-27876](https://github.com/ashrafzaryouh/CVE-2026-27876) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-27876.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-27876.svg)


## CVE-2026-27119
 svelte performance oriented web framework. From 5.39.3, =5.51.4, in certain circumstances, the server-side rendering output of an option element does not properly escape its content, potentially allowing HTML injection in the SSR output. Client-side rendering is not affected. This vulnerability is fixed in 5.51.5.

- [https://github.com/googlesky/CVE-2026-27119](https://github.com/googlesky/CVE-2026-27119) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-27119.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-27119.svg)


## CVE-2026-25769
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Versions 4.0.0 through 4.14.2 have a Remote Code Execution (RCE) vulnerability due to Deserialization of Untrusted Data). All Wazuh deployments using cluster mode (master/worker architecture) and any organization with a compromised worker node (e.g., through initial access, insider threat, or supply chain attack) are impacted. An attacker who gains access to a worker node (through any means) can achieve full RCE on the master node with root privileges. Version 4.14.3 fixes the issue.

- [https://github.com/ashrafzaryouh/CVE-2026-25769](https://github.com/ashrafzaryouh/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-25769.svg)


## CVE-2026-25089
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests

- [https://github.com/ashrafzaryouh/CVE-2026-25089](https://github.com/ashrafzaryouh/CVE-2026-25089) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-25089.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-25089.svg)


## CVE-2026-25057
 MarkUs is a web application for the submission and grading of student assignments. Prior to 2.9.1, instructors are able to upload a zip file to create an assignment from an exported configuration (courses/:course_id/assignments/upload_config_files). The uploaded zip file entry names are used to create paths to write files to disk without checking these paths. This vulnerability is fixed in 2.9.1.

- [https://github.com/rizfol/CVE-2026-25057](https://github.com/rizfol/CVE-2026-25057) :  ![starts](https://img.shields.io/github/stars/rizfol/CVE-2026-25057.svg) ![forks](https://img.shields.io/github/forks/rizfol/CVE-2026-25057.svg)


## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.

- [https://github.com/ashrafzaryouh/CVE-2026-25049](https://github.com/ashrafzaryouh/CVE-2026-25049) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-25049.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-25049.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/ashrafzaryouh/CVE-2026-24061](https://github.com/ashrafzaryouh/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-24061.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/ashrafzaryouh/CVE-2026-23111](https://github.com/ashrafzaryouh/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-23111.svg)


## CVE-2026-22865
 Gradle is a build automation tool, and its native-platform tool provides Java bindings for native APIs. When resolving dependencies in versions before 9.3.0, some exceptions were not treated as fatal errors and would not cause a repository to be disabled. If a build encountered one of these exceptions, Gradle would continue to the next repository in the list and potentially resolve dependencies from a different repository. An exception like NoHttpResponseException can indicate transient errors. If the errors persist after a maximum number of retries, Gradle would continue to the next repository. This behavior could allow an attacker to disrupt the service of a repository and leverage another repository to serve malicious artifacts. This attack requires the attacker to have control over a repository after the disrupted repository. Gradle has introduced a change in behavior in Gradle 9.3.0 to stop searching other repositories when encountering these errors.

- [https://github.com/googlesky/CVE-2026-22865](https://github.com/googlesky/CVE-2026-22865) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-22865.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-22865.svg)


## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.

- [https://github.com/ashrafzaryouh/CVE-2026-22812](https://github.com/ashrafzaryouh/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-22812.svg)


## CVE-2026-22557
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in the UniFi Network Application to access files on the underlying system that could be manipulated to access an underlying account.

- [https://github.com/ashrafzaryouh/CVE-2026-22557](https://github.com/ashrafzaryouh/CVE-2026-22557) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-22557.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-22557.svg)


## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.

- [https://github.com/ashrafzaryouh/CVE-2026-22241](https://github.com/ashrafzaryouh/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-22241.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/ashrafzaryouh/CVE-2026-21962](https://github.com/ashrafzaryouh/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21962.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/ashrafzaryouh/CVE-2026-21858](https://github.com/ashrafzaryouh/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21858.svg)


## CVE-2026-21643
 An improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiClientEMS 7.4.4 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP requests.

- [https://github.com/ashrafzaryouh/CVE-2026-21643](https://github.com/ashrafzaryouh/CVE-2026-21643) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21643.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21643.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/ashrafzaryouh/CVE-2026-21589](https://github.com/ashrafzaryouh/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21589.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/ashrafzaryouh/CVE-2026-20841](https://github.com/ashrafzaryouh/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20841.svg)


## CVE-2026-20320
 This vulnerability exists because XML entries are improperly parsed due to external entity resolution being allowed by default. An attacker could exploit this vulnerability by sending a crafted XML message to the Open Client Interface &ndash; Provisioning (OCI-P) service. A successful exploit could allow the attacker to view sensitive files from the filesystem with the privileges of the Cisco BroadWorks user.

- [https://github.com/cveForge/CVE-2026-20320](https://github.com/cveForge/CVE-2026-20320) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-20320.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-20320.svg)


## CVE-2026-20253
 In Splunk Enterprise 10.2 versions below 10.2.4 and 10 versions below 10.0.7, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. The vulnerability exists because the PostgreSQL sidecar service endpoint lacks authentication controls, allowing any network-reachable user to invoke file operations without credentials. Splunk Enterprise versions 9.4 and earlier are not affected. If you cannot immediately upgrade to a fixed version, you can mitigate this vulnerability by disabling the PostgreSQL sidecar service.

- [https://github.com/ashrafzaryouh/CVE-2026-20253](https://github.com/ashrafzaryouh/CVE-2026-20253) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20253.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20253.svg)


## CVE-2026-20245
Cisco recommends that customers upgrade to the fixed software that is documented in the  that was published on May 14, 2026, and verify the configuration of the edge devices.

- [https://github.com/ashrafzaryouh/CVE-2026-20245](https://github.com/ashrafzaryouh/CVE-2026-20245) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20245.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20245.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/ashrafzaryouh/CVE-2026-20131](https://github.com/ashrafzaryouh/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20131.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/ashrafzaryouh/CVE-2026-20127](https://github.com/ashrafzaryouh/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20127.svg)


## CVE-2026-20079
This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow&nbsp;root access to the device.&nbsp;

- [https://github.com/ashrafzaryouh/CVE-2026-20079](https://github.com/ashrafzaryouh/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20079.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/ashrafzaryouh/CVE-2026-15409](https://github.com/ashrafzaryouh/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-15409.svg)


## CVE-2026-14914
This issue affects Tegsoft Contact Center: before latest-202611161510.

- [https://github.com/cveForge/CVE-2026-14914](https://github.com/cveForge/CVE-2026-14914) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-14914.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-14914.svg)


## CVE-2026-14662
 Integer wraparound in PostgreSQL tsvector and tsquery data type functions allows an unprivileged database user to cause the server to undersize an allocation and write out-of-bounds, via crafted large inputs.  This may execute arbitrary code as the operating system user running the database.  These types are typically sourced from application logic, not taken from the application's user.  Hence, application users attacking the database, through the application as a conduit, are unlikely.  CVE-2026-6473 had fixed similar problems.  Versions before PostgreSQL 18.6, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/cveForge/CVE-2026-14662](https://github.com/cveForge/CVE-2026-14662) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-14662.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-14662.svg)


## CVE-2026-12485
      memcpy(&reply_buf[36], g_network_config-ip_addr, v3);

- [https://github.com/ashrafzaryouh/CVE-2026-12485](https://github.com/ashrafzaryouh/CVE-2026-12485) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-12485.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-12485.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ashrafzaryouh/CVE-2026-11645](https://github.com/ashrafzaryouh/CVE-2026-11645) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-11645.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-11645.svg)


## CVE-2026-11499
 A vulnerability was determined in Tenda HG7, HG9 and HG10 300001138_en_xpon. This affects the function formDOMAINBLK of the file /boaform/formDOMAINBLK. Executing a manipulation of the argument blkDomain can lead to stack-based buffer overflow. The attack may be performed from remote.

- [https://github.com/ashrafzaryouh/CVE-2026-11499](https://github.com/ashrafzaryouh/CVE-2026-11499) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-11499.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-11499.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ashrafzaryouh/CVE-2026-109618](https://github.com/ashrafzaryouh/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-109618.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618](https://github.com/zhaoboy9692/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/ashrafzaryouh/CVE-2026-10520](https://github.com/ashrafzaryouh/CVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-10520.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/ashrafzaryouh/CVE-2026-9082](https://github.com/ashrafzaryouh/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-9082.svg)


## CVE-2026-8932
the private key.

- [https://github.com/ashrafzaryouh/CVE-2026-8932](https://github.com/ashrafzaryouh/CVE-2026-8932) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-8932.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-8932.svg)


## CVE-2026-8461
This issue affects FFmpeg before version 8.1.2.

- [https://github.com/ashrafzaryouh/CVE-2026-8461](https://github.com/ashrafzaryouh/CVE-2026-8461) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-8461.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-8461.svg)


## CVE-2026-8451
 Insufficient input validation in NetScaler ADC and NetScaler Gateway leading to memory overread if NetScaler ADC or NetScaler Gateway is configured as a SAML IDP

- [https://github.com/ashrafzaryouh/CVE-2026-8451](https://github.com/ashrafzaryouh/CVE-2026-8451) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-8451.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-8451.svg)


## CVE-2026-7574
 Anthropic Claude Desktop Cowork VM image handling (confirmed across v1.1348.0 through v1.2278.0, including v1.1348.0, v1.1617.0, and v1.2278.0) validates only file presence and a version marker string before booting rootfs.img, but does not verify image content integrity at time-of-use. A local attacker with unprivileged code execution as the victim macOS user can modify the VM root filesystem image and have it trusted on subsequent Cowork VM boots, enabling persistent arbitrary code execution in the VM and access to host-mounted directories. The estimated CWE mapping is CWE-353 (Missing Support for Integrity Check).

- [https://github.com/ashrafzaryouh/CVE-2026-7574](https://github.com/ashrafzaryouh/CVE-2026-7574) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-7574.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-7574.svg)


## CVE-2026-6471
 Missing authorization in PostgreSQL logical decoding allows a non-superuser holding REPLICATION privilege to dlopen any file visible to the operating system account running the server, via the choice of logical decoding plugin.  This in turn runs arbitrary code as that account.  Versions before PostgreSQL 18.6, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/ashrafzaryouh/CVE-2026-6471](https://github.com/ashrafzaryouh/CVE-2026-6471) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-6471.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-6471.svg)


## CVE-2026-6460
 Type confusion in PostgreSQL allows an object creator to execute arbitrary code as the operating system user running the database, via ALTER ... SET DATA TYPE primarily.  Other DDL attack routes exist, such as "ALTER TABLE ... ADD COLUMN; ROLLBACK; ALTER TABLE ... ADD COLUMN".  The system had inadequate tracking of typed values, and values were not self-identifying.  Stale values could appear in data dictionary entries, PL/pgSQL variables, and many other parts of the system.  PostgreSQL Versions before PostgreSQL 18.7, 17.12, 16.16, 15.20, and 14.25 are affected.

- [https://github.com/gabrielunknown/CVE-2026-6460_PostgreSQL_RCE](https://github.com/gabrielunknown/CVE-2026-6460_PostgreSQL_RCE) :  ![starts](https://img.shields.io/github/stars/gabrielunknown/CVE-2026-6460_PostgreSQL_RCE.svg) ![forks](https://img.shields.io/github/forks/gabrielunknown/CVE-2026-6460_PostgreSQL_RCE.svg)


## CVE-2026-5430
Successful exploitation of this vulnerability may result in unauthorized access to the system, including the potential compromise of administrative accounts and full account takeover. The CVSS score is adjusted to 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) in single-tenant deployments, reflecting that the impact is contained within a single security authority boundary.

- [https://github.com/cveForge/CVE-2026-5430](https://github.com/cveForge/CVE-2026-5430) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-5430.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-5430.svg)


## CVE-2026-5173
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 16.9.6 before 18.8.9, 18.9 before 18.9.5, and 18.10 before 18.10.3 that could have allowed an authenticated user to invoke unintended server-side methods through websocket connections due to improper access control.

- [https://github.com/ashrafzaryouh/CVE-2026-5173](https://github.com/ashrafzaryouh/CVE-2026-5173) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-5173.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-5173.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/ashrafzaryouh/CVE-2026-5027](https://github.com/ashrafzaryouh/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-5027.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/ashrafzaryouh/CVE-2026-4480](https://github.com/ashrafzaryouh/CVE-2026-4480) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-4480.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-4480.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2026-3055
 Insufficient input validation in NetScaler ADC and NetScaler Gateway when configured as a SAML IDP leading to memory overread

- [https://github.com/ashrafzaryouh/CVE-2026-3055](https://github.com/ashrafzaryouh/CVE-2026-3055) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-3055.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-3055.svg)


## CVE-2026-2699
 Customer Managed ShareFile Storage Zones Controller (SZC) allows an unauthenticated attacker to access restricted configuration pages. This leads to changing system configuration and potential remote code execution.

- [https://github.com/ashrafzaryouh/CVE-2026-2699](https://github.com/ashrafzaryouh/CVE-2026-2699) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-2699.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-2699.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/ashrafzaryouh/CVE-2026-1357](https://github.com/ashrafzaryouh/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-1357.svg)


## CVE-2026-1300
 The Responsive Header plugin for WordPress is vulnerable to Stored Cross-Site Scripting via multiple plugin settings parameters in all versions up to, and including, 1.0 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/cveForge/CVE-2026-130001](https://github.com/cveForge/CVE-2026-130001) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-130001.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-130001.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/ashrafzaryouh/CVE-2026-0770](https://github.com/ashrafzaryouh/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0770.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/ashrafzaryouh/CVE-2026-0300](https://github.com/ashrafzaryouh/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0300.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/ashrafzaryouh/CVE-2026-0257](https://github.com/ashrafzaryouh/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0257.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/ashrafzaryouh/CVE-2026-0073](https://github.com/ashrafzaryouh/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0073.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/ashrafzaryouh/CVE-2025-68645](https://github.com/ashrafzaryouh/CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/ashrafzaryouh/CVE-2025-64446](https://github.com/ashrafzaryouh/CVE-2025-64446) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-64446.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-64446.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/ashrafzaryouh/CVE-2025-49844](https://github.com/ashrafzaryouh/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-49844.svg)


## CVE-2025-42884
 SAP NetWeaver Enterprise Portal allows an unauthenticated attacker to inject JNDI environment properties or pass a URL used during JNDI lookup operations, enabling access to an unintended JNDI provider.�This could further lead to disclosure or modification of information about the server. There is no impact on availability.

- [https://github.com/cveForge/CVE-2025-42884](https://github.com/cveForge/CVE-2025-42884) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2025-42884.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2025-42884.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/ashrafzaryouh/CVE-2025-32463](https://github.com/ashrafzaryouh/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/ashrafzaryouh/CVE-2025-32433](https://github.com/ashrafzaryouh/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-32433.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ashrafzaryouh/CVE-2025-31161](https://github.com/ashrafzaryouh/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-31161.svg)


## CVE-2025-31133
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack:  an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/cveForge/CVE-2025-31133](https://github.com/cveForge/CVE-2025-31133) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2025-31133.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2025-31133.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/xianwan1314/cheese-app](https://github.com/xianwan1314/cheese-app) :  ![starts](https://img.shields.io/github/stars/xianwan1314/cheese-app.svg) ![forks](https://img.shields.io/github/forks/xianwan1314/cheese-app.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/ashrafzaryouh/CVE-2025-14847](https://github.com/ashrafzaryouh/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-14847.svg)


## CVE-2025-13315
 Twonky Server 8.5.2 on Linux and Windows is vulnerable to an access control flaw. An unauthenticated attacker can bypass web service API authentication controls to leak a log file and read the administrator's username and encrypted password.

- [https://github.com/ashrafzaryouh/CVE-2025-13315](https://github.com/ashrafzaryouh/CVE-2025-13315) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-13315.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-13315.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/ashrafzaryouh/CVE-2025-5777](https://github.com/ashrafzaryouh/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-5777.svg)


## CVE-2024-10441
 Improper encoding or escaping of output vulnerability in the system plugin daemon in Synology BeeStation OS (BSM) before 1.1-65374 and Synology DiskStation Manager (DSM) before 7.2-64570-4, 7.2.1-69057-6 and 7.2.2-72806-1 allows remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/cveForge/CVE-2024-10441](https://github.com/cveForge/CVE-2024-10441) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2024-10441.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2024-10441.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/ashrafzaryouh/CVE-2024-3094](https://github.com/ashrafzaryouh/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2024-3094.svg)


## CVE-2023-54391
 Proxmox Virtual Environment (VE) 7.0 through 8.0 contains an authentication bypass vulnerability in libpve-access-control before 8.0.4 that allows unauthenticated attackers to authenticate as any existing enabled user without a configured second factor by supplying an arbitrary tfa-challenge value in the API login endpoint. Attackers can send a POST request to the access ticket API endpoint with any value in the tfa-challenge parameter to completely skip password verification, gaining unauthorized access including to the root@pam account. All affected releases are end of life.

- [https://github.com/a0www/CVE-2023-54391-RCE](https://github.com/a0www/CVE-2023-54391-RCE) :  ![starts](https://img.shields.io/github/stars/a0www/CVE-2023-54391-RCE.svg) ![forks](https://img.shields.io/github/forks/a0www/CVE-2023-54391-RCE.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/Chanakya-GH/re-portfolio](https://github.com/Chanakya-GH/re-portfolio) :  ![starts](https://img.shields.io/github/stars/Chanakya-GH/re-portfolio.svg) ![forks](https://img.shields.io/github/forks/Chanakya-GH/re-portfolio.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/TaTrap/Pixel4XL_GPU_TempRoot](https://github.com/TaTrap/Pixel4XL_GPU_TempRoot) :  ![starts](https://img.shields.io/github/stars/TaTrap/Pixel4XL_GPU_TempRoot.svg) ![forks](https://img.shields.io/github/forks/TaTrap/Pixel4XL_GPU_TempRoot.svg)


## CVE-2023-24329
 An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.

- [https://github.com/GotUrBack-Public/CVE-2023-24329](https://github.com/GotUrBack-Public/CVE-2023-24329) :  ![starts](https://img.shields.io/github/stars/GotUrBack-Public/CVE-2023-24329.svg) ![forks](https://img.shields.io/github/forks/GotUrBack-Public/CVE-2023-24329.svg)


## CVE-2022-24905
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. A vulnerability was found in Argo CD prior to versions 2.3.4, 2.2.9, and 2.1.15 that allows an attacker to spoof error messages on the login screen when single sign on (SSO) is enabled. In order to exploit this vulnerability, an attacker would have to trick the victim to visit a specially crafted URL which contains the message to be displayed. As far as the research of the Argo CD team concluded, it is not possible to specify any active content (e.g. Javascript) or other HTML fragments (e.g. clickable links) in the spoofed message. A patch for this vulnerability has been released in Argo CD versions 2.3.4, 2.2.9, and 2.1.15. There are currently no known workarounds.

- [https://github.com/googlesky/CVE-2022-24905](https://github.com/googlesky/CVE-2022-24905) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-24905.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-24905.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/ashrafzaryouh/CVE-2022-22965](https://github.com/ashrafzaryouh/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2022-22965.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)
- [https://github.com/R3leant/CVE-2021-41773](https://github.com/R3leant/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/R3leant/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/R3leant/CVE-2021-41773.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/ashrafzaryouh/CVE-2020-17103](https://github.com/ashrafzaryouh/CVE-2020-17103) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2020-17103.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2020-17103.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/ashrafzaryouh/CVE-2020-5902](https://github.com/ashrafzaryouh/CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2020-5902.svg)


## CVE-2020-2026
 A malicious guest compromised before a container creation (e.g. a malicious guest image or a guest running multiple containers) can trick the kata runtime into mounting the untrusted container filesystem on any host path, potentially allowing for code execution on the host. This issue affects: Kata Containers 1.11 versions earlier than 1.11.1; Kata Containers 1.10 versions earlier than 1.10.5; Kata Containers 1.9 and earlier versions.

- [https://github.com/vinniboy021-blip/PEagle](https://github.com/vinniboy021-blip/PEagle) :  ![starts](https://img.shields.io/github/stars/vinniboy021-blip/PEagle.svg) ![forks](https://img.shields.io/github/forks/vinniboy021-blip/PEagle.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/fantasmakm4/LAB-014-SIMPLE-CTF](https://github.com/fantasmakm4/LAB-014-SIMPLE-CTF) :  ![starts](https://img.shields.io/github/stars/fantasmakm4/LAB-014-SIMPLE-CTF.svg) ![forks](https://img.shields.io/github/forks/fantasmakm4/LAB-014-SIMPLE-CTF.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/Swcct553/shv34-root](https://github.com/Swcct553/shv34-root) :  ![starts](https://img.shields.io/github/stars/Swcct553/shv34-root.svg) ![forks](https://img.shields.io/github/forks/Swcct553/shv34-root.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/ashrafzaryouh/CVE-2017-0144](https://github.com/ashrafzaryouh/CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2017-0144.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/cveForge/CVE-2015-3306](https://github.com/cveForge/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2015-3306.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/ashrafzaryouh/CVE-2014-6271](https://github.com/ashrafzaryouh/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2014-6271.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/ashrafzaryouh/CVE-2014-0160](https://github.com/ashrafzaryouh/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2014-0160.svg)


## CVE-2013-7372
 The engineNextBytes function in classlib/modules/security/src/main/java/common/org/apache/harmony/security/provider/crypto/SHA1PRNG_SecureRandomImpl.java in the SecureRandom implementation in Apache Harmony through 6.0M3, as used in the Java Cryptography Architecture (JCA) in Android before 4.4 and other products, when no seed is provided by the user, uses an incorrect offset value, which makes it easier for attackers to defeat cryptographic protection mechanisms by leveraging the resulting PRNG predictability, as exploited in the wild against Bitcoin wallet applications in August 2013.

- [https://github.com/alapan-porel/ecdsa-nonce-bias-research](https://github.com/alapan-porel/ecdsa-nonce-bias-research) :  ![starts](https://img.shields.io/github/stars/alapan-porel/ecdsa-nonce-bias-research.svg) ![forks](https://img.shields.io/github/forks/alapan-porel/ecdsa-nonce-bias-research.svg)

