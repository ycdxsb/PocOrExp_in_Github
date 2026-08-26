# Update 2026-08-26
## CVE-2026-78329
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.4. For deployments that cannot upgrade immediately, configure the strategy explicitly rather than relying on the default, for example by binding an UndertowHeaderFilterStrategy in the registry and referencing it on the endpoint as undertow:http://0.0.0.0:8080/foo?headerFilterStrategy=#myStrategy, and additionally strip the dispatch headers at the trust boundary with removeHeaders(“websocket.*”). Note a residual limitation that upgrading does not remove: the undertow component deliberately keeps the websocket. values as part of its externally visible API contract, and UndertowProducer reads them with in.getHeader, which does not consult a HeaderFilterStrategy at all. The restored filtering is therefore defence in depth at the undertow transport boundary only. A route that carries an untrusted message from a non-undertow consumer into an undertow producer is not protected by this fix and must strip those headers itself.

- [https://github.com/oscerd/CVE-2026-78329](https://github.com/oscerd/CVE-2026-78329) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78329.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78329.svg)


## CVE-2026-77806
 SPIP before 4.4.21 allows unauthenticated remote attackers to execute arbitrary code, as exploited in the wild in August 2026. This is related to code injection via an X-Spip-Filtre HTTP request header that is mishandled by analyse_resultat_skel.

- [https://github.com/CuteeCat/CVE-2026-77806](https://github.com/CuteeCat/CVE-2026-77806) :  ![starts](https://img.shields.io/github/stars/CuteeCat/CVE-2026-77806.svg) ![forks](https://img.shields.io/github/forks/CuteeCat/CVE-2026-77806.svg)


## CVE-2026-76071
 Netis NC63 firmware through V3.0.0.3327 contains a stack-based buffer overflow vulnerability that allows unauthenticated remote attackers to overwrite saved stack state by supplying an oversized destHost parameter to the ipFilterList=mod action in netis.cgi. Attackers can exploit widthless sscanf conversions that copy user-supplied input into fixed-size stack buffers before authentication is verified, achieving remote code execution as root due to the Boa web server executing the CGI environment with root privileges.

- [https://github.com/ozcanpng/CVE-2026-76071](https://github.com/ozcanpng/CVE-2026-76071) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-76071.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-76071.svg)


## CVE-2026-76070
 Netis NC63 firmware through V3.0.0.3327 contains a stack-based buffer overflow vulnerability that allows unauthenticated remote attackers to overwrite saved stack state by submitting an oversized Base64-encoded password to the login handler in /bin/netis.cgi. Attackers can exploit the custom Base64 decoder's lack of output length validation against the fixed-size stack buffer to achieve remote code execution with root privileges, as the Boa web server executes the CGI environment as root.

- [https://github.com/ozcanpng/CVE-2026-76070](https://github.com/ozcanpng/CVE-2026-76070) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-76070.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-76070.svg)


## CVE-2026-74939
 Privilege escalation in the DOM: Navigation component. This vulnerability was fixed in Firefox 154, Firefox ESR 115.39, Firefox ESR 140.14, Firefox ESR 153.1, Thunderbird 154, Thunderbird 140.14, and Thunderbird 153.1.

- [https://github.com/SneakyNachos/CVE-2026-74939-escape-the-mac-n-cheese-box](https://github.com/SneakyNachos/CVE-2026-74939-escape-the-mac-n-cheese-box) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-74939-escape-the-mac-n-cheese-box.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-74939-escape-the-mac-n-cheese-box.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/BiuTrap/CVE-2026-73570](https://github.com/BiuTrap/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/BiuTrap/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/BiuTrap/CVE-2026-73570.svg)


## CVE-2026-71300
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.4. For deployments that cannot upgrade immediately, strip the dispatch headers at the trust boundary before the producer, for example with removeHeaders(“websocket.*”) placed between the HTTP consumer and the atmosphere-websocket producer. Note that the fix renames the header string values into the Camel namespace, which is a breaking change for routes that set them by literal string: routes referencing the WebsocketConstants fields symbolically are unaffected, and the change is documented in the upgrade guides. As defence in depth, do not bridge an untrusted HTTP consumer directly into a WebSocket producer whose dispatch is header-driven without stripping the dispatch namespace first.

- [https://github.com/oscerd/CVE-2026-71300](https://github.com/oscerd/CVE-2026-71300) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-71300.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-71300.svg)


## CVE-2026-68820
 Use after free in Windows Ancillary Function Driver for WinSock allows an authorized attacker to elevate privileges locally.

- [https://github.com/fevar54/CVE-2026-68820-Mitigation-PoC-](https://github.com/fevar54/CVE-2026-68820-Mitigation-PoC-) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-68820-Mitigation-PoC-.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-68820-Mitigation-PoC-.svg)


## CVE-2026-66908
The fail-closed guard could not be backported. The jwtIssuer and jwtAudience options were themselves only introduced in 4.21.0 by CAMEL-23525, so on camel-4.18.x and camel-4.14.x there was nothing an operator could set to satisfy the requirement and the guard would have broken every JWT deployment on those branches with no remedy available.

- [https://github.com/oscerd/CVE-2026-66908](https://github.com/oscerd/CVE-2026-66908) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-66908.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-66908.svg)


## CVE-2026-66907
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.4. For deployments that cannot upgrade immediately, set the filter option to a regular expression that accepts only simple single-segment object names, so that any name carrying a path separator or a parent-directory segment is excluded before an exchange is created; note that no filtering whatsoever is applied when the option is left unset, and that the expression is matched against the whole object name. Alternatively, give downloadFileName an explicit expression that does not carry the remote path through, for example one built on ${file:onlyname} rather than the implicit ${file:name}, keeping in mind that a downloadFileName containing an expression is treated as route-author-controlled and is not covered by the containment check added in the fix. As defence in depth, treat the object names in any externally writable bucket as untrusted input and do not derive local filesystem paths from them.

- [https://github.com/oscerd/CVE-2026-66907](https://github.com/oscerd/CVE-2026-66907) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-66907.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-66907.svg)


## CVE-2026-66906
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.4. For deployments that cannot upgrade immediately, constrain the names the consumer will act on using the regex endpoint option, which is applied to each listed blob name as a full-string match, so that only simple single-segment names are accepted and any name carrying a path separator or a parent-directory segment is filtered out before an exchange is created; the prefix option can additionally narrow the listing server-side, noting that when both are set regex takes priority and prefix is ignored. Alternatively, avoid the downloadBlobToFile operation on untrusted containers and write the payload from the route under a file name the route itself controls, rather than one taken from the remote listing. As defence in depth, treat the blob names in any externally writable container as untrusted input and do not derive local filesystem paths from them.

- [https://github.com/oscerd/CVE-2026-66906](https://github.com/oscerd/CVE-2026-66906) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-66906.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-66906.svg)


## CVE-2026-63621
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.18.x LTS releases stream, then they are suggested to upgrade to 4.18.4. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. The non-LTS releases 4.15.0 through 4.17.0 and 4.19.0 through 4.21.0 are affected but do not receive a maintenance fix; users on those versions should upgrade to 4.18.4 or 4.22.0.

- [https://github.com/oscerd/CVE-2026-63621](https://github.com/oscerd/CVE-2026-63621) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-63621.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-63621.svg)


## CVE-2026-63039
[1]  https://github.com/apache/inlong/pull/12080 .

- [https://github.com/oscerd/CVE-2026-63039](https://github.com/oscerd/CVE-2026-63039) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-63039.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-63039.svg)


## CVE-2026-60093
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.4. For deployments that cannot upgrade immediately, constrain the names the consumer will act on using the regex endpoint option, which is applied to each listed path name as a full-string match, so that only simple single-segment names are accepted and any name carrying a path separator or a parent-directory segment is filtered out before an exchange is created. Alternatively, avoid the downloadToFile operation on untrusted filesystems and write the payload from the route under a file name the route itself controls, rather than one taken from the remote listing. As defence in depth, treat the object names in any externally writable Data Lake filesystem as untrusted input and do not derive local filesystem paths from them.

- [https://github.com/oscerd/CVE-2026-60093](https://github.com/oscerd/CVE-2026-60093) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-60093.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-60093.svg)


## CVE-2026-59230
Users are recommended to upgrade to version 4.22.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.9. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.4. For deployments that cannot upgrade immediately, leave headersInline at its default of false where the inline headers are not needed, since the copy is only reached when it is enabled. Where it must stay enabled, strip Camel-internal headers immediately after the unmarshal step, for example with removeHeaders(“Camel*”) placed before any processor or producer that reads control headers, and do not unmarshal MIME content from an untrusted sender into a route that dispatches on header values. As defence in depth, treat the header names of any MIME message arriving from outside the trust boundary as untrusted input.

- [https://github.com/oscerd/CVE-2026-59230](https://github.com/oscerd/CVE-2026-59230) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-59230.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-59230.svg)


## CVE-2026-43914
 Vaultwarden is a Bitwarden-compatible server written in Rust. Prior to 1.35.4, there is a security vulnerability in Vaultwarden that allows bypassing the login brute-force protection if email 2fa is enabled. If email 2fa is enabled, the unprotected 2fa-function send_email_login (email.rs, api endpoint /api/two-factor/send-email-login) also acts as an oracle determining whether a username-password combination is correct. An attacker can abuse that endpoint to brute-force passwords without rate-limiting. This works even for users who don't have email 2fa configured. This vulnerability is fixed in 1.35.4.

- [https://github.com/Boreas37/CVE-2026-43914-PoC](https://github.com/Boreas37/CVE-2026-43914-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-43914-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-43914-PoC.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ankitrawatgit/iQOO-Z9_5G-vivo-T3_5G-Root-GhostLock](https://github.com/ankitrawatgit/iQOO-Z9_5G-vivo-T3_5G-Root-GhostLock) :  ![starts](https://img.shields.io/github/stars/ankitrawatgit/iQOO-Z9_5G-vivo-T3_5G-Root-GhostLock.svg) ![forks](https://img.shields.io/github/forks/ankitrawatgit/iQOO-Z9_5G-vivo-T3_5G-Root-GhostLock.svg)
- [https://github.com/Redminote11tech/CVE-2026-43499-NAM-AL00](https://github.com/Redminote11tech/CVE-2026-43499-NAM-AL00) :  ![starts](https://img.shields.io/github/stars/Redminote11tech/CVE-2026-43499-NAM-AL00.svg) ![forks](https://img.shields.io/github/forks/Redminote11tech/CVE-2026-43499-NAM-AL00.svg)
- [https://github.com/XiaoBaiLovesStirring/ghostlock-k419-adapter](https://github.com/XiaoBaiLovesStirring/ghostlock-k419-adapter) :  ![starts](https://img.shields.io/github/stars/XiaoBaiLovesStirring/ghostlock-k419-adapter.svg) ![forks](https://img.shields.io/github/forks/XiaoBaiLovesStirring/ghostlock-k419-adapter.svg)


## CVE-2026-28672
This issue affects Apache Ranger: from 0.6 through 2.8.

- [https://github.com/oscerd/CVE-2026-28672](https://github.com/oscerd/CVE-2026-28672) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-28672.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-28672.svg)


## CVE-2026-28001
 Unauthenticated SQL Injection in WP Directory Kit = 1.5.4 versions.

- [https://github.com/gduma-phData/patch-CVE-2026-28001](https://github.com/gduma-phData/patch-CVE-2026-28001) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-28001.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-28001.svg)


## CVE-2026-22024
 CryptoLib provides a software-only solution using the CCSDS Space Data Link Security Protocol - Extended Procedures (SDLS-EP) to secure communications between a spacecraft running the core Flight System (cFS) and a ground station. Prior to version 1.4.3, the cryptography_encrypt() function allocates multiple buffers for HTTP requests and JSON parsing that are never freed on any code path. Each call leaks approximately 400 bytes of memory. Sustained traffic can gradually exhaust available memory. This issue has been patched in version 1.4.3.

- [https://github.com/gduma-phData/patch-CVE-2026-22024](https://github.com/gduma-phData/patch-CVE-2026-22024) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-22024.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-22024.svg)


## CVE-2026-19874
 A heap-based buffer overflow vulnerability exists in Konami's Metal Gear Online 3, originating from improper validation of lobby data fields related to kicked players. The affected function processes a list of kicked player identifiers using the lobby data key "kick_num" to determine the number of entries, and individual kicked player IDs supplied via keys in the format "kicked_id_%i". The function does not validate that "kick_num" falls within the expected bounds. The game design limits matches to a maximum of 16 players, and the corresponding buffer for storing kicked player IDs is sized accordingly. If "kick_num" exceeds this limit, the function continues writing the provided player IDs past the end of the intended buffer and into adjacent memory regions. These adjacent regions contain Steam callback handler structures responsible for processing lobby data updates, lobby messages, and other related events. By supplying an oversized "kick_num" value and appropriate "kicked_id_%i" fields, an attacker can overwrite fields within the callback handler structures, including function pointers and callback argument values. Successful exploitation may enable control-flow hijacking, potentially allowing arbitrary code execution within the game process.

- [https://github.com/alicealys/mgo3-rce](https://github.com/alicealys/mgo3-rce) :  ![starts](https://img.shields.io/github/stars/alicealys/mgo3-rce.svg) ![forks](https://img.shields.io/github/forks/alicealys/mgo3-rce.svg)


## CVE-2026-19681
 An authenticated command injection vulnerability exists in Security Center related to file upload processing. An attacker could exploit this issue by uploading a specially crafted file, potentially resulting in arbitrary command execution on the underlying operating system.

- [https://github.com/h00die/POC-CVE-2026-19681](https://github.com/h00die/POC-CVE-2026-19681) :  ![starts](https://img.shields.io/github/stars/h00die/POC-CVE-2026-19681.svg) ![forks](https://img.shields.io/github/forks/h00die/POC-CVE-2026-19681.svg)


## CVE-2026-19679
 An input validation vulnerability exists in Security Center's file upload handling, where insufficient sanitization of uploaded filenames could contribute to a downstream command injection issue.

- [https://github.com/h00die/POC-CVE-2026-19679](https://github.com/h00die/POC-CVE-2026-19679) :  ![starts](https://img.shields.io/github/stars/h00die/POC-CVE-2026-19679.svg) ![forks](https://img.shields.io/github/forks/h00die/POC-CVE-2026-19679.svg)


## CVE-2026-19626
 A remote code execution vulnerability exists in Tenable Security Center's report generation functionality. An authenticated, non-administrative user could exploit this issue by supplying specially crafted input that is later processed unsafely during server-side report rendering, resulting in arbitrary code execution with the privileges of the service account.

- [https://github.com/h00die/POC-CVE-2026-19626](https://github.com/h00die/POC-CVE-2026-19626) :  ![starts](https://img.shields.io/github/stars/h00die/POC-CVE-2026-19626.svg) ![forks](https://img.shields.io/github/forks/h00die/POC-CVE-2026-19626.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/Snizi/CVE-2026-18963-Exploit](https://github.com/Snizi/CVE-2026-18963-Exploit) :  ![starts](https://img.shields.io/github/stars/Snizi/CVE-2026-18963-Exploit.svg) ![forks](https://img.shields.io/github/forks/Snizi/CVE-2026-18963-Exploit.svg)
- [https://github.com/Red-Darkin/CVE-2026-18963-keycloak](https://github.com/Red-Darkin/CVE-2026-18963-keycloak) :  ![starts](https://img.shields.io/github/stars/Red-Darkin/CVE-2026-18963-keycloak.svg) ![forks](https://img.shields.io/github/forks/Red-Darkin/CVE-2026-18963-keycloak.svg)
- [https://github.com/minh3102011/CVE-2026-18963_analyst](https://github.com/minh3102011/CVE-2026-18963_analyst) :  ![starts](https://img.shields.io/github/stars/minh3102011/CVE-2026-18963_analyst.svg) ![forks](https://img.shields.io/github/forks/minh3102011/CVE-2026-18963_analyst.svg)
- [https://github.com/T0w0T/POC-CVE-2026-18963](https://github.com/T0w0T/POC-CVE-2026-18963) :  ![starts](https://img.shields.io/github/stars/T0w0T/POC-CVE-2026-18963.svg) ![forks](https://img.shields.io/github/forks/T0w0T/POC-CVE-2026-18963.svg)


## CVE-2026-15502
 A vulnerability was detected in AojiaoZero Antaris 1.0. This affects the function _rewardPurchase of the file /ipn.php of the component PayPal IPN Payment Handler. The manipulation of the argument item_number results in sql injection. The attack may be performed from remote. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/gduma-phData/patch-CVE-2026-15502](https://github.com/gduma-phData/patch-CVE-2026-15502) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-15502.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-15502.svg)


## CVE-2026-14290
 The Embed Google Photos album WordPress plugin through 2.2.1 does not escape a shortcode attribute value before outputting it inside an HTML attribute, allowing users with the Contributor role or above to inject arbitrary JavaScript that executes in the browser of any user, including administrators, who views the affected post.

- [https://github.com/gduma-phData/patch-CVE-2026-14290](https://github.com/gduma-phData/patch-CVE-2026-14290) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-14290.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-14290.svg)


## CVE-2026-12087
Calling pack_ip_mreq_source() with a source value shorter than 4 bytes copies adjacent heap memory into the returned packed structure.

- [https://github.com/gduma-phData/patch-CVE-2026-12087](https://github.com/gduma-phData/patch-CVE-2026-12087) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-12087.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-12087.svg)


## CVE-2026-11553
 A vulnerability was found in Tenda HG7HG9 and HG10 300001138_en_xpon. This affects the function formPPPEdit of the file /boaform/formPPPEdit. The manipulation of the argument encodename results in stack-based buffer overflow. The attack can be launched remotely. The exploit has been made public and could be used.

- [https://github.com/gduma-phData/patch-CVE-2026-11553](https://github.com/gduma-phData/patch-CVE-2026-11553) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-11553.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-11553.svg)


## CVE-2026-10523
 An Authentication Bypass vulnerability (CWE-288) in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated attacker to create arbitrary administrative accounts and obtain full administrative access

- [https://github.com/imbas007/RCE-CVE-2026-10520-CVE-2026-10523](https://github.com/imbas007/RCE-CVE-2026-10520-CVE-2026-10523) :  ![starts](https://img.shields.io/github/stars/imbas007/RCE-CVE-2026-10520-CVE-2026-10523.svg) ![forks](https://img.shields.io/github/forks/imbas007/RCE-CVE-2026-10520-CVE-2026-10523.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/gduma-phData/patch-CVE-2026-10520](https://github.com/gduma-phData/patch-CVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-10520.svg)
- [https://github.com/imbas007/RCE-CVE-2026-10520-CVE-2026-10523](https://github.com/imbas007/RCE-CVE-2026-10520-CVE-2026-10523) :  ![starts](https://img.shields.io/github/stars/imbas007/RCE-CVE-2026-10520-CVE-2026-10523.svg) ![forks](https://img.shields.io/github/forks/imbas007/RCE-CVE-2026-10520-CVE-2026-10523.svg)


## CVE-2026-9254
Successful exploitation may result in complete device compromise and impact the confidentiality, integrity, and availability of the affected device and network traffic.

- [https://github.com/Slagzz/CVE-2026-9254](https://github.com/Slagzz/CVE-2026-9254) :  ![starts](https://img.shields.io/github/stars/Slagzz/CVE-2026-9254.svg) ![forks](https://img.shields.io/github/forks/Slagzz/CVE-2026-9254.svg)


## CVE-2026-3133
 A vulnerability has been found in itsourcecode Document Management System 1.0. This issue affects some unknown processing of the file /loging.php of the component Login. The manipulation of the argument Username leads to sql injection. Remote exploitation of the attack is possible. The exploit has been disclosed to the public and may be used.

- [https://github.com/gduma-phData/patch-CVE-2026-31337](https://github.com/gduma-phData/patch-CVE-2026-31337) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-31337.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-31337.svg)


## CVE-2026-0988
 A flaw was found in glib. Missing validation of offset and count parameters in the g_buffered_input_stream_peek() function can lead to an integer overflow during length calculation. When specially crafted values are provided, this overflow results in an incorrect size being passed to memcpy(), triggering a buffer overflow. This can cause application crashes, leading to a Denial of Service (DoS).

- [https://github.com/gduma-phData/patch-CVE-2026-09881](https://github.com/gduma-phData/patch-CVE-2026-09881) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-09881.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-09881.svg)


## CVE-2026-0874
 A maliciously crafted CATPART file, when parsed through certain Autodesk products, can force an Out-of-Bounds Write vulnerability. A malicious actor may leverage this vulnerability to cause a crash, cause data corruption, or execute arbitrary code in the context of the current process.

- [https://github.com/gduma-phData/patch-CVE-2026-08742](https://github.com/gduma-phData/patch-CVE-2026-08742) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-08742.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-08742.svg)


## CVE-2026-0655
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in TP-Link Deco BE25 v1.0 (web modules) allows authenticated adjacent attacker to read arbitrary files or cause denial of service.  This issue affects Deco BE25 v1.0: through 1.1.1 Build 20250822.

- [https://github.com/gduma-phData/patch-CVE-2026-06555](https://github.com/gduma-phData/patch-CVE-2026-06555) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-06555.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-06555.svg)


## CVE-2026-0589
 A vulnerability was found in code-projects Online Product Reservation System 1.0. Impacted is an unknown function of the component Administration Backend. The manipulation results in improper authentication. The attack may be performed from remote. The exploit has been made public and could be used.

- [https://github.com/gduma-phData/patch-CVE-2026-05890](https://github.com/gduma-phData/patch-CVE-2026-05890) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-05890.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-05890.svg)


## CVE-2026-0432
 Incorrect default permissions in the installation directory for the AMD chipset driver could allow an attacker to achieve privilege escalation resulting in arbitrary code execution.

- [https://github.com/gduma-phData/patch-CVE-2026-04321](https://github.com/gduma-phData/patch-CVE-2026-04321) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-04321.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-04321.svg)


## CVE-2026-0277
The Prisma Access Agent on Windows, macOS, Linux, Android and ChromeOS are not affected.

- [https://github.com/gduma-phData/patch-CVE-2026-02777](https://github.com/gduma-phData/patch-CVE-2026-02777) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-02777.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-02777.svg)


## CVE-2026-0144
 In writeAocCommand of AocAudioCodec.cpp, there is a possible memory safety issue due to a missing bounds check. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/gduma-phData/patch-CVE-2026-01443](https://github.com/gduma-phData/patch-CVE-2026-01443) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-01443.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-01443.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)


## CVE-2025-48595
 In multiple locations, there is a possible way to achieve code execution due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/XiaoBaiLovesStirring/CVE-2025-48595-Exploit](https://github.com/XiaoBaiLovesStirring/CVE-2025-48595-Exploit) :  ![starts](https://img.shields.io/github/stars/XiaoBaiLovesStirring/CVE-2025-48595-Exploit.svg) ![forks](https://img.shields.io/github/forks/XiaoBaiLovesStirring/CVE-2025-48595-Exploit.svg)


## CVE-2025-47029
 Adobe Experience Manager versions 6.5.22 and earlier are affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by a low privileged attacker to inject malicious scripts into vulnerable form fields. Malicious JavaScript may be executed in a victim’s browser when they browse to the page containing the vulnerable field.

- [https://github.com/gduma-phData/patch-CVE-2025-47029](https://github.com/gduma-phData/patch-CVE-2025-47029) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-47029.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-47029.svg)


## CVE-2025-46359
 A path traversal issue exists in backup and restore feature of multiple versions of PowerCMS. A product administrator may execute arbitrary code by restoring a crafted backup file.

- [https://github.com/samarthop2011/PoC-for-CVE-2025-46359](https://github.com/samarthop2011/PoC-for-CVE-2025-46359) :  ![starts](https://img.shields.io/github/stars/samarthop2011/PoC-for-CVE-2025-46359.svg) ![forks](https://img.shields.io/github/forks/samarthop2011/PoC-for-CVE-2025-46359.svg)


## CVE-2025-40123
these situations are not prone to this issue.

- [https://github.com/gduma-phData/patch-CVE-2025-40123](https://github.com/gduma-phData/patch-CVE-2025-40123) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-40123.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-40123.svg)


## CVE-2025-36001
 IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) 11.5.0 - 11.5.9 and 12.1.0 - 12.1.3 could allow an authenticated user to cause a denial of service using a specially crafted SQL statement including XML that performs uncontrolled recursion.

- [https://github.com/gduma-phData/patch-CVE-2025-36001](https://github.com/gduma-phData/patch-CVE-2025-36001) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-36001.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-36001.svg)


## CVE-2025-34555
 This CVE ID was rejected because it was reserved but not used for a vulnerability disclosure.

- [https://github.com/gduma-phData/patch-CVE-2025-34555](https://github.com/gduma-phData/patch-CVE-2025-34555) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-34555.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-34555.svg)


## CVE-2025-33210
 NVIDIA Isaac Lab contains a deserialization vulnerability.  A successful exploit of this vulnerability might lead to code execution.

- [https://github.com/gduma-phData/patch-CVE-2025-33210](https://github.com/gduma-phData/patch-CVE-2025-33210) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-33210.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-33210.svg)


## CVE-2025-32953
 z80pack is a mature emulator of multiple platforms with 8080 and Z80 CPU. In version 1.38 and prior, the `makefile-ubuntu.yml` workflow file uses `actions/upload-artifact@v4` to upload the `z80pack-ubuntu` artifact. This artifact is a zip of the current directory, which includes the automatically generated `.git/config` file containing the run's GITHUB_TOKEN. Seeing as the artifact can be downloaded prior to the end of the workflow, there is a few seconds where an attacker can extract the token from the artifact and use it with the Github API to push malicious code or rewrite release commits in your repository. This issue has been fixed in commit bd95916.

- [https://github.com/pvharmo2/gha-lab-5ed08d6a80](https://github.com/pvharmo2/gha-lab-5ed08d6a80) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-5ed08d6a80.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-5ed08d6a80.svg)


## CVE-2025-31800
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in publitio Publitio publitio allows Path Traversal.This issue affects Publitio: from n/a through = 2.2.0.

- [https://github.com/gduma-phData/patch-CVE-2025-31800](https://github.com/gduma-phData/patch-CVE-2025-31800) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-31800.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-31800.svg)


## CVE-2025-30456
 A parsing issue in the handling of directory paths was addressed with improved path validation. This issue is fixed in iOS 18.4 and iPadOS 18.4, macOS Sequoia 15.4, macOS Sonoma 14.7.5, macOS Ventura 13.7.5. An app may be able to gain root privileges.

- [https://github.com/gduma-phData/patch-CVE-2025-30456](https://github.com/gduma-phData/patch-CVE-2025-30456) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-30456.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-30456.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)
- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-26543
 Cross-Site Request Forgery (CSRF) vulnerability in Pukhraj Suthar Simple Responsive Menu simple-responsive-menu allows Stored XSS.This issue affects Simple Responsive Menu: from n/a through = 2.1.

- [https://github.com/gduma-phData/patch-CVE-2025-26543](https://github.com/gduma-phData/patch-CVE-2025-26543) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-26543.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-26543.svg)


## CVE-2025-25200
 Koa is expressive middleware for Node.js using ES2017 async functions. Prior to versions 0.21.2, 1.7.1, 2.15.4, and 3.0.0-alpha.3, Koa uses an evil regex to parse the `X-Forwarded-Proto` and `X-Forwarded-Host` HTTP headers. This can be exploited to carry out a Denial-of-Service attack. Versions 0.21.2, 1.7.1, 2.15.4, and 3.0.0-alpha.3 fix the issue.

- [https://github.com/gduma-phData/patch-CVE-2025-25200](https://github.com/gduma-phData/patch-CVE-2025-25200) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-25200.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-25200.svg)


## CVE-2025-24001
 Cross-Site Request Forgery (CSRF) vulnerability in Ngô Thắng IT PPO Call To Actions ppo-call-to-actions allows Cross Site Request Forgery.This issue affects PPO Call To Actions: from n/a through = 0.1.3.

- [https://github.com/gduma-phData/patch-CVE-2025-24001](https://github.com/gduma-phData/patch-CVE-2025-24001) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-24001.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-24001.svg)


## CVE-2025-22777
 Deserialization of Untrusted Data vulnerability in StellarWP GiveWP give allows Object Injection.This issue affects GiveWP: from n/a through = 3.19.3.

- [https://github.com/gduma-phData/patch-CVE-2025-22777](https://github.com/gduma-phData/patch-CVE-2025-22777) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-22777.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-22777.svg)


## CVE-2025-21340
 Windows Virtualization-Based Security (VBS) Security Feature Bypass Vulnerability

- [https://github.com/gduma-phData/patch-CVE-2025-21340](https://github.com/gduma-phData/patch-CVE-2025-21340) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-21340.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-21340.svg)


## CVE-2025-20115
This vulnerability is due to a memory corruption that occurs when a BGP update is created with an AS_CONFED_SEQUENCE attribute that has 255 autonomous system numbers (AS numbers). An attacker could exploit this vulnerability by sending a crafted BGP update message, or the network could be designed in such a manner that the AS_CONFED_SEQUENCE attribute grows to 255 AS numbers or more. A successful exploit could allow the attacker to cause memory corruption, which may cause the BGP process to restart, resulting in a DoS condition. To exploit this vulnerability, an attacker must control a BGP confederation speaker within the same autonomous system as the victim, or the network must be designed in such a manner that the AS_CONFED_SEQUENCE attribute grows to 255 AS numbers or more.

- [https://github.com/gduma-phData/patch-CVE-2025-20115](https://github.com/gduma-phData/patch-CVE-2025-20115) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-20115.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-20115.svg)


## CVE-2025-15100
 The JAY Login & Register plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.6.03. This is due to the plugin allowing a user to update arbitrary user meta through the 'jay_panel_ajax_update_profile' function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to elevate their privileges to that of an administrator.

- [https://github.com/gduma-phData/patch-CVE-2025-15100](https://github.com/gduma-phData/patch-CVE-2025-15100) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-15100.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-15100.svg)


## CVE-2025-14001
 The WP Duplicate Page plugin for WordPress is vulnerable to unauthorized modification of data due to missing capability checks on the 'duplicateBulkHandle' and 'duplicateBulkHandleHPOS' functions in all versions up to, and including, 1.8. This makes it possible for authenticated attackers, with Contributor-level access and above, to duplicate arbitrary posts, pages, and WooCommerce HPOS orders even when their role is explicitly excluded from the plugin's "Allowed User Roles" setting, potentially exposing sensitive information and allowing duplicate fulfillment of WooCommerce orders.

- [https://github.com/gduma-phData/patch-CVE-2025-14001](https://github.com/gduma-phData/patch-CVE-2025-14001) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-14001.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-14001.svg)


## CVE-2025-12890
 Improper handling of  malformed Connection Request with the interval set to be 1 (which supposed to be illegal) and the chM 0x7CFFFFFFFF triggers a crash. The peripheral will not be connectable after it.

- [https://github.com/gduma-phData/patch-CVE-2025-12890](https://github.com/gduma-phData/patch-CVE-2025-12890) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-12890.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-12890.svg)


## CVE-2025-11555
 A vulnerability was detected in Campcodes Online Learning Management System 1.0. This affects an unknown part of the file /admin/calendar_of_events.php. The manipulation of the argument date_start results in sql injection. The attack may be launched remotely. The exploit is now public and may be used.

- [https://github.com/gduma-phData/patch-CVE-2025-11555](https://github.com/gduma-phData/patch-CVE-2025-11555) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-11555.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-11555.svg)


## CVE-2025-10200
 Use after free in Serviceworker in Google Chrome on Desktop prior to 140.0.7339.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/gduma-phData/patch-CVE-2025-10200](https://github.com/gduma-phData/patch-CVE-2025-10200) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-10200.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-10200.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/Ather-Energy/POC-CVE-2025-5777](https://github.com/Ather-Energy/POC-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Ather-Energy/POC-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Ather-Energy/POC-CVE-2025-5777.svg)


## CVE-2025-4481
 A vulnerability was found in SourceCodester Apartment Visitor Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /search-result.php. The manipulation of the argument searchdata leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/gduma-phData/patch-CVE-2025-44810](https://github.com/gduma-phData/patch-CVE-2025-44810) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-44810.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-44810.svg)


## CVE-2025-4255
 A vulnerability classified as critical has been found in PCMan FTP Server 2.0.7. This affects an unknown part of the component RMD Command Handler. The manipulation leads to buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/gduma-phData/patch-CVE-2025-42558](https://github.com/gduma-phData/patch-CVE-2025-42558) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-42558.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-42558.svg)


## CVE-2025-3890
 The WordPress Simple Shopping Cart plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'wp_cart_button' shortcode in all versions up to, and including, 5.1.3 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/gduma-phData/patch-CVE-2025-38900](https://github.com/gduma-phData/patch-CVE-2025-38900) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-38900.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-38900.svg)


## CVE-2025-3765
 A vulnerability, which was classified as critical, has been found in SourceCodester Web-based Pharmacy Product Management System 1.0. This issue affects some unknown processing of the file /edit-photo.php. The manipulation of the argument Avatar leads to unrestricted upload. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/gduma-phData/patch-CVE-2025-37654](https://github.com/gduma-phData/patch-CVE-2025-37654) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-37654.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-37654.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)
- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-2911
 Unauthorised access to the call forwarding service system in MeetMe products in versions prior to 2024-09 allows an attacker to identify multiple users and perform brute force attacks via extensions.

- [https://github.com/gduma-phData/patch-CVE-2025-29111](https://github.com/gduma-phData/patch-CVE-2025-29111) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-29111.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-29111.svg)


## CVE-2025-2789
 The MultiVendorX – Empower Your WooCommerce Store with a Dynamic Multivendor Marketplace – Build the Next Amazon, eBay, Etsy plugin for WordPress is vulnerable to unauthorized loss of data due to a missing capability check on the delete_table_rate_shipping_row function in all versions up to, and including, 4.2.19. This makes it possible for unauthenticated attackers to delete Table Rates that can impact the shipping cost calculations.

- [https://github.com/gduma-phData/patch-CVE-2025-27890](https://github.com/gduma-phData/patch-CVE-2025-27890) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-27890.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-27890.svg)


## CVE-2025-1900
 A vulnerability was found in PHPGurukul Restaurant Table Booking System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /add-table.php. The manipulation of the argument tableno leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/gduma-phData/patch-CVE-2025-19000](https://github.com/gduma-phData/patch-CVE-2025-19000) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2025-19000.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2025-19000.svg)


## CVE-2025-0117
GlobalProtect App on macOS, Linux, iOS, Android, Chrome OS and GlobalProtect UWP App are not affected.

- [https://github.com/s3c/globalprotect-ca-cert-ipc](https://github.com/s3c/globalprotect-ca-cert-ipc) :  ![starts](https://img.shields.io/github/stars/s3c/globalprotect-ca-cert-ipc.svg) ![forks](https://img.shields.io/github/forks/s3c/globalprotect-ca-cert-ipc.svg)


## CVE-2024-55890
 D-Tale is a visualizer for pandas data structures. Prior to version 3.16.1, users hosting D-Tale publicly can be vulnerable to remote code execution allowing attackers to run malicious code on the server. Users should upgrade to version 3.16.1 where the `update-settings` endpoint blocks the ability for users to update the `enable_custom_filters` flag. The only workaround for versions earlier than 3.16.1 is to only host D-Tale to trusted users.

- [https://github.com/gduma-phData/patch-CVE-2024-55890](https://github.com/gduma-phData/patch-CVE-2024-55890) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2024-55890.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2024-55890.svg)


## CVE-2024-45798
 arduino-esp32 is an Arduino core for the ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6 and ESP32-H2 microcontrollers. The `arduino-esp32` CI is vulnerable to multiple Poisoned Pipeline Execution (PPE) vulnerabilities. Code injection in `tests_results.yml` workflow (`GHSL-2024-169`) and environment Variable injection (`GHSL-2024-170`). These issue have been addressed but users are advised to verify the contents of the downloaded artifacts.

- [https://github.com/pvharmo2/gha-lab-16bfb18428](https://github.com/pvharmo2/gha-lab-16bfb18428) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-16bfb18428.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-16bfb18428.svg)


## CVE-2024-9900
 mudler/localai version v2.21.1 contains a Cross-Site Scripting (XSS) vulnerability in its search functionality. The vulnerability arises due to improper sanitization of user input, allowing the injection and execution of arbitrary JavaScript code. This can lead to the execution of malicious scripts in the context of the victim's browser, potentially compromising user sessions, stealing session cookies, redirecting users to malicious websites, or manipulating the DOM.

- [https://github.com/gduma-phData/patch-CVE-2024-99001](https://github.com/gduma-phData/patch-CVE-2024-99001) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2024-99001.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2024-99001.svg)


## CVE-2024-8855
 The WordPress Auction Plugin WordPress plugin through 3.7 does not sanitize and escape a parameter before using it in a SQL statement, allowing editors and above to perform SQL injection attacks

- [https://github.com/gduma-phData/patch-CVE-2024-88555](https://github.com/gduma-phData/patch-CVE-2024-88555) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2024-88555.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2024-88555.svg)


## CVE-2024-7720
 HP Security Manager is potentially vulnerable to Remote Code Execution as a result of code vulnerability within the product's solution open-source libraries.

- [https://github.com/gduma-phData/patch-CVE-2024-77200](https://github.com/gduma-phData/patch-CVE-2024-77200) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2024-77200.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2024-77200.svg)


## CVE-2024-6600
 Due to large allocation checks in Angle for GLSL shaders being too lenient an out-of-bounds access could occur when allocating more than 8192 ints in private shader memory on macOS. This vulnerability affects Firefox  128, Firefox ESR  115.13, Thunderbird  115.13, and Thunderbird  128.

- [https://github.com/gduma-phData/patch-CVE-2024-66001](https://github.com/gduma-phData/patch-CVE-2024-66001) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2024-66001.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2024-66001.svg)


## CVE-2024-6297
 Several plugins for WordPress hosted on WordPress.org have been compromised and injected with malicious PHP scripts. A malicious threat actor compromised the source code of various plugins and injected code that exfiltrates database credentials and is used to create new, malicious, administrator users and send that data back to a server. Currently, not all plugins have been patched and we strongly recommend uninstalling the plugins for the time being and running a complete malware scan.

- [https://github.com/Sudo-WP/sudowp-hooks-visualizer](https://github.com/Sudo-WP/sudowp-hooks-visualizer) :  ![starts](https://img.shields.io/github/stars/Sudo-WP/sudowp-hooks-visualizer.svg) ![forks](https://img.shields.io/github/forks/Sudo-WP/sudowp-hooks-visualizer.svg)


## CVE-2023-30628
the `changelog.yml` workflow is vulnerable to command injection attacks because of using an untrusted `github.head_ref` field. The `github.head_ref` value is an attacker-controlled value. Assigning the value to `zzz";echo${IFS}"hello";#` can lead to command injection. Since the permission is not restricted, the attacker has a write-access to the repository. Commit 834c86dfd1b2492ccad7ebbfd6304bfec895fed2 of the kiwitcms/Kiwi repository and commit e39f7e156fdaf6fec09a15ea6f4e8fec8cdbf751 of the kiwitcms/enterprise repository contain a fix for this issue.

- [https://github.com/pvharmo2/gha-lab-227431b300](https://github.com/pvharmo2/gha-lab-227431b300) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-227431b300.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-227431b300.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier  and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/uLl0a/cve-2022-42475-poc](https://github.com/uLl0a/cve-2022-42475-poc) :  ![starts](https://img.shields.io/github/stars/uLl0a/cve-2022-42475-poc.svg) ![forks](https://img.shields.io/github/forks/uLl0a/cve-2022-42475-poc.svg)


## CVE-2022-2590
 A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW) breakage of private read-only shared memory mappings. This flaw allows an unprivileged, local user to gain write access to read-only memory mappings, increasing their privileges on the system.

- [https://github.com/moonnull/CVE-2022-2590-analysis](https://github.com/moonnull/CVE-2022-2590-analysis) :  ![starts](https://img.shields.io/github/stars/moonnull/CVE-2022-2590-analysis.svg) ![forks](https://img.shields.io/github/forks/moonnull/CVE-2022-2590-analysis.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-30327
 Buffer overflow in sahara protocol while processing commands leads to overwrite of secure configuration data in Snapdragon Mobile, Snapdragon Compute, Snapdragon Auto, Snapdragon IOT, Snapdragon Connectivity, Snapdragon Voice & Music

- [https://github.com/Daniel224455/echidna](https://github.com/Daniel224455/echidna) :  ![starts](https://img.shields.io/github/stars/Daniel224455/echidna.svg) ![forks](https://img.shields.io/github/forks/Daniel224455/echidna.svg)


## CVE-2020-1315
 An information disclosure vulnerability exists when Internet Explorer improperly handles objects in memory, aka 'Internet Explorer Information Disclosure Vulnerability'.

- [https://github.com/InfoSec4Fun/CVE-2020-13158](https://github.com/InfoSec4Fun/CVE-2020-13158) :  ![starts](https://img.shields.io/github/stars/InfoSec4Fun/CVE-2020-13158.svg) ![forks](https://img.shields.io/github/forks/InfoSec4Fun/CVE-2020-13158.svg)
- [https://github.com/InfoSec4Fun/CVE-2020-13159](https://github.com/InfoSec4Fun/CVE-2020-13159) :  ![starts](https://img.shields.io/github/stars/InfoSec4Fun/CVE-2020-13159.svg) ![forks](https://img.shields.io/github/forks/InfoSec4Fun/CVE-2020-13159.svg)


## CVE-2018-5803
 In the Linux Kernel before version 4.15.8, 4.14.25, 4.9.87, 4.4.121, 4.1.51, and 3.2.102, an error in the "_sctp_make_chunk()" function (net/sctp/sm_make_chunk.c) when handling SCTP packets length can be exploited to cause a kernel crash.

- [https://github.com/Splinter0/CVE-2018-5803](https://github.com/Splinter0/CVE-2018-5803) :  ![starts](https://img.shields.io/github/stars/Splinter0/CVE-2018-5803.svg) ![forks](https://img.shields.io/github/forks/Splinter0/CVE-2018-5803.svg)


## CVE-2009-0658
 Buffer overflow in Adobe Reader 9.0 and earlier, and Acrobat 9.0 and earlier, allows remote attackers to execute arbitrary code via a crafted PDF document, related to a non-JavaScript function call and possibly an embedded JBIG2 image stream, as exploited in the wild in February 2009 by Trojan.Pidief.E.

- [https://github.com/kyaw-tun/blue-team-capstone](https://github.com/kyaw-tun/blue-team-capstone) :  ![starts](https://img.shields.io/github/stars/kyaw-tun/blue-team-capstone.svg) ![forks](https://img.shields.io/github/forks/kyaw-tun/blue-team-capstone.svg)

