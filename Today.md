# Update 2026-05-27
## CVE-2026-47102
 LiteLLM prior to 1.83.10 allows a user to modify their own user_role via the /user/update endpoint. While the endpoint correctly restricts users to updating only their own account, it does not restrict which fields may be changed. A user who can reach this endpoint can set their role to proxy_admin, gaining full administrative access to LiteLLM including all users, teams, keys, models, and prompt history. Users with the org_admin role have legitimate access to this endpoint and can exploit this vulnerability without chaining any additional flaw.

- [https://github.com/learner202649/CVE-2026-47102-PoC](https://github.com/learner202649/CVE-2026-47102-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2026-47102-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2026-47102-PoC.svg)


## CVE-2026-47101
 LiteLLM prior to 1.83.14 allows an authenticated internal_user to create API keys with access to routes that their role does not permit. When generating a key, the allowed_routes field is stored without verifying that the specified routes fall within the user's own permissions. A key created with access to admin-only routes can then be used to reach those routes successfully, bypassing the role-based access controls that would otherwise block the request, enabling full privilege escalation from internal_user to proxy_admin.

- [https://github.com/learner202649/CVE-2026-47101-PoC](https://github.com/learner202649/CVE-2026-47101-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2026-47101-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2026-47101-PoC.svg)


## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/renewablehacking/CVE-2026-45321-Tanstack](https://github.com/renewablehacking/CVE-2026-45321-Tanstack) :  ![starts](https://img.shields.io/github/stars/renewablehacking/CVE-2026-45321-Tanstack.svg) ![forks](https://img.shields.io/github/forks/renewablehacking/CVE-2026-45321-Tanstack.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/jayhutajulu1/CVE-2026-43494-PinTheft-PoC](https://github.com/jayhutajulu1/CVE-2026-43494-PinTheft-PoC) :  ![starts](https://img.shields.io/github/stars/jayhutajulu1/CVE-2026-43494-PinTheft-PoC.svg) ![forks](https://img.shields.io/github/forks/jayhutajulu1/CVE-2026-43494-PinTheft-PoC.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/bamov970/CVE-2026-42945-Nginx-RCE-bypass-ASLR](https://github.com/bamov970/CVE-2026-42945-Nginx-RCE-bypass-ASLR) :  ![starts](https://img.shields.io/github/stars/bamov970/CVE-2026-42945-Nginx-RCE-bypass-ASLR.svg) ![forks](https://img.shields.io/github/forks/bamov970/CVE-2026-42945-Nginx-RCE-bypass-ASLR.svg)
- [https://github.com/karakapaku43/CVE-2026-42945](https://github.com/karakapaku43/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/karakapaku43/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/karakapaku43/CVE-2026-42945.svg)
- [https://github.com/nu0l/NGINX-Rift](https://github.com/nu0l/NGINX-Rift) :  ![starts](https://img.shields.io/github/stars/nu0l/NGINX-Rift.svg) ![forks](https://img.shields.io/github/forks/nu0l/NGINX-Rift.svg)


## CVE-2026-42880
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. From versions 3.2.0 to before 3.2.11 and 3.3.0 to before 3.3.9, there is a missing authorization and data-masking gap in Argo CD's ServerSideDiff endpoint that allows an attacker with read-only access to extract plaintext Kubernetes Secret data from etcd via the Kubernetes API server's Server-Side Apply dry-run mechanism. This issue has been patched in versions 3.2.11 and 3.3.9.

- [https://github.com/HAERIN-L/POC_CVE-2026-42880](https://github.com/HAERIN-L/POC_CVE-2026-42880) :  ![starts](https://img.shields.io/github/stars/HAERIN-L/POC_CVE-2026-42880.svg) ![forks](https://img.shields.io/github/forks/HAERIN-L/POC_CVE-2026-42880.svg)


## CVE-2026-35196
 Chamilo LMS is an open-source learning management system. In versions prior to 2.0.0-RC.3, an OS Command Injection vulnerability exists in the main/inc/ajax/gradebook.ajax.php endpoint within the export_all_certificates action, where the course code retrieved from the session variable $_SESSION['_cid'] via api_get_course_id() is concatenated directly into a shell_exec() command string without sanitization or escaping using escapeshellarg(). If an attacker can manipulate or poison their session data to inject shell metacharacters into the _cid variable, they can achieve arbitrary command execution on the underlying server. Successful exploitation grants full access to read system files and credentials, alters the application and database, or disrupts server availability. This issue has been fixed in version 2.0.0-RC.3.

- [https://github.com/kx00007/CVE-2026-35196](https://github.com/kx00007/CVE-2026-35196) :  ![starts](https://img.shields.io/github/stars/kx00007/CVE-2026-35196.svg) ![forks](https://img.shields.io/github/forks/kx00007/CVE-2026-35196.svg)


## CVE-2026-33712
 Typebot is a chatbot builder tool. In versions 3.15.2 and prior, the preview chat endpoint (POST /api/v1/typebots/{typebotId}/preview/startChat) allows unauthenticated users to achieve Server-Side Request Forgery (SSRF) by supplying a custom typebot definition with server-side code blocks. The fetch function exposed inside the isolated-vm sandbox calls Node.js native fetch without the SSRF validation (validateHttpReqUrl) that protects the HTTP Request block. This bypasses all SSRF mitigations added after GHSA-8gq9-rw7v-3jpr. Exploitation of this unauthenticated SSRF vulnerability can lead to cloud credential theft, internal network access and data exfiltration for any self-hosted Typebot deployments and hosted services. This issue has been fixed in version 3.16.0.

- [https://github.com/portbuster1337/CVE-2026-33712](https://github.com/portbuster1337/CVE-2026-33712) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-33712.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-33712.svg)


## CVE-2026-33137
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. XWiki Platform is a generic wiki platform. In versions prior to 18.1.0-rc-1, 17.10.3, 17.4.9, and 16.10.17, the POST /wikis/{wikiName} API executes a XAR import without performing any authentication or authorization checks, allowing an unauthenticated attacker to create or update documents in the target wiki. This vulnerability has been patched in XWiki 16.10.17, 17.4.9, 17.10.3, 18.0.1 and 18.1.0-rc-1.

- [https://github.com/portbuster1337/CVE-2026-33137](https://github.com/portbuster1337/CVE-2026-33137) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-33137.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-33137.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Iamliuxiaozhen/copy_fail](https://github.com/Iamliuxiaozhen/copy_fail) :  ![starts](https://img.shields.io/github/stars/Iamliuxiaozhen/copy_fail.svg) ![forks](https://img.shields.io/github/forks/Iamliuxiaozhen/copy_fail.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 26.3 and iPadOS 26.3, macOS Tahoe 26.3, tvOS 26.3, visionOS 26.3, watchOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/notthemystery/CVE-2026-20700-POC-that-ll-never-work](https://github.com/notthemystery/CVE-2026-20700-POC-that-ll-never-work) :  ![starts](https://img.shields.io/github/stars/notthemystery/CVE-2026-20700-POC-that-ll-never-work.svg) ![forks](https://img.shields.io/github/forks/notthemystery/CVE-2026-20700-POC-that-ll-never-work.svg)


## CVE-2026-3909
 Out of bounds write in Skia in Google Chrome prior to 146.0.7680.75 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/anansi2safe/CVE-2026-3909](https://github.com/anansi2safe/CVE-2026-3909) :  ![starts](https://img.shields.io/github/stars/anansi2safe/CVE-2026-3909.svg) ![forks](https://img.shields.io/github/forks/anansi2safe/CVE-2026-3909.svg)


## CVE-2026-3854
 An improper neutralization of special elements vulnerability was identified in GitHub Enterprise Server that allowed an attacker with push access to a repository to achieve remote code execution on the instance. During a git push operation, user-supplied push option values were not properly sanitized before being included in internal service headers. Because the internal header format used a delimiter character that could also appear in user input, an attacker could inject additional metadata fields through crafted push option values. This vulnerability was reported via the GitHub Bug Bounty program and has been fixed in GitHub Enterprise Server versions 3.14.25, 3.15.20, 3.16.16, 3.17.13, 3.18.7 and 3.19.4.

- [https://github.com/daniel30padd/CVE-2026-3854](https://github.com/daniel30padd/CVE-2026-3854) :  ![starts](https://img.shields.io/github/stars/daniel30padd/CVE-2026-3854.svg) ![forks](https://img.shields.io/github/forks/daniel30padd/CVE-2026-3854.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/thakur2309/CVE-2026-0073-ZERO-CLICK](https://github.com/thakur2309/CVE-2026-0073-ZERO-CLICK) :  ![starts](https://img.shields.io/github/stars/thakur2309/CVE-2026-0073-ZERO-CLICK.svg) ![forks](https://img.shields.io/github/forks/thakur2309/CVE-2026-0073-ZERO-CLICK.svg)
- [https://github.com/m00ddy/CVE-2026-0073-Android-client-TLS-auth-bypass](https://github.com/m00ddy/CVE-2026-0073-Android-client-TLS-auth-bypass) :  ![starts](https://img.shields.io/github/stars/m00ddy/CVE-2026-0073-Android-client-TLS-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/m00ddy/CVE-2026-0073-Android-client-TLS-auth-bypass.svg)


## CVE-2025-63353
 A vulnerability in FiberHome GPON ONU HG6145F1 RP4423 allows the device's factory default Wi-Fi password (WPA/WPA2 pre-shared key) to be predicted from the SSID. The device generates default passwords using a deterministic algorithm that derives the router passphrase from the SSID, enabling an attacker who can observe the SSID to predict the default password without authentication or user interaction.

- [https://github.com/Zvckster/CVE-2025-63353](https://github.com/Zvckster/CVE-2025-63353) :  ![starts](https://img.shields.io/github/stars/Zvckster/CVE-2025-63353.svg) ![forks](https://img.shields.io/github/forks/Zvckster/CVE-2025-63353.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/grp-ops/react2shell](https://github.com/grp-ops/react2shell) :  ![starts](https://img.shields.io/github/stars/grp-ops/react2shell.svg) ![forks](https://img.shields.io/github/forks/grp-ops/react2shell.svg)


## CVE-2025-20282
This vulnerability is due a lack of file validation checks that would prevent uploaded files from being placed in privileged directories on an affected system. An attacker could exploit this vulnerability by uploading a crafted file to the affected device. A successful exploit could allow the attacker to store malicious files on the affected system and then execute arbitrary code or obtain root privileges on the system.

- [https://github.com/eggpratacurry/cve-2025-20282](https://github.com/eggpratacurry/cve-2025-20282) :  ![starts](https://img.shields.io/github/stars/eggpratacurry/cve-2025-20282.svg) ![forks](https://img.shields.io/github/forks/eggpratacurry/cve-2025-20282.svg)


## CVE-2024-45496
 A flaw was found in OpenShift. This issue occurs due to the misuse of elevated privileges in the OpenShift Container Platform's build process. During the build initialization step, the git-clone container is run with a privileged security context, allowing unrestricted access to the node. An attacker with developer-level access can provide a crafted .gitconfig file containing commands executed during the cloning process, leading to arbitrary command execution on the worker node. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/eggpratacurry/cve-2024-45496](https://github.com/eggpratacurry/cve-2024-45496) :  ![starts](https://img.shields.io/github/stars/eggpratacurry/cve-2024-45496.svg) ![forks](https://img.shields.io/github/forks/eggpratacurry/cve-2024-45496.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/russellwork2021-lgtm/cosmicsting-cve-2024-34102-exploit](https://github.com/russellwork2021-lgtm/cosmicsting-cve-2024-34102-exploit) :  ![starts](https://img.shields.io/github/stars/russellwork2021-lgtm/cosmicsting-cve-2024-34102-exploit.svg) ![forks](https://img.shields.io/github/forks/russellwork2021-lgtm/cosmicsting-cve-2024-34102-exploit.svg)


## CVE-2024-23113
 A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitchManager versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.3 allows attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/MinhPham123456789/PoC-CVE-2024-23113](https://github.com/MinhPham123456789/PoC-CVE-2024-23113) :  ![starts](https://img.shields.io/github/stars/MinhPham123456789/PoC-CVE-2024-23113.svg) ![forks](https://img.shields.io/github/forks/MinhPham123456789/PoC-CVE-2024-23113.svg)


## CVE-2024-10829
 A Denial of Service (DoS) vulnerability in the multipart request boundary processing mechanism of eosphoros-ai/db-gpt v0.6.0 allows unauthenticated attackers to cause excessive resource consumption. The server fails to handle excessive characters appended to the end of multipart boundaries, leading to an infinite loop and complete denial of service for all users. This vulnerability affects all endpoints processing multipart/form-data requests.

- [https://github.com/junn34/POC_CVE-2024-10829](https://github.com/junn34/POC_CVE-2024-10829) :  ![starts](https://img.shields.io/github/stars/junn34/POC_CVE-2024-10829.svg) ![forks](https://img.shields.io/github/forks/junn34/POC_CVE-2024-10829.svg)


## CVE-2024-7387
 A flaw was found in openshift/builder. This vulnerability allows command injection via path traversal, where a malicious user can execute arbitrary commands on the OpenShift node running the builder container. When using the “Docker” strategy, executable files inside the privileged build container can be overridden using the `spec.source.secrets.secret.destinationDir` attribute of the `BuildConfig` definition. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/eggpratacurry/cve-2024-7387](https://github.com/eggpratacurry/cve-2024-7387) :  ![starts](https://img.shields.io/github/stars/eggpratacurry/cve-2024-7387.svg) ![forks](https://img.shields.io/github/forks/eggpratacurry/cve-2024-7387.svg)


## CVE-2021-44026
 Roundcube before 1.3.17 and 1.4.x before 1.4.12 is prone to a potential SQL injection via search or search_params.

- [https://github.com/shanglyu/roundcube-cve-2021-44026](https://github.com/shanglyu/roundcube-cve-2021-44026) :  ![starts](https://img.shields.io/github/stars/shanglyu/roundcube-cve-2021-44026.svg) ![forks](https://img.shields.io/github/forks/shanglyu/roundcube-cve-2021-44026.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Asbawy/GrafTraverse-CVE-2021-43798](https://github.com/Asbawy/GrafTraverse-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Asbawy/GrafTraverse-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Asbawy/GrafTraverse-CVE-2021-43798.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/0xl0ki/Dubbo-deserialization](https://github.com/0xl0ki/Dubbo-deserialization) :  ![starts](https://img.shields.io/github/stars/0xl0ki/Dubbo-deserialization.svg) ![forks](https://img.shields.io/github/forks/0xl0ki/Dubbo-deserialization.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Dungsocool/CVE-2017-5638](https://github.com/Dungsocool/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2017-5638.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/AtithKhawas/autoblue](https://github.com/AtithKhawas/autoblue) :  ![starts](https://img.shields.io/github/stars/AtithKhawas/autoblue.svg) ![forks](https://img.shields.io/github/forks/AtithKhawas/autoblue.svg)
- [https://github.com/trinadh-dasari-cyber/eternalblue-ms17-010-research](https://github.com/trinadh-dasari-cyber/eternalblue-ms17-010-research) :  ![starts](https://img.shields.io/github/stars/trinadh-dasari-cyber/eternalblue-ms17-010-research.svg) ![forks](https://img.shields.io/github/forks/trinadh-dasari-cyber/eternalblue-ms17-010-research.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/victoriacfigueiredo/heartbleed-lab](https://github.com/victoriacfigueiredo/heartbleed-lab) :  ![starts](https://img.shields.io/github/stars/victoriacfigueiredo/heartbleed-lab.svg) ![forks](https://img.shields.io/github/forks/victoriacfigueiredo/heartbleed-lab.svg)

