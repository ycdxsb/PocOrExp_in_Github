# Update 2026-05-22
## CVE-2026-45829
 A pre-authentication, code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/{tenant}/databases/{db}/collections endpoint.

- [https://github.com/fevar54/FULL-ANALYSIS---CVE-2026-45829-ChromaDB-](https://github.com/fevar54/FULL-ANALYSIS---CVE-2026-45829-ChromaDB-) :  ![starts](https://img.shields.io/github/stars/fevar54/FULL-ANALYSIS---CVE-2026-45829-ChromaDB-.svg) ![forks](https://img.shields.io/github/forks/fevar54/FULL-ANALYSIS---CVE-2026-45829-ChromaDB-.svg)


## CVE-2026-45585
We are issuing this CVE to provide mitigation guidance that can be implemented to protect against this vulnerability until the security update is made available.

- [https://github.com/bjbakker1984/Yellowkey-mitigation](https://github.com/bjbakker1984/Yellowkey-mitigation) :  ![starts](https://img.shields.io/github/stars/bjbakker1984/Yellowkey-mitigation.svg) ![forks](https://img.shields.io/github/forks/bjbakker1984/Yellowkey-mitigation.svg)


## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/prashanthnataraj/mini-shai-hulud-detector](https://github.com/prashanthnataraj/mini-shai-hulud-detector) :  ![starts](https://img.shields.io/github/stars/prashanthnataraj/mini-shai-hulud-detector.svg) ![forks](https://img.shields.io/github/forks/prashanthnataraj/mini-shai-hulud-detector.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/Koshmare-Blossom/Dirtyfrag-go](https://github.com/Koshmare-Blossom/Dirtyfrag-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/Dirtyfrag-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/Dirtyfrag-go.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/Koshmare-Blossom/Dirtyfrag-go](https://github.com/Koshmare-Blossom/Dirtyfrag-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/Dirtyfrag-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/Dirtyfrag-go.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/yusufdalbudak/CVE-2026-42945](https://github.com/yusufdalbudak/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/yusufdalbudak/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/yusufdalbudak/CVE-2026-42945.svg)
- [https://github.com/gagaltotal/CVE-2026-42945-NGINX-Rift-Toolkit](https://github.com/gagaltotal/CVE-2026-42945-NGINX-Rift-Toolkit) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-42945-NGINX-Rift-Toolkit.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-42945-NGINX-Rift-Toolkit.svg)


## CVE-2026-42271
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.74.2 to before version 1.83.7, two endpoints used to preview an MCP server before saving it — POST /mcp-rest/test/connection and POST /mcp-rest/test/tools/list — accepted a full server configuration in the request body, including the command, args, and env fields used by the stdio transport. When called with a stdio configuration, the endpoints attempted to connect, which spawned the supplied command as a subprocess on the proxy host with the privileges of the proxy process. The endpoints were gated only by a valid proxy API key, with no role check. Any authenticated user — including holders of low-privilege internal-user keys — could therefore run arbitrary commands on the host. This issue has been patched in version 1.83.7.

- [https://github.com/learner202649/CVE-2026-42271-PoC](https://github.com/learner202649/CVE-2026-42271-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2026-42271-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2026-42271-PoC.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/Lutfifakee-Project/CVE-2026-41651](https://github.com/Lutfifakee-Project/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-41651.svg)


## CVE-2026-39047
 Buffer Overflow vulnerability in EPSON L14150 FL27PB allows a remote attacker to execute arbitrary code via the RAW Printing Service (JetDirect) on TCP port 9100

- [https://github.com/AzhariRamadhan/CVE-2026-39047](https://github.com/AzhariRamadhan/CVE-2026-39047) :  ![starts](https://img.shields.io/github/stars/AzhariRamadhan/CVE-2026-39047.svg) ![forks](https://img.shields.io/github/forks/AzhariRamadhan/CVE-2026-39047.svg)


## CVE-2026-35037
 Ech0 is an open-source, self-hosted publishing platform for personal idea sharing. Prior to 4.2.8, the GET /api/website/title endpoint accepts an arbitrary URL via the website_url query parameter and makes a server-side HTTP request to it without any validation of the target host or IP address. The endpoint requires no authentication. An attacker can use this to reach internal network services, cloud metadata endpoints (169.254.169.254), and localhost-bound services, with partial response data exfiltrated via the HTML title tag extraction This vulnerability is fixed in 4.2.8.

- [https://github.com/fineman999/POC_CVE-2026-35037](https://github.com/fineman999/POC_CVE-2026-35037) :  ![starts](https://img.shields.io/github/stars/fineman999/POC_CVE-2026-35037.svg) ![forks](https://img.shields.io/github/forks/fineman999/POC_CVE-2026-35037.svg)


## CVE-2026-34474
 Sensitive data exposure leading to admin/WLAN credential leak in ZTE ZXHN H298A 1.1 and H108N 2.6. A crafted request to the router web interface can expose sensitive device and account information. In affected builds, the response may include the administrator password and WLAN PSK, enabling authentication bypass and network compromise. Some firmware versions may expose only partial identifiers (e.g., serial number, ESSID, MAC addresses).

- [https://github.com/minanagehsalalma/cve-2026-34474-zte-h298a-h108n-sensitive-data-exposure](https://github.com/minanagehsalalma/cve-2026-34474-zte-h298a-h108n-sensitive-data-exposure) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/cve-2026-34474-zte-h298a-h108n-sensitive-data-exposure.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/cve-2026-34474-zte-h298a-h108n-sensitive-data-exposure.svg)


## CVE-2026-34472
 Unauthenticated credential disclosure in the wizard interface in ZTE ZXHN H188A V6.0.10P2_TE and V6.0.10P3N3_TE allows unauthenticated attackers on the local network to retrieve sensitive credentials from the router's web management interface, including the default administrator password, WLAN PSK, and PPPoE credentials. In some observed cases, configuration changes may also be performed without authentication.

- [https://github.com/minanagehsalalma/cve-2026-34472-auth-bypass-zte-h188a-router](https://github.com/minanagehsalalma/cve-2026-34472-auth-bypass-zte-h188a-router) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/cve-2026-34472-auth-bypass-zte-h188a-router.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/cve-2026-34472-auth-bypass-zte-h188a-router.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/Lutfifakee-Project/CVE-2026-31635](https://github.com/Lutfifakee-Project/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-31635.svg)
- [https://github.com/aexdyhaxor/DirtyDecrypt](https://github.com/aexdyhaxor/DirtyDecrypt) :  ![starts](https://img.shields.io/github/stars/aexdyhaxor/DirtyDecrypt.svg) ![forks](https://img.shields.io/github/forks/aexdyhaxor/DirtyDecrypt.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/sgkdev/ptrace_may_dream](https://github.com/sgkdev/ptrace_may_dream) :  ![starts](https://img.shields.io/github/stars/sgkdev/ptrace_may_dream.svg) ![forks](https://img.shields.io/github/forks/sgkdev/ptrace_may_dream.svg)
- [https://github.com/Pithase/asm-copyfail](https://github.com/Pithase/asm-copyfail) :  ![starts](https://img.shields.io/github/stars/Pithase/asm-copyfail.svg) ![forks](https://img.shields.io/github/forks/Pithase/asm-copyfail.svg)


## CVE-2026-30950
 AutoGPT is a workflow automation platform for creating, deploying, and managing continuous artificial intelligence agents. Versions 0.6.36 through 0.6.50 are vulnerable to Authenticated Session Hijacking via IDOR. If an authenticated attacker can determine the session_id of another user's session, they can take it over, reading any messages in it and locking the legitimate user out. The PATCH /sessions/{session_id}/assign-user endpoint authenticates the caller but never verifies session ownership: the service layer invokes the session lookup with user_id=None, which the data access layer interprets as a privileged/system call that bypasses the ownership filter, allowing any authenticated user to reassign an arbitrary session to themselves. This issue has been patched in version 0.6.51.

- [https://github.com/ZeroPathAI/autogpt-CVE-2026-30950-poc](https://github.com/ZeroPathAI/autogpt-CVE-2026-30950-poc) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/autogpt-CVE-2026-30950-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/autogpt-CVE-2026-30950-poc.svg)


## CVE-2026-30691
 Cross-Site Scripting (XSS) vulnerability in @cyntler/react-doc-viewer v1.17.1 allows remote attackers to execute arbitrary JavaScript via a crafted .txt file. The TXTRenderer component fails to sanitize file content and explicitly casts raw data as a ReactNode

- [https://github.com/walidriouah/CVE-2026-30691](https://github.com/walidriouah/CVE-2026-30691) :  ![starts](https://img.shields.io/github/stars/walidriouah/CVE-2026-30691.svg) ![forks](https://img.shields.io/github/forks/walidriouah/CVE-2026-30691.svg)


## CVE-2026-26980
 Ghost is a Node.js content management system. Versions 3.24.0 through 6.19.0 allow unauthenticated attackers to perform arbitrary reads from the database. This issue has been fixed in version 6.19.1.

- [https://github.com/Kulik-Labs-Development/Ghost-CMS-Code-Injection-Audit-CVE-2026-26980](https://github.com/Kulik-Labs-Development/Ghost-CMS-Code-Injection-Audit-CVE-2026-26980) :  ![starts](https://img.shields.io/github/stars/Kulik-Labs-Development/Ghost-CMS-Code-Injection-Audit-CVE-2026-26980.svg) ![forks](https://img.shields.io/github/forks/Kulik-Labs-Development/Ghost-CMS-Code-Injection-Audit-CVE-2026-26980.svg)


## CVE-2026-4630
 A flaw was found in Keycloak. An authenticated client could exploit an Insecure Direct Object Reference (IDOR) vulnerability in the Authorization Services Protection API endpoint. By knowing or obtaining a resource's unique identifier (UUID) belonging to another Resource Server within the same realm, the client could bypass authorization checks. This allows the client to perform unauthorized GET, PUT, and DELETE operations on resources, leading to information disclosure and potential unauthorized modification or deletion of data.

- [https://github.com/Maxime288/Fragnesia-CVE-2026-46300](https://github.com/Maxime288/Fragnesia-CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/Maxime288/Fragnesia-CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/Maxime288/Fragnesia-CVE-2026-46300.svg)


## CVE-2026-3910
 Inappropriate implementation in V8 in Google Chrome prior to 146.0.7680.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/MGTx2/CVE-2026-39107](https://github.com/MGTx2/CVE-2026-39107) :  ![starts](https://img.shields.io/github/stars/MGTx2/CVE-2026-39107.svg) ![forks](https://img.shields.io/github/forks/MGTx2/CVE-2026-39107.svg)


## CVE-2026-2587
 A critical Remote Code Execution (RCE) vulnerability was identified in the server-side template rendering mechanism used by the Glassfish gadget handler. The application processes .xml files and evaluates user-supplied values within a context where Expression Language (EL) “expressions” are processed without proper sanitization or escaping. By injecting expressions such as #{7*7}, the server returns 49, confirming server-side EL evaluation. This issue allows a remote attacker to fully compromise the underlying host, enabling capabilities as reading/modifying data, executing arbitrary commands, persistence, and lateral movement.

- [https://github.com/Bhanunamikaze/CVE-2026-2587-Exploit-POC](https://github.com/Bhanunamikaze/CVE-2026-2587-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/Bhanunamikaze/CVE-2026-2587-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/Bhanunamikaze/CVE-2026-2587-Exploit-POC.svg)


## CVE-2026-1953
 Nukegraphic CMS v3.1.2 contains a stored cross-site scripting (XSS) vulnerability in the user profile edit functionality at /ngc-cms/user-edit-profile.php. The application fails to properly sanitize user input in the name field before storing it in the database and rendering it across multiple CMS pages. An authenticated attacker with low privileges can inject malicious JavaScript payloads through the profile edit request, which are then executed site-wide whenever the affected user's name is displayed. This allows the attacker to execute arbitrary JavaScript in the context of other users' sessions, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of victims.

- [https://github.com/dewaguard-red-team/CVE-2026-1953](https://github.com/dewaguard-red-team/CVE-2026-1953) :  ![starts](https://img.shields.io/github/stars/dewaguard-red-team/CVE-2026-1953.svg) ![forks](https://img.shields.io/github/forks/dewaguard-red-team/CVE-2026-1953.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/0xbinder/CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/0xbinder/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/0xbinder/CVE-2026-0073.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/hyperchk/CVE-2025-24071-POC](https://github.com/hyperchk/CVE-2025-24071-POC) :  ![starts](https://img.shields.io/github/stars/hyperchk/CVE-2025-24071-POC.svg) ![forks](https://img.shields.io/github/forks/hyperchk/CVE-2025-24071-POC.svg)


## CVE-2025-22442
 In multiple functions of DevicePolicyManagerService.java, there is a possible way to install unauthorized applications into a newly created work profile due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Hasan-Al-Hussein/android-workprofile-exploit](https://github.com/Hasan-Al-Hussein/android-workprofile-exploit) :  ![starts](https://img.shields.io/github/stars/Hasan-Al-Hussein/android-workprofile-exploit.svg) ![forks](https://img.shields.io/github/forks/Hasan-Al-Hussein/android-workprofile-exploit.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/mananispiwpiw/CVE-2025-8110-PoC](https://github.com/mananispiwpiw/CVE-2025-8110-PoC) :  ![starts](https://img.shields.io/github/stars/mananispiwpiw/CVE-2025-8110-PoC.svg) ![forks](https://img.shields.io/github/forks/mananispiwpiw/CVE-2025-8110-PoC.svg)
- [https://github.com/get-xor/coreweave-demo-2026-05](https://github.com/get-xor/coreweave-demo-2026-05) :  ![starts](https://img.shields.io/github/stars/get-xor/coreweave-demo-2026-05.svg) ![forks](https://img.shields.io/github/forks/get-xor/coreweave-demo-2026-05.svg)


## CVE-2025-3248
code.

- [https://github.com/get-xor/coreweave-demo-2026-05](https://github.com/get-xor/coreweave-demo-2026-05) :  ![starts](https://img.shields.io/github/stars/get-xor/coreweave-demo-2026-05.svg) ![forks](https://img.shields.io/github/forks/get-xor/coreweave-demo-2026-05.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/xiaoqiesec0x1/CVE-2024-4367-PDF.js-xss](https://github.com/xiaoqiesec0x1/CVE-2024-4367-PDF.js-xss) :  ![starts](https://img.shields.io/github/stars/xiaoqiesec0x1/CVE-2024-4367-PDF.js-xss.svg) ![forks](https://img.shields.io/github/forks/xiaoqiesec0x1/CVE-2024-4367-PDF.js-xss.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/CrackerCat/ActiveMQ_RCE_Pro_Max](https://github.com/CrackerCat/ActiveMQ_RCE_Pro_Max) :  ![starts](https://img.shields.io/github/stars/CrackerCat/ActiveMQ_RCE_Pro_Max.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/ActiveMQ_RCE_Pro_Max.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/Destawell/gemini-2.5-pro-nf-tables-red-teaming](https://github.com/Destawell/gemini-2.5-pro-nf-tables-red-teaming) :  ![starts](https://img.shields.io/github/stars/Destawell/gemini-2.5-pro-nf-tables-red-teaming.svg) ![forks](https://img.shields.io/github/forks/Destawell/gemini-2.5-pro-nf-tables-red-teaming.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/julianertle/CVE-2023-0386-CTF](https://github.com/julianertle/CVE-2023-0386-CTF) :  ![starts](https://img.shields.io/github/stars/julianertle/CVE-2023-0386-CTF.svg) ![forks](https://img.shields.io/github/forks/julianertle/CVE-2023-0386-CTF.svg)


## CVE-2022-26923
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/victorhugomierez/CVE-2022-26923](https://github.com/victorhugomierez/CVE-2022-26923) :  ![starts](https://img.shields.io/github/stars/victorhugomierez/CVE-2022-26923.svg) ![forks](https://img.shields.io/github/forks/victorhugomierez/CVE-2022-26923.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wvverez/CVE-2021-41773-PoC](https://github.com/wvverez/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2021-41773-PoC.svg)


## CVE-2021-35036
 A cleartext storage of information vulnerability in the Zyxel VMG3625-T50B firmware version V5.50(ABTL.0)b2k could allow an authenticated attacker to obtain sensitive information from the configuration file.

- [https://github.com/minanagehsalalma/zyxel-cve-2021-35036-super-admin-password-leak](https://github.com/minanagehsalalma/zyxel-cve-2021-35036-super-admin-password-leak) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/zyxel-cve-2021-35036-super-admin-password-leak.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/zyxel-cve-2021-35036-super-admin-password-leak.svg)


## CVE-2021-21735
 A ZTE product has an information leak vulnerability. Due to improper permission settings, an attacker with ordinary user permissions could exploit this vulnerability to obtain some sensitive user information through the wizard page without authentication. This affects ZXHN H168N all versions up to V3.5.0_EG1T4_TE.

- [https://github.com/minanagehsalalma/cve-2021-21735-zte-zxhn-h168n-admin-compromise](https://github.com/minanagehsalalma/cve-2021-21735-zte-zxhn-h168n-admin-compromise) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/cve-2021-21735-zte-zxhn-h168n-admin-compromise.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/cve-2021-21735-zte-zxhn-h168n-admin-compromise.svg)


## CVE-2020-25078
 An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices. The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.

- [https://github.com/flags-alt/abyss-c2](https://github.com/flags-alt/abyss-c2) :  ![starts](https://img.shields.io/github/stars/flags-alt/abyss-c2.svg) ![forks](https://img.shields.io/github/forks/flags-alt/abyss-c2.svg)


## CVE-2020-2024
 An improper link resolution vulnerability affects Kata Containers versions prior to 1.11.0. Upon container teardown, a malicious guest can trick the kata-runtime into unmounting any mount point on the host and all mount points underneath it, potentiality resulting in a host DoS.

- [https://github.com/ayinedjimi/wordpress-vulnerable-lab](https://github.com/ayinedjimi/wordpress-vulnerable-lab) :  ![starts](https://img.shields.io/github/stars/ayinedjimi/wordpress-vulnerable-lab.svg) ![forks](https://img.shields.io/github/forks/ayinedjimi/wordpress-vulnerable-lab.svg)


## CVE-2018-21268
 The traceroute (aka node-traceroute) package through 1.0.0 for Node.js allows remote command injection via the host parameter. This occurs because the Child.exec() method, which is considered to be not entirely safe, is used. In particular, an OS command can be placed after a newline character.

- [https://github.com/dannyEndorTest/node-vulnerable](https://github.com/dannyEndorTest/node-vulnerable) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/node-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/node-vulnerable.svg)


## CVE-2018-14847
 MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.

- [https://github.com/mourafuseti/VULNERAVEL-CVE-2018-14847---CREDENCIAIS-EXTRAIDAS](https://github.com/mourafuseti/VULNERAVEL-CVE-2018-14847---CREDENCIAIS-EXTRAIDAS) :  ![starts](https://img.shields.io/github/stars/mourafuseti/VULNERAVEL-CVE-2018-14847---CREDENCIAIS-EXTRAIDAS.svg) ![forks](https://img.shields.io/github/forks/mourafuseti/VULNERAVEL-CVE-2018-14847---CREDENCIAIS-EXTRAIDAS.svg)


## CVE-2018-3757
 Command injection exists in pdf-image v2.0.0 due to an unescaped string parameter.

- [https://github.com/dannyEndorTest/node-vulnerable](https://github.com/dannyEndorTest/node-vulnerable) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/node-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/node-vulnerable.svg)


## CVE-2016-0714
 The session-persistence implementation in Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M2 mishandles session attributes, which allows remote authenticated users to bypass intended SecurityManager restrictions and execute arbitrary code in a privileged context via a web application that places a crafted object in a session.

- [https://github.com/dannyEndorTest/java-vulnerable](https://github.com/dannyEndorTest/java-vulnerable) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/java-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/java-vulnerable.svg)


## CVE-2013-1814
 The users/get program in the User RPC API in Apache Rave 0.11 through 0.20 allows remote authenticated users to obtain sensitive information about all user accounts via the offset parameter, as demonstrated by discovering password hashes in the password field of a response.

- [https://github.com/dannyEndorTest/java-vulnerable](https://github.com/dannyEndorTest/java-vulnerable) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/java-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/java-vulnerable.svg)

