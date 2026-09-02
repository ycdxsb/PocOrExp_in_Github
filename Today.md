# Update 2026-09-02
## CVE-2026-82222
This issue affects GiveWP: from n/a through 4.16.7.1.

- [https://github.com/R0x19/CVE-2026-82222](https://github.com/R0x19/CVE-2026-82222) :  ![starts](https://img.shields.io/github/stars/R0x19/CVE-2026-82222.svg) ![forks](https://img.shields.io/github/forks/R0x19/CVE-2026-82222.svg)


## CVE-2026-79483
 FastGPT Community Edition 4.10.0 through 4.14.0 are vulnerable to a NoSQL injection in the POST /api/core/chat/getHistories endpoint. An unauthenticated attacker can inject malicious NoSQL operators via crafted JSON payloads to bypass authorization checks, resulting in unauthorized access to chat history titles of all users across the platform.

- [https://github.com/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection](https://github.com/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection) :  ![starts](https://img.shields.io/github/stars/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection.svg) ![forks](https://img.shields.io/github/forks/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection.svg)


## CVE-2026-76569
 Joomla Extension - phoca.cz - Reflected XSS via the search GET parameter in Phoca Download 5.0.0-6.1.4

- [https://github.com/toanln-cov/CVE-2026-76569](https://github.com/toanln-cov/CVE-2026-76569) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-76569.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-76569.svg)


## CVE-2026-71851
 crypto-js is a JavaScript library of crypto standards. Versions of crypto-js prior to 4.0.0 generate randomness in CryptoJS.lib.WordArray.random() using a custom variation of the Multiply-With-Carry pseudorandom number generator, seeded from Math.random(), instead of a cryptographically secure source. This generator was introduced in version 3.1.2-4 and remained present in nearly every 3.x release. Nominal requests for 128 or 256 bits of entropy through this function produce effective search spaces of approximately 2 to the 39th and 2 to the 47th possibilities, small enough to enumerate on commodity hardware. Downstream wallet applications that used CryptoJS.lib.WordArray.random() as the entropy source for BIP39 recovery phrases are affected, and an attacker who enumerates the reduced output space can recover the resulting private keys and control the associated funds. This issue is fixed in version 4.0.0.

- [https://github.com/brendonlee20042004-sys/weakrng-sweep](https://github.com/brendonlee20042004-sys/weakrng-sweep) :  ![starts](https://img.shields.io/github/stars/brendonlee20042004-sys/weakrng-sweep.svg) ![forks](https://img.shields.io/github/forks/brendonlee20042004-sys/weakrng-sweep.svg)


## CVE-2026-62735
 Heap-based buffer overflow in Windows HTTP.sys allows an authorized attacker to elevate privileges locally.

- [https://github.com/nhh9905/CVE-2026-62735](https://github.com/nhh9905/CVE-2026-62735) :  ![starts](https://img.shields.io/github/stars/nhh9905/CVE-2026-62735.svg) ![forks](https://img.shields.io/github/forks/nhh9905/CVE-2026-62735.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/xiaohj233/ghostlock-x200-app](https://github.com/xiaohj233/ghostlock-x200-app) :  ![starts](https://img.shields.io/github/stars/xiaohj233/ghostlock-x200-app.svg) ![forks](https://img.shields.io/github/forks/xiaohj233/ghostlock-x200-app.svg)


## CVE-2026-39816
 The optional extension component TinkerpopClientService is missing the Restricted annotation with the Execute Code Required Permission in Apache NiFi 2.0.0-M1 through 2.8.0. The TinkerpopClientService supports configuration of ByteCode Submission for the Script Submission Type, enabling Groovy Script execution in the service prior to submitting the query. The missing Restricted annotation allows users without the Execute Code Permission to configure the Service in installations that use fine-grained authorization and have the optional TinkerpopClientService installed. Apache NiFi installations that do not have the nifi-other-graph-services-nar installed are not subject to this vulnerability. Upgrading to Apache NiFi 2.9.0 is the recommended mitigation.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-30252
 Multiple reflected cross-site scripting (XSS) vulnerabilities in the login.php endpoint of Interzen Consulting S.r.l ZenShare Suite v17.0 allows attackers to execute arbitrary Javascript in the context of the user's browser via a crafted URL injected into the codice_azienda and red_url parameters.

- [https://github.com/vEnablee/CVE-2026-30252](https://github.com/vEnablee/CVE-2026-30252) :  ![starts](https://img.shields.io/github/stars/vEnablee/CVE-2026-30252.svg) ![forks](https://img.shields.io/github/forks/vEnablee/CVE-2026-30252.svg)


## CVE-2026-30251
 A reflected cross-site scripting (XSS) vulnerability in the login_newpwd.php endpoint of Interzen Consulting S.r.l ZenShare Suite v17.0 allows attackers to execute arbitrary Javascript in the context of the user's browser via a crafted URL injected into the codice_azienda parameter.

- [https://github.com/vEnablee/CVE-2026-30251](https://github.com/vEnablee/CVE-2026-30251) :  ![starts](https://img.shields.io/github/stars/vEnablee/CVE-2026-30251.svg) ![forks](https://img.shields.io/github/forks/vEnablee/CVE-2026-30251.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-7474
 HashiCorp Nomad and Nomad Enterprise prior to 2.0.1 are vulnerable to code execution on the client host through a path traversal attack. This vulnerability (CVE-2026-7474) is fixed in Nomad 2.0.1, 1.11.5 and 1.10.11.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-5006
This vulnerability, CVE-2026-5006, was fixed in Vault Community Edition 2.0.4 and Vault Enterprise 2.0.4, 1.21.9, 1.20.14, and 1.19.20.

- [https://github.com/M4xSec/My-Exploits](https://github.com/M4xSec/My-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/My-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/My-Exploits.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/villager1314/CVE-2026-43499-IQOO-Neo10-Analysis](https://github.com/villager1314/CVE-2026-43499-IQOO-Neo10-Analysis) :  ![starts](https://img.shields.io/github/stars/villager1314/CVE-2026-43499-IQOO-Neo10-Analysis.svg) ![forks](https://img.shields.io/github/forks/villager1314/CVE-2026-43499-IQOO-Neo10-Analysis.svg)


## CVE-2026-3819
 A vulnerability has been found in SourceCodester Resort Reservation System 1.0. The affected element is an unknown function of the file /?page=manage_reservation of the component Reservation Management Module. Such manipulation of the argument ID leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ming1700/CVE-2026-38192](https://github.com/ming1700/CVE-2026-38192) :  ![starts](https://img.shields.io/github/stars/ming1700/CVE-2026-38192.svg) ![forks](https://img.shields.io/github/forks/ming1700/CVE-2026-38192.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/naheeju/POC-CVE-2026-0073](https://github.com/naheeju/POC-CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/naheeju/POC-CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/naheeju/POC-CVE-2026-0073.svg)


## CVE-2025-69080
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in JanStudio Gecko gecko allows PHP Local File Inclusion.This issue affects Gecko: from n/a through = 1.9.8.

- [https://github.com/AndrielSec/CVE-2025-69080](https://github.com/AndrielSec/CVE-2025-69080) :  ![starts](https://img.shields.io/github/stars/AndrielSec/CVE-2025-69080.svg) ![forks](https://img.shields.io/github/forks/AndrielSec/CVE-2025-69080.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/NymiiTechTips/CVE-2025-59528](https://github.com/NymiiTechTips/CVE-2025-59528) :  ![starts](https://img.shields.io/github/stars/NymiiTechTips/CVE-2025-59528.svg) ![forks](https://img.shields.io/github/forks/NymiiTechTips/CVE-2025-59528.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-20333
 This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests. An attacker with valid VPN user credentials could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute arbitrary code as root, possibly resulting in the complete compromise of the affected device.

- [https://github.com/cobbbex/cve-2025-20333](https://github.com/cobbbex/cve-2025-20333) :  ![starts](https://img.shields.io/github/stars/cobbbex/cve-2025-20333.svg) ![forks](https://img.shields.io/github/forks/cobbbex/cve-2025-20333.svg)


## CVE-2025-20197
 Note: The attacker must have privileges to enter configuration mode on the affected device. This is usually referred to as privilege level 15.

- [https://github.com/KaraRyougi/CVE-2025-20197-POC](https://github.com/KaraRyougi/CVE-2025-20197-POC) :  ![starts](https://img.shields.io/github/stars/KaraRyougi/CVE-2025-20197-POC.svg) ![forks](https://img.shields.io/github/forks/KaraRyougi/CVE-2025-20197-POC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/nicecopy/POC-CVE-2025-5777](https://github.com/nicecopy/POC-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/nicecopy/POC-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/nicecopy/POC-CVE-2025-5777.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-0324
 The VAPIX Device Configuration framework allowed a privilege escalation, enabling a lower-privileged user to gain administrator privileges.

- [https://github.com/kemrec/CVE-2025-0324-axis-vapix-privesc](https://github.com/kemrec/CVE-2025-0324-axis-vapix-privesc) :  ![starts](https://img.shields.io/github/stars/kemrec/CVE-2025-0324-axis-vapix-privesc.svg) ![forks](https://img.shields.io/github/forks/kemrec/CVE-2025-0324-axis-vapix-privesc.svg)


## CVE-2024-41570
 An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

- [https://github.com/UnDefinedCS/HavocPwn](https://github.com/UnDefinedCS/HavocPwn) :  ![starts](https://img.shields.io/github/stars/UnDefinedCS/HavocPwn.svg) ![forks](https://img.shields.io/github/forks/UnDefinedCS/HavocPwn.svg)


## CVE-2023-49792
 Nextcloud Server provides data storage for Nextcloud, an open source cloud platform. In Nextcloud Server prior to versions 26.0.9 and 27.1.4; as well as Nextcloud Enterprise Server prior to versions 23.0.12.13, 24.0.12.9, 25.0.13.4, 26.0.9, and 27.1.4; when a (reverse) proxy is configured as trusted proxy the server could be tricked into reading a wrong remote address for an attacker, allowing them executing authentication attempts than intended. Nextcloud Server versions 26.0.9 and 27.1.4 and Nextcloud Enterprise Server versions 23.0.12.13, 24.0.12.9, 25.0.13.4, 26.0.9, and 27.1.4 contain a patch for this issue. No known workarounds are available.

- [https://github.com/CStockdale1/nextcloud-cve-2023-49792-research](https://github.com/CStockdale1/nextcloud-cve-2023-49792-research) :  ![starts](https://img.shields.io/github/stars/CStockdale1/nextcloud-cve-2023-49792-research.svg) ![forks](https://img.shields.io/github/forks/CStockdale1/nextcloud-cve-2023-49792-research.svg)


## CVE-2023-39361
 Cacti is an open source operational monitoring and fault management framework. Affected versions are subject to a SQL injection discovered in graph_view.php. Since guest users can access graph_view.php without authentication by default, if guest users are being utilized in an enabled state, there could be the potential for significant damage. Attackers may exploit this vulnerability, and there may be possibilities for actions such as the usurpation of administrative privileges or remote code execution. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/spartanx-alejandro/cacti-cve-2023-39361](https://github.com/spartanx-alejandro/cacti-cve-2023-39361) :  ![starts](https://img.shields.io/github/stars/spartanx-alejandro/cacti-cve-2023-39361.svg) ![forks](https://img.shields.io/github/forks/spartanx-alejandro/cacti-cve-2023-39361.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/Amperclock/CVE-2023-32784-kdbxpassdmp](https://github.com/Amperclock/CVE-2023-32784-kdbxpassdmp) :  ![starts](https://img.shields.io/github/stars/Amperclock/CVE-2023-32784-kdbxpassdmp.svg) ![forks](https://img.shields.io/github/forks/Amperclock/CVE-2023-32784-kdbxpassdmp.svg)


## CVE-2023-26493
 Cocos Engine is an open-source framework for building 2D & 3D real-time rendering and interactive content. In the github repo for Cocos Engine the `web-interface-check.yml` was subject to command injection. The `web-interface-check.yml` was triggered when a pull request was opened or updated and contained the user controllable field `(${{ github.head_ref }} – the name of the fork’s branch)`. This would allow an attacker to take over the GitHub Runner and run custom commands (potentially stealing secrets such as GITHUB_TOKEN) and altering the repository. The workflow has since been removed for the repository. There are no actions required of users.

- [https://github.com/pvharmo2/gha-lab-fb32aba4a3](https://github.com/pvharmo2/gha-lab-fb32aba4a3) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-fb32aba4a3.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-fb32aba4a3.svg)


## CVE-2023-6572
 Command Injection in GitHub repository gradio-app/gradio prior to main.

- [https://github.com/pvharmo2/gha-lab-6255f5fc33](https://github.com/pvharmo2/gha-lab-6255f5fc33) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-6255f5fc33.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-6255f5fc33.svg)


## CVE-2022-29117
 .NET and Visual Studio Denial of Service Vulnerability

- [https://github.com/CharanMv08/cve-2022-29117-assessment](https://github.com/CharanMv08/cve-2022-29117-assessment) :  ![starts](https://img.shields.io/github/stars/CharanMv08/cve-2022-29117-assessment.svg) ![forks](https://img.shields.io/github/forks/CharanMv08/cve-2022-29117-assessment.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-21423
 `projen` is a project generation tool that synthesizes project configuration files such as `package.json`, `tsconfig.json`, `.gitignore`, GitHub Workflows, `eslint`, `jest`, and more, from a well-typed definition written in JavaScript. Users of projen's `NodeProject` project type (including any project type derived from it) include a `.github/workflows/rebuild-bot.yml` workflow that may allow any GitHub user to trigger execution of un-trusted code in the context of the "main" repository (as opposed to that of a fork). In some situations, such untrusted code may potentially be able to commit to the "main" repository. The rebuild-bot workflow is triggered by comments including `@projen rebuild` on pull-request to trigger a re-build of the projen project, and updating the pull request with the updated files. This workflow is triggered by an `issue_comment` event, and thus always executes with a `GITHUB_TOKEN` belonging to the repository into which the pull-request is made (this is in contrast with workflows triggered by `pull_request` events, which always execute with a `GITHUB_TOKEN` belonging to the repository from which the pull-request is made). Repositories that do not have branch protection configured on their default branch (typically `main` or `master`) could possibly allow an untrusted user to gain access to secrets configured on the repository (such as NPM tokens, etc). Branch protection prohibits this escalation, as the managed `GITHUB_TOKEN` would not be able to modify the contents of a protected branch and affected workflows must be defined on the default branch.

- [https://github.com/pvharmo2/gha-lab-b9842b12c0](https://github.com/pvharmo2/gha-lab-b9842b12c0) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-b9842b12c0.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-b9842b12c0.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4281
 A vulnerability was found in Brave UX for-the-badge and classified as critical. Affected by this issue is some unknown functionality of the file .github/workflows/combine-prs.yml. The manipulation leads to os command injection. The name of the patch is 55b5a234c0fab935df5fb08365bc8fe9c37cf46b. It is recommended to apply a patch to fix this issue. VDB-216842 is the identifier assigned to this vulnerability.

- [https://github.com/pvharmo2/gha-lab-232af4821f](https://github.com/pvharmo2/gha-lab-232af4821f) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-232af4821f.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-232af4821f.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/r3dw4n48m3d/CVE-2021-3493-Exploit](https://github.com/r3dw4n48m3d/CVE-2021-3493-Exploit) :  ![starts](https://img.shields.io/github/stars/r3dw4n48m3d/CVE-2021-3493-Exploit.svg) ![forks](https://img.shields.io/github/forks/r3dw4n48m3d/CVE-2021-3493-Exploit.svg)


## CVE-2018-14667
 The RichFaces Framework 3.X through 3.3.4 is vulnerable to Expression Language (EL) injection via the UserResource resource. A remote, unauthenticated attacker could exploit this to execute arbitrary code using a chain of java serialized objects via org.ajax4jsf.resource.UserResource$UriData.

- [https://github.com/r4ch1d0/CVE-2018-14667_Lab_POC](https://github.com/r4ch1d0/CVE-2018-14667_Lab_POC) :  ![starts](https://img.shields.io/github/stars/r4ch1d0/CVE-2018-14667_Lab_POC.svg) ![forks](https://img.shields.io/github/forks/r4ch1d0/CVE-2018-14667_Lab_POC.svg)


## CVE-2015-5254
 Apache ActiveMQ 5.x before 5.13.0 does not restrict the classes that can be serialized in the broker, which allows remote attackers to execute arbitrary code via a crafted serialized Java Message Service (JMS) ObjectMessage object.

- [https://github.com/radsih/activemq-cve-lab](https://github.com/radsih/activemq-cve-lab) :  ![starts](https://img.shields.io/github/stars/radsih/activemq-cve-lab.svg) ![forks](https://img.shields.io/github/forks/radsih/activemq-cve-lab.svg)

