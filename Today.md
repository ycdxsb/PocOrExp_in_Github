# Update 2026-07-04
## CVE-2026-58116
 LLaMA-Factory through 0.9.5 contains a remote code execution vulnerability that allows attackers with WebUI access to execute arbitrary Python code by supplying a malicious model path in the Chat or Training interfaces. The application passes user-supplied model path input unvalidated into AutoTokenizer.from_pretrained() and AutoModel.from_pretrained() with a hardcoded trust_remote_code=True parameter, causing the Hugging Face transformers library to fetch and execute arbitrary code from a remote or local model repository with the privileges of the server process.

- [https://github.com/Hunt-Benito/llama-factory-webui-rce-cve-2026-58116-trust-remote-code-model-path-injection](https://github.com/Hunt-Benito/llama-factory-webui-rce-cve-2026-58116-trust-remote-code-model-path-injection) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/llama-factory-webui-rce-cve-2026-58116-trust-remote-code-model-path-injection.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/llama-factory-webui-rce-cve-2026-58116-trust-remote-code-model-path-injection.svg)


## CVE-2026-56782
 Gorse before 0.5.10 contains an authentication bypass vulnerability in the /api/dump and /api/restore endpoints that allows unauthenticated attackers to access protected functionality when admin_api_key is empty, which is the default configuration. Remote attackers can exfiltrate the entire database including user records, items, and feedback data containing personally identifiable information, or completely overwrite the dataset without authentication.

- [https://github.com/thecodeb0ss/CVE-2026-56782](https://github.com/thecodeb0ss/CVE-2026-56782) :  ![starts](https://img.shields.io/github/stars/thecodeb0ss/CVE-2026-56782.svg) ![forks](https://img.shields.io/github/forks/thecodeb0ss/CVE-2026-56782.svg)


## CVE-2026-52813
 Gogs is an open source self-hosted Git service. Prior to 0.14.3, organization names containing path traversal sequences (../) are accepted by Gogs, and repositories under them are written to paths following these path traversals. This allows storing/retrieving data for repositories at arbitrary locations on the filesystem. By creating nested structure of Git repositories, one can overwrite the other's hooks configuration to result in Remote Code Execution (RCE). This vulnerability is fixed in 0.14.3.

- [https://github.com/thecodeb0ss/CVE-2026-52813](https://github.com/thecodeb0ss/CVE-2026-52813) :  ![starts](https://img.shields.io/github/stars/thecodeb0ss/CVE-2026-52813.svg) ![forks](https://img.shields.io/github/forks/thecodeb0ss/CVE-2026-52813.svg)


## CVE-2026-48558
 SimpleHelp versions 5.5.15 and prior and 6.0 pre-release versions contain an authentication bypass vulnerability in the OIDC authentication flow. When OIDC authentication is configured, identity tokens submitted during login are accepted without verifying their cryptographic signature. In a vulnerable configuration, a remote, unauthenticated attacker can submit a forged token containing arbitrary identity claims to obtain a fully authenticated technician session. In some configurations, this may also allow bypass of multi-factor authentication. No user interaction is required.

- [https://github.com/J4ck3LSyN-Gen2/CVE-2026-48558](https://github.com/J4ck3LSyN-Gen2/CVE-2026-48558) :  ![starts](https://img.shields.io/github/stars/J4ck3LSyN-Gen2/CVE-2026-48558.svg) ![forks](https://img.shields.io/github/forks/J4ck3LSyN-Gen2/CVE-2026-48558.svg)


## CVE-2026-45498
 Microsoft Defender Denial of Service Vulnerability

- [https://github.com/salihuahmad105-creator/Vulnerability-scanner](https://github.com/salihuahmad105-creator/Vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/salihuahmad105-creator/Vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/salihuahmad105-creator/Vulnerability-scanner.svg)


## CVE-2026-38751
 OpenSTAManager version 2.10 and earlier contains an arbitrary file upload vulnerability in the module update functionality (modules/aggiornamenti/upload_modules.php)

- [https://github.com/Mkps/CVE-2026-38751-OpenSTAManager-Arbitrary-File-Upload-PoC](https://github.com/Mkps/CVE-2026-38751-OpenSTAManager-Arbitrary-File-Upload-PoC) :  ![starts](https://img.shields.io/github/stars/Mkps/CVE-2026-38751-OpenSTAManager-Arbitrary-File-Upload-PoC.svg) ![forks](https://img.shields.io/github/forks/Mkps/CVE-2026-38751-OpenSTAManager-Arbitrary-File-Upload-PoC.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/c0gnit00/CVE-2026-33017](https://github.com/c0gnit00/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2026-33017.svg)


## CVE-2026-30784
 This CVE ID has been withdrawn by its CVE Numbering Authority.

- [https://github.com/malejdj/CVE-2026-30784-rustdesk-poc](https://github.com/malejdj/CVE-2026-30784-rustdesk-poc) :  ![starts](https://img.shields.io/github/stars/malejdj/CVE-2026-30784-rustdesk-poc.svg) ![forks](https://img.shields.io/github/forks/malejdj/CVE-2026-30784-rustdesk-poc.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/vrtlbob/Linux-Kernel-Vulnerabilities-CVE-2026-23111](https://github.com/vrtlbob/Linux-Kernel-Vulnerabilities-CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/vrtlbob/Linux-Kernel-Vulnerabilities-CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/vrtlbob/Linux-Kernel-Vulnerabilities-CVE-2026-23111.svg)


## CVE-2026-13768
 Gardyn devices expose a privileged iothubowner key. Access to this key will allow a malicious user to invoke an IoTHub Registry Manager function which returns connection information for all Gardyn Home Kit and Studio devices. Access to this key also allows a malicious user to execute arbitrary commands on a specific connected device and may allow the malicious user to pivot to other devices on the user's network.

- [https://github.com/MichaelAdamGroberman/CVE-2026-13768](https://github.com/MichaelAdamGroberman/CVE-2026-13768) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-13768.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-13768.svg)


## CVE-2026-12168
 An improper validation vulnerability for driver `GFAC_Sys_x64.sys` in Little Orbit GFAC allows a local attacker to escalate privileges to SYSTEM and execute arbitrary code in kernel mode via crafted messages sent through a Minifilter communication port.

- [https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168](https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168) :  ![starts](https://img.shields.io/github/stars/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168.svg) ![forks](https://img.shields.io/github/forks/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168.svg)


## CVE-2026-12167
 The Minifilter communication port for driver `GFAC_Sys_x64.sys` in Little Orbit GFAC allows a local attacker to access privileged driver functionality via a communication interface that lacks appropriate access restrictions.

- [https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168](https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168) :  ![starts](https://img.shields.io/github/stars/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168.svg) ![forks](https://img.shields.io/github/forks/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168.svg)


## CVE-2026-12166
 A NULL pointer dereference vulnerability for driver `GFAC_Sys_x64.sys` in Little Orbit GFAC allows a local attacker to cause a denial of service via crafted requests that trigger a system crash.

- [https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168](https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168) :  ![starts](https://img.shields.io/github/stars/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168.svg) ![forks](https://img.shields.io/github/forks/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168.svg)


## CVE-2026-8451
 Insufficient input validation in NetScaler ADC and NetScaler Gateway leading to memory overread if NetScaler ADC or NetScaler Gateway is configured as a SAML IDP

- [https://github.com/attarwahyup/Netscaler-CVE-2026-8451](https://github.com/attarwahyup/Netscaler-CVE-2026-8451) :  ![starts](https://img.shields.io/github/stars/attarwahyup/Netscaler-CVE-2026-8451.svg) ![forks](https://img.shields.io/github/forks/attarwahyup/Netscaler-CVE-2026-8451.svg)


## CVE-2026-5572
 A security flaw has been discovered in Technostrobe HI-LED-WR120-G2 5.5.0.1R6.03.30. This affects an unknown function. Performing a manipulation results in cross-site request forgery. The attack can be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/MichaelAdamGroberman/CVE-2026-55726](https://github.com/MichaelAdamGroberman/CVE-2026-55726) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-55726.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-55726.svg)


## CVE-2026-5447
 Heap buffer overflow in CertFromX509 via AuthorityKeyIdentifier size confusion. A heap buffer overflow occurs when converting an X.509 certificate internally due to incorrect size handling of the AuthorityKeyIdentifier extension.

- [https://github.com/MichaelAdamGroberman/CVE-2026-54477](https://github.com/MichaelAdamGroberman/CVE-2026-54477) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-54477.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-54477.svg)


## CVE-2026-5442
 A heap buffer overflow vulnerability exists in the DICOM image decoder. Dimension fields are encoded using Value Representation (VR) Unsigned Long (UL), instead of the expected VR Unsigned Short (US), which allows extremely large dimensions to be processed. This causes an integer overflow during frame size calculation and results in out-of-bounds memory access during image decoding.

- [https://github.com/tomadimitrie/CVE-2026-54424](https://github.com/tomadimitrie/CVE-2026-54424) :  ![starts](https://img.shields.io/github/stars/tomadimitrie/CVE-2026-54424.svg) ![forks](https://img.shields.io/github/forks/tomadimitrie/CVE-2026-54424.svg)


## CVE-2026-4772
This issue affects WAF-ASP: from v1.0.324.900 before v1.4.0.117.

- [https://github.com/0xBlackash/CVE-2026-47729](https://github.com/0xBlackash/CVE-2026-47729) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-47729.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-47729.svg)


## CVE-2026-4767
This issue affects WAF-ASP: from v1.0.324.900 before v1.4.0.117.

- [https://github.com/error-inside/CVE-2026-47670](https://github.com/error-inside/CVE-2026-47670) :  ![starts](https://img.shields.io/github/stars/error-inside/CVE-2026-47670.svg) ![forks](https://img.shields.io/github/forks/error-inside/CVE-2026-47670.svg)


## CVE-2026-2089
 A vulnerability was found in SourceCodester Online Class Record System 1.0. This vulnerability affects unknown code of the file /admin/subject/controller.php. Performing a manipulation of the argument ID results in sql injection. Remote exploitation of the attack is possible. The exploit has been made public and could be used.

- [https://github.com/kaleth4/CVE-2026-20896](https://github.com/kaleth4/CVE-2026-20896) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-20896.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-20896.svg)


## CVE-2026-0740
 The Ninja Forms - File Uploads plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'NF_FU_AJAX_Controllers_Uploads::handle_upload' function in all versions up to, and including, 3.3.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability was partially patched in version 3.3.25 and fully patched in version 3.3.27.

- [https://github.com/BastianXploited/CVE-2026-0740-mass](https://github.com/BastianXploited/CVE-2026-0740-mass) :  ![starts](https://img.shields.io/github/stars/BastianXploited/CVE-2026-0740-mass.svg) ![forks](https://img.shields.io/github/forks/BastianXploited/CVE-2026-0740-mass.svg)


## CVE-2025-69212
 OpenSTAManager is an open source management software for technical assistance and invoicing. In 2.9.8 and earlier, a critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.

- [https://github.com/c0gnit00/CVE-2026-69212](https://github.com/c0gnit00/CVE-2026-69212) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2026-69212.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2026-69212.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/K3ysTr0K3R/CVE-2025-57819](https://github.com/K3ysTr0K3R/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2025-57819.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/sentinel-aidefense/CVE-2025-5777](https://github.com/sentinel-aidefense/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2025-5777.svg)


## CVE-2024-31449
 Redis is an open source, in-memory database that persists on disk. An authenticated user may use a specially crafted Lua script to trigger a stack buffer overflow in the bit library, which may potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This problem has been fixed in Redis versions 6.2.16, 7.2.6, and 7.4.1. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/qwqqaqqwq00/opensource_defect_repare_cc](https://github.com/qwqqaqqwq00/opensource_defect_repare_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repare_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repare_cc.svg)
- [https://github.com/qwqqaqqwq00/opensource_defect_repair_cc](https://github.com/qwqqaqqwq00/opensource_defect_repair_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repair_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repair_cc.svg)


## CVE-2024-27102
 Wings is the server control plane for Pterodactyl Panel. This vulnerability impacts anyone running the affected versions of Wings. The vulnerability can potentially be used to access files and directories on the host system. The full scope of impact is exactly unknown, but reading files outside of a server's base directory (sandbox root) is possible. In order to use this exploit, an attacker must have an existing "server" allocated and controlled by Wings. Details on the exploitation of this vulnerability are embargoed until March 27th, 2024 at 18:00 UTC. In order to mitigate this vulnerability, a full rewrite of the entire server filesystem was necessary. Because of this, the size of the patch is massive, however effort was made to reduce the amount of breaking changes. Users are advised to update to version 1.11.9. There are no known workarounds for this vulnerability.

- [https://github.com/wyllowSec/Magnohost-Vulnerabilities-pentest](https://github.com/wyllowSec/Magnohost-Vulnerabilities-pentest) :  ![starts](https://img.shields.io/github/stars/wyllowSec/Magnohost-Vulnerabilities-pentest.svg) ![forks](https://img.shields.io/github/forks/wyllowSec/Magnohost-Vulnerabilities-pentest.svg)


## CVE-2024-1900
The user will stay authenticated until the Devolutions Server token expiration.

- [https://github.com/mindcodings/cve-2024-19002](https://github.com/mindcodings/cve-2024-19002) :  ![starts](https://img.shields.io/github/stars/mindcodings/cve-2024-19002.svg) ![forks](https://img.shields.io/github/forks/mindcodings/cve-2024-19002.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/mindcodings/CVE-2024-0204](https://github.com/mindcodings/CVE-2024-0204) :  ![starts](https://img.shields.io/github/stars/mindcodings/CVE-2024-0204.svg) ![forks](https://img.shields.io/github/forks/mindcodings/CVE-2024-0204.svg)


## CVE-2023-25155
 Redis is an in-memory database that persists on disk. Authenticated users issuing specially crafted `SRANDMEMBER`, `ZRANDMEMBER`, and `HRANDFIELD` commands can trigger an integer overflow, resulting in a runtime assertion and termination of the Redis server process. This problem affects all Redis versions. Patches were released in Redis version(s) 6.0.18, 6.2.11 and 7.0.9.

- [https://github.com/qwqqaqqwq00/opensource_defect_repare_cc](https://github.com/qwqqaqqwq00/opensource_defect_repare_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repare_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repare_cc.svg)
- [https://github.com/qwqqaqqwq00/opensource_defect_repair_cc](https://github.com/qwqqaqqwq00/opensource_defect_repair_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repair_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repair_cc.svg)


## CVE-2023-22527
Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.

- [https://github.com/mindcodings/CVE-2023-22527](https://github.com/mindcodings/CVE-2023-22527) :  ![starts](https://img.shields.io/github/stars/mindcodings/CVE-2023-22527.svg) ![forks](https://img.shields.io/github/forks/mindcodings/CVE-2023-22527.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/ivanovick1/Windows_AFD_LPE_CVE-2023-21768](https://github.com/ivanovick1/Windows_AFD_LPE_CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/ivanovick1/Windows_AFD_LPE_CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/ivanovick1/Windows_AFD_LPE_CVE-2023-21768.svg)


## CVE-2022-36021
 Redis is an in-memory database that persists on disk. Authenticated users can use string matching commands (like `SCAN` or `KEYS`) with a specially crafted pattern to trigger a denial-of-service attack on Redis, causing it to hang and consume 100% CPU time. The problem is fixed in Redis versions 6.0.18, 6.2.11, 7.0.9.

- [https://github.com/qwqqaqqwq00/opensource_defect_repare_cc](https://github.com/qwqqaqqwq00/opensource_defect_repare_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repare_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repare_cc.svg)
- [https://github.com/qwqqaqqwq00/opensource_defect_repair_cc](https://github.com/qwqqaqqwq00/opensource_defect_repair_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repair_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repair_cc.svg)


## CVE-2022-31144
 Redis is an in-memory database that persists on disk. A specially crafted `XAUTOCLAIM` command on a stream key in a specific state may result with heap overflow, and potentially remote code execution. This problem affects versions on the 7.x branch prior to 7.0.4. The patch is released in version 7.0.4.

- [https://github.com/qwqqaqqwq00/opensource_defect_repare_cc](https://github.com/qwqqaqqwq00/opensource_defect_repare_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repare_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repare_cc.svg)
- [https://github.com/qwqqaqqwq00/opensource_defect_repair_cc](https://github.com/qwqqaqqwq00/opensource_defect_repair_cc) :  ![starts](https://img.shields.io/github/stars/qwqqaqqwq00/opensource_defect_repair_cc.svg) ![forks](https://img.shields.io/github/forks/qwqqaqqwq00/opensource_defect_repair_cc.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit](https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2020-9529
 Firmware developed by Shenzhen Hichip Vision Technology (V6 through V20), as used by many different vendors in millions of Internet of Things devices, suffers from a privilege escalation vulnerability that allows attackers on the local network to reset the device's administrator password. This affects products marketed under the following brand names: Accfly, Alptop, Anlink, Besdersec, BOAVISION, COOAU, CPVAN, Ctronics, D3D Security, Dericam, Elex System, Elite Security, ENSTER, ePGes, Escam, FLOUREON, GENBOLT, Hongjingtian (HJT), ICAMI, Iegeek, Jecurity, Jennov, KKMoon, LEFTEK, Loosafe, Luowice, Nesuniq, Nettoly, ProElite, QZT, Royallite, SDETER, SV3C, SY2L, Tenvis, ThinkValue, TOMLOV, TPTEK, WGCC, and ZILINK.

- [https://github.com/prisect/hichipreset](https://github.com/prisect/hichipreset) :  ![starts](https://img.shields.io/github/stars/prisect/hichipreset.svg) ![forks](https://img.shields.io/github/forks/prisect/hichipreset.svg)


## CVE-2007-6750
 The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.

- [https://github.com/sarjanpatel22/siem-threat-detection-lab](https://github.com/sarjanpatel22/siem-threat-detection-lab) :  ![starts](https://img.shields.io/github/stars/sarjanpatel22/siem-threat-detection-lab.svg) ![forks](https://img.shields.io/github/forks/sarjanpatel22/siem-threat-detection-lab.svg)

