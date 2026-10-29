# Update 2026-10-29
## CVE-2026-117532
 REDAXO core from 5.3.0 before 5.21.4 contains an authentication bypass vulnerability in the structure/history plugin that allows unauthenticated attackers to forge temporary login tokens. Attackers can force the session-tied secret into a predictable state and forge tokens for accounts like admin, gaining backend access and code execution outside live mode.

- [https://github.com/asvorg/CVE-2026-117532-poc](https://github.com/asvorg/CVE-2026-117532-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-117532-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-117532-poc.svg)


## CVE-2026-116471
 A security flaw has been discovered in BKWLD Decoy up to 5.11.1. The impacted element is an unknown function of the file Policy.php of the component Authorization Policy. The manipulation of the argument role results in improper privilege management. The attack may be performed from remote. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/solo506/bkwld-decoy-cve-2026-116471](https://github.com/solo506/bkwld-decoy-cve-2026-116471) :  ![starts](https://img.shields.io/github/stars/solo506/bkwld-decoy-cve-2026-116471.svg) ![forks](https://img.shields.io/github/forks/solo506/bkwld-decoy-cve-2026-116471.svg)


## CVE-2026-115905
 zip is a zip library for Rust that supports reading and writing simple ZIP files. Through 9.0.4, ZipArchive treats Central Directory File Header filenames as authoritative while ZipStreamReader extracts using Local File Header filenames without reconciling the duplicate metadata in src/read/stream.rs. A crafted archive can therefore appear benign to a component that inspects the central directory but cause a streaming extractor to write a different attacker-selected path and content, potentially overwriting files used by a downstream service. This issue is fixed in version 9.0.5.

- [https://github.com/foxcornlab/zip-cloaking-scanner](https://github.com/foxcornlab/zip-cloaking-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/zip-cloaking-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/zip-cloaking-scanner.svg)


## CVE-2026-115893
 Wasmtime is a runtime for WebAssembly. Prior to 36.0.19, 48.0.7, and 49.0.4, the Cranelift compiler backend on aarch64 can compile a Wasm br_table instruction with more than approximately 256,000 targets so that it has an incorrect conditional branch target. The branch can then jump to arbitrary other code at a user-controlled offset, allowing a user-controlled Wasm module to escape the sandbox on aarch64 engines using the default Cranelift backend. This issue is fixed in versions 36.0.19, 48.0.7, and 49.0.4.

- [https://github.com/shreyas-malhotra/CVE-2026-115893-wasmtime-sandbox-escape](https://github.com/shreyas-malhotra/CVE-2026-115893-wasmtime-sandbox-escape) :  ![starts](https://img.shields.io/github/stars/shreyas-malhotra/CVE-2026-115893-wasmtime-sandbox-escape.svg) ![forks](https://img.shields.io/github/forks/shreyas-malhotra/CVE-2026-115893-wasmtime-sandbox-escape.svg)


## CVE-2026-115889
 Wasmtime is a runtime for WebAssembly. Prior to 36.0.19 and 43.0.0, the Cranelift compiler backend bit-packs SSA value indices in a way that can silently overflow in release builds when compiling a sufficiently large or specially crafted Wasm function with many SSA values. The overflow can make Cranelift reference incorrect IR values, causing arbitrary miscompilation, type confusion, and other attacker-controlled effects that may escape the Wasm sandbox on any architecture using the default Cranelift backend. This issue is fixed in versions 36.0.19 and 43.0.0.

- [https://github.com/ideator-labs/wasmtime-sweep](https://github.com/ideator-labs/wasmtime-sweep) :  ![starts](https://img.shields.io/github/stars/ideator-labs/wasmtime-sweep.svg) ![forks](https://img.shields.io/github/forks/ideator-labs/wasmtime-sweep.svg)


## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/piecar21/CVE-2026-114509](https://github.com/piecar21/CVE-2026-114509) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-114509.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-114509.svg)
- [https://github.com/Nxploited/CVE-2026-114509](https://github.com/Nxploited/CVE-2026-114509) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-114509.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-114509.svg)


## CVE-2026-113870
 MongoDB Compass improperly escapes certain BSON values when converting a stored view’s aggregation pipeline into editable source. When a user connects to a MongoDB deployment containing a specially crafted view and opens that view for editing, the values can cause arbitrary code to execute with the privileges of the user running Compass.

- [https://github.com/emirwtz/CVE-2026-113870](https://github.com/emirwtz/CVE-2026-113870) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-113870.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-113870.svg)


## CVE-2026-112611
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Processing a maliciously crafted PDF file may lead to memory corruption.

- [https://github.com/Ping-2o/CVE-2026-112611-cg-shading](https://github.com/Ping-2o/CVE-2026-112611-cg-shading) :  ![starts](https://img.shields.io/github/stars/Ping-2o/CVE-2026-112611-cg-shading.svg) ![forks](https://img.shields.io/github/forks/Ping-2o/CVE-2026-112611-cg-shading.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/tal7aouy/node2shell-scanner](https://github.com/tal7aouy/node2shell-scanner) :  ![starts](https://img.shields.io/github/stars/tal7aouy/node2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/tal7aouy/node2shell-scanner.svg)
- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)
- [https://github.com/paulmann/CVE-2026-111497](https://github.com/paulmann/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/paulmann/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/paulmann/CVE-2026-111497.svg)
- [https://github.com/thebarel/CVE-2026-111497](https://github.com/thebarel/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/thebarel/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/thebarel/CVE-2026-111497.svg)
- [https://github.com/Ghost-Bx1/DotNet-HTTP2Shell-CVE-2026-111497](https://github.com/Ghost-Bx1/DotNet-HTTP2Shell-CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/DotNet-HTTP2Shell-CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/DotNet-HTTP2Shell-CVE-2026-111497.svg)
- [https://github.com/akaihigurashi/brotli2scan](https://github.com/akaihigurashi/brotli2scan) :  ![starts](https://img.shields.io/github/stars/akaihigurashi/brotli2scan.svg) ![forks](https://img.shields.io/github/forks/akaihigurashi/brotli2scan.svg)
- [https://github.com/avatarnewyork/brotli-check](https://github.com/avatarnewyork/brotli-check) :  ![starts](https://img.shields.io/github/stars/avatarnewyork/brotli-check.svg) ![forks](https://img.shields.io/github/forks/avatarnewyork/brotli-check.svg)
- [https://github.com/Nyamort/brotli-pingback-lab](https://github.com/Nyamort/brotli-pingback-lab) :  ![starts](https://img.shields.io/github/stars/Nyamort/brotli-pingback-lab.svg) ![forks](https://img.shields.io/github/forks/Nyamort/brotli-pingback-lab.svg)
- [https://github.com/depuschm/brotli-k8s-scan](https://github.com/depuschm/brotli-k8s-scan) :  ![starts](https://img.shields.io/github/stars/depuschm/brotli-k8s-scan.svg) ![forks](https://img.shields.io/github/forks/depuschm/brotli-k8s-scan.svg)


## CVE-2026-110720
 Consul-k8s versions 0.42.0 and later are vulnerable to a cross-namespace authorization bypass in component ACL binding rules that may allow an attacker to obtain elevated Consul privileges. This vulnerability (CVE-2026-110720) is fixed in consul-k8s 2.1.0 and 1.8.18.

- [https://github.com/Ghost-Bx1/ConsulK8s-CVE-2026-110720](https://github.com/Ghost-Bx1/ConsulK8s-CVE-2026-110720) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/ConsulK8s-CVE-2026-110720.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/ConsulK8s-CVE-2026-110720.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/kunshdeep2812/php2shell-scanner](https://github.com/kunshdeep2812/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/kunshdeep2812/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/kunshdeep2812/php2shell-scanner.svg)
- [https://github.com/tal7aouy/php2shell-scanner](https://github.com/tal7aouy/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/tal7aouy/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/tal7aouy/php2shell-scanner.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc](https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc) :  ![starts](https://img.shields.io/github/stars/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg) ![forks](https://img.shields.io/github/forks/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg)
- [https://github.com/open0x01/php2shell](https://github.com/open0x01/php2shell) :  ![starts](https://img.shields.io/github/stars/open0x01/php2shell.svg) ![forks](https://img.shields.io/github/forks/open0x01/php2shell.svg)
- [https://github.com/kunshdeep2812/php2shell-scanner](https://github.com/kunshdeep2812/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/kunshdeep2812/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/kunshdeep2812/php2shell-scanner.svg)


## CVE-2026-102785
 Joomla Extension - yootheme.com - Unauthenticated remote code execution in YOOtheme Pro 5.0.0-5.0.52 - YOOtheme Pro’s publicly accessible image transformation handler incompletely binds normalized image operations and the output destination to its request signature. An unauthenticated remote attacker can reuse a signature disclosed in a legitimate public image URL, inject additional image operations, traverse out of the intended cache directory, and write an attacker-controlled PNG/PHP polyglot to an executable public media directory.

- [https://github.com/piecar21/CVE-2026-102785](https://github.com/piecar21/CVE-2026-102785) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-102785.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-102785.svg)
- [https://github.com/al4n4n/CVE-2026-102785](https://github.com/al4n4n/CVE-2026-102785) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-102785.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-102785.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/piecar21/CVE-2026-101767](https://github.com/piecar21/CVE-2026-101767) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-101767.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-101767.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/YuKongA/CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/YuKongA/CVE-2026-98260.svg)
- [https://github.com/b1gmang0/CVE-2026-98260-pandora-lpe](https://github.com/b1gmang0/CVE-2026-98260-pandora-lpe) :  ![starts](https://img.shields.io/github/stars/b1gmang0/CVE-2026-98260-pandora-lpe.svg) ![forks](https://img.shields.io/github/forks/b1gmang0/CVE-2026-98260-pandora-lpe.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/G4sp4rCS/CVE-2026-97798-exploit](https://github.com/G4sp4rCS/CVE-2026-97798-exploit) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/CVE-2026-97798-exploit.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/CVE-2026-97798-exploit.svg)


## CVE-2026-97629
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/piecar21/CVE-2026-97629](https://github.com/piecar21/CVE-2026-97629) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-97629.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-97629.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/jburgess-r7/CVE-2026-97229-PoC](https://github.com/jburgess-r7/CVE-2026-97229-PoC) :  ![starts](https://img.shields.io/github/stars/jburgess-r7/CVE-2026-97229-PoC.svg) ![forks](https://img.shields.io/github/forks/jburgess-r7/CVE-2026-97229-PoC.svg)


## CVE-2026-97205
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/piecar21/CVE-2026-97205](https://github.com/piecar21/CVE-2026-97205) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-97205.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-97205.svg)


## CVE-2026-96760
 Authlib (v1.7.2 and below) contains a signature verification bypass vulnerability. The JsonWebSignature.deserialize_json() method accepts a JSON Serialization JWS object and returns the payload as successfully verified without checking for a signature and without requiring a cryptographic key.

- [https://github.com/piecar21/CVE-2026-96760](https://github.com/piecar21/CVE-2026-96760) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-96760.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-96760.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/akaihigurashi/plex2scan](https://github.com/akaihigurashi/plex2scan) :  ![starts](https://img.shields.io/github/stars/akaihigurashi/plex2scan.svg) ![forks](https://img.shields.io/github/forks/akaihigurashi/plex2scan.svg)


## CVE-2026-94300
This issue affects BIND 9 versions 9.11.0 through 9.18.50, 9.20.0 through 9.20.29, 9.21.0 through 9.21.26, 9.11.3-S1 through 9.18.50-S1, and 9.20.9-S1 through 9.20.29-S1.

- [https://github.com/emirwtz/CVE-2026-94300](https://github.com/emirwtz/CVE-2026-94300) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-94300.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-94300.svg)


## CVE-2026-93479
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-93399
 The Bookly plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 28.2 via the 'bookly_get_form_id', 'bookly_render_complete', 'bookly_add_to_calendar' and 'bookly_rollback_order' AJAX actions. This is due to the 'bookly_get_form_id' handler blindly storing the attacker-controlled 'order_id' from the submitted form_data into a new booking session, which the 'bookly_render_complete' handler then trusts to look up and return the corresponding Order's secret token without verifying that the current session created that order. This makes it possible for unauthenticated attackers to enumerate sequential order IDs, disclose other customers' order tokens, retrieve calendar/appointment information via 'bookly_add_to_calendar' and permanently delete arbitrary non-completed bookings via 'bookly_rollback_order', which cascade-deletes the customer_appointment and (when no other customers are attached) the underlying appointment.

- [https://github.com/piecar21/CVE-2026-93399](https://github.com/piecar21/CVE-2026-93399) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-93399.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-93399.svg)


## CVE-2026-93328
 Path Traversal and Missing Authorization in cloud-storage source in Google Cloud MCP Toolbox for Databases (googleapis/mcp-toolbox) versions 1.2.0 through 1.4.0 allows an unauthenticated remote attacker to exfiltrate host files to external Google Cloud Storage buckets and overwrite arbitrary local files via crafted tool invocation parameters.

- [https://github.com/sustilliano/cve-2026-93328-gate](https://github.com/sustilliano/cve-2026-93328-gate) :  ![starts](https://img.shields.io/github/stars/sustilliano/cve-2026-93328-gate.svg) ![forks](https://img.shields.io/github/forks/sustilliano/cve-2026-93328-gate.svg)


## CVE-2026-90817
 An unauthenticated Remote Code Execution vulnerability was found in the survey passthrough routing and Data Import processing logic, in which a malicious user could potentially exploit it by manipulating HTTP requests to access an unintended controller route from a public survey context and by supplying a crafted file-path/stream parameter during import handling. If successfully exploited, this could allow the attacker to remotely execute arbitrary code on the REDCap server. The attacker does not have to be authenticated in order to exploit this, but exploitation requires knowledge of a valid public survey hash. This vulnerability exists in REDCap 13.3.0 and higher.

- [https://github.com/piecar21/CVE-2026-90817](https://github.com/piecar21/CVE-2026-90817) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-90817.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-90817.svg)


## CVE-2026-89035
 MikroTik RouterOS through 7.24.5 contains a session token replay vulnerability in the WebFig interface that allows attackers to bypass authentication by replaying captured session tokens across new ECDH sessions. The makeSessionKey function in libucrypto.so generates tokens using fixed salts without incorporating channel-specific or session-specific input, and the user service validates tokens against the login store without verifying channel context, enabling stolen tokens to grant persistent administrative access until the token store is explicitly cleared. This vulnerability extends the impact of CVE-2025-61481, which identified the underlying transport-layer exposure without a corresponding fix.

- [https://github.com/emirwtz/CVE-2026-89035](https://github.com/emirwtz/CVE-2026-89035) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-89035.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-89035.svg)


## CVE-2026-84636
 An authorization issue was addressed with improved state management. This issue is fixed in iOS 27 and iPadOS 27, tvOS 27, visionOS 27, watchOS 27. An app may be able to access sensitive user data.

- [https://github.com/speedyfriend433/CVE-2026-84636-PoC](https://github.com/speedyfriend433/CVE-2026-84636-PoC) :  ![starts](https://img.shields.io/github/stars/speedyfriend433/CVE-2026-84636-PoC.svg) ![forks](https://img.shields.io/github/forks/speedyfriend433/CVE-2026-84636-PoC.svg)


## CVE-2026-80097
 Improper authentication in Microsoft Authenticator allows an unauthorized attacker to elevate privileges locally.

- [https://github.com/Ghost-Bx1/AuthenticatorFlaw-CVE-2026-80097](https://github.com/Ghost-Bx1/AuthenticatorFlaw-CVE-2026-80097) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/AuthenticatorFlaw-CVE-2026-80097.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/AuthenticatorFlaw-CVE-2026-80097.svg)


## CVE-2026-77647
 SPIP before 4.4.20 allows unauthenticated remote attackers to execute arbitrary code, as exploited in the wild in August 2026. This is related to incorrect identification of ?php blocks, and var_export's mishandling of certain cases such as presence of a '' character.

- [https://github.com/piecar21/CVE-2026-77647](https://github.com/piecar21/CVE-2026-77647) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-77647.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-77647.svg)


## CVE-2026-76475
The vulnerabilities tracked by CVE-2026-76475 are related to issues concerning improper neutralization of input during web page generation that are grouped under the Common Weakness Enumeration (CWE) Base CWE-79.

- [https://github.com/emirwtz/CVE-2026-76475](https://github.com/emirwtz/CVE-2026-76475) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-76475.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-76475.svg)


## CVE-2026-76474
The vulnerabilities tracked by CVE-2026-76474 are related to issues concerning improper authentication that are grouped under the Common Weakness Enumeration (CWE) Class CWE-287.

- [https://github.com/emirwtz/CVE-2026-76474](https://github.com/emirwtz/CVE-2026-76474) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-76474.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-76474.svg)


## CVE-2026-76473
The vulnerabilities tracked by CVE-2026-76473 are related to issues concerning improper neutralization of special elements in output used by a downstream component that are grouped under the Common Weakness Enumeration (CWE) Class CWE-74.

- [https://github.com/emirwtz/CVE-2026-76473](https://github.com/emirwtz/CVE-2026-76473) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-76473.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-76473.svg)


## CVE-2026-71195
 In OpenStack Manila before 23.0.1, multiple Manila API operations on public shares do not verify that the caller owns the share. The API controllers authorize operations against the caller's own project context, then load a foreign public share without re-authorizing against the share's actual owner. This affects the following operations: allow_access: grant data-plane read/write access to another tenant's share; deny_access: revoke the owner's existing access rules; update_access: escalate access level (e.g., ro to rw); create_share_backup: exfiltrate share data via a backup created under the attacker's project; soft_delete: move a foreign share to the recycle bin; restore: interfere with the owner's deletion workflow; export location metadata: create, update, and delete metadata on foreign export locations; access rule listing: disclose IPs, usernames, and CephFS keys. Any authenticated project member can exploit these operations on any public share. The share UUID is visible since the share is public.

- [https://github.com/emirwtz/CVE-2026-71195](https://github.com/emirwtz/CVE-2026-71195) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-71195.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-71195.svg)


## CVE-2026-70748
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-70024
 Stack-based buffer overflow in Windows Internet Information Services allows an unauthorized attacker to execute code over a network.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/Exo1i/opd2415-6.6.118-cve-2026-64560-ksu](https://github.com/Exo1i/opd2415-6.6.118-cve-2026-64560-ksu) :  ![starts](https://img.shields.io/github/stars/Exo1i/opd2415-6.6.118-cve-2026-64560-ksu.svg) ![forks](https://img.shields.io/github/forks/Exo1i/opd2415-6.6.118-cve-2026-64560-ksu.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/dexit/CVE-2026-63030](https://github.com/dexit/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/dexit/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/dexit/CVE-2026-63030.svg)


## CVE-2026-60672
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-55944
 Deserialization of untrusted data in Microsoft Dynamics NAV allows an unauthorized attacker to execute code over a network.

- [https://github.com/kipkorirchirchir800-hash/Cve-2026-55944](https://github.com/kipkorirchirchir800-hash/Cve-2026-55944) :  ![starts](https://img.shields.io/github/stars/kipkorirchirchir800-hash/Cve-2026-55944.svg) ![forks](https://img.shields.io/github/forks/kipkorirchirchir800-hash/Cve-2026-55944.svg)


## CVE-2026-53576
 Kestra is an open-source, event-driven orchestration platform. Prior to 1.0.45 and 1.3.21, the authentication filter for the REST API (@Filter("/api/v1/**")) treats any request whose path ends in /configs as the public instance-config endpoint and forwards it without a credential check. kestra addresses its resources by URL path segments that the caller chooses (/api/v1/{tenant}/flows/{namespace}, /api/v1/{tenant}/executions/{namespace}/{id}, /api/v1/{tenant}/namespaces/{namespace}/kv/{key}). An anonymous caller picks the literal configs as the final segment, and the request bypasses Basic-Auth entirely. Because the bypass reaches the flow-create and execution-trigger routes, an unauthenticated caller creates a flow containing a Shell or Process task and runs it. The task executes as root inside the kestra container. The official docker-compose.yml mounts /var/run/docker.sock, so root in the container reaches the host Docker daemon. This vulnerability is fixed in 1.0.45 and 1.3.21.

- [https://github.com/emitsco768/Vulnerability-lab-cve-2026-53576](https://github.com/emitsco768/Vulnerability-lab-cve-2026-53576) :  ![starts](https://img.shields.io/github/stars/emitsco768/Vulnerability-lab-cve-2026-53576.svg) ![forks](https://img.shields.io/github/forks/emitsco768/Vulnerability-lab-cve-2026-53576.svg)


## CVE-2026-49881
 In serviceClassExists of InCallController.java, there is a possible arbitrary code execution due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/cyb3r-w0lf/CVE-2026-49881](https://github.com/cyb3r-w0lf/CVE-2026-49881) :  ![starts](https://img.shields.io/github/stars/cyb3r-w0lf/CVE-2026-49881.svg) ![forks](https://img.shields.io/github/forks/cyb3r-w0lf/CVE-2026-49881.svg)


## CVE-2026-48356
 Adobe Commerce is affected by an Unrestricted Upload of File with Dangerous Type vulnerability that could result in arbitrary code execution in the context of the current user, potentially gaining elevated access or control over the victim's account or session. Exploitation of this issue requires user interaction in that a victim must visit a maliciously crafted URL or interact with a compromised web page. Scope is changed.

- [https://github.com/piecar21/CVE-2026-48356](https://github.com/piecar21/CVE-2026-48356) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-48356.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-48356.svg)


## CVE-2026-47291
 Integer overflow or wraparound in Windows HTTP.sys allows an unauthorized attacker to execute code over a network.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/k-o-n-t-o-r/ghostlock-sm-g990b](https://github.com/k-o-n-t-o-r/ghostlock-sm-g990b) :  ![starts](https://img.shields.io/github/stars/k-o-n-t-o-r/ghostlock-sm-g990b.svg) ![forks](https://img.shields.io/github/forks/k-o-n-t-o-r/ghostlock-sm-g990b.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.

- [https://github.com/piecar21/CVE-2026-40281](https://github.com/piecar21/CVE-2026-40281) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-40281.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-40281.svg)


## CVE-2026-35301
 Vulnerability in the WebLogic Server product of Oracle Fusion Middleware (component: Console).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise WebLogic Server.  While the vulnerability is in WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of WebLogic Server. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/piecar21/CVE-2026-33825](https://github.com/piecar21/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-33825.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/dichen-L/CVE-2026-16723-vul](https://github.com/dichen-L/CVE-2026-16723-vul) :  ![starts](https://img.shields.io/github/stars/dichen-L/CVE-2026-16723-vul.svg) ![forks](https://img.shields.io/github/forks/dichen-L/CVE-2026-16723-vul.svg)


## CVE-2026-15176
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/hktalent/cve-scanner](https://github.com/hktalent/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hktalent/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hktalent/cve-scanner.svg)
- [https://github.com/FranklinF25/cve-2026-15176](https://github.com/FranklinF25/cve-2026-15176) :  ![starts](https://img.shields.io/github/stars/FranklinF25/cve-2026-15176.svg) ![forks](https://img.shields.io/github/forks/FranklinF25/cve-2026-15176.svg)


## CVE-2026-11823
 The BookingPress Appointment Booking Pro plugin for WordPress is vulnerable to SQL Injection via the 'store_service_date' parameter of the bpa_assign_staffmember_to_slots() function in versions up to and including 5.7.1. This is due to the explicit use of stripslashes_deep() on user-supplied POST data before it is interpolated verbatim into a SQL LIKE clause without use of $wpdb-prepare() or any parameterization. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Cushz/CVE-2026-118238](https://github.com/Cushz/CVE-2026-118238) :  ![starts](https://img.shields.io/github/stars/Cushz/CVE-2026-118238.svg) ![forks](https://img.shields.io/github/forks/Cushz/CVE-2026-118238.svg)


## CVE-2026-11556
 A security flaw has been discovered in Tenda F451 1.0.0.7/1.0.0.9. Impacted is the function formWriteFacMac of the file /goform/WriteFacMac of the component Web Management Interface. Performing a manipulation of the argument mac results in os command injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/yora1928/cve_2026_115560_by_yora](https://github.com/yora1928/cve_2026_115560_by_yora) :  ![starts](https://img.shields.io/github/stars/yora1928/cve_2026_115560_by_yora.svg) ![forks](https://img.shields.io/github/forks/yora1928/cve_2026_115560_by_yora.svg)


## CVE-2026-11414
A separate path traversal vulnerability in the same download endpoint allows the configured storage root to be escaped, enabling reads of arbitrary files on the server filesystem. Combined, these issues allow an unauthenticated attacker to obtain sensitive server configuration and key material, which can lead to full server compromise. The vulnerability can be chained with CVE-2026-9152 to enumerate and bulk-download stored content. Altium 365 cloud deployments are not impacted in practice, as file storage uses object storage rather than the local filesystem.

- [https://github.com/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148](https://github.com/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148.svg)


## CVE-2026-11020
 Inappropriate implementation in Extensions in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted XML file. (Chromium security severity: Medium)

- [https://github.com/rmhowe425/POC-CVE-2026-110200](https://github.com/rmhowe425/POC-CVE-2026-110200) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-110200.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-110200.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Liquescent-Development/CVE-2026-109618-CVE-2026-109619](https://github.com/Liquescent-Development/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/Liquescent-Development/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/Liquescent-Development/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618](https://github.com/zhaoboy9692/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618.svg)
- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)


## CVE-2026-10732
This bypasses all existing path traversal protections including preventWritingThroughSymlink, added as a part of the fix for [CVE-2020-12265](https://security.snyk.io/vuln/SNYK-JS-DECOMPRESS-557358).

- [https://github.com/rmhowe425/POC-CVE-2026-107327](https://github.com/rmhowe425/POC-CVE-2026-107327) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107327.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107327.svg)
- [https://github.com/rmhowe425/POC-CVE-2026-107328](https://github.com/rmhowe425/POC-CVE-2026-107328) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107328.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107328.svg)
- [https://github.com/rmhowe425/POC-CVE-2026-107329](https://github.com/rmhowe425/POC-CVE-2026-107329) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107329.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107329.svg)


## CVE-2026-9539
 An out-of-bounds heap read and integer underflow in the TCP urgent data handling (sosendoob) in freedesktop.org libslirp version before v4.9.2 on hypervisor host environments (e.g., QEMU) allows a privileged guest VM attacker (root or CAP_NET_RAW) to leak gigabytes of sensitive host-process heap memory via sending crafted TCP segments with manipulated URG flags and urgent pointers (ti_urp).

- [https://github.com/quarkslab/slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful) :  ![starts](https://img.shields.io/github/stars/quarkslab/slirp_snapshots_stateful.svg) ![forks](https://img.shields.io/github/forks/quarkslab/slirp_snapshots_stateful.svg)


## CVE-2026-8467
This issue affects phoenix_storybook from 0.5.0 before 1.1.0.

- [https://github.com/piecar21/CVE-2026-8467](https://github.com/piecar21/CVE-2026-8467) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-8467.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-8467.svg)


## CVE-2026-5054
The specific flaw exists within the handling of command line parameters. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of root. Was ZDI-CAN-28630.

- [https://github.com/do4choo/CVE-2026-5054](https://github.com/do4choo/CVE-2026-5054) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-5054.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-5054.svg)


## CVE-2026-5053
The specific flaw exists within the handling of environment variables. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to delete files in the context of root. Was ZDI-CAN-28644.

- [https://github.com/do4choo/CVE-2026-5053](https://github.com/do4choo/CVE-2026-5053) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-5053.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-5053.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC](https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/Y5neKO/copy-fail-CVE-2026-31431-universal](https://github.com/Y5neKO/copy-fail-CVE-2026-31431-universal) :  ![starts](https://img.shields.io/github/stars/Y5neKO/copy-fail-CVE-2026-31431-universal.svg) ![forks](https://img.shields.io/github/forks/Y5neKO/copy-fail-CVE-2026-31431-universal.svg)


## CVE-2026-1306
 The midi-Synth plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type and file extension validation in the 'export' AJAX action in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible granted the attacker can obtain a valid nonce. The nonce is exposed in frontend JavaScript making it trivially accessible to unauthenticated attackers.

- [https://github.com/SecureNet-Dynamics/CVE-2026-1306](https://github.com/SecureNet-Dynamics/CVE-2026-1306) :  ![starts](https://img.shields.io/github/stars/SecureNet-Dynamics/CVE-2026-1306.svg) ![forks](https://img.shields.io/github/forks/SecureNet-Dynamics/CVE-2026-1306.svg)


## CVE-2026-1296
 The Frontend Post Submission Manager Lite plugin for WordPress is vulnerable to Open Redirection in all versions up to, and including, 1.2.7 due to insufficient validation on the 'requested_page' POST parameter in the verify_username_password function. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action such as clicking on a link.

- [https://github.com/Sadaqaty/CVE-2026-1296](https://github.com/Sadaqaty/CVE-2026-1296) :  ![starts](https://img.shields.io/github/stars/Sadaqaty/CVE-2026-1296.svg) ![forks](https://img.shields.io/github/forks/Sadaqaty/CVE-2026-1296.svg)


## CVE-2026-1277
 The URL Shortify plugin for WordPress is vulnerable to Open Redirect in all versions up to, and including, 1.12.1 due to insufficient validation on the 'redirect_to' parameter in the promotional dismissal handler. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites via a crafted link.

- [https://github.com/Sadaqaty/CVE-2026-1277](https://github.com/Sadaqaty/CVE-2026-1277) :  ![starts](https://img.shields.io/github/stars/Sadaqaty/CVE-2026-1277.svg) ![forks](https://img.shields.io/github/forks/Sadaqaty/CVE-2026-1277.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/WallcroftUK/CVE-2026-109619](https://github.com/WallcroftUK/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/WallcroftUK/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/WallcroftUK/CVE-2026-109619.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Ghost-Bx1/TomcatPartialPUT-CVE-2025-24813](https://github.com/Ghost-Bx1/TomcatPartialPUT-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/TomcatPartialPUT-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/TomcatPartialPUT-CVE-2025-24813.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/Ghost-Bx1/TomcatRace-CVE-2024-50379](https://github.com/Ghost-Bx1/TomcatRace-CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/TomcatRace-CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/TomcatRace-CVE-2024-50379.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/Dudasantluiz/Triagem-de-Explora-o-CVE-2024-49138-detectada](https://github.com/Dudasantluiz/Triagem-de-Explora-o-CVE-2024-49138-detectada) :  ![starts](https://img.shields.io/github/stars/Dudasantluiz/Triagem-de-Explora-o-CVE-2024-49138-detectada.svg) ![forks](https://img.shields.io/github/forks/Dudasantluiz/Triagem-de-Explora-o-CVE-2024-49138-detectada.svg)


## CVE-2024-47167
 Gradio is an open-source Python package designed for quick prototyping. This vulnerability relates to **Server-Side Request Forgery (SSRF)** in the `/queue/join` endpoint. Gradio’s `async_save_url_to_cache` function allows attackers to force the Gradio server to send HTTP requests to user-controlled URLs. This could enable attackers to target internal servers or services within a local network and possibly exfiltrate data or cause unwanted internal requests. Additionally, the content from these URLs is stored locally, making it easier for attackers to upload potentially malicious files to the server. This impacts users deploying Gradio servers that use components like the Video component which involve URL fetching. Users are advised to upgrade to `gradio=5` to address this issue.  As a workaround, users can disable or heavily restrict URL-based inputs in their Gradio applications to trusted domains only. Additionally, implementing stricter URL validation (such as allowinglist-based validation) and ensuring that local or internal network addresses cannot be requested via the `/queue/join` endpoint can help mitigate the risk of SSRF attacks.

- [https://github.com/piecar21/CVE-2024-47167](https://github.com/piecar21/CVE-2024-47167) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2024-47167.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2024-47167.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/Cracked5pider/eop24-26229](https://github.com/Cracked5pider/eop24-26229) :  ![starts](https://img.shields.io/github/stars/Cracked5pider/eop24-26229.svg) ![forks](https://img.shields.io/github/forks/Cracked5pider/eop24-26229.svg)


## CVE-2024-5509
The specific flaw exists within the parsing of BIP files. The issue results from loading a library from an unsecured location. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-22738.

- [https://github.com/Pwned007/CVE-2024-55090](https://github.com/Pwned007/CVE-2024-55090) :  ![starts](https://img.shields.io/github/stars/Pwned007/CVE-2024-55090.svg) ![forks](https://img.shields.io/github/forks/Pwned007/CVE-2024-55090.svg)


## CVE-2024-1561
 An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables.

- [https://github.com/ImYangC7/hdu-is-lab1](https://github.com/ImYangC7/hdu-is-lab1) :  ![starts](https://img.shields.io/github/stars/ImYangC7/hdu-is-lab1.svg) ![forks](https://img.shields.io/github/forks/ImYangC7/hdu-is-lab1.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/Charly-bite/SITEUR](https://github.com/Charly-bite/SITEUR) :  ![starts](https://img.shields.io/github/stars/Charly-bite/SITEUR.svg) ![forks](https://img.shields.io/github/forks/Charly-bite/SITEUR.svg)


## CVE-2023-7356
the service UUID is Basic Audio Announcement Service UUID.

- [https://github.com/emirwtz/CVE-2023-7356](https://github.com/emirwtz/CVE-2023-7356) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2023-7356.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2023-7356.svg)


## CVE-2022-30781
 Gitea before 1.16.7 does not escape git fetch remote.

- [https://github.com/403ArkhamS3c/cve-gitea](https://github.com/403ArkhamS3c/cve-gitea) :  ![starts](https://img.shields.io/github/stars/403ArkhamS3c/cve-gitea.svg) ![forks](https://img.shields.io/github/forks/403ArkhamS3c/cve-gitea.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)
- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Jiahe114514/hdu-is-lab1-secure-api](https://github.com/Jiahe114514/hdu-is-lab1-secure-api) :  ![starts](https://img.shields.io/github/stars/Jiahe114514/hdu-is-lab1-secure-api.svg) ![forks](https://img.shields.io/github/forks/Jiahe114514/hdu-is-lab1-secure-api.svg)


## CVE-2021-42694
 An issue was discovered in the character definitions of the Unicode Specification through 14.0. The specification allows an adversary to produce source code identifiers such as function names using homoglyphs that render visually identical to a target identifier. Adversaries can leverage this to inject code via adversarial identifier definitions in upstream software dependencies invoked deceptively in downstream software. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard (all versions). Unless mitigated, an adversary could produce source code identifiers using homoglyph characters that render visually identical to but are distinct from a target identifier. In this way, an adversary could inject adversarial identifier definitions in upstream software that are not detected by human reviewers and are invoked deceptively in downstream software. The Unicode Consortium has documented this class of security vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms.

- [https://github.com/mehul82099/trojan-source-check](https://github.com/mehul82099/trojan-source-check) :  ![starts](https://img.shields.io/github/stars/mehul82099/trojan-source-check.svg) ![forks](https://img.shields.io/github/forks/mehul82099/trojan-source-check.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard and the Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-right and right-to-left characters, the visual order of tokens may be different from their logical order. Additionally, control characters needed to fully support the requirements of bidirectional text can further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such that the ordering of tokens perceived by human reviewers does not match what will be processed by a compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.

- [https://github.com/mehul82099/trojan-source-check](https://github.com/mehul82099/trojan-source-check) :  ![starts](https://img.shields.io/github/stars/mehul82099/trojan-source-check.svg) ![forks](https://img.shields.io/github/forks/mehul82099/trojan-source-check.svg)


## CVE-2021-26088
 An improper authentication vulnerability in FSSO Collector version 5.0.295 and below may allow an unauthenticated user to bypass a FSSO firewall policy and access the protected network via sending specifically crafted UDP login notification packets.

- [https://github.com/theogobinet/CVE-2021-26088](https://github.com/theogobinet/CVE-2021-26088) :  ![starts](https://img.shields.io/github/stars/theogobinet/CVE-2021-26088.svg) ![forks](https://img.shields.io/github/forks/theogobinet/CVE-2021-26088.svg)


## CVE-2021-26086
 Affected versions of Atlassian Jira Server and Data Center allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint. The affected versions are before version 8.5.14, from version 8.6.0 before 8.13.6, and from version 8.14.0 before 8.16.1.

- [https://github.com/ColdFusionX/CVE-2021-26086](https://github.com/ColdFusionX/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-26086.svg)
- [https://github.com/Jeromeyoung/CVE-2021-26086](https://github.com/Jeromeyoung/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-26086.svg)
- [https://github.com/Official-BlackHat13/CVE-2021-26086](https://github.com/Official-BlackHat13/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/Official-BlackHat13/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/Official-BlackHat13/CVE-2021-26086.svg)


## CVE-2021-26085
 Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a Pre-Authorization Arbitrary File Read vulnerability in the /s/ endpoint. The affected versions are before version 7.4.10, and from version 7.5.0 before 7.12.3.

- [https://github.com/ColdFusionX/CVE-2021-26085](https://github.com/ColdFusionX/CVE-2021-26085) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-26085.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-26085.svg)
- [https://github.com/zeroc00I/CVE-2021-26085](https://github.com/zeroc00I/CVE-2021-26085) :  ![starts](https://img.shields.io/github/stars/zeroc00I/CVE-2021-26085.svg) ![forks](https://img.shields.io/github/forks/zeroc00I/CVE-2021-26085.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/hev0x/CVE-2021-26084_Confluence](https://github.com/hev0x/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2021-26084_Confluence.svg)
- [https://github.com/sma11new/PocList](https://github.com/sma11new/PocList) :  ![starts](https://img.shields.io/github/stars/sma11new/PocList.svg) ![forks](https://img.shields.io/github/forks/sma11new/PocList.svg)
- [https://github.com/0xf4n9x/CVE-2021-26084](https://github.com/0xf4n9x/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-26084.svg)
- [https://github.com/dinhbaouit/CVE-2021-26084](https://github.com/dinhbaouit/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/dinhbaouit/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/dinhbaouit/CVE-2021-26084.svg)
- [https://github.com/alt3kx/CVE-2021-26084_PoC](https://github.com/alt3kx/CVE-2021-26084_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2021-26084_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2021-26084_PoC.svg)
- [https://github.com/1ZRR4H/CVE-2021-26084](https://github.com/1ZRR4H/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/1ZRR4H/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/1ZRR4H/CVE-2021-26084.svg)
- [https://github.com/crowsec-edtech/CVE-2021-26084](https://github.com/crowsec-edtech/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/crowsec-edtech/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/crowsec-edtech/CVE-2021-26084.svg)
- [https://github.com/ZZ-SOCMAP/CVE-2021-26084](https://github.com/ZZ-SOCMAP/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/ZZ-SOCMAP/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/ZZ-SOCMAP/CVE-2021-26084.svg)
- [https://github.com/Vulnmachines/Confluence_CVE-2021-26084](https://github.com/Vulnmachines/Confluence_CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Confluence_CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Confluence_CVE-2021-26084.svg)
- [https://github.com/taythebot/CVE-2021-26084](https://github.com/taythebot/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/taythebot/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/taythebot/CVE-2021-26084.svg)
- [https://github.com/lleavesl/CVE-2021-26084](https://github.com/lleavesl/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/lleavesl/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/lleavesl/CVE-2021-26084.svg)
- [https://github.com/JKme/CVE-2021-26084](https://github.com/JKme/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/JKme/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/JKme/CVE-2021-26084.svg)
- [https://github.com/BBD-YZZ/Confluence-RCE](https://github.com/BBD-YZZ/Confluence-RCE) :  ![starts](https://img.shields.io/github/stars/BBD-YZZ/Confluence-RCE.svg) ![forks](https://img.shields.io/github/forks/BBD-YZZ/Confluence-RCE.svg)
- [https://github.com/orangmuda/CVE-2021-26084](https://github.com/orangmuda/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/orangmuda/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/orangmuda/CVE-2021-26084.svg)
- [https://github.com/Loneyers/CVE-2021-26084](https://github.com/Loneyers/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Loneyers/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Loneyers/CVE-2021-26084.svg)
- [https://github.com/BeRserKerSec/CVE-2021-26084-Nuclei-template](https://github.com/BeRserKerSec/CVE-2021-26084-Nuclei-template) :  ![starts](https://img.shields.io/github/stars/BeRserKerSec/CVE-2021-26084-Nuclei-template.svg) ![forks](https://img.shields.io/github/forks/BeRserKerSec/CVE-2021-26084-Nuclei-template.svg)
- [https://github.com/ludy-dev/CVE-2021-26084_PoC](https://github.com/ludy-dev/CVE-2021-26084_PoC) :  ![starts](https://img.shields.io/github/stars/ludy-dev/CVE-2021-26084_PoC.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/CVE-2021-26084_PoC.svg)
- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)
- [https://github.com/toowoxx/docker-confluence-patched](https://github.com/toowoxx/docker-confluence-patched) :  ![starts](https://img.shields.io/github/stars/toowoxx/docker-confluence-patched.svg) ![forks](https://img.shields.io/github/forks/toowoxx/docker-confluence-patched.svg)
- [https://github.com/prettyrecon/CVE-2021-26084_Confluence](https://github.com/prettyrecon/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/prettyrecon/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/prettyrecon/CVE-2021-26084_Confluence.svg)
- [https://github.com/TheclaMcentire/CVE-2021-26084_Confluence](https://github.com/TheclaMcentire/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/TheclaMcentire/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/TheclaMcentire/CVE-2021-26084_Confluence.svg)
- [https://github.com/Jun-5heng/CVE-2021-26084](https://github.com/Jun-5heng/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-26084.svg)
- [https://github.com/nahcusira/CVE-2021-26084](https://github.com/nahcusira/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/nahcusira/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/nahcusira/CVE-2021-26084.svg)
- [https://github.com/nizar0x1f/CVE-2021-26084-patch-](https://github.com/nizar0x1f/CVE-2021-26084-patch-) :  ![starts](https://img.shields.io/github/stars/nizar0x1f/CVE-2021-26084-patch-.svg) ![forks](https://img.shields.io/github/forks/nizar0x1f/CVE-2021-26084-patch-.svg)
- [https://github.com/GlennPegden2/cve-2021-26084-confluence](https://github.com/GlennPegden2/cve-2021-26084-confluence) :  ![starts](https://img.shields.io/github/stars/GlennPegden2/cve-2021-26084-confluence.svg) ![forks](https://img.shields.io/github/forks/GlennPegden2/cve-2021-26084-confluence.svg)
- [https://github.com/bcdannyboy/CVE-2021-26084_GoPOC](https://github.com/bcdannyboy/CVE-2021-26084_GoPOC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/CVE-2021-26084_GoPOC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/CVE-2021-26084_GoPOC.svg)
- [https://github.com/b1gw00d/CVE-2021-26084](https://github.com/b1gw00d/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/b1gw00d/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/b1gw00d/CVE-2021-26084.svg)
- [https://github.com/CrackerCat/CVE-2021-26084](https://github.com/CrackerCat/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-26084.svg)
- [https://github.com/attacker-codeninja/CVE-2021-26084](https://github.com/attacker-codeninja/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/attacker-codeninja/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/attacker-codeninja/CVE-2021-26084.svg)
- [https://github.com/Xc1Ym/cve_2021_26084](https://github.com/Xc1Ym/cve_2021_26084) :  ![starts](https://img.shields.io/github/stars/Xc1Ym/cve_2021_26084.svg) ![forks](https://img.shields.io/github/forks/Xc1Ym/cve_2021_26084.svg)
- [https://github.com/wdjcy/CVE-2021-26084](https://github.com/wdjcy/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/wdjcy/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/wdjcy/CVE-2021-26084.svg)
- [https://github.com/maskerTUI/CVE-2021-26084](https://github.com/maskerTUI/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/maskerTUI/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/maskerTUI/CVE-2021-26084.svg)
- [https://github.com/Jeromeyoung/CVE-2021-26086](https://github.com/Jeromeyoung/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-26086.svg)
- [https://github.com/30579096/Confluence-CVE-2021-26084](https://github.com/30579096/Confluence-CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/30579096/Confluence-CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/30579096/Confluence-CVE-2021-26084.svg)
- [https://github.com/smallpiggy/cve-2021-26084-confluence](https://github.com/smallpiggy/cve-2021-26084-confluence) :  ![starts](https://img.shields.io/github/stars/smallpiggy/cve-2021-26084-confluence.svg) ![forks](https://img.shields.io/github/forks/smallpiggy/cve-2021-26084-confluence.svg)
- [https://github.com/wolf1892/confluence-rce-poc](https://github.com/wolf1892/confluence-rce-poc) :  ![starts](https://img.shields.io/github/stars/wolf1892/confluence-rce-poc.svg) ![forks](https://img.shields.io/github/forks/wolf1892/confluence-rce-poc.svg)
- [https://github.com/Osyanina/westone-CVE-2021-26084-scanner](https://github.com/Osyanina/westone-CVE-2021-26084-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-26084-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-26084-scanner.svg)
- [https://github.com/quesodipesto/conflucheck](https://github.com/quesodipesto/conflucheck) :  ![starts](https://img.shields.io/github/stars/quesodipesto/conflucheck.svg) ![forks](https://img.shields.io/github/forks/quesodipesto/conflucheck.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)


## CVE-2019-16759
 vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code] parameter in an ajax/render/widget_php routestring request.

- [https://github.com/shavchen/CVE-2019-16759](https://github.com/shavchen/CVE-2019-16759) :  ![starts](https://img.shields.io/github/stars/shavchen/CVE-2019-16759.svg) ![forks](https://img.shields.io/github/forks/shavchen/CVE-2019-16759.svg)


## CVE-2019-3403
 The /rest/api/2/user/picker rest resource in Jira before version 7.13.3, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1 allows remote attackers to enumerate usernames via an incorrect authorisation check.

- [https://github.com/davidmckennirey/CVE-2019-3403](https://github.com/davidmckennirey/CVE-2019-3403) :  ![starts](https://img.shields.io/github/stars/davidmckennirey/CVE-2019-3403.svg) ![forks](https://img.shields.io/github/forks/davidmckennirey/CVE-2019-3403.svg)
- [https://github.com/und3sc0n0c1d0/UserEnumJira](https://github.com/und3sc0n0c1d0/UserEnumJira) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/UserEnumJira.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/UserEnumJira.svg)


## CVE-2018-17246
 Kibana versions before 6.4.3 and 5.6.13 contain an arbitrary file inclusion flaw in the Console plugin. An attacker with access to the Kibana Console API could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/ght657/work1-secure-api](https://github.com/ght657/work1-secure-api) :  ![starts](https://img.shields.io/github/stars/ght657/work1-secure-api.svg) ![forks](https://img.shields.io/github/forks/ght657/work1-secure-api.svg)


## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution

- [https://github.com/keitan339/primefaces-cve-2017-1000486](https://github.com/keitan339/primefaces-cve-2017-1000486) :  ![starts](https://img.shields.io/github/stars/keitan339/primefaces-cve-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/keitan339/primefaces-cve-2017-1000486.svg)


## CVE-2017-8295
 WordPress through 4.7.4 relies on the Host HTTP header for a password-reset e-mail message, which makes it easier for remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword request and then arranging for this message to bounce or be resent, leading to transmission of the reset key to a mailbox on an attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in conjunction with the PHP mail function. Exploitation is not achievable in all cases because it requires at least one of the following: (1) the attacker can prevent the victim from receiving any e-mail messages for an extended period of time (such as 5 days), (2) the victim's e-mail system sends an autoresponse containing the original message, or (3) the victim manually composes a reply containing the original message.

- [https://github.com/cyberheartmi9/CVE-2017-8295](https://github.com/cyberheartmi9/CVE-2017-8295) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2017-8295.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2017-8295.svg)
- [https://github.com/alash3al/wp-allowed-hosts](https://github.com/alash3al/wp-allowed-hosts) :  ![starts](https://img.shields.io/github/stars/alash3al/wp-allowed-hosts.svg) ![forks](https://img.shields.io/github/forks/alash3al/wp-allowed-hosts.svg)


## CVE-2017-0806
 An elevation of privilege vulnerability in the Android framework (gatekeeperresponse). Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-62998805.

- [https://github.com/michalbednarski/ReparcelBug](https://github.com/michalbednarski/ReparcelBug) :  ![starts](https://img.shields.io/github/stars/michalbednarski/ReparcelBug.svg) ![forks](https://img.shields.io/github/forks/michalbednarski/ReparcelBug.svg)


## CVE-2015-6612
 libmedia in Android before 5.1.1 LMY48X and 6.0 before 2015-11-01 allows attackers to gain privileges via a crafted application, aka internal bug 23540426.

- [https://github.com/secmob/CVE-2015-6612](https://github.com/secmob/CVE-2015-6612) :  ![starts](https://img.shields.io/github/stars/secmob/CVE-2015-6612.svg) ![forks](https://img.shields.io/github/forks/secmob/CVE-2015-6612.svg)
- [https://github.com/flankerhqd/cve-2015-6612poc-forM](https://github.com/flankerhqd/cve-2015-6612poc-forM) :  ![starts](https://img.shields.io/github/stars/flankerhqd/cve-2015-6612poc-forM.svg) ![forks](https://img.shields.io/github/forks/flankerhqd/cve-2015-6612poc-forM.svg)


## CVE-2015-3673
 Admin Framework in Apple OS X before 10.10.4 does not properly restrict the location of writeconfig clients, which allows local users to obtain root privileges by moving and then modifying Directory Utility.

- [https://github.com/sideeffect42/RootPipeTester](https://github.com/sideeffect42/RootPipeTester) :  ![starts](https://img.shields.io/github/stars/sideeffect42/RootPipeTester.svg) ![forks](https://img.shields.io/github/forks/sideeffect42/RootPipeTester.svg)


## CVE-2015-1701
 Win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in April 2015, aka "Win32k Elevation of Privilege Vulnerability."

- [https://github.com/Anonymous-Family/CVE-2015-1701](https://github.com/Anonymous-Family/CVE-2015-1701) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2015-1701.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2015-1701.svg)
- [https://github.com/Anonymous-Family/CVE-2015-1701-download](https://github.com/Anonymous-Family/CVE-2015-1701-download) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2015-1701-download.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2015-1701-download.svg)
- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2014-8757
 LG On-Screen Phone (OSP) before 4.3.010 allows remote attackers to bypass authorization via a crafted request.

- [https://github.com/irsl/lgosp-poc](https://github.com/irsl/lgosp-poc) :  ![starts](https://img.shields.io/github/stars/irsl/lgosp-poc.svg) ![forks](https://img.shields.io/github/forks/irsl/lgosp-poc.svg)


## CVE-2014-6598
 Unspecified vulnerability in the Oracle Communications Diameter Signaling Router component in Oracle Communications Applications 3.x, 4.x, and 5.0 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Signaling - DPI.

- [https://github.com/KPN-CISO/DRA_writeup](https://github.com/KPN-CISO/DRA_writeup) :  ![starts](https://img.shields.io/github/stars/KPN-CISO/DRA_writeup.svg) ![forks](https://img.shields.io/github/forks/KPN-CISO/DRA_writeup.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/ItzSteve04/shellshock-linux-host-hardening-lab](https://github.com/ItzSteve04/shellshock-linux-host-hardening-lab) :  ![starts](https://img.shields.io/github/stars/ItzSteve04/shellshock-linux-host-hardening-lab.svg) ![forks](https://img.shields.io/github/forks/ItzSteve04/shellshock-linux-host-hardening-lab.svg)


## CVE-2014-3153
 The futex_requeue function in kernel/futex.c in the Linux kernel through 3.14.5 does not ensure that calls have two different futex addresses, which allows local users to gain privileges via a crafted FUTEX_REQUEUE command that facilitates unsafe waiter modification.

- [https://github.com/lastowl/lg-webos2-root](https://github.com/lastowl/lg-webos2-root) :  ![starts](https://img.shields.io/github/stars/lastowl/lg-webos2-root.svg) ![forks](https://img.shields.io/github/forks/lastowl/lg-webos2-root.svg)


## CVE-2014-1303
 Heap-based buffer overflow in Apple Safari 7.0.2 allows remote attackers to execute arbitrary code and bypass a sandbox protection mechanism via unspecified vectors, as demonstrated by Liang Chen during a Pwn2Own competition at CanSecWest 2014.

- [https://github.com/RKX1209/CVE-2014-1303](https://github.com/RKX1209/CVE-2014-1303) :  ![starts](https://img.shields.io/github/stars/RKX1209/CVE-2014-1303.svg) ![forks](https://img.shields.io/github/forks/RKX1209/CVE-2014-1303.svg)


## CVE-2011-3389
 The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a "BEAST" attack.

- [https://github.com/mpgn/BEAST-PoC](https://github.com/mpgn/BEAST-PoC) :  ![starts](https://img.shields.io/github/stars/mpgn/BEAST-PoC.svg) ![forks](https://img.shields.io/github/forks/mpgn/BEAST-PoC.svg)


## CVE-2009-4092
 Cross-site request forgery (CSRF) vulnerability in user.php in Simplog 0.9.3.2, and possibly earlier, allows remote attackers to hijack the authentication of administrators and users for requests that change passwords.

- [https://github.com/xiaoyu-iid/Simplog-Exploit](https://github.com/xiaoyu-iid/Simplog-Exploit) :  ![starts](https://img.shields.io/github/stars/xiaoyu-iid/Simplog-Exploit.svg) ![forks](https://img.shields.io/github/forks/xiaoyu-iid/Simplog-Exploit.svg)


## CVE-2009-3555
 The TLS protocol, and the SSL protocol 3.0 and possibly earlier, as used in Microsoft Internet Information Services (IIS) 7.0, mod_ssl in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5 and earlier, Mozilla Network Security Services (NSS) 3.12.4 and earlier, multiple Cisco products, and other products, does not properly associate renegotiation handshakes with an existing connection, which allows man-in-the-middle attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context, related to a "plaintext injection" attack, aka the "Project Mogul" issue.

- [https://github.com/johnwchadwick/cve-2009-3555-test-server](https://github.com/johnwchadwick/cve-2009-3555-test-server) :  ![starts](https://img.shields.io/github/stars/johnwchadwick/cve-2009-3555-test-server.svg) ![forks](https://img.shields.io/github/forks/johnwchadwick/cve-2009-3555-test-server.svg)


## CVE-2008-2938
 Directory traversal vulnerability in Apache Tomcat 4.1.0 through 4.1.37, 5.5.0 through 5.5.26, and 6.0.0 through 6.0.16, when allowLinking and UTF-8 are enabled, allows remote attackers to read arbitrary files via encoded directory traversal sequences in the URI, a different vulnerability than CVE-2008-2370.  NOTE: versions earlier than 6.0.18 were reported affected, but the vendor advisory lists 6.0.16 as the last affected version.

- [https://github.com/Naramsim/Offensive](https://github.com/Naramsim/Offensive) :  ![starts](https://img.shields.io/github/stars/Naramsim/Offensive.svg) ![forks](https://img.shields.io/github/forks/Naramsim/Offensive.svg)

