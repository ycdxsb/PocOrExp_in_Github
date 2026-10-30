# Update 2026-10-30
## CVE-2026-116692
 MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. From 3.12.0rc0 until 3.17.0, third-party scorer deserialization in mlflow/genai/scorers/base.py accepts request-selected descendants of THIRD_PARTY_SCORER_ALLOWED_MODULES rather than requiring an exact allowed module. A caller can use MLflow artifact endpoints to place a Python module beneath a writable allowed package and submit its module and class through /ajax-api/3.0/mlflow/scorer/invoke. Scorer.model_validate_json() imports the module and constructs the class before trace processing. Authentication-disabled deployments permit this code execution without credentials, while basic-auth deployments require a principal capable of creating an experiment and run and uploading artifacts. In either configuration, the allowed scorer package must be writable by the server process. This issue is fixed in version 3.17.0.

- [https://github.com/foxcornlab/mlflow-scorer-scanner](https://github.com/foxcornlab/mlflow-scorer-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/mlflow-scorer-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/mlflow-scorer-scanner.svg)


## CVE-2026-115905
 zip is a zip library for Rust that supports reading and writing simple ZIP files. Through 9.0.4, ZipArchive treats Central Directory File Header filenames as authoritative while ZipStreamReader extracts using Local File Header filenames without reconciling the duplicate metadata in src/read/stream.rs. A crafted archive can therefore appear benign to a component that inspects the central directory but cause a streaming extractor to write a different attacker-selected path and content, potentially overwriting files used by a downstream service. This issue is fixed in version 9.0.5.

- [https://github.com/cosmonic-labs/demo-zip-rce-sandbox](https://github.com/cosmonic-labs/demo-zip-rce-sandbox) :  ![starts](https://img.shields.io/github/stars/cosmonic-labs/demo-zip-rce-sandbox.svg) ![forks](https://img.shields.io/github/forks/cosmonic-labs/demo-zip-rce-sandbox.svg)


## CVE-2026-114625
Hosted, including Dedicated, versions of VCO were impacted and have already been patched.

- [https://github.com/emirwtz/CVE-2026-114625](https://github.com/emirwtz/CVE-2026-114625) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-114625.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-114625.svg)


## CVE-2026-114595
 In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocated with an incorrect size. Subsequent handling of attacker supplied data may result in memory corruption, denial of service, or potential remote code execution.

- [https://github.com/0xBlackash/CVE-2026-114595](https://github.com/0xBlackash/CVE-2026-114595) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-114595.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-114595.svg)


## CVE-2026-112706
 A permissions issue was addressed with additional restrictions. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, tvOS 27.2, visionOS 27.2, watchOS 27.2. An app may be able to access sensitive user data.

- [https://github.com/MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak](https://github.com/MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak) :  ![starts](https://img.shields.io/github/stars/MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak.svg) ![forks](https://img.shields.io/github/forks/MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/gik2927/CVE-2026-111497-DOS-](https://github.com/gik2927/CVE-2026-111497-DOS-) :  ![starts](https://img.shields.io/github/stars/gik2927/CVE-2026-111497-DOS-.svg) ![forks](https://img.shields.io/github/forks/gik2927/CVE-2026-111497-DOS-.svg)
- [https://github.com/axisops/CVE-2026-111497](https://github.com/axisops/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/axisops/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/axisops/CVE-2026-111497.svg)
- [https://github.com/suominen/CVE-2026-111497](https://github.com/suominen/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-111497.svg)
- [https://github.com/caveeroo/cve-2026-111497-wordpress-poc](https://github.com/caveeroo/cve-2026-111497-wordpress-poc) :  ![starts](https://img.shields.io/github/stars/caveeroo/cve-2026-111497-wordpress-poc.svg) ![forks](https://img.shields.io/github/forks/caveeroo/cve-2026-111497-wordpress-poc.svg)
- [https://github.com/amier-ge/Node2Shell](https://github.com/amier-ge/Node2Shell) :  ![starts](https://img.shields.io/github/stars/amier-ge/Node2Shell.svg) ![forks](https://img.shields.io/github/forks/amier-ge/Node2Shell.svg)
- [https://github.com/hkoeck/node2shell-status](https://github.com/hkoeck/node2shell-status) :  ![starts](https://img.shields.io/github/stars/hkoeck/node2shell-status.svg) ![forks](https://img.shields.io/github/forks/hkoeck/node2shell-status.svg)
- [https://github.com/Quaerendir/node2shell-audit](https://github.com/Quaerendir/node2shell-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/node2shell-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/node2shell-audit.svg)


## CVE-2026-110063
 Improper link resolution before file access ('link following') in VM Inspector for Azure Virtual Machines allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/emirwtz/CVE-2026-110063](https://github.com/emirwtz/CVE-2026-110063) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-110063.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-110063.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/akaihigurashi/php2scan](https://github.com/akaihigurashi/php2scan) :  ![starts](https://img.shields.io/github/stars/akaihigurashi/php2scan.svg) ![forks](https://img.shields.io/github/forks/akaihigurashi/php2scan.svg)
- [https://github.com/gkwelding/php2shell-ioc-check](https://github.com/gkwelding/php2shell-ioc-check) :  ![starts](https://img.shields.io/github/stars/gkwelding/php2shell-ioc-check.svg) ![forks](https://img.shields.io/github/forks/gkwelding/php2shell-ioc-check.svg)
- [https://github.com/KtebhTeam/php2shell](https://github.com/KtebhTeam/php2shell) :  ![starts](https://img.shields.io/github/stars/KtebhTeam/php2shell.svg) ![forks](https://img.shields.io/github/forks/KtebhTeam/php2shell.svg)
- [https://github.com/sonuoffsec/php2shell-detector](https://github.com/sonuoffsec/php2shell-detector) :  ![starts](https://img.shields.io/github/stars/sonuoffsec/php2shell-detector.svg) ![forks](https://img.shields.io/github/forks/sonuoffsec/php2shell-detector.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/akaihigurashi/php2scan](https://github.com/akaihigurashi/php2scan) :  ![starts](https://img.shields.io/github/stars/akaihigurashi/php2scan.svg) ![forks](https://img.shields.io/github/forks/akaihigurashi/php2scan.svg)
- [https://github.com/murat-levi/php2shell-poc](https://github.com/murat-levi/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/murat-levi/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/murat-levi/php2shell-poc.svg)
- [https://github.com/gkwelding/php2shell-ioc-check](https://github.com/gkwelding/php2shell-ioc-check) :  ![starts](https://img.shields.io/github/stars/gkwelding/php2shell-ioc-check.svg) ![forks](https://img.shields.io/github/forks/gkwelding/php2shell-ioc-check.svg)


## CVE-2026-105482
This vulnerability affects Node.js 26.x, 24.x, and 22.x.

- [https://github.com/EthanTech-Offical/CVE-2026-105482-Reproduce](https://github.com/EthanTech-Offical/CVE-2026-105482-Reproduce) :  ![starts](https://img.shields.io/github/stars/EthanTech-Offical/CVE-2026-105482-Reproduce.svg) ![forks](https://img.shields.io/github/forks/EthanTech-Offical/CVE-2026-105482-Reproduce.svg)


## CVE-2026-105014
 Improper neutralization of special elements used in a command ('command injection') in Azure Pipelines allows an unauthorized attacker to execute code over a network.

- [https://github.com/emirwtz/CVE-2026-105014](https://github.com/emirwtz/CVE-2026-105014) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-105014.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-105014.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Sable-Research/CVE-2026-101767-research](https://github.com/Sable-Research/CVE-2026-101767-research) :  ![starts](https://img.shields.io/github/stars/Sable-Research/CVE-2026-101767-research.svg) ![forks](https://img.shields.io/github/forks/Sable-Research/CVE-2026-101767-research.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/4627488/cve-2026-98260-nezha](https://github.com/4627488/cve-2026-98260-nezha) :  ![starts](https://img.shields.io/github/stars/4627488/cve-2026-98260-nezha.svg) ![forks](https://img.shields.io/github/forks/4627488/cve-2026-98260-nezha.svg)
- [https://github.com/zjns/CVE-2026-98260](https://github.com/zjns/CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/zjns/CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/zjns/CVE-2026-98260.svg)
- [https://github.com/NanoTurtle1145/cve-2026-98260-uaf](https://github.com/NanoTurtle1145/cve-2026-98260-uaf) :  ![starts](https://img.shields.io/github/stars/NanoTurtle1145/cve-2026-98260-uaf.svg) ![forks](https://img.shields.io/github/forks/NanoTurtle1145/cve-2026-98260-uaf.svg)
- [https://github.com/Again1996-bit/CVE-2026-98260-GhostKey](https://github.com/Again1996-bit/CVE-2026-98260-GhostKey) :  ![starts](https://img.shields.io/github/stars/Again1996-bit/CVE-2026-98260-GhostKey.svg) ![forks](https://img.shields.io/github/forks/Again1996-bit/CVE-2026-98260-GhostKey.svg)
- [https://github.com/colorgarden/CVE-2026-98260-y700-TB321FU-lpe](https://github.com/colorgarden/CVE-2026-98260-y700-TB321FU-lpe) :  ![starts](https://img.shields.io/github/stars/colorgarden/CVE-2026-98260-y700-TB321FU-lpe.svg) ![forks](https://img.shields.io/github/forks/colorgarden/CVE-2026-98260-y700-TB321FU-lpe.svg)
- [https://github.com/kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot) :  ![starts](https://img.shields.io/github/stars/kpgc10kai/TimerRoot.svg) ![forks](https://img.shields.io/github/forks/kpgc10kai/TimerRoot.svg)


## CVE-2026-97785
 Improper authentication in AAD App Proxy allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/emirwtz/CVE-2026-97785](https://github.com/emirwtz/CVE-2026-97785) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-97785.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-97785.svg)


## CVE-2026-97631
and Availability.

- [https://github.com/slabbdev/uefi-pxe-cve-2026-97631](https://github.com/slabbdev/uefi-pxe-cve-2026-97631) :  ![starts](https://img.shields.io/github/stars/slabbdev/uefi-pxe-cve-2026-97631.svg) ![forks](https://img.shields.io/github/forks/slabbdev/uefi-pxe-cve-2026-97631.svg)
- [https://github.com/Try2Take/CVE-2026-97631-PoC](https://github.com/Try2Take/CVE-2026-97631-PoC) :  ![starts](https://img.shields.io/github/stars/Try2Take/CVE-2026-97631-PoC.svg) ![forks](https://img.shields.io/github/forks/Try2Take/CVE-2026-97631-PoC.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/CompleTech-Security/sharp-rsvg-rce-check](https://github.com/CompleTech-Security/sharp-rsvg-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/sharp-rsvg-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/sharp-rsvg-rce-check.svg)


## CVE-2026-96778
 Pillow is a Python imaging library. From 9.4.0 until 13.0.0, ImagingJpegEncode() in src/libImaging/JpegEncode.c can call jpeg_write_marker() for a JPEG COM comment when an ICC profile has exactly filled the 65536-byte encoder buffer. libjpeg writes one byte before checking the exhausted free_in_buffer counter, which then wraps and permits the attacker-controlled comment and subsequent compressed image data to overwrite adjacent heap memory. Re-saving an untrusted image as JPEG while preserving its ICC profile and forwarded comment can crash the process and may enable code execution in suitable runtime and heap layouts. This issue is fixed in version 13.0.0.

- [https://github.com/paktiko1986/CVE-2026-96778-pillow](https://github.com/paktiko1986/CVE-2026-96778-pillow) :  ![starts](https://img.shields.io/github/stars/paktiko1986/CVE-2026-96778-pillow.svg) ![forks](https://img.shields.io/github/forks/paktiko1986/CVE-2026-96778-pillow.svg)


## CVE-2026-93903
 LiteSpeed Web Server (LSWS) before 6.3.7 build 1 mishandles internal redirect URL validation in a certain "corner case."

- [https://github.com/Tautvydas-Aleliunas/CVE-2026-93903](https://github.com/Tautvydas-Aleliunas/CVE-2026-93903) :  ![starts](https://img.shields.io/github/stars/Tautvydas-Aleliunas/CVE-2026-93903.svg) ![forks](https://img.shields.io/github/forks/Tautvydas-Aleliunas/CVE-2026-93903.svg)


## CVE-2026-92935
 vm2 is a sandbox for running untrusted Node.js code. In versions = 3.11.4 and = 3.11.6, the NodeVM constructor computes `hasRealRequireConfig` with `typeof requireOpts === 'object' && requireOpts !== null`, so an array-shaped `require` value (for example `require: []`) satisfies the guard that is meant to reject nesting without an explicit require configuration. `makeResolverFromLegacyOptions()` then destructures the array into undefined option fields and returns a resolver containing only `NESTING_OVERRIDE.vm2`. As a result, an attacker who can supply JavaScript executed by a NodeVM configured with truthy `nesting` and an array-shaped `require` (e.g. `new NodeVM({nesting: true, require: []})`) can require the host `vm2` module, create an inner NodeVM with an attacker-chosen builtin allowlist (such as `child_process`), and execute arbitrary commands with the privileges of the host Node.js process, escaping the sandbox. Outer builtin restrictions do not constrain the attacker-created inner NodeVM. This issue is fixed in vm2 3.11.7.

- [https://github.com/CompleTech-Security/vm2-nesting-check](https://github.com/CompleTech-Security/vm2-nesting-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/vm2-nesting-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/vm2-nesting-check.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88778-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88778-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88778-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88778-check.svg)


## CVE-2026-88777
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88777-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88777-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88777-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88777-check.svg)


## CVE-2026-88776
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88776-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88776-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88776-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88776-check.svg)


## CVE-2026-88775
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading Memory overflow vulnerability leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88775-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88775-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88775-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88775-check.svg)


## CVE-2026-88774
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to a feature policy bypass due to improper HTTP URL based expression usage.

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88774-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88774-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88774-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88774-check.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88773-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88773-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88773-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88773-check.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88772-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88772-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88772-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88772-check.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/CompleTech-Security/netscaler-cve-2026-88771-check](https://github.com/CompleTech-Security/netscaler-cve-2026-88771-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/netscaler-cve-2026-88771-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/netscaler-cve-2026-88771-check.svg)


## CVE-2026-87690
 The Metasploit Framework post module post/apple_ios/gather/ios_image_gather is affected by a relative path traversal vulnerability (CWE-22). The module interpolates file names taken from a Meterpreter directory listing — data fully controlled by a hostile or tampered iOS device — directly into the local destination path passed to client.fs.file.download_file(), with no sanitization. The underlying stdapi sink (lib/rex/post/meterpreter/extensions/stdapi/fs/file.rb) writes to whatever path is supplied, so a listing entry such as ../../msfconsole.rc escapes the intended ~/.msf4/loot/random directory and overwrites ~/.msf4/msfconsole.rc, a resource file that every msfconsole invocation automatically executes at startup (lib/msf/ui/console/driver.rb:196). An attacker-controlled device that lures an operator into running this gather module achieves an arbitrary file write as the operator; because the written msfconsole.rc can load a second written file (a Ruby plugin whose top-level code runs on require), this converts into persistent code execution and an interactive shell as the operator (frequently root) on the pentester's workstation at the next console launch. The same traversal was previously fixed upstream in the recursive downloader (stdapi/fs/dir.rb scrubs separators); this module omitted the equivalent scrub. The fix applies the same separator scrub (or File.basename) to listing entries before building the local path.

- [https://github.com/h00die/CVE-2026-87690-POC-Metasploit-Dir-Traverse-to-RCE](https://github.com/h00die/CVE-2026-87690-POC-Metasploit-Dir-Traverse-to-RCE) :  ![starts](https://img.shields.io/github/stars/h00die/CVE-2026-87690-POC-Metasploit-Dir-Traverse-to-RCE.svg) ![forks](https://img.shields.io/github/forks/h00die/CVE-2026-87690-POC-Metasploit-Dir-Traverse-to-RCE.svg)


## CVE-2026-84383
 libheif is a HEIF and AVIF file format decoder and encoder. From 1.22.0 until 1.23.2, a crafted HEIF, HEIC, or AVIF item graph using nested iden and auxl references can make HeifPixelImage::transfer_channel_from_image_as() append duplicate Alpha planes with different bit depths to m_storage. HeifPixelImage::scale_nearest_neighbor() in libheif/image/pixelimage.cc allocates the destination Alpha plane using the first plane's 8-bit depth, then iterates a later 10-bit or 12-bit Alpha component and writes uint16_t samples into the same 8-bit allocation. The output geometry controls the overflow extent and the encoded sample values control the data written, allowing a remote file processed by heif_decode_image() to cause a heap out-of-bounds write. This issue is fixed in version 1.23.2.

- [https://github.com/sachincool/cve-2026-84383-poc](https://github.com/sachincool/cve-2026-84383-poc) :  ![starts](https://img.shields.io/github/stars/sachincool/cve-2026-84383-poc.svg) ![forks](https://img.shields.io/github/forks/sachincool/cve-2026-84383-poc.svg)


## CVE-2026-83938
 Missing authentication for critical function in Azure Kubernetes Configuration Service allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/emirwtz/CVE-2026-83938](https://github.com/emirwtz/CVE-2026-83938) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-83938.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-83938.svg)


## CVE-2026-69254
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, executeJavaScriptCode() accepted caller-provided nodeVMOptions and merged them over the default NodeVM security settings in packages/components/src/utils.ts. An authenticated attacker reaching packages/server/src/routes/node-custom-functions/index.ts could run a custom function that imported flowise-components/dist/src/utils.js, called executeJavaScriptCode() again with nodeVMOptions.require.builtin set to allow all built-in modules, and then required child_process to execute arbitrary system commands as root on the Flowise server. This issue is fixed in version 3.1.3.

- [https://github.com/CompleTech-Security/flowise-cve-2026-69254-check](https://github.com/CompleTech-Security/flowise-cve-2026-69254-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/flowise-cve-2026-69254-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/flowise-cve-2026-69254-check.svg)


## CVE-2026-63286
 Database backups are vulnerable to offline attacks. Backups created using a version prior to the patched version are still vulnerable. AXIS Camera Station Pro automatically creates one more such backup for recovery purpose when the update is applied. Delete all these backups and change the credentials stored in AXIS Camera Station Pro.

- [https://github.com/ricardojoserf/CVE-2026-63286](https://github.com/ricardojoserf/CVE-2026-63286) :  ![starts](https://img.shields.io/github/stars/ricardojoserf/CVE-2026-63286.svg) ![forks](https://img.shields.io/github/forks/ricardojoserf/CVE-2026-63286.svg)


## CVE-2026-58045
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-58045-check](https://github.com/CompleTech-Security/node-cve-2026-58045-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58045-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58045-check.svg)


## CVE-2026-58044
This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**.

- [https://github.com/CompleTech-Security/node-cve-2026-58044-check](https://github.com/CompleTech-Security/node-cve-2026-58044-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58044-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58044-check.svg)


## CVE-2026-58043
This vulnerability affects Node.js **main**, **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-58043-check](https://github.com/CompleTech-Security/node-cve-2026-58043-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58043-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58043-check.svg)


## CVE-2026-58042
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-58042-check](https://github.com/CompleTech-Security/node-cve-2026-58042-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58042-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58042-check.svg)


## CVE-2026-58041
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-58041-check](https://github.com/CompleTech-Security/node-cve-2026-58041-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58041-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58041-check.svg)


## CVE-2026-58040
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-58040-check](https://github.com/CompleTech-Security/node-cve-2026-58040-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58040-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58040-check.svg)


## CVE-2026-58039
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-58039-check](https://github.com/CompleTech-Security/node-cve-2026-58039-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-58039-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-58039-check.svg)


## CVE-2026-56850
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-56850-check](https://github.com/CompleTech-Security/node-cve-2026-56850-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-56850-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-56850-check.svg)


## CVE-2026-56848
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-56848-check](https://github.com/CompleTech-Security/node-cve-2026-56848-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-56848-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-56848-check.svg)


## CVE-2026-56847
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-56847-check](https://github.com/CompleTech-Security/node-cve-2026-56847-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-56847-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-56847-check.svg)


## CVE-2026-56846
This vulnerability affects Node.js **24.x** and **22.x**.

- [https://github.com/CompleTech-Security/node-cve-2026-56846-check](https://github.com/CompleTech-Security/node-cve-2026-56846-check) :  ![starts](https://img.shields.io/github/stars/CompleTech-Security/node-cve-2026-56846-check.svg) ![forks](https://img.shields.io/github/forks/CompleTech-Security/node-cve-2026-56846-check.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/AnubisRedTeam/CVE-2026-54121-Certighost](https://github.com/AnubisRedTeam/CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/AnubisRedTeam/CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/AnubisRedTeam/CVE-2026-54121-Certighost.svg)


## CVE-2026-41036
Successful exploitation of this vulnerability could allow the attacker to perform remote code execution with root privileges on the targeted device.

- [https://github.com/mir7867/CVE-2026-41036-Quantum-Networks-Copy-repository-name](https://github.com/mir7867/CVE-2026-41036-Quantum-Networks-Copy-repository-name) :  ![starts](https://img.shields.io/github/stars/mir7867/CVE-2026-41036-Quantum-Networks-Copy-repository-name.svg) ![forks](https://img.shields.io/github/forks/mir7867/CVE-2026-41036-Quantum-Networks-Copy-repository-name.svg)


## CVE-2026-38056
 A local privilege escalation vulnerability exists in the iDirect iQ200 VSAT terminal running firmware 23.0.1.0. The iQ200 is a rackmount satellite modem deployed across oil and gas, maritime, defense, and remote infrastructure as the primary, and often sole communications link for offshore rigs, vessels, and remote sites. Important context: the device ships from the factory with a pre-configured low-privilege local user account. This account is intended for field technicians who need shell access for maintenance and diagnostics but should not have full administrative control over the device. This built-in account provides the initial access required to exploit this vulnerability. No additional credentials need to be obtained or brute-forced.

- [https://github.com/sudo5Q/CVE-2026-38056-PoC](https://github.com/sudo5Q/CVE-2026-38056-PoC) :  ![starts](https://img.shields.io/github/stars/sudo5Q/CVE-2026-38056-PoC.svg) ![forks](https://img.shields.io/github/forks/sudo5Q/CVE-2026-38056-PoC.svg)


## CVE-2026-35223
 An improper access check allows unauthorized access to com_config webservice endpoints.

- [https://github.com/LaRemontada12/CVE-2026-35223-Joomla-Access-Control](https://github.com/LaRemontada12/CVE-2026-35223-Joomla-Access-Control) :  ![starts](https://img.shields.io/github/stars/LaRemontada12/CVE-2026-35223-Joomla-Access-Control.svg) ![forks](https://img.shields.io/github/forks/LaRemontada12/CVE-2026-35223-Joomla-Access-Control.svg)


## CVE-2026-27740
 Discourse is an open-source discussion platform. Versions prior to 2026.3.0-latest.1, 2026.2.1, and 2026.1.2 have a cross-site scripting vulnerability that arises because the system trusts the raw output from an AI Large Language Model (LLM) and renders it using htmlSafe in the Review Queue interface without adequate sanitization. A malicious attacker can use valid Prompt Injection techniques to force the AI to return a malicious payload (e.g., tags). When a Staff member (Admin/Moderator) views the flagged post in the Review Queue, the payload executes. Versions 2026.3.0-latest.1, 2026.2.1, and 2026.1.2 contain a patch. As a workaround, temporarily disable AI triage automation scripts.

- [https://github.com/tyie949/cve-2025-27740](https://github.com/tyie949/cve-2025-27740) :  ![starts](https://img.shields.io/github/stars/tyie949/cve-2025-27740.svg) ![forks](https://img.shields.io/github/forks/tyie949/cve-2025-27740.svg)


## CVE-2026-15723
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 10.1 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, when OmniAuth SAML and LDAP auto-linking were both enabled, an authenticated user could have taken over an existing LDAP-backed account without any interaction from the targeted user, due to improper input sanitization in the LDAP email lookup path used during OmniAuth identity linking.

- [https://github.com/emirwtz/CVE-2026-15723](https://github.com/emirwtz/CVE-2026-15723) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-15723.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-15723.svg)


## CVE-2026-11556
 A security flaw has been discovered in Tenda F451 1.0.0.7/1.0.0.9. Impacted is the function formWriteFacMac of the file /goform/WriteFacMac of the component Web Management Interface. Performing a manipulation of the argument mac results in os command injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-](https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-.svg)
- [https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-](https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-.svg)


## CVE-2026-11232
 Inappropriate implementation in TabGroups in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to perform UI spoofing via malicious network traffic. (Chromium security severity: Low)

- [https://github.com/j0xh-sec/CVE-2026-112325](https://github.com/j0xh-sec/CVE-2026-112325) :  ![starts](https://img.shields.io/github/stars/j0xh-sec/CVE-2026-112325.svg) ![forks](https://img.shields.io/github/forks/j0xh-sec/CVE-2026-112325.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/WallcroftUK/CVE-2026-109619](https://github.com/WallcroftUK/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/WallcroftUK/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/WallcroftUK/CVE-2026-109619.svg)
- [https://github.com/xvanpan/CVE-2026-109619](https://github.com/xvanpan/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xvanpan/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xvanpan/CVE-2026-109619.svg)
- [https://github.com/syrex1013/CVE-2026-109619](https://github.com/syrex1013/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109619.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-109618](https://github.com/alvaroguzmancode/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-109618.svg)


## CVE-2026-7939
 Inappropriate implementation in SanitizerAPI in Google Chrome prior to 148.0.7778.96 allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/jed-parsec/CVE-2026-79397-Authenticated-OS-Command-Injection-in-ONT-4GE-RFDW-Ping-Diagnostics](https://github.com/jed-parsec/CVE-2026-79397-Authenticated-OS-Command-Injection-in-ONT-4GE-RFDW-Ping-Diagnostics) :  ![starts](https://img.shields.io/github/stars/jed-parsec/CVE-2026-79397-Authenticated-OS-Command-Injection-in-ONT-4GE-RFDW-Ping-Diagnostics.svg) ![forks](https://img.shields.io/github/forks/jed-parsec/CVE-2026-79397-Authenticated-OS-Command-Injection-in-ONT-4GE-RFDW-Ping-Diagnostics.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/inforcqb-self/CVE-2026-43499-pja110](https://github.com/inforcqb-self/CVE-2026-43499-pja110) :  ![starts](https://img.shields.io/github/stars/inforcqb-self/CVE-2026-43499-pja110.svg) ![forks](https://img.shields.io/github/forks/inforcqb-self/CVE-2026-43499-pja110.svg)
- [https://github.com/Syerain/cve-2026-43499-vivo-mt6896](https://github.com/Syerain/cve-2026-43499-vivo-mt6896) :  ![starts](https://img.shields.io/github/stars/Syerain/cve-2026-43499-vivo-mt6896.svg) ![forks](https://img.shields.io/github/forks/Syerain/cve-2026-43499-vivo-mt6896.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618_.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618_.svg)
- [https://github.com/1Nightlovel/CVE-2026-109618](https://github.com/1Nightlovel/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109618.svg)


## CVE-2026-0013
 In setupLayout of PickActivity.java, there is a possible way to start any activity as a DocumentsUI app due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/inforcqb-self/cve-2026-0013-exploit](https://github.com/inforcqb-self/cve-2026-0013-exploit) :  ![starts](https://img.shields.io/github/stars/inforcqb-self/cve-2026-0013-exploit.svg) ![forks](https://img.shields.io/github/forks/inforcqb-self/cve-2026-0013-exploit.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-30026
to bypass authentication that is normally required.

- [https://github.com/ricardojoserf/axis-RCE](https://github.com/ricardojoserf/axis-RCE) :  ![starts](https://img.shields.io/github/stars/ricardojoserf/axis-RCE.svg) ![forks](https://img.shields.io/github/forks/ricardojoserf/axis-RCE.svg)


## CVE-2025-30023
 The communication protocol used between client and server had a flaw that could lead to an authenticated user performing a remote code execution attack.

- [https://github.com/ricardojoserf/axis-RCE](https://github.com/ricardojoserf/axis-RCE) :  ![starts](https://img.shields.io/github/stars/ricardojoserf/axis-RCE.svg) ![forks](https://img.shields.io/github/forks/ricardojoserf/axis-RCE.svg)


## CVE-2025-27740
 Weak authentication in Windows Active Directory Certificate Services allows an authorized attacker to elevate privileges over a network.

- [https://github.com/tyie949/cve-2025-27740](https://github.com/tyie949/cve-2025-27740) :  ![starts](https://img.shields.io/github/stars/tyie949/cve-2025-27740.svg) ![forks](https://img.shields.io/github/forks/tyie949/cve-2025-27740.svg)


## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

- [https://github.com/dkchaiv/CVE-2025-10035](https://github.com/dkchaiv/CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/dkchaiv/CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/dkchaiv/CVE-2025-10035.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ppolo1/CVE-2025-5548](https://github.com/ppolo1/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/ppolo1/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/ppolo1/CVE-2025-5548.svg)


## CVE-2024-36779
 Sourcecodester Stock Management System v1.0 is vulnerable to SQL Injection via editCategories.php.

- [https://github.com/AgnesAhalya/rw-stock](https://github.com/AgnesAhalya/rw-stock) :  ![starts](https://img.shields.io/github/stars/AgnesAhalya/rw-stock.svg) ![forks](https://img.shields.io/github/forks/AgnesAhalya/rw-stock.svg)


## CVE-2024-5098
 A vulnerability has been found in SourceCodester Simple Inventory System 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file login.php. The manipulation of the argument username leads to sql injection. The exploit has been disclosed to the public and may be used. The identifier VDB-265081 was assigned to this vulnerability.

- [https://github.com/riftsandroses/CVE-2024-50986](https://github.com/riftsandroses/CVE-2024-50986) :  ![starts](https://img.shields.io/github/stars/riftsandroses/CVE-2024-50986.svg) ![forks](https://img.shields.io/github/forks/riftsandroses/CVE-2024-50986.svg)


## CVE-2024-4442
 The Salon booking system plugin for WordPress is vulnerable to arbitrary file deletion in all versions up to, and including, 9.8. This is due to the plugin not properly validating the path of an uploaded file prior to deleting it. This makes it possible for unauthenticated attackers to delete arbitrary files, including the wp-config.php file, which can make site takeover and remote code execution possible. This was partially patched in 9.9, and sufficiently patched in 10.0. CVE-2024-37231 appears to be a duplicate of this issue.

- [https://github.com/AgnesAhalya/rw-salon](https://github.com/AgnesAhalya/rw-salon) :  ![starts](https://img.shields.io/github/stars/AgnesAhalya/rw-salon.svg) ![forks](https://img.shields.io/github/forks/AgnesAhalya/rw-salon.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/weae26/aia-pdfjs-poc](https://github.com/weae26/aia-pdfjs-poc) :  ![starts](https://img.shields.io/github/stars/weae26/aia-pdfjs-poc.svg) ![forks](https://img.shields.io/github/forks/weae26/aia-pdfjs-poc.svg)


## CVE-2024-4363
 The Visual Portfolio, Photo Gallery & Post Grid plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘title_tag’ parameter in all versions up to, and including, 3.3.2 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with author-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/QuasarBinary/CVE-2024-43630-POC](https://github.com/QuasarBinary/CVE-2024-43630-POC) :  ![starts](https://img.shields.io/github/stars/QuasarBinary/CVE-2024-43630-POC.svg) ![forks](https://img.shields.io/github/forks/QuasarBinary/CVE-2024-43630-POC.svg)


## CVE-2024-4223
 The Tutor LMS plugin for WordPress is vulnerable to unauthorized access of data, modification of data, loss of data due to a missing capability check on multiple functions in all versions up to, and including, 2.7.0. This makes it possible for unauthenticated attackers to add, modify, or delete data.

- [https://github.com/neevmeh18/rw-tutor](https://github.com/neevmeh18/rw-tutor) :  ![starts](https://img.shields.io/github/stars/neevmeh18/rw-tutor.svg) ![forks](https://img.shields.io/github/forks/neevmeh18/rw-tutor.svg)


## CVE-2024-3688
 A vulnerability was found in Xiamen Four-Faith RMP Router Management Platform 5.2.2. It has been declared as critical. This vulnerability affects unknown code of the file /Device/Device/GetDeviceInfoList?deviceCode=&searchField=&deviceState=. The manipulation of the argument groupId leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-260476. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/abubakar-shahid/CVE-2024-36886](https://github.com/abubakar-shahid/CVE-2024-36886) :  ![starts](https://img.shields.io/github/stars/abubakar-shahid/CVE-2024-36886.svg) ![forks](https://img.shields.io/github/forks/abubakar-shahid/CVE-2024-36886.svg)


## CVE-2024-3552
 The Web Directory Free WordPress plugin before 1.7.0 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection with different techniques like UNION, Time-Based and Error-Based.

- [https://github.com/neevmeh18/rw-web-directory-free](https://github.com/neevmeh18/rw-web-directory-free) :  ![starts](https://img.shields.io/github/stars/neevmeh18/rw-web-directory-free.svg) ![forks](https://img.shields.io/github/forks/neevmeh18/rw-web-directory-free.svg)


## CVE-2024-3495
 The Country State City Dropdown CF7 plugin for WordPress is vulnerable to SQL Injection via the ‘cnt’ and 'sid' parameters in versions up to, and including, 2.7.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/AgnesAhalya/rw-country-state-city-auto-dropdown](https://github.com/AgnesAhalya/rw-country-state-city-auto-dropdown) :  ![starts](https://img.shields.io/github/stars/AgnesAhalya/rw-country-state-city-auto-dropdown.svg) ![forks](https://img.shields.io/github/forks/AgnesAhalya/rw-country-state-city-auto-dropdown.svg)


## CVE-2024-3184
 Multiple CWE-476 NULL Pointer Dereference vulnerabilities were found in GoAhead Web Server up to version 6.0.0 when compiled with the ME_GOAHEAD_REPLACE_MALLOC flag. Without a memory notifier for allocation failures, remote attackers can exploit these vulnerabilities by sending malicious requests, leading to a crash and Denial of Service (DoS).

- [https://github.com/Stuub/CVE-2024-31848-PoC](https://github.com/Stuub/CVE-2024-31848-PoC) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2024-31848-PoC.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2024-31848-PoC.svg)


## CVE-2024-2839
 The Colibri Page Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'colibri_post_title' shortcode in all versions up to, and including, 1.0.263 due to insufficient input sanitization and output escaping on user supplied attributes such as 'heading_type'. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/Marven11/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/Marven11/CVE-2024-28397-js2py-Sandbox-Escape.svg)
- [https://github.com/naclapor/CVE-2024-28397](https://github.com/naclapor/CVE-2024-28397) :  ![starts](https://img.shields.io/github/stars/naclapor/CVE-2024-28397.svg) ![forks](https://img.shields.io/github/forks/naclapor/CVE-2024-28397.svg)
- [https://github.com/GhostOverflow/CVE-2024-28397-command-execution-poc](https://github.com/GhostOverflow/CVE-2024-28397-command-execution-poc) :  ![starts](https://img.shields.io/github/stars/GhostOverflow/CVE-2024-28397-command-execution-poc.svg) ![forks](https://img.shields.io/github/forks/GhostOverflow/CVE-2024-28397-command-execution-poc.svg)
- [https://github.com/L1337Xi/CVE-2024-28397-Exploit-Automation](https://github.com/L1337Xi/CVE-2024-28397-Exploit-Automation) :  ![starts](https://img.shields.io/github/stars/L1337Xi/CVE-2024-28397-Exploit-Automation.svg) ![forks](https://img.shields.io/github/forks/L1337Xi/CVE-2024-28397-Exploit-Automation.svg)
- [https://github.com/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit](https://github.com/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit.svg)
- [https://github.com/harutomo-jp/CVE-2024-28397-RCE](https://github.com/harutomo-jp/CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/harutomo-jp/CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/harutomo-jp/CVE-2024-28397-RCE.svg)
- [https://github.com/somisec/CVE-2024-28397-Reverse-Shell](https://github.com/somisec/CVE-2024-28397-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/somisec/CVE-2024-28397-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/somisec/CVE-2024-28397-Reverse-Shell.svg)
- [https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/Naved124/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/Naved124/CVE-2024-28397-js2py-Sandbox-Escape.svg)
- [https://github.com/vitaciminIPI/CVE-2024-28397-RCE](https://github.com/vitaciminIPI/CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/vitaciminIPI/CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/vitaciminIPI/CVE-2024-28397-RCE.svg)
- [https://github.com/3z-p0wn/CVE-2024-28397-exploit](https://github.com/3z-p0wn/CVE-2024-28397-exploit) :  ![starts](https://img.shields.io/github/stars/3z-p0wn/CVE-2024-28397-exploit.svg) ![forks](https://img.shields.io/github/forks/3z-p0wn/CVE-2024-28397-exploit.svg)
- [https://github.com/y0naldez/CVE-2024-28397-Js2Py-RCE](https://github.com/y0naldez/CVE-2024-28397-Js2Py-RCE) :  ![starts](https://img.shields.io/github/stars/y0naldez/CVE-2024-28397-Js2Py-RCE.svg) ![forks](https://img.shields.io/github/forks/y0naldez/CVE-2024-28397-Js2Py-RCE.svg)
- [https://github.com/kyl0-ST12/CVE_2024_28397---js2py-RCE](https://github.com/kyl0-ST12/CVE_2024_28397---js2py-RCE) :  ![starts](https://img.shields.io/github/stars/kyl0-ST12/CVE_2024_28397---js2py-RCE.svg) ![forks](https://img.shields.io/github/forks/kyl0-ST12/CVE_2024_28397---js2py-RCE.svg)
- [https://github.com/D3ltaFormation/CVE-2024-28397-Js2Py-RCE](https://github.com/D3ltaFormation/CVE-2024-28397-Js2Py-RCE) :  ![starts](https://img.shields.io/github/stars/D3ltaFormation/CVE-2024-28397-Js2Py-RCE.svg) ![forks](https://img.shields.io/github/forks/D3ltaFormation/CVE-2024-28397-Js2Py-RCE.svg)
- [https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape.svg)
- [https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE](https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE.svg)
- [https://github.com/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-](https://github.com/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-) :  ![starts](https://img.shields.io/github/stars/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg) ![forks](https://img.shields.io/github/forks/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg)


## CVE-2024-2771
 The Contact Form Plugin by Fluent Forms for Quiz, Survey, and Drag & Drop WP Form Builder plugin for WordPress is vulnerable to privilege escalation due to a missing capability check on the /wp-json/fluentform/v1/managers REST API endpoint in all versions up to, and including, 5.1.16. This makes it possible for unauthenticated attackers to grant users with Fluent Form management permissions which gives them access to all of the plugin's settings and features. This also makes it possible for unauthenticated attackers to delete manager accounts.

- [https://github.com/neevmeh18/rw-fluentform](https://github.com/neevmeh18/rw-fluentform) :  ![starts](https://img.shields.io/github/stars/neevmeh18/rw-fluentform.svg) ![forks](https://img.shields.io/github/forks/neevmeh18/rw-fluentform.svg)


## CVE-2024-2763
 A vulnerability, which was classified as critical, has been found in Tenda AC10U 15.03.06.48. Affected by this issue is the function formSetCfm of the file goform/setcfm. The manipulation of the argument funcpara1 leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-257600. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/ally-petitt/CVE-2024-27632](https://github.com/ally-petitt/CVE-2024-27632) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2024-27632.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2024-27632.svg)
- [https://github.com/ally-petitt/CVE-2024-27631](https://github.com/ally-petitt/CVE-2024-27631) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2024-27631.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2024-27631.svg)


## CVE-2024-2713
 A vulnerability, which was classified as critical, was found in Campcodes Complete Online DJ Booking System 1.0. Affected is an unknown function of the file /admin/booking-search.php. The manipulation of the argument searchdata leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-257466 is the identifier assigned to this vulnerability.

- [https://github.com/watchtowrlabs/CVE-2024-27130](https://github.com/watchtowrlabs/CVE-2024-27130) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2024-27130.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2024-27130.svg)


## CVE-2024-2657
 The Font Farsi plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings in all versions up to, and including, 1.6.6 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/Alaatk/CVE-2024-26574](https://github.com/Alaatk/CVE-2024-26574) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-26574.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-26574.svg)


## CVE-2023-4622
We recommend upgrading past commit 790c2f9d15b594350ae9bca7b236f2b1859de02c (or backported equivalents).

- [https://github.com/android-cve-exploits/0range1337--CVE-CVE-2023-4622](https://github.com/android-cve-exploits/0range1337--CVE-CVE-2023-4622) :  ![starts](https://img.shields.io/github/stars/android-cve-exploits/0range1337--CVE-CVE-2023-4622.svg) ![forks](https://img.shields.io/github/forks/android-cve-exploits/0range1337--CVE-CVE-2023-4622.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/keaidang/TYH831T-S9-Bootloader-Root](https://github.com/keaidang/TYH831T-S9-Bootloader-Root) :  ![starts](https://img.shields.io/github/stars/keaidang/TYH831T-S9-Bootloader-Root.svg) ![forks](https://img.shields.io/github/forks/keaidang/TYH831T-S9-Bootloader-Root.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/s1204IT/CVE-2022-38181](https://github.com/s1204IT/CVE-2022-38181) :  ![starts](https://img.shields.io/github/stars/s1204IT/CVE-2022-38181.svg) ![forks](https://img.shields.io/github/forks/s1204IT/CVE-2022-38181.svg)


## CVE-2022-20186
 In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A

- [https://github.com/android-cve-exploits/SmileTabLabo--CVE-2022-20186](https://github.com/android-cve-exploits/SmileTabLabo--CVE-2022-20186) :  ![starts](https://img.shields.io/github/stars/android-cve-exploits/SmileTabLabo--CVE-2022-20186.svg) ![forks](https://img.shields.io/github/forks/android-cve-exploits/SmileTabLabo--CVE-2022-20186.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/TheElderHacker/CVE-2022-1388](https://github.com/TheElderHacker/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/TheElderHacker/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/TheElderHacker/CVE-2022-1388.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-27190
 A Stored Cross Site Scripting(XSS) Vulnerability was discovered in PEEL SHOPPING 9.3.0 and 9.4.0, which are publicly available. The user supplied input containing polyglot payload is echoed back in javascript code in HTML response. This allows an attacker to input malicious JavaScript which can steal cookie, redirect them to other malicious website, etc.

- [https://github.com/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS](https://github.com/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/tr3m0x/CVE-2021-41773](https://github.com/tr3m0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/tr3m0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/tr3m0x/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-3060
 An OS command injection vulnerability in the Simple Certificate Enrollment Protocol (SCEP) feature of PAN-OS software allows an unauthenticated network-based attacker with specific knowledge of the firewall configuration to execute arbitrary code with root user privileges. The attacker must have network access to the GlobalProtect interfaces to exploit this issue. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.20-h1; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14-h3; PAN-OS 9.1 versions earlier than PAN-OS 9.1.11-h2; PAN-OS 10.0 versions earlier than PAN-OS 10.0.8; PAN-OS 10.1 versions earlier than PAN-OS 10.1.3. Prisma Access customers with Prisma Access 2.1 Preferred and Prisma Access 2.1 Innovation firewalls are impacted by this issue.

- [https://github.com/anmolksachan/CVE-2021-3060](https://github.com/anmolksachan/CVE-2021-3060) :  ![starts](https://img.shields.io/github/stars/anmolksachan/CVE-2021-3060.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/CVE-2021-3060.svg)


## CVE-2020-2733
 Vulnerability in the JD Edwards EnterpriseOne Tools product of Oracle JD Edwards (component: Monitoring and Diagnostics). The supported version that is affected is 9.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise JD Edwards EnterpriseOne Tools. Successful attacks of this vulnerability can result in takeover of JD Edwards EnterpriseOne Tools. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/anmolksachan/CVE-2020-2733](https://github.com/anmolksachan/CVE-2020-2733) :  ![starts](https://img.shields.io/github/stars/anmolksachan/CVE-2020-2733.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/CVE-2020-2733.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/AlonsoJuan1994/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow](https://github.com/AlonsoJuan1994/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow) :  ![starts](https://img.shields.io/github/stars/AlonsoJuan1994/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg) ![forks](https://img.shields.io/github/forks/AlonsoJuan1994/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg)


## CVE-2015-8522
 Buffer overflow in the server in IBM Tivoli Storage Manager FastBack 5.5.x and 6.x before 6.1.12.2 allows remote attackers to execute arbitrary code via a crafted command, a different vulnerability than CVE-2015-8519, CVE-2015-8520, and CVE-2015-8521.

- [https://github.com/damariion/CVE-2015-8522-RCE](https://github.com/damariion/CVE-2015-8522-RCE) :  ![starts](https://img.shields.io/github/stars/damariion/CVE-2015-8522-RCE.svg) ![forks](https://img.shields.io/github/forks/damariion/CVE-2015-8522-RCE.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0xredash/CVE-2014-6271](https://github.com/0xredash/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2014-6271.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/0xredash/CVE-2014-0160](https://github.com/0xredash/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2014-0160.svg)


## CVE-2012-0152
 The Remote Desktop Protocol (RDP) service in Microsoft Windows Server 2008 R2 and R2 SP1 and Windows 7 Gold and SP1 allows remote attackers to cause a denial of service (application hang) via a series of crafted packets, aka "Terminal Server Denial of Service Vulnerability."

- [https://github.com/anmolksachan/MS12-020](https://github.com/anmolksachan/MS12-020) :  ![starts](https://img.shields.io/github/stars/anmolksachan/MS12-020.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/MS12-020.svg)

