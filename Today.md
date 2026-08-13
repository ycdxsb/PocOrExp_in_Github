# Update 2026-08-13
## CVE-2026-66804
 Improper access control in Windows Cross Device Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/DavidCarliez/CVE-2026-66804-CrossDevice-LPE](https://github.com/DavidCarliez/CVE-2026-66804-CrossDevice-LPE) :  ![starts](https://img.shields.io/github/stars/DavidCarliez/CVE-2026-66804-CrossDevice-LPE.svg) ![forks](https://img.shields.io/github/forks/DavidCarliez/CVE-2026-66804-CrossDevice-LPE.svg)


## CVE-2026-64564
branch can never reuse a freed transport.

- [https://github.com/yandex-cloud-examples/yc-mk8s-sctphantom-mitigation](https://github.com/yandex-cloud-examples/yc-mk8s-sctphantom-mitigation) :  ![starts](https://img.shields.io/github/stars/yandex-cloud-examples/yc-mk8s-sctphantom-mitigation.svg) ![forks](https://img.shields.io/github/forks/yandex-cloud-examples/yc-mk8s-sctphantom-mitigation.svg)


## CVE-2026-62737
 Untrusted pointer dereference in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/DavidCarliez/cve-2026-62737-lab](https://github.com/DavidCarliez/cve-2026-62737-lab) :  ![starts](https://img.shields.io/github/stars/DavidCarliez/cve-2026-62737-lab.svg) ![forks](https://img.shields.io/github/forks/DavidCarliez/cve-2026-62737-lab.svg)


## CVE-2026-55040
 Weak authentication in Microsoft Office SharePoint allows an unauthorized attacker to bypass a security feature over a network.

- [https://github.com/sfewer-r7/CVE-2026-55040](https://github.com/sfewer-r7/CVE-2026-55040) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-55040.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-55040.svg)
- [https://github.com/l0ggg/CVE-2026-55040](https://github.com/l0ggg/CVE-2026-55040) :  ![starts](https://img.shields.io/github/stars/l0ggg/CVE-2026-55040.svg) ![forks](https://img.shields.io/github/forks/l0ggg/CVE-2026-55040.svg)


## CVE-2026-53361
Let's set gc_in_progress to true in unix_gc().

- [https://github.com/sgkdev/bad_garbage](https://github.com/sgkdev/bad_garbage) :  ![starts](https://img.shields.io/github/stars/sgkdev/bad_garbage.svg) ![forks](https://img.shields.io/github/forks/sgkdev/bad_garbage.svg)


## CVE-2026-48813
 Flawfinder is a a static analysis tool for finding vulnerabilities in C/C++ source code. Versions prior to 2.0.20 have an improper input neutralization issue leading to output manipulation, specifically, Terminal/ANSI Escape Sequence Injection and XML Injection. A malicious file whose name contains ANSI escape sequences can end up being included in flawfinder's standard terminal output, with many effects. Untrusted fields (such as filenames, categories, or code context text) were not properly sanitized when generating structured reports. An attacker could exploit this to corrupt CSV formats or inject arbitrary XML attributes into SonarQube outputs via output_sonar(). It impacts those who use flawfinder to evaluate intentionally malicious filenames or file contents. This issue has been fully patched in Version 2.0.20 (released 2026-05-16). There is no configuration-based workaround within older versions of flawfinder. If an immediate upgrade is not possible, users can mitigate the risk by pre-scanning filenames, inspecting raw output, and/or restricting untrusted inputs.

- [https://github.com/7alen7/CVE-2026-48813-POC](https://github.com/7alen7/CVE-2026-48813-POC) :  ![starts](https://img.shields.io/github/stars/7alen7/CVE-2026-48813-POC.svg) ![forks](https://img.shields.io/github/forks/7alen7/CVE-2026-48813-POC.svg)


## CVE-2026-48710
 Starlette is a lightweight ASGI framework/toolkit. Prior to version 1.0.1, the HTTP `Host` request header was not validated before being used to reconstruct `request.url`. Because the routing algorithm relies on the raw HTTP path while `request.url` is rebuilt from the `Host` header, a malformed header could make `request.url.path` differ from the path that was actually requested. Middleware and endpoints that apply security restrictions based on `request.url` (rather than the raw `scope` path) could therefore be bypassed. Users should upgrade to a version greater than or equal to version 1.0.1, which validates the `Host` header against the grammar of RFC 9112 §3.2 / RFC 3986 §3.2.2 when constructing `request.url` and falls back to `scope["server"]` for malformed values.

- [https://github.com/CuteeCat/CVE-2026-48710](https://github.com/CuteeCat/CVE-2026-48710) :  ![starts](https://img.shields.io/github/stars/CuteeCat/CVE-2026-48710.svg) ![forks](https://img.shields.io/github/forks/CuteeCat/CVE-2026-48710.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/yellowkeycve/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/yellowkeycve/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/yellowkeycve/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/yellowkeycve/YellowKey-Bitlocker-CVE-2026-45585.svg)


## CVE-2026-44401
 Typemill CMS version 2.x contains a persistent cross-site scripting vulnerability in the Markdown parser extension that allows authenticated users with theme-configuration access to inject malicious JavaScript URIs by supplying unsanitized href values in Markdown links. Attackers can craft Markdown links using the javascript: scheme through ParsedownExtension.php or TwigMarkdownExtension.php, storing a persistent payload that executes in the browser of every visitor who clicks the link, enabling session cookie theft, authenticated request forgery, and credential harvesting.

- [https://github.com/sn0x-sharma/CVE-2026-44401](https://github.com/sn0x-sharma/CVE-2026-44401) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/CVE-2026-44401.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/CVE-2026-44401.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) :  ![starts](https://img.shields.io/github/stars/yijiacloud/ghostlock-cve-2026-43499-4.19-k40.svg) ![forks](https://img.shields.io/github/forks/yijiacloud/ghostlock-cve-2026-43499-4.19-k40.svg)
- [https://github.com/justsoman/CVE-2026-43499-jinghu](https://github.com/justsoman/CVE-2026-43499-jinghu) :  ![starts](https://img.shields.io/github/stars/justsoman/CVE-2026-43499-jinghu.svg) ![forks](https://img.shields.io/github/forks/justsoman/CVE-2026-43499-jinghu.svg)
- [https://github.com/yijiacloud/GhostLock-OPPO-PCKM00](https://github.com/yijiacloud/GhostLock-OPPO-PCKM00) :  ![starts](https://img.shields.io/github/stars/yijiacloud/GhostLock-OPPO-PCKM00.svg) ![forks](https://img.shields.io/github/forks/yijiacloud/GhostLock-OPPO-PCKM00.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/keithbennedict/CVE-2026-41940-Linux](https://github.com/keithbennedict/CVE-2026-41940-Linux) :  ![starts](https://img.shields.io/github/stars/keithbennedict/CVE-2026-41940-Linux.svg) ![forks](https://img.shields.io/github/forks/keithbennedict/CVE-2026-41940-Linux.svg)


## CVE-2026-25194
 Out-of-bounds write in the firmware for the Intel(R) Slim Bootloader may allow a denial of service. System software adversary with a privileged user combined with a low complexity attack may enable denial of service. This result may potentially occur via local access when attack requirements are present without special internal knowledge and requires no user interaction. The potential vulnerability may impact the confidentiality (none), integrity (none) and availability (low) of the vulnerable system, resulting in subsequent system confidentiality (none), integrity (none) and availability (none) impacts.

- [https://github.com/DexSemon/CVE-2026-25194](https://github.com/DexSemon/CVE-2026-25194) :  ![starts](https://img.shields.io/github/stars/DexSemon/CVE-2026-25194.svg) ![forks](https://img.shields.io/github/forks/DexSemon/CVE-2026-25194.svg)


## CVE-2026-23745
 node-tar is a Tar for Node.js. The node-tar library (= 7.5.2) fails to sanitize the linkpath of Link (hardlink) and SymbolicLink entries when preservePaths is false (the default secure behavior). This allows malicious archives to bypass the extraction root restriction, leading to Arbitrary File Overwrite via hardlinks and Symlink Poisoning via absolute symlink targets. This vulnerability is fixed in 7.5.3.

- [https://github.com/OndrejDrapalik/node-tar-cve-demo](https://github.com/OndrejDrapalik/node-tar-cve-demo) :  ![starts](https://img.shields.io/github/stars/OndrejDrapalik/node-tar-cve-demo.svg) ![forks](https://img.shields.io/github/forks/OndrejDrapalik/node-tar-cve-demo.svg)


## CVE-2026-18907
 Path Traversal in Download File Feature in com.talpa.hibrowser 2.23.1.1 on Android allows arbitrary file write via directory traversal sequences in the filename.

- [https://github.com/Hunt-Benito/two-dots-and-a-slash-cve-2026-18907-tecno-hi-browser-download-path-traversal](https://github.com/Hunt-Benito/two-dots-and-a-slash-cve-2026-18907-tecno-hi-browser-download-path-traversal) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/two-dots-and-a-slash-cve-2026-18907-tecno-hi-browser-download-path-traversal.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/two-dots-and-a-slash-cve-2026-18907-tecno-hi-browser-download-path-traversal.svg)


## CVE-2026-6784
 Memory safety bugs present in Firefox 149 and Thunderbird 149. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability was fixed in Firefox 150 and Thunderbird 150.

- [https://github.com/duan528/CVE-2026-67846-BOOM-NBDTLB](https://github.com/duan528/CVE-2026-67846-BOOM-NBDTLB) :  ![starts](https://img.shields.io/github/stars/duan528/CVE-2026-67846-BOOM-NBDTLB.svg) ![forks](https://img.shields.io/github/forks/duan528/CVE-2026-67846-BOOM-NBDTLB.svg)


## CVE-2026-2766
 Use-after-free in the JavaScript Engine: JIT component. This vulnerability was fixed in Firefox 148, Firefox ESR 140.8, Thunderbird 148, and Thunderbird 140.8.

- [https://github.com/SneakyNachos/CVE-2026-2766-but-with-wasm](https://github.com/SneakyNachos/CVE-2026-2766-but-with-wasm) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-2766-but-with-wasm.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-2766-but-with-wasm.svg)


## CVE-2026-1710
 The WooPayments: Integrated WooCommerce Payments plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'save_upe_appearance_ajax' function in all versions up to, and including, 10.5.1. This makes it possible for unauthenticated attackers to update plugin settings.

- [https://github.com/masasron/CopyEscape-CVE-2026-17106](https://github.com/masasron/CopyEscape-CVE-2026-17106) :  ![starts](https://img.shields.io/github/stars/masasron/CopyEscape-CVE-2026-17106.svg) ![forks](https://img.shields.io/github/forks/masasron/CopyEscape-CVE-2026-17106.svg)
- [https://github.com/HackSpeak/CVE-2026-17106](https://github.com/HackSpeak/CVE-2026-17106) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-17106.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-17106.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/DodgeNefoli/CVE-2025-64512](https://github.com/DodgeNefoli/CVE-2025-64512) :  ![starts](https://img.shields.io/github/stars/DodgeNefoli/CVE-2025-64512.svg) ![forks](https://img.shields.io/github/forks/DodgeNefoli/CVE-2025-64512.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/YouGina/CVE-2025-64459](https://github.com/YouGina/CVE-2025-64459) :  ![starts](https://img.shields.io/github/stars/YouGina/CVE-2025-64459.svg) ![forks](https://img.shields.io/github/forks/YouGina/CVE-2025-64459.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-23211
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. A Jinja2 SSTI vulnerability allows any user to execute commands on the server. In the case of the provided Docker Compose file as root. This vulnerability is fixed in 1.5.24.

- [https://github.com/IIxoskeletonII/DataPrivacy-CVE-2025-23211](https://github.com/IIxoskeletonII/DataPrivacy-CVE-2025-23211) :  ![starts](https://img.shields.io/github/stars/IIxoskeletonII/DataPrivacy-CVE-2025-23211.svg) ![forks](https://img.shields.io/github/forks/IIxoskeletonII/DataPrivacy-CVE-2025-23211.svg)


## CVE-2025-10951
 A vulnerability was identified in geyang ml-logger up to acf255bade5be6ad88d90735c8367b28cbe3a743. Affected by this vulnerability is the function log_handler of the file ml_logger/server.py. Such manipulation of the argument File leads to path traversal. It is possible to launch the attack remotely. The exploit is publicly available and might be used. This product takes the approach of rolling releases to provide continious delivery. Therefore, version details for affected and updated releases are not available.

- [https://github.com/1amUnvalid/CVE-2025-10951](https://github.com/1amUnvalid/CVE-2025-10951) :  ![starts](https://img.shields.io/github/stars/1amUnvalid/CVE-2025-10951.svg) ![forks](https://img.shields.io/github/forks/1amUnvalid/CVE-2025-10951.svg)


## CVE-2025-9242
If the Firebox was previously configured with the mobile user VPN with IKEv2 or a branch office VPN using IKEv2 to a dynamic gateway peer, and both of those configurations have since been deleted, that Firebox may still be vulnerable if a branch office VPN to a static gateway peer is still configured.

- [https://github.com/UnusualGiraffe/WatchGuard-CVE-2025-9242-PoC-and-Mass-Scanner](https://github.com/UnusualGiraffe/WatchGuard-CVE-2025-9242-PoC-and-Mass-Scanner) :  ![starts](https://img.shields.io/github/stars/UnusualGiraffe/WatchGuard-CVE-2025-9242-PoC-and-Mass-Scanner.svg) ![forks](https://img.shields.io/github/forks/UnusualGiraffe/WatchGuard-CVE-2025-9242-PoC-and-Mass-Scanner.svg)


## CVE-2025-5781
 Information Exposure Vulnerability in Hitachi Ops Center API Configuration Manager, Hitachi Configuration Manager, Hitachi Device Manager allows Session Hijacking.This issue affects Hitachi Ops Center API Configuration Manager: from 10.0.0-00 before 11.0.5-00; Hitachi Configuration Manager: from 8.5.1-00 before 11.0.5-00; Hitachi Device Manager: from 8.4.1-00 before 8.6.5-00.

- [https://github.com/jasonbernier/CVE-2025-5781](https://github.com/jasonbernier/CVE-2025-5781) :  ![starts](https://img.shields.io/github/stars/jasonbernier/CVE-2025-5781.svg) ![forks](https://img.shields.io/github/forks/jasonbernier/CVE-2025-5781.svg)


## CVE-2025-4917
 A vulnerability classified as critical has been found in PHPGurukul Auto Taxi Stand Management System 1.0. Affected is an unknown function of the file /admin/new-autoortaxi-entry-form.php. The manipulation of the argument drivername leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/aliyabuz25/CVE-2025-49173](https://github.com/aliyabuz25/CVE-2025-49173) :  ![starts](https://img.shields.io/github/stars/aliyabuz25/CVE-2025-49173.svg) ![forks](https://img.shields.io/github/forks/aliyabuz25/CVE-2025-49173.svg)


## CVE-2024-52806
 SimpleSAMLphp SAML2 library is a PHP library for SAML2 related functionality. When loading an (untrusted) XML document, for example the SAMLResponse, it's possible to induce an XXE. This vulnerability is fixed in 4.6.14 and 5.0.0-alpha.18.

- [https://github.com/heartlesseorg-dot/CVE-2024-52806-PoC](https://github.com/heartlesseorg-dot/CVE-2024-52806-PoC) :  ![starts](https://img.shields.io/github/stars/heartlesseorg-dot/CVE-2024-52806-PoC.svg) ![forks](https://img.shields.io/github/forks/heartlesseorg-dot/CVE-2024-52806-PoC.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/yfelipecruvinel/tryhackme-moniker-link](https://github.com/yfelipecruvinel/tryhackme-moniker-link) :  ![starts](https://img.shields.io/github/stars/yfelipecruvinel/tryhackme-moniker-link.svg) ![forks](https://img.shields.io/github/forks/yfelipecruvinel/tryhackme-moniker-link.svg)


## CVE-2024-3867
 The archive-tainacan-collection theme for WordPress is vulnerable to Reflected Cross-Site Scripting due to the use of add_query_arg without appropriate escaping on the URL in version 2.7.2. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/c4cnm/CVE-2024-3867](https://github.com/c4cnm/CVE-2024-3867) :  ![starts](https://img.shields.io/github/stars/c4cnm/CVE-2024-3867.svg) ![forks](https://img.shields.io/github/forks/c4cnm/CVE-2024-3867.svg)

