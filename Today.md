# Update 2026-10-07
## CVE-2026-105314
 Papermerge 3.5.3 allows remote code execution by a standard user via directory traversal in a /api/documents/upload call. A Python .pth file can be written to site-packages, and its code is executed upon the next start of the Python interpreter.

- [https://github.com/kashishtopi/CVE-2026-105314](https://github.com/kashishtopi/CVE-2026-105314) :  ![starts](https://img.shields.io/github/stars/kashishtopi/CVE-2026-105314.svg) ![forks](https://img.shields.io/github/forks/kashishtopi/CVE-2026-105314.svg)


## CVE-2026-105134
 A flaw has been found in Ahsay AhsayCBS up to 10.3.2. This vulnerability affects unknown code of the file /rps/api/json/UpdateReceivers.do of the component Replication Receiver. Executing a manipulation of the argument random can lead to os command injection. It is possible to launch the attack remotely. The exploit has been published and may be used. Upgrading to version 10.3.4 is able to resolve this issue. Upgrading the affected component is advised.

- [https://github.com/RayanAlmulhim/CVE-2026-105134-lab](https://github.com/RayanAlmulhim/CVE-2026-105134-lab) :  ![starts](https://img.shields.io/github/stars/RayanAlmulhim/CVE-2026-105134-lab.svg) ![forks](https://img.shields.io/github/forks/RayanAlmulhim/CVE-2026-105134-lab.svg)


## CVE-2026-102282
 adm-zip is a JavaScript library for creating and extracting ZIP archives in Node.js. Prior to 0.6.1, adm-zip applies the Unix permission bits stored in a zip entry directly to the extracted file via `fs.chmodSync()` when `keepOriginalPermission=true` is passed to `extractAllTo()`/`extractEntryTo()` — and it never filters the setuid/setgid/sticky bits out of those bits. A zip crafted by an attacker can therefore produce an extracted binary with mode `04755`. When extraction runs as root (the default posture in Docker builds, CI runners, and privileged install steps — the exact environments where this flag is used), the resulting root-owned setuid file is executed later by a lesser-privileged user, turning the attacker's code into a root execution. Version 0.6.1 fixes the issue.

- [https://github.com/x86byte/adm-zip_LPE-PoC](https://github.com/x86byte/adm-zip_LPE-PoC) :  ![starts](https://img.shields.io/github/stars/x86byte/adm-zip_LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/x86byte/adm-zip_LPE-PoC.svg)
- [https://github.com/Ahmed-Elmahgob/POC-CVE-2026-102282](https://github.com/Ahmed-Elmahgob/POC-CVE-2026-102282) :  ![starts](https://img.shields.io/github/stars/Ahmed-Elmahgob/POC-CVE-2026-102282.svg) ![forks](https://img.shields.io/github/forks/Ahmed-Elmahgob/POC-CVE-2026-102282.svg)


## CVE-2026-93687
 braces through 3.0.3 contains a stack overflow vulnerability in the recursive AST walkers that lack depth guards. Attackers can supply deeply nested brace patterns under the character limit to exhaust the call stack and terminate the Node.js process with an uncaught RangeError.

- [https://github.com/pillarsdotnet/node-braces](https://github.com/pillarsdotnet/node-braces) :  ![starts](https://img.shields.io/github/stars/pillarsdotnet/node-braces.svg) ![forks](https://img.shields.io/github/forks/pillarsdotnet/node-braces.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/0xBlackash/CVE-2026-86950](https://github.com/0xBlackash/CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-86950.svg)


## CVE-2026-86881
 A certificate validation issue was addressed with improved certificate validation. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27 and iPadOS 27, macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7, tvOS 27, visionOS 27, watchOS 27. An attacker with a compromised intermediate certificate authority may be able to issue certificates with arbitrary extended key usages.

- [https://github.com/0xcrypto/CVE-2026-86881](https://github.com/0xcrypto/CVE-2026-86881) :  ![starts](https://img.shields.io/github/stars/0xcrypto/CVE-2026-86881.svg) ![forks](https://img.shields.io/github/forks/0xcrypto/CVE-2026-86881.svg)


## CVE-2026-71486
 vLLM is an inference and serving engine for large language models. Prior to 0.26.0, the /v1/completions/derender and /v1/chat/completions/derender endpoints accept caller-supplied GenerateResponse objects whose generate_responses, choices, token_ids, prompt_logprobs, logprobs.content, top_logprobs, and routed_experts structures are processed by OnlineDerenderer and tokenizer.decode before max_model_len, max_tokens, max_num_seqs, or response-size limits are enforced, allowing an authenticated API client to consume excessive CPU and memory and produce oversized responses. This issue is fixed in version 0.26.0.

- [https://github.com/tmvictorpeters/jbo4rgl](https://github.com/tmvictorpeters/jbo4rgl) :  ![starts](https://img.shields.io/github/stars/tmvictorpeters/jbo4rgl.svg) ![forks](https://img.shields.io/github/forks/tmvictorpeters/jbo4rgl.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/dr4mohamed/CVE-2026-46333](https://github.com/dr4mohamed/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/dr4mohamed/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/dr4mohamed/CVE-2026-46333.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ihamn/matisse-public](https://github.com/ihamn/matisse-public) :  ![starts](https://img.shields.io/github/stars/ihamn/matisse-public.svg) ![forks](https://img.shields.io/github/forks/ihamn/matisse-public.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/mhdnihan/CVE-2026-43284-DIRTY-FRAG-](https://github.com/mhdnihan/CVE-2026-43284-DIRTY-FRAG-) :  ![starts](https://img.shields.io/github/stars/mhdnihan/CVE-2026-43284-DIRTY-FRAG-.svg) ![forks](https://img.shields.io/github/forks/mhdnihan/CVE-2026-43284-DIRTY-FRAG-.svg)


## CVE-2026-41875
This issue was fixed in a patch to version 6.7 published on 09.11.2026, deployments without this patch are still vulnerable

- [https://github.com/hhg69/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover](https://github.com/hhg69/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover) :  ![starts](https://img.shields.io/github/stars/hhg69/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover.svg) ![forks](https://img.shields.io/github/forks/hhg69/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-39987-Marimo-RCE](https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-39987-Marimo-RCE) :  ![starts](https://img.shields.io/github/stars/Industri4l-H3ll-Xpl0it3rs/CVE-2026-39987-Marimo-RCE.svg) ![forks](https://img.shields.io/github/forks/Industri4l-H3ll-Xpl0it3rs/CVE-2026-39987-Marimo-RCE.svg)


## CVE-2026-31857
 Craft is a content management system (CMS). Prior to 5.9.9 and 4.17.4, a Remote Code Execution vulnerability exists in the Craft CMS 5 conditions system. The BaseElementSelectConditionRule::getElementIds() method passes user-controlled string input through renderObjectTemplate() -- an unsandboxed Twig rendering function with escaping disabled. Any authenticated Control Panel user (including non-admin roles such as Author or Editor) can achieve full RCE by sending a crafted condition rule via standard element listing endpoints. This vulnerability requires no admin privileges, no special permissions beyond basic control panel access, and bypasses all production hardening settings (allowAdminChanges: false, devMode: false, enableTwigSandbox: true). Users should update to the patched 5.9.9 or 4.17.4 release to mitigate the issue.

- [https://github.com/WhiteMachin3/CVE-2026-31857](https://github.com/WhiteMachin3/CVE-2026-31857) :  ![starts](https://img.shields.io/github/stars/WhiteMachin3/CVE-2026-31857.svg) ![forks](https://img.shields.io/github/forks/WhiteMachin3/CVE-2026-31857.svg)


## CVE-2026-28364
 In OCaml before 4.14.3 and 5.x before 5.4.1, a buffer over-read in Marshal deserialization (runtime/intern.c) enables remote code execution through a multi-phase attack chain. The vulnerability stems from missing bounds validation in the readblock() function, which performs unbounded memcpy() operations using attacker-controlled lengths from crafted Marshal data.

- [https://github.com/Akshay-M-Singh/ocaml-marshal-vulnerability](https://github.com/Akshay-M-Singh/ocaml-marshal-vulnerability) :  ![starts](https://img.shields.io/github/stars/Akshay-M-Singh/ocaml-marshal-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Akshay-M-Singh/ocaml-marshal-vulnerability.svg)


## CVE-2026-21096
 Heap-based buffer overflow in JPEG decoder of libimagecodec.quram.so prior to SMR Sep-2026 Release 1 allows remote attackers to execute arbitrary code.

- [https://github.com/Xen0nize/CVE-2026-21096](https://github.com/Xen0nize/CVE-2026-21096) :  ![starts](https://img.shields.io/github/stars/Xen0nize/CVE-2026-21096.svg) ![forks](https://img.shields.io/github/forks/Xen0nize/CVE-2026-21096.svg)


## CVE-2026-16444
affected user.

- [https://github.com/jamir0quai/CVE-2026-16444](https://github.com/jamir0quai/CVE-2026-16444) :  ![starts](https://img.shields.io/github/stars/jamir0quai/CVE-2026-16444.svg) ![forks](https://img.shields.io/github/forks/jamir0quai/CVE-2026-16444.svg)


## CVE-2026-9562
 A vulnerability has been found in sambitraj STUDENT-MANAGEMENT-SYSTEM up to 56ba287f2e9031523ccb4244cb6e3fe530e4e5d5. The affected element is an unknown function of the component Dashboard. Such manipulation leads to improper access controls. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. This product operates on a rolling release basis, ensuring continuous delivery. Consequently, there are no version details for either affected or updated releases. Multiple endpoints are affected. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/0xSemizzz/CVE-2026-95622](https://github.com/0xSemizzz/CVE-2026-95622) :  ![starts](https://img.shields.io/github/stars/0xSemizzz/CVE-2026-95622.svg) ![forks](https://img.shields.io/github/forks/0xSemizzz/CVE-2026-95622.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/inforcqb/CVE-2026-43499-pja110](https://github.com/inforcqb/CVE-2026-43499-pja110) :  ![starts](https://img.shields.io/github/stars/inforcqb/CVE-2026-43499-pja110.svg) ![forks](https://img.shields.io/github/forks/inforcqb/CVE-2026-43499-pja110.svg)
- [https://github.com/a23bc/ALI-AN00-cve-2026-43499](https://github.com/a23bc/ALI-AN00-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/a23bc/ALI-AN00-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/a23bc/ALI-AN00-cve-2026-43499.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-66034
 fontTools is a library for manipulating fonts, written in Python. In versions from 4.33.0 to before 4.60.2, the fonttools varLib (or python3 -m fontTools.varLib) script has an arbitrary file write vulnerability that leads to remote code execution when a malicious .designspace file is processed. The vulnerability affects the main() code path of fontTools.varLib, used by the fonttools varLib CLI and any code that invokes fontTools.varLib.main(). This issue has been patched in version 4.60.2.

- [https://github.com/Liquid-Sec/Variatype.htb-CVE-2025-66034](https://github.com/Liquid-Sec/Variatype.htb-CVE-2025-66034) :  ![starts](https://img.shields.io/github/stars/Liquid-Sec/Variatype.htb-CVE-2025-66034.svg) ![forks](https://img.shields.io/github/forks/Liquid-Sec/Variatype.htb-CVE-2025-66034.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/kelltich-756/FreePBX-Breaker](https://github.com/kelltich-756/FreePBX-Breaker) :  ![starts](https://img.shields.io/github/stars/kelltich-756/FreePBX-Breaker.svg) ![forks](https://img.shields.io/github/forks/kelltich-756/FreePBX-Breaker.svg)


## CVE-2025-54769
 An authenticated, read-only user can upload a file and perform a directory traversal to have the uploaded file placed in a location of their choosing.  This can be used to overwrite existing PERL modules within the application to achieve remote code execution (RCE) by an attacker.

- [https://github.com/tunahantekeoglu/CVE-2025-54769](https://github.com/tunahantekeoglu/CVE-2025-54769) :  ![starts](https://img.shields.io/github/stars/tunahantekeoglu/CVE-2025-54769.svg) ![forks](https://img.shields.io/github/forks/tunahantekeoglu/CVE-2025-54769.svg)


## CVE-2025-48617
 In overrideConfig of CarrierConfigLoader.java, there is a possible way to bypass UID check due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/K1tor/PixelVolte5G](https://github.com/K1tor/PixelVolte5G) :  ![starts](https://img.shields.io/github/stars/K1tor/PixelVolte5G.svg) ![forks](https://img.shields.io/github/forks/K1tor/PixelVolte5G.svg)


## CVE-2025-14659
 A vulnerability was detected in D-Link DIR-860LB1 and DIR-868LB1 203b01/203b03. Affected is an unknown function of the component DHCP Daemon. The manipulation of the argument Hostname results in command injection. It is possible to launch the attack remotely. The exploit is now public and may be used.

- [https://github.com/PeterLinccl/CVE-2025-14659-DIR-860L](https://github.com/PeterLinccl/CVE-2025-14659-DIR-860L) :  ![starts](https://img.shields.io/github/stars/PeterLinccl/CVE-2025-14659-DIR-860L.svg) ![forks](https://img.shields.io/github/forks/PeterLinccl/CVE-2025-14659-DIR-860L.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-1122
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.

- [https://github.com/MCRideable3963/RMASmoke-v2](https://github.com/MCRideable3963/RMASmoke-v2) :  ![starts](https://img.shields.io/github/stars/MCRideable3963/RMASmoke-v2.svg) ![forks](https://img.shields.io/github/forks/MCRideable3963/RMASmoke-v2.svg)


## CVE-2024-40453
 squirrellyjs squirrelly v9.0.0 and fixed in v.9.0.1 was discovered to contain a code injection vulnerability via the component options.varName.

- [https://github.com/AC8999/CVE-2024-40453](https://github.com/AC8999/CVE-2024-40453) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2024-40453.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2024-40453.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/weae26/cve-2024-4367-poc](https://github.com/weae26/cve-2024-4367-poc) :  ![starts](https://img.shields.io/github/stars/weae26/cve-2024-4367-poc.svg) ![forks](https://img.shields.io/github/forks/weae26/cve-2024-4367-poc.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/KiroShehata/CVE-2023-45866-Bluetooth-Security-Research](https://github.com/KiroShehata/CVE-2023-45866-Bluetooth-Security-Research) :  ![starts](https://img.shields.io/github/stars/KiroShehata/CVE-2023-45866-Bluetooth-Security-Research.svg) ![forks](https://img.shields.io/github/forks/KiroShehata/CVE-2023-45866-Bluetooth-Security-Research.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)
- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-31624
 Buffer Overflow vulnerability in Tenda AC9 V1.0 through V15.03.05.19(6318), and AC9 V3.0 V15.03.06.42_multi, allows attackers to execute arbitrary code via the urls parameter.

- [https://github.com/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs](https://github.com/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs) :  ![starts](https://img.shields.io/github/stars/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2021-1931
 Possible buffer overflow due to improper validation of buffer length while processing fast boot commands in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music

- [https://github.com/stanw47/Blackberry-Key2-Research](https://github.com/stanw47/Blackberry-Key2-Research) :  ![starts](https://img.shields.io/github/stars/stanw47/Blackberry-Key2-Research.svg) ![forks](https://img.shields.io/github/forks/stanw47/Blackberry-Key2-Research.svg)


## CVE-2020-23546
 IrfanView 4.54 allows attackers to cause a denial of service or possibly other unspecified impacts via a crafted XBM file, related to a "Data from Faulting Address is used as one or more arguments in a subsequent Function Call starting at FORMATS!ReadMosaic+0x0000000000000981.

- [https://github.com/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs](https://github.com/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs) :  ![starts](https://img.shields.io/github/stars/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/Learn-SecByte-CTF-Labs-Tabnabbing-Web-Recon-Nmap-Netdiscover-CVE-Labs.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Piyush-Tiwatne/struts-patch-gap-auditor](https://github.com/Piyush-Tiwatne/struts-patch-gap-auditor) :  ![starts](https://img.shields.io/github/stars/Piyush-Tiwatne/struts-patch-gap-auditor.svg) ![forks](https://img.shields.io/github/forks/Piyush-Tiwatne/struts-patch-gap-auditor.svg)


## CVE-2007-6750
 The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.

- [https://github.com/RoflSecurity/nodeloris](https://github.com/RoflSecurity/nodeloris) :  ![starts](https://img.shields.io/github/stars/RoflSecurity/nodeloris.svg) ![forks](https://img.shields.io/github/forks/RoflSecurity/nodeloris.svg)

