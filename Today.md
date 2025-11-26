# Update 2025-11-26
## CVE-2025-65018
 LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From version 1.6.0 to before 1.6.51, there is a heap buffer overflow vulnerability in the libpng simplified API function png_image_finish_read when processing 16-bit interlaced PNGs with 8-bit output format. Attacker-crafted interlaced PNG files cause heap writes beyond allocated buffer bounds. This issue has been patched in version 1.6.51.

- [https://github.com/Neo-Neo6/CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-](https://github.com/Neo-Neo6/CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-) :  ![starts](https://img.shields.io/github/stars/Neo-Neo6/CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-.svg) ![forks](https://img.shields.io/github/forks/Neo-Neo6/CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-.svg)


## CVE-2025-64720
 LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From version 1.6.0 to before 1.6.51, an out-of-bounds read vulnerability exists in png_image_read_composite when processing palette images with PNG_FLAG_OPTIMIZE_ALPHA enabled. The palette compositing code in png_init_read_transformations incorrectly applies background compositing during premultiplication, violating the invariant component ≤ alpha × 257 required by the simplified PNG API. This issue has been patched in version 1.6.51.

- [https://github.com/truediogo/CVE-2025-64720](https://github.com/truediogo/CVE-2025-64720) :  ![starts](https://img.shields.io/github/stars/truediogo/CVE-2025-64720.svg) ![forks](https://img.shields.io/github/forks/truediogo/CVE-2025-64720.svg)


## CVE-2025-63914
 An issue was discovered in Cinnamon kotaemon 0.11.0. The _may_extract_zip function in the \libs\ktem\ktem\index\file\ui.py file does not check the contents of uploaded ZIP files. Although the contents are extracted into a temporary folder that is cleared before each extraction, successfully uploading a ZIP bomb could still cause the server to consume excessive resources during decompression. Moreover, if no further files are uploaded afterward, the extracted data could occupy disk space and potentially render the system unavailable. Anyone with permission to upload files can carry out this attack.

- [https://github.com/WxDou/CVE-2025-63914](https://github.com/WxDou/CVE-2025-63914) :  ![starts](https://img.shields.io/github/stars/WxDou/CVE-2025-63914.svg) ![forks](https://img.shields.io/github/forks/WxDou/CVE-2025-63914.svg)


## CVE-2025-63498
 alinto SOGo 5.12.3 is vulnerable to Cross Site Scripting (XSS) via the "userName" parameter.

- [https://github.com/xryptoh/CVE-2025-63498](https://github.com/xryptoh/CVE-2025-63498) :  ![starts](https://img.shields.io/github/stars/xryptoh/CVE-2025-63498.svg) ![forks](https://img.shields.io/github/forks/xryptoh/CVE-2025-63498.svg)


## CVE-2025-62726
 n8n is an open source workflow automation platform. Prior to 1.113.0, a remote code execution vulnerability exists in the Git Node component available in both Cloud and Self-Hosted versions of n8n. When a malicious actor clones a remote repository containing a pre-commit hook, the subsequent use of the Commit operation in the Git Node can inadvertently trigger the hook’s execution. This allows attackers to execute arbitrary code within the n8n environment, potentially compromising the system and any connected credentials or workflows. This vulnerability is fixed in 1.113.0.

- [https://github.com/baktistr/cve-2025-62726-malicious-repo](https://github.com/baktistr/cve-2025-62726-malicious-repo) :  ![starts](https://img.shields.io/github/stars/baktistr/cve-2025-62726-malicious-repo.svg) ![forks](https://img.shields.io/github/forks/baktistr/cve-2025-62726-malicious-repo.svg)
- [https://github.com/baktistr/cve-2025-62726-poc](https://github.com/baktistr/cve-2025-62726-poc) :  ![starts](https://img.shields.io/github/stars/baktistr/cve-2025-62726-poc.svg) ![forks](https://img.shields.io/github/forks/baktistr/cve-2025-62726-poc.svg)
- [https://github.com/baktistr/cve-2025-62726-legit-repo](https://github.com/baktistr/cve-2025-62726-legit-repo) :  ![starts](https://img.shields.io/github/stars/baktistr/cve-2025-62726-legit-repo.svg) ![forks](https://img.shields.io/github/forks/baktistr/cve-2025-62726-legit-repo.svg)
- [https://github.com/baktistr/CVE-2025-62726-POC---n8n-Git-Node-RCE](https://github.com/baktistr/CVE-2025-62726-POC---n8n-Git-Node-RCE) :  ![starts](https://img.shields.io/github/stars/baktistr/CVE-2025-62726-POC---n8n-Git-Node-RCE.svg) ![forks](https://img.shields.io/github/forks/baktistr/CVE-2025-62726-POC---n8n-Git-Node-RCE.svg)


## CVE-2025-58034
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability [CWE-78] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4.0 through 7.4.10, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an authenticated attacker to execute unauthorized code on the underlying system via crafted HTTP requests or CLI commands.

- [https://github.com/fluxmoth/CVE-2025-58034](https://github.com/fluxmoth/CVE-2025-58034) :  ![starts](https://img.shields.io/github/stars/fluxmoth/CVE-2025-58034.svg) ![forks](https://img.shields.io/github/forks/fluxmoth/CVE-2025-58034.svg)


## CVE-2025-54381
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. In versions 1.4.0 until 1.4.19, the file upload processing system contains an SSRF vulnerability that allows unauthenticated remote attackers to force the server to make arbitrary HTTP requests. The vulnerability stems from the multipart form data and JSON request handlers, which automatically download files from user-provided URLs without validating whether those URLs point to internal network addresses, cloud metadata endpoints, or other restricted resources. The documentation explicitly promotes this URL-based file upload feature, making it an intended design that exposes all deployed services to SSRF attacks by default. Version 1.4.19 contains a patch for the issue.

- [https://github.com/IS8123/CVE-2025-54381](https://github.com/IS8123/CVE-2025-54381) :  ![starts](https://img.shields.io/github/stars/IS8123/CVE-2025-54381.svg) ![forks](https://img.shields.io/github/forks/IS8123/CVE-2025-54381.svg)


## CVE-2025-50165
 Untrusted pointer dereference in Microsoft Graphics Component allows an unauthorized attacker to execute code over a network.

- [https://github.com/fluxmoth/CVE-2025-50165](https://github.com/fluxmoth/CVE-2025-50165) :  ![starts](https://img.shields.io/github/stars/fluxmoth/CVE-2025-50165.svg) ![forks](https://img.shields.io/github/forks/fluxmoth/CVE-2025-50165.svg)


## CVE-2025-49752
 Azure Bastion Elevation of Privilege Vulnerability

- [https://github.com/boogabearbombernub/cve-2025-49752-lab](https://github.com/boogabearbombernub/cve-2025-49752-lab) :  ![starts](https://img.shields.io/github/stars/boogabearbombernub/cve-2025-49752-lab.svg) ![forks](https://img.shields.io/github/forks/boogabearbombernub/cve-2025-49752-lab.svg)


## CVE-2025-38678
 [49042.221382] RIP: 0010:nf_hook_entry_head+0xaa/0x150

- [https://github.com/guard-wait/CVE-2025-38678_POC](https://github.com/guard-wait/CVE-2025-38678_POC) :  ![starts](https://img.shields.io/github/stars/guard-wait/CVE-2025-38678_POC.svg) ![forks](https://img.shields.io/github/forks/guard-wait/CVE-2025-38678_POC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-13223
 Type Confusion in V8 in Google Chrome prior to 142.0.7444.175 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Darwin72820/CVE-2025-13223](https://github.com/Darwin72820/CVE-2025-13223) :  ![starts](https://img.shields.io/github/stars/Darwin72820/CVE-2025-13223.svg) ![forks](https://img.shields.io/github/forks/Darwin72820/CVE-2025-13223.svg)


## CVE-2025-11001
The specific flaw exists within the handling of symbolic links in ZIP files. Crafted data in a ZIP file can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of a service account. Was ZDI-CAN-26753.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-11001](https://github.com/B1ack4sh/Blackash-CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-11001.svg)


## CVE-2025-6568
 A vulnerability classified as critical has been found in TOTOLINK EX1200T 4.1.2cu.5232_B20210713. Affected is an unknown function of the file /boafrm/formIpv6Setup of the component HTTP POST Request Handler. The manipulation of the argument submit-url leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Rivek619/CVE-2025-65681](https://github.com/Rivek619/CVE-2025-65681) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65681.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65681.svg)


## CVE-2025-6567
 A vulnerability was found in Campcodes Online Recruitment Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file Recruitment/admin/view_application.php. The manipulation of the argument ID leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Rivek619/CVE-2025-65675](https://github.com/Rivek619/CVE-2025-65675) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65675.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65675.svg)
- [https://github.com/Rivek619/CVE-2025-65672](https://github.com/Rivek619/CVE-2025-65672) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65672.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65672.svg)
- [https://github.com/Rivek619/CVE-2025-65670](https://github.com/Rivek619/CVE-2025-65670) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65670.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65670.svg)
- [https://github.com/Rivek619/CVE-2025-65676](https://github.com/Rivek619/CVE-2025-65676) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65676.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65676.svg)


## CVE-2025-6566
 A vulnerability was found in oatpp Oat++ up to 1.3.1. It has been declared as critical. This vulnerability affects the function deserializeArray of the file src/oatpp/json/Deserializer.cpp. The manipulation leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Rivek619/CVE-2025-65669](https://github.com/Rivek619/CVE-2025-65669) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65669.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65669.svg)


## CVE-2025-6391
 unauthorized access, session hijacking, and information disclosure.

- [https://github.com/zero-day348/CVE-2025-63915-There-is-a-Reflected-xss-vulnerability-exists-in-DoraCMS](https://github.com/zero-day348/CVE-2025-63915-There-is-a-Reflected-xss-vulnerability-exists-in-DoraCMS) :  ![starts](https://img.shields.io/github/stars/zero-day348/CVE-2025-63915-There-is-a-Reflected-xss-vulnerability-exists-in-DoraCMS.svg) ![forks](https://img.shields.io/github/forks/zero-day348/CVE-2025-63915-There-is-a-Reflected-xss-vulnerability-exists-in-DoraCMS.svg)


## CVE-2025-6373
 A vulnerability has been found in D-Link DIR-619L 2.06B01 and classified as critical. This vulnerability affects the function formSetWizard1 of the file /goform/formWlSiteSurvey. The manipulation of the argument curTime leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/huthx/CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS](https://github.com/huthx/CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/huthx/CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/huthx/CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS.svg)


## CVE-2025-2598
 When the AWS Cloud Development Kit (AWS CDK) Command Line Interface (AWS CDK CLI) is used with a credential plugin which returns an expiration property with the retrieved AWS credentials, the credentials are printed to the console output. To mitigate this issue, users should upgrade to version 2.178.2 or later and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/SallyXVIII/Final-Proj](https://github.com/SallyXVIII/Final-Proj) :  ![starts](https://img.shields.io/github/stars/SallyXVIII/Final-Proj.svg) ![forks](https://img.shields.io/github/forks/SallyXVIII/Final-Proj.svg)


## CVE-2025-1338
 A vulnerability was found in NUUO Camera up to 20250203. It has been declared as critical. This vulnerability affects the function print_file of the file /handle_config.php. The manipulation of the argument log leads to command injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/d0n601/CVE-2025-13380](https://github.com/d0n601/CVE-2025-13380) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-13380.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-13380.svg)


## CVE-2024-29943
 An attacker was able to perform an out-of-bounds read or write on a JavaScript object by fooling range-based bounds check elimination. This vulnerability affects Firefox  124.0.1.

- [https://github.com/seadragnol/CVE-2024-29943](https://github.com/seadragnol/CVE-2024-29943) :  ![starts](https://img.shields.io/github/stars/seadragnol/CVE-2024-29943.svg) ![forks](https://img.shields.io/github/forks/seadragnol/CVE-2024-29943.svg)


## CVE-2024-24576
The fix is included in Rust 1.77.2. Note that the new escaping logic for batch files errs on the conservative side, and could reject valid arguments. Those who implement the escaping themselves or only handle trusted inputs on Windows can also use the `CommandExt::raw_arg` method to bypass the standard library's escaping logic.

- [https://github.com/nasa-frostb1te/CVE-2024-24576-PoC](https://github.com/nasa-frostb1te/CVE-2024-24576-PoC) :  ![starts](https://img.shields.io/github/stars/nasa-frostb1te/CVE-2024-24576-PoC.svg) ![forks](https://img.shields.io/github/forks/nasa-frostb1te/CVE-2024-24576-PoC.svg)


## CVE-2024-12084
 A heap-based buffer overflow flaw was found in the rsync daemon. This issue is due to improper handling of attacker-controlled checksum lengths (s2length) in the code. When MAX_DIGEST_LEN exceeds the fixed SUM_LENGTH (16 bytes), an attacker can write out of bounds in the sum2 buffer.

- [https://github.com/InkeyP/CVE-2024-12084](https://github.com/InkeyP/CVE-2024-12084) :  ![starts](https://img.shields.io/github/stars/InkeyP/CVE-2024-12084.svg) ![forks](https://img.shields.io/github/forks/InkeyP/CVE-2024-12084.svg)


## CVE-2023-36845
  *  23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/kopfjager007/CVE-2023-36845](https://github.com/kopfjager007/CVE-2023-36845) :  ![starts](https://img.shields.io/github/stars/kopfjager007/CVE-2023-36845.svg) ![forks](https://img.shields.io/github/forks/kopfjager007/CVE-2023-36845.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-4462
 Employee Records System version 1.0 contains an unrestricted file upload vulnerability that allows a remote unauthenticated attacker to upload arbitrary files via the uploadID.php endpoint; uploaded files can be executed because the application does not perform proper server-side validation. Exploitation evidence was observed by the Shadowserver Foundation on 2025-02-06 UTC.

- [https://github.com/Pranjal6955/CVE-2021-4462](https://github.com/Pranjal6955/CVE-2021-4462) :  ![starts](https://img.shields.io/github/stars/Pranjal6955/CVE-2021-4462.svg) ![forks](https://img.shields.io/github/forks/Pranjal6955/CVE-2021-4462.svg)


## CVE-2019-8451
 The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.

- [https://github.com/b0ul1/CVE-2019-8451](https://github.com/b0ul1/CVE-2019-8451) :  ![starts](https://img.shields.io/github/stars/b0ul1/CVE-2019-8451.svg) ![forks](https://img.shields.io/github/forks/b0ul1/CVE-2019-8451.svg)


## CVE-2018-12533
 JBoss RichFaces 3.1.0 through 3.3.4 allows unauthenticated remote attackers to inject expression language (EL) expressions and execute arbitrary Java code via a /DATA/ substring in a path with an org.richfaces.renderkit.html.Paint2DResource$ImageData object, aka RF-14310.

- [https://github.com/LucasKatashi/paint2die](https://github.com/LucasKatashi/paint2die) :  ![starts](https://img.shields.io/github/stars/LucasKatashi/paint2die.svg) ![forks](https://img.shields.io/github/forks/LucasKatashi/paint2die.svg)

