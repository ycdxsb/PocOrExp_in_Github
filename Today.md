# Update 2026-07-03
## CVE-2026-56011
 Unauthenticated Cross Site Scripting (XSS) in MapPress Maps for WordPress = 2.97.3 versions.

- [https://github.com/rootdirective-sec/CVE-2026-56011-Lab](https://github.com/rootdirective-sec/CVE-2026-56011-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-56011-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-56011-Lab.svg)


## CVE-2026-55200
 libssh2 through 1.11.1, fixed in commit 7acf3df contains an out-of-bounds write vulnerability in ssh2_transport_read() that fails to enforce upper bounds on packet_length field. Remote attackers can send crafted SSH packets with excessively large packet_length values to corrupt heap memory and achieve remote code execution.

- [https://github.com/kaleth4/CVE-2026-55200](https://github.com/kaleth4/CVE-2026-55200) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-55200.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-55200.svg)


## CVE-2026-53753
 Crawl4AI is an open-source LLM friendly web crawler & scraper. Prior to 0.8.7, the _safe_eval_expression() function in the computed fields feature uses an AST validator that only blocks attributes starting with underscore. Python generator and frame object attributes (gi_frame, f_back, f_builtins) do NOT start with underscore, enabling a complete sandbox escape to achieve arbitrary code execution. The attack requires no authentication (JWT disabled by default) and is triggered via POST /crawl with a crafted extraction schema. This vulnerability is fixed in 0.8.7.

- [https://github.com/0xEnc0der/CVE-2026-53753](https://github.com/0xEnc0der/CVE-2026-53753) :  ![starts](https://img.shields.io/github/stars/0xEnc0der/CVE-2026-53753.svg) ![forks](https://img.shields.io/github/forks/0xEnc0der/CVE-2026-53753.svg)


## CVE-2026-53694
 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') vulnerability in Nomachine allows Argument Injection.This issue affects Nomachine: before 9.5.7, before 8.23.2.

- [https://github.com/do4choo/CVE-2026-53694-NoMachine-LPE](https://github.com/do4choo/CVE-2026-53694-NoMachine-LPE) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-53694-NoMachine-LPE.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-53694-NoMachine-LPE.svg)


## CVE-2026-51947
 An issue in Pivotal CRM 6.6.4.08 and systems using patch-ghi-15381-cwe-502-20251225.zip (fixed in Pivotal CRM 6.6.5.10 and Patch_CWE502_20260316.zip) allows a remote attacker to execute arbitrary code via the Pivotal.Engine.Client.Services.Conversion.dll component. NOTE: this issue exists because of an incomplete fix for CVE-2026-39253.

- [https://github.com/timtimxs/CVE-2026-51947-Advisory](https://github.com/timtimxs/CVE-2026-51947-Advisory) :  ![starts](https://img.shields.io/github/stars/timtimxs/CVE-2026-51947-Advisory.svg) ![forks](https://img.shields.io/github/forks/timtimxs/CVE-2026-51947-Advisory.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/NoXiVaR/CVE-2026-48907](https://github.com/NoXiVaR/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/NoXiVaR/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/NoXiVaR/CVE-2026-48907.svg)


## CVE-2026-46680
 containerd is an open-source container runtime. In versions prior to 1.7.32, 2.0.9, 2.2.4 and 2.3.1, containers launched with a numeric User directive that cannot be parsed as a 32-bit integer are incorrectly treated as a username, leading to runAsNonRoot evasion. If a crafted image provides an /etc/passwd file mapping this large numeric string to root, the container ultimately runs as root (UID 0). This allows the Kubernetes runAsNonRoot restriction to be bypassed, causing unexpected behavior for environments that require containers to run as a non-root user. This issue has been fixed in versions 1.7.32, 2.0.9, 2.2.4 and 2.3.1.

- [https://github.com/r0binak/CVE-2026-46680](https://github.com/r0binak/CVE-2026-46680) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2026-46680.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2026-46680.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/V0IDNETWORK/CVE-2026-46331](https://github.com/V0IDNETWORK/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/V0IDNETWORK/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/V0IDNETWORK/CVE-2026-46331.svg)


## CVE-2026-44963
 A vulnerability allowing remote code execution (RCE) on the Backup Server by an authenticated domain user.

- [https://github.com/suce0155/CVE_2026_44963](https://github.com/suce0155/CVE_2026_44963) :  ![starts](https://img.shields.io/github/stars/suce0155/CVE_2026_44963.svg) ![forks](https://img.shields.io/github/forks/suce0155/CVE_2026_44963.svg)


## CVE-2026-43735
 The issue was addressed with improved checks. This issue is fixed in Safari 26.5.2, iOS 26.5.2 and iPadOS 26.5.2, macOS Tahoe 26.5.2. A malicious website may exfiltrate data cross-origin.

- [https://github.com/dem0ns/CVE-2026-43735](https://github.com/dem0ns/CVE-2026-43735) :  ![starts](https://img.shields.io/github/stars/dem0ns/CVE-2026-43735.svg) ![forks](https://img.shields.io/github/forks/dem0ns/CVE-2026-43735.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/aratane/CVE-2026-42945](https://github.com/aratane/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/aratane/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/aratane/CVE-2026-42945.svg)


## CVE-2026-38751
 OpenSTAManager version 2.10 and earlier contains an arbitrary file upload vulnerability in the module update functionality (modules/aggiornamenti/upload_modules.php)

- [https://github.com/hackthem/OpenSTAManager_RCE_Exploit-CVE-2026-38751-](https://github.com/hackthem/OpenSTAManager_RCE_Exploit-CVE-2026-38751-) :  ![starts](https://img.shields.io/github/stars/hackthem/OpenSTAManager_RCE_Exploit-CVE-2026-38751-.svg) ![forks](https://img.shields.io/github/forks/hackthem/OpenSTAManager_RCE_Exploit-CVE-2026-38751-.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/bakano98/cve-2026-23111-poc](https://github.com/bakano98/cve-2026-23111-poc) :  ![starts](https://img.shields.io/github/stars/bakano98/cve-2026-23111-poc.svg) ![forks](https://img.shields.io/github/forks/bakano98/cve-2026-23111-poc.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/emilliewatson96/spryCVE-2026-10520](https://github.com/emilliewatson96/spryCVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/emilliewatson96/spryCVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/emilliewatson96/spryCVE-2026-10520.svg)


## CVE-2026-6307
 Type Confusion in Turbofan in Google Chrome prior to 147.0.7727.101 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xsha/CVE-2026-6307](https://github.com/0xsha/CVE-2026-6307) :  ![starts](https://img.shields.io/github/stars/0xsha/CVE-2026-6307.svg) ![forks](https://img.shields.io/github/forks/0xsha/CVE-2026-6307.svg)
- [https://github.com/J4ck3LSyN-Gen2/CVE-2026-6307-Longinus](https://github.com/J4ck3LSyN-Gen2/CVE-2026-6307-Longinus) :  ![starts](https://img.shields.io/github/stars/J4ck3LSyN-Gen2/CVE-2026-6307-Longinus.svg) ![forks](https://img.shields.io/github/forks/J4ck3LSyN-Gen2/CVE-2026-6307-Longinus.svg)


## CVE-2026-5416
 Due to the improper neutralization of special elements used in a name parameter a low privileged remote attacker can exploit a command injection vulnerability in the Managed Ethernet Switch, resulting in full system compromise.

- [https://github.com/ja-errorpro/CVE-2026-54161](https://github.com/ja-errorpro/CVE-2026-54161) :  ![starts](https://img.shields.io/github/stars/ja-errorpro/CVE-2026-54161.svg) ![forks](https://img.shields.io/github/forks/ja-errorpro/CVE-2026-54161.svg)


## CVE-2026-3227
Successful exploitation allows an authenticated attacker to execute system commands with root privileges, leading to full device compromise.

- [https://github.com/do4choo/CVE-2026-3227-TP-Link-authenticated-RCE](https://github.com/do4choo/CVE-2026-3227-TP-Link-authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-3227-TP-Link-authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-3227-TP-Link-authenticated-RCE.svg)


## CVE-2025-69212
 OpenSTAManager is an open source management software for technical assistance and invoicing. In 2.9.8 and earlier, a critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.

- [https://github.com/m2sousa/CVE-2025-69212](https://github.com/m2sousa/CVE-2025-69212) :  ![starts](https://img.shields.io/github/stars/m2sousa/CVE-2025-69212.svg) ![forks](https://img.shields.io/github/forks/m2sousa/CVE-2025-69212.svg)
- [https://github.com/alaeddine03/CVE-2025-69212-PoC](https://github.com/alaeddine03/CVE-2025-69212-PoC) :  ![starts](https://img.shields.io/github/stars/alaeddine03/CVE-2025-69212-PoC.svg) ![forks](https://img.shields.io/github/forks/alaeddine03/CVE-2025-69212-PoC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/Its1Zero/cve-2025-57819-exploit](https://github.com/Its1Zero/cve-2025-57819-exploit) :  ![starts](https://img.shields.io/github/stars/Its1Zero/cve-2025-57819-exploit.svg) ![forks](https://img.shields.io/github/forks/Its1Zero/cve-2025-57819-exploit.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js](https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js) :  ![starts](https://img.shields.io/github/stars/hujiaozhuzhu/CVE-2025-29927__Next.js.svg) ![forks](https://img.shields.io/github/forks/hujiaozhuzhu/CVE-2025-29927__Next.js.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/T0tooro/cve-2025-24054-lab](https://github.com/T0tooro/cve-2025-24054-lab) :  ![starts](https://img.shields.io/github/stars/T0tooro/cve-2025-24054-lab.svg) ![forks](https://img.shields.io/github/forks/T0tooro/cve-2025-24054-lab.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/RandyNin/CVE-2023-4220](https://github.com/RandyNin/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/RandyNin/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/RandyNin/CVE-2023-4220.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-27877
 An issue was discovered in Veritas Backup Exec before 21.2. It supports multiple authentication schemes: SHA authentication is one of these. This authentication scheme is no longer used in current versions of the product, but hadn't yet been disabled. An attacker could remotely exploit this scheme to gain unauthorized access to an Agent and execute privileged commands.

- [https://github.com/yashswarup12/CVE-2021-27877-PoC](https://github.com/yashswarup12/CVE-2021-27877-PoC) :  ![starts](https://img.shields.io/github/stars/yashswarup12/CVE-2021-27877-PoC.svg) ![forks](https://img.shields.io/github/forks/yashswarup12/CVE-2021-27877-PoC.svg)


## CVE-2021-1931
 Possible buffer overflow due to improper validation of buffer length while processing fast boot commands in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music

- [https://github.com/aomsin2526/xperia_5_bl_unlocker_poc](https://github.com/aomsin2526/xperia_5_bl_unlocker_poc) :  ![starts](https://img.shields.io/github/stars/aomsin2526/xperia_5_bl_unlocker_poc.svg) ![forks](https://img.shields.io/github/forks/aomsin2526/xperia_5_bl_unlocker_poc.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/DevRafaelprogrammer/F5-BIG-IP](https://github.com/DevRafaelprogrammer/F5-BIG-IP) :  ![starts](https://img.shields.io/github/stars/DevRafaelprogrammer/F5-BIG-IP.svg) ![forks](https://img.shields.io/github/forks/DevRafaelprogrammer/F5-BIG-IP.svg)


## CVE-2013-0169
 The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0 and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and other products, do not properly consider timing side-channel attacks on a MAC check requirement during the processing of malformed CBC padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data for crafted packets, aka the "Lucky Thirteen" issue.

- [https://github.com/SwitdnSec/Lucky13-Exploit-Script](https://github.com/SwitdnSec/Lucky13-Exploit-Script) :  ![starts](https://img.shields.io/github/stars/SwitdnSec/Lucky13-Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/SwitdnSec/Lucky13-Exploit-Script.svg)

