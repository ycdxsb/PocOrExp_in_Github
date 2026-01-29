# Update 2026-01-29
## CVE-2026-24688
 pypdf is a free and open-source pure-python PDF library. An attacker who uses an infinite loop vulnerability that is present in versions prior to 6.6.2 can craft a PDF which leads to an infinite loop. This requires accessing the outlines/bookmarks. This has been fixed in pypdf 6.6.2. If projects cannot upgrade yet, consider applying the changes from PR #3610 manually.

- [https://github.com/JoakimBulow/CVE-2026-24688](https://github.com/JoakimBulow/CVE-2026-24688) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-24688.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-24688.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/Lingzesec/CVE-2026-24061-GUI](https://github.com/Lingzesec/CVE-2026-24061-GUI) :  ![starts](https://img.shields.io/github/stars/Lingzesec/CVE-2026-24061-GUI.svg) ![forks](https://img.shields.io/github/forks/Lingzesec/CVE-2026-24061-GUI.svg)
- [https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root](https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg)
- [https://github.com/novitahk/Exploit-CVE-2026-24061](https://github.com/novitahk/Exploit-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/novitahk/Exploit-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/novitahk/Exploit-CVE-2026-24061.svg)
- [https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd](https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd) :  ![starts](https://img.shields.io/github/stars/androidteacher/CVE-2026-24061-PoC-Telnetd.svg) ![forks](https://img.shields.io/github/forks/androidteacher/CVE-2026-24061-PoC-Telnetd.svg)
- [https://github.com/cumakurt/tscan](https://github.com/cumakurt/tscan) :  ![starts](https://img.shields.io/github/stars/cumakurt/tscan.svg) ![forks](https://img.shields.io/github/forks/cumakurt/tscan.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21509](https://github.com/Ashwesker/Ashwesker-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21509.svg)
- [https://github.com/nicole2ilodl/CVE-2026-21509-PoC](https://github.com/nicole2ilodl/CVE-2026-21509-PoC) :  ![starts](https://img.shields.io/github/stars/nicole2ilodl/CVE-2026-21509-PoC.svg) ![forks](https://img.shields.io/github/forks/nicole2ilodl/CVE-2026-21509-PoC.svg)


## CVE-2025-65264
 The kernel driver of CPUID CPU-Z v2.17 and earlier does not validate user-supplied values passed via its IOCTL interface, allowing an attacker to access sensitive information via a crafted request.

- [https://github.com/cwjchoi01/CVE-2025-65264](https://github.com/cwjchoi01/CVE-2025-65264) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2025-65264.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2025-65264.svg)


## CVE-2025-56005
 An undocumented and unsafe feature in the PLY (Python Lex-Yacc) library 3.11 allows Remote Code Execution (RCE) via the `picklefile` parameter in the `yacc()` function. This parameter accepts a `.pkl` file that is deserialized with `pickle.load()` without validation. Because `pickle` allows execution of embedded code via `__reduce__()`, an attacker can achieve code execution by passing a malicious pickle file. The parameter is not mentioned in official documentation or the GitHub repository, yet it is active in the PyPI version. This introduces a stealthy backdoor and persistence risk.

- [https://github.com/tom025/ply_exploit_rejection](https://github.com/tom025/ply_exploit_rejection) :  ![starts](https://img.shields.io/github/stars/tom025/ply_exploit_rejection.svg) ![forks](https://img.shields.io/github/forks/tom025/ply_exploit_rejection.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/0xLittleSpidy/CVE-2025-54309](https://github.com/0xLittleSpidy/CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/0xLittleSpidy/CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/0xLittleSpidy/CVE-2025-54309.svg)


## CVE-2025-43504
 A buffer overflow was addressed with improved bounds checking. This issue is fixed in Xcode 26.1. A user in a privileged network position may be able to cause a denial-of-service.

- [https://github.com/calysteon/CVE-2025-43504](https://github.com/calysteon/CVE-2025-43504) :  ![starts](https://img.shields.io/github/stars/calysteon/CVE-2025-43504.svg) ![forks](https://img.shields.io/github/forks/calysteon/CVE-2025-43504.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/PentHertz/CVE-2025-36911-exploit](https://github.com/PentHertz/CVE-2025-36911-exploit) :  ![starts](https://img.shields.io/github/stars/PentHertz/CVE-2025-36911-exploit.svg) ![forks](https://img.shields.io/github/forks/PentHertz/CVE-2025-36911-exploit.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)


## CVE-2024-50498
 Improper Control of Generation of Code ('Code Injection') vulnerability in LUBUS WP Query Console allows Code Injection.This issue affects WP Query Console: from n/a through 1.0.

- [https://github.com/androidteacher/CVE-2024-50498-wpquery](https://github.com/androidteacher/CVE-2024-50498-wpquery) :  ![starts](https://img.shields.io/github/stars/androidteacher/CVE-2024-50498-wpquery.svg) ![forks](https://img.shields.io/github/forks/androidteacher/CVE-2024-50498-wpquery.svg)


## CVE-2024-44313
 TastyIgniter 3.7.6 contains an Incorrect Access Control vulnerability in the invoice() function within Orders.php which allows unauthorized users to access and generate invoices due to missing permission checks.

- [https://github.com/chessredoffsec/CVE-2024-44313](https://github.com/chessredoffsec/CVE-2024-44313) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2024-44313.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2024-44313.svg)


## CVE-2023-26209
 A improper restriction of excessive authentication attempts vulnerability [CWE-307] in Fortinet FortiDeceptor 3.1.x and before allows  a remote unauthenticated attacker to partially exhaust CPU and memory via sending numerous HTTP requests to the login form.

- [https://github.com/chessredoffsec/CVE-2023-26209](https://github.com/chessredoffsec/CVE-2023-26209) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2023-26209.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2023-26209.svg)


## CVE-2023-26208
 A improper restriction of excessive authentication attempts vulnerability [CWE-307] in Fortinet FortiAuthenticator 6.4.x and before allows  a remote unauthenticated attacker to partially exhaust CPU and memory via sending numerous HTTP requests to the login form.

- [https://github.com/chessredoffsec/CVE-2023-26208](https://github.com/chessredoffsec/CVE-2023-26208) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2023-26208.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2023-26208.svg)


## CVE-2022-29056
 A improper restriction of excessive authentication attempts vulnerability [CWE-307] in Fortinet FortiMail version 6.4.0, version 6.2.0 through 6.2.4 and before 6.0.9 allows  a remote unauthenticated attacker to partially exhaust CPU and memory via sending numerous HTTP requests to the login form.

- [https://github.com/chessredoffsec/CVE-2022-29056](https://github.com/chessredoffsec/CVE-2022-29056) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2022-29056.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2022-29056.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/notbside/CVE-2021-43798-PoC](https://github.com/notbside/CVE-2021-43798-PoC) :  ![starts](https://img.shields.io/github/stars/notbside/CVE-2021-43798-PoC.svg) ![forks](https://img.shields.io/github/forks/notbside/CVE-2021-43798-PoC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065](https://github.com/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065](https://github.com/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Exchange-RCE-v1.0---Microsoft-Exchange-Exploit-CVSS-10.0-CRITICAL-CVE-2021-26855-CVE-2021-27065.svg)


## CVE-2021-24019
 An insufficient session expiration vulnerability [CWE- 613] in FortiClientEMS versions 6.4.2 and below, 6.2.8 and below may allow an attacker to reuse the unexpired admin user session IDs to gain admin privileges, should the attacker be able to obtain that session ID (via other, hypothetical attacks)

- [https://github.com/chessredoffsec/CVE-2021-24019](https://github.com/chessredoffsec/CVE-2021-24019) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2021-24019.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2021-24019.svg)


## CVE-2021-24006
 An improper access control vulnerability in FortiManager versions 6.4.0 to 6.4.3 may allow an authenticated attacker with a restricted user profile to access the SD-WAN Orchestrator panel via directly visiting its URL.

- [https://github.com/chessredoffsec/CVE-2021-24006](https://github.com/chessredoffsec/CVE-2021-24006) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2021-24006.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2021-24006.svg)
- [https://github.com/chessredoffsec/CVE-2021-24006-Fortimanager-Exploit](https://github.com/chessredoffsec/CVE-2021-24006-Fortimanager-Exploit) :  ![starts](https://img.shields.io/github/stars/chessredoffsec/CVE-2021-24006-Fortimanager-Exploit.svg) ![forks](https://img.shields.io/github/forks/chessredoffsec/CVE-2021-24006-Fortimanager-Exploit.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/SimoesCTT/CTT-enhanced-VMware-vCenter](https://github.com/SimoesCTT/CTT-enhanced-VMware-vCenter) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-enhanced-VMware-vCenter.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-enhanced-VMware-vCenter.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/22imer/CVE-2014-0160](https://github.com/22imer/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/22imer/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/22imer/CVE-2014-0160.svg)
- [https://github.com/SimoesCTT/CTT-HEARTBLEED-Temporal-Resonance-Memory-Leak-Exploit-Heartbleed-CVE-2014-0160](https://github.com/SimoesCTT/CTT-HEARTBLEED-Temporal-Resonance-Memory-Leak-Exploit-Heartbleed-CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-HEARTBLEED-Temporal-Resonance-Memory-Leak-Exploit-Heartbleed-CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-HEARTBLEED-Temporal-Resonance-Memory-Leak-Exploit-Heartbleed-CVE-2014-0160.svg)

