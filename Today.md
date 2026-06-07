# Update 2026-06-07
## CVE-2026-48866
This issue affects Gravity Forms: from n/a through 2.10.0.1.

- [https://github.com/0xABCD01/CVE-2026-48866](https://github.com/0xABCD01/CVE-2026-48866) :  ![starts](https://img.shields.io/github/stars/0xABCD01/CVE-2026-48866.svg) ![forks](https://img.shields.io/github/forks/0xABCD01/CVE-2026-48866.svg)


## CVE-2026-48095
 7-Zip is a file archiver with a high compression ratio. Versions 26.00 and prior contain a heap buffer overflow vulnerability caused by an under-allocation in the NTFS compressed stream buffer (GetCuSize shift UB), potentially allowing attackers to cause arbitrary code execution or application crashes. CInStream::GetCuSize() in the NTFS handler computes the compression-unit buffer size as (UInt32)1  (BlockSizeLog + CompressionUnit), and a crafted image with ClusterSizeLog = 28 and CompressionUnit == 4 drives the exponent to 32, which is undefined behavior and collapses on x86/x64 so _inBuf is allocated as 1 byte. ReadStream_FALSE then writes up to 256 MB of attacker-controlled data into that 1-byte buffer in 64 KB iterations, and because the CInStream object sits only 304 bytes after _inBuf, its vtable pointer is overwritten and the next dispatched call achieves a vtable hijack. On 32-bit builds the overflow is unconditionally reached; on 64-bit it requires the parallel 8 GB _outBuf allocation to succeed, otherwise failing closed to denial of service. The NTFS handler is enabled by default in stock 7z.dll and, via signature-based fallback matching "NTFS    " at offset 3, will open a crafted image regardless of file extension during extraction or testing. Version 26.01 fixes the issue.

- [https://github.com/HORKimhab/CVE-2026-48095](https://github.com/HORKimhab/CVE-2026-48095) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-48095.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-48095.svg)


## CVE-2026-46391
 HAX CMS helps manage microsite universe with PHP or NodeJs backends. Starting in version 9.0.1 and prior to version 26.0.0 of @haxtheweb/open-apis, multiple functions conduct substring-only matching to validate hostnames to which basic authorization should be sent. An attacker can append the matched substrings to an attacker-controlled endpoint and capture authentication. Version 26.0.0 fixes the issue.

- [https://github.com/bradyjmcl/cve-2026-46391](https://github.com/bradyjmcl/cve-2026-46391) :  ![starts](https://img.shields.io/github/stars/bradyjmcl/cve-2026-46391.svg) ![forks](https://img.shields.io/github/forks/bradyjmcl/cve-2026-46391.svg)


## CVE-2026-44706
 Chatwoot is a customer engagement suite. From 2.2.0 to before 4.11.2, a SQL injection vulnerability exists in the conversation and contact filter APIs. When filtering by a custom attribute of type date or number using the is_greater_than or is_less_than operators, user-supplied values in the values field of the filter payload are interpolated directly into the SQL query without parameterization. Any authenticated user with access to an account can exploit this to execute arbitrary SQL via time-based blind injection. This affects /api/v1/accounts/{account_id}/conversations/filter, /api/v1/accounts/{account_id}/contacts/filter, and /api/v1/accounts/{account_id}/custom_attribute_definitions. This vulnerability is fixed in 4.11.2.

- [https://github.com/hakaioffsec/CVE-2026-44706](https://github.com/hakaioffsec/CVE-2026-44706) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-44706.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-44706.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/t1ckprivate/CVE-2026-43284-Dirty-Frag](https://github.com/t1ckprivate/CVE-2026-43284-Dirty-Frag) :  ![starts](https://img.shields.io/github/stars/t1ckprivate/CVE-2026-43284-Dirty-Frag.svg) ![forks](https://img.shields.io/github/forks/t1ckprivate/CVE-2026-43284-Dirty-Frag.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/y198nt/Nginx-chain-Rift-Poolslip](https://github.com/y198nt/Nginx-chain-Rift-Poolslip) :  ![starts](https://img.shields.io/github/stars/y198nt/Nginx-chain-Rift-Poolslip.svg) ![forks](https://img.shields.io/github/forks/y198nt/Nginx-chain-Rift-Poolslip.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/olofsatte/CVE-2026-41940-PoC](https://github.com/olofsatte/CVE-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/olofsatte/CVE-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/olofsatte/CVE-2026-41940-PoC.svg)
- [https://github.com/yurahshell/CVE-2026-41940](https://github.com/yurahshell/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/yurahshell/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/yurahshell/CVE-2026-41940.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/SkySmokeMoat/CVE-2026-41089-552](https://github.com/SkySmokeMoat/CVE-2026-41089-552) :  ![starts](https://img.shields.io/github/stars/SkySmokeMoat/CVE-2026-41089-552.svg) ![forks](https://img.shields.io/github/forks/SkySmokeMoat/CVE-2026-41089-552.svg)
- [https://github.com/senseibreathhovel/CVE-2026-41089-663](https://github.com/senseibreathhovel/CVE-2026-41089-663) :  ![starts](https://img.shields.io/github/stars/senseibreathhovel/CVE-2026-41089-663.svg) ![forks](https://img.shields.io/github/forks/senseibreathhovel/CVE-2026-41089-663.svg)
- [https://github.com/Planetpliexpose/CVE-2026-41089-277](https://github.com/Planetpliexpose/CVE-2026-41089-277) :  ![starts](https://img.shields.io/github/stars/Planetpliexpose/CVE-2026-41089-277.svg) ![forks](https://img.shields.io/github/forks/Planetpliexpose/CVE-2026-41089-277.svg)
- [https://github.com/GalleryJoiner/CVE-2026-41089-686](https://github.com/GalleryJoiner/CVE-2026-41089-686) :  ![starts](https://img.shields.io/github/stars/GalleryJoiner/CVE-2026-41089-686.svg) ![forks](https://img.shields.io/github/forks/GalleryJoiner/CVE-2026-41089-686.svg)
- [https://github.com/System32manager/CVE-2026-41089-699](https://github.com/System32manager/CVE-2026-41089-699) :  ![starts](https://img.shields.io/github/stars/System32manager/CVE-2026-41089-699.svg) ![forks](https://img.shields.io/github/forks/System32manager/CVE-2026-41089-699.svg)
- [https://github.com/sidechairmanblast/CVE-2026-41089-984](https://github.com/sidechairmanblast/CVE-2026-41089-984) :  ![starts](https://img.shields.io/github/stars/sidechairmanblast/CVE-2026-41089-984.svg) ![forks](https://img.shields.io/github/forks/sidechairmanblast/CVE-2026-41089-984.svg)


## CVE-2026-40072
 web3.py allows you to interact with the Ethereum blockchain using Python. From 6.0.0b3 to before 7.15.0 and 8.0.0b2, web3.py implements CCIP Read / OffchainLookup (EIP-3668) by performing HTTP requests to URLs supplied by smart contracts in offchain_lookup_payload["urls"]. The implementation uses these contract-supplied URLs directly (after {sender} / {data} template substitution) without any destination validation. CCIP Read is enabled by default (global_ccip_read_enabled = True on all providers), meaning any application using web3.py's .call() method is exposed without explicit opt-in. This results in Server-Side Request Forgery (SSRF) when web3.py is used in backend services, indexers, APIs, or any environment that performs eth_call / .call() against untrusted or user-supplied contract addresses. A malicious contract can force the web3.py process to issue HTTP requests to arbitrary destinations, including internal network services and cloud metadata endpoints. This vulnerability is fixed in 7.15.0 and 8.0.0b2.

- [https://github.com/u1tr0nex/cve-2026-40072-ssrf-lab](https://github.com/u1tr0nex/cve-2026-40072-ssrf-lab) :  ![starts](https://img.shields.io/github/stars/u1tr0nex/cve-2026-40072-ssrf-lab.svg) ![forks](https://img.shields.io/github/forks/u1tr0nex/cve-2026-40072-ssrf-lab.svg)


## CVE-2026-34908
 A malicious actor with access to the network could exploit an Improper Access Control vulnerability found in UniFi OS devices to make unauthorized changes to the system.

- [https://github.com/BishopFox/CVE-2026-34908-check](https://github.com/BishopFox/CVE-2026-34908-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-34908-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-34908-check.svg)


## CVE-2026-33829
 Exposure of sensitive information to an unauthorized actor in Windows Snipping Tool allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/ByteWraith1/CVE-2026-33829](https://github.com/ByteWraith1/CVE-2026-33829) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-33829.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-33829.svg)
- [https://github.com/seguridadentrerios/CVE-2026-33829](https://github.com/seguridadentrerios/CVE-2026-33829) :  ![starts](https://img.shields.io/github/stars/seguridadentrerios/CVE-2026-33829.svg) ![forks](https://img.shields.io/github/forks/seguridadentrerios/CVE-2026-33829.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/erlangparasu/mitigate_cve_2026_31431-sh](https://github.com/erlangparasu/mitigate_cve_2026_31431-sh) :  ![starts](https://img.shields.io/github/stars/erlangparasu/mitigate_cve_2026_31431-sh.svg) ![forks](https://img.shields.io/github/forks/erlangparasu/mitigate_cve_2026_31431-sh.svg)


## CVE-2026-26179
 Double free in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/nikosecurity/CVE-2026-26179](https://github.com/nikosecurity/CVE-2026-26179) :  ![starts](https://img.shields.io/github/stars/nikosecurity/CVE-2026-26179.svg) ![forks](https://img.shields.io/github/forks/nikosecurity/CVE-2026-26179.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/jacubes/CVE-2026-24061](https://github.com/jacubes/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/jacubes/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/jacubes/CVE-2026-24061.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/keeieb79/CVE-2026-23744-poc](https://github.com/keeieb79/CVE-2026-23744-poc) :  ![starts](https://img.shields.io/github/stars/keeieb79/CVE-2026-23744-poc.svg) ![forks](https://img.shields.io/github/forks/keeieb79/CVE-2026-23744-poc.svg)
- [https://github.com/Dahalsamir/CVE-2026-23744-MCPJAM-RCE-exploit](https://github.com/Dahalsamir/CVE-2026-23744-MCPJAM-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/Dahalsamir/CVE-2026-23744-MCPJAM-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/Dahalsamir/CVE-2026-23744-MCPJAM-RCE-exploit.svg)


## CVE-2026-20230
 Note: To exploit this vulnerability, the WebDialer service must be enabled. WebDialer is disabled by default.

- [https://github.com/HORKimhab/CVE-2026-20230](https://github.com/HORKimhab/CVE-2026-20230) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-20230.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-20230.svg)


## CVE-2026-11344
 A vulnerability was found in code-projects Vehicle Management System 1.0. This impacts an unknown function of the file newdriver.php of the component New Driver Registration Form. Performing a manipulation of the argument photo results in unrestricted upload. The attack may be initiated remotely. The exploit has been made public and could be used.

- [https://github.com/Xmyronn/CVE-2026-11344-RCE](https://github.com/Xmyronn/CVE-2026-11344-RCE) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-11344-RCE.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-11344-RCE.svg)


## CVE-2026-9256
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/y198nt/Nginx-chain-Rift-Poolslip](https://github.com/y198nt/Nginx-chain-Rift-Poolslip) :  ![starts](https://img.shields.io/github/stars/y198nt/Nginx-chain-Rift-Poolslip.svg) ![forks](https://img.shields.io/github/forks/y198nt/Nginx-chain-Rift-Poolslip.svg)


## CVE-2026-8206
 The Kirki – Freeform Page Builder, Website Builder & Customizer plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions 6.0.0 to 6.0.6. This is due to the plugin accepting an arbitrary email address when a username is used in the password reset request. This makes it possible for unauthenticated attackers to send a password reset link for any user registered on the site to their own email address.

- [https://github.com/rootdirective-sec/CVE-2026-8206-Lab](https://github.com/rootdirective-sec/CVE-2026-8206-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-8206-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-8206-Lab.svg)


## CVE-2026-6274
This issue affects Redline WR3200: from 7.1.3 before 7.1.8.

- [https://github.com/bugresearch/CVE-2026-6274](https://github.com/bugresearch/CVE-2026-6274) :  ![starts](https://img.shields.io/github/stars/bugresearch/CVE-2026-6274.svg) ![forks](https://img.shields.io/github/forks/bugresearch/CVE-2026-6274.svg)


## CVE-2026-5076
 The ARMember Premium plugin for WordPress is vulnerable to an insecure password reset mechanism in all versions up to, and including, 7.3.1. The plugin stores a plaintext copy of the password reset key in the `arm_reset_password_key` user meta field when a user requests a password reset. This is in addition to the hashed key that WordPress core stores securely in `wp_users.user_activation_key`. The plaintext key stored in `wp_usermeta` can be used with the plugin's custom `armrp` reset action to set a new password for any user. Combined with another vulnerability such as SQL Injection (CVE-2026-5073, CVE-2026-5074), this makes it possible for unauthenticated attackers to extract the plaintext reset key and take over any user account, including administrators.

- [https://github.com/shootcannon/CVE-2026-5076](https://github.com/shootcannon/CVE-2026-5076) :  ![starts](https://img.shields.io/github/stars/shootcannon/CVE-2026-5076.svg) ![forks](https://img.shields.io/github/forks/shootcannon/CVE-2026-5076.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/TheCyberGeek/CVE-2026-4480-PoC](https://github.com/TheCyberGeek/CVE-2026-4480-PoC) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2026-4480-PoC.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2026-4480-PoC.svg)


## CVE-2026-3300
 The Everest Forms Pro plugin for WordPress is vulnerable to Remote Code Execution via PHP Code Injection in all versions up to, and including, 1.9.12. This is due to the Calculation Addon's process_filter() function concatenating user-submitted form field values into a PHP code string without proper escaping before passing it to eval(). The sanitize_text_field() function applied to input does not escape single quotes or other PHP code context characters. This makes it possible for unauthenticated attackers to inject and execute arbitrary PHP code on the server by submitting a crafted value in any string-type form field (text, email, URL, select, radio) when a form uses the "Complex Calculation" feature.

- [https://github.com/HORKimhab/CVE-2026-3300](https://github.com/HORKimhab/CVE-2026-3300) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-3300.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-3300.svg)
- [https://github.com/adamshaikhma/CVE-2026-3300](https://github.com/adamshaikhma/CVE-2026-3300) :  ![starts](https://img.shields.io/github/stars/adamshaikhma/CVE-2026-3300.svg) ![forks](https://img.shields.io/github/forks/adamshaikhma/CVE-2026-3300.svg)


## CVE-2026-2586
 An authenticated Remote Code Execution (RCE) vulnerability was identified in GlassFish's Administration Console. A user with access to the panel can send crafted requests that allow the execution of arbitrary operating system commands with the privileges of the application service user.

- [https://github.com/partywavesec/CVE-2026-25860](https://github.com/partywavesec/CVE-2026-25860) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2026-25860.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2026-25860.svg)


## CVE-2026-1689
 A vulnerability was detected in Tenda HG10 US_HG7_HG9_HG10re_300001138_en_xpon. The impacted element is the function checkUserFromLanOrWan of the file /boaform/admin/formLogin of the component Login Interface. The manipulation of the argument Host results in command injection. The attack can be launched remotely. The exploit is now public and may be used.

- [https://github.com/emkv/tenda-hg10-rce](https://github.com/emkv/tenda-hg10-rce) :  ![starts](https://img.shields.io/github/stars/emkv/tenda-hg10-rce.svg) ![forks](https://img.shields.io/github/forks/emkv/tenda-hg10-rce.svg)


## CVE-2026-1238
 The SlimStat Analytics plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'fh' (fingerprint) parameter in all versions up to, and including, 5.3.5 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/mrk336/Breaking-AWS-IAM-Privilege-Escalation-via-Mis-Evaluated-Policy-Conditions-CVE-2026-1238-](https://github.com/mrk336/Breaking-AWS-IAM-Privilege-Escalation-via-Mis-Evaluated-Policy-Conditions-CVE-2026-1238-) :  ![starts](https://img.shields.io/github/stars/mrk336/Breaking-AWS-IAM-Privilege-Escalation-via-Mis-Evaluated-Policy-Conditions-CVE-2026-1238-.svg) ![forks](https://img.shields.io/github/forks/mrk336/Breaking-AWS-IAM-Privilege-Escalation-via-Mis-Evaluated-Policy-Conditions-CVE-2026-1238-.svg)


## CVE-2026-1232
 A medium-severity vulnerability has been identified in BeyondTrust Privilege Management for Windows versions =25.7. Under certain conditions, a local authenticated user with elevated privileges may be able to bypass the product’s anti-tamper protections, which could allow access to protected application components and the ability to modify product configuration.

- [https://github.com/horrister/beyondtrust-cve-2026-1232](https://github.com/horrister/beyondtrust-cve-2026-1232) :  ![starts](https://img.shields.io/github/stars/horrister/beyondtrust-cve-2026-1232.svg) ![forks](https://img.shields.io/github/forks/horrister/beyondtrust-cve-2026-1232.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-62676
 An Improper Link Resolution Before File Access ('Link Following') vulnerability [CWE-59] vulnerability in Fortinet FortiClientWindows 7.4.0 through 7.4.4, FortiClientWindows 7.2.0 through 7.2.12, FortiClientWindows 7.0 all versions may allow a local low-privilege attacker to perform an arbitrary file write with elevated permissions via crafted named pipe messages.

- [https://github.com/SpacePlant/FortiLPE](https://github.com/SpacePlant/FortiLPE) :  ![starts](https://img.shields.io/github/stars/SpacePlant/FortiLPE.svg) ![forks](https://img.shields.io/github/forks/SpacePlant/FortiLPE.svg)


## CVE-2025-53779
 Relative path traversal in Windows Kerberos allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Musa-xvi/Active-Directory-BadSuccessor](https://github.com/Musa-xvi/Active-Directory-BadSuccessor) :  ![starts](https://img.shields.io/github/stars/Musa-xvi/Active-Directory-BadSuccessor.svg) ![forks](https://img.shields.io/github/forks/Musa-xvi/Active-Directory-BadSuccessor.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/yurahshell/CVE-2025-49132](https://github.com/yurahshell/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/yurahshell/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/yurahshell/CVE-2025-49132.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/achnouri/Editor-CTF-writre-up](https://github.com/achnouri/Editor-CTF-writre-up) :  ![starts](https://img.shields.io/github/stars/achnouri/Editor-CTF-writre-up.svg) ![forks](https://img.shields.io/github/forks/achnouri/Editor-CTF-writre-up.svg)


## CVE-2025-4917
 A vulnerability classified as critical has been found in PHPGurukul Auto Taxi Stand Management System 1.0. Affected is an unknown function of the file /admin/new-autoortaxi-entry-form.php. The manipulation of the argument drivername leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services](https://github.com/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services) :  ![starts](https://img.shields.io/github/stars/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services.svg) ![forks](https://img.shields.io/github/forks/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services.svg)


## CVE-2024-34070
 Froxlor is open source server administration software. Prior to 2.1.9, a Stored Blind Cross-Site Scripting (XSS) vulnerability was identified in the Failed Login Attempts Logging Feature of the Froxlor Application. An unauthenticated User can inject malicious scripts in the loginname parameter on the Login attempt, which will then be executed when viewed by the Administrator in the System Logs.  By exploiting this vulnerability, the attacker can perform various malicious actions such as forcing the Administrator to execute actions without their knowledge or consent. For instance, the attacker can force the Administrator to add a new administrator controlled by the attacker, thereby giving the attacker full control over the application. This vulnerability is fixed in 2.1.9.

- [https://github.com/Okymi-X/CVE-2024-34070](https://github.com/Okymi-X/CVE-2024-34070) :  ![starts](https://img.shields.io/github/stars/Okymi-X/CVE-2024-34070.svg) ![forks](https://img.shields.io/github/forks/Okymi-X/CVE-2024-34070.svg)


## CVE-2024-22120
 Zabbix server can perform command execution for configured scripts. After command is executed, audit entry is added to "Audit Log". Due to "clientip" field is not sanitized, it is possible to injection SQL into "clientip" and exploit time based blind SQL injection.

- [https://github.com/darkbytehunter/CVE-2024-22120-RCE-with-gopher](https://github.com/darkbytehunter/CVE-2024-22120-RCE-with-gopher) :  ![starts](https://img.shields.io/github/stars/darkbytehunter/CVE-2024-22120-RCE-with-gopher.svg) ![forks](https://img.shields.io/github/forks/darkbytehunter/CVE-2024-22120-RCE-with-gopher.svg)


## CVE-2024-21182
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/johnniebozura31/CVE-2024-21182](https://github.com/johnniebozura31/CVE-2024-21182) :  ![starts](https://img.shields.io/github/stars/johnniebozura31/CVE-2024-21182.svg) ![forks](https://img.shields.io/github/forks/johnniebozura31/CVE-2024-21182.svg)


## CVE-2024-3495
 The Country State City Dropdown CF7 plugin for WordPress is vulnerable to SQL Injection via the ‘cnt’ and 'sid' parameters in versions up to, and including, 2.7.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/deltahdf/CVE-2024_3495](https://github.com/deltahdf/CVE-2024_3495) :  ![starts](https://img.shields.io/github/stars/deltahdf/CVE-2024_3495.svg) ![forks](https://img.shields.io/github/forks/deltahdf/CVE-2024_3495.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/REGGYRAIDER/CVE-2023-46604-RCE](https://github.com/REGGYRAIDER/CVE-2023-46604-RCE) :  ![starts](https://img.shields.io/github/stars/REGGYRAIDER/CVE-2023-46604-RCE.svg) ![forks](https://img.shields.io/github/forks/REGGYRAIDER/CVE-2023-46604-RCE.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/KianaBin/CVE-2022-0847-Container-Escape](https://github.com/KianaBin/CVE-2022-0847-Container-Escape) :  ![starts](https://img.shields.io/github/stars/KianaBin/CVE-2022-0847-Container-Escape.svg) ![forks](https://img.shields.io/github/forks/KianaBin/CVE-2022-0847-Container-Escape.svg)
- [https://github.com/t1ckprivate/CVE-2022-0847-Dirty-Pipe](https://github.com/t1ckprivate/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/t1ckprivate/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/t1ckprivate/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2022-0492
 A vulnerability was found in the Linux kernel’s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- [https://github.com/KianaBin/CVE-2022-0492-Container-Escape](https://github.com/KianaBin/CVE-2022-0492-Container-Escape) :  ![starts](https://img.shields.io/github/stars/KianaBin/CVE-2022-0492-Container-Escape.svg) ![forks](https://img.shields.io/github/forks/KianaBin/CVE-2022-0492-Container-Escape.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/krbtgt0/CVE-2019-6447](https://github.com/krbtgt0/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/krbtgt0/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/krbtgt0/CVE-2019-6447.svg)

