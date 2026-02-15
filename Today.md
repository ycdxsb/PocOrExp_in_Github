# Update 2026-02-15
## CVE-2026-25924
 Kanboard is project management software focused on Kanban methodology. Prior to 1.2.50, a security control bypass vulnerability in Kanboard allows an authenticated administrator to achieve full Remote Code Execution (RCE). Although the application correctly hides the plugin installation interface when the PLUGIN_INSTALLER configuration is set to false, the underlying backend endpoint fails to verify this security setting. An attacker can exploit this oversight to force the server to download and install a malicious plugin, leading to arbitrary code execution. This vulnerability is fixed in 1.2.50.

- [https://github.com/drkim-dev/CVE-2026-25924](https://github.com/drkim-dev/CVE-2026-25924) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25924.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25924.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/cybrdude/cve-2026-1731-scanner](https://github.com/cybrdude/cve-2026-1731-scanner) :  ![starts](https://img.shields.io/github/stars/cybrdude/cve-2026-1731-scanner.svg) ![forks](https://img.shields.io/github/forks/cybrdude/cve-2026-1731-scanner.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/halilkirazkaya/CVE-2026-1357](https://github.com/halilkirazkaya/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/halilkirazkaya/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/halilkirazkaya/CVE-2026-1357.svg)


## CVE-2025-66676
 An issue in IObit Unlocker v1.3.0.11 allows attackers to cause a Denial of Service (DoS) via a crafted request.

- [https://github.com/cwjchoi01/CVE-2025-66676](https://github.com/cwjchoi01/CVE-2025-66676) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2025-66676.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2025-66676.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept](https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/undefined-name12/CVE-2025-8088-Winrar](https://github.com/undefined-name12/CVE-2025-8088-Winrar) :  ![starts](https://img.shields.io/github/stars/undefined-name12/CVE-2025-8088-Winrar.svg) ![forks](https://img.shields.io/github/forks/undefined-name12/CVE-2025-8088-Winrar.svg)


## CVE-2025-7083
 A vulnerability was found in Belkin F9K1122 1.00.33. It has been classified as critical. This affects the function mp of the file /goform/mp of the component webs. The manipulation of the argument command leads to os command injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/xiaoxiaoranxxx/CVE-2025-70830](https://github.com/xiaoxiaoranxxx/CVE-2025-70830) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-70830.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-70830.svg)


## CVE-2025-7082
 A vulnerability was found in Belkin F9K1122 1.00.33 and classified as critical. Affected by this issue is the function formBSSetSitesurvey of the file /goform/formBSSetSitesurvey of the component webs. The manipulation of the argument wan_ipaddr/wan_netmask/wan_gateway/wl_ssid is directly passed by the attacker/so we can control the wan_ipaddr/wan_netmask/wan_gateway/wl_ssid leads to os command injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/xiaoxiaoranxxx/CVE-2025-70829](https://github.com/xiaoxiaoranxxx/CVE-2025-70829) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-70829.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-70829.svg)
- [https://github.com/xiaoxiaoranxxx/CVE-2025-70828](https://github.com/xiaoxiaoranxxx/CVE-2025-70828) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-70828.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-70828.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/HexRazor/CVE-2025-6019](https://github.com/HexRazor/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/HexRazor/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/HexRazor/CVE-2025-6019.svg)
- [https://github.com/localh0ste/CVE-2025-6018-and-CVE-2025-6019](https://github.com/localh0ste/CVE-2025-6018-and-CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/localh0ste/CVE-2025-6018-and-CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/localh0ste/CVE-2025-6018-and-CVE-2025-6019.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/localh0ste/CVE-2025-6018-and-CVE-2025-6019](https://github.com/localh0ste/CVE-2025-6018-and-CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/localh0ste/CVE-2025-6018-and-CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/localh0ste/CVE-2025-6018-and-CVE-2025-6019.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/BLUEBERRYP1LL/CVE-2024-48990](https://github.com/BLUEBERRYP1LL/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/BLUEBERRYP1LL/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/BLUEBERRYP1LL/CVE-2024-48990.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/nmmorette/CVE-2024-34102](https://github.com/nmmorette/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/nmmorette/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/nmmorette/CVE-2024-34102.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/seal-sec-demo-2/npm-demo](https://github.com/seal-sec-demo-2/npm-demo) :  ![starts](https://img.shields.io/github/stars/seal-sec-demo-2/npm-demo.svg) ![forks](https://img.shields.io/github/forks/seal-sec-demo-2/npm-demo.svg)


## CVE-2019-19507
 In jpv (aka Json Pattern Validator) before 2.1.1, compareCommon() can be bypassed because certain internal attributes can be overwritten via a conflicting name, as demonstrated by 'constructor': {'name':'Array'}. This affects validate(). Hence, a crafted payload can overwrite this builtin attribute to manipulate the type detection result.

- [https://github.com/CQ-Tools/CVE-2019-19507-unfixed](https://github.com/CQ-Tools/CVE-2019-19507-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-19507-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-19507-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-19507-fixed](https://github.com/CQ-Tools/CVE-2019-19507-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-19507-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-19507-fixed.svg)


## CVE-2019-18350
 In Ant Design Pro 4.0.0, reflected XSS in the user/login redirect GET parameter affects the authorization component, leading to execution of JavaScript code in the login after-action script.

- [https://github.com/CQ-Tools/CVE-2019-18350-unfixed](https://github.com/CQ-Tools/CVE-2019-18350-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-18350-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-18350-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-18350-fixed](https://github.com/CQ-Tools/CVE-2019-18350-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-18350-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-18350-fixed.svg)


## CVE-2019-15657
 In eslint-utils before 1.4.1, the getStaticValue function can execute arbitrary code.

- [https://github.com/CQ-Tools/CVE-2019-15657-fixed](https://github.com/CQ-Tools/CVE-2019-15657-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-15657-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-15657-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-15657-unfixed](https://github.com/CQ-Tools/CVE-2019-15657-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-15657-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-15657-unfixed.svg)


## CVE-2019-15532
 CyberChef before 8.31.2 allows XSS in core/operations/TextEncodingBruteForce.mjs.

- [https://github.com/CQ-Tools/CVE-2019-15532-unfixed](https://github.com/CQ-Tools/CVE-2019-15532-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-15532-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-15532-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-15532-fixed](https://github.com/CQ-Tools/CVE-2019-15532-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-15532-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-15532-fixed.svg)


## CVE-2019-15482
 selectize-plugin-a11y before 1.1.0 has XSS via the msg field.

- [https://github.com/CQ-Tools/CVE-2019-15482-unfixed](https://github.com/CQ-Tools/CVE-2019-15482-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-15482-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-15482-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-15482-fixed](https://github.com/CQ-Tools/CVE-2019-15482-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-15482-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-15482-fixed.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/pasan2002/CVE-2019-9053---CMS-Made-Simple-SQL-Injection-Exploit-Modified-](https://github.com/pasan2002/CVE-2019-9053---CMS-Made-Simple-SQL-Injection-Exploit-Modified-) :  ![starts](https://img.shields.io/github/stars/pasan2002/CVE-2019-9053---CMS-Made-Simple-SQL-Injection-Exploit-Modified-.svg) ![forks](https://img.shields.io/github/forks/pasan2002/CVE-2019-9053---CMS-Made-Simple-SQL-Injection-Exploit-Modified-.svg)


## CVE-2019-5484
 Bower before 1.8.8 has a path traversal vulnerability permitting file write in arbitrary locations via install command, which allows attackers to write arbitrary files when a malicious package is extracted.

- [https://github.com/CQ-Tools/CVE-2019-5484-fixed](https://github.com/CQ-Tools/CVE-2019-5484-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-5484-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-5484-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-5484-unfixed](https://github.com/CQ-Tools/CVE-2019-5484-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-5484-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-5484-unfixed.svg)


## CVE-2019-5483
 Seneca  3.9.0 contains a vulnerability that could lead to exposing environment variables to unauthorized users.

- [https://github.com/CQ-Tools/CVE-2019-5483-unfixed](https://github.com/CQ-Tools/CVE-2019-5483-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-5483-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-5483-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-5483-fixed](https://github.com/CQ-Tools/CVE-2019-5483-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-5483-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-5483-fixed.svg)


## CVE-2018-1002204
 adm-zip npm library before 0.4.9 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/CQ-Tools/CVE-2018-1002204-fixed](https://github.com/CQ-Tools/CVE-2018-1002204-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-1002204-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-1002204-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-1002204-unfixed](https://github.com/CQ-Tools/CVE-2018-1002204-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-1002204-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-1002204-unfixed.svg)


## CVE-2018-1002203
 unzipper npm library before 0.8.13 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/CQ-Tools/CVE-2018-1002203-fixed](https://github.com/CQ-Tools/CVE-2018-1002203-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-1002203-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-1002203-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-1002203-unfixed](https://github.com/CQ-Tools/CVE-2018-1002203-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-1002203-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-1002203-unfixed.svg)


## CVE-2018-1000096
 brianleroux tiny-json-http version all versions since commit 9b8e74a232bba4701844e07bcba794173b0238a8 (Oct 29 2016) contains a Missing SSL certificate validation vulnerability in The libraries core functionality is affected. that can result in Exposes the user to man-in-the-middle attacks.

- [https://github.com/CQ-Tools/CVE-2018-1000096-fixed](https://github.com/CQ-Tools/CVE-2018-1000096-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-1000096-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-1000096-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-1000096-unfixed](https://github.com/CQ-Tools/CVE-2018-1000096-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-1000096-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-1000096-unfixed.svg)


## CVE-2018-20835
 A vulnerability was found in tar-fs before 1.16.2. An Arbitrary File Overwrite issue exists when extracting a tarball containing a hardlink to a file that already exists on the system, in conjunction with a later plain file with the same name as the hardlink. This plain file content replaces the existing file content.

- [https://github.com/CQ-Tools/CVE-2018-20835-unfixed](https://github.com/CQ-Tools/CVE-2018-20835-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-20835-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-20835-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-20835-fixed](https://github.com/CQ-Tools/CVE-2018-20835-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-20835-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-20835-fixed.svg)


## CVE-2018-20834
 A vulnerability was found in node-tar before version 4.4.2 (excluding version 2.2.2). An Arbitrary File Overwrite issue exists when extracting a tarball containing a hardlink to a file that already exists on the system, in conjunction with a later plain file with the same name as the hardlink. This plain file content replaces the existing file content. A patch has been applied to node-tar v2.2.2).

- [https://github.com/CQ-Tools/CVE-2018-20834-unfixed](https://github.com/CQ-Tools/CVE-2018-20834-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-20834-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-20834-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-20834-fixed](https://github.com/CQ-Tools/CVE-2018-20834-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-20834-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-20834-fixed.svg)


## CVE-2018-16491
 A prototype pollution vulnerability was found in node.extend 1.1.7, ~2.0.1 that allows an attacker to inject arbitrary properties onto Object.prototype.

- [https://github.com/CQ-Tools/CVE-2018-16491-fixed](https://github.com/CQ-Tools/CVE-2018-16491-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16491-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16491-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-16491-unfixed](https://github.com/CQ-Tools/CVE-2018-16491-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16491-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16491-unfixed.svg)


## CVE-2018-16490
 A prototype pollution vulnerability was found in module mpath 0.5.1 that allows an attacker to inject arbitrary properties onto Object.prototype.

- [https://github.com/CQ-Tools/CVE-2018-16490-unfixed](https://github.com/CQ-Tools/CVE-2018-16490-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16490-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16490-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-16490-fixed](https://github.com/CQ-Tools/CVE-2018-16490-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16490-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16490-fixed.svg)


## CVE-2018-16478
 A Path Traversal in simplehttpserver versions =0.2.1 allows to list any file in another folder of web root.

- [https://github.com/CQ-Tools/CVE-2018-16478-fixed](https://github.com/CQ-Tools/CVE-2018-16478-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16478-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16478-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-16478-unfixed](https://github.com/CQ-Tools/CVE-2018-16478-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16478-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16478-unfixed.svg)


## CVE-2018-16472
 A prototype pollution attack in cached-path-relative versions =1.0.1 allows an attacker to inject properties on Object.prototype which are then inherited by all the JS objects through the prototype chain causing a DoS attack.

- [https://github.com/CQ-Tools/CVE-2018-16472-fixed](https://github.com/CQ-Tools/CVE-2018-16472-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16472-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16472-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-16472-unfixed](https://github.com/CQ-Tools/CVE-2018-16472-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16472-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16472-unfixed.svg)


## CVE-2018-16462
 A command injection vulnerability in the apex-publish-static-files npm module version 2.0.1 which allows arbitrary shell command execution through a maliciously crafted argument.

- [https://github.com/CQ-Tools/CVE-2018-16462-unfixed](https://github.com/CQ-Tools/CVE-2018-16462-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16462-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16462-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-16462-fixed](https://github.com/CQ-Tools/CVE-2018-16462-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-16462-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-16462-fixed.svg)


## CVE-2018-14042
 In Bootstrap before 4.1.2, XSS is possible in the data-container property of tooltip.

- [https://github.com/CQ-Tools/CVE-2018-14042-unfixed](https://github.com/CQ-Tools/CVE-2018-14042-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-14042-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-14042-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-14042-fixed](https://github.com/CQ-Tools/CVE-2018-14042-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-14042-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-14042-fixed.svg)


## CVE-2018-13797
 The macaddress module before 0.2.9 for Node.js is prone to an arbitrary command injection flaw, due to allowing unsanitized input to an exec (rather than execFile) call.

- [https://github.com/CQ-Tools/CVE-2018-13797-fixed](https://github.com/CQ-Tools/CVE-2018-13797-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-13797-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-13797-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-13797-unfixed](https://github.com/CQ-Tools/CVE-2018-13797-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-13797-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-13797-unfixed.svg)


## CVE-2018-13379
 An Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.

- [https://github.com/Zierax/CVE-2018-13379](https://github.com/Zierax/CVE-2018-13379) :  ![starts](https://img.shields.io/github/stars/Zierax/CVE-2018-13379.svg) ![forks](https://img.shields.io/github/forks/Zierax/CVE-2018-13379.svg)


## CVE-2018-7651
 index.js in the ssri module before 5.2.2 for Node.js is prone to a regular expression denial of service vulnerability in strict mode functionality via a long base64 hash string.

- [https://github.com/CQ-Tools/CVE-2018-7651-unfixed](https://github.com/CQ-Tools/CVE-2018-7651-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-7651-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-7651-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-7651-fixed](https://github.com/CQ-Tools/CVE-2018-7651-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-7651-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-7651-fixed.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/bixiPRO/Drupalgeddon2-CVE-2018-7600](https://github.com/bixiPRO/Drupalgeddon2-CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/bixiPRO/Drupalgeddon2-CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/bixiPRO/Drupalgeddon2-CVE-2018-7600.svg)


## CVE-2018-6537
 A buffer overflow vulnerability in the control protocol of Flexense SyncBreeze Enterprise v10.4.18 allows remote attackers to execute arbitrary code by sending a crafted packet to TCP port 9121.

- [https://github.com/krnlcrow/CVE-2018-6537](https://github.com/krnlcrow/CVE-2018-6537) :  ![starts](https://img.shields.io/github/stars/krnlcrow/CVE-2018-6537.svg) ![forks](https://img.shields.io/github/forks/krnlcrow/CVE-2018-6537.svg)


## CVE-2018-6333
 The hhvm-attach deep link handler in Nuclide did not properly sanitize the provided hostname parameter when rendering. As a result, a malicious URL could be used to render HTML and other content inside of the editor's context, which could potentially be chained to lead to code execution. This issue affected Nuclide prior to v0.290.0.

- [https://github.com/CQ-Tools/CVE-2018-6333-unfixed](https://github.com/CQ-Tools/CVE-2018-6333-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-6333-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-6333-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-6333-fixed](https://github.com/CQ-Tools/CVE-2018-6333-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-6333-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-6333-fixed.svg)


## CVE-2018-5955
 An issue was discovered in GitStack through 2.3.10. User controlled input is not sufficiently filtered, allowing an unauthenticated attacker to add a user to the server via the username and password fields to the rest/user/ URI.

- [https://github.com/QianliZLP/GitStackRCE](https://github.com/QianliZLP/GitStackRCE) :  ![starts](https://img.shields.io/github/stars/QianliZLP/GitStackRCE.svg) ![forks](https://img.shields.io/github/forks/QianliZLP/GitStackRCE.svg)


## CVE-2018-3783
 A privilege escalation detected in flintcms versions = 1.1.9 allows account takeover due to blind MongoDB injection in password reset.

- [https://github.com/CQ-Tools/CVE-2018-3783-fixed](https://github.com/CQ-Tools/CVE-2018-3783-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3783-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3783-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3783-unfixed](https://github.com/CQ-Tools/CVE-2018-3783-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3783-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3783-unfixed.svg)


## CVE-2018-3770
 A path traversal exists in markdown-pdf version 9.0.0 that allows a user to insert a malicious html code that can result in reading the local files.

- [https://github.com/CQ-Tools/CVE-2018-3770-fixed](https://github.com/CQ-Tools/CVE-2018-3770-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3770-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3770-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3770-unfixed](https://github.com/CQ-Tools/CVE-2018-3770-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3770-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3770-unfixed.svg)


## CVE-2018-3757
 Command injection exists in pdf-image v2.0.0 due to an unescaped string parameter.

- [https://github.com/CQ-Tools/CVE-2018-3757-fixed](https://github.com/CQ-Tools/CVE-2018-3757-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3757-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3757-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3757-unfixed](https://github.com/CQ-Tools/CVE-2018-3757-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3757-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3757-unfixed.svg)


## CVE-2018-3752
 The utilities function in all versions = 1.0.0 of the merge-options node module can be tricked into modifying the prototype of Object when the attacker can control part of the structure passed to this function. This can let an attacker add or modify existing properties that will exist on all objects.

- [https://github.com/CQ-Tools/CVE-2018-3752-fixed](https://github.com/CQ-Tools/CVE-2018-3752-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3752-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3752-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3752-unfixed](https://github.com/CQ-Tools/CVE-2018-3752-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3752-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3752-unfixed.svg)


## CVE-2018-3750
 The utilities function in all versions = 0.5.0 of the deep-extend node module can be tricked into modifying the prototype of Object when the attacker can control part of the structure passed to this function. This can let an attacker add or modify existing properties that will exist on all objects.

- [https://github.com/CQ-Tools/CVE-2018-3750-unfixed](https://github.com/CQ-Tools/CVE-2018-3750-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3750-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3750-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3750-fixed](https://github.com/CQ-Tools/CVE-2018-3750-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3750-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3750-fixed.svg)


## CVE-2018-3746
 The pdfinfojs NPM module versions = 0.3.6 has a command injection vulnerability that allows an attacker to execute arbitrary commands on the victim's machine.

- [https://github.com/CQ-Tools/CVE-2018-3746-fixed](https://github.com/CQ-Tools/CVE-2018-3746-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3746-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3746-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3746-unfixed](https://github.com/CQ-Tools/CVE-2018-3746-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3746-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3746-unfixed.svg)


## CVE-2018-3737
 sshpk is vulnerable to ReDoS when parsing crafted invalid public keys.

- [https://github.com/CQ-Tools/CVE-2018-3737-unfixed](https://github.com/CQ-Tools/CVE-2018-3737-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3737-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3737-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3737-fixed](https://github.com/CQ-Tools/CVE-2018-3737-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3737-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3737-fixed.svg)


## CVE-2018-3736
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: CVE-2018-3739.  Reason: This candidate is a duplicate of CVE-2018-3739.  Notes: All CVE users should reference CVE-2018-3739 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage

- [https://github.com/CQ-Tools/CVE-2018-3736-unfixed](https://github.com/CQ-Tools/CVE-2018-3736-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3736-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3736-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3736-fixed](https://github.com/CQ-Tools/CVE-2018-3736-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3736-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3736-fixed.svg)


## CVE-2018-3726
 crud-file-server node module before 0.8.0 suffers from a Cross-Site Scripting vulnerability to a lack of validation of file names.

- [https://github.com/CQ-Tools/CVE-2018-3726-fixed](https://github.com/CQ-Tools/CVE-2018-3726-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3726-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3726-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3726-unfixed](https://github.com/CQ-Tools/CVE-2018-3726-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3726-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3726-unfixed.svg)


## CVE-2018-3713
 angular-http-server node module suffers from a Path Traversal vulnerability due to lack of validation of possibleFilename, which allows a malicious user to read content of any file with known path.

- [https://github.com/CQ-Tools/CVE-2018-3713-fixed](https://github.com/CQ-Tools/CVE-2018-3713-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3713-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3713-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2018-3713-unfixed](https://github.com/CQ-Tools/CVE-2018-3713-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2018-3713-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2018-3713-unfixed.svg)


## CVE-2017-18355
 Installed packages are exposed by node_modules in Rendertron 1.0.0, allowing remote attackers to read absolute paths on the server by examining the "_where" attribute of package.json files.

- [https://github.com/CQ-Tools/CVE-2017-18355-unfixed](https://github.com/CQ-Tools/CVE-2017-18355-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18355-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18355-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-18355-fixed](https://github.com/CQ-Tools/CVE-2017-18355-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18355-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18355-fixed.svg)


## CVE-2017-18354
 Rendertron 1.0.0 allows for alternative protocols such as 'file://' introducing a Local File Inclusion (LFI) bug where arbitrary files can be read by a remote attacker.

- [https://github.com/CQ-Tools/CVE-2017-18354-fixed](https://github.com/CQ-Tools/CVE-2017-18354-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18354-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18354-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-18354-unfixed](https://github.com/CQ-Tools/CVE-2017-18354-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18354-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18354-unfixed.svg)


## CVE-2017-18353
 Rendertron 1.0.0 includes an _ah/stop route to shutdown the Chrome instance responsible for serving render requests to all users. Visiting this route with a GET request allows any unauthorized remote attacker to disable the core service of the application.

- [https://github.com/CQ-Tools/CVE-2017-18353-unfixed](https://github.com/CQ-Tools/CVE-2017-18353-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18353-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18353-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-18353-fixed](https://github.com/CQ-Tools/CVE-2017-18353-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18353-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18353-fixed.svg)


## CVE-2017-18077
 index.js in brace-expansion before 1.1.7 is vulnerable to Regular Expression Denial of Service (ReDoS) attacks, as demonstrated by an expand argument containing many comma characters.

- [https://github.com/CQ-Tools/CVE-2017-18077-fixed](https://github.com/CQ-Tools/CVE-2017-18077-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18077-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18077-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-18077-unfixed](https://github.com/CQ-Tools/CVE-2017-18077-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-18077-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-18077-unfixed.svg)


## CVE-2017-16224
 st is a module for serving static files. An attacker is able to craft a request that results in an HTTP 301 (redirect) to an entirely different domain. A request for: http://some.server.com//nodesecurity.org/%2e%2e would result in a 301 to //nodesecurity.org/%2e%2e which most browsers treat as a proper redirect as // is translated into the current schema being used. Mitigating factor: In order for this to work, st must be serving from the root of a server (/) rather than the typical sub directory (/static/) and the redirect URL will end with some form of URL encoded .. ("%2e%2e", "%2e.", ".%2e").

- [https://github.com/CQ-Tools/CVE-2017-16224-unfixed](https://github.com/CQ-Tools/CVE-2017-16224-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16224-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16224-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16224-fixed](https://github.com/CQ-Tools/CVE-2017-16224-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16224-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16224-fixed.svg)


## CVE-2017-16137
 The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue.

- [https://github.com/CQ-Tools/CVE-2017-16137-fixed](https://github.com/CQ-Tools/CVE-2017-16137-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16137-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16137-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16137-unfixed](https://github.com/CQ-Tools/CVE-2017-16137-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16137-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16137-unfixed.svg)


## CVE-2017-16136
 method-override is a module used by the Express.js framework to let you use HTTP verbs such as PUT or DELETE in places where the client doesn't support it. method-override is vulnerable to a regular expression denial of service vulnerability when specially crafted input is passed in to be parsed via the X-HTTP-Method-Override header.

- [https://github.com/CQ-Tools/CVE-2017-16136-unfixed](https://github.com/CQ-Tools/CVE-2017-16136-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16136-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16136-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16136-fixed](https://github.com/CQ-Tools/CVE-2017-16136-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16136-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16136-fixed.svg)


## CVE-2017-16117
 slug is a module to slugify strings, even if they contain unicode. slug is vulnerable to regular expression denial of service is specially crafted untrusted input is passed as input. About 50k characters can block the event loop for 2 seconds.

- [https://github.com/CQ-Tools/CVE-2017-16117-fixed](https://github.com/CQ-Tools/CVE-2017-16117-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16117-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16117-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16117-unfixed](https://github.com/CQ-Tools/CVE-2017-16117-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16117-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16117-unfixed.svg)


## CVE-2017-16107
 pooledwebsocket is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing "../" in the url.

- [https://github.com/CQ-Tools/CVE-2017-16107-unfixed](https://github.com/CQ-Tools/CVE-2017-16107-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16107-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16107-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16107-fixed](https://github.com/CQ-Tools/CVE-2017-16107-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16107-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16107-fixed.svg)


## CVE-2017-16100
 dns-sync is a sync/blocking dns resolver. If untrusted user input is allowed into the resolve() method then command injection is possible.

- [https://github.com/CQ-Tools/CVE-2017-16100-unfixed](https://github.com/CQ-Tools/CVE-2017-16100-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16100-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16100-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16100-fixed](https://github.com/CQ-Tools/CVE-2017-16100-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16100-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16100-fixed.svg)


## CVE-2017-16043
 Shout is an IRC client. Because the `/topic` command in messages is unescaped, attackers have the ability to inject HTML scripts that will run in the victim's browser. Affects shout =0.44.0 =0.49.3.

- [https://github.com/CQ-Tools/CVE-2017-16043-unfixed](https://github.com/CQ-Tools/CVE-2017-16043-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16043-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16043-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16043-fixed](https://github.com/CQ-Tools/CVE-2017-16043-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16043-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16043-fixed.svg)


## CVE-2017-16042
 Growl adds growl notification support to nodejs. Growl before 1.10.2 does not properly sanitize input before passing it to exec, allowing for arbitrary command execution.

- [https://github.com/CQ-Tools/CVE-2017-16042-unfixed](https://github.com/CQ-Tools/CVE-2017-16042-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16042-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16042-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16042-fixed](https://github.com/CQ-Tools/CVE-2017-16042-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16042-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16042-fixed.svg)


## CVE-2017-16029
 hostr is a simple web server that serves up the contents of the current directory. There is a directory traversal vulnerability in hostr 2.3.5 and earlier that allows an attacker to read files outside the current directory by sending `../` in the url path for GET requests.

- [https://github.com/CQ-Tools/CVE-2017-16029-unfixed](https://github.com/CQ-Tools/CVE-2017-16029-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16029-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16029-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16029-fixed](https://github.com/CQ-Tools/CVE-2017-16029-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16029-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16029-fixed.svg)


## CVE-2017-16028
 react-native-meteor-oauth is a library for Oauth2 login to a Meteor server in React Native. The oauth Random Token is generated using a non-cryptographically strong RNG (Math.random()).

- [https://github.com/CQ-Tools/CVE-2017-16028-unfixed](https://github.com/CQ-Tools/CVE-2017-16028-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16028-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16028-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16028-fixed](https://github.com/CQ-Tools/CVE-2017-16028-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16028-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16028-fixed.svg)


## CVE-2017-16026
 Request is an http client. If a request is made using ```multipart```, and the body type is a ```number```, then the specified number of non-zero memory is passed in the body. This affects Request =2.2.6 2.47.0 || 2.51.0 =2.67.0.

- [https://github.com/CQ-Tools/CVE-2017-16026-fixed](https://github.com/CQ-Tools/CVE-2017-16026-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16026-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16026-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16026-unfixed](https://github.com/CQ-Tools/CVE-2017-16026-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16026-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16026-unfixed.svg)


## CVE-2017-16023
 Decamelize is used to convert a dash/dot/underscore/space separated string to camelCase. Decamelize 1.1.0 through 1.1.1 uses regular expressions to evaluate a string and takes unescaped separator values, which can be used to create a denial of service attack.

- [https://github.com/CQ-Tools/CVE-2017-16023-fixed](https://github.com/CQ-Tools/CVE-2017-16023-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16023-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16023-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16023-unfixed](https://github.com/CQ-Tools/CVE-2017-16023-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16023-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16023-unfixed.svg)


## CVE-2017-16014
 Http-proxy is a proxying library. Because of the way errors are handled in versions before 0.7.0, an attacker that forces an error can crash the server, causing a denial of service.

- [https://github.com/CQ-Tools/CVE-2017-16014-unfixed](https://github.com/CQ-Tools/CVE-2017-16014-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16014-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16014-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16014-fixed](https://github.com/CQ-Tools/CVE-2017-16014-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16014-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16014-fixed.svg)


## CVE-2017-16003
 windows-build-tools is a module for installing C++ Build Tools for Windows using npm. windows-build-tools versions below 1.0.0 download resources over HTTP, which leaves it vulnerable to MITM attacks. It may be possible to cause remote code execution (RCE) by swapping out the requested resources with an attacker controlled copy if the attacker is on the network or positioned in between the user and the remote server.

- [https://github.com/CQ-Tools/CVE-2017-16003-fixed](https://github.com/CQ-Tools/CVE-2017-16003-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16003-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16003-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16003-unfixed](https://github.com/CQ-Tools/CVE-2017-16003-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16003-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16003-unfixed.svg)


## CVE-2017-14980
 Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.

- [https://github.com/krnlcrow/CVE-2017-14980](https://github.com/krnlcrow/CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/krnlcrow/CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/krnlcrow/CVE-2017-14980.svg)


## CVE-2017-8917
 SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.

- [https://github.com/ztrxwzy/joomla.3.7.0exploit](https://github.com/ztrxwzy/joomla.3.7.0exploit) :  ![starts](https://img.shields.io/github/stars/ztrxwzy/joomla.3.7.0exploit.svg) ![forks](https://img.shields.io/github/forks/ztrxwzy/joomla.3.7.0exploit.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/MartinxMax/BloodCat](https://github.com/MartinxMax/BloodCat) :  ![starts](https://img.shields.io/github/stars/MartinxMax/BloodCat.svg) ![forks](https://img.shields.io/github/forks/MartinxMax/BloodCat.svg)
- [https://github.com/mverschu/CVE-2017-7921](https://github.com/mverschu/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/mverschu/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/mverschu/CVE-2017-7921.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/Zanex360/cdt-vulnsamba-deploy](https://github.com/Zanex360/cdt-vulnsamba-deploy) :  ![starts](https://img.shields.io/github/stars/Zanex360/cdt-vulnsamba-deploy.svg) ![forks](https://img.shields.io/github/forks/Zanex360/cdt-vulnsamba-deploy.svg)
- [https://github.com/Zanex360/cdt-samba-deploy](https://github.com/Zanex360/cdt-samba-deploy) :  ![starts](https://img.shields.io/github/stars/Zanex360/cdt-samba-deploy.svg) ![forks](https://img.shields.io/github/forks/Zanex360/cdt-samba-deploy.svg)


## CVE-2017-7184
 The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel through 4.10.6 does not validate certain size data after an XFRM_MSG_NEWAE update, which allows local users to obtain root privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN capability, as demonstrated during a Pwn2Own competition at CanSecWest 2017 for the Ubuntu 16.10 linux-image-* package 4.8.0.41.52.

- [https://github.com/Grish-Pradhan/CVE-2017-7184](https://github.com/Grish-Pradhan/CVE-2017-7184) :  ![starts](https://img.shields.io/github/stars/Grish-Pradhan/CVE-2017-7184.svg) ![forks](https://img.shields.io/github/forks/Grish-Pradhan/CVE-2017-7184.svg)


## CVE-2017-6736
   There are workarounds that address these vulnerabilities.

- [https://github.com/ISTALKMILK/CiscoIOSSNMPToolkit](https://github.com/ISTALKMILK/CiscoIOSSNMPToolkit) :  ![starts](https://img.shields.io/github/stars/ISTALKMILK/CiscoIOSSNMPToolkit.svg) ![forks](https://img.shields.io/github/forks/ISTALKMILK/CiscoIOSSNMPToolkit.svg)
- [https://github.com/ISTALKMILK/CiscoSpectreTakeover](https://github.com/ISTALKMILK/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/ISTALKMILK/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/ISTALKMILK/CiscoSpectreTakeover.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/f41k0n/RCE-NodeJs](https://github.com/f41k0n/RCE-NodeJs) :  ![starts](https://img.shields.io/github/stars/f41k0n/RCE-NodeJs.svg) ![forks](https://img.shields.io/github/forks/f41k0n/RCE-NodeJs.svg)


## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/ISTALKMILK/CiscoSpectreTakeover](https://github.com/ISTALKMILK/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/ISTALKMILK/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/ISTALKMILK/CiscoSpectreTakeover.svg)


## CVE-2017-5715
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/ISTALKMILK/CiscoSpectreTakeover](https://github.com/ISTALKMILK/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/ISTALKMILK/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/ISTALKMILK/CiscoSpectreTakeover.svg)
- [https://github.com/MuhammadAnwaar/spectre](https://github.com/MuhammadAnwaar/spectre) :  ![starts](https://img.shields.io/github/stars/MuhammadAnwaar/spectre.svg) ![forks](https://img.shields.io/github/forks/MuhammadAnwaar/spectre.svg)


## CVE-2017-1608
 IBM Rational Quality Manager and IBM Rational Collaborative Lifecycle Management 5.0 through 5.0.2 and 6.0 through 6.0.5 are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 132928.

- [https://github.com/CQ-Tools/CVE-2017-16087-fixed](https://github.com/CQ-Tools/CVE-2017-16087-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16087-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16087-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2017-16087-unfixed](https://github.com/CQ-Tools/CVE-2017-16087-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2017-16087-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2017-16087-unfixed.svg)


## CVE-2016-1000027
 Pivotal Spring Framework through 5.3.16 suffers from a potential remote code execution (RCE) issue if used for Java deserialization of untrusted data. Depending on how the library is implemented within a product, this issue may or not occur, and authentication may be required. NOTE: the vendor's position is that untrusted data is not an intended use case. The product's behavior will not be changed because some users rely on deserialization of trusted data.

- [https://github.com/Ragatzino/test-cve-2016-1000027](https://github.com/Ragatzino/test-cve-2016-1000027) :  ![starts](https://img.shields.io/github/stars/Ragatzino/test-cve-2016-1000027.svg) ![forks](https://img.shields.io/github/forks/Ragatzino/test-cve-2016-1000027.svg)


## CVE-2016-20016
 MVPower CCTV DVR models, including TV-7104HE 1.8.4 115215B9 and TV7108HE, contain a web shell that is accessible via a /shell URI. A remote unauthenticated attacker can execute arbitrary operating system commands as root. This vulnerability has also been referred to as the "JAWS webserver RCE" because of the easily identifying HTTP response server field. Other firmware versions, at least from 2014 through 2019, can be affected. This was exploited in the wild in 2017 through 2022.

- [https://github.com/MartinxMax/BloodCat](https://github.com/MartinxMax/BloodCat) :  ![starts](https://img.shields.io/github/stars/MartinxMax/BloodCat.svg) ![forks](https://img.shields.io/github/forks/MartinxMax/BloodCat.svg)


## CVE-2016-5674
 __debugging_center_utils___.php in NUUO NVRmini 2 1.7.5 through 3.0.0, NUUO NVRsolo 1.7.5 through 3.0.0, and NETGEAR ReadyNAS Surveillance 1.1.1 through 1.4.1 allows remote attackers to execute arbitrary PHP code via the log parameter.

- [https://github.com/MartinxMax/BloodCat](https://github.com/MartinxMax/BloodCat) :  ![starts](https://img.shields.io/github/stars/MartinxMax/BloodCat.svg) ![forks](https://img.shields.io/github/forks/MartinxMax/BloodCat.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/theo543/OSDS_Paper_CVE-2016-5195](https://github.com/theo543/OSDS_Paper_CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/theo543/OSDS_Paper_CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/theo543/OSDS_Paper_CVE-2016-5195.svg)
- [https://github.com/elhaddadalaa788-alt/kernel-exploit-dirtycow-project-subm](https://github.com/elhaddadalaa788-alt/kernel-exploit-dirtycow-project-subm) :  ![starts](https://img.shields.io/github/stars/elhaddadalaa788-alt/kernel-exploit-dirtycow-project-subm.svg) ![forks](https://img.shields.io/github/forks/elhaddadalaa788-alt/kernel-exploit-dirtycow-project-subm.svg)
- [https://github.com/Nathanloupy/42adv_boot2root](https://github.com/Nathanloupy/42adv_boot2root) :  ![starts](https://img.shields.io/github/stars/Nathanloupy/42adv_boot2root.svg) ![forks](https://img.shields.io/github/forks/Nathanloupy/42adv_boot2root.svg)
- [https://github.com/hermesash1ray/cow](https://github.com/hermesash1ray/cow) :  ![starts](https://img.shields.io/github/stars/hermesash1ray/cow.svg) ![forks](https://img.shields.io/github/forks/hermesash1ray/cow.svg)


## CVE-2016-0856
 Multiple stack-based buffer overflows in Advantech WebAccess before 8.1 allow remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/mzuhair9933/PoPE-pytorch](https://github.com/mzuhair9933/PoPE-pytorch) :  ![starts](https://img.shields.io/github/stars/mzuhair9933/PoPE-pytorch.svg) ![forks](https://img.shields.io/github/forks/mzuhair9933/PoPE-pytorch.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka "HTTP.sys Remote Code Execution Vulnerability."

- [https://github.com/hedgecore/HTTPsys](https://github.com/hedgecore/HTTPsys) :  ![starts](https://img.shields.io/github/stars/hedgecore/HTTPsys.svg) ![forks](https://img.shields.io/github/forks/hedgecore/HTTPsys.svg)


## CVE-2014-8610
 AndroidManifest.xml in Android before 5.0.0 does not require the SEND_SMS permission for the SmsReceiver receiver, which allows attackers to send stored SMS messages, and consequently transmit arbitrary new draft SMS messages or trigger additional per-message charges from a network operator for old messages, via a crafted application that broadcasts an intent with the com.android.mms.transaction.MESSAGE_SENT action, aka Bug 17671795.

- [https://github.com/eddieoz/dual-ec-drbg](https://github.com/eddieoz/dual-ec-drbg) :  ![starts](https://img.shields.io/github/stars/eddieoz/dual-ec-drbg.svg) ![forks](https://img.shields.io/github/forks/eddieoz/dual-ec-drbg.svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/SDimitri05/cve-2013-3900-winverifytrust-mitigation](https://github.com/SDimitri05/cve-2013-3900-winverifytrust-mitigation) :  ![starts](https://img.shields.io/github/stars/SDimitri05/cve-2013-3900-winverifytrust-mitigation.svg) ![forks](https://img.shields.io/github/forks/SDimitri05/cve-2013-3900-winverifytrust-mitigation.svg)

