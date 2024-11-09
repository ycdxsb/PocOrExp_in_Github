# Update 2024-11-09
## CVE-2024-38077
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/amfg145/CVE-2024-38077](https://github.com/amfg145/CVE-2024-38077) :  ![starts](https://img.shields.io/github/stars/amfg145/CVE-2024-38077.svg) ![forks](https://img.shields.io/github/forks/amfg145/CVE-2024-38077.svg)


## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AliHj98/cve-2024-38063-Anonyvader](https://github.com/AliHj98/cve-2024-38063-Anonyvader) :  ![starts](https://img.shields.io/github/stars/AliHj98/cve-2024-38063-Anonyvader.svg) ![forks](https://img.shields.io/github/forks/AliHj98/cve-2024-38063-Anonyvader.svg)


## CVE-2024-34351
 Next.js is a React framework that can provide building blocks to create web applications. A Server-Side Request Forgery (SSRF) vulnerability was identified in Next.js Server Actions. If the `Host` header is modified, and the below conditions are also met, an attacker may be able to make requests that appear to be originating from the Next.js application server itself. The required conditions are 1) Next.js is running in a self-hosted manner; 2) the Next.js application makes use of Server Actions; and 3) the Server Action performs a redirect to a relative path which starts with a `/`. This vulnerability was fixed in Next.js `14.1.1`.

- [https://github.com/avergnaud/Next.js_exploit_CVE-2024-34351](https://github.com/avergnaud/Next.js_exploit_CVE-2024-34351) :  ![starts](https://img.shields.io/github/stars/avergnaud/Next.js_exploit_CVE-2024-34351.svg) ![forks](https://img.shields.io/github/forks/avergnaud/Next.js_exploit_CVE-2024-34351.svg)


## CVE-2024-27914
 GLPI is a Free Asset and IT Management Software package, Data center management, ITIL Service Desk, licenses tracking and software auditing. An unauthenticated user can provide a malicious link to a GLPI administrator in order to exploit a reflected XSS vulnerability. The XSS will only trigger if the administrator navigates through the debug bar. This issue has been patched in version 10.0.13.

- [https://github.com/shellkraft/CVE-2024-27914](https://github.com/shellkraft/CVE-2024-27914) :  ![starts](https://img.shields.io/github/stars/shellkraft/CVE-2024-27914.svg) ![forks](https://img.shields.io/github/forks/shellkraft/CVE-2024-27914.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/Pylonet/CVE-2024-23334](https://github.com/Pylonet/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/Pylonet/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/Pylonet/CVE-2024-23334.svg)


## CVE-2024-5156
 The Flatsome theme for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's shortcode(s) in all versions up to, and including, 3.18.7 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/thehash007/CVE-2024-51567-RCE-EXPLOIT](https://github.com/thehash007/CVE-2024-51567-RCE-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/thehash007/CVE-2024-51567-RCE-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/thehash007/CVE-2024-51567-RCE-EXPLOIT.svg)


## CVE-2023-42115
 Exim AUTH Out-Of-Bounds Write Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Exim. Authentication is not required to exploit this vulnerability. The specific flaw exists within the smtp service, which listens on TCP port 25 by default. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of a buffer. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-17434.

- [https://github.com/AdaHop-Cyber-Security/Pocy](https://github.com/AdaHop-Cyber-Security/Pocy) :  ![starts](https://img.shields.io/github/stars/AdaHop-Cyber-Security/Pocy.svg) ![forks](https://img.shields.io/github/forks/AdaHop-Cyber-Security/Pocy.svg)


## CVE-2023-41652
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in David F. Carr RSVPMaker rsvpmaker allows SQL Injection.This issue affects RSVPMaker: from n/a through 10.6.6.

- [https://github.com/RandomRobbieBF/CVE-2023-41652](https://github.com/RandomRobbieBF/CVE-2023-41652) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-41652.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-41652.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/wxuycea/CVE-2023-25813](https://github.com/wxuycea/CVE-2023-25813) :  ![starts](https://img.shields.io/github/stars/wxuycea/CVE-2023-25813.svg) ![forks](https://img.shields.io/github/forks/wxuycea/CVE-2023-25813.svg)


## CVE-2022-25845
 The package com.alibaba:fastjson before 1.2.83 are vulnerable to Deserialization of Untrusted Data by bypassing the default autoType shutdown restrictions, which is possible under certain conditions. Exploiting this vulnerability allows attacking remote servers. Workaround: If upgrading is not possible, you can enable [safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode).

- [https://github.com/luelueking/CVE-2022-25845-In-Spring](https://github.com/luelueking/CVE-2022-25845-In-Spring) :  ![starts](https://img.shields.io/github/stars/luelueking/CVE-2022-25845-In-Spring.svg) ![forks](https://img.shields.io/github/forks/luelueking/CVE-2022-25845-In-Spring.svg)


## CVE-2022-0944
 Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.

- [https://github.com/LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944](https://github.com/LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944) :  ![starts](https://img.shields.io/github/stars/LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944.svg) ![forks](https://img.shields.io/github/forks/LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2018-16452
 The SMB parser in tcpdump before 4.9.3 has stack exhaustion in smbutil.c:smb_fdata() via recursion.

- [https://github.com/uthrasri/CVE-2018-16452_tcpdump_AOSP10_R33](https://github.com/uthrasri/CVE-2018-16452_tcpdump_AOSP10_R33) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2018-16452_tcpdump_AOSP10_R33.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2018-16452_tcpdump_AOSP10_R33.svg)

