# Update 2026-02-22
## CVE-2026-26988
 LibreNMS is an auto-discovering PHP/MySQL/SNMP based network monitoring tool. Versions 25.12.0 and below contain an SQL Injection vulnerability in the ajax_table.php endpoint. The application fails to properly sanitize or parameterize user input when processing IPv6 address searches. Specifically, the address parameter is split into an address and a prefix, and the prefix portion is directly concatenated into the SQL query string without validation. This allows an attacker to inject arbitrary SQL commands, potentially leading to unauthorized data access or database manipulation. This issue has been fixed in version 26.2.0.

- [https://github.com/mbanyamer/CVE-2026-26988-LibreNMS-SQLi](https://github.com/mbanyamer/CVE-2026-26988-LibreNMS-SQLi) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26988-LibreNMS-SQLi.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26988-LibreNMS-SQLi.svg)


## CVE-2026-26746
 OpenSourcePOS 3.4.1 contains a Local File Inclusion (LFI) vulnerability in the Sales.php::getInvoice() function. An attacker can read arbitrary files on the web server by manipulating the Invoice Type configuration. This issue can be chained with the file upload functionality to achieve Remote Code Execution (RCE).

- [https://github.com/hungnqdz/CVE-2026-26746](https://github.com/hungnqdz/CVE-2026-26746) :  ![starts](https://img.shields.io/github/stars/hungnqdz/CVE-2026-26746.svg) ![forks](https://img.shields.io/github/forks/hungnqdz/CVE-2026-26746.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/Ckokoski/moatbot-security](https://github.com/Ckokoski/moatbot-security) :  ![starts](https://img.shields.io/github/stars/Ckokoski/moatbot-security.svg) ![forks](https://img.shields.io/github/forks/Ckokoski/moatbot-security.svg)


## CVE-2026-24514
 A security issue was discovered in ingress-nginx where the validating admission controller feature is subject to a denial of service condition. By sending large requests to the validating admission controller, an attacker can cause memory consumption, which may result in the ingress-nginx controller pod being killed or the node running out of memory.

- [https://github.com/mbanyamer/cve-2026-24514-Kubernetes-Dos](https://github.com/mbanyamer/cve-2026-24514-Kubernetes-Dos) :  ![starts](https://img.shields.io/github/stars/mbanyamer/cve-2026-24514-Kubernetes-Dos.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/cve-2026-24514-Kubernetes-Dos.svg)


## CVE-2026-21533
 Improper privilege management in Windows Remote Desktop allows an authorized attacker to elevate privileges locally.

- [https://github.com/washingtonmaister/CVE-2026-21533](https://github.com/washingtonmaister/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/washingtonmaister/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/washingtonmaister/CVE-2026-21533.svg)
- [https://github.com/richardpaimu34/CVE-2026-21533](https://github.com/richardpaimu34/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-21533.svg)


## CVE-2026-2670
 A vulnerability was identified in Advantech WISE-6610 1.2.1_20251110. Affected is an unknown function of the file /cgi-bin/luci/admin/openvpn_apply of the component Background Management. Such manipulation of the argument delete_file leads to os command injection. The attack can be executed remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/ali-py3/exploit-CVE-2026-2670](https://github.com/ali-py3/exploit-CVE-2026-2670) :  ![starts](https://img.shields.io/github/stars/ali-py3/exploit-CVE-2026-2670.svg) ![forks](https://img.shields.io/github/forks/ali-py3/exploit-CVE-2026-2670.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/washingtonmaister/CVE-2026-2441](https://github.com/washingtonmaister/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/washingtonmaister/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/washingtonmaister/CVE-2026-2441.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/richardpaimu34/CVE-2026-1731](https://github.com/richardpaimu34/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-1731.svg)


## CVE-2026-1405
 The Slider Future plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'slider_future_handle_image_upload' function in all versions up to, and including, 1.0.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2026-1405](https://github.com/Nxploited/CVE-2026-1405) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1405.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1405.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/vatslaaeytoygag/CVE-2025-59287](https://github.com/vatslaaeytoygag/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/vatslaaeytoygag/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/vatslaaeytoygag/CVE-2025-59287.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MammaniNelsonD/React2P4IM0Nshell](https://github.com/MammaniNelsonD/React2P4IM0Nshell) :  ![starts](https://img.shields.io/github/stars/MammaniNelsonD/React2P4IM0Nshell.svg) ![forks](https://img.shields.io/github/forks/MammaniNelsonD/React2P4IM0Nshell.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/vpr-labs/CVE-2025-32463](https://github.com/vpr-labs/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/vpr-labs/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/vpr-labs/CVE-2025-32463.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/Shisones/CVE-2025-31161](https://github.com/Shisones/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Shisones/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Shisones/CVE-2025-31161.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)


## CVE-2025-6358
 A vulnerability was found in code-projects Simple Pizza Ordering System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /saveorder.php. The manipulation of the argument ID leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/NRTLOX/CVE-2025-63587](https://github.com/NRTLOX/CVE-2025-63587) :  ![starts](https://img.shields.io/github/stars/NRTLOX/CVE-2025-63587.svg) ![forks](https://img.shields.io/github/forks/NRTLOX/CVE-2025-63587.svg)


## CVE-2025-2304
When a user wishes to change his password, the 'updated_ajax' method of the UsersController is called. The vulnerability stems from the use of the dangerous permit! method, which allows all parameters to pass through without any filtering.

- [https://github.com/estebanzarate/CVE-2025-2304-Camaleon-CMS-Mass-Assignment-Privilege-Escalation-PoC](https://github.com/estebanzarate/CVE-2025-2304-Camaleon-CMS-Mass-Assignment-Privilege-Escalation-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2025-2304-Camaleon-CMS-Mass-Assignment-Privilege-Escalation-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2025-2304-Camaleon-CMS-Mass-Assignment-Privilege-Escalation-PoC.svg)


## CVE-2024-27804
 The issue was addressed with improved memory handling. This issue is fixed in iOS 17.5 and iPadOS 17.5, tvOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/R00tkitSMM/CVE-2024-27804](https://github.com/R00tkitSMM/CVE-2024-27804) :  ![starts](https://img.shields.io/github/stars/R00tkitSMM/CVE-2024-27804.svg) ![forks](https://img.shields.io/github/forks/R00tkitSMM/CVE-2024-27804.svg)
- [https://github.com/a0zhar/QuarkPoC](https://github.com/a0zhar/QuarkPoC) :  ![starts](https://img.shields.io/github/stars/a0zhar/QuarkPoC.svg) ![forks](https://img.shields.io/github/forks/a0zhar/QuarkPoC.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.

- [https://github.com/0xR00/CVE-2024-23334](https://github.com/0xR00/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/0xR00/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/0xR00/CVE-2024-23334.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2022-26923
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/Eliasdekiniweek/CVE-2022-26923](https://github.com/Eliasdekiniweek/CVE-2022-26923) :  ![starts](https://img.shields.io/github/stars/Eliasdekiniweek/CVE-2022-26923.svg) ![forks](https://img.shields.io/github/forks/Eliasdekiniweek/CVE-2022-26923.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2018-3615
 Systems with microprocessors utilizing speculative execution and Intel software guard extensions (Intel SGX) may allow unauthorized disclosure of information residing in the L1 data cache from an enclave to an attacker with local user access via a side-channel analysis.

- [https://github.com/toes485829-coder/Spectre](https://github.com/toes485829-coder/Spectre) :  ![starts](https://img.shields.io/github/stars/toes485829-coder/Spectre.svg) ![forks](https://img.shields.io/github/forks/toes485829-coder/Spectre.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2014-6271-Shellshock](https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2014-6271-Shellshock) :  ![starts](https://img.shields.io/github/stars/Industri4l-H3ll-Xpl0it3rs/CVE-2014-6271-Shellshock.svg) ![forks](https://img.shields.io/github/forks/Industri4l-H3ll-Xpl0it3rs/CVE-2014-6271-Shellshock.svg)

