# Update 2024-03-21
## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/jhonnybonny/CVE-2024-23334](https://github.com/jhonnybonny/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2024-23334.svg)


## CVE-2024-1698
 The NotificationX &#8211; Best FOMO, Social Proof, WooCommerce Sales Popup &amp; Notification Bar Plugin With Elementor plugin for WordPress is vulnerable to SQL Injection via the 'type' parameter in all versions up to, and including, 2.8.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/codeb0ss/CVE-2024-1698-PoC](https://github.com/codeb0ss/CVE-2024-1698-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-1698-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-1698-PoC.svg)


## CVE-2024-1212
 Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.

- [https://github.com/Chocapikk/CVE-2024-1212](https://github.com/Chocapikk/CVE-2024-1212) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-1212.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-1212.svg)


## CVE-2024-0015
 In convertToComponentName of DreamService.java, there is a possible way to launch arbitrary protected activities due to intent redirection. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/UmVfX1BvaW50/CVE-2024-0015](https://github.com/UmVfX1BvaW50/CVE-2024-0015) :  ![starts](https://img.shields.io/github/stars/UmVfX1BvaW50/CVE-2024-0015.svg) ![forks](https://img.shields.io/github/forks/UmVfX1BvaW50/CVE-2024-0015.svg)


## CVE-2023-38545
 This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due to this bug, the local variable that means &quot;let the host resolve the name&quot; could get the wrong value during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target buffer instead of copying just the resolved address there. The target buffer being a heap based buffer, and the host name coming from the URL that curl has been told to operate with.

- [https://github.com/Yang-Shun-Yu/CVE-2023-38545](https://github.com/Yang-Shun-Yu/CVE-2023-38545) :  ![starts](https://img.shields.io/github/stars/Yang-Shun-Yu/CVE-2023-38545.svg) ![forks](https://img.shields.io/github/forks/Yang-Shun-Yu/CVE-2023-38545.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/Nkipohcs/CVE-2023-2640-CVE-2023-32629](https://github.com/Nkipohcs/CVE-2023-2640-CVE-2023-32629) :  ![starts](https://img.shields.io/github/stars/Nkipohcs/CVE-2023-2640-CVE-2023-32629.svg) ![forks](https://img.shields.io/github/forks/Nkipohcs/CVE-2023-2640-CVE-2023-32629.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and &quot;UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs&quot;, an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/Nkipohcs/CVE-2023-2640-CVE-2023-32629](https://github.com/Nkipohcs/CVE-2023-2640-CVE-2023-32629) :  ![starts](https://img.shields.io/github/stars/Nkipohcs/CVE-2023-2640-CVE-2023-32629.svg) ![forks](https://img.shields.io/github/forks/Nkipohcs/CVE-2023-2640-CVE-2023-32629.svg)


## CVE-2022-46395
 An issue was discovered in the Arm Mali GPU Kernel Driver. A non-privileged user can make improper GPU processing operations to gain access to already freed memory. This affects Midgard r0p0 through r32p0, Bifrost r0p0 through r41p0 before r42p0, Valhall r19p0 through r41p0 before r42p0, and Avalon r41p0 before r42p0.

- [https://github.com/Pro-me3us/CVE_2022_46395_Raven](https://github.com/Pro-me3us/CVE_2022_46395_Raven) :  ![starts](https://img.shields.io/github/stars/Pro-me3us/CVE_2022_46395_Raven.svg) ![forks](https://img.shields.io/github/forks/Pro-me3us/CVE_2022_46395_Raven.svg)
- [https://github.com/Pro-me3us/CVE_2022_46395_Gazelle](https://github.com/Pro-me3us/CVE_2022_46395_Gazelle) :  ![starts](https://img.shields.io/github/stars/Pro-me3us/CVE_2022_46395_Gazelle.svg) ![forks](https://img.shields.io/github/forks/Pro-me3us/CVE_2022_46395_Gazelle.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2014-3508
 The OBJ_obj2txt function in crypto/objects/obj_dat.c in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before 1.0.1i, when pretty printing is used, does not ensure the presence of '\0' characters, which allows context-dependent attackers to obtain sensitive information from process stack memory by reading output from X509_name_oneline, X509_name_print_ex, and unspecified other functions.

- [https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3508](https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3508) :  ![starts](https://img.shields.io/github/stars/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3508.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3508.svg)


## CVE-2014-3507
 Memory leak in d1_both.c in the DTLS implementation in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before 1.0.1i allows remote attackers to cause a denial of service (memory consumption) via zero-length DTLS fragments that trigger improper handling of the return value of a certain insert function.

- [https://github.com/Satheesh575555/openSSL_1.0.1g_CVE-2014-3507](https://github.com/Satheesh575555/openSSL_1.0.1g_CVE-2014-3507) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/openSSL_1.0.1g_CVE-2014-3507.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/openSSL_1.0.1g_CVE-2014-3507.svg)

