# Update 2025-05-31
## CVE-2025-48828
 Certain vBulletin versions might allow attackers to execute arbitrary PHP code by abusing Template Conditionals in the template engine. By crafting template code in an alternative PHP function invocation syntax, such as the "var_dump"("test") syntax, attackers can bypass security checks and execute arbitrary PHP code, as exploited in the wild in May 2025.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)


## CVE-2025-48827
 vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 allows unauthenticated users to invoke protected API controllers' methods when running on PHP 8.1 or later, as demonstrated by the /api.php?method=protectedMethod pattern, as exploited in the wild in May 2025.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)
- [https://github.com/0xgh057r3c0n/CVE-2025-48827](https://github.com/0xgh057r3c0n/CVE-2025-48827) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-48827.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-48827.svg)


## CVE-2025-46701
Users are recommended to upgrade to version 11.0.7, 10.1.41 or 9.0.105, which fixes the issue.

- [https://github.com/gregk4sec/CVE-2025-46701](https://github.com/gregk4sec/CVE-2025-46701) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-46701.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-46701.svg)


## CVE-2025-46080
 HuoCMS V3.5.1 has a File Upload Vulnerability. An attacker can exploit this flaw to bypass whitelist restrictions and craft malicious files with specific suffixes, thereby gaining control of the server.

- [https://github.com/yggcwhat/CVE-2025-46080](https://github.com/yggcwhat/CVE-2025-46080) :  ![starts](https://img.shields.io/github/stars/yggcwhat/CVE-2025-46080.svg) ![forks](https://img.shields.io/github/forks/yggcwhat/CVE-2025-46080.svg)


## CVE-2025-46078
 HuoCMS V3.5.1 and before is vulnerable to file upload, which allows attackers to take control of the target server

- [https://github.com/yggcwhat/CVE-2025-46078](https://github.com/yggcwhat/CVE-2025-46078) :  ![starts](https://img.shields.io/github/stars/yggcwhat/CVE-2025-46078.svg) ![forks](https://img.shields.io/github/forks/yggcwhat/CVE-2025-46078.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/nkuty/CVE-2025-30208-31125-31486-32395](https://github.com/nkuty/CVE-2025-30208-31125-31486-32395) :  ![starts](https://img.shields.io/github/stars/nkuty/CVE-2025-30208-31125-31486-32395.svg) ![forks](https://img.shields.io/github/forks/nkuty/CVE-2025-30208-31125-31486-32395.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927.svg)


## CVE-2025-29632
 Buffer Overflow vulnerability in Free5gc v.4.0.0 allows a remote attacker to cause a denial of service via the AMF, NGAP, security.go, handler_generated.go, handleInitialUEMessageMain, DecodePlainNasNoIntegrityCheck, GetSecurityHeaderType components

- [https://github.com/OHnogood/CVE-2025-29632](https://github.com/OHnogood/CVE-2025-29632) :  ![starts](https://img.shields.io/github/stars/OHnogood/CVE-2025-29632.svg) ![forks](https://img.shields.io/github/forks/OHnogood/CVE-2025-29632.svg)


## CVE-2025-5328
 A vulnerability was found in chshcms mccms 2.7. It has been declared as critical. This vulnerability affects the function restore_del of the file /sys/apps/controllers/admin/Backups.php. The manipulation of the argument dirs leads to path traversal. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/voyagken/CVE-2025-5328](https://github.com/voyagken/CVE-2025-5328) :  ![starts](https://img.shields.io/github/stars/voyagken/CVE-2025-5328.svg) ![forks](https://img.shields.io/github/forks/voyagken/CVE-2025-5328.svg)


## CVE-2025-2760
The specific flaw exists within the parsing of XWD files. The issue results from the lack of proper validation of user-supplied data, which can result in an integer overflow before allocating a buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-25082.

- [https://github.com/korden-c/CVE-2025-2760](https://github.com/korden-c/CVE-2025-2760) :  ![starts](https://img.shields.io/github/stars/korden-c/CVE-2025-2760.svg) ![forks](https://img.shields.io/github/forks/korden-c/CVE-2025-2760.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/Humbug52542/DLang-file-encryptor](https://github.com/Humbug52542/DLang-file-encryptor) :  ![starts](https://img.shields.io/github/stars/Humbug52542/DLang-file-encryptor.svg) ![forks](https://img.shields.io/github/forks/Humbug52542/DLang-file-encryptor.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/OWASP/www-project-eks-goat](https://github.com/OWASP/www-project-eks-goat) :  ![starts](https://img.shields.io/github/stars/OWASP/www-project-eks-goat.svg) ![forks](https://img.shields.io/github/forks/OWASP/www-project-eks-goat.svg)


## CVE-2024-11234
 In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14, when using streams with configured proxy and "request_fulluri" option, the URI is not properly sanitized which can lead to HTTP request smuggling and allow the attacker to use the proxy to perform arbitrary HTTP requests originating from the server, thus potentially gaining access to resources not normally available to the external user.

- [https://github.com/cyivor/CVE-2024-11234](https://github.com/cyivor/CVE-2024-11234) :  ![starts](https://img.shields.io/github/stars/cyivor/CVE-2024-11234.svg) ![forks](https://img.shields.io/github/forks/cyivor/CVE-2024-11234.svg)


## CVE-2023-22527
Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.

- [https://github.com/thompson005/CVE-2023-22527](https://github.com/thompson005/CVE-2023-22527) :  ![starts](https://img.shields.io/github/stars/thompson005/CVE-2023-22527.svg) ![forks](https://img.shields.io/github/forks/thompson005/CVE-2023-22527.svg)


## CVE-2023-4949
 An attacker with local access to a system (either through a disk or external drive) can present a modified XFS partition to grub-legacy in such a way to exploit a memory corruption in grub’s XFS file system implementation.

- [https://github.com/HuangYanQwQ/CVE-2023-49496_PoC](https://github.com/HuangYanQwQ/CVE-2023-49496_PoC) :  ![starts](https://img.shields.io/github/stars/HuangYanQwQ/CVE-2023-49496_PoC.svg) ![forks](https://img.shields.io/github/forks/HuangYanQwQ/CVE-2023-49496_PoC.svg)


## CVE-2023-1234
 Inappropriate implementation in Intents in Google Chrome on Android prior to 111.0.5563.64 allowed a remote attacker to perform domain spoofing via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/Yuri08loveElaina/CVE-2023-1234](https://github.com/Yuri08loveElaina/CVE-2023-1234) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2023-1234.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2023-1234.svg)


## CVE-2021-26828
 OpenPLC ScadaBR through 0.9.1 on Linux and through 1.12.4 on Windows allows remote authenticated users to upload and execute arbitrary JSP files via view_edit.shtm.

- [https://github.com/ridpath/CVE-2021-26828-Ultimate](https://github.com/ridpath/CVE-2021-26828-Ultimate) :  ![starts](https://img.shields.io/github/stars/ridpath/CVE-2021-26828-Ultimate.svg) ![forks](https://img.shields.io/github/forks/ridpath/CVE-2021-26828-Ultimate.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 & 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/octodi/CVE-2021-22911](https://github.com/octodi/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/octodi/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/octodi/CVE-2021-22911.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447](https://github.com/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447.svg)


## CVE-2011-0762
 The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

- [https://github.com/AndreyFreitass/CVE-2011-0762](https://github.com/AndreyFreitass/CVE-2011-0762) :  ![starts](https://img.shields.io/github/stars/AndreyFreitass/CVE-2011-0762.svg) ![forks](https://img.shields.io/github/forks/AndreyFreitass/CVE-2011-0762.svg)

