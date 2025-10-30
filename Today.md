# Update 2025-10-30
## CVE-2025-62727
 Starlette is a lightweight ASGI framework/toolkit. Prior to 0.49.1 , an unauthenticated attacker can send a crafted HTTP Range header that triggers quadratic-time processing in Starlette's FileResponse Range parsing/merging logic. This enables CPU exhaustion per request, causing denial‑of‑service for endpoints serving files (e.g., StaticFiles or any use of FileResponse). This vulnerability is fixed in 0.49.1.

- [https://github.com/ch4n3-yoon/CVE-2025-62727-Demo](https://github.com/ch4n3-yoon/CVE-2025-62727-Demo) :  ![starts](https://img.shields.io/github/stars/ch4n3-yoon/CVE-2025-62727-Demo.svg) ![forks](https://img.shields.io/github/forks/ch4n3-yoon/CVE-2025-62727-Demo.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/GhoStZA-debug/CVE-2025-61882](https://github.com/GhoStZA-debug/CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/GhoStZA-debug/CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/GhoStZA-debug/CVE-2025-61882.svg)


## CVE-2025-61155
 Hotta Studio GameDriverX64.sys 7.23.4.7, a signed kernel-mode anti-cheat driver, allows local attackers to cause a denial of service by crashing arbitrary processes via sending crafted IOCTL requests.

- [https://github.com/pollotherunner/CVE-2025-61155](https://github.com/pollotherunner/CVE-2025-61155) :  ![starts](https://img.shields.io/github/stars/pollotherunner/CVE-2025-61155.svg) ![forks](https://img.shields.io/github/forks/pollotherunner/CVE-2025-61155.svg)


## CVE-2025-60349
 An issue was discovered in Prevx v3.0.5.220 allowing attackers to cause a denial of service via sending IOCTL code 0x22E044 to the pxscan.sys driver. Any processes listed under registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\pxscan\Files will be terminated.

- [https://github.com/djackreuter/CVE-2025-60349](https://github.com/djackreuter/CVE-2025-60349) :  ![starts](https://img.shields.io/github/stars/djackreuter/CVE-2025-60349.svg) ![forks](https://img.shields.io/github/forks/djackreuter/CVE-2025-60349.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector](https://github.com/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector.svg)
- [https://github.com/esteban11121/WSUS-RCE-Mitigation-59287](https://github.com/esteban11121/WSUS-RCE-Mitigation-59287) :  ![starts](https://img.shields.io/github/stars/esteban11121/WSUS-RCE-Mitigation-59287.svg) ![forks](https://img.shields.io/github/forks/esteban11121/WSUS-RCE-Mitigation-59287.svg)
- [https://github.com/FurkanKAYAPINAR/CVE-2025-59287](https://github.com/FurkanKAYAPINAR/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2025-59287.svg)
- [https://github.com/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat](https://github.com/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat) :  ![starts](https://img.shields.io/github/stars/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat.svg) ![forks](https://img.shields.io/github/forks/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat.svg)


## CVE-2025-59230
 Improper access control in Windows Remote Access Connection Manager allows an authorized attacker to elevate privileges locally.

- [https://github.com/moegameka/CVE-2025-59230-LPE](https://github.com/moegameka/CVE-2025-59230-LPE) :  ![starts](https://img.shields.io/github/stars/moegameka/CVE-2025-59230-LPE.svg) ![forks](https://img.shields.io/github/forks/moegameka/CVE-2025-59230-LPE.svg)


## CVE-2025-56399
 alexusmai laravel-file-manager 3.3.1 and before allows an authenticated attacker to achieve Remote Code Execution (RCE) through a crafted file upload. A file with a '.png` extension containing PHP code can be uploaded via the file manager interface. Although the upload appears to fail client-side validation, the file is still saved on the server. The attacker can then use the rename API to change the file extension to `.php`, and upon accessing it via a public URL, the server executes the embedded code.

- [https://github.com/Theethat-Thamwasin/CVE-2025-56399](https://github.com/Theethat-Thamwasin/CVE-2025-56399) :  ![starts](https://img.shields.io/github/stars/Theethat-Thamwasin/CVE-2025-56399.svg) ![forks](https://img.shields.io/github/forks/Theethat-Thamwasin/CVE-2025-56399.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-9519
 The Easy Timer plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.2.1 via the plugin's shortcodes. This is due to insufficient restriction of shortcode attributes. This makes it possible for authenticated attackers, with Editor-level access and above, to execute code on the server.

- [https://github.com/coramarcet/WordPressCVEExploitProject](https://github.com/coramarcet/WordPressCVEExploitProject) :  ![starts](https://img.shields.io/github/stars/coramarcet/WordPressCVEExploitProject.svg) ![forks](https://img.shields.io/github/forks/coramarcet/WordPressCVEExploitProject.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/LordBheem/CVE-2025-6554](https://github.com/LordBheem/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/LordBheem/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/LordBheem/CVE-2025-6554.svg)


## CVE-2025-6059
 The Seraphinite Accelerator plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 2.27.21. This is due to missing or incorrect nonce validation on the 'OnAdminApi_CacheOpBegin' function. This makes it possible for unauthenticated attackers to perform several administrative actions, including deleting the cache, via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Clicksafeae/CVE-2025-60595](https://github.com/Clicksafeae/CVE-2025-60595) :  ![starts](https://img.shields.io/github/stars/Clicksafeae/CVE-2025-60595.svg) ![forks](https://img.shields.io/github/forks/Clicksafeae/CVE-2025-60595.svg)


## CVE-2025-5585
 The SiteOrigin Widgets Bundle plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the `data-url` DOM Element Attribute in all versions up to, and including, 1.68.4 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/PushkarAyengar/CVE-2025-55854-PoC](https://github.com/PushkarAyengar/CVE-2025-55854-PoC) :  ![starts](https://img.shields.io/github/stars/PushkarAyengar/CVE-2025-55854-PoC.svg) ![forks](https://img.shields.io/github/forks/PushkarAyengar/CVE-2025-55854-PoC.svg)


## CVE-2025-5287
 The Likes and Dislikes Plugin plugin for WordPress is vulnerable to SQL Injection via the 'post' parameter in all versions up to, and including, 1.0.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/coramarcet/WordPressCVEExploitProject](https://github.com/coramarcet/WordPressCVEExploitProject) :  ![starts](https://img.shields.io/github/stars/coramarcet/WordPressCVEExploitProject.svg) ![forks](https://img.shields.io/github/forks/coramarcet/WordPressCVEExploitProject.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/mladicstefan/CVE-2024-48990](https://github.com/mladicstefan/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/mladicstefan/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/mladicstefan/CVE-2024-48990.svg)
- [https://github.com/Serner77/CVE-2024-48990-Automatic-Exploit](https://github.com/Serner77/CVE-2024-48990-Automatic-Exploit) :  ![starts](https://img.shields.io/github/stars/Serner77/CVE-2024-48990-Automatic-Exploit.svg) ![forks](https://img.shields.io/github/forks/Serner77/CVE-2024-48990-Automatic-Exploit.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/yangdayyy/cve-2023-38831](https://github.com/yangdayyy/cve-2023-38831) :  ![starts](https://img.shields.io/github/stars/yangdayyy/cve-2023-38831.svg) ![forks](https://img.shields.io/github/forks/yangdayyy/cve-2023-38831.svg)


## CVE-2023-6019
 A command injection existed in Ray's cpu_profile URL parameter allowing attackers to execute os commands on the system running the ray dashboard remotely without authentication. The issue is fixed in version 2.8.1+. Ray maintainers' response can be found here: https://www.anyscale.com/blog/update-on-ray-cves-cve-2023-6019-cve-2023-6020-cve-2023-6021-cve-2023-48022-cve-2023-48023

- [https://github.com/Zohaibkhan1472/cve-2023-6019](https://github.com/Zohaibkhan1472/cve-2023-6019) :  ![starts](https://img.shields.io/github/stars/Zohaibkhan1472/cve-2023-6019.svg) ![forks](https://img.shields.io/github/forks/Zohaibkhan1472/cve-2023-6019.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit](https://github.com/FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/the-chivalrousZ/cve-2021-21300](https://github.com/the-chivalrousZ/cve-2021-21300) :  ![starts](https://img.shields.io/github/stars/the-chivalrousZ/cve-2021-21300.svg) ![forks](https://img.shields.io/github/forks/the-chivalrousZ/cve-2021-21300.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/AshrafZaryouh/CVE-2020-14882](https://github.com/AshrafZaryouh/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/AshrafZaryouh/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/AshrafZaryouh/CVE-2020-14882.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/0xDamian/CVE-2018-9995-rs](https://github.com/0xDamian/CVE-2018-9995-rs) :  ![starts](https://img.shields.io/github/stars/0xDamian/CVE-2018-9995-rs.svg) ![forks](https://img.shields.io/github/forks/0xDamian/CVE-2018-9995-rs.svg)

