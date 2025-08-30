# Update 2025-08-30
## CVE-2025-51643
 Meitrack T366G-L GPS Tracker devices contain an SPI flash chip (Winbond 25Q64JVSIQ) that is accessible without authentication or tamper protection. An attacker with physical access to the device can use a standard SPI programmer to extract the firmware using flashrom. This results in exposure of sensitive configuration data such as APN credentials, backend server information, and network parameter

- [https://github.com/NastyCrow/CVE-2025-51643](https://github.com/NastyCrow/CVE-2025-51643) :  ![starts](https://img.shields.io/github/stars/NastyCrow/CVE-2025-51643.svg) ![forks](https://img.shields.io/github/forks/NastyCrow/CVE-2025-51643.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/butyraldehyde/CVE-2025-48384-PoC](https://github.com/butyraldehyde/CVE-2025-48384-PoC) :  ![starts](https://img.shields.io/github/stars/butyraldehyde/CVE-2025-48384-PoC.svg) ![forks](https://img.shields.io/github/forks/butyraldehyde/CVE-2025-48384-PoC.svg)
- [https://github.com/jacobholtz/CVE-2025-48384-submodule](https://github.com/jacobholtz/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/jacobholtz/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/jacobholtz/CVE-2025-48384-submodule.svg)
- [https://github.com/jacobholtz/CVE-2025-48384-poc](https://github.com/jacobholtz/CVE-2025-48384-poc) :  ![starts](https://img.shields.io/github/stars/jacobholtz/CVE-2025-48384-poc.svg) ![forks](https://img.shields.io/github/forks/jacobholtz/CVE-2025-48384-poc.svg)
- [https://github.com/butyraldehyde/CVE-2025-48384-PoC-Part2](https://github.com/butyraldehyde/CVE-2025-48384-PoC-Part2) :  ![starts](https://img.shields.io/github/stars/butyraldehyde/CVE-2025-48384-PoC-Part2.svg) ![forks](https://img.shields.io/github/forks/butyraldehyde/CVE-2025-48384-PoC-Part2.svg)


## CVE-2025-47987
 Heap-based buffer overflow in Windows Cred SSProvider Protocol allows an authorized attacker to elevate privileges locally.

- [https://github.com/Kryptoenix/CVE-2025-47987_PoC](https://github.com/Kryptoenix/CVE-2025-47987_PoC) :  ![starts](https://img.shields.io/github/stars/Kryptoenix/CVE-2025-47987_PoC.svg) ![forks](https://img.shields.io/github/forks/Kryptoenix/CVE-2025-47987_PoC.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Mdusmandasthaheer/CVE-2025-32433](https://github.com/Mdusmandasthaheer/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Mdusmandasthaheer/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Mdusmandasthaheer/CVE-2025-32433.svg)


## CVE-2025-31200
 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.

- [https://github.com/hunters-sec/CVE-2025-31200](https://github.com/hunters-sec/CVE-2025-31200) :  ![starts](https://img.shields.io/github/stars/hunters-sec/CVE-2025-31200.svg) ![forks](https://img.shields.io/github/forks/hunters-sec/CVE-2025-31200.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/zs1n/CVE-2025-29927](https://github.com/zs1n/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2025-29927.svg)


## CVE-2025-27410
 PwnDoc is a penetration test reporting application. Prior to version 1.2.0, the backup restore functionality is vulnerable to path traversal in the TAR entry's name, allowing an attacker to overwrite any file on the system with their content. By overwriting an included `.js` file and restarting the container, this allows for Remote Code Execution as an administrator. The remote code execution occurs because any user with the `backups:create` and `backups:update` (only administrators by default) is able to overwrite any file on the system. Version 1.2.0 fixes the issue.

- [https://github.com/shreyas-malhotra/CVE-2025-27410](https://github.com/shreyas-malhotra/CVE-2025-27410) :  ![starts](https://img.shields.io/github/stars/shreyas-malhotra/CVE-2025-27410.svg) ![forks](https://img.shields.io/github/forks/shreyas-malhotra/CVE-2025-27410.svg)


## CVE-2025-9345
 The File Manager, Code Editor, and Backup by Managefy plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.4.8 via the ajax_downloadfile() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to perform actions on files outside of the originally intended directory.

- [https://github.com/NagisaYumaa/CVE-2025-9345](https://github.com/NagisaYumaa/CVE-2025-9345) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-9345.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-9345.svg)


## CVE-2025-7955
 The RingCentral Communications plugin for WordPress is vulnerable to Authentication Bypass due to improper validation within the ringcentral_admin_login_2fa_verify() function in versions 1.5 to 1.6.8. This makes it possible for unauthenticated attackers to log in as any user simply by supplying identical bogus codes.

- [https://github.com/Nxploited/CVE-2025-7955](https://github.com/Nxploited/CVE-2025-7955) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7955.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7955.svg)


## CVE-2025-7775
CR virtual server with type HDX

- [https://github.com/hacker-r3volv3r/CVE-2025-7775-PoC](https://github.com/hacker-r3volv3r/CVE-2025-7775-PoC) :  ![starts](https://img.shields.io/github/stars/hacker-r3volv3r/CVE-2025-7775-PoC.svg) ![forks](https://img.shields.io/github/forks/hacker-r3volv3r/CVE-2025-7775-PoC.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/pavan3478/CVE-2025-5419](https://github.com/pavan3478/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/pavan3478/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/pavan3478/CVE-2025-5419.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/Naved124/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/Naved124/CVE-2024-28397-js2py-Sandbox-Escape.svg)


## CVE-2024-12877
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.19.2 via deserialization of untrusted input from the donation form like 'firstName'. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to delete arbitrary files on the server that makes remote code execution possible. Please note this was only partially patched in 3.19.3, a fully sufficient patch was not released until 3.19.4. However, another CVE was assigned by another CNA for version 3.19.3 so we will leave this as affecting 3.19.2 and before. We have recommended the vendor use JSON encoding to prevent any further deserialization vulnerabilities from being present.

- [https://github.com/soltanali0/CVE-2024-12877-Exploit](https://github.com/soltanali0/CVE-2024-12877-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2024-12877-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2024-12877-Exploit.svg)


## CVE-2022-20421
 In binder_inc_ref_for_node of binder.c, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-239630375References: Upstream kernel

- [https://github.com/sandiyochristan/oo](https://github.com/sandiyochristan/oo) :  ![starts](https://img.shields.io/github/stars/sandiyochristan/oo.svg) ![forks](https://img.shields.io/github/forks/sandiyochristan/oo.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)


## CVE-2019-9641
 An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3. There is an uninitialized read in exif_process_IFD_in_TIFF.

- [https://github.com/Schnaidr/CVE-2019-9641-php-RCE](https://github.com/Schnaidr/CVE-2019-9641-php-RCE) :  ![starts](https://img.shields.io/github/stars/Schnaidr/CVE-2019-9641-php-RCE.svg) ![forks](https://img.shields.io/github/forks/Schnaidr/CVE-2019-9641-php-RCE.svg)


## CVE-2019-6329
 HP Support Assistant 8.7.50 and earlier allows a user to gain system privilege and allows unauthorized modification of directories or files. Note: A different vulnerability than CVE-2019-6328.

- [https://github.com/ManhNDd/CVE-2019-6329](https://github.com/ManhNDd/CVE-2019-6329) :  ![starts](https://img.shields.io/github/stars/ManhNDd/CVE-2019-6329.svg) ![forks](https://img.shields.io/github/forks/ManhNDd/CVE-2019-6329.svg)


## CVE-2019-6203
 A logic issue was addressed with improved state management. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2. An attacker in a privileged network position may be able to intercept network traffic.

- [https://github.com/qingxp9/CVE-2019-6203-PoC](https://github.com/qingxp9/CVE-2019-6203-PoC) :  ![starts](https://img.shields.io/github/stars/qingxp9/CVE-2019-6203-PoC.svg) ![forks](https://img.shields.io/github/forks/qingxp9/CVE-2019-6203-PoC.svg)

