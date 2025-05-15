# Update 2025-05-15
## CVE-2025-46721
 nosurf is cross-site request forgery (CSRF) protection middleware for Go. A vulnerability in versions prior to 1.2.0 allows an attacker who controls content on the target site, or on a subdomain of the target site (either via XSS, or otherwise) to bypass CSRF checks and issue requests on user's behalf. Due to misuse of the Go `net/http` library, nosurf categorizes all incoming requests as plain-text HTTP requests, in which case the `Referer` header is not checked to have the same origin as the target webpage. If the attacker has control over HTML contents on either the target website (e.g. `example.com`), or on a website hosted on a subdomain of the target (e.g. `attacker.example.com`), they will also be able to manipulate cookies set for the target website. By acquiring the secret CSRF token from the cookie, or overriding the cookie with a new token known to the attacker, `attacker.example.com` is able to craft cross-site requests to `example.com`. A patch for the issue was released in nosurf 1.2.0. In lieu of upgrading to a patched version of nosurf, users may additionally use another HTTP middleware to ensure that a non-safe HTTP request is coming from the same origin (e.g. by requiring a `Sec-Fetch-Site: same-origin` header in the request).

- [https://github.com/justinas/nosurf-cve-2025-46721](https://github.com/justinas/nosurf-cve-2025-46721) :  ![starts](https://img.shields.io/github/stars/justinas/nosurf-cve-2025-46721.svg) ![forks](https://img.shields.io/github/forks/justinas/nosurf-cve-2025-46721.svg)


## CVE-2025-44039
 CP-XR-DE21-S -4G Router Firmware version 1.031.022 was discovered to contain insecure protections for its UART console. This vulnerability allows local attackers to connect to the UART port via a serial connection, read all boot sequence, and revealing internal system details and sensitive information without any authentication.

- [https://github.com/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities](https://github.com/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities.svg)


## CVE-2025-31201
 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.

- [https://github.com/pxx917144686/12345](https://github.com/pxx917144686/12345) :  ![starts](https://img.shields.io/github/stars/pxx917144686/12345.svg) ![forks](https://img.shields.io/github/forks/pxx917144686/12345.svg)


## CVE-2025-31200
 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.

- [https://github.com/pxx917144686/12345](https://github.com/pxx917144686/12345) :  ![starts](https://img.shields.io/github/stars/pxx917144686/12345.svg) ![forks](https://img.shields.io/github/forks/pxx917144686/12345.svg)


## CVE-2025-24203
 The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5. An app may be able to modify protected parts of the file system.

- [https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging](https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging) :  ![starts](https://img.shields.io/github/stars/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging.svg) ![forks](https://img.shields.io/github/forks/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging.svg)
- [https://github.com/GeoSn0w/iDevice-Toolkit](https://github.com/GeoSn0w/iDevice-Toolkit) :  ![starts](https://img.shields.io/github/stars/GeoSn0w/iDevice-Toolkit.svg) ![forks](https://img.shields.io/github/forks/GeoSn0w/iDevice-Toolkit.svg)


## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.

- [https://github.com/pxx917144686/12345](https://github.com/pxx917144686/12345) :  ![starts](https://img.shields.io/github/stars/pxx917144686/12345.svg) ![forks](https://img.shields.io/github/forks/pxx917144686/12345.svg)


## CVE-2025-3248
code.

- [https://github.com/vigilante-1337/CVE-2025-3248](https://github.com/vigilante-1337/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/vigilante-1337/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/vigilante-1337/CVE-2025-3248.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/Yucaerin/CVE-2025-2294](https://github.com/Yucaerin/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2294.svg)


## CVE-2024-23651
 BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and repeatable manner. Two malicious build steps running in parallel sharing the same cache mounts with subpaths could cause a race condition that can lead to files from the host system being accessible to the build container. The issue has been fixed in v0.12.5. Workarounds include, avoiding using BuildKit frontend from an untrusted source or building an untrusted Dockerfile containing cache mounts with --mount=type=cache,source=... options.

- [https://github.com/shkch02/eBPF_cve_2024_23651](https://github.com/shkch02/eBPF_cve_2024_23651) :  ![starts](https://img.shields.io/github/stars/shkch02/eBPF_cve_2024_23651.svg) ![forks](https://img.shields.io/github/forks/shkch02/eBPF_cve_2024_23651.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/MandipJoshi/CVE-2021-3560](https://github.com/MandipJoshi/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/MandipJoshi/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/MandipJoshi/CVE-2021-3560.svg)


## CVE-2018-25031
 Swagger UI 4.1.2 and earlier could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions. Note: This was originally claimed to be resolved in 4.1.3. However, third parties have indicated this is not resolved in 4.1.3 and even occurs in that version and possibly others.

- [https://github.com/faccimatteo/CVE-2018-25031](https://github.com/faccimatteo/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/faccimatteo/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/faccimatteo/CVE-2018-25031.svg)


## CVE-2018-14498
 get_8bit_row in rdbmp.c in libjpeg-turbo through 1.5.90 and MozJPEG through 3.3.1 allows attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted 8-bit BMP in which one or more of the color indices is out of range for the number of palette entries.

- [https://github.com/h31md4llr/libjpeg_cve-2018-14498_2](https://github.com/h31md4llr/libjpeg_cve-2018-14498_2) :  ![starts](https://img.shields.io/github/stars/h31md4llr/libjpeg_cve-2018-14498_2.svg) ![forks](https://img.shields.io/github/forks/h31md4llr/libjpeg_cve-2018-14498_2.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/Z3R0-0x30/CVE-2015-3306](https://github.com/Z3R0-0x30/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/Z3R0-0x30/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/Z3R0-0x30/CVE-2015-3306.svg)

