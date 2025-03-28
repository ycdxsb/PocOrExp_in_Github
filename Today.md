# Update 2025-03-28
## CVE-2025-30567
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in wp01ru WP01 allows Path Traversal. This issue affects WP01: from n/a through 2.6.2.

- [https://github.com/Oyst3r1ng/CVE-2025-30567](https://github.com/Oyst3r1ng/CVE-2025-30567) :  ![starts](https://img.shields.io/github/stars/Oyst3r1ng/CVE-2025-30567.svg) ![forks](https://img.shields.io/github/forks/Oyst3r1ng/CVE-2025-30567.svg)


## CVE-2025-30216
 CryptoLib provides a software-only solution using the CCSDS Space Data Link Security Protocol - Extended Procedures (SDLS-EP) to secure communications between a spacecraft running the core Flight System (cFS) and a ground station. In versions 1.3.3 and prior, a Heap Overflow vulnerability occurs in the `Crypto_TM_ProcessSecurity` function (`crypto_tm.c:1735:8`). When processing the Secondary Header Length of a TM protocol packet, if the Secondary Header Length exceeds the packet's total length, a heap overflow is triggered during the memcpy operation that copies packet data into the dynamically allocated buffer `p_new_dec_frame`. This allows an attacker to overwrite adjacent heap memory, potentially leading to arbitrary code execution or system instability. A patch is available at commit 810fd66d592c883125272fef123c3240db2f170f.

- [https://github.com/oliviaisntcringe/CVE-2025-30216-PoC](https://github.com/oliviaisntcringe/CVE-2025-30216-PoC) :  ![starts](https://img.shields.io/github/stars/oliviaisntcringe/CVE-2025-30216-PoC.svg) ![forks](https://img.shields.io/github/forks/oliviaisntcringe/CVE-2025-30216-PoC.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/ThumpBo/CVE-2025-30208-EXP](https://github.com/ThumpBo/CVE-2025-30208-EXP) :  ![starts](https://img.shields.io/github/stars/ThumpBo/CVE-2025-30208-EXP.svg) ![forks](https://img.shields.io/github/forks/ThumpBo/CVE-2025-30208-EXP.svg)
- [https://github.com/xuemian168/CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-30208.svg)
- [https://github.com/marino-admin/Vite-CVE-2025-30208-Scanner](https://github.com/marino-admin/Vite-CVE-2025-30208-Scanner) :  ![starts](https://img.shields.io/github/stars/marino-admin/Vite-CVE-2025-30208-Scanner.svg) ![forks](https://img.shields.io/github/forks/marino-admin/Vite-CVE-2025-30208-Scanner.svg)
- [https://github.com/xaitx/CVE-2025-30208](https://github.com/xaitx/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xaitx/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xaitx/CVE-2025-30208.svg)
- [https://github.com/kk12-30/CVE-2025-30208](https://github.com/kk12-30/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/kk12-30/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/kk12-30/CVE-2025-30208.svg)
- [https://github.com/YuanBenSir/CVE-2025-30208_POC](https://github.com/YuanBenSir/CVE-2025-30208_POC) :  ![starts](https://img.shields.io/github/stars/YuanBenSir/CVE-2025-30208_POC.svg) ![forks](https://img.shields.io/github/forks/YuanBenSir/CVE-2025-30208_POC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/yugo-eliatrope/test-cve-2025-29927](https://github.com/yugo-eliatrope/test-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/yugo-eliatrope/test-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/yugo-eliatrope/test-cve-2025-29927.svg)
- [https://github.com/Eve-SatOrU/POC-CVE-2025-29927](https://github.com/Eve-SatOrU/POC-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Eve-SatOrU/POC-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Eve-SatOrU/POC-CVE-2025-29927.svg)
- [https://github.com/aleongx/CVE-2025-29927](https://github.com/aleongx/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29927.svg)
- [https://github.com/Slvignesh05/CVE-2025-29927](https://github.com/Slvignesh05/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Slvignesh05/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Slvignesh05/CVE-2025-29927.svg)
- [https://github.com/gotcadumitru/test-cve-2025-29927](https://github.com/gotcadumitru/test-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/gotcadumitru/test-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/gotcadumitru/test-cve-2025-29927.svg)
- [https://github.com/nicknisi/next-attack](https://github.com/nicknisi/next-attack) :  ![starts](https://img.shields.io/github/stars/nicknisi/next-attack.svg) ![forks](https://img.shields.io/github/forks/nicknisi/next-attack.svg)


## CVE-2025-24514
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/raulchung/CVE-2025-2783](https://github.com/raulchung/CVE-2025-2783) :  ![starts](https://img.shields.io/github/stars/raulchung/CVE-2025-2783.svg) ![forks](https://img.shields.io/github/forks/raulchung/CVE-2025-2783.svg)


## CVE-2025-2596
 Session logout could be overwritten in Checkmk GmbH's Checkmk versions 2.3.0p30, 2.2.0p41, and 2.1.0p49 (EOL)

- [https://github.com/Sudo-Sakib/CVE-2025-25964](https://github.com/Sudo-Sakib/CVE-2025-25964) :  ![starts](https://img.shields.io/github/stars/Sudo-Sakib/CVE-2025-25964.svg) ![forks](https://img.shields.io/github/forks/Sudo-Sakib/CVE-2025-25964.svg)
- [https://github.com/Sudo-Sakib/CVE-2025-25965](https://github.com/Sudo-Sakib/CVE-2025-25965) :  ![starts](https://img.shields.io/github/stars/Sudo-Sakib/CVE-2025-25965.svg) ![forks](https://img.shields.io/github/forks/Sudo-Sakib/CVE-2025-25965.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)
- [https://github.com/Esonhugh/nginxnightmare](https://github.com/Esonhugh/nginxnightmare) :  ![starts](https://img.shields.io/github/stars/Esonhugh/nginxnightmare.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/nginxnightmare.svg)
- [https://github.com/zwxxb/CVE-2025-1974](https://github.com/zwxxb/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/zwxxb/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/zwxxb/CVE-2025-1974.svg)
- [https://github.com/hi-unc1e/CVE-2025-1974-poc](https://github.com/hi-unc1e/CVE-2025-1974-poc) :  ![starts](https://img.shields.io/github/stars/hi-unc1e/CVE-2025-1974-poc.svg) ![forks](https://img.shields.io/github/forks/hi-unc1e/CVE-2025-1974-poc.svg)
- [https://github.com/m-q-t/ingressnightmare-detection-poc](https://github.com/m-q-t/ingressnightmare-detection-poc) :  ![starts](https://img.shields.io/github/stars/m-q-t/ingressnightmare-detection-poc.svg) ![forks](https://img.shields.io/github/forks/m-q-t/ingressnightmare-detection-poc.svg)
- [https://github.com/dttuss/IngressNightmare-RCE-POC](https://github.com/dttuss/IngressNightmare-RCE-POC) :  ![starts](https://img.shields.io/github/stars/dttuss/IngressNightmare-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/dttuss/IngressNightmare-RCE-POC.svg)


## CVE-2025-1098
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `mirror-target` and `mirror-host` Ingress annotations can be used to inject arbitrary configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)


## CVE-2025-1097
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-tls-match-cn` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)


## CVE-2024-52510
 The Nextcloud Desktop Client is a tool to synchronize files from Nextcloud Server with your computer. The Desktop client did not stop with an error but allowed by-passing the signature validation, if a manipulated server sends an empty initial signature. It is recommended that the Nextcloud Desktop client is upgraded to 3.14.2 or later.

- [https://github.com/d-xuan/CVE-2024-52510](https://github.com/d-xuan/CVE-2024-52510) :  ![starts](https://img.shields.io/github/stars/d-xuan/CVE-2024-52510.svg) ![forks](https://img.shields.io/github/forks/d-xuan/CVE-2024-52510.svg)


## CVE-2024-7479
 Improper verification of cryptographic signature during installation of a VPN driver via the TeamViewer_service.exe component of TeamViewer Remote Clients prior version 15.58.4 for Windows allows an attacker with local unprivileged access on a Windows system to elevate their privileges and install drivers.

- [https://github.com/fortra/CVE-2024-7479](https://github.com/fortra/CVE-2024-7479) :  ![starts](https://img.shields.io/github/stars/fortra/CVE-2024-7479.svg) ![forks](https://img.shields.io/github/forks/fortra/CVE-2024-7479.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/art-of-defence/CVE-2024-4956](https://github.com/art-of-defence/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/art-of-defence/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/art-of-defence/CVE-2024-4956.svg)


## CVE-2023-45878
 GibbonEdu Gibbon version 25.0.1 and before allows Arbitrary File Write because rubrics_visualise_saveAjax.phps does not require authentication. The endpoint accepts the img, path, and gibbonPersonID parameters. The img parameter is expected to be a base64 encoded image. If the path parameter is set, the defined path is used as the destination folder, concatenated with the absolute path of the installation directory. The content of the img parameter is base64 decoded and written to the defined file path. This allows creation of PHP files that permit Remote Code Execution (unauthenticated).

- [https://github.com/nrazv/CVE-2023-45878](https://github.com/nrazv/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/nrazv/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/nrazv/CVE-2023-45878.svg)


## CVE-2023-1521
If the server is run as root (which is the default when installing the  snap package https://snapcraft.io/sccache ), this means a user running the sccache client can get root privileges.

- [https://github.com/rubbxalc/CVE-2023-1521](https://github.com/rubbxalc/CVE-2023-1521) :  ![starts](https://img.shields.io/github/stars/rubbxalc/CVE-2023-1521.svg) ![forks](https://img.shields.io/github/forks/rubbxalc/CVE-2023-1521.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/Code2Crusader/46689](https://github.com/Code2Crusader/46689) :  ![starts](https://img.shields.io/github/stars/Code2Crusader/46689.svg) ![forks](https://img.shields.io/github/forks/Code2Crusader/46689.svg)


## CVE-2022-0944
 Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.

- [https://github.com/Artemisxxx37/OverlayFS-PrivEsc-CVE-2022-0944](https://github.com/Artemisxxx37/OverlayFS-PrivEsc-CVE-2022-0944) :  ![starts](https://img.shields.io/github/stars/Artemisxxx37/OverlayFS-PrivEsc-CVE-2022-0944.svg) ![forks](https://img.shields.io/github/forks/Artemisxxx37/OverlayFS-PrivEsc-CVE-2022-0944.svg)


## CVE-2018-9206
 Unauthenticated arbitrary file upload vulnerability in Blueimp jQuery-File-Upload = v9.22.0

- [https://github.com/liemkaka/CVE-2018-9206](https://github.com/liemkaka/CVE-2018-9206) :  ![starts](https://img.shields.io/github/stars/liemkaka/CVE-2018-9206.svg) ![forks](https://img.shields.io/github/forks/liemkaka/CVE-2018-9206.svg)


## CVE-2018-4150
 An issue was discovered in certain Apple products. iOS before 11.3 is affected. macOS before 10.13.4 is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the "Kernel" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.

- [https://github.com/mirdhan/LovelySn0w](https://github.com/mirdhan/LovelySn0w) :  ![starts](https://img.shields.io/github/stars/mirdhan/LovelySn0w.svg) ![forks](https://img.shields.io/github/forks/mirdhan/LovelySn0w.svg)

