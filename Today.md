# Update 2025-04-02
## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/jackieya/CVE-2025-30208](https://github.com/jackieya/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/jackieya/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/jackieya/CVE-2025-30208.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/B1gN0Se/Tomcat-CVE-2025-24813](https://github.com/B1gN0Se/Tomcat-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/B1gN0Se/Tomcat-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/B1gN0Se/Tomcat-CVE-2025-24813.svg)


## CVE-2025-24799
 GLPI is a free asset and IT management software package. An unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 10.0.18.

- [https://github.com/realcodeb0ss/CVE-2025-24799-PoC](https://github.com/realcodeb0ss/CVE-2025-24799-PoC) :  ![starts](https://img.shields.io/github/stars/realcodeb0ss/CVE-2025-24799-PoC.svg) ![forks](https://img.shields.io/github/forks/realcodeb0ss/CVE-2025-24799-PoC.svg)


## CVE-2025-3010
 A vulnerability, which was classified as problematic, has been found in Khronos Group glslang 15.1.0. Affected by this issue is the function glslang::TIntermediate::isConversionAllowed of the file glslang/MachineIndependent/Intermediate.cpp. The manipulation leads to null pointer dereference. The attack needs to be approached locally. The exploit has been disclosed to the public and may be used.

- [https://github.com/4xura/CVE-2025-30108](https://github.com/4xura/CVE-2025-30108) :  ![starts](https://img.shields.io/github/stars/4xura/CVE-2025-30108.svg) ![forks](https://img.shields.io/github/forks/4xura/CVE-2025-30108.svg)


## CVE-2025-2997
 A vulnerability was found in zhangyanbo2007 youkefu 4.2.0. It has been classified as critical. Affected is an unknown function of the file /res/url. The manipulation of the argument url leads to server-side request forgery. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ThemeHackers/CVE-2025-29972](https://github.com/ThemeHackers/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-29972.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/mrrivaldo/CVE-2025-2294](https://github.com/mrrivaldo/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/mrrivaldo/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/mrrivaldo/CVE-2025-2294.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/zulloper/CVE-2025-1974](https://github.com/zulloper/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/zulloper/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/zulloper/CVE-2025-1974.svg)
- [https://github.com/gian2dchris/ingress-nightmare-poc](https://github.com/gian2dchris/ingress-nightmare-poc) :  ![starts](https://img.shields.io/github/stars/gian2dchris/ingress-nightmare-poc.svg) ![forks](https://img.shields.io/github/forks/gian2dchris/ingress-nightmare-poc.svg)


## CVE-2025-0868
This issue affects DocsGPT: from 0.8.1 through 0.12.0.

- [https://github.com/shreyas-malhotra/PoC_CVE-2025-0868](https://github.com/shreyas-malhotra/PoC_CVE-2025-0868) :  ![starts](https://img.shields.io/github/stars/shreyas-malhotra/PoC_CVE-2025-0868.svg) ![forks](https://img.shields.io/github/forks/shreyas-malhotra/PoC_CVE-2025-0868.svg)


## CVE-2024-44450
 Multiple functions are vulnerable to Authorization Bypass in AIMS eCrew. The issue was fixed in version JUN23 #190.

- [https://github.com/NaunetEU/CVE-2024-44450](https://github.com/NaunetEU/CVE-2024-44450) :  ![starts](https://img.shields.io/github/stars/NaunetEU/CVE-2024-44450.svg) ![forks](https://img.shields.io/github/forks/NaunetEU/CVE-2024-44450.svg)


## CVE-2024-36991
 In Splunk Enterprise on Windows versions below 9.2.2, 9.1.5, and 9.0.10, an attacker could perform a path traversal on the /modules/messaging/ endpoint in Splunk Enterprise on Windows. This vulnerability should only affect Splunk Enterprise on Windows.

- [https://github.com/gunzf0x/CVE-2024-36991](https://github.com/gunzf0x/CVE-2024-36991) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2024-36991.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2024-36991.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/so1icitx/CVE-2024-25600](https://github.com/so1icitx/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/so1icitx/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/so1icitx/CVE-2024-25600.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/G4sp4rCS/CVE-2023-32784-password-combinator-fixer](https://github.com/G4sp4rCS/CVE-2023-32784-password-combinator-fixer) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/CVE-2023-32784-password-combinator-fixer.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/CVE-2023-32784-password-combinator-fixer.svg)


## CVE-2023-21554
 Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability

- [https://github.com/leongxudong/MSMQ-Vulnerbaility](https://github.com/leongxudong/MSMQ-Vulnerbaility) :  ![starts](https://img.shields.io/github/stars/leongxudong/MSMQ-Vulnerbaility.svg) ![forks](https://img.shields.io/github/forks/leongxudong/MSMQ-Vulnerbaility.svg)


## CVE-2020-7699
 This affects the package express-fileupload before 1.1.8. If the parseNested option is enabled, sending a corrupt HTTP request can lead to denial of service or arbitrary code execution.

- [https://github.com/zodiac12-pub/CVE-2020-7699_reproduce](https://github.com/zodiac12-pub/CVE-2020-7699_reproduce) :  ![starts](https://img.shields.io/github/stars/zodiac12-pub/CVE-2020-7699_reproduce.svg) ![forks](https://img.shields.io/github/forks/zodiac12-pub/CVE-2020-7699_reproduce.svg)


## CVE-2013-0169
 The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0 and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and other products, do not properly consider timing side-channel attacks on a MAC check requirement during the processing of malformed CBC padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data for crafted packets, aka the "Lucky Thirteen" issue.

- [https://github.com/wearohat/lucky13](https://github.com/wearohat/lucky13) :  ![starts](https://img.shields.io/github/stars/wearohat/lucky13.svg) ![forks](https://img.shields.io/github/forks/wearohat/lucky13.svg)


## CVE-2003-0282
 Directory traversal vulnerability in UnZip 5.50 allows attackers to overwrite arbitrary files via invalid characters between two . (dot) characters, which are filtered and result in a ".." sequence.

- [https://github.com/angus-cx/cve-2003-0282](https://github.com/angus-cx/cve-2003-0282) :  ![starts](https://img.shields.io/github/stars/angus-cx/cve-2003-0282.svg) ![forks](https://img.shields.io/github/forks/angus-cx/cve-2003-0282.svg)


## CVE-2002-0082
 The dbm and shm session cache code in mod_ssl before 2.8.7-1.3.23, and Apache-SSL before 1.3.22+1.46, does not properly initialize memory using the i2d_SSL_SESSION function, which allows remote attackers to use a buffer overflow to execute arbitrary code via a large client certificate that is signed by a trusted Certificate Authority (CA), which produces a large serialized session.

- [https://github.com/ratiros01/CVE-2002-0082](https://github.com/ratiros01/CVE-2002-0082) :  ![starts](https://img.shields.io/github/stars/ratiros01/CVE-2002-0082.svg) ![forks](https://img.shields.io/github/forks/ratiros01/CVE-2002-0082.svg)

