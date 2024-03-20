# Update 2024-03-20
## CVE-2024-25153
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/rainbowhatrkn/CVE-2024-25153](https://github.com/rainbowhatrkn/CVE-2024-25153) :  ![starts](https://img.shields.io/github/stars/rainbowhatrkn/CVE-2024-25153.svg) ![forks](https://img.shields.io/github/forks/rainbowhatrkn/CVE-2024-25153.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/z3rObyte/CVE-2024-23334-PoC](https://github.com/z3rObyte/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/z3rObyte/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/z3rObyte/CVE-2024-23334-PoC.svg)


## CVE-2024-1071
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Matrexdz/CVE-2024-1071](https://github.com/Matrexdz/CVE-2024-1071) :  ![starts](https://img.shields.io/github/stars/Matrexdz/CVE-2024-1071.svg) ![forks](https://img.shields.io/github/forks/Matrexdz/CVE-2024-1071.svg)
- [https://github.com/Matrexdz/CVE-2024-1071-Docker](https://github.com/Matrexdz/CVE-2024-1071-Docker) :  ![starts](https://img.shields.io/github/stars/Matrexdz/CVE-2024-1071-Docker.svg) ![forks](https://img.shields.io/github/forks/Matrexdz/CVE-2024-1071-Docker.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc](https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2023-43208-mirth-connect-rce-poc.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2023-43208-mirth-connect-rce-poc.svg)


## CVE-2023-33733
 Reportlab up to v3.6.12 allows attackers to execute arbitrary code via supplying a crafted PDF file.

- [https://github.com/onion2203/Lab_Reportlab](https://github.com/onion2203/Lab_Reportlab) :  ![starts](https://img.shields.io/github/stars/onion2203/Lab_Reportlab.svg) ![forks](https://img.shields.io/github/forks/onion2203/Lab_Reportlab.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/jhonnybonny/CVE-2023-3824](https://github.com/jhonnybonny/CVE-2023-3824) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2023-3824.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2023-3824.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2022-0778](https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/hshivhare67/OpenSSL_1.0.1g_CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/OpenSSL_1.0.1g_CVE-2022-0778.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2020-0423
 In binder_release_work of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-161151868References: N/A

- [https://github.com/sparrow-labz/CVE-2020-0423](https://github.com/sparrow-labz/CVE-2020-0423) :  ![starts](https://img.shields.io/github/stars/sparrow-labz/CVE-2020-0423.svg) ![forks](https://img.shields.io/github/forks/sparrow-labz/CVE-2020-0423.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/jftierno/CVE-2018-6574](https://github.com/jftierno/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/jftierno/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/jftierno/CVE-2018-6574.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/K3ysTr0K3R/CVE-2017-12617-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-12617-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-12617-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-12617-EXPLOIT.svg)

