# Update 2023-10-04
## CVE-2023-43838
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/rootd4ddy/CVE-2023-43838](https://github.com/rootd4ddy/CVE-2023-43838) :  ![starts](https://img.shields.io/github/stars/rootd4ddy/CVE-2023-43838.svg) ![forks](https://img.shields.io/github/forks/rootd4ddy/CVE-2023-43838.svg)


## CVE-2023-43654
 TorchServe is a tool for serving and scaling PyTorch models in production. TorchServe default configuration lacks proper input validation, enabling third parties to invoke remote HTTP download requests and write files to the disk. This issue could be taken advantage of to compromise the integrity of the system and sensitive data. This issue is present in versions 0.1.0 to 0.8.1. A user is able to load the model of their choice from any URL that they would like to use. The user of TorchServe is responsible for configuring both the allowed_urls and specifying the model URL to be used. A pull request to warn the user when the default value for allowed_urls is used has been merged in PR #2534. TorchServe release 0.8.2 includes this change. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/OligoCyberSecurity/ShellTorchChecker](https://github.com/OligoCyberSecurity/ShellTorchChecker) :  ![starts](https://img.shields.io/github/stars/OligoCyberSecurity/ShellTorchChecker.svg) ![forks](https://img.shields.io/github/forks/OligoCyberSecurity/ShellTorchChecker.svg)


## CVE-2023-40044
 In WS_FTP Server versions prior to 8.7.4 and 8.8.2, a pre-authenticated attacker could leverage a .NET deserialization vulnerability in the Ad Hoc Transfer module to execute remote commands on the underlying WS_FTP Server operating system.

- [https://github.com/kenbuckler/WS_FTP-CVE-2023-40044](https://github.com/kenbuckler/WS_FTP-CVE-2023-40044) :  ![starts](https://img.shields.io/github/stars/kenbuckler/WS_FTP-CVE-2023-40044.svg) ![forks](https://img.shields.io/github/forks/kenbuckler/WS_FTP-CVE-2023-40044.svg)


## CVE-2023-36845
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to remotely execute code. Using a crafted request which sets the variable PHPRC an attacker is able to modify the PHP execution environment allowing the injection und execution of code. This issue affects Juniper Networks Junos OS on EX Series and SRX Series: * All versions prior to 20.4R3-S9; * 21.1 versions 21.1R1 and later; * 21.2 versions prior to 21.2R3-S7; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R2-S2, 22.3R3-S1; * 22.4 versions prior to 22.4R2-S1, 22.4R3; * 23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/cyberh3als/CVE-2023-36845-POC](https://github.com/cyberh3als/CVE-2023-36845-POC) :  ![starts](https://img.shields.io/github/stars/cyberh3als/CVE-2023-36845-POC.svg) ![forks](https://img.shields.io/github/forks/cyberh3als/CVE-2023-36845-POC.svg)


## CVE-2023-31584
 GitHub repository cu/silicon commit a9ef36 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the User Input field.

- [https://github.com/rootd4ddy/CVE-2023-43838](https://github.com/rootd4ddy/CVE-2023-43838) :  ![starts](https://img.shields.io/github/stars/rootd4ddy/CVE-2023-43838.svg) ![forks](https://img.shields.io/github/forks/rootd4ddy/CVE-2023-43838.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/Rosayxy/Recreate-cve-2023-21768](https://github.com/Rosayxy/Recreate-cve-2023-21768) :  ![starts](https://img.shields.io/github/stars/Rosayxy/Recreate-cve-2023-21768.svg) ![forks](https://img.shields.io/github/forks/Rosayxy/Recreate-cve-2023-21768.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/mrluc4s-sysadmin/PoC-CVE-2022-0778-](https://github.com/mrluc4s-sysadmin/PoC-CVE-2022-0778-) :  ![starts](https://img.shields.io/github/stars/mrluc4s-sysadmin/PoC-CVE-2022-0778-.svg) ![forks](https://img.shields.io/github/forks/mrluc4s-sysadmin/PoC-CVE-2022-0778-.svg)
- [https://github.com/Trinadh465/openssl-1.1.1g_CVE-2022-0778](https://github.com/Trinadh465/openssl-1.1.1g_CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/Trinadh465/openssl-1.1.1g_CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/openssl-1.1.1g_CVE-2022-0778.svg)


## CVE-2021-44906
 Minimist &lt;=1.2.5 is vulnerable to Prototype Pollution via file index.js, function setKey() (lines 69-95).

- [https://github.com/nevermoe/CVE-2021-44906](https://github.com/nevermoe/CVE-2021-44906) :  ![starts](https://img.shields.io/github/stars/nevermoe/CVE-2021-44906.svg) ![forks](https://img.shields.io/github/forks/nevermoe/CVE-2021-44906.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773-v-](https://github.com/mightysai1997/cve-2021-41773-v-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773-v-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773-v-.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/AssassinUKG/Polkit-CVE-2021-3560](https://github.com/AssassinUKG/Polkit-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/Polkit-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/Polkit-CVE-2021-3560.svg)
- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/SNCKER/CVE-2021-3129](https://github.com/SNCKER/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/SNCKER/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/SNCKER/CVE-2021-3129.svg)
- [https://github.com/keyuan15/CVE-2021-3129](https://github.com/keyuan15/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/keyuan15/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/keyuan15/CVE-2021-3129.svg)

