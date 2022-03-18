# Update 2022-03-18
## CVE-2022-26503
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sinsinology/CVE-2022-26503](https://github.com/sinsinology/CVE-2022-26503) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2022-26503.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2022-26503.svg)


## CVE-2022-25949
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/tandasat/CVE-2022-25949](https://github.com/tandasat/CVE-2022-25949) :  ![starts](https://img.shields.io/github/stars/tandasat/CVE-2022-25949.svg) ![forks](https://img.shields.io/github/forks/tandasat/CVE-2022-25949.svg)


## CVE-2022-25640
 In wolfSSL before 5.2.0, a TLS 1.3 server cannot properly enforce a requirement for mutual authentication. A client can simply omit the certificate_verify message from the handshake, and never present a certificate.

- [https://github.com/dim0x69/cve-2022-25640-exploit](https://github.com/dim0x69/cve-2022-25640-exploit) :  ![starts](https://img.shields.io/github/stars/dim0x69/cve-2022-25640-exploit.svg) ![forks](https://img.shields.io/github/forks/dim0x69/cve-2022-25640-exploit.svg)


## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112](https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/M4xSec/Apache-APISIX-CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/M4xSec/Apache-APISIX-CVE-2022-24112.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/BobTheShoplifter/CVE-2022-0778-POC](https://github.com/BobTheShoplifter/CVE-2022-0778-POC) :  ![starts](https://img.shields.io/github/stars/BobTheShoplifter/CVE-2022-0778-POC.svg) ![forks](https://img.shields.io/github/forks/BobTheShoplifter/CVE-2022-0778-POC.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/aodsec/CVE-2022-0543](https://github.com/aodsec/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/aodsec/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/aodsec/CVE-2022-0543.svg)


## CVE-2021-43008
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/p0dalirius/CVE-2021-43008-AdminerRead](https://github.com/p0dalirius/CVE-2021-43008-AdminerRead) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2021-43008-AdminerRead.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2021-43008-AdminerRead.svg)


## CVE-2021-21983
 Arbitrary file write vulnerability in vRealize Operations Manager API (CVE-2021-21983) prior to 8.4 may allow an authenticated malicious actor with network access to the vRealize Operations Manager API can write files to arbitrary locations on the underlying photon operating system.

- [https://github.com/murataydemir/CVE-2021-21983](https://github.com/murataydemir/CVE-2021-21983) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-21983.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-21983.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/Jiang59991/cve-2021-21300](https://github.com/Jiang59991/cve-2021-21300) :  ![starts](https://img.shields.io/github/stars/Jiang59991/cve-2021-21300.svg) ![forks](https://img.shields.io/github/forks/Jiang59991/cve-2021-21300.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)
- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)


## CVE-2021-0595
 In lockAllProfileTasks of RootWindowContainer.java, there is a possible way to access the work profile without the profile PIN, after logging in. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11 Android-8.1Android ID: A-177457096

- [https://github.com/pazhanivel07/Settings-CVE-2021-0595](https://github.com/pazhanivel07/Settings-CVE-2021-0595) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/Settings-CVE-2021-0595.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/Settings-CVE-2021-0595.svg)
- [https://github.com/pazhanivel07/frameworks_base-CVE-2021-0595](https://github.com/pazhanivel07/frameworks_base-CVE-2021-0595) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/frameworks_base-CVE-2021-0595.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/frameworks_base-CVE-2021-0595.svg)


## CVE-2019-1181
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/major203/cve-2019-1181](https://github.com/major203/cve-2019-1181) :  ![starts](https://img.shields.io/github/stars/major203/cve-2019-1181.svg) ![forks](https://img.shields.io/github/forks/major203/cve-2019-1181.svg)


## CVE-2018-4185
 In iOS before 11.3, tvOS before 11.3, watchOS before 4.3, and macOS before High Sierra 10.13.4, an information disclosure issue existed in the transition of program state. This issue was addressed with improved state handling.

- [https://github.com/xigexbh/bazad1](https://github.com/xigexbh/bazad1) :  ![starts](https://img.shields.io/github/stars/xigexbh/bazad1.svg) ![forks](https://img.shields.io/github/forks/xigexbh/bazad1.svg)

