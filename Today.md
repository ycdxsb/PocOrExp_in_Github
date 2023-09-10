# Update 2023-09-10
## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.

- [https://github.com/jakabakos/CVE-2023-27524-Apache-Superset-Auth-Bypass-and-RCE](https://github.com/jakabakos/CVE-2023-27524-Apache-Superset-Auth-Bypass-and-RCE) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2023-27524-Apache-Superset-Auth-Bypass-and-RCE.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2023-27524-Apache-Superset-Auth-Bypass-and-RCE.svg)


## CVE-2021-23841
 The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-23841](https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-23841) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_CVE-2021-23841.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_CVE-2021-23841.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/Hikikan/CVE-2021-22205](https://github.com/Hikikan/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/Hikikan/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/Hikikan/CVE-2021-22205.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)
- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449](https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/Winter3un/CVE-2021-1675](https://github.com/Winter3un/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/Winter3un/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/Winter3un/CVE-2021-1675.svg)
- [https://github.com/jj4152/cve-2021-1675](https://github.com/jj4152/cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/jj4152/cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/jj4152/cve-2021-1675.svg)
- [https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.](https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.) :  ![starts](https://img.shields.io/github/stars/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg) ![forks](https://img.shields.io/github/forks/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg)


## CVE-2021-1366
 A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to perform a DLL hijacking attack on an affected device if the VPN Posture (HostScan) Module is installed on the AnyConnect client. This vulnerability is due to insufficient validation of resources that are loaded by the application at run time. An attacker could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process. A successful exploit could allow the attacker to execute arbitrary code on the affected machine with SYSTEM privileges. To exploit this vulnerability, the attacker needs valid credentials on the Windows system.

- [https://github.com/koztkozt/CVE-2021-1366](https://github.com/koztkozt/CVE-2021-1366) :  ![starts](https://img.shields.io/github/stars/koztkozt/CVE-2021-1366.svg) ![forks](https://img.shields.io/github/forks/koztkozt/CVE-2021-1366.svg)


## CVE-2020-2915
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching, CacheStore, Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/txrw/Dubbo-CVE-2020-1948](https://github.com/txrw/Dubbo-CVE-2020-1948) :  ![starts](https://img.shields.io/github/stars/txrw/Dubbo-CVE-2020-1948.svg) ![forks](https://img.shields.io/github/forks/txrw/Dubbo-CVE-2020-1948.svg)


## CVE-2020-1481
 A remote code execution vulnerability exists in the ESLint extension for Visual Studio Code when it validates source code after opening a project, aka 'Visual Studio Code ESLint Extention Remote Code Execution Vulnerability'.

- [https://github.com/Rival420/CVE-2020-14181](https://github.com/Rival420/CVE-2020-14181) :  ![starts](https://img.shields.io/github/stars/Rival420/CVE-2020-14181.svg) ![forks](https://img.shields.io/github/forks/Rival420/CVE-2020-14181.svg)


## CVE-2020-0041
 In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel

- [https://github.com/jcalabres/root-exploit-pixel3](https://github.com/jcalabres/root-exploit-pixel3) :  ![starts](https://img.shields.io/github/stars/jcalabres/root-exploit-pixel3.svg) ![forks](https://img.shields.io/github/forks/jcalabres/root-exploit-pixel3.svg)


## CVE-2019-12815
 An arbitrary file copy vulnerability in mod_copy in ProFTPD up to 1.3.5b allows for remote code execution and information disclosure without authentication, a related issue to CVE-2015-3306.

- [https://github.com/KTN1990/CVE-2019-12815](https://github.com/KTN1990/CVE-2019-12815) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2019-12815.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2019-12815.svg)


## CVE-2019-8331
 In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.

- [https://github.com/Thampakon/CVE-2019-8331](https://github.com/Thampakon/CVE-2019-8331) :  ![starts](https://img.shields.io/github/stars/Thampakon/CVE-2019-8331.svg) ![forks](https://img.shields.io/github/forks/Thampakon/CVE-2019-8331.svg)


## CVE-2018-1932
 IBM API Connect 5.0.0.0 through 5.0.8.4 is affected by a vulnerability in the role-based access control in the management server that could allow an authenticated user to obtain highly sensitive information. IBM X-Force ID: 153175.

- [https://github.com/BKreisel/CVE-2018-1932X](https://github.com/BKreisel/CVE-2018-1932X) :  ![starts](https://img.shields.io/github/stars/BKreisel/CVE-2018-1932X.svg) ![forks](https://img.shields.io/github/forks/BKreisel/CVE-2018-1932X.svg)


## CVE-2017-8225
 On Wireless IP Camera (P2P) WIFICAM devices, access to .ini files (containing credentials) is not correctly checked. An attacker can bypass authentication by providing an empty loginuse parameter and an empty loginpas parameter in the URI.

- [https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg)


## CVE-2017-5754
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)
- [https://github.com/speecyy/Am-I-affected-by-Meltdown](https://github.com/speecyy/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/speecyy/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/speecyy/Am-I-affected-by-Meltdown.svg)


## CVE-2014-9390
 Git before 1.8.5.6, 1.9.x before 1.9.5, 2.0.x before 2.0.5, 2.1.x before 2.1.4, and 2.2.x before 2.2.1 on Windows and OS X; Mercurial before 3.2.3 on Windows and OS X; Apple Xcode before 6.2 beta 3; mine all versions before 08-12-2014; libgit2 all versions up to 0.21.2; Egit all versions before 08-12-2014; and JGit all versions before 08-12-2014 allow remote Git servers to execute arbitrary commands via a tree containing a crafted .git/config file with (1) an ignorable Unicode codepoint, (2) a git~1/config representation, or (3) mixed case that is improperly handled on a case-insensitive filesystem.

- [https://github.com/mdisec/CVE-2014-9390](https://github.com/mdisec/CVE-2014-9390) :  ![starts](https://img.shields.io/github/stars/mdisec/CVE-2014-9390.svg) ![forks](https://img.shields.io/github/forks/mdisec/CVE-2014-9390.svg)

