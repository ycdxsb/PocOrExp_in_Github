# Update 2022-11-13
## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavisd via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavisd automatically prefers it over cpio.

- [https://github.com/Cr4ckC4t/cve-2022-41352-zimbra-rce](https://github.com/Cr4ckC4t/cve-2022-41352-zimbra-rce) :  ![starts](https://img.shields.io/github/stars/Cr4ckC4t/cve-2022-41352-zimbra-rce.svg) ![forks](https://img.shields.io/github/forks/Cr4ckC4t/cve-2022-41352-zimbra-rce.svg)


## CVE-2022-40140
 An origin validation error vulnerability in Trend Micro Apex One and Apex One as a Service could allow a local attacker to cause a denial-of-service on affected installations. Please note: an attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability.

- [https://github.com/ipsBruno/CVE-2022-40140-SCANNER](https://github.com/ipsBruno/CVE-2022-40140-SCANNER) :  ![starts](https://img.shields.io/github/stars/ipsBruno/CVE-2022-40140-SCANNER.svg) ![forks](https://img.shields.io/github/forks/ipsBruno/CVE-2022-40140-SCANNER.svg)


## CVE-2022-37967
 Windows Kerberos Elevation of Privilege Vulnerability.

- [https://github.com/bmcmcm/Get-msDSSupportedEncryptionTypes](https://github.com/bmcmcm/Get-msDSSupportedEncryptionTypes) :  ![starts](https://img.shields.io/github/stars/bmcmcm/Get-msDSSupportedEncryptionTypes.svg) ![forks](https://img.shields.io/github/forks/bmcmcm/Get-msDSSupportedEncryptionTypes.svg)


## CVE-2022-31898
 gl-inet GL-MT300N-V2 Mango v3.212 and GL-AX1800 Flint v3.214 were discovered to contain multiple command injection vulnerabilities via the ping_addr and trace_addr function parameters.

- [https://github.com/gigaryte/cve-2022-31898](https://github.com/gigaryte/cve-2022-31898) :  ![starts](https://img.shields.io/github/stars/gigaryte/cve-2022-31898.svg) ![forks](https://img.shields.io/github/forks/gigaryte/cve-2022-31898.svg)


## CVE-2022-22620
 A use after free issue was addressed with improved memory management. This issue is fixed in macOS Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8). Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

- [https://github.com/dkjiayu/dkjiayu.github.io](https://github.com/dkjiayu/dkjiayu.github.io) :  ![starts](https://img.shields.io/github/stars/dkjiayu/dkjiayu.github.io.svg) ![forks](https://img.shields.io/github/forks/dkjiayu/dkjiayu.github.io.svg)


## CVE-2022-3949
 A vulnerability, which was classified as problematic, has been found in Sourcecodester Simple Cashiering System. This issue affects some unknown processing of the component User Account Handler. The manipulation of the argument fullname leads to cross site scripting. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-213455.

- [https://github.com/maikroservice/CVE-2022-3949](https://github.com/maikroservice/CVE-2022-3949) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2022-3949.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2022-3949.svg)


## CVE-2022-3942
 A vulnerability was found in SourceCodester Sanitization Management System and classified as problematic. This issue affects some unknown processing of the file php-sms/?p=request_quote. The manipulation leads to cross site scripting. The attack may be initiated remotely. The identifier VDB-213449 was assigned to this vulnerability.

- [https://github.com/maikroservice/CVE-2022-3942](https://github.com/maikroservice/CVE-2022-3942) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2022-3942.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2022-3942.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639](https://github.com/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639.svg)


## CVE-2022-2274
 The OpenSSL 3.0.4 release introduced a serious bug in the RSA implementation for X86_64 CPUs supporting the AVX512IFMA instructions. This issue makes the RSA implementation with 2048 bit private keys incorrect on such machines and memory corruption will happen during the computation. As a consequence of the memory corruption an attacker may be able to trigger a remote code execution on the machine performing the computation. SSL/TLS servers or other servers using 2048 bit RSA private keys running on machines supporting AVX512IFMA instructions of the X86_64 architecture are affected by this issue.

- [https://github.com/EkamSinghWalia/OpenSSL-Vulnerability-Detection-Script](https://github.com/EkamSinghWalia/OpenSSL-Vulnerability-Detection-Script) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/OpenSSL-Vulnerability-Detection-Script.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/OpenSSL-Vulnerability-Detection-Script.svg)


## CVE-2022-1679
 A use-after-free flaw was found in the Linux kernel&#8217;s Atheros wireless adapter driver in the way a user forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679](https://github.com/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679.svg)


## CVE-2022-1015
 A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem. This flaw allows a local user to cause an out-of-bounds write issue.

- [https://github.com/ysanatomic/CVE-2022-1015](https://github.com/ysanatomic/CVE-2022-1015) :  ![starts](https://img.shields.io/github/stars/ysanatomic/CVE-2022-1015.svg) ![forks](https://img.shields.io/github/forks/ysanatomic/CVE-2022-1015.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/M3l0nPan/wordpress-cve-2021-29447](https://github.com/M3l0nPan/wordpress-cve-2021-29447) :  ![starts](https://img.shields.io/github/stars/M3l0nPan/wordpress-cve-2021-29447.svg) ![forks](https://img.shields.io/github/forks/M3l0nPan/wordpress-cve-2021-29447.svg)


## CVE-2019-17662
 ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is stored in cleartext in a file that can be read via a ../../ThinVnc.ini directory traversal attack vector.

- [https://github.com/bl4ck574r/CVE-2019-17662](https://github.com/bl4ck574r/CVE-2019-17662) :  ![starts](https://img.shields.io/github/stars/bl4ck574r/CVE-2019-17662.svg) ![forks](https://img.shields.io/github/forks/bl4ck574r/CVE-2019-17662.svg)

