# Update 2021-05-25
## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/Udyz/CVE-2021-31166](https://github.com/Udyz/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-31166.svg)


## CVE-2021-29687
 IBM Security Identity Manager 7.0.2 could allow a remote user to enumerate usernames due to a difference of responses from valid and invalid login attempts. IBM X-Force ID: 200018

- [https://github.com/JamesGeee/CVE-2021-29687](https://github.com/JamesGeee/CVE-2021-29687) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29687.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29687.svg)


## CVE-2021-23841
 The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

- [https://github.com/JamesGeee/CVE-2021-23841](https://github.com/JamesGeee/CVE-2021-23841) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-23841.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-23841.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/briskets/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/briskets/CVE-2021-3493.svg)


## CVE-2021-3310
 Western Digital My Cloud OS 5 devices before 5.10.122 mishandle Symbolic Link Following on SMB and AFP shares. This can lead to code execution and information disclosure (by reading local files).

- [https://github.com/piffd0s/CVE-2021-3310](https://github.com/piffd0s/CVE-2021-3310) :  ![starts](https://img.shields.io/github/stars/piffd0s/CVE-2021-3310.svg) ![forks](https://img.shields.io/github/forks/piffd0s/CVE-2021-3310.svg)


## CVE-2021-3012
 A cross-site scripting (XSS) vulnerability in the Document Link of documents in ESRI Enterprise before 10.9 allows remote authenticated users to inject arbitrary JavaScript code via a malicious HTML attribute such as onerror (in the URL field of the Parameters tab).

- [https://github.com/JamesGeee/CVE-2021-3012](https://github.com/JamesGeee/CVE-2021-3012) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-3012.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-3012.svg)


## CVE-2020-28948
 Archive_Tar through 1.4.10 allows an unserialization attack because phar: is blocked but PHAR: is not blocked.

- [https://github.com/nopdata/cve-2020-28948](https://github.com/nopdata/cve-2020-28948) :  ![starts](https://img.shields.io/github/stars/nopdata/cve-2020-28948.svg) ![forks](https://img.shields.io/github/forks/nopdata/cve-2020-28948.svg)


## CVE-2020-24993
 There is a cross site scripting vulnerability on CmsWing 1.3.7. This vulnerability (stored XSS) is triggered when visitors access the article module.

- [https://github.com/JamesGeee/CVE-2020-24993](https://github.com/JamesGeee/CVE-2020-24993) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-24993.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-24993.svg)


## CVE-2020-24755
 In Ubiquiti UniFi Video v3.10.13, when the executable starts, its first library validation is in the current directory. This allows the impersonation and modification of the library to execute code on the system. This was tested in (Windows 7 x64/Windows 10 x64).

- [https://github.com/JamesGeee/CVE-2020-24755](https://github.com/JamesGeee/CVE-2020-24755) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-24755.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-24755.svg)


## CVE-2020-18220
 Weak Encoding for Password in DoraCMS v2.1.1 and earlier allows attackers to obtain sensitive information as it does not use a random salt or IV for its AES-CBC encryption, causes password encrypted for users to be susceptible to dictionary attacks.

- [https://github.com/JamesGeee/CVE-2020-18220](https://github.com/JamesGeee/CVE-2020-18220) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-18220.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-18220.svg)


## CVE-2020-18178
 Path Traversal in HongCMS v4.0.0 allows remote attackers to view, edit, and delete arbitrary files via a crafted POST request to the component &quot;/hcms/admin/index.php/language/ajax.&quot;

- [https://github.com/JamesGeee/CVE-2020-18178](https://github.com/JamesGeee/CVE-2020-18178) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-18178.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-18178.svg)


## CVE-2017-13208
 In receive_packet of libnetutils/packet.c, there is a possible out-of-bounds write due to a missing bounds check on the DHCP response. This could lead to remote code execution as a privileged process with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0, 8.1. Android ID: A-67474440.

- [https://github.com/idanshechter/CVE-2017-13208-Scanner](https://github.com/idanshechter/CVE-2017-13208-Scanner) :  ![starts](https://img.shields.io/github/stars/idanshechter/CVE-2017-13208-Scanner.svg) ![forks](https://img.shields.io/github/forks/idanshechter/CVE-2017-13208-Scanner.svg)


## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.

- [https://github.com/ZhenwarX/Telerik-CVE-2017-9248-PoC](https://github.com/ZhenwarX/Telerik-CVE-2017-9248-PoC) :  ![starts](https://img.shields.io/github/stars/ZhenwarX/Telerik-CVE-2017-9248-PoC.svg) ![forks](https://img.shields.io/github/forks/ZhenwarX/Telerik-CVE-2017-9248-PoC.svg)

