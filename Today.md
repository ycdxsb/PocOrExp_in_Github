# Update 2022-07-08
## CVE-2022-31749
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/iveresk/cve-2022-31749](https://github.com/iveresk/cve-2022-31749) :  ![starts](https://img.shields.io/github/stars/iveresk/cve-2022-31749.svg) ![forks](https://img.shields.io/github/forks/iveresk/cve-2022-31749.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/maxgestic/Follina-RTF-Generator](https://github.com/maxgestic/Follina-RTF-Generator) :  ![starts](https://img.shields.io/github/stars/maxgestic/Follina-RTF-Generator.svg) ![forks](https://img.shields.io/github/forks/maxgestic/Follina-RTF-Generator.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)
- [https://github.com/W01fh4cker/Serein_Linux](https://github.com/W01fh4cker/Serein_Linux) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein_Linux.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein_Linux.svg)


## CVE-2022-27255
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/infobyte/cve-2022-27255](https://github.com/infobyte/cve-2022-27255) :  ![starts](https://img.shields.io/github/stars/infobyte/cve-2022-27255.svg) ![forks](https://img.shields.io/github/forks/infobyte/cve-2022-27255.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/incogbyte/CVE_2022_26134-detect](https://github.com/incogbyte/CVE_2022_26134-detect) :  ![starts](https://img.shields.io/github/stars/incogbyte/CVE_2022_26134-detect.svg) ![forks](https://img.shields.io/github/forks/incogbyte/CVE_2022_26134-detect.svg)


## CVE-2022-20138
 In ACTION_MANAGED_PROFILE_PROVISIONED of DevicePolicyManagerService.java, there is a possible way for unprivileged app to send MANAGED_PROFILE_PROVISIONED intent due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-210469972

- [https://github.com/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2022-20138](https://github.com/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2022-20138) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2022-20138.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2022-20138.svg)


## CVE-2022-20133
 In setDiscoverableTimeout of AdapterService.java, there is a possible bypass of user interaction due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-206807679

- [https://github.com/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133](https://github.com/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133) :  ![starts](https://img.shields.io/github/stars/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133.svg)


## CVE-2022-2333
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/shirouQwQ/CVE-2022-2333](https://github.com/shirouQwQ/CVE-2022-2333) :  ![starts](https://img.shields.io/github/stars/shirouQwQ/CVE-2022-2333.svg) ![forks](https://img.shields.io/github/forks/shirouQwQ/CVE-2022-2333.svg)


## CVE-2022-2097
 AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn't written. In the special case of &quot;in place&quot; encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p).

- [https://github.com/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu](https://github.com/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu) :  ![starts](https://img.shields.io/github/stars/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu.svg) ![forks](https://img.shields.io/github/forks/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/z92g/CVE-2022-0543](https://github.com/z92g/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/z92g/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/z92g/CVE-2022-0543.svg)


## CVE-2021-27850
 A critical unauthenticated remote code execution vulnerability was found all recent versions of Apache Tapestry. The affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. The vulnerability I have found is a bypass of the fix for CVE-2019-0195. Recap: Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL. An attacker was able to download the file `AppModule.class` by requesting the URL `http://localhost:8080/assets/something/services/AppModule.class` which contains a HMAC secret key. The fix for that bug was a blacklist filter that checks if the URL ends with `.class`, `.properties` or `.xml`. Bypass: Unfortunately, the blacklist solution can simply be bypassed by appending a `/` at the end of the URL: `http://localhost:8080/assets/something/services/AppModule.class/` The slash is stripped after the blacklist check and the file `AppModule.class` is loaded into the response. This class usually contains the HMAC secret key which is used to sign serialized Java objects. With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE (e.g. CommonsBeanUtils1 from ysoserial). Solution for this vulnerability: * For Apache Tapestry 5.4.0 to 5.6.1, upgrade to 5.6.2 or later. * For Apache Tapestry 5.7.0, upgrade to 5.7.1 or later.

- [https://github.com/novysodope/CVE-2021-27850](https://github.com/novysodope/CVE-2021-27850) :  ![starts](https://img.shields.io/github/stars/novysodope/CVE-2021-27850.svg) ![forks](https://img.shields.io/github/forks/novysodope/CVE-2021-27850.svg)


## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.

- [https://github.com/B1anda0/CVE-2021-3019](https://github.com/B1anda0/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/B1anda0/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/B1anda0/CVE-2021-3019.svg)
- [https://github.com/murataydemir/CVE-2021-3019](https://github.com/murataydemir/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-3019.svg)


## CVE-2020-0136
 In multiple locations of Parcel.cpp, there is a possible out-of-bounds write due to an integer overflow. This could lead to local escalation of privilege in the system server with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-120078455

- [https://github.com/Satheesh575555/libhwbinder_AOSP10_r33_CVE-2020-0136](https://github.com/Satheesh575555/libhwbinder_AOSP10_r33_CVE-2020-0136) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/libhwbinder_AOSP10_r33_CVE-2020-0136.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/libhwbinder_AOSP10_r33_CVE-2020-0136.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation](https://github.com/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation) :  ![starts](https://img.shields.io/github/stars/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation.svg) ![forks](https://img.shields.io/github/forks/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/incogbyte/laravel-phpunit-rce-masscaner](https://github.com/incogbyte/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/incogbyte/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/incogbyte/laravel-phpunit-rce-masscaner.svg)
- [https://github.com/yoloskr/CVE-2017-9841-Scan](https://github.com/yoloskr/CVE-2017-9841-Scan) :  ![starts](https://img.shields.io/github/stars/yoloskr/CVE-2017-9841-Scan.svg) ![forks](https://img.shields.io/github/forks/yoloskr/CVE-2017-9841-Scan.svg)


## CVE-2014-3153
 The futex_requeue function in kernel/futex.c in the Linux kernel through 3.14.5 does not ensure that calls have two different futex addresses, which allows local users to gain privileges via a crafted FUTEX_REQUEUE command that facilitates unsafe waiter modification.

- [https://github.com/geekben/towelroot](https://github.com/geekben/towelroot) :  ![starts](https://img.shields.io/github/stars/geekben/towelroot.svg) ![forks](https://img.shields.io/github/forks/geekben/towelroot.svg)
- [https://github.com/c3c/CVE-2014-3153](https://github.com/c3c/CVE-2014-3153) :  ![starts](https://img.shields.io/github/stars/c3c/CVE-2014-3153.svg) ![forks](https://img.shields.io/github/forks/c3c/CVE-2014-3153.svg)

