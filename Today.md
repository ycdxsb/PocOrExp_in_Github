# Update 2022-04-20
## CVE-2022-29072
 7-Zip through 21.07 on Windows allows privilege escalation and command execution when a file with the .7z extension is dragged to the Help&gt;Contents area. This is caused by misconfiguration of 7z.dll and a heap overflow. The command runs in a child process under the 7zFM.exe process,

- [https://github.com/tiktb8/CVE-2022-29072](https://github.com/tiktb8/CVE-2022-29072) :  ![starts](https://img.shields.io/github/stars/tiktb8/CVE-2022-29072.svg) ![forks](https://img.shields.io/github/forks/tiktb8/CVE-2022-29072.svg)
- [https://github.com/sentinelblue/CVE-2022-29072](https://github.com/sentinelblue/CVE-2022-29072) :  ![starts](https://img.shields.io/github/stars/sentinelblue/CVE-2022-29072.svg) ![forks](https://img.shields.io/github/forks/sentinelblue/CVE-2022-29072.svg)


## CVE-2022-27772
 ** UNSUPPORTED WHEN ASSIGNED ** spring-boot versions prior to version v2.2.11.RELEASE was vulnerable to temporary directory hijacking. This vulnerability impacted the org.springframework.boot.web.server.AbstractConfigurableWebServerFactory.createTempDir method. NOTE: This vulnerability only affects products and/or versions that are no longer supported by the maintainer.

- [https://github.com/puneetbehl/grails3-cve-2022-27772](https://github.com/puneetbehl/grails3-cve-2022-27772) :  ![starts](https://img.shields.io/github/stars/puneetbehl/grails3-cve-2022-27772.svg) ![forks](https://img.shields.io/github/forks/puneetbehl/grails3-cve-2022-27772.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/HellKnightsCrew/CVE-2022-26809](https://github.com/HellKnightsCrew/CVE-2022-26809) :  ![starts](https://img.shields.io/github/stars/HellKnightsCrew/CVE-2022-26809.svg) ![forks](https://img.shields.io/github/forks/HellKnightsCrew/CVE-2022-26809.svg)
- [https://github.com/hemazoher/CVE-2022-26809-RCE](https://github.com/hemazoher/CVE-2022-26809-RCE) :  ![starts](https://img.shields.io/github/stars/hemazoher/CVE-2022-26809-RCE.svg) ![forks](https://img.shields.io/github/forks/hemazoher/CVE-2022-26809-RCE.svg)


## CVE-2022-26318
 On WatchGuard Firebox and XTM appliances, an unauthenticated user can execute arbitrary code, aka FBX-22786. This vulnerability impacts Fireware OS before 12.7.2_U2, 12.x before 12.1.3_U8, and 12.2.x through 12.5.x before 12.5.9_U2.

- [https://github.com/h3llk4t3/Watchguard-RCE-POC-CVE-2022-26318](https://github.com/h3llk4t3/Watchguard-RCE-POC-CVE-2022-26318) :  ![starts](https://img.shields.io/github/stars/h3llk4t3/Watchguard-RCE-POC-CVE-2022-26318.svg) ![forks](https://img.shields.io/github/forks/h3llk4t3/Watchguard-RCE-POC-CVE-2022-26318.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/jkakavas/CVE-2022-0778-POC](https://github.com/jkakavas/CVE-2022-0778-POC) :  ![starts](https://img.shields.io/github/stars/jkakavas/CVE-2022-0778-POC.svg) ![forks](https://img.shields.io/github/forks/jkakavas/CVE-2022-0778-POC.svg)


## CVE-2021-44255
 Authenticated remote code execution in MotionEye &lt;= 0.42.1 and MotioneEyeOS &lt;= 20200606 allows a remote attacker to upload a configuration backup file containing a malicious python pickle file which will execute arbitrary code on the server.

- [https://github.com/pizza-power/motioneye-authenticated-RCE](https://github.com/pizza-power/motioneye-authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/pizza-power/motioneye-authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/pizza-power/motioneye-authenticated-RCE.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/rexpository/linux-privilege-escalation](https://github.com/rexpository/linux-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/rexpository/linux-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/rexpository/linux-privilege-escalation.svg)


## CVE-2021-0705
 In sanitizeSbn of NotificationManagerService.java, there is a possible way to keep service running in foreground and keep granted permissions due to Bypass of Background Service Restrictions. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-10Android ID: A-185388103

- [https://github.com/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-0705](https://github.com/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-0705) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-0705.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-0705.svg)


## CVE-2021-0594
 In onCreate of ConfirmConnectActivity, there is a possible remote bypass of user consent due to improper input validation. This could lead to remote (proximal, NFC) escalation of privilege allowing an attacker to deceive a user into allowing a Bluetooth connection with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-176445224

- [https://github.com/Satheesh575555/packages_apps_Nfc_AOSP10_r33_CVE-2021-0594](https://github.com/Satheesh575555/packages_apps_Nfc_AOSP10_r33_CVE-2021-0594) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Nfc_AOSP10_r33_CVE-2021-0594.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Nfc_AOSP10_r33_CVE-2021-0594.svg)


## CVE-2021-0478
 In updateDrawable of StatusBarIconView.java, there is a possible permission bypass due to an uncaught exception. This could lead to local escalation of privilege by running foreground services without notifying the user, with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-169255797

- [https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0478](https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0478) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0478.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0478.svg)


## CVE-2021-0319
 In checkCallerIsSystemOr of CompanionDeviceManagerService.java, there is a possible way to get a nearby Bluetooth device's MAC address without appropriate permissions due to a permissions bypass. This could lead to local escalation of privilege that grants access to nearby MAC addresses, with User execution privileges needed. User interaction is needed for exploitation. Product: Android; Versions: Android-8.0, Android-8.1, Android-9, Android-10, Android-11; Android ID: A-167244818.

- [https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0319](https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0319) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0319.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0319.svg)


## CVE-2020-14343
 A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.

- [https://github.com/j4k0m/loader-CVE-2020-14343](https://github.com/j4k0m/loader-CVE-2020-14343) :  ![starts](https://img.shields.io/github/stars/j4k0m/loader-CVE-2020-14343.svg) ![forks](https://img.shields.io/github/forks/j4k0m/loader-CVE-2020-14343.svg)


## CVE-2020-0226
 In createWithSurfaceParent of Client.cpp, there is a possible out of bounds write due to type confusion. This could lead to local escalation of privilege in the graphics server with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-150226994

- [https://github.com/ShaikUsaf/frameworks_native_AOSP10_r33_ShaikUsaf-frameworks_native_AOSP10_r33_CVE-2020-0226](https://github.com/ShaikUsaf/frameworks_native_AOSP10_r33_ShaikUsaf-frameworks_native_AOSP10_r33_CVE-2020-0226) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/frameworks_native_AOSP10_r33_ShaikUsaf-frameworks_native_AOSP10_r33_CVE-2020-0226.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/frameworks_native_AOSP10_r33_ShaikUsaf-frameworks_native_AOSP10_r33_CVE-2020-0226.svg)


## CVE-2020-0219
 In onCreate of SliceDeepLinkSpringBoard.java there is a possible insecure Intent. This could lead to local elevation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-122836081

- [https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0219](https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0219) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0219.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0219.svg)


## CVE-2018-6481
 A buffer overflow vulnerability in the control protocol of Disk Savvy Enterprise v10.4.18 allows remote attackers to execute arbitrary code by sending a crafted packet to TCP port 9124.

- [https://github.com/gerbsec/CVE-2018-6481-Reverse-shell-instead-of-bind.](https://github.com/gerbsec/CVE-2018-6481-Reverse-shell-instead-of-bind.) :  ![starts](https://img.shields.io/github/stars/gerbsec/CVE-2018-6481-Reverse-shell-instead-of-bind..svg) ![forks](https://img.shields.io/github/forks/gerbsec/CVE-2018-6481-Reverse-shell-instead-of-bind..svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/ThanHuuTuan/CVE-2017-7269](https://github.com/ThanHuuTuan/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/ThanHuuTuan/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/ThanHuuTuan/CVE-2017-7269.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/SkinAir/ms15-034-Scan](https://github.com/SkinAir/ms15-034-Scan) :  ![starts](https://img.shields.io/github/stars/SkinAir/ms15-034-Scan.svg) ![forks](https://img.shields.io/github/forks/SkinAir/ms15-034-Scan.svg)

