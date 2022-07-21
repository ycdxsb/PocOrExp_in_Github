# Update 2022-07-21
## CVE-2022-35899
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AngeloPioAmirante/CVE-2022-35899](https://github.com/AngeloPioAmirante/CVE-2022-35899) :  ![starts](https://img.shields.io/github/stars/AngeloPioAmirante/CVE-2022-35899.svg) ![forks](https://img.shields.io/github/forks/AngeloPioAmirante/CVE-2022-35899.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/west-wind/CVE-2022-33891](https://github.com/west-wind/CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/west-wind/CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/west-wind/CVE-2022-33891.svg)
- [https://github.com/HuskyHacks/cve-2022-33891](https://github.com/HuskyHacks/cve-2022-33891) :  ![starts](https://img.shields.io/github/stars/HuskyHacks/cve-2022-33891.svg) ![forks](https://img.shields.io/github/forks/HuskyHacks/cve-2022-33891.svg)


## CVE-2022-29455
 DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.

- [https://github.com/alirezasalehizadeh/cve-2022-29455](https://github.com/alirezasalehizadeh/cve-2022-29455) :  ![starts](https://img.shields.io/github/stars/alirezasalehizadeh/cve-2022-29455.svg) ![forks](https://img.shields.io/github/forks/alirezasalehizadeh/cve-2022-29455.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/cybersecurityresearcher/CVE-2022-26809-RCE-POC](https://github.com/cybersecurityresearcher/CVE-2022-26809-RCE-POC) :  ![starts](https://img.shields.io/github/stars/cybersecurityresearcher/CVE-2022-26809-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/cybersecurityresearcher/CVE-2022-26809-RCE-POC.svg)


## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42278, CVE-2021-42282, CVE-2021-42291.

- [https://github.com/IAMinZoho/sAMAccountName-Spoofing](https://github.com/IAMinZoho/sAMAccountName-Spoofing) :  ![starts](https://img.shields.io/github/stars/IAMinZoho/sAMAccountName-Spoofing.svg) ![forks](https://img.shields.io/github/forks/IAMinZoho/sAMAccountName-Spoofing.svg)


## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42282, CVE-2021-42287, CVE-2021-42291.

- [https://github.com/IAMinZoho/sAMAccountName-Spoofing](https://github.com/IAMinZoho/sAMAccountName-Spoofing) :  ![starts](https://img.shields.io/github/stars/IAMinZoho/sAMAccountName-Spoofing.svg) ![forks](https://img.shields.io/github/forks/IAMinZoho/sAMAccountName-Spoofing.svg)


## CVE-2021-41073
 loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by using /proc/&lt;pid&gt;/maps for exploitation.

- [https://github.com/abhyanandsharma311099/cve2021-41073](https://github.com/abhyanandsharma311099/cve2021-41073) :  ![starts](https://img.shields.io/github/stars/abhyanandsharma311099/cve2021-41073.svg) ![forks](https://img.shields.io/github/forks/abhyanandsharma311099/cve2021-41073.svg)


## CVE-2021-20233
 A flaw was found in grub2 in versions prior to 2.06. Setparam_prefix() in the menu rendering code performs a length calculation on the assumption that expressing a quoted single quote will require 3 characters, while it actually requires 4 characters which allows an attacker to corrupt memory by one byte for each quote in the input. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/pauljrowland/BootHoleFix](https://github.com/pauljrowland/BootHoleFix) :  ![starts](https://img.shields.io/github/stars/pauljrowland/BootHoleFix.svg) ![forks](https://img.shields.io/github/forks/pauljrowland/BootHoleFix.svg)


## CVE-2020-25632
 A flaw was found in grub2 in versions prior to 2.06. The rmmod implementation allows the unloading of a module used as a dependency without checking if any other dependent module is still loaded leading to a use-after-free scenario. This could allow arbitrary code to be executed or a bypass of Secure Boot protections. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/pauljrowland/BootHoleFix](https://github.com/pauljrowland/BootHoleFix) :  ![starts](https://img.shields.io/github/stars/pauljrowland/BootHoleFix.svg) ![forks](https://img.shields.io/github/forks/pauljrowland/BootHoleFix.svg)


## CVE-2020-0188
 In onCreatePermissionRequest of SettingsSliceProvider.java, there is a possible permissions bypass due to a PendingIntent error. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-147355897

- [https://github.com/Nivaskumark/packages_apps_Settings_CVE-2020-0188_A10_R33](https://github.com/Nivaskumark/packages_apps_Settings_CVE-2020-0188_A10_R33) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/packages_apps_Settings_CVE-2020-0188_A10_R33.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/packages_apps_Settings_CVE-2020-0188_A10_R33.svg)


## CVE-2019-17621
 The UPnP endpoint URL /gena.cgi in the D-Link DIR-859 Wi-Fi router 1.05 and 1.06B01 Beta01 allows an Unauthenticated remote attacker to execute system commands as root, by sending a specially crafted HTTP SUBSCRIBE request to the UPnP service when connecting to the local network.

- [https://github.com/Ler2sq/CVE-2019-17621](https://github.com/Ler2sq/CVE-2019-17621) :  ![starts](https://img.shields.io/github/stars/Ler2sq/CVE-2019-17621.svg) ![forks](https://img.shields.io/github/forks/Ler2sq/CVE-2019-17621.svg)


## CVE-2019-8985
 On Netis WF2411 with firmware 2.1.36123 and other Netis WF2xxx devices (possibly WF2411 through WF2880), there is a stack-based buffer overflow that does not require authentication. This can cause denial of service (device restart) or remote code execution. This vulnerability can be triggered by a GET request with a long HTTP &quot;Authorization: Basic&quot; header that is mishandled by user_auth-&gt;user_ok in /bin/boa.

- [https://github.com/Ler2sq/CVE-2019-8985](https://github.com/Ler2sq/CVE-2019-8985) :  ![starts](https://img.shields.io/github/stars/Ler2sq/CVE-2019-8985.svg) ![forks](https://img.shields.io/github/forks/Ler2sq/CVE-2019-8985.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/201646613/CVE-2017-7921](https://github.com/201646613/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/201646613/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/201646613/CVE-2017-7921.svg)


## CVE-2014-7921
 mediaserver in Android 4.0.3 through 5.x before 5.1 allows attackers to gain privileges.  NOTE: This is a different vulnerability than CVE-2014-7920.

- [https://github.com/laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921) :  ![starts](https://img.shields.io/github/stars/laginimaineb/cve-2014-7920-7921.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/cve-2014-7920-7921.svg)


## CVE-2014-7920
 mediaserver in Android 2.2 through 5.x before 5.1 allows attackers to gain privileges.  NOTE: This is a different vulnerability than CVE-2014-7921.

- [https://github.com/laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921) :  ![starts](https://img.shields.io/github/stars/laginimaineb/cve-2014-7920-7921.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/cve-2014-7920-7921.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/mr-l0n3lly/CVE-2007-2447](https://github.com/mr-l0n3lly/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/mr-l0n3lly/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/mr-l0n3lly/CVE-2007-2447.svg)

