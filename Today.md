# Update 2023-01-03
## CVE-2023-22551
 The FTP (aka &quot;Implementation of a simple FTP client and server&quot;) project through 96c1a35 allows remote attackers to cause a denial of service (memory consumption) by engaging in client activity, such as establishing and then terminating a connection. This occurs because malloc is used but free is not.

- [https://github.com/Live-Hack-CVE/CVE-2023-22551](https://github.com/Live-Hack-CVE/CVE-2023-22551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22551.svg)


## CVE-2023-0029
 A vulnerability was found in Multilaser RE708 RE1200R4GC-2T2R-V3_v3411b_MUL029B. It has been rated as problematic. This issue affects some unknown processing of the component Telnet Service. The manipulation leads to denial of service. The attack may be initiated remotely. The identifier VDB-217169 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0029](https://github.com/Live-Hack-CVE/CVE-2023-0029) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0029.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0029.svg)


## CVE-2022-48198
 The ntpd_driver component before 1.3.0 and 2.x before 2.2.0 for Robot Operating System (ROS) allows attackers, who control the source code of a different node in the same ROS application, to change a robot's behavior. This occurs because a topic name depends on the attacker-controlled time_ref_topic parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-48198](https://github.com/Live-Hack-CVE/CVE-2022-48198) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48198.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48198.svg)


## CVE-2022-47952
 lxc-user-nic in lxc through 5.0.1 is installed setuid root, and may allow local users to infer whether any file exists, even within a protected directory tree, because &quot;Failed to open&quot; often indicates that a file does not exist, whereas &quot;does not refer to a network namespace path&quot; often indicates that a file exists. NOTE: this is different from CVE-2018-6556 because the CVE-2018-6556 fix design was based on the premise that &quot;we will report back to the user that the open() failed but the user has no way of knowing why it failed&quot;; however, in many realistic cases, there are no plausible reasons for failing except that the file does not exist.

- [https://github.com/Live-Hack-CVE/CVE-2022-47952](https://github.com/Live-Hack-CVE/CVE-2022-47952) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47952.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47952.svg)


## CVE-2022-47634
 M-Link Archive Server in Isode M-Link R16.2v1 through R17.0 before R17.0v24 allows non-administrative users to access and manipulate archive data via certain HTTP endpoints, aka LINK-2867.

- [https://github.com/Live-Hack-CVE/CVE-2022-47634](https://github.com/Live-Hack-CVE/CVE-2022-47634) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47634.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47634.svg)


## CVE-2022-45213
 perfSONAR before 4.4.6 inadvertently supports the parse option for a file:// URL.

- [https://github.com/Live-Hack-CVE/CVE-2022-45213](https://github.com/Live-Hack-CVE/CVE-2022-45213) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45213.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45213.svg)


## CVE-2022-45027
 perfSONAR before 4.4.6, when performing participant discovery, incorrectly uses an HTTP request header value to determine a local address.

- [https://github.com/Live-Hack-CVE/CVE-2022-45027](https://github.com/Live-Hack-CVE/CVE-2022-45027) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45027.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45027.svg)


## CVE-2022-40711
 PrimeKey EJBCA 7.9.0.2 Community allows stored XSS in the End Entity section. A user with the RA Administrator role can inject an XSS payload to target higher-privilege users.

- [https://github.com/Live-Hack-CVE/CVE-2022-40711](https://github.com/Live-Hack-CVE/CVE-2022-40711) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40711.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40711.svg)


## CVE-2022-38223
 There is an out-of-bounds write in checkType located in etc.c in w3m 0.5.3. It can be triggered by sending a crafted HTML file to the w3m binary. It allows an attacker to cause Denial of Service or possibly have unspecified other impact.

- [https://github.com/Live-Hack-CVE/CVE-2022-38223](https://github.com/Live-Hack-CVE/CVE-2022-38223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38223.svg)


## CVE-2022-37787
 An issue was discovered in WeCube platform 3.2.2. A DOM XSS vulnerability has been found on the plugin database execution page.

- [https://github.com/Live-Hack-CVE/CVE-2022-37787](https://github.com/Live-Hack-CVE/CVE-2022-37787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37787.svg)


## CVE-2022-37786
 An issue was discovered in WeCube Platform 3.2.2. There are multiple CSV injection issues: the [Home / Admin / Resources] page, the [Home / Admin / System Params] page, and the [Home / Design / Basekey Configuration] page.

- [https://github.com/Live-Hack-CVE/CVE-2022-37786](https://github.com/Live-Hack-CVE/CVE-2022-37786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37786.svg)


## CVE-2022-37785
 An issue was discovered in WeCube Platform 3.2.2. Cleartext passwords are displayed in the configuration for terminal plugins.

- [https://github.com/Live-Hack-CVE/CVE-2022-37785](https://github.com/Live-Hack-CVE/CVE-2022-37785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37785.svg)


## CVE-2022-34324
 Multiple SQL injections in Sage XRT Business Exchange 12.4.302 allow an authenticated attacker to inject malicious data in SQL queries: Add Currencies, Payment Order, and Transfer History.

- [https://github.com/Live-Hack-CVE/CVE-2022-34324](https://github.com/Live-Hack-CVE/CVE-2022-34324) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34324.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34324.svg)


## CVE-2022-34323
 Multiple XSS issues were discovered in Sage XRT Business Exchange 12.4.302 that allow an attacker to execute JavaScript code in the context of other users' browsers. The attacker needs to be authenticated to reach the vulnerable features. An issue is present in the Filters and Display model features (OnlineBanking &gt; Web Monitoring &gt; Settings &gt; Filters / Display models). The name of a filter or a display model is interpreted as HTML and can thus embed JavaScript code, which is executed when displayed. This is a stored XSS. Another issue is present in the Notification feature (OnlineBanking &gt; Configuration &gt; Notifications and alerts &gt; Alerts *). The name of an alert is interpreted as HTML, and can thus embed JavaScript code, which is executed when displayed. This is a stored XSS. (Also, an issue is present in the File download feature, accessible via /OnlineBanking/cgi/isapi.dll/DOWNLOADFRS. When requesting to show the list of downloadable files, the contents of three form fields are embedded in the JavaScript code without prior sanitization. This is essentially a self-XSS.)

- [https://github.com/Live-Hack-CVE/CVE-2022-34323](https://github.com/Live-Hack-CVE/CVE-2022-34323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34323.svg)


## CVE-2022-34322
 Multiple XSS issues were discovered in Sage Enterprise Intelligence 2021 R1.1 that allow an attacker to execute JavaScript code in the context of users' browsers. The attacker needs to be authenticated to reach the vulnerable features. An issue is present in the Notify Users About Modification menu and the Notifications feature. A user can send malicious notifications and execute JavaScript code in the browser of every user who has enabled notifications. This is a stored XSS, and can lead to privilege escalation in the context of the application. (Another issue is present in the Favorites tab. The name of a favorite or a folder of favorites is interpreted as HTML, and can thus embed JavaScript code, which is executed when displayed. This is a self-XSS.)

- [https://github.com/Live-Hack-CVE/CVE-2022-34322](https://github.com/Live-Hack-CVE/CVE-2022-34322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34322.svg)


## CVE-2021-21366
 xmldom is a pure JavaScript W3C standard-based (XML DOM Level 2 Core) DOMParser and XMLSerializer module. xmldom versions 0.4.0 and older do not correctly preserve system identifiers, FPIs or namespaces when repeatedly parsing and serializing maliciously crafted documents. This may lead to unexpected syntactic changes during XML processing in some downstream applications. This is fixed in version 0.5.0. As a workaround downstream applications can validate the input and reject the maliciously crafted documents.

- [https://github.com/Live-Hack-CVE/CVE-2021-21366](https://github.com/Live-Hack-CVE/CVE-2021-21366) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21366.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21366.svg)


## CVE-2021-4297
 A vulnerability has been found in trampgeek jobe up to 1.6.4 and classified as problematic. This vulnerability affects the function runs_post of the file application/controllers/Restapi.php. The manipulation of the argument sourcefilename leads to an unknown weakness. Upgrading to version 1.6.5 is able to address this issue. The name of the patch is 694da5013dbecc8d30dd83e2a83e78faadf93771. It is recommended to upgrade the affected component. VDB-217174 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4297](https://github.com/Live-Hack-CVE/CVE-2021-4297) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4297.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4297.svg)


## CVE-2020-17382
 The MSI AmbientLink MsIo64 driver 1.0.0.8 has a Buffer Overflow (0x80102040, 0x80102044, 0x80102050,and 0x80102054).

- [https://github.com/houseofxyz/CVE-2020-17382](https://github.com/houseofxyz/CVE-2020-17382) :  ![starts](https://img.shields.io/github/stars/houseofxyz/CVE-2020-17382.svg) ![forks](https://img.shields.io/github/forks/houseofxyz/CVE-2020-17382.svg)


## CVE-2019-25093
 A vulnerability, which was classified as problematic, was found in dragonexpert Recent Threads on Index. Affected is the function recentthread_list_threads of the file inc/plugins/recentthreads/hooks.php of the component Setting Handler. The manipulation of the argument recentthread_forumskip leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is 051465d807a8fcc6a8b0f4bcbb19299672399f48. It is recommended to apply a patch to fix this issue. VDB-217182 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25093](https://github.com/Live-Hack-CVE/CVE-2019-25093) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25093.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25093.svg)


## CVE-2019-2022
 In rw_t3t_act_handle_fmt_rsp and rw_t3t_act_handle_sro_rsp of rw_t3t.cc, there is a possible out-of-bound read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-120506143

- [https://github.com/AhnSungHoon/Kali_CVE](https://github.com/AhnSungHoon/Kali_CVE) :  ![starts](https://img.shields.io/github/stars/AhnSungHoon/Kali_CVE.svg) ![forks](https://img.shields.io/github/forks/AhnSungHoon/Kali_CVE.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/philippedixon/CVE-2018-15473](https://github.com/philippedixon/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/philippedixon/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/philippedixon/CVE-2018-15473.svg)


## CVE-2018-6242
 Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.

- [https://github.com/rgisreventlov/Nephael-Nintendo-CVE-2018-6242](https://github.com/rgisreventlov/Nephael-Nintendo-CVE-2018-6242) :  ![starts](https://img.shields.io/github/stars/rgisreventlov/Nephael-Nintendo-CVE-2018-6242.svg) ![forks](https://img.shields.io/github/forks/rgisreventlov/Nephael-Nintendo-CVE-2018-6242.svg)


## CVE-2017-20161
 A vulnerability classified as problematic has been found in rofl0r MacGeiger. Affected is the function dump_wlan_at of the file macgeiger.c of the component ESSID Handler. The manipulation leads to injection. Access to the local network is required for this attack to succeed. The name of the patch is 57f1dd50a4821b8c8e676e8020006ae4bfd3c9cb. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217188.

- [https://github.com/Live-Hack-CVE/CVE-2017-20161](https://github.com/Live-Hack-CVE/CVE-2017-20161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20161.svg)


## CVE-2016-15006
 A vulnerability, which was classified as problematic, has been found in enigmaX up to 2.2. This issue affects the function getSeed of the file main.c of the component Scrambling Table Handler. The manipulation leads to predictable seed in pseudo-random number generator (prng). The attack may be initiated remotely. Upgrading to version 2.3 is able to address this issue. The name of the patch is 922bf90ca14a681629ba0b807a997a81d70225b5. It is recommended to upgrade the affected component. The identifier VDB-217181 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-15006](https://github.com/Live-Hack-CVE/CVE-2016-15006) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15006.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15006.svg)


## CVE-2015-10009
 A vulnerability was found in nterchange up to 4.1.0. It has been rated as critical. This issue affects the function getContent of the file app/controllers/code_caller_controller.php. The manipulation of the argument q with the input %5C%27%29;phpinfo%28%29;/* leads to code injection. The exploit has been disclosed to the public and may be used. Upgrading to version 4.1.1 is able to address this issue. The name of the patch is fba7d89176fba8fe289edd58835fe45080797d99. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217187.

- [https://github.com/Live-Hack-CVE/CVE-2015-10009](https://github.com/Live-Hack-CVE/CVE-2015-10009) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10009.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10009.svg)


## CVE-2015-10008
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in 82Flex WEIPDCRM. It has been classified as critical. This affects an unknown part. The manipulation leads to sql injection. It is possible to initiate the attack remotely. The name of the patch is 43bad79392332fa39e31b95268e76fbda9fec3a4. It is recommended to apply a patch to fix this issue. The identifier VDB-217185 was assigned to this vulnerability. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2015-10008](https://github.com/Live-Hack-CVE/CVE-2015-10008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10008.svg)


## CVE-2015-10007
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in 82Flex WEIPDCRM and classified as problematic. Affected by this issue is some unknown functionality. The manipulation leads to cross site scripting. The attack may be launched remotely. The name of the patch is 43bad79392332fa39e31b95268e76fbda9fec3a4. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217184. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2015-10007](https://github.com/Live-Hack-CVE/CVE-2015-10007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10007.svg)


## CVE-2014-125038
 A vulnerability has been found in IS_Projecto2 and classified as critical. This vulnerability affects unknown code of the file Cnn-EJB/ejbModule/ejbs/NewsBean.java. The manipulation of the argument date leads to sql injection. The name of the patch is aa128b2c9c9fdcbbf5ecd82c1e92103573017fe0. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217192.

- [https://github.com/Live-Hack-CVE/CVE-2014-125038](https://github.com/Live-Hack-CVE/CVE-2014-125038) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125038.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125038.svg)


## CVE-2014-125037
 A vulnerability, which was classified as critical, was found in License to Kill. This affects an unknown part of the file models/injury.rb. The manipulation of the argument name leads to sql injection. The name of the patch is cd11cf174f361c98e9b1b4c281aa7b77f46b5078. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217191.

- [https://github.com/Live-Hack-CVE/CVE-2014-125037](https://github.com/Live-Hack-CVE/CVE-2014-125037) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125037.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125037.svg)


## CVE-2014-125035
 A vulnerability classified as problematic was found in Jobs-Plugin. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross site scripting. The attack can be launched remotely. The name of the patch is b8a56718b1d42834c6ec51d9c489c5dc20471d7b. It is recommended to apply a patch to fix this issue. The identifier VDB-217189 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125035](https://github.com/Live-Hack-CVE/CVE-2014-125035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125035.svg)


## CVE-2014-125034
 A vulnerability has been found in stiiv contact_app and classified as problematic. Affected by this vulnerability is the function render of the file libs/View.php. The manipulation of the argument var leads to cross site scripting. The attack can be launched remotely. The name of the patch is 67bec33f559da9d41a1b45eb9e992bd8683a7f8c. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217183.

- [https://github.com/Live-Hack-CVE/CVE-2014-125034](https://github.com/Live-Hack-CVE/CVE-2014-125034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125034.svg)


## CVE-2014-125033
 A vulnerability was found in rails-cv-app. It has been rated as problematic. Affected by this issue is some unknown functionality of the file app/controllers/uploaded_files_controller.rb. The manipulation with the input ../../../etc/passwd leads to path traversal: '../filedir'. The exploit has been disclosed to the public and may be used. The name of the patch is 0d20362af0a5f8a126f67c77833868908484a863. It is recommended to apply a patch to fix this issue. VDB-217178 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125033](https://github.com/Live-Hack-CVE/CVE-2014-125033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125033.svg)


## CVE-2014-125032
 A vulnerability was found in porpeeranut go-with-me. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file module/frontend/add.php. The manipulation leads to sql injection. The name of the patch is b92451e4f9e85e26cf493c95ea0a69e354c35df9. It is recommended to apply a patch to fix this issue. The identifier VDB-217177 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125032](https://github.com/Live-Hack-CVE/CVE-2014-125032) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125032.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125032.svg)


## CVE-2014-125031
 A vulnerability was found in kirill2485 TekNet. It has been classified as problematic. Affected is an unknown function of the file pages/loggedin.php. The manipulation of the argument statusentery leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is 1c575340539f983333aa43fc58ecd76eb53e1816. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217176.

- [https://github.com/Live-Hack-CVE/CVE-2014-125031](https://github.com/Live-Hack-CVE/CVE-2014-125031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125031.svg)

