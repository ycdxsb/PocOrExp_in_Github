# Update 2023-02-20
## CVE-2023-24809
 NetHack is a single player dungeon exploration game. Starting with version 3.6.2 and prior to version 3.6.7, illegal input to the &quot;C&quot; (call) command can cause a buffer overflow and crash the NetHack process. This vulnerability may be a security issue for systems that have NetHack installed suid/sgid and for shared systems. For all systems, it may result in a process crash. This issue is resolved in NetHack 3.6.7. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-24809](https://github.com/Live-Hack-CVE/CVE-2023-24809) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24809.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24809.svg)


## CVE-2023-24348
 D-Link N300 WI-FI Router DIR-605L v2.13B01 was discovered to contain a stack overflow via the curTime parameter at /goform/formSetACLFilter.

- [https://github.com/Live-Hack-CVE/CVE-2023-24348](https://github.com/Live-Hack-CVE/CVE-2023-24348) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24348.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24348.svg)


## CVE-2023-23923
 The vulnerability was found Moodle which exists due to insufficient limitations on the &quot;start page&quot; preference. A remote attacker can set that preference for another user. The vulnerability allows a remote attacker to gain unauthorized access to otherwise restricted functionality.

- [https://github.com/Live-Hack-CVE/CVE-2023-23923](https://github.com/Live-Hack-CVE/CVE-2023-23923) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23923.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23923.svg)


## CVE-2023-23922
 The vulnerability was found Moodle which exists due to insufficient sanitization of user-supplied data in blog search. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website. This flaw allows a remote attacker to perform cross-site scripting (XSS) attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-23922](https://github.com/Live-Hack-CVE/CVE-2023-23922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23922.svg)


## CVE-2023-23921
 The vulnerability was found Moodle which exists due to insufficient sanitization of user-supplied data in some returnurl parameters. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website. This flaw allows a remote attacker to perform cross-site scripting (XSS) attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-23921](https://github.com/Live-Hack-CVE/CVE-2023-23921) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23921.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23921.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/Saboor-Hakimi/CVE-2023-23752](https://github.com/Saboor-Hakimi/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/Saboor-Hakimi/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/Saboor-Hakimi/CVE-2023-23752.svg)
- [https://github.com/WhiteOwl-Pub/CVE-2023-23752](https://github.com/WhiteOwl-Pub/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/WhiteOwl-Pub/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/WhiteOwl-Pub/CVE-2023-23752.svg)


## CVE-2023-23695
 Dell Secure Connect Gateway (SCG) version 5.14.00.12 contains a broken cryptographic algorithm vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability by performing MitM attacks and let attackers obtain sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2023-23695](https://github.com/Live-Hack-CVE/CVE-2023-23695) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23695.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23695.svg)


## CVE-2023-23586
 Due to a vulnerability in the io_uring subsystem, it is possible to leak kernel memory information to the user process. timens_install calls current_is_single_threaded to determine if the current process is single-threaded, but this call does not consider io_uring's io_worker threads, thus it is possible to insert a time namespace's vvar page to process's memory space via a page fault. When this time namespace is destroyed, the vvar page is also freed, but not removed from the process' memory, and a next page allocated by the kernel will be still available from the user-space process and can leak memory contents via this (read-only) use-after-free vulnerability. We recommend upgrading past version 5.10.161 or commit 788d0824269bef539fe31a785b1517882eafed93 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/io_uring

- [https://github.com/Live-Hack-CVE/CVE-2023-23586](https://github.com/Live-Hack-CVE/CVE-2023-23586) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23586.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23586.svg)


## CVE-2023-23007
 An issue was discovered in ESPCMS P8.21120101 after logging in to the background, there is a SQL injection vulnerability in the function node where members are added.

- [https://github.com/Live-Hack-CVE/CVE-2023-23007](https://github.com/Live-Hack-CVE/CVE-2023-23007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23007.svg)


## CVE-2023-22243
 Adobe Animate versions 22.0.8 (and earlier) and 23.0.0 (and earlier) are affected by a Stack-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-22243](https://github.com/Live-Hack-CVE/CVE-2023-22243) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22243.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22243.svg)


## CVE-2023-22238
 After Affects versions 23.1 (and earlier), 22.6.3 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-22238](https://github.com/Live-Hack-CVE/CVE-2023-22238) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22238.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22238.svg)


## CVE-2023-22237
 After Affects versions 23.1 (and earlier), 22.6.3 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-22237](https://github.com/Live-Hack-CVE/CVE-2023-22237) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22237.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22237.svg)


## CVE-2023-22236
 Adobe Animate versions 22.0.8 (and earlier) and 23.0.0 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-22236](https://github.com/Live-Hack-CVE/CVE-2023-22236) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22236.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22236.svg)


## CVE-2023-21754
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)


## CVE-2023-21583
 Adobe Bridge versions 12.0.3 (and earlier) and 13.0.1 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-21583](https://github.com/Live-Hack-CVE/CVE-2023-21583) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21583.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21583.svg)


## CVE-2023-21578
 Photoshop version 23.5.3 (and earlier), 24.1 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-21578](https://github.com/Live-Hack-CVE/CVE-2023-21578) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21578.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21578.svg)


## CVE-2023-21577
 Photoshop version 23.5.3 (and earlier), 24.1 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2023-21577](https://github.com/Live-Hack-CVE/CVE-2023-21577) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21577.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21577.svg)


## CVE-2023-21434
 Improper input validation vulnerability in Galaxy Store prior to version 4.5.49.8 allows local attackers to execute JavaScript by launching a web page.

- [https://github.com/Live-Hack-CVE/CVE-2023-21434](https://github.com/Live-Hack-CVE/CVE-2023-21434) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21434.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21434.svg)


## CVE-2023-0901
 Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository pixelfed/pixelfed prior to 0.11.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0901](https://github.com/Live-Hack-CVE/CVE-2023-0901) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0901.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0901.svg)


## CVE-2023-0878
 Cross-site Scripting (XSS) - Generic in GitHub repository nuxt/framework prior to 3.2.1.

- [https://github.com/Live-Hack-CVE/CVE-2023-0878](https://github.com/Live-Hack-CVE/CVE-2023-0878) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0878.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0878.svg)


## CVE-2023-0877
 Code Injection in GitHub repository froxlor/froxlor prior to 2.0.11.

- [https://github.com/Live-Hack-CVE/CVE-2023-0877](https://github.com/Live-Hack-CVE/CVE-2023-0877) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0877.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0877.svg)


## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.

- [https://github.com/yosef0x01/CVE-2023-0669](https://github.com/yosef0x01/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2023-0669.svg)


## CVE-2023-0575
 External Control of Critical State Data, Improper Control of Generation of Code ('Code Injection') vulnerability in YugaByte, Inc. Yugabyte DB on Windows, Linux, MacOS, iOS (DevopsBase.Java:execCommand, TableManager.Java:runCommand modules) allows API Manipulation, Privilege Abuse. This vulnerability is associated with program files backup.Py. This issue affects Yugabyte DB: Lesser then 2.2.

- [https://github.com/Live-Hack-CVE/CVE-2023-0575](https://github.com/Live-Hack-CVE/CVE-2023-0575) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0575.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0575.svg)


## CVE-2023-0482
 In RESTEasy the insecure File.createTempFile() is used in the DataSourceProvider, FileProvider and Mime4JWorkaround classes which creates temp files with insecure permissions that could be read by a local user.

- [https://github.com/Live-Hack-CVE/CVE-2023-0482](https://github.com/Live-Hack-CVE/CVE-2023-0482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0482.svg)


## CVE-2022-32132
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/reewardius/CVE-2022-32132](https://github.com/reewardius/CVE-2022-32132) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2022-32132.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2022-32132.svg)


## CVE-2022-32074
 A stored cross-site scripting (XSS) vulnerability in the component audit/class.audit.php of osTicket-plugins - Storage-FS before commit a7842d494889fd5533d13deb3c6a7789768795ae allows attackers to execute arbitrary web scripts or HTML via a crafted SVG file.

- [https://github.com/reewardius/CVE-2022-32074](https://github.com/reewardius/CVE-2022-32074) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2022-32074.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2022-32074.svg)


## CVE-2022-31890
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/reewardius/CVE-2022-31890](https://github.com/reewardius/CVE-2022-31890) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2022-31890.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2022-31890.svg)


## CVE-2022-31889
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/reewardius/CVE-2022-31889](https://github.com/reewardius/CVE-2022-31889) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2022-31889.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2022-31889.svg)


## CVE-2022-26580
 PAX Technology A930 PayDroid 7.1.1 Virgo V04.4.02 20211201 was discovered to be vulnerable to command injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-26580](https://github.com/Live-Hack-CVE/CVE-2022-26580) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26580.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26580.svg)


## CVE-2022-20578
 In RadioImpl::setGsmBroadcastConfig of ril_service_legacy.cpp, there is a possible stack clash leading to memory corruption. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-243509749References: N/A

- [https://github.com/Live-Hack-CVE/CVE-2022-20578](https://github.com/Live-Hack-CVE/CVE-2022-20578) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20578.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20578.svg)


## CVE-2022-3348
 Just like in the previous report, an attacker could steal the account of different users. But in this case, it's a little bit more specific, because it is needed to be an editor in the same app as the victim.

- [https://github.com/Live-Hack-CVE/CVE-2022-3348](https://github.com/Live-Hack-CVE/CVE-2022-3348) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3348.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3348.svg)


## CVE-2022-2463
 Rockwell Automation ISaGRAF Workbench software versions 6.0 through 6.6.9 are affected by a Path Traversal vulnerability. A crafted malicious .7z exchange file may allow an attacker to gain the privileges of the ISaGRAF Workbench software when opened. If the software is running at the SYSTEM level, then the attacker will gain admin level privileges. User interaction is required for this exploit to be successful.

- [https://github.com/Live-Hack-CVE/CVE-2022-2463](https://github.com/Live-Hack-CVE/CVE-2022-2463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2463.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/ElGanz0/CVE-2022-0739](https://github.com/ElGanz0/CVE-2022-0739) :  ![starts](https://img.shields.io/github/stars/ElGanz0/CVE-2022-0739.svg) ![forks](https://img.shields.io/github/forks/ElGanz0/CVE-2022-0739.svg)


## CVE-2022-0492
 A vulnerability was found in the Linux kernel&#8217;s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- [https://github.com/T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC](https://github.com/T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC) :  ![starts](https://img.shields.io/github/stars/T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC.svg) ![forks](https://img.shields.io/github/forks/T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/jm33-m0/CVE-2021-3156](https://github.com/jm33-m0/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/jm33-m0/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/CVE-2021-3156.svg)
- [https://github.com/freeFV/CVE-2021-3156](https://github.com/freeFV/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/freeFV/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/freeFV/CVE-2021-3156.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/milo2012/CVE-2020-14882](https://github.com/milo2012/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/milo2012/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/milo2012/CVE-2020-14882.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/RicYaben/CVE-2020-1472-LAB](https://github.com/RicYaben/CVE-2020-1472-LAB) :  ![starts](https://img.shields.io/github/stars/RicYaben/CVE-2020-1472-LAB.svg) ![forks](https://img.shields.io/github/forks/RicYaben/CVE-2020-1472-LAB.svg)


## CVE-2019-15514
 The Privacy &gt; Phone Number feature in the Telegram app 5.10 for Android and iOS provides an incorrect indication that the access level is Nobody, because attackers can find these numbers via the Group Info feature, e.g., by adding a significant fraction of a region's assigned phone numbers.

- [https://github.com/bibi1959/CVE-2019-15514](https://github.com/bibi1959/CVE-2019-15514) :  ![starts](https://img.shields.io/github/stars/bibi1959/CVE-2019-15514.svg) ![forks](https://img.shields.io/github/forks/bibi1959/CVE-2019-15514.svg)

