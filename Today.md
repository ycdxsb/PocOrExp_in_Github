# Update 2023-12-27
## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/Le1a/CVE-2023-51385](https://github.com/Le1a/CVE-2023-51385) :  ![starts](https://img.shields.io/github/stars/Le1a/CVE-2023-51385.svg) ![forks](https://img.shields.io/github/forks/Le1a/CVE-2023-51385.svg)
- [https://github.com/watarium/poc-cve-2023-51385](https://github.com/watarium/poc-cve-2023-51385) :  ![starts](https://img.shields.io/github/stars/watarium/poc-cve-2023-51385.svg) ![forks](https://img.shields.io/github/forks/watarium/poc-cve-2023-51385.svg)
- [https://github.com/zls1793/CVE-2023-51385_test](https://github.com/zls1793/CVE-2023-51385_test) :  ![starts](https://img.shields.io/github/stars/zls1793/CVE-2023-51385_test.svg) ![forks](https://img.shields.io/github/forks/zls1793/CVE-2023-51385_test.svg)
- [https://github.com/Tachanka-zz/CVE-2023-51385_test](https://github.com/Tachanka-zz/CVE-2023-51385_test) :  ![starts](https://img.shields.io/github/stars/Tachanka-zz/CVE-2023-51385_test.svg) ![forks](https://img.shields.io/github/forks/Tachanka-zz/CVE-2023-51385_test.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/r1yaz/winDED](https://github.com/r1yaz/winDED) :  ![starts](https://img.shields.io/github/stars/r1yaz/winDED.svg) ![forks](https://img.shields.io/github/forks/r1yaz/winDED.svg)


## CVE-2023-32314
 vm2 is a sandbox that can run untrusted code with Node's built-in modules. A sandbox escape vulnerability exists in vm2 for versions up to and including 3.9.17. It abuses an unexpected creation of a host object based on the specification of `Proxy`. As a result a threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version `3.9.18` of `vm2`. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/giovanni-iannaccone/vm2_3.9.17](https://github.com/giovanni-iannaccone/vm2_3.9.17) :  ![starts](https://img.shields.io/github/stars/giovanni-iannaccone/vm2_3.9.17.svg) ![forks](https://img.shields.io/github/forks/giovanni-iannaccone/vm2_3.9.17.svg)


## CVE-2023-29325
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/a-bazi/test-CVE-2023-29325](https://github.com/a-bazi/test-CVE-2023-29325) :  ![starts](https://img.shields.io/github/stars/a-bazi/test-CVE-2023-29325.svg) ![forks](https://img.shields.io/github/forks/a-bazi/test-CVE-2023-29325.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/imancybersecurity/CVE-2023-27350-POC](https://github.com/imancybersecurity/CVE-2023-27350-POC) :  ![starts](https://img.shields.io/github/stars/imancybersecurity/CVE-2023-27350-POC.svg) ![forks](https://img.shields.io/github/forks/imancybersecurity/CVE-2023-27350-POC.svg)


## CVE-2023-6710
 A flaw was found in the mod_proxy_cluster in the Apache server. This issue may allow a malicious user to add a script in the 'alias' parameter in the URL to trigger the stored cross-site scripting (XSS) vulnerability. By adding a script on the alias parameter on the URL, it adds a new virtual host and adds the script to the cluster-manager page. The impact of this vulnerability is considered as Low, as the cluster_manager URL should not be exposed outside and is protected by user/password.

- [https://github.com/DedSec-47/CVE-2023-6710](https://github.com/DedSec-47/CVE-2023-6710) :  ![starts](https://img.shields.io/github/stars/DedSec-47/CVE-2023-6710.svg) ![forks](https://img.shields.io/github/forks/DedSec-47/CVE-2023-6710.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/leesh3288/CVE-2023-4911](https://github.com/leesh3288/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/leesh3288/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/leesh3288/CVE-2023-4911.svg)
- [https://github.com/hadrian3689/looney-tunables-CVE-2023-4911](https://github.com/hadrian3689/looney-tunables-CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/hadrian3689/looney-tunables-CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/looney-tunables-CVE-2023-4911.svg)


## CVE-2022-28117
 A Server-Side Request Forgery (SSRF) in feed_parser class of Navigate CMS v2.9.4 allows remote attackers to force the application to make arbitrary requests via injection of arbitrary URLs into the feed parameter.

- [https://github.com/kimstars/POC-CVE-2022-28117](https://github.com/kimstars/POC-CVE-2022-28117) :  ![starts](https://img.shields.io/github/stars/kimstars/POC-CVE-2022-28117.svg) ![forks](https://img.shields.io/github/forks/kimstars/POC-CVE-2022-28117.svg)


## CVE-2021-39704
 In deleteNotificationChannelGroup of NotificationManagerService.java, there is a possible way to run foreground service without user notification due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12Android ID: A-209965481

- [https://github.com/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704](https://github.com/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704) :  ![starts](https://img.shields.io/github/stars/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704.svg) ![forks](https://img.shields.io/github/forks/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/vlrhsgody/CVE-2021-22911](https://github.com/vlrhsgody/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/vlrhsgody/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/vlrhsgody/CVE-2021-22911.svg)


## CVE-2021-21983
 Arbitrary file write vulnerability in vRealize Operations Manager API (CVE-2021-21983) prior to 8.4 may allow an authenticated malicious actor with network access to the vRealize Operations Manager API can write files to arbitrary locations on the underlying photon operating system.

- [https://github.com/murataydemir/CVE-2021-21983](https://github.com/murataydemir/CVE-2021-21983) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-21983.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-21983.svg)


## CVE-2021-4428
 A vulnerability has been found in what3words Autosuggest Plugin up to 4.0.0 on WordPress and classified as problematic. Affected by this vulnerability is the function enqueue_scripts of the file w3w-autosuggest/public/class-w3w-autosuggest-public.php of the component Setting Handler. The manipulation leads to information disclosure. The attack can be launched remotely. Upgrading to version 4.0.1 is able to address this issue. The patch is named dd59cbac5f86057d6a73b87007c08b8bfa0c32ac. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-234247.

- [https://github.com/lov3r/cve-2021-44228-log4j-exploits](https://github.com/lov3r/cve-2021-44228-log4j-exploits) :  ![starts](https://img.shields.io/github/stars/lov3r/cve-2021-44228-log4j-exploits.svg) ![forks](https://img.shields.io/github/forks/lov3r/cve-2021-44228-log4j-exploits.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/B3nj4h/CVE-2021-4045](https://github.com/B3nj4h/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/B3nj4h/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/B3nj4h/CVE-2021-4045.svg)


## CVE-2019-16920
 Unauthenticated remote code execution occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends an arbitrary input to a &quot;PingTest&quot; device common gateway interface that could lead to common injection. An attacker who successfully triggers the command injection could achieve full system compromise. Later, it was independently found that these are also affected: DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.

- [https://github.com/eniac888/CVE-2019-16920-MassPwn3r](https://github.com/eniac888/CVE-2019-16920-MassPwn3r) :  ![starts](https://img.shields.io/github/stars/eniac888/CVE-2019-16920-MassPwn3r.svg) ![forks](https://img.shields.io/github/forks/eniac888/CVE-2019-16920-MassPwn3r.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/tannlh/CVE-2018-20250](https://github.com/tannlh/CVE-2018-20250) :  ![starts](https://img.shields.io/github/stars/tannlh/CVE-2018-20250.svg) ![forks](https://img.shields.io/github/forks/tannlh/CVE-2018-20250.svg)


## CVE-2018-18387
 playSMS through 1.4.2 allows Privilege Escalation through Daemon abuse.

- [https://github.com/TheeBlind/CVE-2018-18387](https://github.com/TheeBlind/CVE-2018-18387) :  ![starts](https://img.shields.io/github/stars/TheeBlind/CVE-2018-18387.svg) ![forks](https://img.shields.io/github/forks/TheeBlind/CVE-2018-18387.svg)


## CVE-2015-6086
 Microsoft Internet Explorer 9 through 11 allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka &quot;Internet Explorer Information Disclosure Vulnerability.&quot;

- [https://github.com/payatu/CVE-2015-6086](https://github.com/payatu/CVE-2015-6086) :  ![starts](https://img.shields.io/github/stars/payatu/CVE-2015-6086.svg) ![forks](https://img.shields.io/github/forks/payatu/CVE-2015-6086.svg)

