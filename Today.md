# Update 2023-08-26
## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/BoredHackerBlog/winrar_CVE-2023-38831_lazy_poc](https://github.com/BoredHackerBlog/winrar_CVE-2023-38831_lazy_poc) :  ![starts](https://img.shields.io/github/stars/BoredHackerBlog/winrar_CVE-2023-38831_lazy_poc.svg) ![forks](https://img.shields.io/github/forks/BoredHackerBlog/winrar_CVE-2023-38831_lazy_poc.svg)


## CVE-2023-38035
 A security vulnerability in MICS Admin Portal in Ivanti MobileIron Sentry versions 9.18.0 and below, which may allow an attacker to bypass authentication controls on the administrative interface due to an insufficiently restrictive Apache HTTPD configuration.

- [https://github.com/horizon3ai/CVE-2023-38035](https://github.com/horizon3ai/CVE-2023-38035) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-38035.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-38035.svg)
- [https://github.com/LeakIX/sentryexploit](https://github.com/LeakIX/sentryexploit) :  ![starts](https://img.shields.io/github/stars/LeakIX/sentryexploit.svg) ![forks](https://img.shields.io/github/forks/LeakIX/sentryexploit.svg)


## CVE-2023-36874
 Windows Error Reporting Service Elevation of Privilege Vulnerability

- [https://github.com/Octoberfest7/CVE-2023-36874_BOF](https://github.com/Octoberfest7/CVE-2023-36874_BOF) :  ![starts](https://img.shields.io/github/stars/Octoberfest7/CVE-2023-36874_BOF.svg) ![forks](https://img.shields.io/github/forks/Octoberfest7/CVE-2023-36874_BOF.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/johnlettman/juju-scripts](https://github.com/johnlettman/juju-scripts) :  ![starts](https://img.shields.io/github/stars/johnlettman/juju-scripts.svg) ![forks](https://img.shields.io/github/forks/johnlettman/juju-scripts.svg)


## CVE-2023-24998
 Apache Commons FileUpload before 1.5 does not limit the number of request parts to be processed resulting in the possibility of an attacker triggering a DoS with a malicious upload or series of uploads. Note that, like all of the file upload limits, the new configuration option (FileUploadBase#setFileCountMax) is not enabled by default and must be explicitly configured.

- [https://github.com/nice1st/CVE-2023-24998](https://github.com/nice1st/CVE-2023-24998) :  ![starts](https://img.shields.io/github/stars/nice1st/CVE-2023-24998.svg) ![forks](https://img.shields.io/github/forks/nice1st/CVE-2023-24998.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and &quot;UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs&quot;, an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/johnlettman/juju-scripts](https://github.com/johnlettman/juju-scripts) :  ![starts](https://img.shields.io/github/stars/johnlettman/juju-scripts.svg) ![forks](https://img.shields.io/github/forks/johnlettman/juju-scripts.svg)


## CVE-2022-39986
 A Command injection vulnerability in RaspAP 2.8.0 thru 2.8.7 allows unauthenticated attackers to execute arbitrary commands via the cfg_id parameter in /ajax/openvpn/activate_ovpncfg.php and /ajax/openvpn/del_ovpncfg.php.

- [https://github.com/mind2hex/RaspAP_Hunter](https://github.com/mind2hex/RaspAP_Hunter) :  ![starts](https://img.shields.io/github/stars/mind2hex/RaspAP_Hunter.svg) ![forks](https://img.shields.io/github/forks/mind2hex/RaspAP_Hunter.svg)


## CVE-2022-26904
 Windows User Profile Service Elevation of Privilege Vulnerability

- [https://github.com/0nyx-hkr/cve_2022_26904](https://github.com/0nyx-hkr/cve_2022_26904) :  ![starts](https://img.shields.io/github/stars/0nyx-hkr/cve_2022_26904.svg) ![forks](https://img.shields.io/github/forks/0nyx-hkr/cve_2022_26904.svg)


## CVE-2022-24990
 TerraMaster NAS 4.2.29 and earlier allows remote attackers to discover the administrative password by sending &quot;User-Agent: TNAS&quot; to module/api.php?mobile/webNasIPS and then reading the PWD field in the response.

- [https://github.com/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-](https://github.com/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-) :  ![starts](https://img.shields.io/github/stars/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-.svg) ![forks](https://img.shields.io/github/forks/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Immersive-Labs-Sec/CVE-2021-4034](https://github.com/Immersive-Labs-Sec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2021-4034.svg)
- [https://github.com/A1vinSmith/CVE-2021-4034](https://github.com/A1vinSmith/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/A1vinSmith/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/A1vinSmith/CVE-2021-4034.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/ptkhai15/OverlayFS---CVE-2021-3493](https://github.com/ptkhai15/OverlayFS---CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/ptkhai15/OverlayFS---CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/ptkhai15/OverlayFS---CVE-2021-3493.svg)


## CVE-2020-13937
 Apache Kylin 2.0.0, 2.1.0, 2.2.0, 2.3.0, 2.3.1, 2.3.2, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.5.2, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 3.0.0-alpha, 3.0.0-alpha2, 3.0.0-beta, 3.0.0, 3.0.1, 3.0.2, 3.1.0, 4.0.0-alpha has one restful api which exposed Kylin's configuration information without any authentication, so it is dangerous because some confidential information entries will be disclosed to everyone.

- [https://github.com/yaunsky/CVE-2020-13937](https://github.com/yaunsky/CVE-2020-13937) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-2020-13937.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-2020-13937.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Y4er/CVE-2020-2883](https://github.com/Y4er/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2883.svg)


## CVE-2019-19943
 The HTTP service in quickweb.exe in Pablo Quick 'n Easy Web Server 3.3.8 allows Remote Unauthenticated Heap Memory Corruption via a large host or domain parameter. It may be possible to achieve remote code execution because of a double free.

- [https://github.com/5l1v3r1/CVE-2019-19943](https://github.com/5l1v3r1/CVE-2019-19943) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2019-19943.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2019-19943.svg)


## CVE-2019-0709
 A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system, aka 'Windows Hyper-V Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0620, CVE-2019-0722.

- [https://github.com/ciakim/CVE-2019-0709](https://github.com/ciakim/CVE-2019-0709) :  ![starts](https://img.shields.io/github/stars/ciakim/CVE-2019-0709.svg) ![forks](https://img.shields.io/github/forks/ciakim/CVE-2019-0709.svg)


## CVE-2018-8120
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.

- [https://github.com/bigric3/cve-2018-8120](https://github.com/bigric3/cve-2018-8120) :  ![starts](https://img.shields.io/github/stars/bigric3/cve-2018-8120.svg) ![forks](https://img.shields.io/github/forks/bigric3/cve-2018-8120.svg)


## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;

- [https://github.com/xssfile/CVE-2017-8464-EXP](https://github.com/xssfile/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/xssfile/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/xssfile/CVE-2017-8464-EXP.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/gemboxteam/exploit-nginx-1.10.3](https://github.com/gemboxteam/exploit-nginx-1.10.3) :  ![starts](https://img.shields.io/github/stars/gemboxteam/exploit-nginx-1.10.3.svg) ![forks](https://img.shields.io/github/forks/gemboxteam/exploit-nginx-1.10.3.svg)


## CVE-2014-5460
 Unrestricted file upload vulnerability in the Tribulant Slideshow Gallery plugin before 1.4.7 for WordPress allows remote authenticated users to execute arbitrary code by uploading a PHP file, then accessing it via a direct request to the file in wp-content/uploads/slideshow-gallery/.

- [https://github.com/brookeses69/CVE-2014-5460](https://github.com/brookeses69/CVE-2014-5460) :  ![starts](https://img.shields.io/github/stars/brookeses69/CVE-2014-5460.svg) ![forks](https://img.shields.io/github/forks/brookeses69/CVE-2014-5460.svg)

