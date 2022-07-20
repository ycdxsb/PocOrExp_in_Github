# Update 2022-07-20
## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)
- [https://github.com/W01fh4cker/cve-2022-33891](https://github.com/W01fh4cker/cve-2022-33891) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/cve-2022-33891.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/cve-2022-33891.svg)


## CVE-2022-30333
 RARLAB UnRAR before 6.12 on Linux and UNIX allows directory traversal to write to files during an extract (aka unpack) operation, as demonstrated by creating a ~/.ssh/authorized_keys file. NOTE: WinRAR and Android RAR are unaffected.

- [https://github.com/rbowes-r7/unrar-cve-2022-30333-poc](https://github.com/rbowes-r7/unrar-cve-2022-30333-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/unrar-cve-2022-30333-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/unrar-cve-2022-30333-poc.svg)


## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/Cory65/CVE-2022-24086-POC](https://github.com/Cory65/CVE-2022-24086-POC) :  ![starts](https://img.shields.io/github/stars/Cory65/CVE-2022-24086-POC.svg) ![forks](https://img.shields.io/github/forks/Cory65/CVE-2022-24086-POC.svg)


## CVE-2022-23614
 Twig is an open source template language for PHP. When in a sandbox mode, the `arrow` parameter of the `sort` filter must be a closure to avoid attackers being able to run arbitrary PHP functions. In affected versions this constraint was not properly enforced and could lead to code injection of arbitrary PHP code. Patched versions now disallow calling non Closure in the `sort` filter as is the case for some other filters. Users are advised to upgrade.

- [https://github.com/davwwwx/CVE-2022-23614](https://github.com/davwwwx/CVE-2022-23614) :  ![starts](https://img.shields.io/github/stars/davwwwx/CVE-2022-23614.svg) ![forks](https://img.shields.io/github/forks/davwwwx/CVE-2022-23614.svg)


## CVE-2022-22029
 Windows Network File System Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-22039.

- [https://github.com/mchoudhary15/CVE-2022-22029-NFS-Server-](https://github.com/mchoudhary15/CVE-2022-22029-NFS-Server-) :  ![starts](https://img.shields.io/github/stars/mchoudhary15/CVE-2022-22029-NFS-Server-.svg) ![forks](https://img.shields.io/github/forks/mchoudhary15/CVE-2022-22029-NFS-Server-.svg)


## CVE-2022-20138
 In ACTION_MANAGED_PROFILE_PROVISIONED of DevicePolicyManagerService.java, there is a possible way for unprivileged app to send MANAGED_PROFILE_PROVISIONED intent due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-210469972

- [https://github.com/ShaikUsaf/ShaikUsaf-frameworks_base_AOSP10_r33_CVE-2022-20138](https://github.com/ShaikUsaf/ShaikUsaf-frameworks_base_AOSP10_r33_CVE-2022-20138) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/ShaikUsaf-frameworks_base_AOSP10_r33_CVE-2022-20138.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/ShaikUsaf-frameworks_base_AOSP10_r33_CVE-2022-20138.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/BJLIYANLIANG/CVE-2021-43798-Grafana-File-Read](https://github.com/BJLIYANLIANG/CVE-2021-43798-Grafana-File-Read) :  ![starts](https://img.shields.io/github/stars/BJLIYANLIANG/CVE-2021-43798-Grafana-File-Read.svg) ![forks](https://img.shields.io/github/forks/BJLIYANLIANG/CVE-2021-43798-Grafana-File-Read.svg)


## CVE-2021-36955
 Windows Common Log File System Driver Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36963, CVE-2021-38633.

- [https://github.com/JiaJinRong12138/CVE-2021-36955-EXP](https://github.com/JiaJinRong12138/CVE-2021-36955-EXP) :  ![starts](https://img.shields.io/github/stars/JiaJinRong12138/CVE-2021-36955-EXP.svg) ![forks](https://img.shields.io/github/forks/JiaJinRong12138/CVE-2021-36955-EXP.svg)


## CVE-2021-20138
 An unauthenticated command injection vulnerability exists in multiple parameters in the Gryphon Tower router&#8217;s web interface at /cgi-bin/luci/rc. An unauthenticated remote attacker on the same network can execute commands as root on the device by sending a specially crafted malicious packet to the web interface.

- [https://github.com/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-20138](https://github.com/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-20138) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-20138.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2021-20138.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)
- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)


## CVE-2021-3749
 axios is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/T-Guerrero/axios-redos](https://github.com/T-Guerrero/axios-redos) :  ![starts](https://img.shields.io/github/stars/T-Guerrero/axios-redos.svg) ![forks](https://img.shields.io/github/forks/T-Guerrero/axios-redos.svg)


## CVE-2020-8103
 A vulnerability in the improper handling of symbolic links in Bitdefender Antivirus Free can allow an unprivileged user to substitute a quarantined file, and restore it to a privileged location. This issue affects Bitdefender Antivirus Free versions prior to 1.0.17.178.

- [https://github.com/RedyOpsResearchLabs/-CVE-2020-8103-Bitdefender-Antivirus-Free-EoP](https://github.com/RedyOpsResearchLabs/-CVE-2020-8103-Bitdefender-Antivirus-Free-EoP) :  ![starts](https://img.shields.io/github/stars/RedyOpsResearchLabs/-CVE-2020-8103-Bitdefender-Antivirus-Free-EoP.svg) ![forks](https://img.shields.io/github/forks/RedyOpsResearchLabs/-CVE-2020-8103-Bitdefender-Antivirus-Free-EoP.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/5l1v3r1/CVE-2020-5902-Mass](https://github.com/5l1v3r1/CVE-2020-5902-Mass) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-5902-Mass.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-5902-Mass.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/cruxN3T/CVE-2020-3580](https://github.com/cruxN3T/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/cruxN3T/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/cruxN3T/CVE-2020-3580.svg)


## CVE-2019-16920
 Unauthenticated remote code execution occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends an arbitrary input to a &quot;PingTest&quot; device common gateway interface that could lead to common injection. An attacker who successfully triggers the command injection could achieve full system compromise. Later, it was independently found that these are also affected: DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.

- [https://github.com/avavav777/CVE-2019-16920-MassPwn3r](https://github.com/avavav777/CVE-2019-16920-MassPwn3r) :  ![starts](https://img.shields.io/github/stars/avavav777/CVE-2019-16920-MassPwn3r.svg) ![forks](https://img.shields.io/github/forks/avavav777/CVE-2019-16920-MassPwn3r.svg)


## CVE-2018-19864
 NUUO NVRmini2 Network Video Recorder firmware through 3.9.1 allows remote attackers to execute arbitrary code or cause a denial of service (buffer overflow), resulting in ability to read camera feeds or reconfigure the device.

- [https://github.com/5l1v3r1/CVE-2018-19864](https://github.com/5l1v3r1/CVE-2018-19864) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2018-19864.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2018-19864.svg)


## CVE-2007-0038
 Stack-based buffer overflow in the animated cursor code in Microsoft Windows 2000 SP4 through Vista allows remote attackers to execute arbitrary code or cause a denial of service (persistent reboot) via a large length value in the second (or later) anih block of a RIFF .ANI, cur, or .ico file, which results in memory corruption when processing cursors, animated cursors, and icons, a variant of CVE-2005-0416, as originally demonstrated using Internet Explorer 6 and 7. NOTE: this might be a duplicate of CVE-2007-1765; if so, then CVE-2007-0038 should be preferred.

- [https://github.com/Cheesse/cve2007-0038x64](https://github.com/Cheesse/cve2007-0038x64) :  ![starts](https://img.shields.io/github/stars/Cheesse/cve2007-0038x64.svg) ![forks](https://img.shields.io/github/forks/Cheesse/cve2007-0038x64.svg)

