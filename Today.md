# Update 2023-02-24
## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states &quot;remote code execution is theoretically possible.&quot;

- [https://github.com/Christbowel/CVE-2023-25136](https://github.com/Christbowel/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2023-25136.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/wangking1/CVE-2023-23752-poc](https://github.com/wangking1/CVE-2023-23752-poc) :  ![starts](https://img.shields.io/github/stars/wangking1/CVE-2023-23752-poc.svg) ![forks](https://img.shields.io/github/forks/wangking1/CVE-2023-23752-poc.svg)
- [https://github.com/ibaiw/joomla_CVE-2023-23752](https://github.com/ibaiw/joomla_CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/ibaiw/joomla_CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/ibaiw/joomla_CVE-2023-23752.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/M4fiaB0y/CVE-2023-22809](https://github.com/M4fiaB0y/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/M4fiaB0y/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/M4fiaB0y/CVE-2023-22809.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/DXask88MA/Weblogic-CVE-2023-21839](https://github.com/DXask88MA/Weblogic-CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/DXask88MA/Weblogic-CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/DXask88MA/Weblogic-CVE-2023-21839.svg)


## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.

- [https://github.com/b11y/CVE-2023-0297](https://github.com/b11y/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/b11y/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/b11y/CVE-2023-0297.svg)


## CVE-2022-32429
 An authentication-bypass issue in the component http://MYDEVICEIP/cgi-bin-sdb/ExportSettings.sh of Mega System Technologies Inc MSNSwitch MNT.2408 allows unauthenticated attackers to arbitrarily configure settings within the application, leading to remote code execution.

- [https://github.com/b11y/CVE-2022-32429](https://github.com/b11y/CVE-2022-32429) :  ![starts](https://img.shields.io/github/stars/b11y/CVE-2022-32429.svg) ![forks](https://img.shields.io/github/forks/b11y/CVE-2022-32429.svg)


## CVE-2022-31814
 pfSense pfBlockerNG through 2.1.4_26 allows remote attackers to execute arbitrary OS commands as root via shell metacharacters in the HTTP Host header. NOTE: 3.x is unaffected.

- [https://github.com/Madliife0/CVE-2022-31814](https://github.com/Madliife0/CVE-2022-31814) :  ![starts](https://img.shields.io/github/stars/Madliife0/CVE-2022-31814.svg) ![forks](https://img.shields.io/github/forks/Madliife0/CVE-2022-31814.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/justakazh/mass_cve-2021-41773](https://github.com/justakazh/mass_cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/justakazh/mass_cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/justakazh/mass_cve-2021-41773.svg)
- [https://github.com/ZephrFish/CVE-2021-41773-PoC](https://github.com/ZephrFish/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-41773-PoC.svg)
- [https://github.com/j4k0m/CVE-2021-41773](https://github.com/j4k0m/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2021-41773.svg)
- [https://github.com/TishcaTpx/POC-CVE-2021-41773](https://github.com/TishcaTpx/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TishcaTpx/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TishcaTpx/POC-CVE-2021-41773.svg)
- [https://github.com/orangmuda/CVE-2021-41773](https://github.com/orangmuda/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/orangmuda/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/orangmuda/CVE-2021-41773.svg)
- [https://github.com/masahiro331/CVE-2021-41773](https://github.com/masahiro331/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/masahiro331/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/masahiro331/CVE-2021-41773.svg)
- [https://github.com/mohwahyudi/cve-2021-41773](https://github.com/mohwahyudi/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mohwahyudi/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mohwahyudi/cve-2021-41773.svg)
- [https://github.com/Hattan-515/POC-CVE-2021-41773](https://github.com/Hattan-515/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Hattan-515/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Hattan-515/POC-CVE-2021-41773.svg)
- [https://github.com/mightysai1997/CVE-2021-41773S](https://github.com/mightysai1997/CVE-2021-41773S) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773S.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773S.svg)
- [https://github.com/mightysai1997/CVE-2021-41773m](https://github.com/mightysai1997/CVE-2021-41773m) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773m.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773m.svg)
- [https://github.com/mightysai1997/cve-2021-41773-v-](https://github.com/mightysai1997/cve-2021-41773-v-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773-v-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773-v-.svg)


## CVE-2021-39690
 In setDisplayPadding of WallpaperManagerService.java, there is a possible way to cause a persistent DoS due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-204316511

- [https://github.com/Supersonic/Wallbreak](https://github.com/Supersonic/Wallbreak) :  ![starts](https://img.shields.io/github/stars/Supersonic/Wallbreak.svg) ![forks](https://img.shields.io/github/forks/Supersonic/Wallbreak.svg)


## CVE-2021-39670
 In setStream of WallpaperManager.java, there is a possible way to cause a permanent DoS due to improper input validation. This could lead to local denial of service with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-204087139

- [https://github.com/Supersonic/Wallbreak](https://github.com/Supersonic/Wallbreak) :  ![starts](https://img.shields.io/github/stars/Supersonic/Wallbreak.svg) ![forks](https://img.shields.io/github/forks/Supersonic/Wallbreak.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/scent2d/PoC-CVE-2021-4034](https://github.com/scent2d/PoC-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/scent2d/PoC-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/scent2d/PoC-CVE-2021-4034.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Donghan-gugugu/weblogic-CVE2019-2725POC](https://github.com/Donghan-gugugu/weblogic-CVE2019-2725POC) :  ![starts](https://img.shields.io/github/stars/Donghan-gugugu/weblogic-CVE2019-2725POC.svg) ![forks](https://img.shields.io/github/forks/Donghan-gugugu/weblogic-CVE2019-2725POC.svg)


## CVE-2008-7220
 Unspecified vulnerability in Prototype JavaScript framework (prototypejs) before 1.6.0.2 allows attackers to make &quot;cross-site ajax requests&quot; via unknown vectors.

- [https://github.com/followboy1999/CVE-2008-7220](https://github.com/followboy1999/CVE-2008-7220) :  ![starts](https://img.shields.io/github/stars/followboy1999/CVE-2008-7220.svg) ![forks](https://img.shields.io/github/forks/followboy1999/CVE-2008-7220.svg)

