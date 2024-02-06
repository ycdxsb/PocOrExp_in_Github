# Update 2024-02-06
## CVE-2024-23208
 The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.3, watchOS 10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/hrtowii/CVE-2024-23208-test](https://github.com/hrtowii/CVE-2024-23208-test) :  ![starts](https://img.shields.io/github/stars/hrtowii/CVE-2024-23208-test.svg) ![forks](https://img.shields.io/github/forks/hrtowii/CVE-2024-23208-test.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/Shisones/MetabaseRCE_CVE-2023-38646](https://github.com/Shisones/MetabaseRCE_CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/Shisones/MetabaseRCE_CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/Shisones/MetabaseRCE_CVE-2023-38646.svg)


## CVE-2023-29199
 There exists a vulnerability in source code transformer (exception sanitization logic) of vm2 for versions up to 3.9.15, allowing attackers to bypass `handleException()` and leak unsanitized host exceptions which can be used to escape the sandbox and run arbitrary code in host context. A threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version `3.9.16` of `vm2`.

- [https://github.com/u-crew/vm2-test](https://github.com/u-crew/vm2-test) :  ![starts](https://img.shields.io/github/stars/u-crew/vm2-test.svg) ![forks](https://img.shields.io/github/forks/u-crew/vm2-test.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/kakaroot1337/-2022-LOCALROOT-CVE-2022-2639](https://github.com/kakaroot1337/-2022-LOCALROOT-CVE-2022-2639) :  ![starts](https://img.shields.io/github/stars/kakaroot1337/-2022-LOCALROOT-CVE-2022-2639.svg) ![forks](https://img.shields.io/github/forks/kakaroot1337/-2022-LOCALROOT-CVE-2022-2639.svg)


## CVE-2022-1040
 An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v18.5 MR3 and older.

- [https://github.com/xMr110/CVE-2022-1040](https://github.com/xMr110/CVE-2022-1040) :  ![starts](https://img.shields.io/github/stars/xMr110/CVE-2022-1040.svg) ![forks](https://img.shields.io/github/forks/xMr110/CVE-2022-1040.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/kakaroot1337/-2021-LOCALROOT-CVE-2021-22555](https://github.com/kakaroot1337/-2021-LOCALROOT-CVE-2021-22555) :  ![starts](https://img.shields.io/github/stars/kakaroot1337/-2021-LOCALROOT-CVE-2021-22555.svg) ![forks](https://img.shields.io/github/forks/kakaroot1337/-2021-LOCALROOT-CVE-2021-22555.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/wechicken456/CVE-2021-4034-writeup](https://github.com/wechicken456/CVE-2021-4034-writeup) :  ![starts](https://img.shields.io/github/stars/wechicken456/CVE-2021-4034-writeup.svg) ![forks](https://img.shields.io/github/forks/wechicken456/CVE-2021-4034-writeup.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/willboka/CVE-2019-2215-HuaweiP20Lite](https://github.com/willboka/CVE-2019-2215-HuaweiP20Lite) :  ![starts](https://img.shields.io/github/stars/willboka/CVE-2019-2215-HuaweiP20Lite.svg) ![forks](https://img.shields.io/github/forks/willboka/CVE-2019-2215-HuaweiP20Lite.svg)


## CVE-2019-1332
 A cross-site scripting (XSS) vulnerability exists when Microsoft SQL Server Reporting Services (SSRS) does not properly sanitize a specially-crafted web request to an affected SSRS server, aka 'Microsoft SQL Server Reporting Services XSS Vulnerability'.

- [https://github.com/mbadanoiu/CVE-2019-1332](https://github.com/mbadanoiu/CVE-2019-1332) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-1332.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-1332.svg)

