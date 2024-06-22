# Update 2024-06-22
## CVE-2024-34470
 An issue was discovered in HSC Mailinspector 5.2.17-3 through v.5.2.18. An Unauthenticated Path Traversal vulnerability exists in the /public/loader.php file. The path parameter does not properly filter whether the file and directory passed are part of the webroot, allowing an attacker to read arbitrary files on the server.

- [https://github.com/Mr-r00t11/CVE-2024-34470](https://github.com/Mr-r00t11/CVE-2024-34470) :  ![starts](https://img.shields.io/github/stars/Mr-r00t11/CVE-2024-34470.svg) ![forks](https://img.shields.io/github/forks/Mr-r00t11/CVE-2024-34470.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/bonnettheo/CVE-2024-32002](https://github.com/bonnettheo/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/bonnettheo/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/bonnettheo/CVE-2024-32002.svg)


## CVE-2024-30270
 mailcow: dockerized is an open source groupware/email suite based on docker. A security vulnerability has been identified in mailcow affecting versions prior to 2024-04. This vulnerability is a combination of path traversal and arbitrary code execution, specifically targeting the `rspamd_maps()` function. It allows authenticated admin users to overwrite any file writable by the www-data user by exploiting improper path validation. The exploit chain can lead to the execution of arbitrary commands on the server. Version 2024-04 contains a patch for the issue.

- [https://github.com/Alchemist3dot14/CVE-2024-30270-PoC](https://github.com/Alchemist3dot14/CVE-2024-30270-PoC) :  ![starts](https://img.shields.io/github/stars/Alchemist3dot14/CVE-2024-30270-PoC.svg) ![forks](https://img.shields.io/github/forks/Alchemist3dot14/CVE-2024-30270-PoC.svg)


## CVE-2024-30078
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/blkph0x/CVE_2024_30078_POC_WIFI](https://github.com/blkph0x/CVE_2024_30078_POC_WIFI) :  ![starts](https://img.shields.io/github/stars/blkph0x/CVE_2024_30078_POC_WIFI.svg) ![forks](https://img.shields.io/github/forks/blkph0x/CVE_2024_30078_POC_WIFI.svg)


## CVE-2024-29972
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/WanLiChangChengWanLiChang/CVE-2024-29972](https://github.com/WanLiChangChengWanLiChang/CVE-2024-29972) :  ![starts](https://img.shields.io/github/stars/WanLiChangChengWanLiChang/CVE-2024-29972.svg) ![forks](https://img.shields.io/github/forks/WanLiChangChengWanLiChang/CVE-2024-29972.svg)


## CVE-2024-29275
 SQL injection vulnerability in SeaCMS version 12.9, allows remote unauthenticated attackers to execute arbitrary code and obtain sensitive information via the id parameter in class.php.

- [https://github.com/Cyphercoda/nuclei_template](https://github.com/Cyphercoda/nuclei_template) :  ![starts](https://img.shields.io/github/stars/Cyphercoda/nuclei_template.svg) ![forks](https://img.shields.io/github/forks/Cyphercoda/nuclei_template.svg)


## CVE-2024-28397
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape.svg)


## CVE-2024-27815
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jprx/CVE-2024-27815](https://github.com/jprx/CVE-2024-27815) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2024-27815.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2024-27815.svg)


## CVE-2024-24590
 Deserialization of untrusted data can occur in versions 0.17.0 to 1.14.2 of the client SDK of Allegro AI&#8217;s ClearML platform, enabling a maliciously uploaded artifact to run arbitrary code on an end user&#8217;s system when interacted with.

- [https://github.com/junnythemarksman/CVE-2024-24590](https://github.com/junnythemarksman/CVE-2024-24590) :  ![starts](https://img.shields.io/github/stars/junnythemarksman/CVE-2024-24590.svg) ![forks](https://img.shields.io/github/forks/junnythemarksman/CVE-2024-24590.svg)


## CVE-2024-20338
 A vulnerability in the ISE Posture (System Scan) module of Cisco Secure Client for Linux could allow an authenticated, local attacker to elevate privileges on an affected device. This vulnerability is due to the use of an uncontrolled search path element. An attacker could exploit this vulnerability by copying a malicious library file to a specific directory in the filesystem and persuading an administrator to restart a specific process. A successful exploit could allow the attacker to execute arbitrary code on an affected device with root privileges.

- [https://github.com/annmuor/CVE-2024-20338](https://github.com/annmuor/CVE-2024-20338) :  ![starts](https://img.shields.io/github/stars/annmuor/CVE-2024-20338.svg) ![forks](https://img.shields.io/github/forks/annmuor/CVE-2024-20338.svg)


## CVE-2024-3775
 aEnrich Technology a+HRD's functionality for downloading files using youtube-dl.exe does not properly restrict user input. This allows attackers to pass arbitrary arguments to youtube-dl.exe, leading to the download of partial unauthorized files.

- [https://github.com/crumbledwall/CVE-2024-37759_PoC](https://github.com/crumbledwall/CVE-2024-37759_PoC) :  ![starts](https://img.shields.io/github/stars/crumbledwall/CVE-2024-37759_PoC.svg) ![forks](https://img.shields.io/github/forks/crumbledwall/CVE-2024-37759_PoC.svg)


## CVE-2024-3774
 aEnrich Technology a+HRD's functionality for front-end retrieval of system configuration values lacks proper restrictions on a specific parameter, allowing attackers to modify this parameter to access certain sensitive system configuration values.

- [https://github.com/Eteblue/CVE-2024-37742](https://github.com/Eteblue/CVE-2024-37742) :  ![starts](https://img.shields.io/github/stars/Eteblue/CVE-2024-37742.svg) ![forks](https://img.shields.io/github/forks/Eteblue/CVE-2024-37742.svg)


## CVE-2024-3652
 The Libreswan Project was notified of an issue causing libreswan to restart when using IKEv1 without specifying an esp= line. When the peer requests AES-GMAC, libreswan's default proposal handler causes an assertion failure and crashes and restarts. IKEv2 connections are not affected.

- [https://github.com/bigb0x/CVE-2024-36527](https://github.com/bigb0x/CVE-2024-36527) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-36527.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-36527.svg)


## CVE-2023-30253
 Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: &lt;?PHP instead of &lt;?php in injected data.

- [https://github.com/g4nkd/CVE-2023-30253-PoC](https://github.com/g4nkd/CVE-2023-30253-PoC) :  ![starts](https://img.shields.io/github/stars/g4nkd/CVE-2023-30253-PoC.svg) ![forks](https://img.shields.io/github/forks/g4nkd/CVE-2023-30253-PoC.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/blacks1ph0n/CVE-2023-23752](https://github.com/blacks1ph0n/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/blacks1ph0n/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/blacks1ph0n/CVE-2023-23752.svg)


## CVE-2023-6241
 Use After Free vulnerability in Arm Ltd Midgard GPU Kernel Driver, Arm Ltd Bifrost GPU Kernel Driver, Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user to exploit a software race condition to perform improper memory processing operations. If the system&#8217;s memory is carefully prepared by the user, then this in turn cause a use-after-free.This issue affects Midgard GPU Kernel Driver: from r13p0 through r32p0; Bifrost GPU Kernel Driver: from r11p0 through r25p0; Valhall GPU Kernel Driver: from r19p0 through r25p0, from r29p0 through r46p0; Arm 5th Gen GPU Architecture Kernel Driver: from r41p0 through r46p0.

- [https://github.com/s1204IT/CVE-2023-6241](https://github.com/s1204IT/CVE-2023-6241) :  ![starts](https://img.shields.io/github/stars/s1204IT/CVE-2023-6241.svg) ![forks](https://img.shields.io/github/forks/s1204IT/CVE-2023-6241.svg)


## CVE-2023-4357
 Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/CamillaFranceschini/CVE-2023-4357](https://github.com/CamillaFranceschini/CVE-2023-4357) :  ![starts](https://img.shields.io/github/stars/CamillaFranceschini/CVE-2023-4357.svg) ![forks](https://img.shields.io/github/forks/CamillaFranceschini/CVE-2023-4357.svg)


## CVE-2023-2825
 An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.

- [https://github.com/cc3305/CVE-2023-2825](https://github.com/cc3305/CVE-2023-2825) :  ![starts](https://img.shields.io/github/stars/cc3305/CVE-2023-2825.svg) ![forks](https://img.shields.io/github/forks/cc3305/CVE-2023-2825.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/NeonWhiteRabbit/CVE-2021-4034](https://github.com/NeonWhiteRabbit/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/NeonWhiteRabbit/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/NeonWhiteRabbit/CVE-2021-4034.svg)
- [https://github.com/NeonWhiteRabbit/CVE-2021-4034-BASH-One-File-Exploit](https://github.com/NeonWhiteRabbit/CVE-2021-4034-BASH-One-File-Exploit) :  ![starts](https://img.shields.io/github/stars/NeonWhiteRabbit/CVE-2021-4034-BASH-One-File-Exploit.svg) ![forks](https://img.shields.io/github/forks/NeonWhiteRabbit/CVE-2021-4034-BASH-One-File-Exploit.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/NeonWhiteRabbit/CVE-2021-3560](https://github.com/NeonWhiteRabbit/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/NeonWhiteRabbit/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/NeonWhiteRabbit/CVE-2021-3560.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Dh4nuJ4/SimpleCTF-UpdatedExploit](https://github.com/Dh4nuJ4/SimpleCTF-UpdatedExploit) :  ![starts](https://img.shields.io/github/stars/Dh4nuJ4/SimpleCTF-UpdatedExploit.svg) ![forks](https://img.shields.io/github/forks/Dh4nuJ4/SimpleCTF-UpdatedExploit.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/OmarSuarezDoro/CVE-2017-7269](https://github.com/OmarSuarezDoro/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/OmarSuarezDoro/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/OmarSuarezDoro/CVE-2017-7269.svg)

