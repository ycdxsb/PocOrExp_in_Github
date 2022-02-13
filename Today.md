# Update 2022-02-13
## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/ZZ-SOCMAP/CVE-2022-21907](https://github.com/ZZ-SOCMAP/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/ZZ-SOCMAP/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/ZZ-SOCMAP/CVE-2022-21907.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/an0n7os/CVE-2021-4034](https://github.com/an0n7os/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/an0n7os/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/an0n7os/CVE-2021-4034.svg)


## CVE-2020-9768
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 13.4 and iPadOS 13.4, tvOS 13.4, watchOS 6.2. An application may be able to execute arbitrary code with system privileges.

- [https://github.com/XorgX304/CVE-2020-9768](https://github.com/XorgX304/CVE-2020-9768) :  ![starts](https://img.shields.io/github/stars/XorgX304/CVE-2020-9768.svg) ![forks](https://img.shields.io/github/forks/XorgX304/CVE-2020-9768.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/ColdFusionX/CVE-2020-9484](https://github.com/ColdFusionX/CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2020-9484.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/4n0nym0u5dk/CVE-2017-7269](https://github.com/4n0nym0u5dk/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2017-7269.svg)


## CVE-2015-6668
 The Job Manager plugin before 0.7.25 allows remote attackers to read arbitrary CV files via a brute force attack to the WordPress upload directory structure, related to an insecure direct object reference.

- [https://github.com/4n0nym0u5dk/CVE-2015-6668](https://github.com/4n0nym0u5dk/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2015-6668.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/4n0nym0u5dk/CVE-2015-1635-POC](https://github.com/4n0nym0u5dk/CVE-2015-1635-POC) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2015-1635-POC.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2015-1635-POC.svg)
- [https://github.com/4n0nym0u5dk/CVE-2015-1635](https://github.com/4n0nym0u5dk/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2015-1635.svg)


## CVE-2014-1767
 Double free vulnerability in the Ancillary Function Driver (AFD) in afd.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to gain privileges via a crafted application, aka &quot;Ancillary Function Driver Elevation of Privilege Vulnerability.&quot;

- [https://github.com/ExploitCN/CVE-2014-1767-EXP-PAPER](https://github.com/ExploitCN/CVE-2014-1767-EXP-PAPER) :  ![starts](https://img.shields.io/github/stars/ExploitCN/CVE-2014-1767-EXP-PAPER.svg) ![forks](https://img.shields.io/github/forks/ExploitCN/CVE-2014-1767-EXP-PAPER.svg)


## CVE-2011-1249
 The Ancillary Function Driver (AFD) in afd.sys in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly validate user-mode input, which allows local users to gain privileges via a crafted application, aka &quot;Ancillary Function Driver Elevation of Privilege Vulnerability.&quot;

- [https://github.com/4n0nym0u5dk/CVE-2011-1249](https://github.com/4n0nym0u5dk/CVE-2011-1249) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2011-1249.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2011-1249.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/4n0nym0u5dk/CVE-2009-2265](https://github.com/4n0nym0u5dk/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2009-2265.svg)


## CVE-2008-4250
 The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka &quot;Server Service Vulnerability.&quot;

- [https://github.com/4n0nym0u5dk/MS08_067_CVE-2008-4250](https://github.com/4n0nym0u5dk/MS08_067_CVE-2008-4250) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/MS08_067_CVE-2008-4250.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/MS08_067_CVE-2008-4250.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/4n0nym0u5dk/usermap_script_CVE-2007-2447](https://github.com/4n0nym0u5dk/usermap_script_CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/usermap_script_CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/usermap_script_CVE-2007-2447.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/4n0nym0u5dk/distccd_rce_CVE-2004-2687](https://github.com/4n0nym0u5dk/distccd_rce_CVE-2004-2687) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/distccd_rce_CVE-2004-2687.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/distccd_rce_CVE-2004-2687.svg)

