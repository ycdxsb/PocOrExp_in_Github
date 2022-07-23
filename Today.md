# Update 2022-07-23
## CVE-2022-34918
 An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.

- [https://github.com/trhacknon/CVE-2022-34918-LPE-PoC](https://github.com/trhacknon/CVE-2022-34918-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-34918-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-34918-LPE-PoC.svg)


## CVE-2022-32832
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Muirey03/CVE-2022-32832](https://github.com/Muirey03/CVE-2022-32832) :  ![starts](https://img.shields.io/github/stars/Muirey03/CVE-2022-32832.svg) ![forks](https://img.shields.io/github/forks/Muirey03/CVE-2022-32832.svg)


## CVE-2022-30333
 RARLAB UnRAR before 6.12 on Linux and UNIX allows directory traversal to write to files during an extract (aka unpack) operation, as demonstrated by creating a ~/.ssh/authorized_keys file. NOTE: WinRAR and Android RAR are unaffected.

- [https://github.com/J0hnbX/CVE-2022-30333](https://github.com/J0hnbX/CVE-2022-30333) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2022-30333.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2022-30333.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/EkamSinghWalia/Follina-MSDT-Vulnerability-CVE-2022-30190-](https://github.com/EkamSinghWalia/Follina-MSDT-Vulnerability-CVE-2022-30190-) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/Follina-MSDT-Vulnerability-CVE-2022-30190-.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/Follina-MSDT-Vulnerability-CVE-2022-30190-.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/ToomArni65/CVE-2022-26809-POC](https://github.com/ToomArni65/CVE-2022-26809-POC) :  ![starts](https://img.shields.io/github/stars/ToomArni65/CVE-2022-26809-POC.svg) ![forks](https://img.shields.io/github/forks/ToomArni65/CVE-2022-26809-POC.svg)


## CVE-2022-26138
 The Atlassian Questions For Confluence app for Confluence Server and Data Center creates a Confluence user account in the confluence-users group with the username disabledsystemuser and a hardcoded password. A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content accessible to users in the confluence-users group. This user account is created when installing versions 2.7.34, 2.7.35, and 3.0.2 of the app.

- [https://github.com/alcaparra/CVE-2022-26138](https://github.com/alcaparra/CVE-2022-26138) :  ![starts](https://img.shields.io/github/stars/alcaparra/CVE-2022-26138.svg) ![forks](https://img.shields.io/github/forks/alcaparra/CVE-2022-26138.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/chaosec2021/EXP-POC](https://github.com/chaosec2021/EXP-POC) :  ![starts](https://img.shields.io/github/stars/chaosec2021/EXP-POC.svg) ![forks](https://img.shields.io/github/forks/chaosec2021/EXP-POC.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/chaosec2021/EXP-POC](https://github.com/chaosec2021/EXP-POC) :  ![starts](https://img.shields.io/github/stars/chaosec2021/EXP-POC.svg) ![forks](https://img.shields.io/github/forks/chaosec2021/EXP-POC.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/chaosec2021/EXP-POC](https://github.com/chaosec2021/EXP-POC) :  ![starts](https://img.shields.io/github/stars/chaosec2021/EXP-POC.svg) ![forks](https://img.shields.io/github/forks/chaosec2021/EXP-POC.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/luckythandel/CVE-2021-4034](https://github.com/luckythandel/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/luckythandel/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/luckythandel/CVE-2021-4034.svg)


## CVE-2020-0137
 In setIPv6AddrGenMode of NetworkManagementService.java, there is a possible bypass of networking permissions due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-141920289

- [https://github.com/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2020-0137](https://github.com/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2020-0137) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2020-0137.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/frameworks_base_AOSP10_r33_CVE-2020-0137.svg)


## CVE-2014-4210
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect confidentiality via vectors related to WLS - Web Services.

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/NoneNotNull/SSRFX](https://github.com/NoneNotNull/SSRFX) :  ![starts](https://img.shields.io/github/stars/NoneNotNull/SSRFX.svg) ![forks](https://img.shields.io/github/forks/NoneNotNull/SSRFX.svg)
- [https://github.com/NHPT/WebLogic-SSRF_CVE-2014-4210](https://github.com/NHPT/WebLogic-SSRF_CVE-2014-4210) :  ![starts](https://img.shields.io/github/stars/NHPT/WebLogic-SSRF_CVE-2014-4210.svg) ![forks](https://img.shields.io/github/forks/NHPT/WebLogic-SSRF_CVE-2014-4210.svg)
- [https://github.com/unmanarc/CVE-2014-4210-SSRF-PORTSCANNER-POC](https://github.com/unmanarc/CVE-2014-4210-SSRF-PORTSCANNER-POC) :  ![starts](https://img.shields.io/github/stars/unmanarc/CVE-2014-4210-SSRF-PORTSCANNER-POC.svg) ![forks](https://img.shields.io/github/forks/unmanarc/CVE-2014-4210-SSRF-PORTSCANNER-POC.svg)

