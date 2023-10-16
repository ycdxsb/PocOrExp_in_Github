# Update 2023-10-16
## CVE-2023-45603
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/codeb0ss/CVE-2023-45603-PoC](https://github.com/codeb0ss/CVE-2023-45603-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-45603-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-45603-PoC.svg)


## CVE-2023-45471
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/itsAptx/CVE-2023-45471](https://github.com/itsAptx/CVE-2023-45471) :  ![starts](https://img.shields.io/github/stars/itsAptx/CVE-2023-45471.svg) ![forks](https://img.shields.io/github/forks/itsAptx/CVE-2023-45471.svg)


## CVE-2023-42820
 JumpServer is an open source bastion host. This vulnerability is due to exposing the random number seed to the API, potentially allowing the randomly generated verification codes to be replayed, which could lead to password resets. If MFA is enabled users are not affect. Users not using local authentication are also not affected. Users are advised to upgrade to either version 2.28.19 or to 3.6.5. There are no known workarounds or this issue.

- [https://github.com/tarimoe/blackjump](https://github.com/tarimoe/blackjump) :  ![starts](https://img.shields.io/github/stars/tarimoe/blackjump.svg) ![forks](https://img.shields.io/github/forks/tarimoe/blackjump.svg)


## CVE-2023-42442
 JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication. Session replays stored in S3, OSS, or other cloud storage are not affected. The api `/api/v1/terminal/sessions/` permission control is broken and can be accessed anonymously. SessionViewSet permission classes set to `[RBACPermission | IsSessionAssignee]`, relation is or, so any permission matched will be allowed. Versions 3.5.5 and 3.6.4 have a fix. After upgrading, visit the api `$HOST/api/v1/terminal/sessions/?limit=1`. The expected http response code is 401 (`not_authenticated`).

- [https://github.com/tarimoe/blackjump](https://github.com/tarimoe/blackjump) :  ![starts](https://img.shields.io/github/stars/tarimoe/blackjump.svg) ![forks](https://img.shields.io/github/forks/tarimoe/blackjump.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/Pyr0sec/CVE-2023-38646](https://github.com/Pyr0sec/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/Pyr0sec/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/Pyr0sec/CVE-2023-38646.svg)
- [https://github.com/asepsaepdin/CVE-2023-38646](https://github.com/asepsaepdin/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/CVE-2023-38646.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/kor34N/CVE-2023-34362-mass](https://github.com/kor34N/CVE-2023-34362-mass) :  ![starts](https://img.shields.io/github/stars/kor34N/CVE-2023-34362-mass.svg) ![forks](https://img.shields.io/github/forks/kor34N/CVE-2023-34362-mass.svg)


## CVE-2023-3710
 Improper Input Validation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Command Injection.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of the respective printers to version MR19.5 (e.g. P10.19.050006).

- [https://github.com/CwEeR313/CVE-2023-3710](https://github.com/CwEeR313/CVE-2023-3710) :  ![starts](https://img.shields.io/github/stars/CwEeR313/CVE-2023-3710.svg) ![forks](https://img.shields.io/github/forks/CwEeR313/CVE-2023-3710.svg)
- [https://github.com/Mahdi22228/CVE-2023-3710](https://github.com/Mahdi22228/CVE-2023-3710) :  ![starts](https://img.shields.io/github/stars/Mahdi22228/CVE-2023-3710.svg) ![forks](https://img.shields.io/github/forks/Mahdi22228/CVE-2023-3710.svg)


## CVE-2023-2523
 A vulnerability was found in Weaver E-Office 9.5. It has been rated as critical. Affected by this issue is some unknown functionality of the file App/Ajax/ajax.php?action=mobile_upload_save. The manipulation of the argument upload_quwan leads to unrestricted upload. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-228014 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648](https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648) :  ![starts](https://img.shields.io/github/stars/bingtangbanli/cve-2023-2523-and-cve-2023-2648.svg) ![forks](https://img.shields.io/github/forks/bingtangbanli/cve-2023-2523-and-cve-2023-2648.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/GameProfOrg/Jpg-Png-Exploit-Downloader-Fud-Cryter-Malware-Builder-Cve-2022](https://github.com/GameProfOrg/Jpg-Png-Exploit-Downloader-Fud-Cryter-Malware-Builder-Cve-2022) :  ![starts](https://img.shields.io/github/stars/GameProfOrg/Jpg-Png-Exploit-Downloader-Fud-Cryter-Malware-Builder-Cve-2022.svg) ![forks](https://img.shields.io/github/forks/GameProfOrg/Jpg-Png-Exploit-Downloader-Fud-Cryter-Malware-Builder-Cve-2022.svg)
- [https://github.com/GameProfOrg/Slient-Doc-Pdf-Exploit-Builder-Fud-Malware-Cve](https://github.com/GameProfOrg/Slient-Doc-Pdf-Exploit-Builder-Fud-Malware-Cve) :  ![starts](https://img.shields.io/github/stars/GameProfOrg/Slient-Doc-Pdf-Exploit-Builder-Fud-Malware-Cve.svg) ![forks](https://img.shields.io/github/forks/GameProfOrg/Slient-Doc-Pdf-Exploit-Builder-Fud-Malware-Cve.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)
- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2017-6074
 The dccp_rcv_state_process function in net/dccp/input.c in the Linux kernel through 4.9.11 mishandles DCCP_PKT_REQUEST packet data structures in the LISTEN state, which allows local users to obtain root privileges or cause a denial of service (double free) via an application that makes an IPV6_RECVPKTINFO setsockopt system call.

- [https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074](https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074) :  ![starts](https://img.shields.io/github/stars/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.svg) ![forks](https://img.shields.io/github/forks/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.svg)
- [https://github.com/toanthang1842002/CVE-2017-6074](https://github.com/toanthang1842002/CVE-2017-6074) :  ![starts](https://img.shields.io/github/stars/toanthang1842002/CVE-2017-6074.svg) ![forks](https://img.shields.io/github/forks/toanthang1842002/CVE-2017-6074.svg)


## CVE-2014-0038
 The compat_sys_recvmmsg function in net/compat.c in the Linux kernel before 3.13.2, when CONFIG_X86_X32 is enabled, allows local users to gain privileges via a recvmmsg system call with a crafted timeout pointer parameter.

- [https://github.com/kiruthikan99/IT19115276](https://github.com/kiruthikan99/IT19115276) :  ![starts](https://img.shields.io/github/stars/kiruthikan99/IT19115276.svg) ![forks](https://img.shields.io/github/forks/kiruthikan99/IT19115276.svg)

