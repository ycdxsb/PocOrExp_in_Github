# Update 2024-05-12
## CVE-2024-31497
 In PuTTY 0.68 through 0.80 before 0.81, biased ECDSA nonce generation allows an attacker to recover a user's NIST P-521 secret key via a quick attack in approximately 60 signatures. This is especially important in a scenario where an adversary is able to read messages signed by PuTTY or Pageant. The required set of signed messages may be publicly readable because they are stored in a public Git service that supports use of SSH for commit signing, and the signatures were made by Pageant through an agent-forwarding mechanism. In other words, an adversary may already have enough signature information to compromise a victim's private key, even if there is no further use of vulnerable PuTTY versions. After a key compromise, an adversary may be able to conduct supply-chain attacks on software maintained in Git. A second, independent scenario is that the adversary is an operator of an SSH server to which the victim authenticates (for remote login or file copy), even though this server is not fully trusted by the victim, and the victim uses the same private key for SSH connections to other services operated by other entities. Here, the rogue server operator (who would otherwise have no way to determine the victim's private key) can derive the victim's private key, and then use it for unauthorized access to those other services. If the other services include Git services, then again it may be possible to conduct supply-chain attacks on software maintained in Git. This also affects, for example, FileZilla before 3.67.0, WinSCP before 6.3.3, TortoiseGit before 2.15.0.1, and TortoiseSVN through 1.14.6.

- [https://github.com/HugoBond/CVE-2024-31497-POC](https://github.com/HugoBond/CVE-2024-31497-POC) :  ![starts](https://img.shields.io/github/stars/HugoBond/CVE-2024-31497-POC.svg) ![forks](https://img.shields.io/github/forks/HugoBond/CVE-2024-31497-POC.svg)


## CVE-2024-24787
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LOURC0D3/CVE-2024-24787-PoC](https://github.com/LOURC0D3/CVE-2024-24787-PoC) :  ![starts](https://img.shields.io/github/stars/LOURC0D3/CVE-2024-24787-PoC.svg) ![forks](https://img.shields.io/github/forks/LOURC0D3/CVE-2024-24787-PoC.svg)


## CVE-2024-3807
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc](https://github.com/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc.svg)


## CVE-2024-3806
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc](https://github.com/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-3806-AND-CVE-2024-3807-Poc.svg)


## CVE-2024-3431
 A vulnerability was found in EyouCMS 1.6.5. It has been declared as critical. This vulnerability affects unknown code of the file /login.php?m=admin&amp;c=Field&amp;a=channel_edit of the component Backend. The manipulation of the argument channel_id leads to deserialization. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-259612. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/3309899621/CVE-2024-34310](https://github.com/3309899621/CVE-2024-34310) :  ![starts](https://img.shields.io/github/stars/3309899621/CVE-2024-34310.svg) ![forks](https://img.shields.io/github/forks/3309899621/CVE-2024-34310.svg)


## CVE-2023-49606
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/rezardoss/CVE-2023-49606-Poc](https://github.com/rezardoss/CVE-2023-49606-Poc) :  ![starts](https://img.shields.io/github/stars/rezardoss/CVE-2023-49606-Poc.svg) ![forks](https://img.shields.io/github/forks/rezardoss/CVE-2023-49606-Poc.svg)


## CVE-2023-46870
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Chapoly1305/CVE-2023-46870](https://github.com/Chapoly1305/CVE-2023-46870) :  ![starts](https://img.shields.io/github/stars/Chapoly1305/CVE-2023-46870.svg) ![forks](https://img.shields.io/github/forks/Chapoly1305/CVE-2023-46870.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/rasan2001/CVE-2023-27350](https://github.com/rasan2001/CVE-2023-27350) :  ![starts](https://img.shields.io/github/stars/rasan2001/CVE-2023-27350.svg) ![forks](https://img.shields.io/github/forks/rasan2001/CVE-2023-27350.svg)


## CVE-2022-29072
 ** DISPUTED ** 7-Zip through 21.07 on Windows allows privilege escalation and command execution when a file with the .7z extension is dragged to the Help&gt;Contents area. This is caused by misconfiguration of 7z.dll and a heap overflow. The command runs in a child process under the 7zFM.exe process. NOTE: multiple third parties have reported that no privilege escalation can occur.

- [https://github.com/rasan2001/CVE-2022-29072](https://github.com/rasan2001/CVE-2022-29072) :  ![starts](https://img.shields.io/github/stars/rasan2001/CVE-2022-29072.svg) ![forks](https://img.shields.io/github/forks/rasan2001/CVE-2022-29072.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/blasty/CVE-2021-41773](https://github.com/blasty/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/blasty/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/blasty/CVE-2021-41773.svg)

