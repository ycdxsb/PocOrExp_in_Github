# Update 2024-06-04
## CVE-2024-34958
 idccms v1.35 was discovered to contain a Cross-Site Request Forgery (CSRF) via the component admin/banner_deal.php?mudi=add

- [https://github.com/Gr-1m/CVE-2024-34958](https://github.com/Gr-1m/CVE-2024-34958) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2024-34958.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2024-34958.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/Basyaact/CVE-2024-32002-PoC_Chinese](https://github.com/Basyaact/CVE-2024-32002-PoC_Chinese) :  ![starts](https://img.shields.io/github/stars/Basyaact/CVE-2024-32002-PoC_Chinese.svg) ![forks](https://img.shields.io/github/forks/Basyaact/CVE-2024-32002-PoC_Chinese.svg)
- [https://github.com/431m/rcetest](https://github.com/431m/rcetest) :  ![starts](https://img.shields.io/github/stars/431m/rcetest.svg) ![forks](https://img.shields.io/github/forks/431m/rcetest.svg)


## CVE-2024-24919
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/mr-kasim-mehar/CVE-2024-24919-Exploit](https://github.com/mr-kasim-mehar/CVE-2024-24919-Exploit) :  ![starts](https://img.shields.io/github/stars/mr-kasim-mehar/CVE-2024-24919-Exploit.svg) ![forks](https://img.shields.io/github/forks/mr-kasim-mehar/CVE-2024-24919-Exploit.svg)
- [https://github.com/J4F9S5D2Q7/CVE-2024-24919](https://github.com/J4F9S5D2Q7/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/J4F9S5D2Q7/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/J4F9S5D2Q7/CVE-2024-24919.svg)
- [https://github.com/Expl0itD0g/CVE-2024-24919---Poc](https://github.com/Expl0itD0g/CVE-2024-24919---Poc) :  ![starts](https://img.shields.io/github/stars/Expl0itD0g/CVE-2024-24919---Poc.svg) ![forks](https://img.shields.io/github/forks/Expl0itD0g/CVE-2024-24919---Poc.svg)
- [https://github.com/B1naryo/CVE-2024-24919-POC](https://github.com/B1naryo/CVE-2024-24919-POC) :  ![starts](https://img.shields.io/github/stars/B1naryo/CVE-2024-24919-POC.svg) ![forks](https://img.shields.io/github/forks/B1naryo/CVE-2024-24919-POC.svg)
- [https://github.com/bigb0x/CVE-2024-24919-Sniper](https://github.com/bigb0x/CVE-2024-24919-Sniper) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-24919-Sniper.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-24919-Sniper.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/Cappricio-Securities/CVE-2024-4956](https://github.com/Cappricio-Securities/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2024-4956.svg)


## CVE-2023-6702
 Type confusion in V8 in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/kaist-hacking/CVE-2023-6702](https://github.com/kaist-hacking/CVE-2023-6702) :  ![starts](https://img.shields.io/github/stars/kaist-hacking/CVE-2023-6702.svg) ![forks](https://img.shields.io/github/forks/kaist-hacking/CVE-2023-6702.svg)


## CVE-2022-37706
 enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.

- [https://github.com/junnythemarksman/CVE-2022-37706](https://github.com/junnythemarksman/CVE-2022-37706) :  ![starts](https://img.shields.io/github/stars/junnythemarksman/CVE-2022-37706.svg) ![forks](https://img.shields.io/github/forks/junnythemarksman/CVE-2022-37706.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Maybe4a6f7365/CVE-2021-41773](https://github.com/Maybe4a6f7365/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Maybe4a6f7365/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Maybe4a6f7365/CVE-2021-41773.svg)


## CVE-2017-8759
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka &quot;.NET Framework Remote Code Execution Vulnerability.&quot;

- [https://github.com/sythass/CVE-2017-8759](https://github.com/sythass/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/sythass/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/sythass/CVE-2017-8759.svg)


## CVE-2008-4250
 The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka &quot;Server Service Vulnerability.&quot;

- [https://github.com/pxcs/CVE-29343-Sysmon-list](https://github.com/pxcs/CVE-29343-Sysmon-list) :  ![starts](https://img.shields.io/github/stars/pxcs/CVE-29343-Sysmon-list.svg) ![forks](https://img.shields.io/github/forks/pxcs/CVE-29343-Sysmon-list.svg)

