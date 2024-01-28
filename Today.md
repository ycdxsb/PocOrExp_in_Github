# Update 2024-01-28
## CVE-2023-47400
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LucasVanHaaren/CVE-2023-47400](https://github.com/LucasVanHaaren/CVE-2023-47400) :  ![starts](https://img.shields.io/github/stars/LucasVanHaaren/CVE-2023-47400.svg) ![forks](https://img.shields.io/github/forks/LucasVanHaaren/CVE-2023-47400.svg)


## CVE-2022-34729
 Windows GDI Elevation of Privilege Vulnerability

- [https://github.com/MagicPwnrin/CVE-2022-34729](https://github.com/MagicPwnrin/CVE-2022-34729) :  ![starts](https://img.shields.io/github/stars/MagicPwnrin/CVE-2022-34729.svg) ![forks](https://img.shields.io/github/forks/MagicPwnrin/CVE-2022-34729.svg)


## CVE-2022-30206
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/MagicPwnrin/CVE-2022-30206](https://github.com/MagicPwnrin/CVE-2022-30206) :  ![starts](https://img.shields.io/github/stars/MagicPwnrin/CVE-2022-30206.svg) ![forks](https://img.shields.io/github/forks/MagicPwnrin/CVE-2022-30206.svg)


## CVE-2022-28282
 By using a link with &lt;code&gt;rel=&quot;localization&quot;&lt;/code&gt; a use-after-free could have been triggered by destroying an object during JavaScript execution and then referencing the object through a freed pointer, leading to a potential exploitable crash. This vulnerability affects Thunderbird &lt; 91.8, Firefox &lt; 99, and Firefox ESR &lt; 91.8.

- [https://github.com/MagicPwnrin/CVE-2022-28282](https://github.com/MagicPwnrin/CVE-2022-28282) :  ![starts](https://img.shields.io/github/stars/MagicPwnrin/CVE-2022-28282.svg) ![forks](https://img.shields.io/github/forks/MagicPwnrin/CVE-2022-28282.svg)


## CVE-2022-3910
 Use After Free vulnerability in Linux Kernel allows Privilege Escalation. An improper Update of Reference Count in io_uring leads to Use-After-Free and Local Privilege Escalation. When io_msg_ring was invoked with a fixed file, it called io_fput_file() which improperly decreased its reference count (leading to Use-After-Free and Local Privilege Escalation). Fixed files are permanently registered to the ring, and should not be put separately. We recommend upgrading past commit https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679

- [https://github.com/veritas501/CVE-2022-3910](https://github.com/veritas501/CVE-2022-3910) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-3910.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-3910.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/scarmandef/CVE-2021-41773](https://github.com/scarmandef/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/scarmandef/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/scarmandef/CVE-2021-41773.svg)
- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/qwutony/CVE-2021-41773](https://github.com/qwutony/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/qwutony/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/qwutony/CVE-2021-41773.svg)
- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/locksec/CVE-2021-4034](https://github.com/locksec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/locksec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/locksec/CVE-2021-4034.svg)


## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

- [https://github.com/riptl/cve-2021-3449](https://github.com/riptl/cve-2021-3449) :  ![starts](https://img.shields.io/github/stars/riptl/cve-2021-3449.svg) ![forks](https://img.shields.io/github/forks/riptl/cve-2021-3449.svg)


## CVE-2021-2022
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/Lotus6/ConfluenceMemshell](https://github.com/Lotus6/ConfluenceMemshell) :  ![starts](https://img.shields.io/github/stars/Lotus6/ConfluenceMemshell.svg) ![forks](https://img.shields.io/github/forks/Lotus6/ConfluenceMemshell.svg)


## CVE-2019-1322
 An elevation of privilege vulnerability exists when Windows improperly handles authentication requests, aka 'Microsoft Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1320, CVE-2019-1340.

- [https://github.com/apt69/COMahawk](https://github.com/apt69/COMahawk) :  ![starts](https://img.shields.io/github/stars/apt69/COMahawk.svg) ![forks](https://img.shields.io/github/forks/apt69/COMahawk.svg)


## CVE-2018-9160
 SickRage before v2018.03.09-1 includes cleartext credentials in HTTP responses.

- [https://github.com/mechanico/sickrageWTF](https://github.com/mechanico/sickrageWTF) :  ![starts](https://img.shields.io/github/stars/mechanico/sickrageWTF.svg) ![forks](https://img.shields.io/github/forks/mechanico/sickrageWTF.svg)


## CVE-2017-16894
 In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.

- [https://github.com/H3dI/ENV-Mass-Exploit](https://github.com/H3dI/ENV-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/H3dI/ENV-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/H3dI/ENV-Mass-Exploit.svg)

