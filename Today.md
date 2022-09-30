# Update 2022-09-30
## CVE-2022-40916
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/whitej3rry/CVE-2022-40916](https://github.com/whitej3rry/CVE-2022-40916) :  ![starts](https://img.shields.io/github/stars/whitej3rry/CVE-2022-40916.svg) ![forks](https://img.shields.io/github/forks/whitej3rry/CVE-2022-40916.svg)


## CVE-2022-40490
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/whitej3rry/CVE-2022-40490](https://github.com/whitej3rry/CVE-2022-40490) :  ![starts](https://img.shields.io/github/stars/whitej3rry/CVE-2022-40490.svg) ![forks](https://img.shields.io/github/forks/whitej3rry/CVE-2022-40490.svg)


## CVE-2022-36934
 An integer overflow in WhatsApp could result in remote code execution in an established video call.

- [https://github.com/F1uk369/CVE-2022-36934](https://github.com/F1uk369/CVE-2022-36934) :  ![starts](https://img.shields.io/github/stars/F1uk369/CVE-2022-36934.svg) ![forks](https://img.shields.io/github/forks/F1uk369/CVE-2022-36934.svg)
- [https://github.com/d4rk0x00/CVE-2022-36934-POC](https://github.com/d4rk0x00/CVE-2022-36934-POC) :  ![starts](https://img.shields.io/github/stars/d4rk0x00/CVE-2022-36934-POC.svg) ![forks](https://img.shields.io/github/forks/d4rk0x00/CVE-2022-36934-POC.svg)


## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/Xu0Tex1/CVE-2022-32548-RCE-POC](https://github.com/Xu0Tex1/CVE-2022-32548-RCE-POC) :  ![starts](https://img.shields.io/github/stars/Xu0Tex1/CVE-2022-32548-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/Xu0Tex1/CVE-2022-32548-RCE-POC.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/flux10n/CVE-2022-30190](https://github.com/flux10n/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/flux10n/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/flux10n/CVE-2022-30190.svg)


## CVE-2022-3236
 A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

- [https://github.com/Xu0Tex1/CVE-2022-3236](https://github.com/Xu0Tex1/CVE-2022-3236) :  ![starts](https://img.shields.io/github/stars/Xu0Tex1/CVE-2022-3236.svg) ![forks](https://img.shields.io/github/forks/Xu0Tex1/CVE-2022-3236.svg)
- [https://github.com/Ziggy78/CVE-2022-3236-RCE-POC](https://github.com/Ziggy78/CVE-2022-3236-RCE-POC) :  ![starts](https://img.shields.io/github/stars/Ziggy78/CVE-2022-3236-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/Ziggy78/CVE-2022-3236-RCE-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/ruifi47/cve-2021-21300-PoC](https://github.com/ruifi47/cve-2021-21300-PoC) :  ![starts](https://img.shields.io/github/stars/ruifi47/cve-2021-21300-PoC.svg) ![forks](https://img.shields.io/github/forks/ruifi47/cve-2021-21300-PoC.svg)


## CVE-2020-12928
 A vulnerability in a dynamically loaded AMD driver in AMD Ryzen Master V15 may allow any authenticated user to escalate privileges to NT authority system.

- [https://github.com/ekknod/AmdRyzenMasterCheat](https://github.com/ekknod/AmdRyzenMasterCheat) :  ![starts](https://img.shields.io/github/stars/ekknod/AmdRyzenMasterCheat.svg) ![forks](https://img.shields.io/github/forks/ekknod/AmdRyzenMasterCheat.svg)


## CVE-2018-25032
 zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches.

- [https://github.com/Trinadh465/external_zlib_4.4_CVE-2018-25032](https://github.com/Trinadh465/external_zlib_4.4_CVE-2018-25032) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_zlib_4.4_CVE-2018-25032.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_zlib_4.4_CVE-2018-25032.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/awesome-consumer-iot/HTC](https://github.com/awesome-consumer-iot/HTC) :  ![starts](https://img.shields.io/github/stars/awesome-consumer-iot/HTC.svg) ![forks](https://img.shields.io/github/forks/awesome-consumer-iot/HTC.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Bj0rn-gungnir/cve2018-6574-gogetRCE](https://github.com/Bj0rn-gungnir/cve2018-6574-gogetRCE) :  ![starts](https://img.shields.io/github/stars/Bj0rn-gungnir/cve2018-6574-gogetRCE.svg) ![forks](https://img.shields.io/github/forks/Bj0rn-gungnir/cve2018-6574-gogetRCE.svg)


## CVE-2008-4609
 The TCP implementation in (1) Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4) Cisco products, and probably other operating systems allows remote attackers to cause a denial of service (connection queue exhaustion) via multiple vectors that manipulate information in the TCP state table, as demonstrated by sockstress.

- [https://github.com/mrclki/sockstress](https://github.com/mrclki/sockstress) :  ![starts](https://img.shields.io/github/stars/mrclki/sockstress.svg) ![forks](https://img.shields.io/github/forks/mrclki/sockstress.svg)

