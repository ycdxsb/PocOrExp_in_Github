# Update 2023-05-24
## CVE-2023-31726
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/J6451/CVE-2023-31726](https://github.com/J6451/CVE-2023-31726) :  ![starts](https://img.shields.io/github/stars/J6451/CVE-2023-31726.svg) ![forks](https://img.shields.io/github/forks/J6451/CVE-2023-31726.svg)


## CVE-2023-28771
 Improper error message handling in Zyxel ZyWALL/USG series firmware versions 4.60 through 4.73, VPN series firmware versions 4.60 through 5.35, USG FLEX series firmware versions 4.60 through 5.35, and ATP series firmware versions 4.60 through 5.35, which could allow an unauthenticated attacker to execute some OS commands remotely by sending crafted packets to an affected device.

- [https://github.com/BenHays142/CVE-2023-28771-PoC](https://github.com/BenHays142/CVE-2023-28771-PoC) :  ![starts](https://img.shields.io/github/stars/BenHays142/CVE-2023-28771-PoC.svg) ![forks](https://img.shields.io/github/forks/BenHays142/CVE-2023-28771-PoC.svg)


## CVE-2023-20052
 On Feb 15, 2023, the following vulnerability in the ClamAV scanning library was disclosed: A vulnerability in the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and earlier could allow an unauthenticated, remote attacker to access sensitive information on an affected device. This vulnerability is due to enabling XML entity substitution that may result in XML external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file that may be read by the ClamAV scanning process.

- [https://github.com/nokn0wthing/CVE-2023-20052](https://github.com/nokn0wthing/CVE-2023-20052) :  ![starts](https://img.shields.io/github/stars/nokn0wthing/CVE-2023-20052.svg) ![forks](https://img.shields.io/github/forks/nokn0wthing/CVE-2023-20052.svg)


## CVE-2022-4395
 The Membership For WooCommerce WordPress plugin before 2.1.7 does not validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as malicious PHP code, and achieve RCE.

- [https://github.com/MrG3P5/CVE-2022-4395](https://github.com/MrG3P5/CVE-2022-4395) :  ![starts](https://img.shields.io/github/stars/MrG3P5/CVE-2022-4395.svg) ![forks](https://img.shields.io/github/forks/MrG3P5/CVE-2022-4395.svg)


## CVE-2021-42694
 ** DISPUTED ** An issue was discovered in the character definitions of the Unicode Specification through 14.0. The specification allows an adversary to produce source code identifiers such as function names using homoglyphs that render visually identical to a target identifier. Adversaries can leverage this to inject code via adversarial identifier definitions in upstream software dependencies invoked deceptively in downstream software. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard (all versions). Unless mitigated, an adversary could produce source code identifiers using homoglyph characters that render visually identical to but are distinct from a target identifier. In this way, an adversary could inject adversarial identifier definitions in upstream software that are not detected by human reviewers and are invoked deceptively in downstream software. The Unicode Consortium has documented this class of security vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms.

- [https://github.com/simplylu/CVE-2021-42694](https://github.com/simplylu/CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/simplylu/CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/simplylu/CVE-2021-42694.svg)


## CVE-2021-42574
 ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard and the Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-right and right-to-left characters, the visual order of tokens may be different from their logical order. Additionally, control characters needed to fully support the requirements of bidirectional text can further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such that the ordering of tokens perceived by human reviewers does not match what will be processed by a compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.

- [https://github.com/simplylu/CVE-2021-42574](https://github.com/simplylu/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/simplylu/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/simplylu/CVE-2021-42574.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2020-15416
 This vulnerability allows network-adjacent attackers to bypass authentication on affected installations of NETGEAR R6700 V1.0.4.84_10.0.58 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the httpd service, which listens on TCP port 80 by default. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length, stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-9703.

- [https://github.com/k3vinlusec/R7000_httpd_BOF_CVE-2020-15416](https://github.com/k3vinlusec/R7000_httpd_BOF_CVE-2020-15416) :  ![starts](https://img.shields.io/github/stars/k3vinlusec/R7000_httpd_BOF_CVE-2020-15416.svg) ![forks](https://img.shields.io/github/forks/k3vinlusec/R7000_httpd_BOF_CVE-2020-15416.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/k3vinlusec/WhatsApp-Double-Free-Vulnerability_CVE-2019-11932](https://github.com/k3vinlusec/WhatsApp-Double-Free-Vulnerability_CVE-2019-11932) :  ![starts](https://img.shields.io/github/stars/k3vinlusec/WhatsApp-Double-Free-Vulnerability_CVE-2019-11932.svg) ![forks](https://img.shields.io/github/forks/k3vinlusec/WhatsApp-Double-Free-Vulnerability_CVE-2019-11932.svg)


## CVE-2018-8172
 A remote code execution vulnerability exists in Visual Studio software when the software does not check the source markup of a file for an unbuilt project, aka &quot;Visual Studio Remote Code Execution Vulnerability.&quot; This affects Microsoft Visual Studio, Expression Blend 4.

- [https://github.com/SyFi/CVE-2018-8172](https://github.com/SyFi/CVE-2018-8172) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2018-8172.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2018-8172.svg)


## CVE-2017-1000405
 The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a COW cycle. This bug is not as severe as the original &quot;Dirty cow&quot; because an ext4 file (or any other regular file) cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.

- [https://github.com/bindecy/HugeDirtyCowPOC](https://github.com/bindecy/HugeDirtyCowPOC) :  ![starts](https://img.shields.io/github/stars/bindecy/HugeDirtyCowPOC.svg) ![forks](https://img.shields.io/github/forks/bindecy/HugeDirtyCowPOC.svg)


## CVE-2014-1812
 The Group Policy implementation in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 does not properly handle distribution of passwords, which allows remote authenticated users to obtain sensitive credential information and consequently gain privileges by leveraging access to the SYSVOL share, as exploited in the wild in May 2014, aka &quot;Group Policy Preferences Password Elevation of Privilege Vulnerability.&quot;

- [https://github.com/mauricelambert/gpp-encrypt](https://github.com/mauricelambert/gpp-encrypt) :  ![starts](https://img.shields.io/github/stars/mauricelambert/gpp-encrypt.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/gpp-encrypt.svg)

