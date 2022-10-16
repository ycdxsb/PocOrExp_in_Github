# Update 2022-10-16
## CVE-2022-41852
 Those using JXPath to interpret untrusted XPath expressions may be vulnerable to a remote code execution attack. All JXPathContext class functions processing a XPath string are vulnerable except compile() and compilePath() function. The XPath expression can be used by an attacker to load any Java class from the classpath resulting in code execution.

- [https://github.com/Warxim/CVE-2022-41852](https://github.com/Warxim/CVE-2022-41852) :  ![starts](https://img.shields.io/github/stars/Warxim/CVE-2022-41852.svg) ![forks](https://img.shields.io/github/forks/Warxim/CVE-2022-41852.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/ITPATJIDR/CVE-2022-41040](https://github.com/ITPATJIDR/CVE-2022-41040) :  ![starts](https://img.shields.io/github/stars/ITPATJIDR/CVE-2022-41040.svg) ![forks](https://img.shields.io/github/forks/ITPATJIDR/CVE-2022-41040.svg)


## CVE-2022-40684
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Carl0sV1e1ra/CVE-2022-40684](https://github.com/Carl0sV1e1ra/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/Carl0sV1e1ra/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/Carl0sV1e1ra/CVE-2022-40684.svg)
- [https://github.com/mhd108/CVE-2022-40684](https://github.com/mhd108/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/mhd108/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/mhd108/CVE-2022-40684.svg)
- [https://github.com/iveresk/CVE-2022-40684](https://github.com/iveresk/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/iveresk/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/iveresk/CVE-2022-40684.svg)


## CVE-2022-40648
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of Ansys SpaceClaim 2022 R1. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of X_B files. The issue results from the lack of proper validation of user-supplied data, which can result in a write before the start of an allocated data structure. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-17563.

- [https://github.com/b3wT/CVE-2022-40648-MASS](https://github.com/b3wT/CVE-2022-40648-MASS) :  ![starts](https://img.shields.io/github/stars/b3wT/CVE-2022-40648-MASS.svg) ![forks](https://img.shields.io/github/forks/b3wT/CVE-2022-40648-MASS.svg)


## CVE-2022-37434
 zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).

- [https://github.com/xen0bit/CVE-2022-37434_poc](https://github.com/xen0bit/CVE-2022-37434_poc) :  ![starts](https://img.shields.io/github/stars/xen0bit/CVE-2022-37434_poc.svg) ![forks](https://img.shields.io/github/forks/xen0bit/CVE-2022-37434_poc.svg)


## CVE-2022-34298
 The NT auth module in OpenAM before 14.6.6 allows a &quot;replace Samba username attack.&quot;

- [https://github.com/watchtowrlabs/CVE-2022-34298](https://github.com/watchtowrlabs/CVE-2022-34298) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2022-34298.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2022-34298.svg)


## CVE-2022-2992
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Malwareman007/CVE-2022-2992](https://github.com/Malwareman007/CVE-2022-2992) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-2992.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-2992.svg)


## CVE-2020-1066
 An elevation of privilege vulnerability exists in .NET Framework which could allow an attacker to elevate their privilege level.To exploit the vulnerability, an attacker would first have to access the local machine, and then run a malicious program.The update addresses the vulnerability by correcting how .NET Framework activates COM objects., aka '.NET Framework Elevation of Privilege Vulnerability'.

- [https://github.com/xyddnljydd/cve-2020-1066](https://github.com/xyddnljydd/cve-2020-1066) :  ![starts](https://img.shields.io/github/stars/xyddnljydd/cve-2020-1066.svg) ![forks](https://img.shields.io/github/forks/xyddnljydd/cve-2020-1066.svg)


## CVE-2020-0557
 Insecure inherited permissions in Intel(R) PROSet/Wireless WiFi products before version 21.70 on Windows 10 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/hessandrew/CVE-2020-0557_INTEL-SA-00338](https://github.com/hessandrew/CVE-2020-0557_INTEL-SA-00338) :  ![starts](https://img.shields.io/github/stars/hessandrew/CVE-2020-0557_INTEL-SA-00338.svg) ![forks](https://img.shields.io/github/forks/hessandrew/CVE-2020-0557_INTEL-SA-00338.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/bukitbarisan/laravel-rce-cve-2018-15133](https://github.com/bukitbarisan/laravel-rce-cve-2018-15133) :  ![starts](https://img.shields.io/github/stars/bukitbarisan/laravel-rce-cve-2018-15133.svg) ![forks](https://img.shields.io/github/forks/bukitbarisan/laravel-rce-cve-2018-15133.svg)


## CVE-2017-1000117
 A malicious third-party can give a crafted &quot;ssh://...&quot; URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running &quot;git clone --recurse-submodules&quot; to trigger the vulnerability.

- [https://github.com/Q2h1Cg/CVE-2017-1000117](https://github.com/Q2h1Cg/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Q2h1Cg/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Q2h1Cg/CVE-2017-1000117.svg)
- [https://github.com/Jerry-zhuang/CVE-2017-1000117](https://github.com/Jerry-zhuang/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Jerry-zhuang/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Jerry-zhuang/CVE-2017-1000117.svg)


## CVE-2016-0856
 Multiple stack-based buffer overflows in Advantech WebAccess before 8.1 allow remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/readloud/PoC](https://github.com/readloud/PoC) :  ![starts](https://img.shields.io/github/stars/readloud/PoC.svg) ![forks](https://img.shields.io/github/forks/readloud/PoC.svg)

