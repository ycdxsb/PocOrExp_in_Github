# Update 2024-10-17
## CVE-2024-38816
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Galaxy-system/cve-2024-38816](https://github.com/Galaxy-system/cve-2024-38816) :  ![starts](https://img.shields.io/github/stars/Galaxy-system/cve-2024-38816.svg) ![forks](https://img.shields.io/github/forks/Galaxy-system/cve-2024-38816.svg)


## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/thanawee321/CVE-2024-38063](https://github.com/thanawee321/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/thanawee321/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/thanawee321/CVE-2024-38063.svg)


## CVE-2024-37084
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Ly4j/CVE-2024-37084-Exp](https://github.com/Ly4j/CVE-2024-37084-Exp) :  ![starts](https://img.shields.io/github/stars/Ly4j/CVE-2024-37084-Exp.svg) ![forks](https://img.shields.io/github/forks/Ly4j/CVE-2024-37084-Exp.svg)
- [https://github.com/A0be/CVE-2024-37084-Exp](https://github.com/A0be/CVE-2024-37084-Exp) :  ![starts](https://img.shields.io/github/stars/A0be/CVE-2024-37084-Exp.svg) ![forks](https://img.shields.io/github/forks/A0be/CVE-2024-37084-Exp.svg)


## CVE-2024-36842
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-](https://github.com/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-) :  ![starts](https://img.shields.io/github/stars/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-.svg) ![forks](https://img.shields.io/github/forks/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-.svg)


## CVE-2024-24686
 Multiple stack-based buffer overflow vulnerabilities exist in the readOFF functionality of libigl v2.5.0. A specially crafted .off file can lead to stack-based buffer overflow. An attacker can provide a malicious file to trigger this vulnerability.This vulnerability concerns the parsing of comments within the faces section of an `.off` file processed via the `readOFF` function.

- [https://github.com/SpiralBL0CK/CVE-2024-24686](https://github.com/SpiralBL0CK/CVE-2024-24686) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-24686.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-24686.svg)


## CVE-2024-24685
 Multiple stack-based buffer overflow vulnerabilities exist in the readOFF functionality of libigl v2.5.0. A specially crafted .off file can lead to stack-based buffer overflow. An attacker can provide a malicious file to trigger this vulnerability.This vulnerability concerns the parsing of comments within the vertex section of an `.off` file processed via the `readOFF` function.

- [https://github.com/SpiralBL0CK/CVE-2024-24685](https://github.com/SpiralBL0CK/CVE-2024-24685) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-24685.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-24685.svg)


## CVE-2024-24684
 Multiple stack-based buffer overflow vulnerabilities exist in the readOFF functionality of libigl v2.5.0. A specially crafted .off file can lead to stack-based buffer overflow. An attacker can provide a malicious file to trigger this vulnerability.This vulnerability concerns the header parsing occuring while processing an `.off` file via the `readOFF` function. We can see above that at [0] a stack-based buffer called `comment` is defined with an hardcoded size of `1000 bytes`. The call to `fscanf` at [1] is unsafe and if the first line of the header of the `.off` files is longer than 1000 bytes it will overflow the `header` buffer.

- [https://github.com/SpiralBL0CK/CVE-2024-24684](https://github.com/SpiralBL0CK/CVE-2024-24684) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-24684.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-24684.svg)


## CVE-2024-4433
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Mr Digital Simple Image Popup allows Stored XSS.This issue affects Simple Image Popup: from n/a through 2.4.0.

- [https://github.com/Brinmon/CVE-2024-44337](https://github.com/Brinmon/CVE-2024-44337) :  ![starts](https://img.shields.io/github/stars/Brinmon/CVE-2024-44337.svg) ![forks](https://img.shields.io/github/forks/Brinmon/CVE-2024-44337.svg)


## CVE-2023-50564
 An arbitrary file upload vulnerability in the component /inc/modules_install.php of Pluck-CMS v4.7.18 allows attackers to execute arbitrary code via uploading a crafted ZIP file.

- [https://github.com/Mrterrestrial/CVE-2023-50564](https://github.com/Mrterrestrial/CVE-2023-50564) :  ![starts](https://img.shields.io/github/stars/Mrterrestrial/CVE-2023-50564.svg) ![forks](https://img.shields.io/github/forks/Mrterrestrial/CVE-2023-50564.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/idkwastaken/CVE-2023-38831](https://github.com/idkwastaken/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/idkwastaken/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/idkwastaken/CVE-2023-38831.svg)


## CVE-2023-35674
 In onCreate of WindowState.java, there is a possible way to launch a background activity due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/SpiralBL0CK/Guide-and-theoretical-code-for-CVE-2023-35674](https://github.com/SpiralBL0CK/Guide-and-theoretical-code-for-CVE-2023-35674) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/Guide-and-theoretical-code-for-CVE-2023-35674.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/Guide-and-theoretical-code-for-CVE-2023-35674.svg)


## CVE-2023-32560
 An attacker can send a specially crafted message to the Wavelink Avalanche Manager, which could result in service disruption or arbitrary code execution. Thanks to a Researcher at Tenable for finding and reporting. Fixed in version 6.4.1.

- [https://github.com/idkwastaken/CVE-2023-32560](https://github.com/idkwastaken/CVE-2023-32560) :  ![starts](https://img.shields.io/github/stars/idkwastaken/CVE-2023-32560.svg) ![forks](https://img.shields.io/github/forks/idkwastaken/CVE-2023-32560.svg)


## CVE-2023-25581
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/p33d/CVE-2023-25581](https://github.com/p33d/CVE-2023-25581) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2023-25581.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2023-25581.svg)


## CVE-2022-24439
 All versions of package gitpython are vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. Exploiting this vulnerability is possible because the library makes external calls to git without sufficient sanitization of input arguments.

- [https://github.com/muhammadhendro/CVE-2022-24439](https://github.com/muhammadhendro/CVE-2022-24439) :  ![starts](https://img.shields.io/github/stars/muhammadhendro/CVE-2022-24439.svg) ![forks](https://img.shields.io/github/forks/muhammadhendro/CVE-2022-24439.svg)


## CVE-2022-1015
 A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem. This flaw allows a local user to cause an out-of-bounds write issue.

- [https://github.com/hoanghailongvn/CVE-2022-1015](https://github.com/hoanghailongvn/CVE-2022-1015) :  ![starts](https://img.shields.io/github/stars/hoanghailongvn/CVE-2022-1015.svg) ![forks](https://img.shields.io/github/forks/hoanghailongvn/CVE-2022-1015.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/nwclasantha/Apache_2.4.29_Exploit](https://github.com/nwclasantha/Apache_2.4.29_Exploit) :  ![starts](https://img.shields.io/github/stars/nwclasantha/Apache_2.4.29_Exploit.svg) ![forks](https://img.shields.io/github/forks/nwclasantha/Apache_2.4.29_Exploit.svg)

