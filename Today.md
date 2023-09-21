# Update 2023-09-21
## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/elefantesagradodeluzinfinita/cve-2023-38831](https://github.com/elefantesagradodeluzinfinita/cve-2023-38831) :  ![starts](https://img.shields.io/github/stars/elefantesagradodeluzinfinita/cve-2023-38831.svg) ![forks](https://img.shields.io/github/forks/elefantesagradodeluzinfinita/cve-2023-38831.svg)


## CVE-2023-36844
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series allows an unauthenticated, network-based attacker to control certain, important environments variables. Utilizing a crafted request an attacker is able to modify certain PHP environments variables leading to partial loss of integrity, which may allow chaining to other vulnerabilities. This issue affects Juniper Networks Junos OS on EX Series: * All versions prior to 20.4R3-S9; * 21.2 versions prior to 21.2R3-S6; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R3-S1; * 22.4 versions prior to 22.4R2-S2, 22.4R3.

- [https://github.com/Pari-Malam/CVE-2023-36844](https://github.com/Pari-Malam/CVE-2023-36844) :  ![starts](https://img.shields.io/github/stars/Pari-Malam/CVE-2023-36844.svg) ![forks](https://img.shields.io/github/forks/Pari-Malam/CVE-2023-36844.svg)


## CVE-2023-36319
 File Upload vulnerability in Openupload Stable v.0.4.3 allows a remote attacker to execute arbitrary code via the action parameter of the compress-inc.php file.

- [https://github.com/Lowalu/CVE-2023-36319](https://github.com/Lowalu/CVE-2023-36319) :  ![starts](https://img.shields.io/github/stars/Lowalu/CVE-2023-36319.svg) ![forks](https://img.shields.io/github/forks/Lowalu/CVE-2023-36319.svg)


## CVE-2023-4128
 A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue.

- [https://github.com/nidhi7598/linux-4.19.72_CVE-2023-4128](https://github.com/nidhi7598/linux-4.19.72_CVE-2023-4128) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.19.72_CVE-2023-4128.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.19.72_CVE-2023-4128.svg)


## CVE-2023-0255
 The Enable Media Replace WordPress plugin before 4.0.2 does not prevent authors from uploading arbitrary files to the site, which may allow them to upload PHP shells on affected sites.

- [https://github.com/codeb0ss/CVE-2023-0255-PoC](https://github.com/codeb0ss/CVE-2023-0255-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-0255-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-0255-PoC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2020-9715
 Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier, and 2015.006.30523 and earlier have an use-after-free vulnerability. Successful exploitation could lead to arbitrary code execution .

- [https://github.com/wonjunchun/CVE-2020-9715](https://github.com/wonjunchun/CVE-2020-9715) :  ![starts](https://img.shields.io/github/stars/wonjunchun/CVE-2020-9715.svg) ![forks](https://img.shields.io/github/forks/wonjunchun/CVE-2020-9715.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/brompwnie/CVE-2019-5418-Scanner](https://github.com/brompwnie/CVE-2019-5418-Scanner) :  ![starts](https://img.shields.io/github/stars/brompwnie/CVE-2019-5418-Scanner.svg) ![forks](https://img.shields.io/github/forks/brompwnie/CVE-2019-5418-Scanner.svg)
- [https://github.com/ztgrace/CVE-2019-5418-Rails3](https://github.com/ztgrace/CVE-2019-5418-Rails3) :  ![starts](https://img.shields.io/github/stars/ztgrace/CVE-2019-5418-Rails3.svg) ![forks](https://img.shields.io/github/forks/ztgrace/CVE-2019-5418-Rails3.svg)


## CVE-2018-1335
 From Apache Tika versions 1.7 to 1.17, clients could send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients. The mitigation is to upgrade to Tika 1.18.

- [https://github.com/Zebra64/CVE-2018-1335](https://github.com/Zebra64/CVE-2018-1335) :  ![starts](https://img.shields.io/github/stars/Zebra64/CVE-2018-1335.svg) ![forks](https://img.shields.io/github/forks/Zebra64/CVE-2018-1335.svg)


## CVE-2017-17562
 Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.

- [https://github.com/nu11pointer/goahead-rce-exploit](https://github.com/nu11pointer/goahead-rce-exploit) :  ![starts](https://img.shields.io/github/stars/nu11pointer/goahead-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/nu11pointer/goahead-rce-exploit.svg)

