# Update 2025-03-04
## CVE-2023-1488
 A vulnerability, which was classified as problematic, was found in Lespeed WiseCleaner Wise System Monitor 1.5.3.54. Affected is the function 0x9C40A0D8/0x9C40A0DC/0x9C40A0E0 in the library WiseHDInfo64.dll of the component IoControlCode Handler. The manipulation leads to denial of service. It is possible to launch the attack on the local host. The exploit has been disclosed to the public and may be used. VDB-223374 is the identifier assigned to this vulnerability.

- [https://github.com/sqqrky/CVE-2023-1488](https://github.com/sqqrky/CVE-2023-1488) :  ![starts](https://img.shields.io/github/stars/sqqrky/CVE-2023-1488.svg) ![forks](https://img.shields.io/github/forks/sqqrky/CVE-2023-1488.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/yeep1115/ICT287_CVE-2022-30190_Exploit](https://github.com/yeep1115/ICT287_CVE-2022-30190_Exploit) :  ![starts](https://img.shields.io/github/stars/yeep1115/ICT287_CVE-2022-30190_Exploit.svg) ![forks](https://img.shields.io/github/forks/yeep1115/ICT287_CVE-2022-30190_Exploit.svg)


## CVE-2020-35391
 Tenda N300 F3 12.01.01.48 devices allow remote attackers to obtain sensitive information (possibly including an http_passwd line) via a direct request for cgi-bin/DownloadCfg/RouterCfm.cfg, a related issue to CVE-2017-14942. NOTE: the vulnerability report may suggest that either a ? character must be placed after the RouterCfm.cfg filename, or that the HTTP request headers must be unusual, but it is not known why these are relevant to the device's HTTP response behavior.

- [https://github.com/4d000/Tenda-F3-V4](https://github.com/4d000/Tenda-F3-V4) :  ![starts](https://img.shields.io/github/stars/4d000/Tenda-F3-V4.svg) ![forks](https://img.shields.io/github/forks/4d000/Tenda-F3-V4.svg)


## CVE-2020-17519
 A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.

- [https://github.com/GazettEl/CVE-2020-17519](https://github.com/GazettEl/CVE-2020-17519) :  ![starts](https://img.shields.io/github/stars/GazettEl/CVE-2020-17519.svg) ![forks](https://img.shields.io/github/forks/GazettEl/CVE-2020-17519.svg)


## CVE-2019-0678
 An elevation of privilege vulnerability exists when Microsoft Edge does not properly enforce cross-domain policies, which could allow an attacker to access information from one domain and inject it into another domain.In a web-based attack scenario, an attacker could host a website that is used to attempt to exploit the vulnerability, aka 'Microsoft Edge Elevation of Privilege Vulnerability'.

- [https://github.com/sandi-go/CVE-2019-0678](https://github.com/sandi-go/CVE-2019-0678) :  ![starts](https://img.shields.io/github/stars/sandi-go/CVE-2019-0678.svg) ![forks](https://img.shields.io/github/forks/sandi-go/CVE-2019-0678.svg)


## CVE-2018-15968
 Adobe Acrobat and Reader versions 2018.011.20063 and earlier, 2017.011.30102 and earlier, and 2015.006.30452 and earlier have an out-of-bounds read vulnerability. Successful exploitation could lead to information disclosure.

- [https://github.com/sandi-go/cve-2018-15968](https://github.com/sandi-go/cve-2018-15968) :  ![starts](https://img.shields.io/github/stars/sandi-go/cve-2018-15968.svg) ![forks](https://img.shields.io/github/forks/sandi-go/cve-2018-15968.svg)


## CVE-2018-14442
 Foxit Reader before 9.2 and PhantomPDF before 9.2 have a Use-After-Free that leads to Remote Code Execution, aka V-88f4smlocs.

- [https://github.com/sandi-go/PS-2018-002---CVE-2018-14442](https://github.com/sandi-go/PS-2018-002---CVE-2018-14442) :  ![starts](https://img.shields.io/github/stars/sandi-go/PS-2018-002---CVE-2018-14442.svg) ![forks](https://img.shields.io/github/forks/sandi-go/PS-2018-002---CVE-2018-14442.svg)


## CVE-2018-12798
 Adobe Acrobat and Reader 2018.011.20040 and earlier, 2017.011.30080 and earlier, and 2015.006.30418 and earlier versions have a Heap Overflow vulnerability. Successful exploitation could lead to arbitrary code execution in the context of the current user.

- [https://github.com/sandi-go/cve-2018-12798](https://github.com/sandi-go/cve-2018-12798) :  ![starts](https://img.shields.io/github/stars/sandi-go/cve-2018-12798.svg) ![forks](https://img.shields.io/github/forks/sandi-go/cve-2018-12798.svg)


## CVE-2018-9951
 This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of CPDF_Object objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-5414.

- [https://github.com/sandi-go/cve-2018-9951](https://github.com/sandi-go/cve-2018-9951) :  ![starts](https://img.shields.io/github/stars/sandi-go/cve-2018-9951.svg) ![forks](https://img.shields.io/github/forks/sandi-go/cve-2018-9951.svg)


## CVE-2018-9950
 This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF documents. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the current process. Was ZDI-CAN-5413.

- [https://github.com/sandi-go/PS-2017-13---CVE-2018-9950](https://github.com/sandi-go/PS-2017-13---CVE-2018-9950) :  ![starts](https://img.shields.io/github/stars/sandi-go/PS-2017-13---CVE-2018-9950.svg) ![forks](https://img.shields.io/github/forks/sandi-go/PS-2017-13---CVE-2018-9950.svg)


## CVE-2018-8389
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka "Scripting Engine Memory Corruption Vulnerability." This affects Internet Explorer 9, Internet Explorer 11, Internet Explorer 10. This CVE ID is unique from CVE-2018-8353, CVE-2018-8355, CVE-2018-8359, CVE-2018-8371, CVE-2018-8372, CVE-2018-8373, CVE-2018-8385, CVE-2018-8390.

- [https://github.com/sandi-go/cve-2018-8389](https://github.com/sandi-go/cve-2018-8389) :  ![starts](https://img.shields.io/github/stars/sandi-go/cve-2018-8389.svg) ![forks](https://img.shields.io/github/forks/sandi-go/cve-2018-8389.svg)

