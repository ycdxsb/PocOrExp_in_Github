# Update 2025-02-27
## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/iSee857/CVE-2025-24893-PoC](https://github.com/iSee857/CVE-2025-24893-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-24893-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-24893-PoC.svg)


## CVE-2025-24104
 This issue was addressed with improved handling of symlinks. This issue is fixed in iPadOS 17.7.4, iOS 18.3 and iPadOS 18.3. Restoring a maliciously crafted backup file may lead to modification of protected system files.

- [https://github.com/ifpdz/CVE-2025-24104](https://github.com/ifpdz/CVE-2025-24104) :  ![starts](https://img.shields.io/github/stars/ifpdz/CVE-2025-24104.svg) ![forks](https://img.shields.io/github/forks/ifpdz/CVE-2025-24104.svg)


## CVE-2025-23942
 Unrestricted Upload of File with Dangerous Type vulnerability in NgocCode WP Load Gallery allows Upload a Web Shell to a Web Server. This issue affects WP Load Gallery: from n/a through 2.1.6.

- [https://github.com/Nxploited/CVE-2025-23942-poc](https://github.com/Nxploited/CVE-2025-23942-poc) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-23942-poc.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-23942-poc.svg)


## CVE-2025-1302
This is caused by an incomplete fix for [CVE-2024-21534](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-7945884).

- [https://github.com/EQSTLab/CVE-2025-1302](https://github.com/EQSTLab/CVE-2025-1302) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-1302.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-1302.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/44xo/CVE-2025-0282](https://github.com/44xo/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/44xo/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/44xo/CVE-2025-0282.svg)


## CVE-2024-23346
 Pymatgen (Python Materials Genomics) is an open-source Python library for materials analysis. A critical security vulnerability exists in the `JonesFaithfulTransformation.from_transformation_str()` method within the `pymatgen` library prior to version 2024.2.20. This method insecurely utilizes `eval()` for processing input, enabling execution of arbitrary code when parsing untrusted input. Version 2024.2.20 fixes this issue.

- [https://github.com/szyth/CVE-2024-23346-rust-exploit](https://github.com/szyth/CVE-2024-23346-rust-exploit) :  ![starts](https://img.shields.io/github/stars/szyth/CVE-2024-23346-rust-exploit.svg) ![forks](https://img.shields.io/github/forks/szyth/CVE-2024-23346-rust-exploit.svg)


## CVE-2023-36845
  *  23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/meekchest/cve-2023-36845-scanner](https://github.com/meekchest/cve-2023-36845-scanner) :  ![starts](https://img.shields.io/github/stars/meekchest/cve-2023-36845-scanner.svg) ![forks](https://img.shields.io/github/forks/meekchest/cve-2023-36845-scanner.svg)


## CVE-2023-28121
 An issue in WooCommerce Payments plugin for WordPress (versions 5.6.1 and lower) allows an unauthenticated attacker to send requests on behalf of an elevated user, like administrator. This allows a remote, unauthenticated attacker to gain admin access on a site that has the affected version of the plugin activated.

- [https://github.com/sug4r-wr41th/CVE-2023-28121](https://github.com/sug4r-wr41th/CVE-2023-28121) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2023-28121.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2023-28121.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/sameep0/CVE-2021-22204](https://github.com/sameep0/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/sameep0/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/sameep0/CVE-2021-22204.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/monjheta/CVE-2020-0796](https://github.com/monjheta/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/monjheta/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/monjheta/CVE-2020-0796.svg)


## CVE-2018-0202
 clamscan in ClamAV before 0.99.4 contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to improper input validation checking mechanisms when handling Portable Document Format (.pdf) files sent to an affected device. An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted .pdf file to an affected device. This action could cause an out-of-bounds read when ClamAV scans the malicious file, allowing the attacker to cause a DoS condition. This concerns pdf_parse_array and pdf_parse_string in libclamav/pdfng.c. Cisco Bug IDs: CSCvh91380, CSCvh91400.

- [https://github.com/jcjjaidigital/CVE-2018-0202](https://github.com/jcjjaidigital/CVE-2018-0202) :  ![starts](https://img.shields.io/github/stars/jcjjaidigital/CVE-2018-0202.svg) ![forks](https://img.shields.io/github/forks/jcjjaidigital/CVE-2018-0202.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/YunchoHang/CVE-2014-6271-SHELLSHOCK](https://github.com/YunchoHang/CVE-2014-6271-SHELLSHOCK) :  ![starts](https://img.shields.io/github/stars/YunchoHang/CVE-2014-6271-SHELLSHOCK.svg) ![forks](https://img.shields.io/github/forks/YunchoHang/CVE-2014-6271-SHELLSHOCK.svg)

