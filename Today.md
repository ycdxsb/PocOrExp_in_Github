# Update 2023-08-27
## CVE-2023-39063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AndreGNogueira/CVE-2023-39063](https://github.com/AndreGNogueira/CVE-2023-39063) :  ![starts](https://img.shields.io/github/stars/AndreGNogueira/CVE-2023-39063.svg) ![forks](https://img.shields.io/github/forks/AndreGNogueira/CVE-2023-39063.svg)


## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/b1tg/CVE-2023-38831-winrar-exploit](https://github.com/b1tg/CVE-2023-38831-winrar-exploit) :  ![starts](https://img.shields.io/github/stars/b1tg/CVE-2023-38831-winrar-exploit.svg) ![forks](https://img.shields.io/github/forks/b1tg/CVE-2023-38831-winrar-exploit.svg)


## CVE-2023-36844
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series allows an unauthenticated, network-based attacker to control certain, important environments variables. Utilizing a crafted request an attacker is able to modify certain PHP environments variables leading to partial loss of integrity, which may allow chaining to other vulnerabilities. This issue affects Juniper Networks Junos OS on EX Series: * All versions prior to 20.4R3-S9; * 21.2 versions prior to 21.2R3-S6; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R3-S1; * 22.4 versions prior to 22.4R2-S2, 22.4R3.

- [https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844](https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/juniper-rce_cve-2023-36844.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/juniper-rce_cve-2023-36844.svg)


## CVE-2023-28772
 An issue was discovered in the Linux kernel before 5.13.3. lib/seq_buf.c has a seq_buf_putmem_hex buffer overflow.

- [https://github.com/hshivhare67/kernel_v4.1.15_CVE-2023-28772](https://github.com/hshivhare67/kernel_v4.1.15_CVE-2023-28772) :  ![starts](https://img.shields.io/github/stars/hshivhare67/kernel_v4.1.15_CVE-2023-28772.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/kernel_v4.1.15_CVE-2023-28772.svg)


## CVE-2023-26255
 An unauthenticated path traversal vulnerability affects the &quot;STAGIL Navigation for Jira - Menu &amp; Themes&quot; plugin before 2.0.52 for Jira. By modifying the fileName parameter to the snjCustomDesignConfig endpoint, it is possible to traverse and read the file system.

- [https://github.com/tucommenceapousser/CVE-2023-26255-Exp](https://github.com/tucommenceapousser/CVE-2023-26255-Exp) :  ![starts](https://img.shields.io/github/stars/tucommenceapousser/CVE-2023-26255-Exp.svg) ![forks](https://img.shields.io/github/forks/tucommenceapousser/CVE-2023-26255-Exp.svg)


## CVE-2023-3460
 The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.

- [https://github.com/yon3zu/Mass-CVE-2023-3460](https://github.com/yon3zu/Mass-CVE-2023-3460) :  ![starts](https://img.shields.io/github/stars/yon3zu/Mass-CVE-2023-3460.svg) ![forks](https://img.shields.io/github/forks/yon3zu/Mass-CVE-2023-3460.svg)


## CVE-2023-2868
 A remote command injection vulnerability exists in the Barracuda Email Security Gateway (appliance form factor only) product effecting versions 5.1.3.001-9.2.0.006. The vulnerability arises out of a failure to comprehensively sanitize the processing of .tar file (tape archives). The vulnerability stems from incomplete input validation of a user-supplied .tar file as it pertains to the names of the files contained within the archive. As a consequence, a remote attacker can specifically format these file names in a particular manner that will result in remotely executing a system command through Perl's qx operator with the privileges of the Email Security Gateway product. This issue was fixed as part of BNSF-36456 patch. This patch was automatically applied to all customer appliances.

- [https://github.com/krmxd/CVE-2023-2868](https://github.com/krmxd/CVE-2023-2868) :  ![starts](https://img.shields.io/github/stars/krmxd/CVE-2023-2868.svg) ![forks](https://img.shields.io/github/forks/krmxd/CVE-2023-2868.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/hakivvi/CVE-2022-29464](https://github.com/hakivvi/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2022-29464.svg)


## CVE-2022-0412
 The TI WooCommerce Wishlist WordPress plugin before 1.40.1, TI WooCommerce Wishlist Pro WordPress plugin before 1.40.1 do not sanitise and escape the item_id parameter before using it in a SQL statement via the wishlist/remove_product REST endpoint, allowing unauthenticated attackers to perform SQL injection attacks

- [https://github.com/TcherB31/CVE-2022-0412_Exploit](https://github.com/TcherB31/CVE-2022-0412_Exploit) :  ![starts](https://img.shields.io/github/stars/TcherB31/CVE-2022-0412_Exploit.svg) ![forks](https://img.shields.io/github/forks/TcherB31/CVE-2022-0412_Exploit.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/K3ysTr0K3R/CVE-2021-42013-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-42013-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-42013-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-42013-EXPLOIT.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)


## CVE-2020-36109
 ASUS RT-AX86U router firmware below version under 9.0.0.4_386 has a buffer overflow in the blocking_request.cgi function of the httpd module that can cause code execution when an attacker constructs malicious data.

- [https://github.com/sunn1day/CVE-2020-36109-POC](https://github.com/sunn1day/CVE-2020-36109-POC) :  ![starts](https://img.shields.io/github/stars/sunn1day/CVE-2020-36109-POC.svg) ![forks](https://img.shields.io/github/forks/sunn1day/CVE-2020-36109-POC.svg)
- [https://github.com/tin-z/CVE-2020-36109-POC](https://github.com/tin-z/CVE-2020-36109-POC) :  ![starts](https://img.shields.io/github/stars/tin-z/CVE-2020-36109-POC.svg) ![forks](https://img.shields.io/github/forks/tin-z/CVE-2020-36109-POC.svg)


## CVE-2019-2022
 In rw_t3t_act_handle_fmt_rsp and rw_t3t_act_handle_sro_rsp of rw_t3t.cc, there is a possible out-of-bound read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-120506143

- [https://github.com/AhnSungHoon/Kali_CVE](https://github.com/AhnSungHoon/Kali_CVE) :  ![starts](https://img.shields.io/github/stars/AhnSungHoon/Kali_CVE.svg) ![forks](https://img.shields.io/github/forks/AhnSungHoon/Kali_CVE.svg)


## CVE-2018-16858
 It was found that libreoffice before versions 6.0.7 and 6.1.3 was vulnerable to a directory traversal attack which could be used to execute arbitrary macros bundled with a document. An attacker could craft a document, which when opened by LibreOffice, would execute a Python method from a script in any arbitrary file system location, specified relative to the LibreOffice install location.

- [https://github.com/Henryisnotavailable/CVE-2018-16858-Python](https://github.com/Henryisnotavailable/CVE-2018-16858-Python) :  ![starts](https://img.shields.io/github/stars/Henryisnotavailable/CVE-2018-16858-Python.svg) ![forks](https://img.shields.io/github/forks/Henryisnotavailable/CVE-2018-16858-Python.svg)


## CVE-2015-7501
 Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and Red Hat Subscription Asset Manager 1.3 allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.

- [https://github.com/ianxtianxt/CVE-2015-7501](https://github.com/ianxtianxt/CVE-2015-7501) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2015-7501.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2015-7501.svg)

