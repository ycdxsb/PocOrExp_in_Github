# Update 2023-09-17
## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/IMHarman/CVE-2023-38831](https://github.com/IMHarman/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/IMHarman/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/IMHarman/CVE-2023-38831.svg)


## CVE-2023-26607
 In the Linux kernel 6.0.8, there is an out-of-bounds read in ntfs_attr_find in fs/ntfs/attrib.c.

- [https://github.com/Trinadh465/linux-4.1.15_CVE-2023-26607](https://github.com/Trinadh465/linux-4.1.15_CVE-2023-26607) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.1.15_CVE-2023-26607.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.1.15_CVE-2023-26607.svg)


## CVE-2023-5000
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/codeb0ss/Wordpress-Forminator-Exploiter](https://github.com/codeb0ss/Wordpress-Forminator-Exploiter) :  ![starts](https://img.shields.io/github/stars/codeb0ss/Wordpress-Forminator-Exploiter.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/Wordpress-Forminator-Exploiter.svg)


## CVE-2023-4128
 A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue.

- [https://github.com/Trinadh465/linux-4.1.15_CVE-2023-4128](https://github.com/Trinadh465/linux-4.1.15_CVE-2023-4128) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.1.15_CVE-2023-4128.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.1.15_CVE-2023-4128.svg)


## CVE-2022-43680
 In libexpat through 2.4.9, there is a use-after free caused by overeager destruction of a shared DTD in XML_ExternalEntityParserCreate in out-of-memory situations.

- [https://github.com/Trinadh465/external_expat-2.1.0_CVE-2022-43680](https://github.com/Trinadh465/external_expat-2.1.0_CVE-2022-43680) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_expat-2.1.0_CVE-2022-43680.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_expat-2.1.0_CVE-2022-43680.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/IMHarman/CVE-2022-33891](https://github.com/IMHarman/CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/IMHarman/CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/IMHarman/CVE-2022-33891.svg)


## CVE-2022-4060
 The User Post Gallery WordPress plugin through 2.19 does not limit what callback functions can be called by users, making it possible to any visitors to run code on sites running it.

- [https://github.com/im-hanzou/UPGer](https://github.com/im-hanzou/UPGer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/UPGer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/UPGer.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/colmmacc/CVE-2022-3602](https://github.com/colmmacc/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/colmmacc/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/colmmacc/CVE-2022-3602.svg)
- [https://github.com/alicangnll/SpookySSL-Scanner](https://github.com/alicangnll/SpookySSL-Scanner) :  ![starts](https://img.shields.io/github/stars/alicangnll/SpookySSL-Scanner.svg) ![forks](https://img.shields.io/github/forks/alicangnll/SpookySSL-Scanner.svg)


## CVE-2022-3564
 A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211087.

- [https://github.com/nidhi7598/linux-v4.19.72_CVE-2022-3564](https://github.com/nidhi7598/linux-v4.19.72_CVE-2022-3564) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-v4.19.72_CVE-2022-3564.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-v4.19.72_CVE-2022-3564.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/kal1gh0st/CVE-2021-3156](https://github.com/kal1gh0st/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/CVE-2021-3156.svg)
- [https://github.com/unauth401/CVE-2021-3156](https://github.com/unauth401/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/unauth401/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/unauth401/CVE-2021-3156.svg)
- [https://github.com/binw2018/CVE-2021-3156-SCRIPT](https://github.com/binw2018/CVE-2021-3156-SCRIPT) :  ![starts](https://img.shields.io/github/stars/binw2018/CVE-2021-3156-SCRIPT.svg) ![forks](https://img.shields.io/github/forks/binw2018/CVE-2021-3156-SCRIPT.svg)
- [https://github.com/0x7183/CVE-2021-3156](https://github.com/0x7183/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/0x7183/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/0x7183/CVE-2021-3156.svg)
- [https://github.com/nexcess/sudo_cve-2021-3156](https://github.com/nexcess/sudo_cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/nexcess/sudo_cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/nexcess/sudo_cve-2021-3156.svg)
- [https://github.com/sharkmoos/Baron-Samedit](https://github.com/sharkmoos/Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/sharkmoos/Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/sharkmoos/Baron-Samedit.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/shi10587s/Sauercloude](https://github.com/shi10587s/Sauercloude) :  ![starts](https://img.shields.io/github/stars/shi10587s/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/shi10587s/Sauercloude.svg)


## CVE-2021-2108
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2019-13288
 In Xpdf 4.01.01, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted file. A remote attacker can leverage this for a DoS attack. This is similar to CVE-2018-16646.

- [https://github.com/gleaming0/CVE-2019-13288](https://github.com/gleaming0/CVE-2019-13288) :  ![starts](https://img.shields.io/github/stars/gleaming0/CVE-2019-13288.svg) ![forks](https://img.shields.io/github/forks/gleaming0/CVE-2019-13288.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/hoaan1995/CVE-2018-9995](https://github.com/hoaan1995/CVE-2018-9995) :  ![starts](https://img.shields.io/github/stars/hoaan1995/CVE-2018-9995.svg) ![forks](https://img.shields.io/github/forks/hoaan1995/CVE-2018-9995.svg)
- [https://github.com/gwolfs/CVE-2018-9995-ModifiedByGwolfs](https://github.com/gwolfs/CVE-2018-9995-ModifiedByGwolfs) :  ![starts](https://img.shields.io/github/stars/gwolfs/CVE-2018-9995-ModifiedByGwolfs.svg) ![forks](https://img.shields.io/github/forks/gwolfs/CVE-2018-9995-ModifiedByGwolfs.svg)
- [https://github.com/codeholic2k18/CVE-2018-9995](https://github.com/codeholic2k18/CVE-2018-9995) :  ![starts](https://img.shields.io/github/stars/codeholic2k18/CVE-2018-9995.svg) ![forks](https://img.shields.io/github/forks/codeholic2k18/CVE-2018-9995.svg)


## CVE-2015-2291
 (1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.

- [https://github.com/Tare05/Intel-CVE-2015-2291](https://github.com/Tare05/Intel-CVE-2015-2291) :  ![starts](https://img.shields.io/github/stars/Tare05/Intel-CVE-2015-2291.svg) ![forks](https://img.shields.io/github/forks/Tare05/Intel-CVE-2015-2291.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/0xTabun/CVE-2014-6287](https://github.com/0xTabun/CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/0xTabun/CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/0xTabun/CVE-2014-6287.svg)


## CVE-2011-3192
 The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.

- [https://github.com/futurezayka/CVE-2011-3192](https://github.com/futurezayka/CVE-2011-3192) :  ![starts](https://img.shields.io/github/stars/futurezayka/CVE-2011-3192.svg) ![forks](https://img.shields.io/github/forks/futurezayka/CVE-2011-3192.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/brunorhis/CVE2009-2265](https://github.com/brunorhis/CVE2009-2265) :  ![starts](https://img.shields.io/github/stars/brunorhis/CVE2009-2265.svg) ![forks](https://img.shields.io/github/forks/brunorhis/CVE2009-2265.svg)

