# Update 2025-11-16
## CVE-2025-64513
 Milvus is an open-source vector database built for generative AI applications. An unauthenticated attacker can exploit a vulnerability in versions prior to 2.4.24, 2.5.21, and 2.6.5 to bypass all authentication mechanisms in the Milvus Proxy component, gaining full administrative access to the Milvus cluster. This grants the attacker the ability to read, modify, or delete data, and to perform privileged administrative operations such as database or collection management. This issue has been fixed in Milvus 2.4.24, 2.5.21, and 2.6.5. If immediate upgrade is not possible, a temporary mitigation can be applied by removing the sourceID header from all incoming requests at the gateway, API gateway, or load balancer level before they reach the Milvus Proxy. This prevents attackers from exploiting the authentication bypass behavior.

- [https://github.com/shinyseam/CVE-2025-64513](https://github.com/shinyseam/CVE-2025-64513) :  ![starts](https://img.shields.io/github/stars/shinyseam/CVE-2025-64513.svg) ![forks](https://img.shields.io/github/forks/shinyseam/CVE-2025-64513.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/fevar54/CVE-2025-64446-PoC---FortiWeb-Path-Traversal](https://github.com/fevar54/CVE-2025-64446-PoC---FortiWeb-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2025-64446-PoC---FortiWeb-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2025-64446-PoC---FortiWeb-Path-Traversal.svg)
- [https://github.com/sxyrxyy/CVE-2025-64446-FortiWeb-CGI-Bypass-PoC](https://github.com/sxyrxyy/CVE-2025-64446-FortiWeb-CGI-Bypass-PoC) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/CVE-2025-64446-FortiWeb-CGI-Bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/CVE-2025-64446-FortiWeb-CGI-Bypass-PoC.svg)


## CVE-2025-63830
 CKFinder 1.4.3 is vulnerable to Cross Site Scripting (XSS) in the File Upload function. An attacker can upload a crafted SVG containing active content.

- [https://github.com/Shubham03007/CVE-2025-63830](https://github.com/Shubham03007/CVE-2025-63830) :  ![starts](https://img.shields.io/github/stars/Shubham03007/CVE-2025-63830.svg) ![forks](https://img.shields.io/github/forks/Shubham03007/CVE-2025-63830.svg)


## CVE-2025-62215
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/dexterm300/CVE-2025-62215-exploit-poc](https://github.com/dexterm300/CVE-2025-62215-exploit-poc) :  ![starts](https://img.shields.io/github/stars/dexterm300/CVE-2025-62215-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/dexterm300/CVE-2025-62215-exploit-poc.svg)


## CVE-2025-60724
 Heap-based buffer overflow in Microsoft Graphics Component allows an unauthorized attacker to execute code over a network.

- [https://github.com/callinston/CVE-2025-60724](https://github.com/callinston/CVE-2025-60724) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-60724.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-60724.svg)


## CVE-2025-60710
 Improper link resolution before file access ('link following') in Host Process for Windows Tasks allows an authorized attacker to elevate privileges locally.

- [https://github.com/redpack-kr/CVE-2025-60710](https://github.com/redpack-kr/CVE-2025-60710) :  ![starts](https://img.shields.io/github/stars/redpack-kr/CVE-2025-60710.svg) ![forks](https://img.shields.io/github/forks/redpack-kr/CVE-2025-60710.svg)


## CVE-2025-59367
 An authentication bypass vulnerability has been identified in certain DSL series routers, may allow remote attackers to gain unauthorized access into the affected system. Refer to the 'Security Update for DSL Series Router' section on the ASUS Security Advisory for more information.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-59367](https://github.com/B1ack4sh/Blackash-CVE-2025-59367) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-59367.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-59367.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/Twodimensionalitylevelcrossing817/CVE-2025-59287](https://github.com/Twodimensionalitylevelcrossing817/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/Twodimensionalitylevelcrossing817/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/Twodimensionalitylevelcrossing817/CVE-2025-59287.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/uziii2208/CVE-2025-33073](https://github.com/uziii2208/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/uziii2208/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/uziii2208/CVE-2025-33073.svg)


## CVE-2025-21202
 Windows Recovery Environment Agent Elevation of Privilege Vulnerability

- [https://github.com/7amzahard/CVE-2025-21202-exploit](https://github.com/7amzahard/CVE-2025-21202-exploit) :  ![starts](https://img.shields.io/github/stars/7amzahard/CVE-2025-21202-exploit.svg) ![forks](https://img.shields.io/github/forks/7amzahard/CVE-2025-21202-exploit.svg)


## CVE-2025-12904
 The SNORDIAN's H5PxAPIkatchu plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'insert_data' AJAX endpoint in all versions up to, and including, 0.4.17 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report](https://github.com/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report.svg)


## CVE-2025-12101
 Cross-Site Scripting (XSS) in NetScaler ADC and NetScaler Gateway when the appliance is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/7amzahard/CVE-2025-21202-exploit](https://github.com/7amzahard/CVE-2025-21202-exploit) :  ![starts](https://img.shields.io/github/stars/7amzahard/CVE-2025-21202-exploit.svg) ![forks](https://img.shields.io/github/forks/7amzahard/CVE-2025-21202-exploit.svg)


## CVE-2025-8571
 Concrete CMS 9 to 9.4.2 and versions below 8.5.21 are vulnerable to Reflected Cross-Site Scripting (XSS) in the Conversation Messages Dashboard Page. Unsanitized input could cause theft of session cookies or tokens, defacement of web content, redirection to malicious sites, and (if victim is an admin), the execution of unauthorized actions. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 4.8 with vector CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N. Thanks  Fortbridge https://fortbridge.co.uk/  for performing a penetration test and vulnerability assessment on Concrete CMS and reporting this issue.

- [https://github.com/chimdi2700/CVE-2025-8571](https://github.com/chimdi2700/CVE-2025-8571) :  ![starts](https://img.shields.io/github/stars/chimdi2700/CVE-2025-8571.svg) ![forks](https://img.shields.io/github/forks/chimdi2700/CVE-2025-8571.svg)


## CVE-2025-8550
 A vulnerability was found in atjiu pybbs up to 6.0.0. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file /admin/topic/list. The manipulation of the argument Username leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The patch is named 2fe4a51afbce0068c291bc1818bbc8f7f3b01a22. It is recommended to apply a patch to fix this issue.

- [https://github.com/byteReaper77/CVE-2025-8550](https://github.com/byteReaper77/CVE-2025-8550) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8550.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8550.svg)


## CVE-2025-6394
 A vulnerability was found in code-projects Simple Online Hotel Reservation System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /add_reserve.php. The manipulation of the argument firstname leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/RedOpsX/CVE-2025-63943](https://github.com/RedOpsX/CVE-2025-63943) :  ![starts](https://img.shields.io/github/stars/RedOpsX/CVE-2025-63943.svg) ![forks](https://img.shields.io/github/forks/RedOpsX/CVE-2025-63943.svg)


## CVE-2025-6360
 A vulnerability classified as critical has been found in code-projects Simple Pizza Ordering System 1.0. This affects an unknown part of the file /portal.php. The manipulation of the argument ID leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/D7EAD/CVE-2025-63602](https://github.com/D7EAD/CVE-2025-63602) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2025-63602.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2025-63602.svg)


## CVE-2025-5652
 A vulnerability, which was classified as critical, was found in PHPGurukul Complaint Management System 2.0. Affected is an unknown function of the file /admin/between-date-complaintreport.php. The manipulation of the argument fromdate/todate leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/HanTul/Kotaemon-CVE-2025-56526-56527-disclosure](https://github.com/HanTul/Kotaemon-CVE-2025-56526-56527-disclosure) :  ![starts](https://img.shields.io/github/stars/HanTul/Kotaemon-CVE-2025-56526-56527-disclosure.svg) ![forks](https://img.shields.io/github/forks/HanTul/Kotaemon-CVE-2025-56526-56527-disclosure.svg)


## CVE-2025-4893
 A vulnerability classified as critical has been found in jammy928 CoinExchange_CryptoExchange_Java up to 8adf508b996020d3efbeeb2473d7235bd01436fa. This affects the function uploadLocalImage of the file /CoinExchange_CryptoExchange_Java-master/00_framework/core/src/main/java/com/bizzan/bitrade/util/UploadFileUtil.java of the component File Upload Endpoint. The manipulation of the argument filename leads to path traversal. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. This product does not use versioning. This is why information about affected and unaffected releases are unavailable.

- [https://github.com/XploitGh0st/CVE-2025-48932---exploit](https://github.com/XploitGh0st/CVE-2025-48932---exploit) :  ![starts](https://img.shields.io/github/stars/XploitGh0st/CVE-2025-48932---exploit.svg) ![forks](https://img.shields.io/github/forks/XploitGh0st/CVE-2025-48932---exploit.svg)


## CVE-2025-4618
Browser self-protection should be enabled to mitigate this issue.

- [https://github.com/shemkumar/CVE-2025-46181-XSS](https://github.com/shemkumar/CVE-2025-46181-XSS) :  ![starts](https://img.shields.io/github/stars/shemkumar/CVE-2025-46181-XSS.svg) ![forks](https://img.shields.io/github/forks/shemkumar/CVE-2025-46181-XSS.svg)


## CVE-2023-35317
 Windows Server Update Service (WSUS) Elevation of Privilege Vulnerability

- [https://github.com/M507/CVE-2023-35317-PoC](https://github.com/M507/CVE-2023-35317-PoC) :  ![starts](https://img.shields.io/github/stars/M507/CVE-2023-35317-PoC.svg) ![forks](https://img.shields.io/github/forks/M507/CVE-2023-35317-PoC.svg)


## CVE-2022-0324
Discovered by Eugene Lim of GovTech Singapore.

- [https://github.com/ngtuonghung/CVE-2022-0324](https://github.com/ngtuonghung/CVE-2022-0324) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2022-0324.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2022-0324.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka "SMBv2 Negotiation Vulnerability." NOTE: some of these details are obtained from third party information.

- [https://github.com/Neved4/exploits](https://github.com/Neved4/exploits) :  ![starts](https://img.shields.io/github/stars/Neved4/exploits.svg) ![forks](https://img.shields.io/github/forks/Neved4/exploits.svg)

