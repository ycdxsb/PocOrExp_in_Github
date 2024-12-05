# Update 2024-12-05
## CVE-2024-36401
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/punitdarji/GeoServer-CVE-2024-36401](https://github.com/punitdarji/GeoServer-CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/punitdarji/GeoServer-CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/punitdarji/GeoServer-CVE-2024-36401.svg)


## CVE-2024-5268
 Sonos Era 100 SMB2 Message Handling Out-Of-Bounds Read Information Disclosure Vulnerability. This vulnerability allows network-adjacent attackers to disclose sensitive information on affected installations of Sonos Era 100 smart speakers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of SMB2 messages. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-CAN-22428.

- [https://github.com/cyb3res3c/CVE-2024-52680](https://github.com/cyb3res3c/CVE-2024-52680) :  ![starts](https://img.shields.io/github/stars/cyb3res3c/CVE-2024-52680.svg) ![forks](https://img.shields.io/github/forks/cyb3res3c/CVE-2024-52680.svg)


## CVE-2024-5124
 A timing attack vulnerability exists in the gaizhenbiao/chuanhuchatgpt repository, specifically within the password comparison logic. The vulnerability is present in version 20240310 of the software, where passwords are compared using the '=' operator in Python. This method of comparison allows an attacker to guess passwords based on the timing of each character's comparison. The issue arises from the code segment that checks a password for a particular username, which can lead to the exposure of sensitive information to an unauthorized actor. An attacker exploiting this vulnerability could potentially guess user passwords, compromising the security of the system.

- [https://github.com/XiaomingX/CVE-2024-5124-poc](https://github.com/XiaomingX/CVE-2024-5124-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/CVE-2024-5124-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/CVE-2024-5124-poc.svg)


## CVE-2024-5049
 A vulnerability, which was classified as critical, has been found in Codezips E-Commerce Site 1.0. Affected by this issue is some unknown functionality of the file admin/editproduct.php. The manipulation of the argument profilepic leads to unrestricted upload. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-264746 is the identifier assigned to this vulnerability.

- [https://github.com/p0et08/CVE-2024-50498](https://github.com/p0et08/CVE-2024-50498) :  ![starts](https://img.shields.io/github/stars/p0et08/CVE-2024-50498.svg) ![forks](https://img.shields.io/github/forks/p0et08/CVE-2024-50498.svg)


## CVE-2024-4232
 This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to lack of encryption or hashing in storing of passwords within the router's firmware/ database. An attacker with physical access could exploit this by extracting the firmware and reverse engineer the binary data to access the plaintext passwords on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to gain unauthorized access to the targeted system.

- [https://github.com/compr00t/CVE-2024-42327](https://github.com/compr00t/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/compr00t/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/compr00t/CVE-2024-42327.svg)


## CVE-2024-1092
 The RSS Aggregator by Feedzy &#8211; Feed to Post, Autoblogging, News &amp; YouTube Video Feeds Aggregator plugin for WordPress is vulnerable to unauthorized data modification due to a missing capability check on the feedzy dashboard in all versions up to, and including, 4.4.1. This makes it possible for authenticated attackers, with contributor access or higher, to create, edit or delete feed categories created by them.

- [https://github.com/Hunt3r850/CVE-2024-10924-Wordpress-Docker](https://github.com/Hunt3r850/CVE-2024-10924-Wordpress-Docker) :  ![starts](https://img.shields.io/github/stars/Hunt3r850/CVE-2024-10924-Wordpress-Docker.svg) ![forks](https://img.shields.io/github/forks/Hunt3r850/CVE-2024-10924-Wordpress-Docker.svg)
- [https://github.com/Hunt3r850/CVE-2024-10924-PoC](https://github.com/Hunt3r850/CVE-2024-10924-PoC) :  ![starts](https://img.shields.io/github/stars/Hunt3r850/CVE-2024-10924-PoC.svg) ![forks](https://img.shields.io/github/forks/Hunt3r850/CVE-2024-10924-PoC.svg)


## CVE-2024-0012
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/punitdarji/Paloalto-CVE-2024-0012](https://github.com/punitdarji/Paloalto-CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/punitdarji/Paloalto-CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Paloalto-CVE-2024-0012.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC](https://github.com/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/VictoriousKnight/CVE-2023-38831_Exploit](https://github.com/VictoriousKnight/CVE-2023-38831_Exploit) :  ![starts](https://img.shields.io/github/stars/VictoriousKnight/CVE-2023-38831_Exploit.svg) ![forks](https://img.shields.io/github/forks/VictoriousKnight/CVE-2023-38831_Exploit.svg)


## CVE-2023-1488
 A vulnerability, which was classified as problematic, was found in Lespeed WiseCleaner Wise System Monitor 1.5.3.54. Affected is the function 0x9C40A0D8/0x9C40A0DC/0x9C40A0E0 in the library WiseHDInfo64.dll of the component IoControlCode Handler. The manipulation leads to denial of service. It is possible to launch the attack on the local host. The exploit has been disclosed to the public and may be used. VDB-223374 is the identifier assigned to this vulnerability.

- [https://github.com/involuntairly/CVE-2023-1488](https://github.com/involuntairly/CVE-2023-1488) :  ![starts](https://img.shields.io/github/stars/involuntairly/CVE-2023-1488.svg) ![forks](https://img.shields.io/github/forks/involuntairly/CVE-2023-1488.svg)


## CVE-2021-42260
 TinyXML through 2.6.2 has an infinite loop in TiXmlParsingData::Stamp in tinyxmlparser.cpp via the TIXML_UTF_LEAD_0 case. It can be triggered by a crafted XML message and leads to a denial of service.

- [https://github.com/vm2mv/tinyxml](https://github.com/vm2mv/tinyxml) :  ![starts](https://img.shields.io/github/stars/vm2mv/tinyxml.svg) ![forks](https://img.shields.io/github/forks/vm2mv/tinyxml.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/specializzazione-cyber-security/demo-CVE-2021-29447-lezione](https://github.com/specializzazione-cyber-security/demo-CVE-2021-29447-lezione) :  ![starts](https://img.shields.io/github/stars/specializzazione-cyber-security/demo-CVE-2021-29447-lezione.svg) ![forks](https://img.shields.io/github/forks/specializzazione-cyber-security/demo-CVE-2021-29447-lezione.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/azhao1981/CVE-2021-29441](https://github.com/azhao1981/CVE-2021-29441) :  ![starts](https://img.shields.io/github/stars/azhao1981/CVE-2021-29441.svg) ![forks](https://img.shields.io/github/forks/azhao1981/CVE-2021-29441.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/saccles/CVE-2018-16763-Proof-of-Concept](https://github.com/saccles/CVE-2018-16763-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/saccles/CVE-2018-16763-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/saccles/CVE-2018-16763-Proof-of-Concept.svg)

