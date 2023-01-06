# Update 2023-01-06
## CVE-2023-22467
 Luxon is a library for working with dates and times in JavaScript. On the 1.x branch prior to 1.38.1, the 2.x branch prior to 2.5.2, and the 3.x branch on 3.2.1, Luxon's `DateTime.fromRFC2822() has quadratic (N^2) complexity on some specific inputs. This causes a noticeable slowdown for inputs with lengths above 10k characters. Users providing untrusted data to this method are therefore vulnerable to (Re)DoS attacks. This issue also appears in Moment as CVE-2022-31129. Versions 1.38.1, 2.5.2, and 3.2.1 contain patches for this issue. As a workaround, limit the length of the input.

- [https://github.com/Live-Hack-CVE/CVE-2023-22467](https://github.com/Live-Hack-CVE/CVE-2023-22467) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22467.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22467.svg)


## CVE-2023-22466
 Tokio is a runtime for writing applications with Rust. Starting with version 1.7.0 and prior to versions 1.18.4, 1.20.3, and 1.23.1, when configuring a Windows named pipe server, setting `pipe_mode` will reset `reject_remote_clients` to `false`. If the application has previously configured `reject_remote_clients` to `true`, this effectively undoes the configuration. Remote clients may only access the named pipe if the named pipe's associated path is accessible via a publicly shared folder (SMB). Versions 1.23.1, 1.20.3, and 1.18.4 have been patched. The fix will also be present in all releases starting from version 1.24.0. Named pipes were introduced to Tokio in version 1.7.0, so releases older than 1.7.0 are not affected. As a workaround, ensure that `pipe_mode` is set first after initializing a `ServerOptions`.

- [https://github.com/Live-Hack-CVE/CVE-2023-22466](https://github.com/Live-Hack-CVE/CVE-2023-22466) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22466.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22466.svg)


## CVE-2023-22463
 KubePi is a k8s panel. The jwt authentication function of KubePi through version 1.6.2 uses hard-coded Jwtsigkeys, resulting in the same Jwtsigkeys for all online projects. This means that an attacker can forge any jwt token to take over the administrator account of any online project. Furthermore, they may use the administrator to take over the k8s cluster of the target enterprise. `session.go`, the use of hard-coded JwtSigKey, allows an attacker to use this value to forge jwt tokens arbitrarily. The JwtSigKey is confidential and should not be hard-coded in the code. The vulnerability has been fixed in 1.6.3. In the patch, JWT key is specified in app.yml. If the user leaves it blank, a random key will be used. There are no workarounds aside from upgrading.

- [https://github.com/Live-Hack-CVE/CVE-2023-22463](https://github.com/Live-Hack-CVE/CVE-2023-22463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22463.svg)


## CVE-2023-0055
 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository pyload/pyload prior to 0.5.0b3.dev32.

- [https://github.com/Live-Hack-CVE/CVE-2023-0055](https://github.com/Live-Hack-CVE/CVE-2023-0055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0055.svg)


## CVE-2023-0054
 Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145.

- [https://github.com/Live-Hack-CVE/CVE-2023-0054](https://github.com/Live-Hack-CVE/CVE-2023-0054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0054.svg)


## CVE-2023-0049
 Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143.

- [https://github.com/Live-Hack-CVE/CVE-2023-0049](https://github.com/Live-Hack-CVE/CVE-2023-0049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0049.svg)


## CVE-2023-0048
 Code Injection in GitHub repository lirantal/daloradius prior to master-branch.

- [https://github.com/Live-Hack-CVE/CVE-2023-0048](https://github.com/Live-Hack-CVE/CVE-2023-0048) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0048.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0048.svg)


## CVE-2023-0046
 Improper Restriction of Names for Files and Other Resources in GitHub repository lirantal/daloradius prior to master-branch.

- [https://github.com/Live-Hack-CVE/CVE-2023-0046](https://github.com/Live-Hack-CVE/CVE-2023-0046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0046.svg)


## CVE-2022-48217
 ** DISPUTED ** The tf_remapper_node component 1.1.1 for Robot Operating System (ROS) allows attackers, who control the source code of a different node in the same ROS application, to change a robot's behavior. This occurs because a topic name depends on the attacker-controlled old_tf_topic_name and/or new_tf_topic_name parameter. NOTE: the vendor's position is &quot;it is the responsibility of the programmer to make sure that only known and required parameters are set and unexpected parameters are not.&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-48217](https://github.com/Live-Hack-CVE/CVE-2022-48217) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48217.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48217.svg)


## CVE-2022-48216
 Uniswap Universal Router before 1.1.0 mishandles reentrancy. This would have allowed theft of funds.

- [https://github.com/Live-Hack-CVE/CVE-2022-48216](https://github.com/Live-Hack-CVE/CVE-2022-48216) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48216.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48216.svg)


## CVE-2022-47102
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sudoninja-noob/CVE-2022-47102](https://github.com/sudoninja-noob/CVE-2022-47102) :  ![starts](https://img.shields.io/github/stars/sudoninja-noob/CVE-2022-47102.svg) ![forks](https://img.shields.io/github/forks/sudoninja-noob/CVE-2022-47102.svg)


## CVE-2022-46623
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sudoninja-noob/CVE-2022-46623](https://github.com/sudoninja-noob/CVE-2022-46623) :  ![starts](https://img.shields.io/github/stars/sudoninja-noob/CVE-2022-46623.svg) ![forks](https://img.shields.io/github/forks/sudoninja-noob/CVE-2022-46623.svg)


## CVE-2022-46622
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sudoninja-noob/CVE-2022-46622](https://github.com/sudoninja-noob/CVE-2022-46622) :  ![starts](https://img.shields.io/github/stars/sudoninja-noob/CVE-2022-46622.svg) ![forks](https://img.shields.io/github/forks/sudoninja-noob/CVE-2022-46622.svg)


## CVE-2022-46456
 NASM v2.16 was discovered to contain a global buffer overflow in the component dbgdbg_typevalue at /output/outdbg.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-46456](https://github.com/Live-Hack-CVE/CVE-2022-46456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46456.svg)


## CVE-2022-46178
 MeterSphere is a one-stop open source continuous testing platform, covering test management, interface testing, UI testing and performance testing. Versions prior to 2.5.1 allow users to upload a file, but do not validate the file name, which may lead to upload file to any path. The vulnerability has been fixed in v2.5.1. There are no workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-46178](https://github.com/Live-Hack-CVE/CVE-2022-46178) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46178.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46178.svg)


## CVE-2022-45778
 https://www.hillstonenet.com.cn/ Hillstone Firewall SG-6000 &lt;= 5.0.4.0 is vulnerable to Incorrect Access Control. There is a permission bypass vulnerability in the Hillstone WEB application firewall. An attacker can enter the background of the firewall with super administrator privileges through a configuration error in report.m.

- [https://github.com/Live-Hack-CVE/CVE-2022-45778](https://github.com/Live-Hack-CVE/CVE-2022-45778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45778.svg)


## CVE-2022-45729
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sudoninja-noob/CVE-2022-45729](https://github.com/sudoninja-noob/CVE-2022-45729) :  ![starts](https://img.shields.io/github/stars/sudoninja-noob/CVE-2022-45729.svg) ![forks](https://img.shields.io/github/forks/sudoninja-noob/CVE-2022-45729.svg)


## CVE-2022-45728
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sudoninja-noob/CVE-2022-45728](https://github.com/sudoninja-noob/CVE-2022-45728) :  ![starts](https://img.shields.io/github/stars/sudoninja-noob/CVE-2022-45728.svg) ![forks](https://img.shields.io/github/forks/sudoninja-noob/CVE-2022-45728.svg)


## CVE-2022-45434
 Some Dahua software products have a vulnerability of unauthenticated un-throttled ICMP requests on remote DSS Server. After bypassing the firewall access control policy, by sending a specific crafted packet to the vulnerable interface, an attacker could exploit the victim server to launch ICMP request attack to the designated target host.

- [https://github.com/Live-Hack-CVE/CVE-2022-45434](https://github.com/Live-Hack-CVE/CVE-2022-45434) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45434.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45434.svg)


## CVE-2022-45433
 Some Dahua software products have a vulnerability of unauthenticated traceroute host from remote DSS Server. After bypassing the firewall access control policy, by sending a specific crafted packet to the vulnerable interface, an attacker could get the traceroute results.

- [https://github.com/Live-Hack-CVE/CVE-2022-45433](https://github.com/Live-Hack-CVE/CVE-2022-45433) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45433.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45433.svg)


## CVE-2022-45432
 Some Dahua software products have a vulnerability of unauthenticated search for devices. After bypassing the firewall access control policy, by sending a specific crafted packet to the vulnerable interface, an attacker could unauthenticated search for devices in range of IPs from remote DSS Server.

- [https://github.com/Live-Hack-CVE/CVE-2022-45432](https://github.com/Live-Hack-CVE/CVE-2022-45432) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45432.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45432.svg)


## CVE-2022-45431
 Some Dahua software products have a vulnerability of unauthenticated restart of remote DSS Server. After bypassing the firewall access control policy, by sending a specific crafted packet to the vulnerable interface, an attacker could unauthenticated restart of remote DSS Server.

- [https://github.com/Live-Hack-CVE/CVE-2022-45431](https://github.com/Live-Hack-CVE/CVE-2022-45431) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45431.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45431.svg)


## CVE-2022-45430
 Some Dahua software products have a vulnerability of unauthenticated enable or disable SSHD service. After bypassing the firewall access control policy, by sending a specific crafted packet to the vulnerable interface, an attacker could enable or disable the SSHD service.

- [https://github.com/Live-Hack-CVE/CVE-2022-45430](https://github.com/Live-Hack-CVE/CVE-2022-45430) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45430.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45430.svg)


## CVE-2022-45429
 Some Dahua software products have a vulnerability of server-side request forgery (SSRF). An Attacker can access internal resources by concatenating links (URL) that conform to specific rules.

- [https://github.com/Live-Hack-CVE/CVE-2022-45429](https://github.com/Live-Hack-CVE/CVE-2022-45429) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45429.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45429.svg)


## CVE-2022-45428
 Some Dahua software products have a vulnerability of sensitive information leakage. After obtaining the permissions of administrators, by sending a specific crafted packet to the vulnerable interface, an attacker can obtain the debugging information.

- [https://github.com/Live-Hack-CVE/CVE-2022-45428](https://github.com/Live-Hack-CVE/CVE-2022-45428) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45428.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45428.svg)


## CVE-2022-45427
 Some Dahua software products have a vulnerability of unrestricted upload of file. After obtaining the permissions of administrators, by sending a specific crafted packet to the vulnerable interface, an attacker can upload arbitrary files.

- [https://github.com/Live-Hack-CVE/CVE-2022-45427](https://github.com/Live-Hack-CVE/CVE-2022-45427) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45427.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45427.svg)


## CVE-2022-45425
 Some Dahua software products have a vulnerability of using of hard-coded cryptographic key. An attacker can obtain the AES crypto key by exploiting this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-45425](https://github.com/Live-Hack-CVE/CVE-2022-45425) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45425.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45425.svg)


## CVE-2022-45424
 Some Dahua software products have a vulnerability of unauthenticated request of AES crypto key. An attacker can obtain the AES crypto key by sending a specific crafted packet to the vulnerable interface.

- [https://github.com/Live-Hack-CVE/CVE-2022-45424](https://github.com/Live-Hack-CVE/CVE-2022-45424) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45424.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45424.svg)


## CVE-2022-45423
 Some Dahua software products have a vulnerability of unauthenticated request of MQTT credentials. An attacker can obtain encrypted MQTT credentials by sending a specific crafted packet to the vulnerable interface (the credentials cannot be directly exploited).

- [https://github.com/Live-Hack-CVE/CVE-2022-45423](https://github.com/Live-Hack-CVE/CVE-2022-45423) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45423.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45423.svg)


## CVE-2022-45052
 A Local File Inclusion vulnerability has been found in Axiell Iguana CMS. Due to insufficient neutralisation of user input on the url parameter on the imageProxy.type.php endpoint, external users are capable of accessing files on the server.

- [https://github.com/Live-Hack-CVE/CVE-2022-45052](https://github.com/Live-Hack-CVE/CVE-2022-45052) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45052.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45052.svg)


## CVE-2022-45051
 A reflected XSS vulnerability has been found in Axiell Iguana CMS, allowing an attacker to execute code in a victim's browser. The module parameter on the Service.template.cls endpoint does not properly neutralise user input, resulting in the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-45051](https://github.com/Live-Hack-CVE/CVE-2022-45051) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45051.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45051.svg)


## CVE-2022-45049
 A reflected XSS vulnerability has been found in Axiell Iguana CMS, allowing an attacker to execute code in a victim's browser. The url parameter on the novelist.php endpoint does not properly neutralise user input, resulting in the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-45049](https://github.com/Live-Hack-CVE/CVE-2022-45049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45049.svg)


## CVE-2022-44426
 In wlan driver, there is a possible missing bounds check. This could lead to local denial of service in wlan services.

- [https://github.com/Live-Hack-CVE/CVE-2022-44426](https://github.com/Live-Hack-CVE/CVE-2022-44426) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44426.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44426.svg)


## CVE-2022-44425
 In wlan driver, there is a possible missing bounds check. This could lead to local denial of service in wlan services.

- [https://github.com/Live-Hack-CVE/CVE-2022-44425](https://github.com/Live-Hack-CVE/CVE-2022-44425) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44425.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44425.svg)


## CVE-2022-44424
 In music service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-44424](https://github.com/Live-Hack-CVE/CVE-2022-44424) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44424.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44424.svg)


## CVE-2022-44423
 In music service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-44423](https://github.com/Live-Hack-CVE/CVE-2022-44423) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44423.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44423.svg)


## CVE-2022-44422
 In music service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-44422](https://github.com/Live-Hack-CVE/CVE-2022-44422) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44422.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44422.svg)


## CVE-2022-44137
 SourceCodester Sanitization Management System 1.0 is vulnerable to SQL Injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-44137](https://github.com/Live-Hack-CVE/CVE-2022-44137) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44137.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44137.svg)


## CVE-2022-43920
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 could allow an authenticated user to gain privileges in a different group due to an access control vulnerability in the Sftp server adapter. IBM X-Force ID: 241362.

- [https://github.com/Live-Hack-CVE/CVE-2022-43920](https://github.com/Live-Hack-CVE/CVE-2022-43920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43920.svg)


## CVE-2022-39118
 In sprd_sysdump driver, there is a possible out of bounds write due to a missing bounds check. This could lead to local denial of service in kernel.

- [https://github.com/Live-Hack-CVE/CVE-2022-39118](https://github.com/Live-Hack-CVE/CVE-2022-39118) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39118.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39118.svg)


## CVE-2022-39116
 In sprd_sysdump driver, there is a possible out of bounds write due to a missing bounds check. This could lead to local denial of service in kernel.

- [https://github.com/Live-Hack-CVE/CVE-2022-39116](https://github.com/Live-Hack-CVE/CVE-2022-39116) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39116.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39116.svg)


## CVE-2022-39104
 In contacts service, there is a missing permission check. This could lead to local denial of service in Contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39104](https://github.com/Live-Hack-CVE/CVE-2022-39104) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39104.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39104.svg)


## CVE-2022-39088
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39088](https://github.com/Live-Hack-CVE/CVE-2022-39088) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39088.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39088.svg)


## CVE-2022-39087
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39087](https://github.com/Live-Hack-CVE/CVE-2022-39087) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39087.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39087.svg)


## CVE-2022-39086
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39086](https://github.com/Live-Hack-CVE/CVE-2022-39086) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39086.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39086.svg)


## CVE-2022-39085
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39085](https://github.com/Live-Hack-CVE/CVE-2022-39085) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39085.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39085.svg)


## CVE-2022-39084
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39084](https://github.com/Live-Hack-CVE/CVE-2022-39084) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39084.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39084.svg)


## CVE-2022-39083
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39083](https://github.com/Live-Hack-CVE/CVE-2022-39083) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39083.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39083.svg)


## CVE-2022-39082
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39082](https://github.com/Live-Hack-CVE/CVE-2022-39082) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39082.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39082.svg)


## CVE-2022-39081
 In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-39081](https://github.com/Live-Hack-CVE/CVE-2022-39081) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39081.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39081.svg)


## CVE-2022-38684
 In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-38684](https://github.com/Live-Hack-CVE/CVE-2022-38684) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38684.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38684.svg)


## CVE-2022-38683
 In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-38683](https://github.com/Live-Hack-CVE/CVE-2022-38683) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38683.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38683.svg)


## CVE-2022-38682
 In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-38682](https://github.com/Live-Hack-CVE/CVE-2022-38682) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38682.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38682.svg)


## CVE-2022-38678
 In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-38678](https://github.com/Live-Hack-CVE/CVE-2022-38678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38678.svg)


## CVE-2022-34772
 Tabit - password enumeration. Description: Tabit - password enumeration. The passwords for the Tabit system is a 4 digit OTP. One can resend OTP and try logging in indefinitely. Once again, this is an example of OWASP: API4 - Rate limiting.

- [https://github.com/Live-Hack-CVE/CVE-2022-34772](https://github.com/Live-Hack-CVE/CVE-2022-34772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34772.svg)


## CVE-2022-32620
 In mpu, there is a possible memory corruption due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07541753; Issue ID: ALPS07541753.

- [https://github.com/Live-Hack-CVE/CVE-2022-32620](https://github.com/Live-Hack-CVE/CVE-2022-32620) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32620.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32620.svg)


## CVE-2022-29899
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2022. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-29899](https://github.com/Live-Hack-CVE/CVE-2022-29899) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29899.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29899.svg)


## CVE-2022-27502
 RealVNC VNC Server 6.9.0 through 5.1.0 for Windows allows local privilege escalation because an installer repair operation executes %TEMP% files as SYSTEM.

- [https://github.com/alirezac0/CVE-2022-27502](https://github.com/alirezac0/CVE-2022-27502) :  ![starts](https://img.shields.io/github/stars/alirezac0/CVE-2022-27502.svg) ![forks](https://img.shields.io/github/forks/alirezac0/CVE-2022-27502.svg)


## CVE-2022-25926
 Versions of the package window-control before 1.4.5 are vulnerable to Command Injection via the sendKeys function, due to improper input sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-25926](https://github.com/Live-Hack-CVE/CVE-2022-25926) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25926.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25926.svg)


## CVE-2022-22352
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 220398.

- [https://github.com/Live-Hack-CVE/CVE-2022-22352](https://github.com/Live-Hack-CVE/CVE-2022-22352) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22352.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22352.svg)


## CVE-2022-22338
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 is vulnerable to SQL injection. A remote attacker could send specially crafted SQL statements, which could allow the attacker to view, add, modify or delete information in the back-end database. IBM X-Force ID: 219510.

- [https://github.com/Live-Hack-CVE/CVE-2022-22338](https://github.com/Live-Hack-CVE/CVE-2022-22338) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22338.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22338.svg)


## CVE-2022-22337
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 could disclose sensitive information to an authenticated user. IBM X-Force ID: 219507.

- [https://github.com/Live-Hack-CVE/CVE-2022-22337](https://github.com/Live-Hack-CVE/CVE-2022-22337) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22337.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22337.svg)


## CVE-2022-4876
 A vulnerability was found in Kaltura mwEmbed up to 2.96.rc1 and classified as problematic. This issue affects some unknown processing of the file includes/DefaultSettings.php. The manipulation of the argument HTTP_X_FORWARDED_HOST leads to cross site scripting. The attack may be initiated remotely. Upgrading to version 2.96.rc2 is able to address this issue. The name of the patch is 13b8812ebc8c9fa034eed91ab35ba8423a528c0b. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217427.

- [https://github.com/Live-Hack-CVE/CVE-2022-4876](https://github.com/Live-Hack-CVE/CVE-2022-4876) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4876.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4876.svg)


## CVE-2022-4875
 A vulnerability has been found in fossology and classified as problematic. This vulnerability affects unknown code. The manipulation of the argument sql/VarValue leads to cross site scripting. The attack can be initiated remotely. The name of the patch is 8e0eba001662c7eb35f045b70dd458a4643b4553. It is recommended to apply a patch to fix this issue. VDB-217426 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4875](https://github.com/Live-Hack-CVE/CVE-2022-4875) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4875.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4875.svg)


## CVE-2022-3576
 A vulnerability regarding out-of-bounds read is found in the session processing functionality of Out-of-Band (OOB) Management. This allows remote attackers to obtain sensitive information via unspecified vectors. The following models with Synology DiskStation Manager (DSM) versions before 7.1.1-42962-2 may be affected: DS3622xs+, FS3410, and HD6500.

- [https://github.com/Live-Hack-CVE/CVE-2022-3576](https://github.com/Live-Hack-CVE/CVE-2022-3576) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3576.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3576.svg)


## CVE-2022-3394
 The WP All Export Pro WordPress plugin before 1.7.9 does not limit some functionality during exports only to users with the Administrator role, allowing any logged in user which has been given privileges to perform exports to execute arbitrary code on the site. By default only administrators can run exports, but the privilege can be delegated to lower privileged users.

- [https://github.com/Live-Hack-CVE/CVE-2022-3394](https://github.com/Live-Hack-CVE/CVE-2022-3394) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3394.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3394.svg)


## CVE-2022-3195
 Out of bounds write in Storage in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-3195](https://github.com/Live-Hack-CVE/CVE-2022-3195) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3195.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3195.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/ajith737/Dirty-Pipe-CVE-2022-0847-POCs](https://github.com/ajith737/Dirty-Pipe-CVE-2022-0847-POCs) :  ![starts](https://img.shields.io/github/stars/ajith737/Dirty-Pipe-CVE-2022-0847-POCs.svg) ![forks](https://img.shields.io/github/forks/ajith737/Dirty-Pipe-CVE-2022-0847-POCs.svg)


## CVE-2022-0259
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2022. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-0259](https://github.com/Live-Hack-CVE/CVE-2022-0259) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0259.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0259.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/juuso256/CVE-2021-41773](https://github.com/juuso256/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/juuso256/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/juuso256/CVE-2021-41773.svg)


## CVE-2021-41986
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41986](https://github.com/Live-Hack-CVE/CVE-2021-41986) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41986.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41986.svg)


## CVE-2021-41985
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41985](https://github.com/Live-Hack-CVE/CVE-2021-41985) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41985.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41985.svg)


## CVE-2021-41984
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41984](https://github.com/Live-Hack-CVE/CVE-2021-41984) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41984.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41984.svg)


## CVE-2021-41983
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41983](https://github.com/Live-Hack-CVE/CVE-2021-41983) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41983.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41983.svg)


## CVE-2021-41982
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41982](https://github.com/Live-Hack-CVE/CVE-2021-41982) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41982.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41982.svg)


## CVE-2021-41981
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41981](https://github.com/Live-Hack-CVE/CVE-2021-41981) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41981.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41981.svg)


## CVE-2021-41980
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41980](https://github.com/Live-Hack-CVE/CVE-2021-41980) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41980.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41980.svg)


## CVE-2021-41979
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41979](https://github.com/Live-Hack-CVE/CVE-2021-41979) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41979.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41979.svg)


## CVE-2021-41978
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41978](https://github.com/Live-Hack-CVE/CVE-2021-41978) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41978.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41978.svg)


## CVE-2021-41977
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2021. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-41977](https://github.com/Live-Hack-CVE/CVE-2021-41977) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41977.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41977.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/juuso256/CVE-2021-41773](https://github.com/juuso256/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/juuso256/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/juuso256/CVE-2021-41773.svg)
- [https://github.com/pirenga/CVE-2021-41773](https://github.com/pirenga/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/pirenga/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/pirenga/CVE-2021-41773.svg)


## CVE-2021-39696
 In Task.java, there is a possible escalation of privilege due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12Android ID: A-185810717

- [https://github.com/nidhihcl/frameworks_base_AOSP_10_r33_CVE-2021-39696](https://github.com/nidhihcl/frameworks_base_AOSP_10_r33_CVE-2021-39696) :  ![starts](https://img.shields.io/github/stars/nidhihcl/frameworks_base_AOSP_10_r33_CVE-2021-39696.svg) ![forks](https://img.shields.io/github/forks/nidhihcl/frameworks_base_AOSP_10_r33_CVE-2021-39696.svg)


## CVE-2021-38928
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 uses Cross-Origin Resource Sharing (CORS) which could allow an attacker to carry out privileged actions and retrieve sensitive information as the domain name is not being limited to only trusted domains. IBM X-Force ID: 210323.

- [https://github.com/Live-Hack-CVE/CVE-2021-38928](https://github.com/Live-Hack-CVE/CVE-2021-38928) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-38928.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-38928.svg)


## CVE-2021-4302
 A vulnerability was found in slackero phpwcms up to 1.9.26. It has been classified as problematic. This affects an unknown part of the component SVG File Handler. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. Upgrading to version 1.9.27 is able to address this issue. The name of the patch is b39db9c7ad3800f319195ff0e26a0981395b1c54. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217419.

- [https://github.com/Live-Hack-CVE/CVE-2021-4302](https://github.com/Live-Hack-CVE/CVE-2021-4302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4302.svg)


## CVE-2021-4300
 A vulnerability has been found in ghostlander Halcyon and classified as critical. Affected by this vulnerability is the function CBlock::AddToBlockIndex of the file src/main.cpp of the component Block Verification. The manipulation leads to improper access controls. The attack can be launched remotely. Upgrading to version 1.1.1.0-hal is able to address this issue. The name of the patch is 0675b25ae9cc10b5fdc8ea3a32c642979762d45e. It is recommended to upgrade the affected component. The identifier VDB-217417 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4300](https://github.com/Live-Hack-CVE/CVE-2021-4300) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4300.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4300.svg)


## CVE-2021-4238
 Randomly-generated alphanumeric strings contain significantly less entropy than expected. The RandomAlphaNumeric and CryptoRandomAlphaNumeric functions always return strings containing at least one digit from 0 to 9. This significantly reduces the amount of entropy in short strings generated by these functions.

- [https://github.com/Live-Hack-CVE/CVE-2021-4238](https://github.com/Live-Hack-CVE/CVE-2021-4238) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4238.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4238.svg)


## CVE-2021-4236
 Web Sockets do not execute any AuthenticateMethod methods which may be set, leading to a nil pointer dereference if the returned UserData pointer is assumed to be non-nil, or authentication bypass. This issue only affects WebSockets with an AuthenticateMethod hook. Request handlers that do not explicitly use WebSockets are not vulnerable.

- [https://github.com/Live-Hack-CVE/CVE-2021-4236](https://github.com/Live-Hack-CVE/CVE-2021-4236) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4236.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4236.svg)


## CVE-2021-4142
 The Candlepin component of Red Hat Satellite was affected by an improper authentication flaw. Few factors could allow an attacker to use the SCA (simple content access) certificate for authentication with Candlepin.

- [https://github.com/Live-Hack-CVE/CVE-2021-4142](https://github.com/Live-Hack-CVE/CVE-2021-4142) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4142.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4142.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/Ishan3011/CVE-2021-3493](https://github.com/Ishan3011/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Ishan3011/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Ishan3011/CVE-2021-3493.svg)


## CVE-2020-36640
 A vulnerability, which was classified as problematic, was found in bonitasoft bonita-connector-webservice up to 1.3.0. This affects the function TransformerConfigurationException of the file src/main/java/org/bonitasoft/connectors/ws/SecureWSConnector.java. The manipulation leads to xml external entity reference. Upgrading to version 1.3.1 is able to address this issue. The name of the patch is a12ad691c05af19e9061d7949b6b828ce48815d5. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217443.

- [https://github.com/Live-Hack-CVE/CVE-2020-36640](https://github.com/Live-Hack-CVE/CVE-2020-36640) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36640.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36640.svg)


## CVE-2020-7274
 Privilege escalation vulnerability in McTray.exe in McAfee Endpoint Security (ENS) for Windows Prior to 10.7.0 April 2020 Update allows local users to spawn unrelated processes with elevated privileges via the system administrator granting McTray.exe elevated privileges (by default it runs with the current user's privileges).

- [https://github.com/Caj6r/SNP_report_assignement_IT19009278](https://github.com/Caj6r/SNP_report_assignement_IT19009278) :  ![starts](https://img.shields.io/github/stars/Caj6r/SNP_report_assignement_IT19009278.svg) ![forks](https://img.shields.io/github/forks/Caj6r/SNP_report_assignement_IT19009278.svg)


## CVE-2019-25098
 A vulnerability was found in soerennb eXtplorer up to 2.1.12. It has been classified as critical. This affects an unknown part of the file include/archive.php of the component Archive Handler. The manipulation leads to path traversal. Upgrading to version 2.1.13 is able to address this issue. The name of the patch is b8fcb888f4ff5e171c16797a4b075c6c6f50bf46. It is recommended to upgrade the affected component. The identifier VDB-217437 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25098](https://github.com/Live-Hack-CVE/CVE-2019-25098) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25098.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25098.svg)


## CVE-2019-25097
 A vulnerability was found in soerennb eXtplorer up to 2.1.12 and classified as critical. Affected by this issue is some unknown functionality of the component Directory Content Handler. The manipulation leads to path traversal. Upgrading to version 2.1.13 is able to address this issue. The name of the patch is b8fcb888f4ff5e171c16797a4b075c6c6f50bf46. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217436.

- [https://github.com/Live-Hack-CVE/CVE-2019-25097](https://github.com/Live-Hack-CVE/CVE-2019-25097) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25097.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25097.svg)


## CVE-2019-25096
 A vulnerability has been found in soerennb eXtplorer up to 2.1.12 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross site scripting. The attack can be launched remotely. Upgrading to version 2.1.13 is able to address this issue. The name of the patch is b8fcb888f4ff5e171c16797a4b075c6c6f50bf46. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217435.

- [https://github.com/Live-Hack-CVE/CVE-2019-25096](https://github.com/Live-Hack-CVE/CVE-2019-25096) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25096.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25096.svg)


## CVE-2019-25095
 A vulnerability, which was classified as problematic, was found in kakwa LdapCherry up to 0.x. Affected is an unknown function of the component URL Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.0.0 is able to address this issue. The name of the patch is 6f98076281e9452fdb1adcd1bcbb70a6f968ade9. It is recommended to upgrade the affected component. VDB-217434 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25095](https://github.com/Live-Hack-CVE/CVE-2019-25095) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25095.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25095.svg)


## CVE-2018-25065
 A vulnerability was found in Wikimedia mediawiki-extensions-I18nTags and classified as problematic. This issue affects some unknown processing of the file I18nTags_body.php of the component Unlike Parser. The manipulation leads to cross site scripting. The attack may be initiated remotely. The name of the patch is b4bc3cbbb099eab50cf2b544cf577116f1867b94. It is recommended to apply a patch to fix this issue. The identifier VDB-217445 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25065](https://github.com/Live-Hack-CVE/CVE-2018-25065) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25065.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25065.svg)


## CVE-2018-25064
 A vulnerability was found in OSM Lab show-me-the-way. It has been rated as problematic. This issue affects some unknown processing of the file js/site.js. The manipulation leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 4bed3b34dcc01fe6661f39c0e5d2285b340f7cac. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217439.

- [https://github.com/Live-Hack-CVE/CVE-2018-25064](https://github.com/Live-Hack-CVE/CVE-2018-25064) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25064.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25064.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/CaledoniaProject/CVE-2018-1270](https://github.com/CaledoniaProject/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/CaledoniaProject/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/CaledoniaProject/CVE-2018-1270.svg)


## CVE-2017-20162
 A vulnerability, which was classified as problematic, has been found in vercel ms up to 1.x. This issue affects the function parse of the file index.js. The manipulation of the argument str leads to inefficient regular expression complexity. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 2.0.0 is able to address this issue. The name of the patch is caae2988ba2a37765d055c4eee63d383320ee662. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217451.

- [https://github.com/Live-Hack-CVE/CVE-2017-20162](https://github.com/Live-Hack-CVE/CVE-2017-20162) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20162.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20162.svg)


## CVE-2016-15010
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability classified as problematic was found in University of Cambridge django-ucamlookup up to 1.9.1. Affected by this vulnerability is an unknown functionality of the component Lookup Handler. The manipulation leads to cross site scripting. The attack can be launched remotely. Upgrading to version 1.9.2 is able to address this issue. The name of the patch is 5e25e4765637ea4b9e0bf5fcd5e9a922abee7eb3. It is recommended to upgrade the affected component. The identifier VDB-217441 was assigned to this vulnerability. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2016-15010](https://github.com/Live-Hack-CVE/CVE-2016-15010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15010.svg)


## CVE-2016-15009
 A vulnerability classified as problematic has been found in OpenACS bug-tracker. Affected is an unknown function of the file lib/nav-bar.adp of the component Search. The manipulation leads to cross-site request forgery. It is possible to launch the attack remotely. The name of the patch is aee43e5714cd8b697355ec3bf83eefee176d3fc3. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217440.

- [https://github.com/Live-Hack-CVE/CVE-2016-15009](https://github.com/Live-Hack-CVE/CVE-2016-15009) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15009.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15009.svg)


## CVE-2015-10014
 A vulnerability classified as critical has been found in arekk uke. This affects an unknown part of the file lib/uke/finder.rb. The manipulation leads to sql injection. The name of the patch is 52fd3b2d0bc16227ef57b7b98a3658bb67c1833f. It is recommended to apply a patch to fix this issue. The identifier VDB-217485 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10014](https://github.com/Live-Hack-CVE/CVE-2015-10014) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10014.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10014.svg)


## CVE-2015-10013
 A vulnerability was found in WebDevStudios taxonomy-switcher Plugin up to 1.0.3. It has been classified as problematic. Affected is the function taxonomy_switcher_init of the file taxonomy-switcher.php. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.0.4 is able to address this issue. It is recommended to upgrade the affected component. VDB-217446 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10013](https://github.com/Live-Hack-CVE/CVE-2015-10013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10013.svg)


## CVE-2014-125041
 A vulnerability classified as critical was found in Miccighel PR-CWT. This vulnerability affects unknown code. The manipulation leads to sql injection. The name of the patch is e412127d07004668e5a213932c94807d87067a1f. It is recommended to apply a patch to fix this issue. VDB-217486 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125041](https://github.com/Live-Hack-CVE/CVE-2014-125041) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125041.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125041.svg)


## CVE-2014-125040
 A vulnerability was found in stevejagodzinski DevNewsAggregator. It has been rated as critical. Affected by this issue is the function getByName of the file php/data_access/RemoteHtmlContentDataAccess.php. The manipulation of the argument name leads to sql injection. The name of the patch is b9de907e7a8c9ca9d75295da675e58c5bf06b172. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217484.

- [https://github.com/Live-Hack-CVE/CVE-2014-125040](https://github.com/Live-Hack-CVE/CVE-2014-125040) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125040.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125040.svg)


## CVE-2007-10001
 A vulnerability classified as problematic has been found in web-cyradm. This affects an unknown part of the file search.php. The manipulation of the argument searchstring leads to sql injection. It is recommended to apply a patch to fix this issue. The identifier VDB-217449 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2007-10001](https://github.com/Live-Hack-CVE/CVE-2007-10001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2007-10001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2007-10001.svg)

