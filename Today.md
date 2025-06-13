# Update 2025-06-13
## CVE-2025-24514
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/KimJuhyeong95/cve-2025-24514](https://github.com/KimJuhyeong95/cve-2025-24514) :  ![starts](https://img.shields.io/github/stars/KimJuhyeong95/cve-2025-24514.svg) ![forks](https://img.shields.io/github/forks/KimJuhyeong95/cve-2025-24514.svg)


## CVE-2025-24252
 A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.4, tvOS 18.4, macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sonoma 14.7.5, iOS 18.4 and iPadOS 18.4, visionOS 2.4. An attacker on the local network may be able to corrupt process memory.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-24252](https://github.com/B1ack4sh/Blackash-CVE-2025-24252) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24252.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24252.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/B1ack4sh/Blackash-CVE-2025-21333](https://github.com/B1ack4sh/Blackash-CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-21333.svg)


## CVE-2025-20286
Note: If the Primary Administration node is deployed in the cloud, then Cisco ISE is affected by this vulnerability. If the Primary Administration node is on-premises, then it is not affected.

- [https://github.com/rbaicba/CVE-2025-20286](https://github.com/rbaicba/CVE-2025-20286) :  ![starts](https://img.shields.io/github/stars/rbaicba/CVE-2025-20286.svg) ![forks](https://img.shields.io/github/forks/rbaicba/CVE-2025-20286.svg)


## CVE-2025-4275
 Running the provided utility changes the certificate on any Insyde BIOS and then the attached .efi file can be launched.

- [https://github.com/NikolajSchlej/Hydroph0bia](https://github.com/NikolajSchlej/Hydroph0bia) :  ![starts](https://img.shields.io/github/stars/NikolajSchlej/Hydroph0bia.svg) ![forks](https://img.shields.io/github/forks/NikolajSchlej/Hydroph0bia.svg)


## CVE-2025-1793
 Multiple vector store integrations in run-llama/llama_index version v0.12.21 have SQL injection vulnerabilities. These vulnerabilities allow an attacker to read and write data using SQL, potentially leading to unauthorized access to data of other users depending on the usage of the llama-index library in a web application.

- [https://github.com/Usama-Figueira/-CVE-2025-1793-poc](https://github.com/Usama-Figueira/-CVE-2025-1793-poc) :  ![starts](https://img.shields.io/github/stars/Usama-Figueira/-CVE-2025-1793-poc.svg) ![forks](https://img.shields.io/github/forks/Usama-Figueira/-CVE-2025-1793-poc.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/brunoh6/web-threat-mitigation](https://github.com/brunoh6/web-threat-mitigation) :  ![starts](https://img.shields.io/github/stars/brunoh6/web-threat-mitigation.svg) ![forks](https://img.shields.io/github/forks/brunoh6/web-threat-mitigation.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE](https://github.com/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE) :  ![starts](https://img.shields.io/github/stars/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE.svg) ![forks](https://img.shields.io/github/forks/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE.svg)


## CVE-2021-36934
pAfter installing this security update, you emmust/em manually delete all shadow copies of system files, including the SAM database, to fully mitigate this vulnerabilty. strongSimply installing this security update will not fully mitigate this vulnerability./strong See a href="https://support.microsoft.com/topic/1ceaa637-aaa3-4b58-a48b-baf72a2fa9e7"KB5005357- Delete Volume Shadow Copies/a./p

- [https://github.com/P1rat3R00t/Why-so-Serious-SAM](https://github.com/P1rat3R00t/Why-so-Serious-SAM) :  ![starts](https://img.shields.io/github/stars/P1rat3R00t/Why-so-Serious-SAM.svg) ![forks](https://img.shields.io/github/forks/P1rat3R00t/Why-so-Serious-SAM.svg)


## CVE-2021-30047
 VSFTPD 3.0.3 allows attackers to cause a denial of service due to limited number of connections allowed.

- [https://github.com/AndreyFreitass/CVE-2021-30047](https://github.com/AndreyFreitass/CVE-2021-30047) :  ![starts](https://img.shields.io/github/stars/AndreyFreitass/CVE-2021-30047.svg) ![forks](https://img.shields.io/github/forks/AndreyFreitass/CVE-2021-30047.svg)


## CVE-2021-26295
 Apache OFBiz has unsafe deserialization prior to 17.12.06. An unauthenticated attacker can use this vulnerability to successfully take over Apache OFBiz.

- [https://github.com/DarkFunct/exp_hub](https://github.com/DarkFunct/exp_hub) :  ![starts](https://img.shields.io/github/stars/DarkFunct/exp_hub.svg) ![forks](https://img.shields.io/github/forks/DarkFunct/exp_hub.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/DarkFunct/exp_hub](https://github.com/DarkFunct/exp_hub) :  ![starts](https://img.shields.io/github/stars/DarkFunct/exp_hub.svg) ![forks](https://img.shields.io/github/forks/DarkFunct/exp_hub.svg)


## CVE-2021-21975
 Server Side Request Forgery in vRealize Operations Manager API (CVE-2021-21975) prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API can perform a Server Side Request Forgery attack to steal administrative credentials.

- [https://github.com/DarkFunct/exp_hub](https://github.com/DarkFunct/exp_hub) :  ![starts](https://img.shields.io/github/stars/DarkFunct/exp_hub.svg) ![forks](https://img.shields.io/github/forks/DarkFunct/exp_hub.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/m4lk3rnel/CVE-2019-15107](https://github.com/m4lk3rnel/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/m4lk3rnel/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/m4lk3rnel/CVE-2019-15107.svg)


## CVE-2011-0762
 The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

- [https://github.com/AndreyFreitass/CVE-2011-0762](https://github.com/AndreyFreitass/CVE-2011-0762) :  ![starts](https://img.shields.io/github/stars/AndreyFreitass/CVE-2011-0762.svg) ![forks](https://img.shields.io/github/forks/AndreyFreitass/CVE-2011-0762.svg)

