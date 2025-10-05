# Update 2025-10-05
## CVE-2025-61622
Users are recommended to upgrade to pyfory version 0.12.3 or later, which has removed pickle fallback serializer and thus fixes this issue.

- [https://github.com/fa1consec/cve_2025_61622_poc](https://github.com/fa1consec/cve_2025_61622_poc) :  ![starts](https://img.shields.io/github/stars/fa1consec/cve_2025_61622_poc.svg) ![forks](https://img.shields.io/github/forks/fa1consec/cve_2025_61622_poc.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/prabhatverma47/CVE-2025-60787](https://github.com/prabhatverma47/CVE-2025-60787) :  ![starts](https://img.shields.io/github/stars/prabhatverma47/CVE-2025-60787.svg) ![forks](https://img.shields.io/github/forks/prabhatverma47/CVE-2025-60787.svg)


## CVE-2025-59489
 Unity Runtime before 2025-10-02 on Android, Windows, macOS, and Linux allows argument injection that can result in loading of library code from an unintended location. If an application was built with a version of Unity Editor that had the vulnerable Unity Runtime code, then an adversary may be able to execute code on, and exfiltrate confidential information from, the machine on which that application is running. NOTE: product status is provided for Unity Editor because that is the information available from the Supplier. However, updating Unity Editor typically does not address the effects of the vulnerability; instead, it is necessary to rebuild and redeploy all affected applications.

- [https://github.com/RealtekDotSys/Meteor](https://github.com/RealtekDotSys/Meteor) :  ![starts](https://img.shields.io/github/stars/RealtekDotSys/Meteor.svg) ![forks](https://img.shields.io/github/forks/RealtekDotSys/Meteor.svg)


## CVE-2025-55972
 A TCL Smart TV running a vulnerable UPnP/DLNA MediaRenderer implementation is affected by a remote, unauthenticated Denial of Service (DoS) condition. By sending a flood of malformed or oversized SetAVTransportURI SOAP requests to the UPnP control endpoint, an attacker can cause the device to become unresponsive. This denial persists as long as the attack continues and affects all forms of TV operation. Manual user control and even reboots do not restore functionality unless the flood stops.

- [https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport) :  ![starts](https://img.shields.io/github/stars/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg) ![forks](https://img.shields.io/github/forks/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg)


## CVE-2025-55971
 TCL 65C655 Smart TV, running firmware version V8-R75PT01-LF1V269.001116 (Android TV, Kernel 5.4.242+), is vulnerable to a blind, unauthenticated Server-Side Request Forgery (SSRF) vulnerability via the UPnP MediaRenderer service (AVTransport:1). The device accepts unauthenticated SetAVTransportURI SOAP requests over TCP/16398 and attempts to retrieve externally referenced URIs, including attacker-controlled payloads. The blind SSRF allows for sending requests on behalf of the TV, which can be leveraged to probe for other internal or external services accessible by the device (e.g., 127.0.0.1:16XXX, LAN services, or internet targets), potentially enabling additional exploit chains.

- [https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport) :  ![starts](https://img.shields.io/github/stars/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg) ![forks](https://img.shields.io/github/forks/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg)


## CVE-2025-36604
 Dell Unity, version(s) 5.5 and prior, contain(s) an Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability, leading to arbitrary command execution.

- [https://github.com/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604](https://github.com/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604.svg)


## CVE-2025-34226
 OpenPLC Runtime v3 contains an input validation flaw in the /upload-program-action endpoint: the epoch_time field supplied during program uploads is not validated and can be crafted to induce corruption of the programs database. After a successful malformed upload the runtime continues to operate until a restart; on restart the runtime can fail to start because of corrupted database entries, resulting in persistent denial of service requiring complete rebase of the product to recover. This vulnerability was remediated by commit 095ee09623dd229b64ad3a1db38a901a3772f6fc.

- [https://github.com/Eyodav/CVE-2025-34226](https://github.com/Eyodav/CVE-2025-34226) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34226.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34226.svg)


## CVE-2025-9286
 The Appy Pie Connect for WooCommerce plugin for WordPress is vulnerable to Privilege Escalation due to missing authorization within the reset_user_password() REST handler in all versions up to, and including, 1.1.2. This makes it possible for unauthenticated attackers to to reset the password of arbitrary users, including administrators, thereby gaining administrative access.

- [https://github.com/Nxploited/CVE-2025-9286](https://github.com/Nxploited/CVE-2025-9286) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-9286.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-9286.svg)


## CVE-2025-8625
 The Copypress Rest API plugin for WordPress is vulnerable to Remote Code Execution via copyreap_handle_image() Function in versions 1.1 to 1.2. The plugin falls back to a hard-coded JWT signing key when no secret is defined and does not restrict which file types can be fetched and saved as attachments. As a result, unauthenticated attackers can forge a valid token to gain elevated privileges and upload an arbitrary file (e.g. a PHP script) through the image handler, leading to remote code execution.

- [https://github.com/Nxploited/CVE-2025-8625](https://github.com/Nxploited/CVE-2025-8625) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8625.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8625.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/Gabriel-Lacorte/CVE-2025-7771](https://github.com/Gabriel-Lacorte/CVE-2025-7771) :  ![starts](https://img.shields.io/github/stars/Gabriel-Lacorte/CVE-2025-7771.svg) ![forks](https://img.shields.io/github/forks/Gabriel-Lacorte/CVE-2025-7771.svg)


## CVE-2025-7558
 A vulnerability was found in code-projects Voting System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /admin/positions_add.php. The manipulation of the argument description leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/rundas-r00t/CVE-2025-7558-PoC](https://github.com/rundas-r00t/CVE-2025-7558-PoC) :  ![starts](https://img.shields.io/github/stars/rundas-r00t/CVE-2025-7558-PoC.svg) ![forks](https://img.shields.io/github/forks/rundas-r00t/CVE-2025-7558-PoC.svg)


## CVE-2025-6073
This issue affects RMC-100: from 2105457-043 through 2105457-045; RMC-100 LITE: from 2106229-015 through 2106229-016.

- [https://github.com/WinDyAlphA/CVE-2025-60736](https://github.com/WinDyAlphA/CVE-2025-60736) :  ![starts](https://img.shields.io/github/stars/WinDyAlphA/CVE-2025-60736.svg) ![forks](https://img.shields.io/github/forks/WinDyAlphA/CVE-2025-60736.svg)


## CVE-2023-49968
 Customer Support System v1 was discovered to contain a SQL injection vulnerability via the id parameter at /customer_support/manage_department.php.

- [https://github.com/geraldoalcantara/CVE-2023-49968](https://github.com/geraldoalcantara/CVE-2023-49968) :  ![starts](https://img.shields.io/github/stars/geraldoalcantara/CVE-2023-49968.svg) ![forks](https://img.shields.io/github/forks/geraldoalcantara/CVE-2023-49968.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/nivedh-j/EternalBlue-Explained](https://github.com/nivedh-j/EternalBlue-Explained) :  ![starts](https://img.shields.io/github/stars/nivedh-j/EternalBlue-Explained.svg) ![forks](https://img.shields.io/github/forks/nivedh-j/EternalBlue-Explained.svg)


## CVE-2016-0792
 Multiple unspecified API endpoints in Jenkins before 1.650 and LTS before 1.642.2 allow remote authenticated users to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.

- [https://github.com/bugdotexe/CVE-2016-0792](https://github.com/bugdotexe/CVE-2016-0792) :  ![starts](https://img.shields.io/github/stars/bugdotexe/CVE-2016-0792.svg) ![forks](https://img.shields.io/github/forks/bugdotexe/CVE-2016-0792.svg)

