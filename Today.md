# Update 2025-05-03
## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ibrahimsql/CVE-2025-31161](https://github.com/ibrahimsql/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ibrahimsql/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ibrahimsql/CVE-2025-31161.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/S4mma3l/CVE-2025-24054](https://github.com/S4mma3l/CVE-2025-24054) :  ![starts](https://img.shields.io/github/stars/S4mma3l/CVE-2025-24054.svg) ![forks](https://img.shields.io/github/forks/S4mma3l/CVE-2025-24054.svg)


## CVE-2025-20029
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/schoi1337/CVE-2025-20029-simulation](https://github.com/schoi1337/CVE-2025-20029-simulation) :  ![starts](https://img.shields.io/github/stars/schoi1337/CVE-2025-20029-simulation.svg) ![forks](https://img.shields.io/github/forks/schoi1337/CVE-2025-20029-simulation.svg)


## CVE-2025-4162
 A vulnerability classified as critical was found in PCMan FTP Server up to 2.0.7. This vulnerability affects unknown code of the component ASCII Command Handler. The manipulation leads to buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/NotItsSixtyN3in/CVE-2025-4162028](https://github.com/NotItsSixtyN3in/CVE-2025-4162028) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162028.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162028.svg)
- [https://github.com/NotItsSixtyN3in/CVE-2025-4162030](https://github.com/NotItsSixtyN3in/CVE-2025-4162030) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162030.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162030.svg)
- [https://github.com/NotItsSixtyN3in/CVE-2025-4162029](https://github.com/NotItsSixtyN3in/CVE-2025-4162029) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162029.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162029.svg)
- [https://github.com/NotItsSixtyN3in/CVE-2025-4162026](https://github.com/NotItsSixtyN3in/CVE-2025-4162026) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162026.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162026.svg)
- [https://github.com/NotItsSixtyN3in/CVE-2025-4162027](https://github.com/NotItsSixtyN3in/CVE-2025-4162027) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162027.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162027.svg)
- [https://github.com/NotItsSixtyN3in/CVE-2025-4162025](https://github.com/NotItsSixtyN3in/CVE-2025-4162025) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162025.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162025.svg)


## CVE-2025-2068
 An open redirect vulnerability was reported in the FileZ client that could allow information disclosure if a crafted url is visited by a local user.

- [https://github.com/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk](https://github.com/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk) :  ![starts](https://img.shields.io/github/stars/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg) ![forks](https://img.shields.io/github/forks/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg)


## CVE-2025-1265
 An OS command injection vulnerability exists in Vinci Protocol Analyzer that could allow an attacker to escalate privileges and perform code execution on affected system.

- [https://github.com/Yuweixn/Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Yuweixn/Anydesk-Exploit-CVE-2025-12654-RCE-Builder) :  ![starts](https://img.shields.io/github/stars/Yuweixn/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg) ![forks](https://img.shields.io/github/forks/Yuweixn/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/JadeByteZen/CVE-2024-31317-PoC-Deployer](https://github.com/JadeByteZen/CVE-2024-31317-PoC-Deployer) :  ![starts](https://img.shields.io/github/stars/JadeByteZen/CVE-2024-31317-PoC-Deployer.svg) ![forks](https://img.shields.io/github/forks/JadeByteZen/CVE-2024-31317-PoC-Deployer.svg)
- [https://github.com/mianliupindao/CVE-2024-31317-PoC-Deployer](https://github.com/mianliupindao/CVE-2024-31317-PoC-Deployer) :  ![starts](https://img.shields.io/github/stars/mianliupindao/CVE-2024-31317-PoC-Deployer.svg) ![forks](https://img.shields.io/github/forks/mianliupindao/CVE-2024-31317-PoC-Deployer.svg)


## CVE-2024-27956
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/devsec23/CVE-2024-27956](https://github.com/devsec23/CVE-2024-27956) :  ![starts](https://img.shields.io/github/stars/devsec23/CVE-2024-27956.svg) ![forks](https://img.shields.io/github/forks/devsec23/CVE-2024-27956.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/Rohith-Reddy-Y/Zero-Day-Vulnerability-Exploitation-Detection-Tool](https://github.com/Rohith-Reddy-Y/Zero-Day-Vulnerability-Exploitation-Detection-Tool) :  ![starts](https://img.shields.io/github/stars/Rohith-Reddy-Y/Zero-Day-Vulnerability-Exploitation-Detection-Tool.svg) ![forks](https://img.shields.io/github/forks/Rohith-Reddy-Y/Zero-Day-Vulnerability-Exploitation-Detection-Tool.svg)


## CVE-2023-40355
 Cross Site Scripting (XSS) vulnerability in Axigen versions 10.3.3.0 before 10.3.3.59, 10.4.0 before 10.4.19, and 10.5.0 before 10.5.5, allows authenticated attackers to execute arbitrary code and obtain sensitive information via the logic for switching between the Standard and Ajax versions.

- [https://github.com/ace-83/CVE-2023-40355](https://github.com/ace-83/CVE-2023-40355) :  ![starts](https://img.shields.io/github/stars/ace-83/CVE-2023-40355.svg) ![forks](https://img.shields.io/github/forks/ace-83/CVE-2023-40355.svg)


## CVE-2023-4226
 Unrestricted file upload in `/main/inc/ajax/work.ajax.php` in Chamilo LMS = v1.11.24 allows authenticated attackers with learner role to obtain remote code execution via uploading of PHP files.

- [https://github.com/SkyW4r33x/CVE-2023-4226](https://github.com/SkyW4r33x/CVE-2023-4226) :  ![starts](https://img.shields.io/github/stars/SkyW4r33x/CVE-2023-4226.svg) ![forks](https://img.shields.io/github/forks/SkyW4r33x/CVE-2023-4226.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/0x3n19m4/CVE-2016-5195](https://github.com/0x3n19m4/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/0x3n19m4/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/0x3n19m4/CVE-2016-5195.svg)


## CVE-2012-3576
 Unrestricted file upload vulnerability in php/upload.php in the wpStoreCart plugin before 2.5.30 for WordPress allows remote attackers to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in uploads/wpstorecart.

- [https://github.com/Ydvmtzv/wpstorecart-exploit](https://github.com/Ydvmtzv/wpstorecart-exploit) :  ![starts](https://img.shields.io/github/stars/Ydvmtzv/wpstorecart-exploit.svg) ![forks](https://img.shields.io/github/forks/Ydvmtzv/wpstorecart-exploit.svg)

