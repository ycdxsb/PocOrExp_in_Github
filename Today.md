# Update 2025-09-29
## CVE-2025-59932
 Flag Forge is a Capture The Flag (CTF) platform. From versions 2.0.0 to before 2.3.1, the /api/resources endpoint previously allowed POST and DELETE requests without proper authentication or authorization. This could have enabled unauthorized users to create, modify, or delete resources on the platform. The issue has been fixed in FlagForge version 2.3.1.

- [https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932](https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932) :  ![starts](https://img.shields.io/github/stars/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg) ![forks](https://img.shields.io/github/forks/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg)


## CVE-2025-59843
 Flag Forge is a Capture The Flag (CTF) platform. From versions 2.0.0 to before 2.3.1, the public endpoint /api/user/[username] returns user email addresses in its JSON response. The problem has been patched in FlagForge version 2.3.1. The fix removes email addresses from public API responses while keeping the endpoint publicly accessible. Users should upgrade to version 2.3.1 or later to eliminate exposure. There are no workarounds for this vulnerability.

- [https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932](https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932) :  ![starts](https://img.shields.io/github/stars/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg) ![forks](https://img.shields.io/github/forks/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg)


## CVE-2025-39596
 Weak Authentication vulnerability in Quentn.com GmbH Quentn WP allows Privilege Escalation. This issue affects Quentn WP: from n/a through 1.2.8.

- [https://github.com/Nxploited/CVE-2025-39596](https://github.com/Nxploited/CVE-2025-39596) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39596.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39596.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161](https://github.com/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161.svg)


## CVE-2025-20333
 This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests. An attacker with valid VPN user credentials could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute arbitrary code as root, possibly resulting in the complete compromise of the affected device.

- [https://github.com/callinston/CVE-2025-20333](https://github.com/callinston/CVE-2025-20333) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-20333.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-20333.svg)


## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

- [https://github.com/orange0Mint/CVE-2025-10035_GoAnywhere](https://github.com/orange0Mint/CVE-2025-10035_GoAnywhere) :  ![starts](https://img.shields.io/github/stars/orange0Mint/CVE-2025-10035_GoAnywhere.svg) ![forks](https://img.shields.io/github/forks/orange0Mint/CVE-2025-10035_GoAnywhere.svg)


## CVE-2025-9999
 Some payload elements of the messages sent between two stations in a networking architecture are not properly checked on the receiving station allowing an attacker to execute unauthorized commands in the application.

- [https://github.com/umxr286/ExploitScript](https://github.com/umxr286/ExploitScript) :  ![starts](https://img.shields.io/github/stars/umxr286/ExploitScript.svg) ![forks](https://img.shields.io/github/forks/umxr286/ExploitScript.svg)


## CVE-2025-5676
 A vulnerability was found in Campcodes Online Recruitment Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /admin/ajax.php?action=login. The manipulation of the argument Username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Remenis/CVE-2025-56764-trivision-nc227wf](https://github.com/Remenis/CVE-2025-56764-trivision-nc227wf) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-56764-trivision-nc227wf.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-56764-trivision-nc227wf.svg)


## CVE-2025-5304
 The PT Project Notebooks plugin for WordPress is vulnerable to Privilege Escalation due to missing authorization in the wpnb_pto_new_users_add() function in versions 1.0.0 through 1.1.3. This makes it possible for unauthenticated attackers to elevate their privileges to that of an administrator.

- [https://github.com/Nxploited/CVE-2025-5304](https://github.com/Nxploited/CVE-2025-5304) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5304.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5304.svg)


## CVE-2025-4606
 The Sala - Startup & SaaS WordPress Theme theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.1.4. This is due to the theme not properly validating a user's identity prior to updating their details like password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.

- [https://github.com/UcenHaxor07/CVE-2025-4606](https://github.com/UcenHaxor07/CVE-2025-4606) :  ![starts](https://img.shields.io/github/stars/UcenHaxor07/CVE-2025-4606.svg) ![forks](https://img.shields.io/github/forks/UcenHaxor07/CVE-2025-4606.svg)


## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/Adel2411/cve-2023-38408](https://github.com/Adel2411/cve-2023-38408) :  ![starts](https://img.shields.io/github/stars/Adel2411/cve-2023-38408.svg) ![forks](https://img.shields.io/github/forks/Adel2411/cve-2023-38408.svg)


## CVE-2022-36537
 ZK Framework v9.6.1, 9.6.0.1, 9.5.1.3, 9.0.1.2 and 8.6.4.1 allows attackers to access sensitive information via a crafted POST request sent to the component AuUploader.

- [https://github.com/ethan-repo-lab4b6/CVE-2022-36537](https://github.com/ethan-repo-lab4b6/CVE-2022-36537) :  ![starts](https://img.shields.io/github/stars/ethan-repo-lab4b6/CVE-2022-36537.svg) ![forks](https://img.shields.io/github/forks/ethan-repo-lab4b6/CVE-2022-36537.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/nika0x38/CVE-2009-2265](https://github.com/nika0x38/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/nika0x38/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/nika0x38/CVE-2009-2265.svg)

