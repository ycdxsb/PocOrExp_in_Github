# Update 2025-04-10
## CVE-2025-32013
 LNbits is a Lightning wallet and accounts system. A Server-Side Request Forgery (SSRF) vulnerability has been discovered in LNbits' LNURL authentication handling functionality. When processing LNURL authentication requests, the application accepts a callback URL parameter and makes an HTTP request to that URL using the httpx library with redirect following enabled. The application doesn't properly validate the callback URL, allowing attackers to specify internal network addresses and access internal resources.

- [https://github.com/Mohith-T/CVE-2025-32013](https://github.com/Mohith-T/CVE-2025-32013) :  ![starts](https://img.shields.io/github/stars/Mohith-T/CVE-2025-32013.svg) ![forks](https://img.shields.io/github/forks/Mohith-T/CVE-2025-32013.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/Immersive-Labs-Sec/CVE-2025-31161](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2025-31161.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/goncalocsousa1/CVE-2025-29927](https://github.com/goncalocsousa1/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/goncalocsousa1/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/goncalocsousa1/CVE-2025-29927.svg)
- [https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/pickovven/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/pickovven/vulnerable-nextjs-14-CVE-2025-29927.svg)
- [https://github.com/ValGrace/middleware-auth-bypass](https://github.com/ValGrace/middleware-auth-bypass) :  ![starts](https://img.shields.io/github/stars/ValGrace/middleware-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/ValGrace/middleware-auth-bypass.svg)


## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).

- [https://github.com/ladyg00se/CVE-2025-27840-WIP](https://github.com/ladyg00se/CVE-2025-27840-WIP) :  ![starts](https://img.shields.io/github/stars/ladyg00se/CVE-2025-27840-WIP.svg) ![forks](https://img.shields.io/github/forks/ladyg00se/CVE-2025-27840-WIP.svg)


## CVE-2025-26633
 Improper neutralization in Microsoft Management Console allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/sandsoncosta/CVE-2025-26633](https://github.com/sandsoncosta/CVE-2025-26633) :  ![starts](https://img.shields.io/github/stars/sandsoncosta/CVE-2025-26633.svg) ![forks](https://img.shields.io/github/forks/sandsoncosta/CVE-2025-26633.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/GadaLuBau1337/CVE-2025-24813](https://github.com/GadaLuBau1337/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/GadaLuBau1337/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/GadaLuBau1337/CVE-2025-24813.svg)


## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/N4SL1/CVE-2025-22457-PoC](https://github.com/N4SL1/CVE-2025-22457-PoC) :  ![starts](https://img.shields.io/github/stars/N4SL1/CVE-2025-22457-PoC.svg) ![forks](https://img.shields.io/github/forks/N4SL1/CVE-2025-22457-PoC.svg)
- [https://github.com/Vinylrider/ivantiunlocker](https://github.com/Vinylrider/ivantiunlocker) :  ![starts](https://img.shields.io/github/stars/Vinylrider/ivantiunlocker.svg) ![forks](https://img.shields.io/github/forks/Vinylrider/ivantiunlocker.svg)


## CVE-2025-3165
 A vulnerability classified as critical has been found in thu-pacman chitu 0.1.0. This affects the function torch.load of the file chitu/chitu/backend.py. The manipulation of the argument ckpt_path/quant_ckpt_dir leads to deserialization. An attack has to be approached locally.

- [https://github.com/gregk4sec/CVE-2025-31651](https://github.com/gregk4sec/CVE-2025-31651) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-31651.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-31651.svg)


## CVE-2025-2825
 DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2025-31161. Reason: This Record is a reservation duplicate of CVE-2025-31161. Notes: All CVE users should reference CVE-2025-31161 instead of this Record. All references and descriptions in this Record have been removed to prevent accidental usage.

- [https://github.com/Immersive-Labs-Sec/CVE-2025-31161](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2025-31161.svg)


## CVE-2025-2807
 The Motors – Car Dealership & Classified Listings Plugin plugin for WordPress is vulnerable to arbitrary plugin installations due to a missing capability check in the mvl_setup_wizard_install_plugin() function in all versions up to, and including, 1.4.64. This makes it possible for authenticated attackers, with Subscriber-level access and above, to install and activate arbitrary plugins on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-2807](https://github.com/Nxploited/CVE-2025-2807) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2807.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2807.svg)


## CVE-2024-53027
 Transient DOS may occur while processing the country IE.

- [https://github.com/ladyg00se/CVE-2024-53027-WIP](https://github.com/ladyg00se/CVE-2024-53027-WIP) :  ![starts](https://img.shields.io/github/stars/ladyg00se/CVE-2024-53027-WIP.svg) ![forks](https://img.shields.io/github/forks/ladyg00se/CVE-2024-53027-WIP.svg)


## CVE-2024-5521
 Two Cross-Site Scripting vulnerabilities have been discovered in Alkacon's OpenCMS affecting version 16, which could allow a user having the roles of gallery editor or VFS resource manager will have the permission to upload images in the .svg format containing JavaScript code. The code will be executed the moment another user accesses the image.

- [https://github.com/c4cnm/CVE-2024-55210](https://github.com/c4cnm/CVE-2024-55210) :  ![starts](https://img.shields.io/github/stars/c4cnm/CVE-2024-55210.svg) ![forks](https://img.shields.io/github/forks/c4cnm/CVE-2024-55210.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/ladyg00se/CVE-2023-45866_WIP](https://github.com/ladyg00se/CVE-2023-45866_WIP) :  ![starts](https://img.shields.io/github/stars/ladyg00se/CVE-2023-45866_WIP.svg) ![forks](https://img.shields.io/github/forks/ladyg00se/CVE-2023-45866_WIP.svg)


## CVE-2023-32007
Users are recommended to upgrade to a supported version of Apache Spark, such as version 3.4.0.

- [https://github.com/Lee0568/CVE-2023-32007](https://github.com/Lee0568/CVE-2023-32007) :  ![starts](https://img.shields.io/github/stars/Lee0568/CVE-2023-32007.svg) ![forks](https://img.shields.io/github/forks/Lee0568/CVE-2023-32007.svg)


## CVE-2023-2255
 Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used "floating frames" linked to external files, would load the contents of those frames without prompting the user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.

- [https://github.com/G4sp4rCS/CVE-2023-2255](https://github.com/G4sp4rCS/CVE-2023-2255) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/CVE-2023-2255.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/CVE-2023-2255.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/RathoreAbhiii/Folina-Vulnerability-Exploitation-Detection-and-Mitigation](https://github.com/RathoreAbhiii/Folina-Vulnerability-Exploitation-Detection-and-Mitigation) :  ![starts](https://img.shields.io/github/stars/RathoreAbhiii/Folina-Vulnerability-Exploitation-Detection-and-Mitigation.svg) ![forks](https://img.shields.io/github/forks/RathoreAbhiii/Folina-Vulnerability-Exploitation-Detection-and-Mitigation.svg)


## CVE-2022-0952
 The Sitemap by click5 WordPress plugin before 1.0.36 does not have authorisation and CSRF checks when updating options via a REST endpoint, and does not ensure that the option to be updated belongs to the plugin. As a result, unauthenticated attackers could change arbitrary blog options, such as the users_can_register and default_role, allowing them to create a new admin account and take over the blog.

- [https://github.com/RandomRobbieBF/CVE-2022-0952](https://github.com/RandomRobbieBF/CVE-2022-0952) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2022-0952.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2022-0952.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)

