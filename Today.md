# Update 2025-10-18
## CVE-2025-62410
 In versions before 20.0.2, it was found that --disallow-code-generation-from-strings is not sufficient for isolating untrusted JavaScript in happy-dom. The untrusted script and the rest of the application still run in the same Isolate/process, so attackers can deploy prototype pollution payloads to hijack important references like "process" in the example below, or to hijack control flow via flipping checks of undefined property. This vulnerability is due to an incomplete fix for CVE-2025-61927. The vulnerability is fixed in 20.0.2.

- [https://github.com/SubZeroHackerz/CVE-2025-62410](https://github.com/SubZeroHackerz/CVE-2025-62410) :  ![starts](https://img.shields.io/github/stars/SubZeroHackerz/CVE-2025-62410.svg) ![forks](https://img.shields.io/github/forks/SubZeroHackerz/CVE-2025-62410.svg)


## CVE-2025-62376
 pwn.college DOJO is an education platform for learning cybersecurity. In versions up to and including commit 781d91157cfc234a434d0bab45cbcf97894c642e, the /workspace endpoint contains an improper authentication vulnerability that allows an attacker to access any active Windows VM without proper authorization. The vulnerability occurs in the view_desktop function where the user is retrieved via a URL parameter without verifying that the requester has administrative privileges. An attacker can supply any user ID and arbitrary password in the request parameters to impersonate another user. When requesting a Windows desktop service, the function does not validate the supplied password before generating access credentials, allowing the attacker to obtain an iframe source URL that grants full access to the target user's Windows VM. This impacts all users with active Windows VMs, as an attacker can access and modify data on the Windows machine and in the home directory of the associated Linux machine via the Z: drive. This issue has been patched in commit 467db0b9ea0d9a929dc89b41f6eb59f7cfc68bef. No known workarounds exist.

- [https://github.com/digitalsnemesis/CVE-2025-62376](https://github.com/digitalsnemesis/CVE-2025-62376) :  ![starts](https://img.shields.io/github/stars/digitalsnemesis/CVE-2025-62376.svg) ![forks](https://img.shields.io/github/forks/digitalsnemesis/CVE-2025-62376.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit](https://github.com/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit.svg)
- [https://github.com/MindflareX/CVE-2025-61882-POC](https://github.com/MindflareX/CVE-2025-61882-POC) :  ![starts](https://img.shields.io/github/stars/MindflareX/CVE-2025-61882-POC.svg) ![forks](https://img.shields.io/github/forks/MindflareX/CVE-2025-61882-POC.svg)


## CVE-2025-59214
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/rubenformation/CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/rubenformation/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/rubenformation/CVE-2025-50154.svg)


## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.

- [https://github.com/snowcrashlord/CVE-2025-55315](https://github.com/snowcrashlord/CVE-2025-55315) :  ![starts](https://img.shields.io/github/stars/snowcrashlord/CVE-2025-55315.svg) ![forks](https://img.shields.io/github/forks/snowcrashlord/CVE-2025-55315.svg)
- [https://github.com/sirredbeard/CVE-2025-55315-repro](https://github.com/sirredbeard/CVE-2025-55315-repro) :  ![starts](https://img.shields.io/github/stars/sirredbeard/CVE-2025-55315-repro.svg) ![forks](https://img.shields.io/github/forks/sirredbeard/CVE-2025-55315-repro.svg)
- [https://github.com/nickcopi/CVE-2025-55315-detection-playground](https://github.com/nickcopi/CVE-2025-55315-detection-playground) :  ![starts](https://img.shields.io/github/stars/nickcopi/CVE-2025-55315-detection-playground.svg) ![forks](https://img.shields.io/github/forks/nickcopi/CVE-2025-55315-detection-playground.svg)


## CVE-2025-49553
 Adobe Connect versions 12.9 and earlier are affected by a DOM-based Cross-Site Scripting (XSS) vulnerability that could be exploited by an attacker to execute malicious scripts in a victim's browser. Exploitation of this issue requires user interaction in that a victim must navigate to a crafted web page. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality and integrity impact as high. Scope is changed.

- [https://github.com/silentexploitexe/CVE-2025-49553](https://github.com/silentexploitexe/CVE-2025-49553) :  ![starts](https://img.shields.io/github/stars/silentexploitexe/CVE-2025-49553.svg) ![forks](https://img.shields.io/github/forks/silentexploitexe/CVE-2025-49553.svg)


## CVE-2025-41020
 Insecure direct object reference (IDOR) vulnerability in Sergestec's Exito v8.0. This vulnerability allows an attacker to access data belonging to other customers through the 'id' parameter in '/admin/ticket_a4.php'.

- [https://github.com/ImTheCopilotNow/CVE-2025-4102025](https://github.com/ImTheCopilotNow/CVE-2025-4102025) :  ![starts](https://img.shields.io/github/stars/ImTheCopilotNow/CVE-2025-4102025.svg) ![forks](https://img.shields.io/github/forks/ImTheCopilotNow/CVE-2025-4102025.svg)


## CVE-2025-32324
 In onCommand of ActivityManagerShellCommand.java, there is a possible arbitrary activity launch due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/rifting/UnrestrictedUserCreator](https://github.com/rifting/UnrestrictedUserCreator) :  ![starts](https://img.shields.io/github/stars/rifting/UnrestrictedUserCreator.svg) ![forks](https://img.shields.io/github/forks/rifting/UnrestrictedUserCreator.svg)


## CVE-2025-24990
Microsoft recommends removing any existing dependencies on this hardware.

- [https://github.com/moiz-2x/CVE-2025-24990_POC](https://github.com/moiz-2x/CVE-2025-24990_POC) :  ![starts](https://img.shields.io/github/stars/moiz-2x/CVE-2025-24990_POC.svg) ![forks](https://img.shields.io/github/forks/moiz-2x/CVE-2025-24990_POC.svg)


## CVE-2025-20282
This vulnerability is due a lack of file validation checks that would prevent uploaded files from being placed in privileged directories on an affected system. An attacker could exploit this vulnerability by uploading a crafted file to the affected device. A successful exploit could allow the attacker to store malicious files on the affected system and then execute arbitrary code or obtain root privileges on the system.

- [https://github.com/skadevare/CiscoISE-CVE-2025-20282-POC](https://github.com/skadevare/CiscoISE-CVE-2025-20282-POC) :  ![starts](https://img.shields.io/github/stars/skadevare/CiscoISE-CVE-2025-20282-POC.svg) ![forks](https://img.shields.io/github/forks/skadevare/CiscoISE-CVE-2025-20282-POC.svg)


## CVE-2025-10850
 The Felan Framework plugin for WordPress is vulnerable to improper authentication in versions up to, and including, 1.1.4. This is due to the hardcoded password in the 'fb_ajax_login_or_register' function and in the 'google_ajax_login_or_register' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, if they registered with facebook or google social login and did not change their password.

- [https://github.com/pulsecipher/CVE-2025-10850](https://github.com/pulsecipher/CVE-2025-10850) :  ![starts](https://img.shields.io/github/stars/pulsecipher/CVE-2025-10850.svg) ![forks](https://img.shields.io/github/forks/pulsecipher/CVE-2025-10850.svg)


## CVE-2025-9242
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.3 and 2025.1.

- [https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242](https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/aldisakti2/CVE-2025-8088-BUILDER-Winrar-Tool](https://github.com/aldisakti2/CVE-2025-8088-BUILDER-Winrar-Tool) :  ![starts](https://img.shields.io/github/stars/aldisakti2/CVE-2025-8088-BUILDER-Winrar-Tool.svg) ![forks](https://img.shields.io/github/forks/aldisakti2/CVE-2025-8088-BUILDER-Winrar-Tool.svg)


## CVE-2025-5645
 A vulnerability, which was classified as problematic, was found in Radare2 5.9.9. This affects the function r_cons_pal_init in the library /libr/cons/pal.c of the component radiff2. The manipulation of the argument -T leads to memory corruption. Attacking locally is a requirement. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. The real existence of this vulnerability is still doubted at the moment. The identifier of the patch is 5705d99cc1f23f36f9a84aab26d1724010b97798. It is recommended to apply a patch to fix this issue. The documentation explains that the parameter -T is experimental and "crashy". Further analysis has shown "the race is not a real problem unless you use asan". A new warning has been added.

- [https://github.com/apboss123/CVE-2025-56450](https://github.com/apboss123/CVE-2025-56450) :  ![starts](https://img.shields.io/github/stars/apboss123/CVE-2025-56450.svg) ![forks](https://img.shields.io/github/forks/apboss123/CVE-2025-56450.svg)


## CVE-2024-31497
 In PuTTY 0.68 through 0.80 before 0.81, biased ECDSA nonce generation allows an attacker to recover a user's NIST P-521 secret key via a quick attack in approximately 60 signatures. This is especially important in a scenario where an adversary is able to read messages signed by PuTTY or Pageant. The required set of signed messages may be publicly readable because they are stored in a public Git service that supports use of SSH for commit signing, and the signatures were made by Pageant through an agent-forwarding mechanism. In other words, an adversary may already have enough signature information to compromise a victim's private key, even if there is no further use of vulnerable PuTTY versions. After a key compromise, an adversary may be able to conduct supply-chain attacks on software maintained in Git. A second, independent scenario is that the adversary is an operator of an SSH server to which the victim authenticates (for remote login or file copy), even though this server is not fully trusted by the victim, and the victim uses the same private key for SSH connections to other services operated by other entities. Here, the rogue server operator (who would otherwise have no way to determine the victim's private key) can derive the victim's private key, and then use it for unauthorized access to those other services. If the other services include Git services, then again it may be possible to conduct supply-chain attacks on software maintained in Git. This also affects, for example, FileZilla before 3.67.0, WinSCP before 6.3.3, TortoiseGit before 2.15.0.1, and TortoiseSVN through 1.14.6.

- [https://github.com/LukaWynants/Onderzoek_CVE-2024-31497-POC](https://github.com/LukaWynants/Onderzoek_CVE-2024-31497-POC) :  ![starts](https://img.shields.io/github/stars/LukaWynants/Onderzoek_CVE-2024-31497-POC.svg) ![forks](https://img.shields.io/github/forks/LukaWynants/Onderzoek_CVE-2024-31497-POC.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/M1lo25/CS50FinalProject](https://github.com/M1lo25/CS50FinalProject) :  ![starts](https://img.shields.io/github/stars/M1lo25/CS50FinalProject.svg) ![forks](https://img.shields.io/github/forks/M1lo25/CS50FinalProject.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/madhusudhan-in/CVE_2023_44487-Rapid_Reset](https://github.com/madhusudhan-in/CVE_2023_44487-Rapid_Reset) :  ![starts](https://img.shields.io/github/stars/madhusudhan-in/CVE_2023_44487-Rapid_Reset.svg) ![forks](https://img.shields.io/github/forks/madhusudhan-in/CVE_2023_44487-Rapid_Reset.svg)


## CVE-2022-31192
 DSpace open source software is a repository application which provides durable access to digital resources. dspace-jspui is a UI component for DSpace. The JSPUI "Request a Copy" feature does not properly escape values submitted and stored from the "Request a Copy" form. This means that item requests could be vulnerable to XSS attacks. This vulnerability only impacts the JSPUI. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31192_5-100](https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31192_5-100) :  ![starts](https://img.shields.io/github/stars/shoucheng3/DSpace__DSpace_CVE-2022-31192_5-100.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/DSpace__DSpace_CVE-2022-31192_5-100.svg)


## CVE-2022-1364
 Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/interruptlabs/uc_browser_poc_CVE-2022-1364](https://github.com/interruptlabs/uc_browser_poc_CVE-2022-1364) :  ![starts](https://img.shields.io/github/stars/interruptlabs/uc_browser_poc_CVE-2022-1364.svg) ![forks](https://img.shields.io/github/forks/interruptlabs/uc_browser_poc_CVE-2022-1364.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability

- [https://github.com/flyinbedxyz/CVE-2021-1732](https://github.com/flyinbedxyz/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/flyinbedxyz/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/flyinbedxyz/CVE-2021-1732.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/autocode07/cisagov__check-cve-2019-19781.4142e02b](https://github.com/autocode07/cisagov__check-cve-2019-19781.4142e02b) :  ![starts](https://img.shields.io/github/stars/autocode07/cisagov__check-cve-2019-19781.4142e02b.svg) ![forks](https://img.shields.io/github/forks/autocode07/cisagov__check-cve-2019-19781.4142e02b.svg)


## CVE-2019-5591
 A Default Configuration vulnerability in FortiOS may allow an unauthenticated attacker on the same subnet to intercept sensitive information by impersonating the LDAP server.

- [https://github.com/ayewo/fortios-ldap-mitm-poc-CVE-2019-5591](https://github.com/ayewo/fortios-ldap-mitm-poc-CVE-2019-5591) :  ![starts](https://img.shields.io/github/stars/ayewo/fortios-ldap-mitm-poc-CVE-2019-5591.svg) ![forks](https://img.shields.io/github/forks/ayewo/fortios-ldap-mitm-poc-CVE-2019-5591.svg)


## CVE-2017-1000367
 Todd Miller's sudo version 1.8.20 and earlier is vulnerable to an input validation (embedded spaces) in the get_process_ttyname() function resulting in information disclosure and command execution.

- [https://github.com/letsr00t/CVE-2017-1000367](https://github.com/letsr00t/CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/letsr00t/CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/letsr00t/CVE-2017-1000367.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/Pwdnx1337/CVE-2017-9841](https://github.com/Pwdnx1337/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2017-9841.svg)

