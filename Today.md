# Update 2025-06-07
## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/fearsoff-org/CVE-2025-49113](https://github.com/fearsoff-org/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/fearsoff-org/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/fearsoff-org/CVE-2025-49113.svg)
- [https://github.com/rasool13x/exploit-CVE-2025-49113](https://github.com/rasool13x/exploit-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/rasool13x/exploit-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/rasool13x/exploit-CVE-2025-49113.svg)


## CVE-2025-47827
 In IGEL OS before 11, Secure Boot can be bypassed because the igel-flash-driver module improperly verifies a cryptographic signature. Ultimately, a crafted root filesystem can be mounted from an unverified SquashFS image.

- [https://github.com/Zedeldi/CVE-2025-47827](https://github.com/Zedeldi/CVE-2025-47827) :  ![starts](https://img.shields.io/github/stars/Zedeldi/CVE-2025-47827.svg) ![forks](https://img.shields.io/github/forks/Zedeldi/CVE-2025-47827.svg)


## CVE-2025-46701
Users are recommended to upgrade to version 11.0.7, 10.1.41 or 9.0.105, which fixes the issue.

- [https://github.com/gregk4sec/CVE-2025-46701](https://github.com/gregk4sec/CVE-2025-46701) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-46701.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-46701.svg)


## CVE-2025-32756
 A stack-based buffer overflow vulnerability [CWE-121] in Fortinet FortiVoice versions 7.2.0, 7.0.0 through 7.0.6, 6.4.0 through 6.4.10, FortiRecorder versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.5, 6.4.0 through 6.4.5, FortiMail versions 7.6.0 through 7.6.2, 7.4.0 through 7.4.4, 7.2.0 through 7.2.7, 7.0.0 through 7.0.8, FortiNDR versions 7.6.0, 7.4.0 through 7.4.7, 7.2.0 through 7.2.4, 7.0.0 through 7.0.6, FortiCamera versions 2.1.0 through 2.1.3, 2.0 all versions, 1.1 all versions, allows a remote unauthenticated attacker to execute arbitrary code or commands via sending HTTP requests with specially crafted hash cookie.

- [https://github.com/kn0x0x/CVE-2025-32756-POC](https://github.com/kn0x0x/CVE-2025-32756-POC) :  ![starts](https://img.shields.io/github/stars/kn0x0x/CVE-2025-32756-POC.svg) ![forks](https://img.shields.io/github/forks/kn0x0x/CVE-2025-32756-POC.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/ibrahimsql/cve-2025-24893](https://github.com/ibrahimsql/cve-2025-24893) :  ![starts](https://img.shields.io/github/stars/ibrahimsql/cve-2025-24893.svg) ![forks](https://img.shields.io/github/forks/ibrahimsql/cve-2025-24893.svg)


## CVE-2025-22224
 VMware ESXi, and Workstation contain a TOCTOU (Time-of-Check Time-of-Use) vulnerability that leads to an out-of-bounds write. A malicious actor with local administrative privileges on a virtual machine may exploit this issue to execute code as the virtual machine's VMX process running on the host.

- [https://github.com/takerishunte/CVE-2025-22224](https://github.com/takerishunte/CVE-2025-22224) :  ![starts](https://img.shields.io/github/stars/takerishunte/CVE-2025-22224.svg) ![forks](https://img.shields.io/github/forks/takerishunte/CVE-2025-22224.svg)


## CVE-2025-5701
 The HyperComments plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the hc_request_handler function in all versions up to, and including, 1.2.2. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.

- [https://github.com/Harley21211/CVE-2025-5701-Exploit](https://github.com/Harley21211/CVE-2025-5701-Exploit) :  ![starts](https://img.shields.io/github/stars/Harley21211/CVE-2025-5701-Exploit.svg) ![forks](https://img.shields.io/github/forks/Harley21211/CVE-2025-5701-Exploit.svg)
- [https://github.com/Nxploited/CVE-2025-5701](https://github.com/Nxploited/CVE-2025-5701) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5701.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5701.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/takerishunte/CVE-2025-5419](https://github.com/takerishunte/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/takerishunte/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/takerishunte/CVE-2025-5419.svg)


## CVE-2025-4460
 A vulnerability classified as problematic has been found in TOTOLINK N150RT 3.4.0-B20190525. This affects an unknown part of the component URL Filtering Page. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers](https://github.com/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers) :  ![starts](https://img.shields.io/github/stars/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers.svg) ![forks](https://img.shields.io/github/forks/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers.svg)


## CVE-2025-3419
 The Event Manager, Events Calendar, Tickets, Registrations – Eventin plugin for WordPress is vulnerable to arbitrary file read in all versions up to, and including, 4.0.26 via the proxy_image() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/Yucaerin/CVE-2025-3419](https://github.com/Yucaerin/CVE-2025-3419) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-3419.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-3419.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/B1ack4sh/CVE-2025-3102](https://github.com/B1ack4sh/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/CVE-2025-3102.svg)


## CVE-2025-3054
 The WP User Frontend Pro plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the upload_files() function in all versions up to, and including, 4.1.3. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. Please note that this requires the 'Private Message' module to be enabled and the Business version of the PRO software to be in use.

- [https://github.com/frogchung/CVE-2025-3054-Exploit](https://github.com/frogchung/CVE-2025-3054-Exploit) :  ![starts](https://img.shields.io/github/stars/frogchung/CVE-2025-3054-Exploit.svg) ![forks](https://img.shields.io/github/forks/frogchung/CVE-2025-3054-Exploit.svg)


## CVE-2025-0316
 The WP Directorybox Manager plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.5. This is due to incorrect authentication in the 'wp_dp_enquiry_agent_contact_form_submit_callback' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the username.

- [https://github.com/zorvithonleon/CVE-2025-0316-Exploit](https://github.com/zorvithonleon/CVE-2025-0316-Exploit) :  ![starts](https://img.shields.io/github/stars/zorvithonleon/CVE-2025-0316-Exploit.svg) ![forks](https://img.shields.io/github/forks/zorvithonleon/CVE-2025-0316-Exploit.svg)
- [https://github.com/AvonBorn/CVE-2025-0316-Exploit](https://github.com/AvonBorn/CVE-2025-0316-Exploit) :  ![starts](https://img.shields.io/github/stars/AvonBorn/CVE-2025-0316-Exploit.svg) ![forks](https://img.shields.io/github/forks/AvonBorn/CVE-2025-0316-Exploit.svg)


## CVE-2024-53703
 A vulnerability in the SonicWall SMA100 SSLVPN firmware 10.2.1.13-72sv and earlier versions mod_httprp library loaded by the Apache web server allows remote attackers to cause Stack-based buffer overflow and potentially lead to code execution.

- [https://github.com/scrt/cve-2024-53703-poc](https://github.com/scrt/cve-2024-53703-poc) :  ![starts](https://img.shields.io/github/stars/scrt/cve-2024-53703-poc.svg) ![forks](https://img.shields.io/github/forks/scrt/cve-2024-53703-poc.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/l0n3m4n/CVE-2024-47176](https://github.com/l0n3m4n/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-47176.svg)


## CVE-2024-22274
 The vCenter Server contains an authenticated remote code execution vulnerability. A malicious actor with administrative privileges on the vCenter appliance shell may exploit this issue to run arbitrary commands on the underlying operating system.

- [https://github.com/l0n3m4n/CVE-2024-22274-RCE](https://github.com/l0n3m4n/CVE-2024-22274-RCE) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-22274-RCE.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-22274-RCE.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/l0n3m4n/CVE-2024-6387](https://github.com/l0n3m4n/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-6387.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/l0n3m4n/CVE-2024-4577-RCE](https://github.com/l0n3m4n/CVE-2024-4577-RCE) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-4577-RCE.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-4577-RCE.svg)


## CVE-2023-29489
 An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.

- [https://github.com/Thuankobtcode/CVE-2023-29489](https://github.com/Thuankobtcode/CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/Thuankobtcode/CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/Thuankobtcode/CVE-2023-29489.svg)


## CVE-2023-5612
 An issue has been discovered in GitLab affecting all versions before 16.6.6, 16.7 prior to 16.7.4, and 16.8 prior to 16.8.1. It was possible to read the user email address via tags feed although the visibility in the user profile has been disabled.

- [https://github.com/TopskiyPavelQwertyGang/Review.CVE-2023-5612](https://github.com/TopskiyPavelQwertyGang/Review.CVE-2023-5612) :  ![starts](https://img.shields.io/github/stars/TopskiyPavelQwertyGang/Review.CVE-2023-5612.svg) ![forks](https://img.shields.io/github/forks/TopskiyPavelQwertyGang/Review.CVE-2023-5612.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/l0n3m4n/CVE-2022-29078](https://github.com/l0n3m4n/CVE-2022-29078) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2022-29078.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2022-29078.svg)


## CVE-2021-30862
 A validation issue was addressed with improved input sanitization. This issue is fixed in iTunes U 3.8.3. Processing a maliciously crafted URL may lead to arbitrary javascript code execution.

- [https://github.com/3h6-1/CVE-2021-30862](https://github.com/3h6-1/CVE-2021-30862) :  ![starts](https://img.shields.io/github/stars/3h6-1/CVE-2021-30862.svg) ![forks](https://img.shields.io/github/forks/3h6-1/CVE-2021-30862.svg)


## CVE-2020-14871
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: Pluggable authentication module). Supported versions that are affected are 10 and 11. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. Note: This CVE is not exploitable for Solaris 11.1 and later releases, and ZFSSA 8.7 and later releases, thus the CVSS Base Score is 0.0. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/FromPartsUnknown/EvilSunCheck](https://github.com/FromPartsUnknown/EvilSunCheck) :  ![starts](https://img.shields.io/github/stars/FromPartsUnknown/EvilSunCheck.svg) ![forks](https://img.shields.io/github/forks/FromPartsUnknown/EvilSunCheck.svg)


## CVE-2020-5142
 A stored cross-site scripting (XSS) vulnerability exists in the SonicOS SSLVPN web interface. A remote unauthenticated attacker is able to store and potentially execute arbitrary JavaScript code in the firewall SSLVPN portal. This vulnerability affected SonicOS Gen 5 version 5.9.1.7, 5.9.1.13, Gen 6 version 6.5.4.7, 6.5.1.12, 6.0.5.3, SonicOSv 6.5.4.v and Gen 7 version SonicOS 7.0.0.0.

- [https://github.com/hackerlawyer/CVE-2020-5142-POC-MB](https://github.com/hackerlawyer/CVE-2020-5142-POC-MB) :  ![starts](https://img.shields.io/github/stars/hackerlawyer/CVE-2020-5142-POC-MB.svg) ![forks](https://img.shields.io/github/forks/hackerlawyer/CVE-2020-5142-POC-MB.svg)


## CVE-2015-9251
 jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.

- [https://github.com/rox-11/xss](https://github.com/rox-11/xss) :  ![starts](https://img.shields.io/github/stars/rox-11/xss.svg) ![forks](https://img.shields.io/github/forks/rox-11/xss.svg)


## CVE-2011-0762
 The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

- [https://github.com/Andreyfrtz/CVE-2011-0762](https://github.com/Andreyfrtz/CVE-2011-0762) :  ![starts](https://img.shields.io/github/stars/Andreyfrtz/CVE-2011-0762.svg) ![forks](https://img.shields.io/github/forks/Andreyfrtz/CVE-2011-0762.svg)

