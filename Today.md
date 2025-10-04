# Update 2025-10-04
## CVE-2025-59713
 Snipe-IT before 8.1.18 allows unsafe deserialization.

- [https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713](https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-59712_CVE-2025-59713.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-59712_CVE-2025-59713.svg)


## CVE-2025-59712
 Snipe-IT before 8.1.18 allows XSS.

- [https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713](https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-59712_CVE-2025-59713.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-59712_CVE-2025-59713.svg)


## CVE-2025-56381
 ERPNEXT v15.67.0 was discovered to contain multiple SQL injection vulnerabilities in the /api/method/frappe.desk.reportview.get endpoint via the order_by and group_by parameters.

- [https://github.com/MoAlali/CVE-2025-56381](https://github.com/MoAlali/CVE-2025-56381) :  ![starts](https://img.shields.io/github/stars/MoAlali/CVE-2025-56381.svg) ![forks](https://img.shields.io/github/forks/MoAlali/CVE-2025-56381.svg)


## CVE-2025-56380
 Frappe Framework v15.72.4 was discovered to contain a SQL injection vulnerability via the fieldname parameter in the frappe.client.get_value API endpoint and a crafted script to the fieldname parameter

- [https://github.com/MoAlali/CVE-2025-56380](https://github.com/MoAlali/CVE-2025-56380) :  ![starts](https://img.shields.io/github/stars/MoAlali/CVE-2025-56380.svg) ![forks](https://img.shields.io/github/forks/MoAlali/CVE-2025-56380.svg)


## CVE-2025-56379
 A stored cross-site scripting (XSS) vulnerability in the blog post feature of ERPNEXT v15.67.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the content field.

- [https://github.com/MoAlali/CVE-2025-56379](https://github.com/MoAlali/CVE-2025-56379) :  ![starts](https://img.shields.io/github/stars/MoAlali/CVE-2025-56379.svg) ![forks](https://img.shields.io/github/forks/MoAlali/CVE-2025-56379.svg)


## CVE-2025-56019
 An insecure permission vulnerability exists in the Agasta Easytouch+ version 9.3.97 The device allows unauthorized mobile applications to connect via Bluetooth Low Energy (BLE) without authentication. Once an unauthorized connection is established, legitimate applications are unable to connect, causing a denial of service. The attack requires proximity to the device, making it exploitable from an adjacent network location.

- [https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019](https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019) :  ![starts](https://img.shields.io/github/stars/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019.svg) ![forks](https://img.shields.io/github/forks/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019.svg)


## CVE-2025-32942
 SSH Tectia Server before 6.6.6 sometimes allows attackers to read and alter a user's session traffic.

- [https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts](https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/khoazero123/CVE-2025-32463](https://github.com/khoazero123/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/khoazero123/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/khoazero123/CVE-2025-32463.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/ibrahmsql/CVE-2025-24893](https://github.com/ibrahmsql/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2025-24893.svg)
- [https://github.com/gotr00t0day/CVE-2025-24893](https://github.com/gotr00t0day/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2025-24893.svg)


## CVE-2025-8359
 The AdForest theme for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 6.0.9. This is due to the plugin not properly verifying a user's identity prior to authenticating them. This makes it possible for unauthenticated attackers to log in as other users, including administrators, without access to a password.

- [https://github.com/Nxploited/CVE-2025-8359](https://github.com/Nxploited/CVE-2025-8359) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8359.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8359.svg)


## CVE-2025-5745
 The strncmp implementation optimized for the Power10 processor in the GNU C Library version 2.40 and later writes to vector registers v20 to v31 without saving contents from the caller (those registers are defined as non-volatile registers by the powerpc64le ABI), resulting in overwriting of its contents and potentially altering control flow of the caller, or leaking the input strings to the function to other parts of the program.

- [https://github.com/restdone/CVE-2025-57457](https://github.com/restdone/CVE-2025-57457) :  ![starts](https://img.shields.io/github/stars/restdone/CVE-2025-57457.svg) ![forks](https://img.shields.io/github/forks/restdone/CVE-2025-57457.svg)


## CVE-2025-5597
 Improper Authentication vulnerability in WF Steuerungstechnik GmbH airleader MASTER allows Authentication Bypass.This issue affects airleader MASTER: 3.00571.

- [https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport) :  ![starts](https://img.shields.io/github/stars/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg) ![forks](https://img.shields.io/github/forks/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg)
- [https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport) :  ![starts](https://img.shields.io/github/stars/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg) ![forks](https://img.shields.io/github/forks/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/AhmedMansour93/Event-ID-263-Rule-Name-SOC287---Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-](https://github.com/AhmedMansour93/Event-ID-263-Rule-Name-SOC287---Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-) :  ![starts](https://img.shields.io/github/stars/AhmedMansour93/Event-ID-263-Rule-Name-SOC287---Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-.svg) ![forks](https://img.shields.io/github/forks/AhmedMansour93/Event-ID-263-Rule-Name-SOC287---Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/AhmedMansour93/Event-ID-268-Rule-Name-SOC292-Possible-PHP-Injection-Detected-CVE-2024-4577-](https://github.com/AhmedMansour93/Event-ID-268-Rule-Name-SOC292-Possible-PHP-Injection-Detected-CVE-2024-4577-) :  ![starts](https://img.shields.io/github/stars/AhmedMansour93/Event-ID-268-Rule-Name-SOC292-Possible-PHP-Injection-Detected-CVE-2024-4577-.svg) ![forks](https://img.shields.io/github/forks/AhmedMansour93/Event-ID-268-Rule-Name-SOC292-Possible-PHP-Injection-Detected-CVE-2024-4577-.svg)


## CVE-2024-2528
 A vulnerability was found in MAGESH-K21 Online-College-Event-Hall-Reservation-System 1.0. It has been classified as critical. This affects an unknown part of the file /admin/update-rooms.php. The manipulation of the argument room_id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-256965 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/sajaljat/CVE-2024-25280](https://github.com/sajaljat/CVE-2024-25280) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25280.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25280.svg)
- [https://github.com/sajaljat/CVE-2024-25281](https://github.com/sajaljat/CVE-2024-25281) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25281.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25281.svg)


## CVE-2024-1709
critical systems.

- [https://github.com/AhmedMansour93/Event-ID-229-Rule-Name-SOC262-CVE-2024-1709-](https://github.com/AhmedMansour93/Event-ID-229-Rule-Name-SOC262-CVE-2024-1709-) :  ![starts](https://img.shields.io/github/stars/AhmedMansour93/Event-ID-229-Rule-Name-SOC262-CVE-2024-1709-.svg) ![forks](https://img.shields.io/github/forks/AhmedMansour93/Event-ID-229-Rule-Name-SOC262-CVE-2024-1709-.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/AhmedMansour93/Event-ID-217-Rule-Name-SOC254-Apache-OFBiz-Auth-Bypass-and-Code-Injection-0Day-CVE-2023-51467-](https://github.com/AhmedMansour93/Event-ID-217-Rule-Name-SOC254-Apache-OFBiz-Auth-Bypass-and-Code-Injection-0Day-CVE-2023-51467-) :  ![starts](https://img.shields.io/github/stars/AhmedMansour93/Event-ID-217-Rule-Name-SOC254-Apache-OFBiz-Auth-Bypass-and-Code-Injection-0Day-CVE-2023-51467-.svg) ![forks](https://img.shields.io/github/forks/AhmedMansour93/Event-ID-217-Rule-Name-SOC254-Apache-OFBiz-Auth-Bypass-and-Code-Injection-0Day-CVE-2023-51467-.svg)


## CVE-2023-29357
 Microsoft SharePoint Server Elevation of Privilege Vulnerability

- [https://github.com/AhmedMansour93/Event-ID-189-Rule-Name-SOC227-CVE-2023-29357](https://github.com/AhmedMansour93/Event-ID-189-Rule-Name-SOC227-CVE-2023-29357) :  ![starts](https://img.shields.io/github/stars/AhmedMansour93/Event-ID-189-Rule-Name-SOC227-CVE-2023-29357.svg) ![forks](https://img.shields.io/github/forks/AhmedMansour93/Event-ID-189-Rule-Name-SOC227-CVE-2023-29357.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/AhmedMansour93/Event-ID-193-Rule-Name-SOC231-Cisco-IOS-XE-Web-UI-ZeroDay-CVE-2023-20198-](https://github.com/AhmedMansour93/Event-ID-193-Rule-Name-SOC231-Cisco-IOS-XE-Web-UI-ZeroDay-CVE-2023-20198-) :  ![starts](https://img.shields.io/github/stars/AhmedMansour93/Event-ID-193-Rule-Name-SOC231-Cisco-IOS-XE-Web-UI-ZeroDay-CVE-2023-20198-.svg) ![forks](https://img.shields.io/github/forks/AhmedMansour93/Event-ID-193-Rule-Name-SOC231-Cisco-IOS-XE-Web-UI-ZeroDay-CVE-2023-20198-.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoJun/CVE-2022-39299-Research](https://github.com/KaztoJun/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoJun/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoJun/CVE-2022-39299-Research.svg)


## CVE-2020-11023
 In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing option elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/paktiko1986/pocpoc_bypass_cve_2020-11023](https://github.com/paktiko1986/pocpoc_bypass_cve_2020-11023) :  ![starts](https://img.shields.io/github/stars/paktiko1986/pocpoc_bypass_cve_2020-11023.svg) ![forks](https://img.shields.io/github/forks/paktiko1986/pocpoc_bypass_cve_2020-11023.svg)

