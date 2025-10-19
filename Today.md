# Update 2025-10-19
## CVE-2025-58718
 Use after free in Remote Desktop Client allows an unauthorized attacker to execute code over a network.

- [https://github.com/callinston/CVE-2025-58718](https://github.com/callinston/CVE-2025-58718) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-58718.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-58718.svg)


## CVE-2025-56221
 A lack of rate limiting in the login mechanism of SigningHub v8.6.8 allows attackers to bypass authentication via a brute force attack.

- [https://github.com/saykino/CVE-2025-56221](https://github.com/saykino/CVE-2025-56221) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56221.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56221.svg)


## CVE-2025-56218
 An arbitrary file upload vulnerability in SigningHub v8.6.8 allows attackers to execute arbitrary code via uploading a crafted PDF file.

- [https://github.com/saykino/CVE-2025-56218](https://github.com/saykino/CVE-2025-56218) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56218.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56218.svg)


## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.

- [https://github.com/RootAid/CVE-2025-55315](https://github.com/RootAid/CVE-2025-55315) :  ![starts](https://img.shields.io/github/stars/RootAid/CVE-2025-55315.svg) ![forks](https://img.shields.io/github/forks/RootAid/CVE-2025-55315.svg)
- [https://github.com/digitalsnemesis/CVE-2025-55315](https://github.com/digitalsnemesis/CVE-2025-55315) :  ![starts](https://img.shields.io/github/stars/digitalsnemesis/CVE-2025-55315.svg) ![forks](https://img.shields.io/github/forks/digitalsnemesis/CVE-2025-55315.svg)


## CVE-2025-52136
 In EMQX before 5.8.6, administrators can install arbitrary novel plugins via the Dashboard web interface. NOTE: the Supplier's position is that this is the intended behavior; however, 5.8.6 adds a defense-in-depth feature in which a plugin's acceptability (for later Dashboard installation) is set by the "emqx ctl plugins allow" CLI command.

- [https://github.com/f1r3K0/CVE-2025-52136](https://github.com/f1r3K0/CVE-2025-52136) :  ![starts](https://img.shields.io/github/stars/f1r3K0/CVE-2025-52136.svg) ![forks](https://img.shields.io/github/forks/f1r3K0/CVE-2025-52136.svg)


## CVE-2025-50165
 Untrusted pointer dereference in Microsoft Graphics Component allows an unauthorized attacker to execute code over a network.

- [https://github.com/allinsthon/CVE-2025-50165](https://github.com/allinsthon/CVE-2025-50165) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-50165.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-50165.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/dr4x-c0d3r/sudo-chroot](https://github.com/dr4x-c0d3r/sudo-chroot) :  ![starts](https://img.shields.io/github/stars/dr4x-c0d3r/sudo-chroot.svg) ![forks](https://img.shields.io/github/forks/dr4x-c0d3r/sudo-chroot.svg)
- [https://github.com/dr4xp/sudo-chroot](https://github.com/dr4xp/sudo-chroot) :  ![starts](https://img.shields.io/github/stars/dr4xp/sudo-chroot.svg) ![forks](https://img.shields.io/github/forks/dr4xp/sudo-chroot.svg)


## CVE-2025-25198
 mailcow: dockerized is an open source groupware/email suite based on docker. Prior to version 2025-01a, a vulnerability in mailcow's password reset functionality allows an attacker to manipulate the `Host HTTP` header to generate a password reset link pointing to an attacker-controlled domain. This can lead to account takeover if a user clicks the poisoned link. Version 2025-01a contains a patch. As a workaround, deactivate the password reset functionality by clearing `Notification email sender` and `Notification email subject` under System - Configuration - Options - Password Settings.

- [https://github.com/enzocipher/CVE-2025-25198](https://github.com/enzocipher/CVE-2025-25198) :  ![starts](https://img.shields.io/github/stars/enzocipher/CVE-2025-25198.svg) ![forks](https://img.shields.io/github/forks/enzocipher/CVE-2025-25198.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/Yukik4z3/CVE-2025-24893](https://github.com/Yukik4z3/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Yukik4z3/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Yukik4z3/CVE-2025-24893.svg)


## CVE-2025-11371
This issue impacts Gladinet CentreStack and Triofox: All versions prior to and including 16.7.10368.56560

- [https://github.com/lap1nou/CVE-2025-11371](https://github.com/lap1nou/CVE-2025-11371) :  ![starts](https://img.shields.io/github/stars/lap1nou/CVE-2025-11371.svg) ![forks](https://img.shields.io/github/forks/lap1nou/CVE-2025-11371.svg)


## CVE-2025-10742
 The Truelysell Core plugin for WordPress is vulnerable to Arbitrary User Password Change in versions up to, and including, 1.8.6. This is due to the plugin providing user-controlled access to objects, letting a user bypass authorization and access system resources. This makes it possible for unauthenticated attackers to change user passwords and potentially take over administrator accounts. Note: This can only be exploited unauthenticated if the attacker knows which page contains the 'truelysell_edit_staff' shortcode.

- [https://github.com/netspecters/CVE-2025-10742](https://github.com/netspecters/CVE-2025-10742) :  ![starts](https://img.shields.io/github/stars/netspecters/CVE-2025-10742.svg) ![forks](https://img.shields.io/github/forks/netspecters/CVE-2025-10742.svg)


## CVE-2025-10041
 The Flex QR Code Generator plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in thesave_qr_code_to_db() function in all versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041](https://github.com/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041) :  ![starts](https://img.shields.io/github/stars/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041.svg)


## CVE-2025-9242
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.3 and 2025.1.

- [https://github.com/pulsecipher/CVE-2025-9242](https://github.com/pulsecipher/CVE-2025-9242) :  ![starts](https://img.shields.io/github/stars/pulsecipher/CVE-2025-9242.svg) ![forks](https://img.shields.io/github/forks/pulsecipher/CVE-2025-9242.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/blowrrr/cve-2025-8088](https://github.com/blowrrr/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/blowrrr/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/blowrrr/cve-2025-8088.svg)


## CVE-2025-8081
 The Elementor plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 3.30.2 via the Import_Images::import() function due to insufficient controls on the filename specified. This makes it possible for authenticated attackers, with administrator-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/LyesH4ck/CVE-2025-8081-Elementor](https://github.com/LyesH4ck/CVE-2025-8081-Elementor) :  ![starts](https://img.shields.io/github/stars/LyesH4ck/CVE-2025-8081-Elementor.svg) ![forks](https://img.shields.io/github/forks/LyesH4ck/CVE-2025-8081-Elementor.svg)


## CVE-2025-6050
 Mezzanine CMS, in versions prior to 6.1.1, contains a Stored Cross-Site Scripting (XSS) vulnerability in the admin interface. The vulnerability exists in the "displayable_links_js" function, which fails to properly sanitize blog post titles before including them in JSON responses served via "/admin/displayable_links.js". An authenticated admin user can create a blog post with a malicious JavaScript payload in the title field, then trick another admin user into clicking a direct link to the "/admin/displayable_links.js" endpoint, causing the malicious script to execute in their browser.

- [https://github.com/H4zaz/CVE-2025-60500](https://github.com/H4zaz/CVE-2025-60500) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2025-60500.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2025-60500.svg)


## CVE-2024-51793
 Unrestricted Upload of File with Dangerous Type vulnerability in Webful Creations Computer Repair Shop allows Upload a Web Shell to a Web Server.This issue affects Computer Repair Shop: from n/a through 3.8115.

- [https://github.com/0axz-tools/CVE-2024-51793](https://github.com/0axz-tools/CVE-2024-51793) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2024-51793.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2024-51793.svg)


## CVE-2024-50849
 A Stored Cross-Site Scripting (XSS) vulnerability in the "Rules" functionality of WorldServer v11.8.2 allows a remote authenticated attacker to execute arbitrary JavaScript code.

- [https://github.com/1mhr4b/CVE-2024-50849](https://github.com/1mhr4b/CVE-2024-50849) :  ![starts](https://img.shields.io/github/stars/1mhr4b/CVE-2024-50849.svg) ![forks](https://img.shields.io/github/forks/1mhr4b/CVE-2024-50849.svg)


## CVE-2024-50848
 An XML External Entity (XXE) vulnerability in the Import object and Translation Memory import functionalities of WorldServer v11.8.2 to access sensitive information and execute arbitrary commands via supplying a crafted .tmx file.

- [https://github.com/1mhr4b/CVE-2024-50848](https://github.com/1mhr4b/CVE-2024-50848) :  ![starts](https://img.shields.io/github/stars/1mhr4b/CVE-2024-50848.svg) ![forks](https://img.shields.io/github/forks/1mhr4b/CVE-2024-50848.svg)


## CVE-2024-27956
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/0axz-tools/CVE-2024-27956](https://github.com/0axz-tools/CVE-2024-27956) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2024-27956.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2024-27956.svg)


## CVE-2024-21754
 A use of password hash with insufficient computational effort vulnerability [CWE-916] affecting FortiOS version 7.4.3 and below, 7.2 all versions, 7.0 all versions, 6.4 all versions and FortiProxy version 7.4.2 and below, 7.2 all versions, 7.0 all versions, 2.0 all versions may allow a privileged attacker with super-admin profile and CLI access to decrypting the backup file.

- [https://github.com/hacktidexp/CVE-2024-21754-FORTI-RCE](https://github.com/hacktidexp/CVE-2024-21754-FORTI-RCE) :  ![starts](https://img.shields.io/github/stars/hacktidexp/CVE-2024-21754-FORTI-RCE.svg) ![forks](https://img.shields.io/github/forks/hacktidexp/CVE-2024-21754-FORTI-RCE.svg)


## CVE-2024-13513
 The Oliver POS – A WooCommerce Point of Sale (POS) plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 2.4.2.3 via the logging functionality. This makes it possible for unauthenticated attackers to extract sensitive data including the plugin's clientToken, which in turn can be used to change user account information including emails and account type. This allows attackers to then change account passwords resulting in a complete site takeover. Version 2.4.2.3 disabled logging but left sites with existing log files vulnerable.

- [https://github.com/0axz-tools/CVE-2024-13513.py](https://github.com/0axz-tools/CVE-2024-13513.py) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2024-13513.py.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2024-13513.py.svg)


## CVE-2022-1386
 The Fusion Builder WordPress plugin before 3.6.2, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.

- [https://github.com/kreeksec/CVE-2022-1386](https://github.com/kreeksec/CVE-2022-1386) :  ![starts](https://img.shields.io/github/stars/kreeksec/CVE-2022-1386.svg) ![forks](https://img.shields.io/github/forks/kreeksec/CVE-2022-1386.svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM](https://github.com/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM) :  ![starts](https://img.shields.io/github/stars/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM.svg) ![forks](https://img.shields.io/github/forks/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM.svg)

