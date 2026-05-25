# Update 2026-05-25
## CVE-2026-48172
 LiteSpeed User-End cPanel Plugin before 2.4.5 allows privilege escalation (possibly to root), as exploited in the wild in May 2026. Detection is best done via a command line of grep -rE "cpanel_jsonapi_func=redisAble" /var/cpanel/logs /usr/local/cpanel/logs/ 2/dev/null in Bash. If you get no output, you have not been hit with exploitation of the vulnerability. If there is output, we recommend you examine the IP addresses in the list, determine if they are valid IP addresses, and if not, block them. To determine damage done, examine the system logs for use by the detected IP addresses. The issue is related to mishandling of Redis enable/disable features. The recommended minimum version is 2.4.7.

- [https://github.com/retmakarunia/CVE-2026-48172](https://github.com/retmakarunia/CVE-2026-48172) :  ![starts](https://img.shields.io/github/stars/retmakarunia/CVE-2026-48172.svg) ![forks](https://img.shields.io/github/forks/retmakarunia/CVE-2026-48172.svg)
- [https://github.com/HORKimhab/CVE-2026-48172](https://github.com/HORKimhab/CVE-2026-48172) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-48172.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-48172.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag](https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag) :  ![starts](https://img.shields.io/github/stars/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg)
- [https://github.com/0xBlackash/CVE-2026-46300](https://github.com/0xBlackash/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46300.svg)
- [https://github.com/Sentebale/CVE-2026-46300](https://github.com/Sentebale/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/Sentebale/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/Sentebale/CVE-2026-46300.svg)
- [https://github.com/HORKimhab/CVE-2026-46300](https://github.com/HORKimhab/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-46300.svg)
- [https://github.com/ExploitEoom/CVE-2026-46300](https://github.com/ExploitEoom/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/ExploitEoom/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/ExploitEoom/CVE-2026-46300.svg)
- [https://github.com/Maxime288/Fragnesia-CVE-2026-46300](https://github.com/Maxime288/Fragnesia-CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/Maxime288/Fragnesia-CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/Maxime288/Fragnesia-CVE-2026-46300.svg)
- [https://github.com/Koshmare-Blossom/Fragnesia-go](https://github.com/Koshmare-Blossom/Fragnesia-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/Fragnesia-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/Fragnesia-go.svg)
- [https://github.com/First-John/cve_2026_frag_family_fix](https://github.com/First-John/cve_2026_frag_family_fix) :  ![starts](https://img.shields.io/github/stars/First-John/cve_2026_frag_family_fix.svg) ![forks](https://img.shields.io/github/forks/First-John/cve_2026_frag_family_fix.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/Mclisterjoeh2o/yellowkey-bitlocker](https://github.com/Mclisterjoeh2o/yellowkey-bitlocker) :  ![starts](https://img.shields.io/github/stars/Mclisterjoeh2o/yellowkey-bitlocker.svg) ![forks](https://img.shields.io/github/forks/Mclisterjoeh2o/yellowkey-bitlocker.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/webdev75950-ux/nginx-rce-cve-2026-42945](https://github.com/webdev75950-ux/nginx-rce-cve-2026-42945) :  ![starts](https://img.shields.io/github/stars/webdev75950-ux/nginx-rce-cve-2026-42945.svg) ![forks](https://img.shields.io/github/forks/webdev75950-ux/nginx-rce-cve-2026-42945.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/xxconi/CVE-2026-41940](https://github.com/xxconi/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-41940.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/bajoex/CVE-2026-41096-POC-trigger-no-exploit-](https://github.com/bajoex/CVE-2026-41096-POC-trigger-no-exploit-) :  ![starts](https://img.shields.io/github/stars/bajoex/CVE-2026-41096-POC-trigger-no-exploit-.svg) ![forks](https://img.shields.io/github/forks/bajoex/CVE-2026-41096-POC-trigger-no-exploit-.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/rfxn/rfxn-defense](https://github.com/rfxn/rfxn-defense) :  ![starts](https://img.shields.io/github/stars/rfxn/rfxn-defense.svg) ![forks](https://img.shields.io/github/forks/rfxn/rfxn-defense.svg)


## CVE-2026-23813
 A vulnerability has been identified in the web-based management interface of AOS-CX switches that could potentially allow an unauthenticated remote actor to circumvent existing authentication controls. In some cases this could enable resetting the admin password.

- [https://github.com/offseckit/CVE-2026-23813](https://github.com/offseckit/CVE-2026-23813) :  ![starts](https://img.shields.io/github/stars/offseckit/CVE-2026-23813.svg) ![forks](https://img.shields.io/github/forks/offseckit/CVE-2026-23813.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 26.3 and iPadOS 26.3, macOS Tahoe 26.3, tvOS 26.3, visionOS 26.3, watchOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/R3n3r0/CVE-2026-20700](https://github.com/R3n3r0/CVE-2026-20700) :  ![starts](https://img.shields.io/github/stars/R3n3r0/CVE-2026-20700.svg) ![forks](https://img.shields.io/github/forks/R3n3r0/CVE-2026-20700.svg)


## CVE-2026-9018
 The Easy Elements for Elementor – Addons & Website Templates plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 1.4.5 via the `easyel_handle_register()` function. This is due to the `wp_ajax_nopriv_eel_register` AJAX handler iterating the attacker-controlled `custom_meta` POST array and writing every supplied key-value pair to the newly created user's meta via `update_user_meta()` without any key whitelist or blocklist, allowing the `wp_capabilities` user meta key to be overwritten after `wp_insert_user()` has already assigned a safe role. This makes it possible for unauthenticated attackers to register a new account with full administrator-level privileges by supplying `custom_meta[wp_capabilities][administrator]=1`. Exploitation requires that user registration is enabled on the site and that at least one page exposes the Login/Register widget, which publishes the required `easy_elements_nonce` into the page DOM where it can be retrieved by any unauthenticated visitor via a simple GET request.

- [https://github.com/xxconi/CVE-2026-9018](https://github.com/xxconi/CVE-2026-9018) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-9018.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-9018.svg)


## CVE-2026-6960
 The BookingPress Pro plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'bookingpress_validate_submitted_booking_form_func' function in all versions up to, and including, 5.6. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability can only be exploited if a signature custom field is added to the booking form.

- [https://github.com/xxconi/CVE-2026-6960](https://github.com/xxconi/CVE-2026-6960) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-6960.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-6960.svg)


## CVE-2026-6279
 The Avada Builder (fusion-builder) plugin for WordPress is vulnerable to Unauthenticated Remote Code Execution via PHP Function Injection in versions up to and including 3.15.2. This is due to the `wp_conditional_tags` case in `Fusion_Builder_Conditional_Render_Helper::get_value()` passing attacker-controlled values from a base64-decoded JSON blob directly to `call_user_func()` without any allowlist validation. This is exploitable by unauthenticated attackers through the `fusion_get_widget_markup` AJAX endpoint, which is registered for non-privileged (unauthenticated) users via `wp_ajax_nopriv_fusion_get_widget_markup`. The endpoint is protected only by a nonce (`fusion_load_nonce`), but this nonce is generated for user ID 0 and is deterministically exposed in the JavaScript output of any public-facing page containing a Post Cards (`[fusion_post_cards]`) or Table of Contents (`[fusion_table_of_contents]`) element. This makes it possible for unauthenticated attackers to execute arbitrary code on affected sites.

- [https://github.com/xxconi/CVE-2026-6279](https://github.com/xxconi/CVE-2026-6279) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-6279.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-6279.svg)
- [https://github.com/zycoder0day/CVE-2026-6279](https://github.com/zycoder0day/CVE-2026-6279) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-6279.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-6279.svg)


## CVE-2026-6009
 Java Deserialisation Vulnerability in Jaspersoft Reports Library leads to Remote Code Execution (RCE), potentially allowing code execution on the affected system

- [https://github.com/Pumila03/CVE-2026-6009](https://github.com/Pumila03/CVE-2026-6009) :  ![starts](https://img.shields.io/github/stars/Pumila03/CVE-2026-6009.svg) ![forks](https://img.shields.io/github/forks/Pumila03/CVE-2026-6009.svg)


## CVE-2026-4885
 The Piotnet Addons for Elementor Pro plugin for WordPress is vulnerable to arbitrary file upload due to missing file type validation in the 'pafe_ajax_form_builder' function in all versions up to, and including, 7.1.70. The plugin uses an incomplete extension blacklist that only blocks php, phpt, php5, php7, and exe extensions, while allowing dangerous extensions such as .phar or .phtml to be uploaded. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The exploit can only be exploited if a file field is added to the form.

- [https://github.com/Jenderal92/CVE-2026-4885](https://github.com/Jenderal92/CVE-2026-4885) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-4885.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-4885.svg)


## CVE-2026-0926
 The Prodigy Commerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 3.3.0 via the 'parameters[template_name]' parameter. This makes it possible for unauthenticated attackers to include and read arbitrary files or execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/diamorphine666/CVE-2026-0926-exploit](https://github.com/diamorphine666/CVE-2026-0926-exploit) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2026-0926-exploit.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2026-0926-exploit.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/diamorphine666/CVE-2026-0770](https://github.com/diamorphine666/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2026-0770.svg)


## CVE-2025-56803
 Figma Desktop for Windows version 125.6.5 contains a command injection vulnerability in the local plugin loader. An attacker can execute arbitrary OS commands by setting a crafted build field in the plugin's manifest.json. This field is passed to child_process.exec without validation, leading to possible RCE. NOTE: this is disputed by the Supplier because the behavior only allows a local user to attack himself via a local plugin. The local build procedure, which is essential to the attack, is not executed for plugins shared to the Figma Community.

- [https://github.com/yosasasutsut/CVE-2025-56803](https://github.com/yosasasutsut/CVE-2025-56803) :  ![starts](https://img.shields.io/github/stars/yosasasutsut/CVE-2025-56803.svg) ![forks](https://img.shields.io/github/forks/yosasasutsut/CVE-2025-56803.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/p3ta00/react2shell-poc](https://github.com/p3ta00/react2shell-poc) :  ![starts](https://img.shields.io/github/stars/p3ta00/react2shell-poc.svg) ![forks](https://img.shields.io/github/forks/p3ta00/react2shell-poc.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/mein-0/cve-2025-7771](https://github.com/mein-0/cve-2025-7771) :  ![starts](https://img.shields.io/github/stars/mein-0/cve-2025-7771.svg) ![forks](https://img.shields.io/github/forks/mein-0/cve-2025-7771.svg)


## CVE-2024-42323
Users are recommended to upgrade to version 1.6.0, which fixes the issue.

- [https://github.com/forwjm/CVE-2024-42323](https://github.com/forwjm/CVE-2024-42323) :  ![starts](https://img.shields.io/github/stars/forwjm/CVE-2024-42323.svg) ![forks](https://img.shields.io/github/forks/forwjm/CVE-2024-42323.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/kernel364/CVE-2024-29973](https://github.com/kernel364/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-29973.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/diamorphine666/CVE-2024-25600](https://github.com/diamorphine666/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2024-25600.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/kernel364/CVE-2024-24919](https://github.com/kernel364/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-24919.svg)


## CVE-2024-7928
 A vulnerability, which was classified as problematic, has been found in FastAdmin up to 1.3.3.20220121. Affected by this issue is some unknown functionality of the file /index/ajax/lang. The manipulation of the argument lang leads to path traversal. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.3.4.20220530 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/diamorphine666/CVE-2024-7928](https://github.com/diamorphine666/CVE-2024-7928) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2024-7928.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2024-7928.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/kernel364/CVE-2024-7593](https://github.com/kernel364/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-7593.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/kernel364/CVE-2024-2876](https://github.com/kernel364/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-2876.svg)


## CVE-2023-21563
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/LR2006-Robot/bitpixie](https://github.com/LR2006-Robot/bitpixie) :  ![starts](https://img.shields.io/github/stars/LR2006-Robot/bitpixie.svg) ![forks](https://img.shields.io/github/forks/LR2006-Robot/bitpixie.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/SpeatX/ChamiloLMS-CVE-2023-4220](https://github.com/SpeatX/ChamiloLMS-CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/SpeatX/ChamiloLMS-CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/SpeatX/ChamiloLMS-CVE-2023-4220.svg)


## CVE-2019-8943
 WordPress through 5.0.3 allows Path Traversal in wp_crop_image(). An attacker (who has privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two image extensions and ../ sequences, such as a filename ending with the .jpg?/../../file.jpg substring.

- [https://github.com/SpeatX/WordPress-RCE-CVE-2019-8942](https://github.com/SpeatX/WordPress-RCE-CVE-2019-8942) :  ![starts](https://img.shields.io/github/stars/SpeatX/WordPress-RCE-CVE-2019-8942.svg) ![forks](https://img.shields.io/github/forks/SpeatX/WordPress-RCE-CVE-2019-8942.svg)


## CVE-2019-8942
 WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif metadata. Exploitation can leverage CVE-2019-8943.

- [https://github.com/SpeatX/WordPress-RCE-CVE-2019-8942](https://github.com/SpeatX/WordPress-RCE-CVE-2019-8942) :  ![starts](https://img.shields.io/github/stars/SpeatX/WordPress-RCE-CVE-2019-8942.svg) ![forks](https://img.shields.io/github/forks/SpeatX/WordPress-RCE-CVE-2019-8942.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Chathura123git/ethical-hacking-CVE-2011-2523](https://github.com/Chathura123git/ethical-hacking-CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/Chathura123git/ethical-hacking-CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/Chathura123git/ethical-hacking-CVE-2011-2523.svg)

