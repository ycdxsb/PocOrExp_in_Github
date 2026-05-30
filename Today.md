# Update 2026-05-30
## CVE-2026-49009
 Northern.tech Mender Server v4.1.0, v4.0.1 and below, and fixed in v4.1.1 and v4.0.2 allows Directory Traversal.

- [https://github.com/j0xh-sec/CVE-2026-49009](https://github.com/j0xh-sec/CVE-2026-49009) :  ![starts](https://img.shields.io/github/stars/j0xh-sec/CVE-2026-49009.svg) ![forks](https://img.shields.io/github/forks/j0xh-sec/CVE-2026-49009.svg)


## CVE-2026-48710
 Starlette is a lightweight ASGI framework/toolkit. Prior to version 1.0.1, the HTTP `Host` request header was not validated before being used to reconstruct `request.url`. Because the routing algorithm relies on the raw HTTP path while `request.url` is rebuilt from the `Host` header, a malformed header could make `request.url.path` differ from the path that was actually requested. Middleware and endpoints that apply security restrictions based on `request.url` (rather than the raw `scope` path) could therefore be bypassed. Users should upgrade to a version greater than or equal to version 1.0.1, which validates the `Host` header against the grammar of RFC 9112 §3.2 / RFC 3986 §3.2.2 when constructing `request.url` and falls back to `scope["server"]` for malformed values.

- [https://github.com/Bhanunamikaze/BadHost-CVE-2026-48710-Exploit](https://github.com/Bhanunamikaze/BadHost-CVE-2026-48710-Exploit) :  ![starts](https://img.shields.io/github/stars/Bhanunamikaze/BadHost-CVE-2026-48710-Exploit.svg) ![forks](https://img.shields.io/github/forks/Bhanunamikaze/BadHost-CVE-2026-48710-Exploit.svg)


## CVE-2026-48172
 LiteSpeed User-End cPanel Plugin before 2.4.5 allows privilege escalation (possibly to root), as exploited in the wild in May 2026. Detection is best done via a command line of grep -rE "cpanel_jsonapi_func=redisAble" /var/cpanel/logs /usr/local/cpanel/logs/ 2/dev/null in Bash. If you get no output, you have not been hit with exploitation of the vulnerability. If there is output, we recommend you examine the IP addresses in the list, determine if they are valid IP addresses, and if not, block them. To determine damage done, examine the system logs for use by the detected IP addresses. The issue is related to mishandling of Redis enable/disable features. The recommended minimum version is 2.4.7.

- [https://github.com/fevar54/CVE-2026-48172---LiteSpeed-cPanel-Plugin-Version-Auditor](https://github.com/fevar54/CVE-2026-48172---LiteSpeed-cPanel-Plugin-Version-Auditor) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-48172---LiteSpeed-cPanel-Plugin-Version-Auditor.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-48172---LiteSpeed-cPanel-Plugin-Version-Auditor.svg)


## CVE-2026-47100
 Funnel Builder for WooCommerce Checkout prior to 3.15.0.3 contains a missing authorization vulnerability in the public checkout endpoint that allows unauthenticated attackers to invoke internal methods and write arbitrary data to the plugin's External Scripts global setting. Attackers can inject malicious JavaScript through the External Scripts setting that executes in the browsers of all checkout page visitors.

- [https://github.com/rootdirective-sec/CVE-2026-47100-Analysis-Lab](https://github.com/rootdirective-sec/CVE-2026-47100-Analysis-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-47100-Analysis-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-47100-Analysis-Lab.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag](https://github.com/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag) :  ![starts](https://img.shields.io/github/stars/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag.svg) ![forks](https://img.shields.io/github/forks/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/Koshmare-Blossom/PinTheft-asm](https://github.com/Koshmare-Blossom/PinTheft-asm) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/PinTheft-asm.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/PinTheft-asm.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag](https://github.com/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag) :  ![starts](https://img.shields.io/github/stars/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag.svg) ![forks](https://img.shields.io/github/forks/DylanClaudio/Reporte-de-Escalada-de-Privilegios-Local-Dirty-Frag.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/quantumworld-dpdns-io/CVE-2026-42945](https://github.com/quantumworld-dpdns-io/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/quantumworld-dpdns-io/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/quantumworld-dpdns-io/CVE-2026-42945.svg)


## CVE-2026-40701
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/edgecases-PurpleHax/cve-images](https://github.com/edgecases-PurpleHax/cve-images) :  ![starts](https://img.shields.io/github/stars/edgecases-PurpleHax/cve-images.svg) ![forks](https://img.shields.io/github/forks/edgecases-PurpleHax/cve-images.svg)


## CVE-2026-35616
 A improper access control vulnerability in Fortinet FortiClientEMS 7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/HORKimhab/CVE-2026-35616](https://github.com/HORKimhab/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-35616.svg)


## CVE-2026-20817
 Improper handling of insufficient permissions or privileges in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/dwgth4i/CVE-2026-20817](https://github.com/dwgth4i/CVE-2026-20817) :  ![starts](https://img.shields.io/github/stars/dwgth4i/CVE-2026-20817.svg) ![forks](https://img.shields.io/github/forks/dwgth4i/CVE-2026-20817.svg)


## CVE-2026-9999
 Inappropriate implementation in ANGLE in Google Chrome on Mac prior to 148.0.7778.216 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/24520597-blip/CVE-2026-999999](https://github.com/24520597-blip/CVE-2026-999999) :  ![starts](https://img.shields.io/github/stars/24520597-blip/CVE-2026-999999.svg) ![forks](https://img.shields.io/github/forks/24520597-blip/CVE-2026-999999.svg)


## CVE-2026-9256
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/3nou9h/CVE-2026-9256-Poc](https://github.com/3nou9h/CVE-2026-9256-Poc) :  ![starts](https://img.shields.io/github/stars/3nou9h/CVE-2026-9256-Poc.svg) ![forks](https://img.shields.io/github/forks/3nou9h/CVE-2026-9256-Poc.svg)
- [https://github.com/W5M1n9/NGINX-ngx_http_rewrite_module-heap-buffer-overflow-CVE-2026-9256](https://github.com/W5M1n9/NGINX-ngx_http_rewrite_module-heap-buffer-overflow-CVE-2026-9256) :  ![starts](https://img.shields.io/github/stars/W5M1n9/NGINX-ngx_http_rewrite_module-heap-buffer-overflow-CVE-2026-9256.svg) ![forks](https://img.shields.io/github/forks/W5M1n9/NGINX-ngx_http_rewrite_module-heap-buffer-overflow-CVE-2026-9256.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/ambionics/cve-2026-9082-drupal-postgresql-rce](https://github.com/ambionics/cve-2026-9082-drupal-postgresql-rce) :  ![starts](https://img.shields.io/github/stars/ambionics/cve-2026-9082-drupal-postgresql-rce.svg) ![forks](https://img.shields.io/github/forks/ambionics/cve-2026-9082-drupal-postgresql-rce.svg)


## CVE-2026-8832
 The WPCode - Insert Headers and Footers + Custom Code Snippets - WordPress Code Manager plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 2.3.5 This is due to the 'wpcode' custom post type being registered without a custom capability_type or capability restrictions in the wpcode_register_post_type() function, allowing WordPress core to fall back to standard post capabilities for all creation paths including XML-RPC. This makes it possible for authenticated attackers, with author-level access and above, to create and publish executable PHP snippet posts via XML-RPC wp.newPost, which are then executed server-side via eval() in the run_eval() function when the snippet is rendered through the [wpcode] shortcode.

- [https://github.com/funixone/EXPLOIT-CVE-2026-8832-](https://github.com/funixone/EXPLOIT-CVE-2026-8832-) :  ![starts](https://img.shields.io/github/stars/funixone/EXPLOIT-CVE-2026-8832-.svg) ![forks](https://img.shields.io/github/forks/funixone/EXPLOIT-CVE-2026-8832-.svg)
- [https://github.com/funixone/EXPLOIT-CVE-2026-8832](https://github.com/funixone/EXPLOIT-CVE-2026-8832) :  ![starts](https://img.shields.io/github/stars/funixone/EXPLOIT-CVE-2026-8832.svg) ![forks](https://img.shields.io/github/forks/funixone/EXPLOIT-CVE-2026-8832.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/BastianXploited/CVE-2026-8181](https://github.com/BastianXploited/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/BastianXploited/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/BastianXploited/CVE-2026-8181.svg)


## CVE-2026-7791
 Improper privilege management in the log rotation mechanism of the Skylight Workspace Config Service in Amazon WorkSpaces for Windows before 2.6.2034.0 allows a local non-admin authenticated user to place arbitrary files into arbitrary locations bypassing file system permission protections, leading to local privilege escalation to SYSTEM.

- [https://github.com/BenZamir/CVE-2026-7791](https://github.com/BenZamir/CVE-2026-7791) :  ![starts](https://img.shields.io/github/stars/BenZamir/CVE-2026-7791.svg) ![forks](https://img.shields.io/github/forks/BenZamir/CVE-2026-7791.svg)


## CVE-2026-4803
 The Royal Elementor Addons plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'status' parameter in the wpr_update_form_action_meta AJAX action in all versions up to, and including, 1.7.1056. This is due to insufficient input sanitization and output escaping, combined with a publicly leaked nonce that allows unauthenticated access to the AJAX handler. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/muslimbek-0x/CVE-2026-48030](https://github.com/muslimbek-0x/CVE-2026-48030) :  ![starts](https://img.shields.io/github/stars/muslimbek-0x/CVE-2026-48030.svg) ![forks](https://img.shields.io/github/forks/muslimbek-0x/CVE-2026-48030.svg)


## CVE-2026-3929
 Side-channel information leakage in ResourceTiming in Google Chrome prior to 146.0.7680.71 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/krishnadevpmelevila/CVE-2026-39292](https://github.com/krishnadevpmelevila/CVE-2026-39292) :  ![starts](https://img.shields.io/github/stars/krishnadevpmelevila/CVE-2026-39292.svg) ![forks](https://img.shields.io/github/forks/krishnadevpmelevila/CVE-2026-39292.svg)


## CVE-2026-3609
Cross reference to KVE 2023-5589 (https://krcert.or.kr)

- [https://github.com/BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/BYOVD.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/BYOVD.svg)


## CVE-2026-0740
 The Ninja Forms - File Uploads plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'NF_FU_AJAX_Controllers_Uploads::handle_upload' function in all versions up to, and including, 3.3.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability was partially patched in version 3.3.25 and fully patched in version 3.3.27.

- [https://github.com/a24ac1/CVE-2026-0740](https://github.com/a24ac1/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/a24ac1/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/a24ac1/CVE-2026-0740.svg)


## CVE-2025-47227
 In the Production Environment extension in Netmake ScriptCase through 9.12.006 (23), the Administrator password reset mechanism is mishandled. Making both a GET and a POST request to login.php.is sufficient. An unauthenticated attacker can then bypass authentication via administrator account takeover.

- [https://github.com/Outs1d3r-Net/cve_2025_47227](https://github.com/Outs1d3r-Net/cve_2025_47227) :  ![starts](https://img.shields.io/github/stars/Outs1d3r-Net/cve_2025_47227.svg) ![forks](https://img.shields.io/github/forks/Outs1d3r-Net/cve_2025_47227.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/giriaryan694-a11y/cve-2025-32433_rce_exploit](https://github.com/giriaryan694-a11y/cve-2025-32433_rce_exploit) :  ![starts](https://img.shields.io/github/stars/giriaryan694-a11y/cve-2025-32433_rce_exploit.svg) ![forks](https://img.shields.io/github/forks/giriaryan694-a11y/cve-2025-32433_rce_exploit.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/hasecto/CVE-2025-24893](https://github.com/hasecto/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/hasecto/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/hasecto/CVE-2025-24893.svg)


## CVE-2025-15030
 The User Profile Builder  WordPress plugin before 3.15.2 does not have a proper password reset process, allowing a few unauthenticated requests to reset the password of any user by knowing their username, such as administrator ones, and therefore gain access to their account

- [https://github.com/BastianXploited/CVE-2025-15030](https://github.com/BastianXploited/CVE-2025-15030) :  ![starts](https://img.shields.io/github/stars/BastianXploited/CVE-2025-15030.svg) ![forks](https://img.shields.io/github/forks/BastianXploited/CVE-2025-15030.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/Rhyru9/CUPS-CVE-2024-47176](https://github.com/Rhyru9/CUPS-CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/Rhyru9/CUPS-CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/Rhyru9/CUPS-CVE-2024-47176.svg)


## CVE-2024-30085
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/12121211aaaaa/CVE_2024_30085](https://github.com/12121211aaaaa/CVE_2024_30085) :  ![starts](https://img.shields.io/github/stars/12121211aaaaa/CVE_2024_30085.svg) ![forks](https://img.shields.io/github/forks/12121211aaaaa/CVE_2024_30085.svg)


## CVE-2024-29510
 Artifex Ghostscript before 10.03.1 allows memory corruption, and SAFER sandbox bypass, via format string injection with a uniprint device.

- [https://github.com/whyuhurtz/wongpress](https://github.com/whyuhurtz/wongpress) :  ![starts](https://img.shields.io/github/stars/whyuhurtz/wongpress.svg) ![forks](https://img.shields.io/github/forks/whyuhurtz/wongpress.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/whyuhurtz/wongpress](https://github.com/whyuhurtz/wongpress) :  ![starts](https://img.shields.io/github/stars/whyuhurtz/wongpress.svg) ![forks](https://img.shields.io/github/forks/whyuhurtz/wongpress.svg)


## CVE-2022-26923
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/Nefhara/CVE-2022-26923](https://github.com/Nefhara/CVE-2022-26923) :  ![starts](https://img.shields.io/github/stars/Nefhara/CVE-2022-26923.svg) ![forks](https://img.shields.io/github/forks/Nefhara/CVE-2022-26923.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/CaptainChicky/MiniPlasma](https://github.com/CaptainChicky/MiniPlasma) :  ![starts](https://img.shields.io/github/stars/CaptainChicky/MiniPlasma.svg) ![forks](https://img.shields.io/github/forks/CaptainChicky/MiniPlasma.svg)


## CVE-2017-18349
 parseObject in Fastjson before 1.2.25, as used in FastjsonEngine in Pippo 1.11.0 and other products, allows remote attackers to execute arbitrary code via a crafted JSON request, as demonstrated by a crafted rmi:// URI in the dataSourceName field of HTTP POST data to the Pippo /json URI, which is mishandled in AjaxApplication.java.

- [https://github.com/Dungsocool/CVE-2017-18349](https://github.com/Dungsocool/CVE-2017-18349) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2017-18349.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2017-18349.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/DesmondHinds94/S22_The_Verification_Protocol](https://github.com/DesmondHinds94/S22_The_Verification_Protocol) :  ![starts](https://img.shields.io/github/stars/DesmondHinds94/S22_The_Verification_Protocol.svg) ![forks](https://img.shields.io/github/forks/DesmondHinds94/S22_The_Verification_Protocol.svg)


## CVE-2006-3918
 http_protocol.c in (1) IBM HTTP Server 6.0 before 6.0.2.13 and 6.1 before 6.1.0.1, and (2) Apache HTTP Server 1.3 before 1.3.35, 2.0 before 2.0.58, and 2.2 before 2.2.2, does not sanitize the Expect header from an HTTP request when it is reflected back in an error message, which might allow cross-site scripting (XSS) style attacks using web client components that can send arbitrary headers in requests, as demonstrated using a Flash SWF file.

- [https://github.com/reallyngb/badstore-webapp-pentest](https://github.com/reallyngb/badstore-webapp-pentest) :  ![starts](https://img.shields.io/github/stars/reallyngb/badstore-webapp-pentest.svg) ![forks](https://img.shields.io/github/forks/reallyngb/badstore-webapp-pentest.svg)

