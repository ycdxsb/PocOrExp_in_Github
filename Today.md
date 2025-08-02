# Update 2025-08-02
## CVE-2025-54589
 Copyparty is a portable file server. In versions 1.18.6 and below, when accessing the recent uploads page at `/?ru`, users can filter the results using an input field at the top. This field appends a filter parameter to the URL, which reflects its value directly into a `script` block without proper escaping, allowing for reflected Cross-Site Scripting (XSS) and can be exploited against both authenticated and unauthenticated users. This is fixed in version 1.18.7.

- [https://github.com/byteReaper77/CVE-2025-54589](https://github.com/byteReaper77/CVE-2025-54589) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-54589.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-54589.svg)


## CVE-2025-52289
 A Broken Access Control vulnerability in MagnusBilling v7.8.5.3 allows newly registered users to gain escalated privileges by sending a crafted request to /mbilling/index.php/user/save to set their account status fom "pending" to "active" without requiring administrator approval.

- [https://github.com/Madhav-Bhardwaj/CVE-2025-52289](https://github.com/Madhav-Bhardwaj/CVE-2025-52289) :  ![starts](https://img.shields.io/github/stars/Madhav-Bhardwaj/CVE-2025-52289.svg) ![forks](https://img.shields.io/github/forks/Madhav-Bhardwaj/CVE-2025-52289.svg)
- [https://github.com/Whit3-d3viL-hacker/CVE-2025-52289](https://github.com/Whit3-d3viL-hacker/CVE-2025-52289) :  ![starts](https://img.shields.io/github/stars/Whit3-d3viL-hacker/CVE-2025-52289.svg) ![forks](https://img.shields.io/github/forks/Whit3-d3viL-hacker/CVE-2025-52289.svg)


## CVE-2025-51482
 Remote Code Execution in letta.server.rest_api.routers.v1.tools.run_tool_from_source in letta-ai Letta 0.7.12 allows remote attackers to execute arbitrary Python code and system commands via crafted payloads to the /v1/tools/run endpoint, bypassing intended sandbox restrictions.

- [https://github.com/Kai-One001/Letta-CVE-2025-51482-RCE](https://github.com/Kai-One001/Letta-CVE-2025-51482-RCE) :  ![starts](https://img.shields.io/github/stars/Kai-One001/Letta-CVE-2025-51482-RCE.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/Letta-CVE-2025-51482-RCE.svg)


## CVE-2025-51385
 D-LINK DI-8200 16.07.26A1 is vulnerable to Buffer Overflow in the yyxz_dlink_asp function via the id parameter.

- [https://github.com/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC](https://github.com/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC.svg)


## CVE-2025-50867
 A SQL Injection vulnerability exists in the takeassessment2.php endpoint of the CloudClassroom-PHP-Project 1.0, where the Q5 POST parameter is directly embedded in SQL statements without sanitization.

- [https://github.com/SacX-7/CVE-2025-50867](https://github.com/SacX-7/CVE-2025-50867) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-50867.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-50867.svg)


## CVE-2025-50866
 CloudClassroom-PHP-Project 1.0 contains a reflected Cross-site Scripting (XSS) vulnerability in the email parameter of the postquerypublic endpoint. Improper sanitization allows an attacker to inject arbitrary JavaScript code that executes in the context of the user s browser, potentially leading to session hijacking or phishing attacks.

- [https://github.com/SacX-7/CVE-2025-50866](https://github.com/SacX-7/CVE-2025-50866) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-50866.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-50866.svg)


## CVE-2025-30406
 Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

- [https://github.com/mchklt/CVE-2025-30406](https://github.com/mchklt/CVE-2025-30406) :  ![starts](https://img.shields.io/github/stars/mchklt/CVE-2025-30406.svg) ![forks](https://img.shields.io/github/forks/mchklt/CVE-2025-30406.svg)


## CVE-2025-29557
 ExaGrid EX10 6.3 - 7.0.1.P08 is vulnerable to Incorrect Access Control in the MailConfiguration API endpoint, where users with operator-level privileges can issue an HTTP request to retrieve SMTP credentials, including plaintext passwords.

- [https://github.com/0xsu3ks/CVE-2025-29557](https://github.com/0xsu3ks/CVE-2025-29557) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2025-29557.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2025-29557.svg)


## CVE-2025-29556
 ExaGrid EX10 6.3 - 7.0.1.P08 is vulnerable to Incorrect Access Control. Since version 6.3, ExaGrid enforces restrictions preventing users with the Admin role from creating or modifying users with the Security Officer role without approval. However, a flaw in the account creation process allows an attacker to bypass these restrictions via API request manipulation. An attacker with an Admin access can intercept and modify the API request during user creation, altering the parameters to assign the new account to the ExaGrid Security Officers group without the required approval.

- [https://github.com/0xsu3ks/CVE-2025-29556](https://github.com/0xsu3ks/CVE-2025-29556) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2025-29556.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2025-29556.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/Cythonic1/CVE-2025-27591](https://github.com/Cythonic1/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/Cythonic1/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/Cythonic1/CVE-2025-27591.svg)


## CVE-2025-5394
 The Alone – Charity Multipurpose Non-profit WordPress Theme theme for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the alone_import_pack_install_plugin() function in all versions up to, and including, 7.8.3. This makes it possible for unauthenticated attackers to upload zip files containing webshells disguised as plugins from remote locations to achieve remote code execution.

- [https://github.com/fokda-prodz/CVE-2025-5394](https://github.com/fokda-prodz/CVE-2025-5394) :  ![starts](https://img.shields.io/github/stars/fokda-prodz/CVE-2025-5394.svg) ![forks](https://img.shields.io/github/forks/fokda-prodz/CVE-2025-5394.svg)


## CVE-2025-5172
 A vulnerability, which was classified as critical, was found in Econtrata up to 20250516. Affected is an unknown function of the file /valida. The manipulation of the argument usuario leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/meisterlos/CVE-2025-51726](https://github.com/meisterlos/CVE-2025-51726) :  ![starts](https://img.shields.io/github/stars/meisterlos/CVE-2025-51726.svg) ![forks](https://img.shields.io/github/forks/meisterlos/CVE-2025-51726.svg)


## CVE-2025-5075
 A vulnerability has been found in FreeFloat FTP Server 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the component DEBUG Command Handler. The manipulation leads to buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/furk4nyildiz/CVE-2025-50754-PoC](https://github.com/furk4nyildiz/CVE-2025-50754-PoC) :  ![starts](https://img.shields.io/github/stars/furk4nyildiz/CVE-2025-50754-PoC.svg) ![forks](https://img.shields.io/github/forks/furk4nyildiz/CVE-2025-50754-PoC.svg)


## CVE-2025-5034
 The wp-file-download WordPress plugin before 6.2.6 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting

- [https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341](https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341) :  ![starts](https://img.shields.io/github/stars/millad7/Axelor-vulnerability-CVE-2025-50341.svg) ![forks](https://img.shields.io/github/forks/millad7/Axelor-vulnerability-CVE-2025-50341.svg)
- [https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340](https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340) :  ![starts](https://img.shields.io/github/stars/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340.svg) ![forks](https://img.shields.io/github/forks/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340.svg)


## CVE-2025-3969
 A vulnerability was found in codeprojects News Publishing Site Dashboard 1.0. It has been rated as critical. This issue affects some unknown processing of the file /edit-category.php of the component Edit Category Page. The manipulation of the argument category_image leads to unrestricted upload. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Alif145/CVE-2025-3969-Exploit](https://github.com/Alif145/CVE-2025-3969-Exploit) :  ![starts](https://img.shields.io/github/stars/Alif145/CVE-2025-3969-Exploit.svg) ![forks](https://img.shields.io/github/forks/Alif145/CVE-2025-3969-Exploit.svg)


## CVE-2024-55555
 Invoice Ninja before 5.10.43 allows remote code execution from a pre-authenticated route when an attacker knows the APP_KEY. This is exacerbated by .env files, available from the product's repository, that have default APP_KEY values. The route/{hash} route defined in the invoiceninja/routes/client.php file can be accessed without authentication. The parameter {hash} is passed to the function decrypt that expects a Laravel ciphered value containing a serialized object. (Furthermore, Laravel contains several gadget chains usable to trigger remote command execution from arbitrary deserialization.) Therefore, an attacker in possession of the APP_KEY is able to fully control a string passed to an unserialize function.

- [https://github.com/Yucaerin/CVE-2024-55555](https://github.com/Yucaerin/CVE-2024-55555) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2024-55555.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2024-55555.svg)


## CVE-2024-34328
 An open redirect in Sielox AnyWare v2.1.2 allows attackers to execute a man-in-the-middle attack via a crafted URL.

- [https://github.com/0xsu3ks/CVE-2024-34328](https://github.com/0xsu3ks/CVE-2024-34328) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2024-34328.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2024-34328.svg)


## CVE-2024-34327
 Sielox AnyWare v2.1.2 was discovered to contain a SQL injection vulnerability via the email address field of the password reset form.

- [https://github.com/0xsu3ks/CVE-2024-34327](https://github.com/0xsu3ks/CVE-2024-34327) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2024-34327.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2024-34327.svg)


## CVE-2024-3552
 The Web Directory Free WordPress plugin before 1.7.0 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection with different techniques like UNION, Time-Based and Error-Based.

- [https://github.com/KiPhuong/challenge-cve-2024-3552](https://github.com/KiPhuong/challenge-cve-2024-3552) :  ![starts](https://img.shields.io/github/stars/KiPhuong/challenge-cve-2024-3552.svg) ![forks](https://img.shields.io/github/forks/KiPhuong/challenge-cve-2024-3552.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/vulnerk0/CVE-2023-46818](https://github.com/vulnerk0/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/vulnerk0/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/vulnerk0/CVE-2023-46818.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/0xVoodoo/CVE-2023-23752](https://github.com/0xVoodoo/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/0xVoodoo/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/0xVoodoo/CVE-2023-23752.svg)


## CVE-2023-22894
 Strapi through 4.5.5 allows attackers (with access to the admin panel) to discover sensitive user details by exploiting the query filter. The attacker can filter users by columns that contain sensitive information and infer a value from API responses. If the attacker has super admin access, then this can be exploited to discover the password hash and password reset token of all users. If the attacker has admin panel access to an account with permission to access the username and email of API users with a lower privileged role (e.g., Editor or Author), then this can be exploited to discover sensitive information for all API users but not other admin accounts.

- [https://github.com/maxntv24/CVE-2023-22894-PoC](https://github.com/maxntv24/CVE-2023-22894-PoC) :  ![starts](https://img.shields.io/github/stars/maxntv24/CVE-2023-22894-PoC.svg) ![forks](https://img.shields.io/github/forks/maxntv24/CVE-2023-22894-PoC.svg)


## CVE-2023-0159
 The Extensive VC Addons for WPBakery page builder WordPress plugin before 1.9.1 does not validate a parameter passed to the php extract function when loading templates, allowing an unauthenticated attacker to override the template path to read arbitrary files from the hosts file system. This may be escalated to RCE using PHP filter chains.

- [https://github.com/Sn20393873/Extensive](https://github.com/Sn20393873/Extensive) :  ![starts](https://img.shields.io/github/stars/Sn20393873/Extensive.svg) ![forks](https://img.shields.io/github/forks/Sn20393873/Extensive.svg)


## CVE-2022-44268
 ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

- [https://github.com/mouftan/CVE-2022-44268](https://github.com/mouftan/CVE-2022-44268) :  ![starts](https://img.shields.io/github/stars/mouftan/CVE-2022-44268.svg) ![forks](https://img.shields.io/github/forks/mouftan/CVE-2022-44268.svg)


## CVE-2022-34155
 Improper Authentication vulnerability in miniOrange OAuth Single Sign On – SSO (OAuth Client) plugin allows Authentication Bypass.This issue affects OAuth Single Sign On – SSO (OAuth Client): from n/a through 6.23.3.

- [https://github.com/vanh-88/CVE-2022-34155](https://github.com/vanh-88/CVE-2022-34155) :  ![starts](https://img.shields.io/github/stars/vanh-88/CVE-2022-34155.svg) ![forks](https://img.shields.io/github/forks/vanh-88/CVE-2022-34155.svg)


## CVE-2022-29806
 ZoneMinder before 1.36.13 allows remote code execution via an invalid language. Ability to create a debug log file at an arbitrary pathname contributes to exploitability.

- [https://github.com/Sigm0n/CVE-2022-29806](https://github.com/Sigm0n/CVE-2022-29806) :  ![starts](https://img.shields.io/github/stars/Sigm0n/CVE-2022-29806.svg) ![forks](https://img.shields.io/github/forks/Sigm0n/CVE-2022-29806.svg)


## CVE-2022-1386
 The Fusion Builder WordPress plugin before 3.6.2, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.

- [https://github.com/ptrgits/CVE-2022-1386](https://github.com/ptrgits/CVE-2022-1386) :  ![starts](https://img.shields.io/github/stars/ptrgits/CVE-2022-1386.svg) ![forks](https://img.shields.io/github/forks/ptrgits/CVE-2022-1386.svg)


## CVE-2018-12537
 In Eclipse Vert.x version 3.0 to 3.5.1, the HttpServer response headers and HttpClient request headers do not filter carriage return and line feed characters from the header value. This allow unfiltered values to inject a new header in the client request or server response.

- [https://github.com/tafamace/CVE-2018-12537](https://github.com/tafamace/CVE-2018-12537) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-12537.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-12537.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/mohammadamin382/dirtycow-lab](https://github.com/mohammadamin382/dirtycow-lab) :  ![starts](https://img.shields.io/github/stars/mohammadamin382/dirtycow-lab.svg) ![forks](https://img.shields.io/github/forks/mohammadamin382/dirtycow-lab.svg)


## CVE-2016-4631
 ImageIO in Apple iOS before 9.3.3, OS X before 10.11.6, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted TIFF file.

- [https://github.com/l3onkers/FuxiOS](https://github.com/l3onkers/FuxiOS) :  ![starts](https://img.shields.io/github/stars/l3onkers/FuxiOS.svg) ![forks](https://img.shields.io/github/forks/l3onkers/FuxiOS.svg)


## CVE-2015-6668
 The Job Manager plugin before 0.7.25 allows remote attackers to read arbitrary CV files via a brute force attack to the WordPress upload directory structure, related to an insecure direct object reference.

- [https://github.com/NoTrustedx/Job-Manager-Disclosure](https://github.com/NoTrustedx/Job-Manager-Disclosure) :  ![starts](https://img.shields.io/github/stars/NoTrustedx/Job-Manager-Disclosure.svg) ![forks](https://img.shields.io/github/forks/NoTrustedx/Job-Manager-Disclosure.svg)


## CVE-1999-0517
 An SNMP community name is the default (e.g. public), null, or missing.

- [https://github.com/ialejandrozalles/InvestigacionAplicacionCVE-1999-0517](https://github.com/ialejandrozalles/InvestigacionAplicacionCVE-1999-0517) :  ![starts](https://img.shields.io/github/stars/ialejandrozalles/InvestigacionAplicacionCVE-1999-0517.svg) ![forks](https://img.shields.io/github/forks/ialejandrozalles/InvestigacionAplicacionCVE-1999-0517.svg)

