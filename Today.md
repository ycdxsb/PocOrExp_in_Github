# Update 2025-07-21
## CVE-2025-53640
 Indico is an event management system that uses Flask-Multipass, a multi-backend authentication system for Flask. Starting in version 2.2 and prior to version 3.3.7, an endpoint used to display details of users listed in certain fields (such as ACLs) could be misused to dump basic user details (such as name, affiliation and email) in bulk. Version 3.3.7 fixes the issue. Owners of instances that allow everyone to create a user account, who wish to truly restrict access to these user details, should consider restricting user search to managers. As a workaround, it is possible to restrict access to the affected endpoints (e.g. in the webserver config), but doing so would break certain form fields which could no longer show the details of the users listed in those fields, so upgrading instead is highly recommended.

- [https://github.com/rafaelcorvino1/CVE-2025-53640](https://github.com/rafaelcorvino1/CVE-2025-53640) :  ![starts](https://img.shields.io/github/stars/rafaelcorvino1/CVE-2025-53640.svg) ![forks](https://img.shields.io/github/forks/rafaelcorvino1/CVE-2025-53640.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/00xCanelo/CVE-2025-49113](https://github.com/00xCanelo/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/00xCanelo/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/00xCanelo/CVE-2025-49113.svg)


## CVE-2025-48828
 Certain vBulletin versions might allow attackers to execute arbitrary PHP code by abusing Template Conditionals in the template engine. By crafting template code in an alternative PHP function invocation syntax, such as the "var_dump"("test") syntax, attackers can bypass security checks and execute arbitrary PHP code, as exploited in the wild in May 2025.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2025-48827
 vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 allows unauthenticated users to invoke protected API controllers' methods when running on PHP 8.1 or later, as demonstrated by the /api.php?method=protectedMethod pattern, as exploited in the wild in May 2025.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/Anezatraa/CVE-2025-48384-submodule](https://github.com/Anezatraa/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/Anezatraa/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/Anezatraa/CVE-2025-48384-submodule.svg)


## CVE-2025-41646
 An unauthorized remote attacker can bypass the authentication of the affected software package by misusing an incorrect type conversion. This leads to full compromise of the device

- [https://github.com/r0otk3r/CVE-2025-41646](https://github.com/r0otk3r/CVE-2025-41646) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-41646.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-41646.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Maalfer/Sudo-CVE-2021-3156](https://github.com/Maalfer/Sudo-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Maalfer/Sudo-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Maalfer/Sudo-CVE-2021-3156.svg)


## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.

- [https://github.com/LordBheem/CVE-2025-32023](https://github.com/LordBheem/CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/LordBheem/CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/LordBheem/CVE-2025-32023.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/r0otk3r/CVE-2025-31161](https://github.com/r0otk3r/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-31161.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/00xCanelo/CVE-2025-27591-PoC](https://github.com/00xCanelo/CVE-2025-27591-PoC) :  ![starts](https://img.shields.io/github/stars/00xCanelo/CVE-2025-27591-PoC.svg) ![forks](https://img.shields.io/github/forks/00xCanelo/CVE-2025-27591-PoC.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/TheStingR/CVE-2025-25257](https://github.com/TheStingR/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/TheStingR/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/TheStingR/CVE-2025-25257.svg)
- [https://github.com/mrmtwoj/CVE-2025-25257](https://github.com/mrmtwoj/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/CVE-2025-25257.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/x00byte/PutScanner](https://github.com/x00byte/PutScanner) :  ![starts](https://img.shields.io/github/stars/x00byte/PutScanner.svg) ![forks](https://img.shields.io/github/forks/x00byte/PutScanner.svg)


## CVE-2025-23266
 NVIDIA Container Toolkit for all platforms contains a vulnerability in some hooks used to initialize the container, where an attacker could execute arbitrary code with elevated permissions. A successful exploit of this vulnerability might lead to escalation of privileges, data tampering, information disclosure, and denial of service.

- [https://github.com/jpts/cve-2025-23266-poc](https://github.com/jpts/cve-2025-23266-poc) :  ![starts](https://img.shields.io/github/stars/jpts/cve-2025-23266-poc.svg) ![forks](https://img.shields.io/github/forks/jpts/cve-2025-23266-poc.svg)


## CVE-2025-20337
This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.

- [https://github.com/barbaraeivyu/CVE-2025-20337-EXP](https://github.com/barbaraeivyu/CVE-2025-20337-EXP) :  ![starts](https://img.shields.io/github/stars/barbaraeivyu/CVE-2025-20337-EXP.svg) ![forks](https://img.shields.io/github/forks/barbaraeivyu/CVE-2025-20337-EXP.svg)


## CVE-2025-7795
 A vulnerability, which was classified as critical, has been found in Tenda FH451 1.0.0.9. Affected by this issue is the function fromP2pListFilter of the file /goform/P2pListFilter. The manipulation of the argument page leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/byteReaper77/CVE-2025-7795](https://github.com/byteReaper77/CVE-2025-7795) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7795.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7795.svg)


## CVE-2025-5186
 A vulnerability was found in thinkgem JeeSite up to 5.11.1. It has been rated as critical. Affected by this issue is the function ResourceLoader.getResource of the file /cms/fileTemplate/form of the component URI Scheme Handler. The manipulation of the argument Name leads to server-side request forgery. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Secsys-FDU/CVE-2025-51864](https://github.com/Secsys-FDU/CVE-2025-51864) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51864.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51864.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51868](https://github.com/Secsys-FDU/CVE-2025-51868) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51868.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51868.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51865](https://github.com/Secsys-FDU/CVE-2025-51865) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51865.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51865.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51863](https://github.com/Secsys-FDU/CVE-2025-51863) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51863.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51863.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51862](https://github.com/Secsys-FDU/CVE-2025-51862) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51862.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51862.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51867](https://github.com/Secsys-FDU/CVE-2025-51867) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51867.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51867.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51860](https://github.com/Secsys-FDU/CVE-2025-51860) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51860.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51860.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51869](https://github.com/Secsys-FDU/CVE-2025-51869) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51869.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51869.svg)


## CVE-2025-5185
 A vulnerability was found in Summer Pearl Group Vacation Rental Management Platform up to 1.0.1. It has been declared as problematic. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross-site request forgery. The attack can be launched remotely. Upgrading to version 1.0.2 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/Secsys-FDU/CVE-2025-51858](https://github.com/Secsys-FDU/CVE-2025-51858) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51858.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51858.svg)
- [https://github.com/Secsys-FDU/CVE-2025-51859](https://github.com/Secsys-FDU/CVE-2025-51859) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51859.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51859.svg)


## CVE-2025-3248
code.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2024-47575
 A missing authentication for critical function in FortiManager 7.6.0, FortiManager 7.4.0 through 7.4.4, FortiManager 7.2.0 through 7.2.7, FortiManager 7.0.0 through 7.0.12, FortiManager 6.4.0 through 6.4.14, FortiManager 6.2.0 through 6.2.12, Fortinet FortiManager Cloud 7.4.1 through 7.4.4, FortiManager Cloud 7.2.1 through 7.2.7, FortiManager Cloud 7.0.1 through 7.0.12, FortiManager Cloud 6.4.1 through 6.4.7 allows attacker to execute arbitrary code or commands via specially crafted requests.

- [https://github.com/AnnnNix/CVE-2024-47575](https://github.com/AnnnNix/CVE-2024-47575) :  ![starts](https://img.shields.io/github/stars/AnnnNix/CVE-2024-47575.svg) ![forks](https://img.shields.io/github/forks/AnnnNix/CVE-2024-47575.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2024-20767
 ColdFusion versions 2023.6, 2021.12 and earlier are affected by an Improper Access Control vulnerability that could result in arbitrary file system read. An attacker could leverage this vulnerability to access or modify restricted files. Exploitation of this issue does not require user interaction. Exploitation of this issue requires the admin panel be exposed to the internet.

- [https://github.com/alm6no5/CVE-2024-20767](https://github.com/alm6no5/CVE-2024-20767) :  ![starts](https://img.shields.io/github/stars/alm6no5/CVE-2024-20767.svg) ![forks](https://img.shields.io/github/forks/alm6no5/CVE-2024-20767.svg)


## CVE-2024-9047
 The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2024-5084
 The Hash Form – Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2023-34960
 A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2023-28432
and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)


## CVE-2022-1609
 The School Management WordPress plugin before 9.9.7 contains an obfuscated backdoor injected in it's license checking code that registers a REST API handler, allowing an unauthenticated attacker to execute arbitrary PHP code on the site.

- [https://github.com/hex0x13h/cve-2022-1609-exploit](https://github.com/hex0x13h/cve-2022-1609-exploit) :  ![starts](https://img.shields.io/github/stars/hex0x13h/cve-2022-1609-exploit.svg) ![forks](https://img.shields.io/github/forks/hex0x13h/cve-2022-1609-exploit.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5](https://github.com/peiqiF4ck/WebFrameworkTools-5.5) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5.svg)

