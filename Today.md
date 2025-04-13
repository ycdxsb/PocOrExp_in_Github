# Update 2025-04-13
## CVE-2025-32641
 Cross-Site Request Forgery (CSRF) vulnerability in anantaddons Anant Addons for Elementor allows Cross Site Request Forgery. This issue affects Anant Addons for Elementor: from n/a through 1.1.5.

- [https://github.com/Nxploited/CVE-2025-32641](https://github.com/Nxploited/CVE-2025-32641) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32641.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32641.svg)


## CVE-2025-32367
 The Oz Forensics face recognition application before 4.0.8 late 2023 allows PII retrieval via /statistic/list Insecure Direct Object Reference. NOTE: the number 4.0.8 was used for both the unpatched and patched versions.

- [https://github.com/Brakerciti/OZForensics_exploit](https://github.com/Brakerciti/OZForensics_exploit) :  ![starts](https://img.shields.io/github/stars/Brakerciti/OZForensics_exploit.svg) ![forks](https://img.shields.io/github/forks/Brakerciti/OZForensics_exploit.svg)


## CVE-2025-32206
 Unrestricted Upload of File with Dangerous Type vulnerability in LABCAT Processing Projects allows Upload a Web Shell to a Web Server. This issue affects Processing Projects: from n/a through 1.0.2.

- [https://github.com/Nxploited/CVE-2025-32206](https://github.com/Nxploited/CVE-2025-32206) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32206.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32206.svg)


## CVE-2025-31486
 Vite is a frontend tooling framework for javascript. The contents of arbitrary files can be returned to the browser. By adding ?.svg with ?.wasm?init or with sec-fetch-dest: script header, the server.fs.deny restriction was able to bypass. This bypass is only possible if the file is smaller than build.assetsInlineLimit (default: 4kB) and when using Vite 6.0+. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 4.5.12, 5.4.17, 6.0.14, 6.1.4, and 6.2.5.

- [https://github.com/Ly4j/CVE-2025-31486](https://github.com/Ly4j/CVE-2025-31486) :  ![starts](https://img.shields.io/github/stars/Ly4j/CVE-2025-31486.svg) ![forks](https://img.shields.io/github/forks/Ly4j/CVE-2025-31486.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ghostsec420/ShatteredFTP](https://github.com/ghostsec420/ShatteredFTP) :  ![starts](https://img.shields.io/github/stars/ghostsec420/ShatteredFTP.svg) ![forks](https://img.shields.io/github/forks/ghostsec420/ShatteredFTP.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter](https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter) :  ![starts](https://img.shields.io/github/stars/darklotuskdb/nextjs-CVE-2025-29927-hunter.svg) ![forks](https://img.shields.io/github/forks/darklotuskdb/nextjs-CVE-2025-29927-hunter.svg)


## CVE-2025-26865
In that case, users are recommended to upgrade to version 18.12.18, which fixes the issue.

- [https://github.com/mbadanoiu/CVE-2025-26865](https://github.com/mbadanoiu/CVE-2025-26865) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-26865.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-26865.svg)


## CVE-2025-3248
code.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)


## CVE-2025-2825
 DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2025-31161. Reason: This Record is a reservation duplicate of CVE-2025-31161. Notes: All CVE users should reference CVE-2025-31161 instead of this Record. All references and descriptions in this Record have been removed to prevent accidental usage.

- [https://github.com/ghostsec420/ShatteredFTP](https://github.com/ghostsec420/ShatteredFTP) :  ![starts](https://img.shields.io/github/stars/ghostsec420/ShatteredFTP.svg) ![forks](https://img.shields.io/github/forks/ghostsec420/ShatteredFTP.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/binarywarm/exp-cmd-add-admin-vpn-CVE-2024-55591](https://github.com/binarywarm/exp-cmd-add-admin-vpn-CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/binarywarm/exp-cmd-add-admin-vpn-CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/binarywarm/exp-cmd-add-admin-vpn-CVE-2024-55591.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/bmth666/GeoServer-Tools-CVE-2024-36401](https://github.com/bmth666/GeoServer-Tools-CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/bmth666/GeoServer-Tools-CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/bmth666/GeoServer-Tools-CVE-2024-36401.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/G4sul1n/Cisco-IOS-XE-CVE-2023-20198](https://github.com/G4sul1n/Cisco-IOS-XE-CVE-2023-20198) :  ![starts](https://img.shields.io/github/stars/G4sul1n/Cisco-IOS-XE-CVE-2023-20198.svg) ![forks](https://img.shields.io/github/forks/G4sul1n/Cisco-IOS-XE-CVE-2023-20198.svg)


## CVE-2022-25813
 In Apache OFBiz, versions 18.12.05 and earlier, an attacker acting as an anonymous user of the ecommerce plugin, can insert a malicious content in a message “Subject” field from the "Contact us" page. Then a party manager needs to list the communications in the party component to activate the SSTI. A RCE is then possible.

- [https://github.com/mbadanoiu/CVE-2025-26865](https://github.com/mbadanoiu/CVE-2025-26865) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-26865.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-26865.svg)


## CVE-2021-24006
 An improper access control vulnerability in FortiManager versions 6.4.0 to 6.4.3 may allow an authenticated attacker with a restricted user profile to access the SD-WAN Orchestrator panel via directly visiting its URL.

- [https://github.com/cnetsec/CVE-2021-24006-Fortimanager-Exploit](https://github.com/cnetsec/CVE-2021-24006-Fortimanager-Exploit) :  ![starts](https://img.shields.io/github/stars/cnetsec/CVE-2021-24006-Fortimanager-Exploit.svg) ![forks](https://img.shields.io/github/forks/cnetsec/CVE-2021-24006-Fortimanager-Exploit.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/VoyagerOnne/Exim-CVE-2019-10149](https://github.com/VoyagerOnne/Exim-CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/VoyagerOnne/Exim-CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/VoyagerOnne/Exim-CVE-2019-10149.svg)


## CVE-2019-0232
 When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).

- [https://github.com/x3m1Sec/CVE-2019-0232_tomcat_cgi_exploit](https://github.com/x3m1Sec/CVE-2019-0232_tomcat_cgi_exploit) :  ![starts](https://img.shields.io/github/stars/x3m1Sec/CVE-2019-0232_tomcat_cgi_exploit.svg) ![forks](https://img.shields.io/github/forks/x3m1Sec/CVE-2019-0232_tomcat_cgi_exploit.svg)


## CVE-2016-6210
 sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remote attackers to enumerate users by leveraging the timing difference between responses when a large password is provided.

- [https://github.com/nicoleman0/CVE-2016-6210-OpenSSHd-7.2p2](https://github.com/nicoleman0/CVE-2016-6210-OpenSSHd-7.2p2) :  ![starts](https://img.shields.io/github/stars/nicoleman0/CVE-2016-6210-OpenSSHd-7.2p2.svg) ![forks](https://img.shields.io/github/forks/nicoleman0/CVE-2016-6210-OpenSSHd-7.2p2.svg)


## CVE-2015-4133
 Unrestricted file upload vulnerability in admin/scripts/FileUploader/php.php in the ReFlex Gallery plugin before 3.1.4 for WordPress allows remote attackers to execute arbitrary PHP code by uploading a file with a PHP extension, then accessing it via a direct request to the file in uploads/ directory.

- [https://github.com/sug4r-wr41th/CVE-2015-4133](https://github.com/sug4r-wr41th/CVE-2015-4133) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2015-4133.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2015-4133.svg)

