# Update 2025-10-23
## CVE-2025-62518
 astral-tokio-tar is a tar archive reading/writing library for async Rust. Versions of astral-tokio-tar prior to 0.5.6 contain a boundary parsing vulnerability that allows attackers to smuggle additional archive entries by exploiting inconsistent PAX/ustar header handling. When processing archives with PAX-extended headers containing size overrides, the parser incorrectly advances stream position based on ustar header size (often zero) instead of the PAX-specified size, causing it to interpret file content as legitimate tar headers. This issue has been patched in version 0.5.6. There are no workarounds.

- [https://github.com/edera-dev/cve-tarmageddon](https://github.com/edera-dev/cve-tarmageddon) :  ![starts](https://img.shields.io/github/stars/edera-dev/cve-tarmageddon.svg) ![forks](https://img.shields.io/github/forks/edera-dev/cve-tarmageddon.svg)


## CVE-2025-60751
 GeographicLib 2.5 is vulnerable to Buffer Overflow in GeoConvert DMS::InternalDecode.

- [https://github.com/zer0matt/CVE-2025-60751](https://github.com/zer0matt/CVE-2025-60751) :  ![starts](https://img.shields.io/github/stars/zer0matt/CVE-2025-60751.svg) ![forks](https://img.shields.io/github/forks/zer0matt/CVE-2025-60751.svg)


## CVE-2025-60500
 QDocs Smart School Management System 7.1 allows authenticated users with roles such as "accountant" or "admin" to bypass file type restrictions in the media upload feature by abusing the alternate YouTube URL option. This logic flaw permits uploading of arbitrary PHP files, which are stored in a web-accessible directory.

- [https://github.com/H4zaz/CVE-2025-60500](https://github.com/H4zaz/CVE-2025-60500) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2025-60500.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2025-60500.svg)


## CVE-2025-59230
 Improper access control in Windows Remote Access Connection Manager allows an authorized attacker to elevate privileges locally.

- [https://github.com/stalker110119/CVE-2025-59230](https://github.com/stalker110119/CVE-2025-59230) :  ![starts](https://img.shields.io/github/stars/stalker110119/CVE-2025-59230.svg) ![forks](https://img.shields.io/github/forks/stalker110119/CVE-2025-59230.svg)


## CVE-2025-56802
 The Reolink desktop application uses a hard-coded and predictable AES encryption key to encrypt user configuration files allowing attackers with local access to decrypt sensitive application data stored in %APPDATA%. A different vulnerability than CVE-2025-56802.

- [https://github.com/shinyColumn/CVE-2025-56802](https://github.com/shinyColumn/CVE-2025-56802) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56802.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56802.svg)


## CVE-2025-56801
 The Reolink Desktop Application 8.18.12 contains hardcoded credentials as the Initialization Vector (IV) in its AES-CFB encryption implementation allowing attackers with access to the application environment to reliably decrypt encrypted configuration data.

- [https://github.com/shinyColumn/CVE-2025-56801](https://github.com/shinyColumn/CVE-2025-56801) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56801.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56801.svg)


## CVE-2025-56800
 Reolink desktop application 8.18.12 contains a vulnerability in its local authentication mechanism. The application implements lock screen password logic entirely on the client side using JavaScript within an Electron resource file. Because the password is stored and returned via a modifiable JavaScript property(a.settingsManager.lockScreenPassword), an attacker can patch the return value to bypass authentication.

- [https://github.com/shinyColumn/CVE-2025-56800](https://github.com/shinyColumn/CVE-2025-56800) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56800.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56800.svg)


## CVE-2025-56799
 Reolink desktop application 8.18.12 contains a command injection vulnerability in its scheduled cache-clearing mechanism via a crafted folder name.

- [https://github.com/shinyColumn/CVE-2025-56799](https://github.com/shinyColumn/CVE-2025-56799) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56799.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56799.svg)


## CVE-2025-56450
 Log2Space Subscriber Management Software 1.1 is vulnerable to unauthenticated SQL injection via the `lead_id` parameter in the `/l2s/api/selfcareLeadHistory` endpoint. A remote attacker can exploit this by sending a specially crafted POST request, resulting in the execution of arbitrary SQL queries. The backend fails to sanitize the user input, allowing enumeration of database schemas, table names, and potentially leading to full database compromise.

- [https://github.com/apboss123/CVE-2025-56450](https://github.com/apboss123/CVE-2025-56450) :  ![starts](https://img.shields.io/github/stars/apboss123/CVE-2025-56450.svg) ![forks](https://img.shields.io/github/forks/apboss123/CVE-2025-56450.svg)


## CVE-2025-49002
 DataEase is an open source business intelligence and data visualization tool. Versions prior to version 2.10.10 have a flaw in the patch for CVE-2025-32966 that allow the patch to be bypassed through case insensitivity because INIT and RUNSCRIPT are prohibited. The vulnerability has been fixed in v2.10.10. No known workarounds are available.

- [https://github.com/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002](https://github.com/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002) :  ![starts](https://img.shields.io/github/stars/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002.svg) ![forks](https://img.shields.io/github/forks/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/cesarbtakeda/CVE-2025-31161](https://github.com/cesarbtakeda/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/cesarbtakeda/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/cesarbtakeda/CVE-2025-31161.svg)


## CVE-2025-20682
 In wlan AP driver, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation. Patch ID: WCNCR00416937; Issue ID: MSV-3445.

- [https://github.com/Kartiowmn/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk](https://github.com/Kartiowmn/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk) :  ![starts](https://img.shields.io/github/stars/Kartiowmn/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg) ![forks](https://img.shields.io/github/forks/Kartiowmn/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg)


## CVE-2025-10377
 The System Dashboard plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 2.8.20. This is due to missing nonce validation on the sd_toggle_logs() function. This makes it possible for unauthenticated attackers to toggle critical logging settings including Page Access Logs, Error Logs, and Email Delivery Logs via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/NagisaYumaa/CVE-2025-10377](https://github.com/NagisaYumaa/CVE-2025-10377) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-10377.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-10377.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/kaucent/CVE-2025-8088](https://github.com/kaucent/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/kaucent/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/kaucent/CVE-2025-8088.svg)
- [https://github.com/papcaii2004/CVE-2025-8088-WinRAR-builder](https://github.com/papcaii2004/CVE-2025-8088-WinRAR-builder) :  ![starts](https://img.shields.io/github/stars/papcaii2004/CVE-2025-8088-WinRAR-builder.svg) ![forks](https://img.shields.io/github/forks/papcaii2004/CVE-2025-8088-WinRAR-builder.svg)


## CVE-2025-1265
 An OS command injection vulnerability exists in Vinci Protocol Analyzer that could allow an attacker to escalate privileges and perform code execution on affected system.

- [https://github.com/Tarimaow/Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Tarimaow/Anydesk-Exploit-CVE-2025-12654-RCE-Builder) :  ![starts](https://img.shields.io/github/stars/Tarimaow/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg) ![forks](https://img.shields.io/github/forks/Tarimaow/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg)


## CVE-2024-29269
 An issue discovered in Telesquare TLR-2005Ksh 1.0.0 and 1.1.4 allows attackers to run arbitrary system commands via the Cmd parameter.

- [https://github.com/chsxthwik/CVE-2024-29269](https://github.com/chsxthwik/CVE-2024-29269) :  ![starts](https://img.shields.io/github/stars/chsxthwik/CVE-2024-29269.svg) ![forks](https://img.shields.io/github/forks/chsxthwik/CVE-2024-29269.svg)


## CVE-2024-9348
 Docker Desktop before v4.34.3 allows RCE via unsanitized GitHub source link in Build view.

- [https://github.com/Nimisha17/CVE-2024-9348-poc](https://github.com/Nimisha17/CVE-2024-9348-poc) :  ![starts](https://img.shields.io/github/stars/Nimisha17/CVE-2024-9348-poc.svg) ![forks](https://img.shields.io/github/forks/Nimisha17/CVE-2024-9348-poc.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/chsxthwik/CVE-2024-2876](https://github.com/chsxthwik/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/chsxthwik/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/chsxthwik/CVE-2024-2876.svg)


## CVE-2024-1209
 The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.1 via direct file access due to insufficient protection of uploaded assignments. This makes it possible for unauthenticated attackers to obtain those uploads.

- [https://github.com/karlemilnikka/CVE-2024-1209](https://github.com/karlemilnikka/CVE-2024-1209) :  ![starts](https://img.shields.io/github/stars/karlemilnikka/CVE-2024-1209.svg) ![forks](https://img.shields.io/github/forks/karlemilnikka/CVE-2024-1209.svg)


## CVE-2023-39143
 PaperCut NG and PaperCut MF before 22.1.3 on Windows allow path traversal, enabling attackers to upload, read, or delete arbitrary files. This leads to remote code execution when external device integration is enabled (a very common configuration).

- [https://github.com/foregenix/CVE-2023-39143](https://github.com/foregenix/CVE-2023-39143) :  ![starts](https://img.shields.io/github/stars/foregenix/CVE-2023-39143.svg) ![forks](https://img.shields.io/github/forks/foregenix/CVE-2023-39143.svg)


## CVE-2023-33669
 Tenda AC8V4.0-V16.03.34.06 was discovered to contain a stack overflow via the timeZone parameter in the sub_44db3c function.

- [https://github.com/retr0reg/tenda-ac8v4-rop](https://github.com/retr0reg/tenda-ac8v4-rop) :  ![starts](https://img.shields.io/github/stars/retr0reg/tenda-ac8v4-rop.svg) ![forks](https://img.shields.io/github/forks/retr0reg/tenda-ac8v4-rop.svg)
- [https://github.com/Mohammaddvd/CVE-2023-33669](https://github.com/Mohammaddvd/CVE-2023-33669) :  ![starts](https://img.shields.io/github/stars/Mohammaddvd/CVE-2023-33669.svg) ![forks](https://img.shields.io/github/forks/Mohammaddvd/CVE-2023-33669.svg)


## CVE-2023-32571
 Dynamic Linq 1.0.7.10 through 1.2.25 before 1.3.0 allows attackers to execute arbitrary code and commands when untrusted input to methods including Where, Select, OrderBy is parsed.

- [https://github.com/SecTex/CVE-2023-32571](https://github.com/SecTex/CVE-2023-32571) :  ![starts](https://img.shields.io/github/stars/SecTex/CVE-2023-32571.svg) ![forks](https://img.shields.io/github/forks/SecTex/CVE-2023-32571.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/xtwip/fortipwn](https://github.com/xtwip/fortipwn) :  ![starts](https://img.shields.io/github/stars/xtwip/fortipwn.svg) ![forks](https://img.shields.io/github/forks/xtwip/fortipwn.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/delyee/Spring4Shell](https://github.com/delyee/Spring4Shell) :  ![starts](https://img.shields.io/github/stars/delyee/Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/delyee/Spring4Shell.svg)


## CVE-2019-7164
 SQLAlchemy through 1.2.17 and 1.3.x through 1.3.0b2 allows SQL Injection via the order_by parameter.

- [https://github.com/stuxbench/mlflow-cve-2019-7164](https://github.com/stuxbench/mlflow-cve-2019-7164) :  ![starts](https://img.shields.io/github/stars/stuxbench/mlflow-cve-2019-7164.svg) ![forks](https://img.shields.io/github/forks/stuxbench/mlflow-cve-2019-7164.svg)


## CVE-2017-7679
 In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.

- [https://github.com/Al-Lord0x/CVE-2017-7679](https://github.com/Al-Lord0x/CVE-2017-7679) :  ![starts](https://img.shields.io/github/stars/Al-Lord0x/CVE-2017-7679.svg) ![forks](https://img.shields.io/github/forks/Al-Lord0x/CVE-2017-7679.svg)


## CVE-2010-2861
 Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the locale parameter to (1) CFIDE/administrator/settings/mappings.cfm, (2) logging/settings.cfm, (3) datasources/index.cfm, (4) j2eepackaging/editarchive.cfm, and (5) enter.cfm in CFIDE/administrator/.

- [https://github.com/greysneakthief/14641-v2](https://github.com/greysneakthief/14641-v2) :  ![starts](https://img.shields.io/github/stars/greysneakthief/14641-v2.svg) ![forks](https://img.shields.io/github/forks/greysneakthief/14641-v2.svg)

