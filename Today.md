# Update 2025-02-24
## CVE-2025-26794
 Exim 4.98 before 4.98.1, when SQLite hints and ETRN serialization are used, allows remote SQL injection.

- [https://github.com/OscarBataille/CVE-2025-26794](https://github.com/OscarBataille/CVE-2025-26794) :  ![starts](https://img.shields.io/github/stars/OscarBataille/CVE-2025-26794.svg) ![forks](https://img.shields.io/github/forks/OscarBataille/CVE-2025-26794.svg)


## CVE-2025-0924
 The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘message’ parameter in all versions up to, and including, 5.2.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/skrkcb2/CVE-2025-0924](https://github.com/skrkcb2/CVE-2025-0924) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2025-0924.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2025-0924.svg)


## CVE-2024-56199
 phpMyFAQ is an open source FAQ web application. Starting no later than version 3.2.10 and prior to version 4.0.2, an attacker can inject malicious HTML content into the FAQ editor at `http[:]//localhost/admin/index[.]php?action=editentry`, resulting in a complete disruption of the FAQ page's user interface. By injecting malformed HTML elements styled to cover the entire screen, an attacker can render the page unusable. This injection manipulates the page structure by introducing overlapping buttons, images, and iframes, breaking the intended layout and functionality. Exploiting this issue can lead to Denial of Service for legitimate users, damage to the user experience, and potential abuse in phishing or defacement attacks. Version 4.0.2 contains a patch for the vulnerability.

- [https://github.com/geo-chen/phpMyFAQ](https://github.com/geo-chen/phpMyFAQ) :  ![starts](https://img.shields.io/github/stars/geo-chen/phpMyFAQ.svg) ![forks](https://img.shields.io/github/forks/geo-chen/phpMyFAQ.svg)


## CVE-2024-55889
 phpMyFAQ is an open source FAQ web application. Prior to version 3.2.10, a vulnerability exists in the FAQ Record component where a privileged attacker can trigger a file download on a victim's machine upon page visit by embedding it in an iframe element without user interaction or explicit consent. Version 3.2.10 fixes the issue.

- [https://github.com/geo-chen/phpMyFAQ](https://github.com/geo-chen/phpMyFAQ) :  ![starts](https://img.shields.io/github/stars/geo-chen/phpMyFAQ.svg) ![forks](https://img.shields.io/github/forks/geo-chen/phpMyFAQ.svg)


## CVE-2024-54141
 phpMyFAQ is an open source FAQ web application for PHP 8.1+ and MySQL, PostgreSQL and other databases. Prior to 4.0.0, phpMyFAQ exposes the database (ie postgreSQL) server's credential when connection to DB fails. This vulnerability is fixed in 4.0.0.

- [https://github.com/geo-chen/phpMyFAQ](https://github.com/geo-chen/phpMyFAQ) :  ![starts](https://img.shields.io/github/stars/geo-chen/phpMyFAQ.svg) ![forks](https://img.shields.io/github/forks/geo-chen/phpMyFAQ.svg)


## CVE-2024-13869
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'upload_files' function in all versions up to, and including, 0.9.112. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: Uploaded files are only accessible on WordPress instances running on the NGINX web server as the existing .htaccess within the target file upload folder prevents access on Apache servers.

- [https://github.com/d0n601/CVE-2024-13869](https://github.com/d0n601/CVE-2024-13869) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2024-13869.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2024-13869.svg)


## CVE-2024-13209
 A vulnerability was found in Redaxo CMS 5.18.1. It has been classified as problematic. Affected is an unknown function of the file /index.php?page=structure&category_id=1&article_id=1&clang=1&function=edit_art&artstart=0 of the component Structure Management Page. The manipulation of the argument Article Name leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/geo-chen/Redaxo](https://github.com/geo-chen/Redaxo) :  ![starts](https://img.shields.io/github/stars/geo-chen/Redaxo.svg) ![forks](https://img.shields.io/github/forks/geo-chen/Redaxo.svg)


## CVE-2024-12884
 A vulnerability was found in Codezips E-Commerce Website 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file /login.php. The manipulation of the argument email leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/geo-chen/E-Commerce](https://github.com/geo-chen/E-Commerce) :  ![starts](https://img.shields.io/github/stars/geo-chen/E-Commerce.svg) ![forks](https://img.shields.io/github/forks/geo-chen/E-Commerce.svg)


## CVE-2024-5482
 A Server-Side Request Forgery (SSRF) vulnerability exists in the 'add_webpage' endpoint of the parisneo/lollms-webui application, affecting the latest version. The vulnerability arises because the application does not adequately validate URLs entered by users, allowing them to input arbitrary URLs, including those that target internal resources such as 'localhost' or '127.0.0.1'. This flaw enables attackers to make unauthorized requests to internal or external systems, potentially leading to access to sensitive data, service disruption, network integrity compromise, business logic manipulation, and abuse of third-party resources. The issue is critical and requires immediate attention to maintain the application's security and integrity.

- [https://github.com/jcarabantes/CVE-2024-54820](https://github.com/jcarabantes/CVE-2024-54820) :  ![starts](https://img.shields.io/github/stars/jcarabantes/CVE-2024-54820.svg) ![forks](https://img.shields.io/github/forks/jcarabantes/CVE-2024-54820.svg)


## CVE-2023-1545
 SQL Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.0.23.

- [https://github.com/HarshRajSinghania/CVE-2023-1545-Exploit](https://github.com/HarshRajSinghania/CVE-2023-1545-Exploit) :  ![starts](https://img.shields.io/github/stars/HarshRajSinghania/CVE-2023-1545-Exploit.svg) ![forks](https://img.shields.io/github/forks/HarshRajSinghania/CVE-2023-1545-Exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-27365
 An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message.

- [https://github.com/coderzawad/Kernel-CVE-2021-27365-hotfix](https://github.com/coderzawad/Kernel-CVE-2021-27365-hotfix) :  ![starts](https://img.shields.io/github/stars/coderzawad/Kernel-CVE-2021-27365-hotfix.svg) ![forks](https://img.shields.io/github/forks/coderzawad/Kernel-CVE-2021-27365-hotfix.svg)


## CVE-2014-0221
 The dtls1_get_message_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h allows remote attackers to cause a denial of service (recursion and client crash) via a DTLS hello message in an invalid DTLS handshake.

- [https://github.com/chihyeonwon/OpenSSL_DTLS_CVE_2014_0221](https://github.com/chihyeonwon/OpenSSL_DTLS_CVE_2014_0221) :  ![starts](https://img.shields.io/github/stars/chihyeonwon/OpenSSL_DTLS_CVE_2014_0221.svg) ![forks](https://img.shields.io/github/forks/chihyeonwon/OpenSSL_DTLS_CVE_2014_0221.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/yashfren/CVE-2014-0160-HeartBleed](https://github.com/yashfren/CVE-2014-0160-HeartBleed) :  ![starts](https://img.shields.io/github/stars/yashfren/CVE-2014-0160-HeartBleed.svg) ![forks](https://img.shields.io/github/forks/yashfren/CVE-2014-0160-HeartBleed.svg)

