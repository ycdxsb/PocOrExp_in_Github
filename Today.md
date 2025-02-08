# Update 2025-02-08
## CVE-2025-1015
 The Thunderbird Address Book URI fields contained unsanitized links. This could be used by an attacker to create and export an address book containing a malicious payload in a field. For example, in the “Other” field of the Instant Messaging section. If another user imported the address book, clicking on the link could result in opening a web page inside Thunderbird, and that page could execute (unprivileged) JavaScript. This vulnerability affects Thunderbird  128.7.

- [https://github.com/r3m0t3nu11/CVE-2025-1015](https://github.com/r3m0t3nu11/CVE-2025-1015) :  ![starts](https://img.shields.io/github/stars/r3m0t3nu11/CVE-2025-1015.svg) ![forks](https://img.shields.io/github/forks/r3m0t3nu11/CVE-2025-1015.svg)


## CVE-2024-57610
 A rate limiting issue in Sylius v2.0.2 allows a remote attacker to perform unrestricted brute-force attacks on user accounts, significantly increasing the risk of account compromise and denial of service for legitimate users.

- [https://github.com/nca785/CVE-2024-57610](https://github.com/nca785/CVE-2024-57610) :  ![starts](https://img.shields.io/github/stars/nca785/CVE-2024-57610.svg) ![forks](https://img.shields.io/github/forks/nca785/CVE-2024-57610.svg)


## CVE-2024-57609
 An issue in Kanaries Inc Pygwalker before v.0.4.9.9 allows a remote attacker to obtain sensitive information and execute arbitrary code via the redirect_path parameter of the login redirection function.

- [https://github.com/nca785/CVE-2024-57609](https://github.com/nca785/CVE-2024-57609) :  ![starts](https://img.shields.io/github/stars/nca785/CVE-2024-57609.svg) ![forks](https://img.shields.io/github/forks/nca785/CVE-2024-57609.svg)


## CVE-2024-57523
 Cross Site Request Forgery (CSRF) in Users.php in SourceCodester Packers and Movers Management System 1.0 allows attackers to create unauthorized admin accounts via crafted requests sent to an authenticated admin user.

- [https://github.com/HackWidMaddy/CVE-2024-57523.](https://github.com/HackWidMaddy/CVE-2024-57523.) :  ![starts](https://img.shields.io/github/stars/HackWidMaddy/CVE-2024-57523..svg) ![forks](https://img.shields.io/github/forks/HackWidMaddy/CVE-2024-57523..svg)


## CVE-2024-57430
 An SQL injection vulnerability in the pjActionGetUser function of PHPJabbers Cinema Booking System v2.0 allows attackers to manipulate database queries via the column parameter. Exploiting this flaw can lead to unauthorized information disclosure, privilege escalation, or database manipulation.

- [https://github.com/ahrixia/CVE-2024-57430](https://github.com/ahrixia/CVE-2024-57430) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57430.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57430.svg)


## CVE-2024-57429
 A cross-site request forgery (CSRF) vulnerability in the pjActionUpdate function of PHPJabbers Cinema Booking System v2.0 allows remote attackers to escalate privileges by tricking an authenticated admin into submitting an unauthorized request.

- [https://github.com/ahrixia/CVE-2024-57429](https://github.com/ahrixia/CVE-2024-57429) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57429.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57429.svg)


## CVE-2024-57428
 A stored cross-site scripting (XSS) vulnerability in PHPJabbers Cinema Booking System v2.0 exists due to unsanitized input in file upload fields (event_img, seat_maps) and seat number configurations (number[new_X] in pjActionCreate). Attackers can inject persistent JavaScript, leading to phishing, malware injection, and session hijacking.

- [https://github.com/ahrixia/CVE-2024-57428](https://github.com/ahrixia/CVE-2024-57428) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57428.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57428.svg)


## CVE-2024-57427
 PHPJabbers Cinema Booking System v2.0 is vulnerable to reflected cross-site scripting (XSS). Multiple endpoints improperly handle user input, allowing malicious scripts to execute in a victim’s browser. Attackers can craft malicious links to steal session cookies or conduct phishing attacks.

- [https://github.com/ahrixia/CVE-2024-57427](https://github.com/ahrixia/CVE-2024-57427) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57427.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57427.svg)


## CVE-2024-56889
 Incorrect access control in the endpoint /admin/m_delete.php of CodeAstro Complaint Management System v1.0 allows unauthorized attackers to arbitrarily delete complaints via modification of the id parameter.

- [https://github.com/vigneshr232/CVE-2024-56889](https://github.com/vigneshr232/CVE-2024-56889) :  ![starts](https://img.shields.io/github/stars/vigneshr232/CVE-2024-56889.svg) ![forks](https://img.shields.io/github/forks/vigneshr232/CVE-2024-56889.svg)


## CVE-2024-48589
 Cross Site Scripting vulnerability in Gilnei Moraes phpABook v.0.9 allows a remote attacker to execute arbitrary code via the rol parameter in index.php

- [https://github.com/Exek1el/CVE-2024-48589](https://github.com/Exek1el/CVE-2024-48589) :  ![starts](https://img.shields.io/github/stars/Exek1el/CVE-2024-48589.svg) ![forks](https://img.shields.io/github/forks/Exek1el/CVE-2024-48589.svg)


## CVE-2024-35235
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.8 and earlier, when starting the cupsd server with a Listen configuration item pointing to a symbolic link, the cupsd process can be caused to perform an arbitrary chmod of the provided argument, providing world-writable access to the target. Given that cupsd is often running as root, this can result in the change of permission of any user or system files to be world writable. Given the aforementioned Ubuntu AppArmor context, on such systems this vulnerability is limited to those files modifiable by the cupsd process. In that specific case it was found to be possible to turn the configuration of the Listen argument into full control over the cupsd.conf and cups-files.conf configuration files. By later setting the User and Group arguments in cups-files.conf, and printing with a printer configured by PPD with a `FoomaticRIPCommandLine` argument, arbitrary user and group (not root) command execution could be achieved, which can further be used on Ubuntu systems to achieve full root command execution. Commit ff1f8a623e090dee8a8aadf12a6a4b25efac143d contains a patch for the issue.

- [https://github.com/zrax-x/CVE-2024-5290-exp](https://github.com/zrax-x/CVE-2024-5290-exp) :  ![starts](https://img.shields.io/github/stars/zrax-x/CVE-2024-5290-exp.svg) ![forks](https://img.shields.io/github/forks/zrax-x/CVE-2024-5290-exp.svg)


## CVE-2024-9474
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/dcollaoa/cve-2024-0012-gui-poc](https://github.com/dcollaoa/cve-2024-0012-gui-poc) :  ![starts](https://img.shields.io/github/stars/dcollaoa/cve-2024-0012-gui-poc.svg) ![forks](https://img.shields.io/github/forks/dcollaoa/cve-2024-0012-gui-poc.svg)


## CVE-2024-6624
 The JSON API User plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 3.9.3. This is due to improper controls on custom user meta fields. This makes it possible for unauthenticated attackers to register as administrators on the site. The plugin requires the JSON API plugin to also be installed.

- [https://github.com/Jenderal92/CVE-2024-6624](https://github.com/Jenderal92/CVE-2024-6624) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2024-6624.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2024-6624.svg)


## CVE-2024-5290
Membership in the netdev group or access to the dbus interface of wpa_supplicant allow an unprivileged user to specify an arbitrary path to a module to be loaded by the wpa_supplicant process; other escalation paths might exist.

- [https://github.com/zrax-x/CVE-2024-5290-exp](https://github.com/zrax-x/CVE-2024-5290-exp) :  ![starts](https://img.shields.io/github/stars/zrax-x/CVE-2024-5290-exp.svg) ![forks](https://img.shields.io/github/forks/zrax-x/CVE-2024-5290-exp.svg)


## CVE-2024-0012
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/dcollaoa/cve-2024-0012-gui-poc](https://github.com/dcollaoa/cve-2024-0012-gui-poc) :  ![starts](https://img.shields.io/github/stars/dcollaoa/cve-2024-0012-gui-poc.svg) ![forks](https://img.shields.io/github/forks/dcollaoa/cve-2024-0012-gui-poc.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/Potato-9257/CVE-2022-30190_page](https://github.com/Potato-9257/CVE-2022-30190_page) :  ![starts](https://img.shields.io/github/stars/Potato-9257/CVE-2022-30190_page.svg) ![forks](https://img.shields.io/github/forks/Potato-9257/CVE-2022-30190_page.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2007-4559
 Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in filenames in a TAR archive, a related issue to CVE-2001-1267.

- [https://github.com/JamesDarf/wargame-tarpioka](https://github.com/JamesDarf/wargame-tarpioka) :  ![starts](https://img.shields.io/github/stars/JamesDarf/wargame-tarpioka.svg) ![forks](https://img.shields.io/github/forks/JamesDarf/wargame-tarpioka.svg)

