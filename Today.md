# Update 2025-09-24
## CVE-2025-59424
 LinkAce is a self-hosted archive to collect website links. Prior to 2.3.1, a Stored Cross-Site Scripting (XSS) vulnerability has been identified on the /system/audit page. The application fails to properly sanitize the username field before it is rendered in the audit log. An authenticated attacker can set a malicious JavaScript payload as their username. When an action performed by this user is recorded (e.g., generate or revoke an API token), the payload is stored in the database. The script is then executed in the browser of any user, particularly administrators, who views the /system/audit page. This vulnerability is fixed in 2.3.1.

- [https://github.com/JOOJIII/CVE-2025-59424](https://github.com/JOOJIII/CVE-2025-59424) :  ![starts](https://img.shields.io/github/stars/JOOJIII/CVE-2025-59424.svg) ![forks](https://img.shields.io/github/forks/JOOJIII/CVE-2025-59424.svg)


## CVE-2025-55888
 Cross-Site Scripting (XSS) vulnerability was discovered in the Ajax transaction manager endpoint of ARD. An attacker can intercept the Ajax response and inject malicious JavaScript into the accountName field. This input is not properly sanitized or encoded when rendered, allowing script execution in the context of users browsers. This flaw could lead to session hijacking, cookie theft, and other malicious actions.

- [https://github.com/0xZeroSec/CVE-2025-55888](https://github.com/0xZeroSec/CVE-2025-55888) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55888.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55888.svg)


## CVE-2025-55887
 Cross-Site Scripting (XSS) vulnerability was discovered in the meal reservation service ARD. The vulnerability exists in the transactionID GET parameter on the transaction confirmation page. Due to improper input validation and output encoding, an attacker can inject malicious JavaScript code that is executed in the context of a user s browser. This can lead to session hijacking, theft of cookies, and other malicious actions performed on behalf of the victim.

- [https://github.com/0xZeroSec/CVE-2025-55887](https://github.com/0xZeroSec/CVE-2025-55887) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55887.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55887.svg)


## CVE-2025-55886
 An Insecure Direct Object Reference (IDOR) vulnerability was discovered in ARD. The flaw exists in the `fe_uid` parameter of the payment history API endpoint. An authenticated attacker can manipulate this parameter to access the payment history of other users without authorization.

- [https://github.com/0xZeroSec/CVE-2025-55886](https://github.com/0xZeroSec/CVE-2025-55886) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55886.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55886.svg)


## CVE-2025-55885
 SQL Injection vulnerability in Alpes Recherche et Developpement ARD GEC en Lign before v.2025-04-23 allows a remote attacker to escalate privileges via the GET parameters in index.php

- [https://github.com/0xZeroSec/CVE-2025-55885](https://github.com/0xZeroSec/CVE-2025-55885) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55885.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55885.svg)


## CVE-2025-55234
Adopt appropriate SMB Server hardening measures.

- [https://github.com/mrk336/CVE-2025-55234](https://github.com/mrk336/CVE-2025-55234) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-55234.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-55234.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/chin-tech/CrushFTP_CVE-2025-54309](https://github.com/chin-tech/CrushFTP_CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/chin-tech/CrushFTP_CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/chin-tech/CrushFTP_CVE-2025-54309.svg)


## CVE-2025-52357
 Cross-Site Scripting (XSS) vulnerability exists in the ping diagnostic feature of FiberHome FD602GW-DX-R410 router (firmware V2.2.14), allowing an authenticated attacker to execute arbitrary JavaScript code in the context of the router s web interface. The vulnerability is triggered via user-supplied input in the ping form field, which fails to sanitize special characters. This can be exploited to hijack sessions or escalate privileges through social engineering or browser-based attacks.

- [https://github.com/wrathfulDiety/CVE-2025-52357](https://github.com/wrathfulDiety/CVE-2025-52357) :  ![starts](https://img.shields.io/github/stars/wrathfulDiety/CVE-2025-52357.svg) ![forks](https://img.shields.io/github/forks/wrathfulDiety/CVE-2025-52357.svg)


## CVE-2025-52122
 Freeform 5.0.0 to before 5.10.16, a plugin for CraftCMS, contains an Server-side template injection (SSTI) vulnerability, resulting in arbitrary code injection for all users that have access to editing a form (submission title).

- [https://github.com/TimTrademark/CVE-2025-52122](https://github.com/TimTrademark/CVE-2025-52122) :  ![starts](https://img.shields.io/github/stars/TimTrademark/CVE-2025-52122.svg) ![forks](https://img.shields.io/github/forks/TimTrademark/CVE-2025-52122.svg)


## CVE-2025-51006
 Within tcpreplay's tcprewrite, a double free vulnerability has been identified in the dlt_linuxsll2_cleanup() function in plugins/dlt_linuxsll2/linuxsll2.c. This vulnerability is triggered when tcpedit_dlt_cleanup() indirectly invokes the cleanup routine multiple times on the same memory region. By supplying a specifically crafted pcap file to the tcprewrite binary, a local attacker can exploit this flaw to cause a Denial of Service (DoS) via memory corruption.

- [https://github.com/sy460129/CVE-2025-51006](https://github.com/sy460129/CVE-2025-51006) :  ![starts](https://img.shields.io/github/stars/sy460129/CVE-2025-51006.svg) ![forks](https://img.shields.io/github/forks/sy460129/CVE-2025-51006.svg)


## CVE-2025-49619
 Skyvern through 0.1.85 is vulnerable to server-side template injection (SSTI) in the Prompt field of workflow blocks such as the Navigation v2 Block. Improper sanitization of Jinja2 template input allows authenticated users to inject crafted expressions that are evaluated on the server, leading to blind remote code execution (RCE).

- [https://github.com/cristibtz/CVE-2025-49619](https://github.com/cristibtz/CVE-2025-49619) :  ![starts](https://img.shields.io/github/stars/cristibtz/CVE-2025-49619.svg) ![forks](https://img.shields.io/github/forks/cristibtz/CVE-2025-49619.svg)


## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/Vr00mm/CVE-2025-49144](https://github.com/Vr00mm/CVE-2025-49144) :  ![starts](https://img.shields.io/github/stars/Vr00mm/CVE-2025-49144.svg) ![forks](https://img.shields.io/github/forks/Vr00mm/CVE-2025-49144.svg)
- [https://github.com/assad12341/notepad-v8.8.1-LPE-CVE-](https://github.com/assad12341/notepad-v8.8.1-LPE-CVE-) :  ![starts](https://img.shields.io/github/stars/assad12341/notepad-v8.8.1-LPE-CVE-.svg) ![forks](https://img.shields.io/github/forks/assad12341/notepad-v8.8.1-LPE-CVE-.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/qiaojojo/CVE-2025-49132_poc](https://github.com/qiaojojo/CVE-2025-49132_poc) :  ![starts](https://img.shields.io/github/stars/qiaojojo/CVE-2025-49132_poc.svg) ![forks](https://img.shields.io/github/forks/qiaojojo/CVE-2025-49132_poc.svg)
- [https://github.com/63square/CVE-2025-49132](https://github.com/63square/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/63square/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/63square/CVE-2025-49132.svg)
- [https://github.com/pxxdrobits/CVE-2025-49132](https://github.com/pxxdrobits/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/pxxdrobits/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/pxxdrobits/CVE-2025-49132.svg)
- [https://github.com/melonlonmeo/CVE-2025-49132](https://github.com/melonlonmeo/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/melonlonmeo/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/melonlonmeo/CVE-2025-49132.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/BiiTts/Roundcube-CVE-2025-49113](https://github.com/BiiTts/Roundcube-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/BiiTts/Roundcube-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/BiiTts/Roundcube-CVE-2025-49113.svg)
- [https://github.com/issamjr/CVE-2025-49113-Scanner](https://github.com/issamjr/CVE-2025-49113-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-49113-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-49113-Scanner.svg)
- [https://github.com/rasool13x/exploit-CVE-2025-49113](https://github.com/rasool13x/exploit-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/rasool13x/exploit-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/rasool13x/exploit-CVE-2025-49113.svg)
- [https://github.com/SyFi/CVE-2025-49113](https://github.com/SyFi/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2025-49113.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-49113](https://github.com/B1ack4sh/Blackash-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-49113.svg)
- [https://github.com/Yuri08loveElaina/CVE-2025-49113](https://github.com/Yuri08loveElaina/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-49113.svg)
- [https://github.com/5kr1pt/Roundcube_CVE-2025-49113](https://github.com/5kr1pt/Roundcube_CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/5kr1pt/Roundcube_CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/5kr1pt/Roundcube_CVE-2025-49113.svg)
- [https://github.com/punitdarji/roundcube-cve-2025-49113](https://github.com/punitdarji/roundcube-cve-2025-49113) :  ![starts](https://img.shields.io/github/stars/punitdarji/roundcube-cve-2025-49113.svg) ![forks](https://img.shields.io/github/forks/punitdarji/roundcube-cve-2025-49113.svg)


## CVE-2025-48988
Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.

- [https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988](https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988) :  ![starts](https://img.shields.io/github/stars/nankuo/CVE-2025-48976_CVE-2025-48988.svg) ![forks](https://img.shields.io/github/forks/nankuo/CVE-2025-48976_CVE-2025-48988.svg)
- [https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976](https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976) :  ![starts](https://img.shields.io/github/stars/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg) ![forks](https://img.shields.io/github/forks/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg)


## CVE-2025-48976
Users are recommended to upgrade to versions 1.6 or 2.0.0-M4, which fix the issue.

- [https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988](https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988) :  ![starts](https://img.shields.io/github/stars/nankuo/CVE-2025-48976_CVE-2025-48988.svg) ![forks](https://img.shields.io/github/forks/nankuo/CVE-2025-48976_CVE-2025-48988.svg)
- [https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976](https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976) :  ![starts](https://img.shields.io/github/stars/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg) ![forks](https://img.shields.io/github/forks/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg)


## CVE-2025-48828
 Certain vBulletin versions might allow attackers to execute arbitrary PHP code by abusing Template Conditionals in the template engine. By crafting template code in an alternative PHP function invocation syntax, such as the "var_dump"("test") syntax, attackers can bypass security checks and execute arbitrary PHP code, as exploited in the wild in May 2025.

- [https://github.com/ill-deed/vBulletin-CVE-2025-48828-Multi-target](https://github.com/ill-deed/vBulletin-CVE-2025-48828-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/vBulletin-CVE-2025-48828-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/vBulletin-CVE-2025-48828-Multi-target.svg)


## CVE-2025-48799
 Improper link resolution before file access ('link following') in Windows Update Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/ukisshinaah/CVE-2025-48799](https://github.com/ukisshinaah/CVE-2025-48799) :  ![starts](https://img.shields.io/github/stars/ukisshinaah/CVE-2025-48799.svg) ![forks](https://img.shields.io/github/forks/ukisshinaah/CVE-2025-48799.svg)


## CVE-2025-48703
 CWP (aka Control Web Panel or CentOS Web Panel) before 0.9.8.1205 allows unauthenticated remote code execution via shell metacharacters in the t_total parameter in a filemanager changePerm request. A valid non-root username must be known.

- [https://github.com/Skynoxk/CVE-2025-48703](https://github.com/Skynoxk/CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/Skynoxk/CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/Skynoxk/CVE-2025-48703.svg)


## CVE-2025-48466
 Successful exploitation of the vulnerability could allow an unauthenticated, remote attacker to send Modbus TCP packets to manipulate Digital Outputs, potentially allowing remote control of relay channel which may lead to operational or safety risks.

- [https://github.com/shipcod3/CVE-2025-48466](https://github.com/shipcod3/CVE-2025-48466) :  ![starts](https://img.shields.io/github/stars/shipcod3/CVE-2025-48466.svg) ![forks](https://img.shields.io/github/forks/shipcod3/CVE-2025-48466.svg)


## CVE-2025-48461
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to conduct brute force guessing and account takeover as the session cookies are predictable, potentially allowing the attackers to gain root, admin or user access and reset passwords.

- [https://github.com/joelczk/CVE-2025-48461](https://github.com/joelczk/CVE-2025-48461) :  ![starts](https://img.shields.io/github/stars/joelczk/CVE-2025-48461.svg) ![forks](https://img.shields.io/github/forks/joelczk/CVE-2025-48461.svg)


## CVE-2025-48129
 Incorrect Privilege Assignment vulnerability in Holest Engineering Spreadsheet Price Changer for WooCommerce and WP E-commerce – Light allows Privilege Escalation. This issue affects Spreadsheet Price Changer for WooCommerce and WP E-commerce – Light: from n/a through 2.4.37.

- [https://github.com/Nxploited/CVE-2025-48129](https://github.com/Nxploited/CVE-2025-48129) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-48129.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-48129.svg)


## CVE-2025-47577
 Unrestricted Upload of File with Dangerous Type vulnerability in TemplateInvaders TI WooCommerce Wishlist allows Upload a Web Shell to a Web Server.This issue affects TI WooCommerce Wishlist: from n/a before 2.10.0.

- [https://github.com/sug4r-wr41th/CVE-2025-47577](https://github.com/sug4r-wr41th/CVE-2025-47577) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2025-47577.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2025-47577.svg)


## CVE-2025-46178
 Cross-Site Scripting (XSS) vulnerability exists in askquery.php via the eid parameter in the CloudClassroom PHP Project. This allows remote attackers to inject arbitrary JavaScript in the context of a victim s browser session by sending a crafted URL, leading to session hijacking or defacement.

- [https://github.com/SacX-7/CVE-2025-46178](https://github.com/SacX-7/CVE-2025-46178) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-46178.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-46178.svg)


## CVE-2025-46171
 vBulletin 3.8.7 is vulnerable to a denial-of-service condition via the misc.php?do=buddylist endpoint. If an authenticated user has a sufficiently large buddy list, processing the list can consume excessive memory, exhausting system resources and crashing the forum.

- [https://github.com/oiyl/CVE-2025-46171](https://github.com/oiyl/CVE-2025-46171) :  ![starts](https://img.shields.io/github/stars/oiyl/CVE-2025-46171.svg) ![forks](https://img.shields.io/github/forks/oiyl/CVE-2025-46171.svg)


## CVE-2025-46157
 An issue in EfroTech Time Trax v.1.0 allows a remote attacker to execute arbitrary code via the file attachment function in the leave request form

- [https://github.com/morphine009/CVE-2025-46157](https://github.com/morphine009/CVE-2025-46157) :  ![starts](https://img.shields.io/github/stars/morphine009/CVE-2025-46157.svg) ![forks](https://img.shields.io/github/forks/morphine009/CVE-2025-46157.svg)


## CVE-2025-46041
 A stored cross-site scripting (XSS) vulnerability in Anchor CMS v0.12.7 allows attackers to inject malicious JavaScript via the page description field in the page creation interface (/admin/pages/add).

- [https://github.com/binneko/CVE-2025-46041](https://github.com/binneko/CVE-2025-46041) :  ![starts](https://img.shields.io/github/stars/binneko/CVE-2025-46041.svg) ![forks](https://img.shields.io/github/forks/binneko/CVE-2025-46041.svg)


## CVE-2025-45960
 Cross Site Scripting vulnerability in tawk.to Live Chat v.1.6.1 allows a remote attacker to execute arbitrary code via the web application stores and displays user-supplied input without proper input validation or encoding

- [https://github.com/pracharapol/CVE-2025-45960](https://github.com/pracharapol/CVE-2025-45960) :  ![starts](https://img.shields.io/github/stars/pracharapol/CVE-2025-45960.svg) ![forks](https://img.shields.io/github/forks/pracharapol/CVE-2025-45960.svg)


## CVE-2025-45620
 An issue in Aver PTC310UV2 v.0.1.0000.59 allows a remote attacker to obtain sensitive information via a crafted request

- [https://github.com/weedl/CVE-2025-45620](https://github.com/weedl/CVE-2025-45620) :  ![starts](https://img.shields.io/github/stars/weedl/CVE-2025-45620.svg) ![forks](https://img.shields.io/github/forks/weedl/CVE-2025-45620.svg)


## CVE-2025-45619
 An issue in Aver PTC310UV2 firmware v.0.1.0000.59 allows a remote attacker to execute arbitrary code via the SendAction function

- [https://github.com/weedl/CVE-2025-45619](https://github.com/weedl/CVE-2025-45619) :  ![starts](https://img.shields.io/github/stars/weedl/CVE-2025-45619.svg) ![forks](https://img.shields.io/github/forks/weedl/CVE-2025-45619.svg)


## CVE-2025-45467
 Unitree Go1 = Go1_2022_05_11 is vulnerable to Insecure Permissions as the firmware update functionality (via Wi-Fi/Ethernet) implements an insecure verification mechanism that solely relies on MD5 checksums for firmware integrity validation.

- [https://github.com/zgsnj123/CVE-2025-45467](https://github.com/zgsnj123/CVE-2025-45467) :  ![starts](https://img.shields.io/github/stars/zgsnj123/CVE-2025-45467.svg) ![forks](https://img.shields.io/github/forks/zgsnj123/CVE-2025-45467.svg)


## CVE-2025-45466
 Unitree Go1 = Go1_2022_05_11 is vulnerale to Incorrect Access Control due to authentication credentials being hardcoded in plaintext.

- [https://github.com/zgsnj123/CVE-2025-45466](https://github.com/zgsnj123/CVE-2025-45466) :  ![starts](https://img.shields.io/github/stars/zgsnj123/CVE-2025-45466.svg) ![forks](https://img.shields.io/github/forks/zgsnj123/CVE-2025-45466.svg)


## CVE-2025-44608
 CloudClassroom-PHP Project v1.0 was discovered to contain a SQL injection vulnerability via the viewid parameter.

- [https://github.com/mr-xmen786/CVE-2025-44608](https://github.com/mr-xmen786/CVE-2025-44608) :  ![starts](https://img.shields.io/github/stars/mr-xmen786/CVE-2025-44608.svg) ![forks](https://img.shields.io/github/forks/mr-xmen786/CVE-2025-44608.svg)


## CVE-2025-44203
 In HotelDruid 3.0.7, an unauthenticated attacker can exploit verbose SQL error messages on creadb.php before the 'create database' button is pressed. By sending malformed POST requests to this endpoint, the attacker may obtain the administrator username, password hash, and salt. In some cases, the attack results in a Denial of Service (DoS), preventing the administrator from logging in even with the correct credentials.

- [https://github.com/IvanT7D3/CVE-2025-44203](https://github.com/IvanT7D3/CVE-2025-44203) :  ![starts](https://img.shields.io/github/stars/IvanT7D3/CVE-2025-44203.svg) ![forks](https://img.shields.io/github/forks/IvanT7D3/CVE-2025-44203.svg)


## CVE-2025-40677
 SQL injection vulnerability in Summar Software´s Portal del Empleado. This vulnerability allows an attacker to retrieve, create, update, and delete the database by sending a POST request using the parameter “ctl00$ContentPlaceHolder1$filtroNombre” in “/MemberPages/quienesquien.aspx”.

- [https://github.com/PeterGabaldon/CVE-2025-40677](https://github.com/PeterGabaldon/CVE-2025-40677) :  ![starts](https://img.shields.io/github/stars/PeterGabaldon/CVE-2025-40677.svg) ![forks](https://img.shields.io/github/forks/PeterGabaldon/CVE-2025-40677.svg)


## CVE-2025-39507
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in NasaTheme Nasa Core allows PHP Local File Inclusion. This issue affects Nasa Core: from n/a through 6.3.2.

- [https://github.com/TheCyberFairy/cve-lfi-lab](https://github.com/TheCyberFairy/cve-lfi-lab) :  ![starts](https://img.shields.io/github/stars/TheCyberFairy/cve-lfi-lab.svg) ![forks](https://img.shields.io/github/forks/TheCyberFairy/cve-lfi-lab.svg)


## CVE-2025-37899
be in the smb2_sess_setup function which makes use of sess-user.

- [https://github.com/vett3x/SMB-LINUX-CVE-2025-37899](https://github.com/vett3x/SMB-LINUX-CVE-2025-37899) :  ![starts](https://img.shields.io/github/stars/vett3x/SMB-LINUX-CVE-2025-37899.svg) ![forks](https://img.shields.io/github/forks/vett3x/SMB-LINUX-CVE-2025-37899.svg)


## CVE-2025-36041
 IBM MQ Operator LTS 2.0.0 through 2.0.29, MQ Operator CD 3.0.0, 3.0.1, 3.1.0 through 3.1.3, 3.3.0, 3.4.0, 3.4.1, 3.5.0, 3.5.1 through 3.5.3, and MQ Operator SC2 3.2.0 through 3.2.12 Native HA CRR could be configured with a private key and chain other than the intended key which could disclose sensitive information or allow the attacker to perform unauthorized actions.

- [https://github.com/byteReaper77/CVE-2025-36041](https://github.com/byteReaper77/CVE-2025-36041) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-36041.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-36041.svg)


## CVE-2025-33053
 External control of file name or path in Internet Shortcut Files allows an unauthorized attacker to execute code over a network.

- [https://github.com/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept](https://github.com/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept.svg)
- [https://github.com/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept](https://github.com/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept) :  ![starts](https://img.shields.io/github/stars/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept.svg) ![forks](https://img.shields.io/github/forks/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept.svg)
- [https://github.com/TheTorjanCaptain/CVE-2025-33053-Checker-PoC](https://github.com/TheTorjanCaptain/CVE-2025-33053-Checker-PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2025-33053-Checker-PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2025-33053-Checker-PoC.svg)


## CVE-2025-32756
 A stack-based buffer overflow vulnerability [CWE-121] in Fortinet FortiVoice versions 7.2.0, 7.0.0 through 7.0.6, 6.4.0 through 6.4.10, FortiRecorder versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.5, 6.4.0 through 6.4.5, FortiMail versions 7.6.0 through 7.6.2, 7.4.0 through 7.4.4, 7.2.0 through 7.2.7, 7.0.0 through 7.0.8, FortiNDR versions 7.6.0, 7.4.0 through 7.4.7, 7.2.0 through 7.2.4, 7.0.0 through 7.0.6, FortiCamera versions 2.1.0 through 2.1.3, 2.0 all versions, 1.1 all versions, allows a remote unauthenticated attacker to execute arbitrary code or commands via sending HTTP requests with specially crafted hash cookie.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32756](https://github.com/B1ack4sh/Blackash-CVE-2025-32756) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32756.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32756.svg)
- [https://github.com/becrevex/CVE-2025-32756](https://github.com/becrevex/CVE-2025-32756) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2025-32756.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2025-32756.svg)
- [https://github.com/alm6no5/CVE-2025-32756-POC](https://github.com/alm6no5/CVE-2025-32756-POC) :  ![starts](https://img.shields.io/github/stars/alm6no5/CVE-2025-32756-POC.svg) ![forks](https://img.shields.io/github/forks/alm6no5/CVE-2025-32756-POC.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Yuri08loveElaina/CVE_2025_32433_exploit](https://github.com/Yuri08loveElaina/CVE_2025_32433_exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_32433_exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_32433_exploit.svg)
- [https://github.com/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit](https://github.com/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-32433](https://github.com/B1ack4sh/Blackash-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32433.svg)


## CVE-2025-31650
Users are recommended to upgrade to version 9.0.104, 10.1.40 or 11.0.6 which fix the issue.

- [https://github.com/assad12341/Dos-exploit-](https://github.com/assad12341/Dos-exploit-) :  ![starts](https://img.shields.io/github/stars/assad12341/Dos-exploit-.svg) ![forks](https://img.shields.io/github/forks/assad12341/Dos-exploit-.svg)
- [https://github.com/assad12341/DOS-exploit](https://github.com/assad12341/DOS-exploit) :  ![starts](https://img.shields.io/github/stars/assad12341/DOS-exploit.svg) ![forks](https://img.shields.io/github/forks/assad12341/DOS-exploit.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ibrahmsql/CVE-2025-31161](https://github.com/ibrahmsql/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2025-31161.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-31161](https://github.com/B1ack4sh/Blackash-CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-31161.svg)


## CVE-2025-31131
 YesWiki is a wiki system written in PHP. The squelette parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server. This vulnerability is fixed in 4.5.2.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-31131](https://github.com/B1ack4sh/Blackash-CVE-2025-31131) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-31131.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-31131.svg)


## CVE-2025-30712
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).   The supported version that is affected is 7.1.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle VM VirtualBox accessible data as well as  unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L).

- [https://github.com/jamesb5959/CVE-2025-30712-_PoC](https://github.com/jamesb5959/CVE-2025-30712-_PoC) :  ![starts](https://img.shields.io/github/stars/jamesb5959/CVE-2025-30712-_PoC.svg) ![forks](https://img.shields.io/github/forks/jamesb5959/CVE-2025-30712-_PoC.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/ThemeHackers/CVE-2025-30208](https://github.com/ThemeHackers/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-30208.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-30208](https://github.com/B1ack4sh/Blackash-CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-30208.svg)
- [https://github.com/HaGsec/CVE-2025-30208](https://github.com/HaGsec/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/HaGsec/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/HaGsec/CVE-2025-30208.svg)


## CVE-2025-29972
 Server-Side Request Forgery (SSRF) in Azure allows an authorized attacker to perform spoofing over a network.

- [https://github.com/TH-SecForge/CVE-2025-29972](https://github.com/TH-SecForge/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-29972.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/TH-SecForge/CVE-2025-29972](https://github.com/TH-SecForge/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-29972.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-29927](https://github.com/B1ack4sh/Blackash-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-29927.svg)
- [https://github.com/amitlttwo/Next.JS-CVE-2025-29927](https://github.com/amitlttwo/Next.JS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/amitlttwo/Next.JS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/Next.JS-CVE-2025-29927.svg)


## CVE-2025-29471
 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.

- [https://github.com/skraft9/CVE-2025-29471](https://github.com/skraft9/CVE-2025-29471) :  ![starts](https://img.shields.io/github/stars/skraft9/CVE-2025-29471.svg) ![forks](https://img.shields.io/github/forks/skraft9/CVE-2025-29471.svg)


## CVE-2025-27817
Since Apache Kafka 3.9.1/4.0.0, we have added a system property ("-Dorg.apache.kafka.sasl.oauthbearer.allowed.urls") to set the allowed urls in SASL JAAS configuration. In 3.9.1, it accepts all urls by default for backward compatibility. However in 4.0.0 and newer, the default value is empty list and users have to set the allowed urls explicitly.

- [https://github.com/kk12-30/CVE-2025-27817](https://github.com/kk12-30/CVE-2025-27817) :  ![starts](https://img.shields.io/github/stars/kk12-30/CVE-2025-27817.svg) ![forks](https://img.shields.io/github/forks/kk12-30/CVE-2025-27817.svg)


## CVE-2025-27580
 NIH BRICS (aka Biomedical Research Informatics Computing System) through 14.0.0-67 generates predictable tokens (that depend on username, time, and the fixed 7Dl9#dj- string) and thus allows unauthenticated users with a Common Access Card (CAC) to escalate privileges and compromise any account, including administrators.

- [https://github.com/TrustStackSecurity/CVE-2025-27580](https://github.com/TrustStackSecurity/CVE-2025-27580) :  ![starts](https://img.shields.io/github/stars/TrustStackSecurity/CVE-2025-27580.svg) ![forks](https://img.shields.io/github/forks/TrustStackSecurity/CVE-2025-27580.svg)


## CVE-2025-27558
 IEEE P802.11-REVme D1.1 through D7.0 allows FragAttacks against mesh networks. In mesh networks using Wi-Fi Protected Access (WPA, WPA2, or WPA3) or Wired Equivalent Privacy (WEP), an adversary can exploit this vulnerability to inject arbitrary frames towards devices that support receiving non-SSP A-MSDU frames. NOTE: this issue exists because of an incorrect fix for CVE-2020-24588. P802.11-REVme, as of early 2025, is a planned release of the 802.11 standard.

- [https://github.com/Atlas-ghostshell/CVE-2025-27558_Patching](https://github.com/Atlas-ghostshell/CVE-2025-27558_Patching) :  ![starts](https://img.shields.io/github/stars/Atlas-ghostshell/CVE-2025-27558_Patching.svg) ![forks](https://img.shields.io/github/forks/Atlas-ghostshell/CVE-2025-27558_Patching.svg)


## CVE-2025-27520
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version (v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server. It exists an unsafe code segment in serde.py. This vulnerability is fixed in 1.4.3.

- [https://github.com/amalpvatayam67/day09-bentoml-deser-lab](https://github.com/amalpvatayam67/day09-bentoml-deser-lab) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day09-bentoml-deser-lab.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day09-bentoml-deser-lab.svg)


## CVE-2025-27152
 axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if ⁠baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2.

- [https://github.com/davidblakecoe/axios-CVE-2025-27152-PoC](https://github.com/davidblakecoe/axios-CVE-2025-27152-PoC) :  ![starts](https://img.shields.io/github/stars/davidblakecoe/axios-CVE-2025-27152-PoC.svg) ![forks](https://img.shields.io/github/forks/davidblakecoe/axios-CVE-2025-27152-PoC.svg)


## CVE-2025-26909
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in John Darrel Hide My WP Ghost allows PHP Local File Inclusion.This issue affects Hide My WP Ghost: from n/a through 5.4.01.

- [https://github.com/issamjr/CVE-2025-26909-Scanner](https://github.com/issamjr/CVE-2025-26909-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-26909-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-26909-Scanner.svg)


## CVE-2025-26892
 Unrestricted Upload of File with Dangerous Type vulnerability in dkszone Celestial Aura allows Using Malicious Files.This issue affects Celestial Aura: from n/a through 2.2.

- [https://github.com/Nxploited/CVE-2025-26892](https://github.com/Nxploited/CVE-2025-26892) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-26892.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-26892.svg)


## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.

- [https://github.com/mrowkoob/CVE-2025-26466-msf](https://github.com/mrowkoob/CVE-2025-26466-msf) :  ![starts](https://img.shields.io/github/stars/mrowkoob/CVE-2025-26466-msf.svg) ![forks](https://img.shields.io/github/forks/mrowkoob/CVE-2025-26466-msf.svg)


## CVE-2025-26443
 In parseHtml of HtmlToSpannedParser.java, there is a possible way to install apps without allowing installation from unknown sources due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.

- [https://github.com/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443](https://github.com/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443) :  ![starts](https://img.shields.io/github/stars/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443.svg) ![forks](https://img.shields.io/github/forks/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443.svg)


## CVE-2025-26199
 CloudClassroom-PHP-Project v1.0 is affected by an insecure credential transmission vulnerability. The application transmits passwords over unencrypted HTTP during the login process, exposing sensitive credentials to potential interception by network-based attackers. A remote attacker with access to the same network (e.g., public Wi-Fi or compromised router) can capture login credentials via Man-in-the-Middle (MitM) techniques. If the attacker subsequently uses the credentials to log in and exploit administrative functions (e.g., file upload), this may lead to remote code execution depending on the environment.

- [https://github.com/tansique-17/CVE-2025-26199](https://github.com/tansique-17/CVE-2025-26199) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-26199.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-26199.svg)


## CVE-2025-26198
 CloudClassroom-PHP-Project v1.0 contains a critical SQL Injection vulnerability in the loginlinkadmin.php component. The application fails to sanitize user-supplied input in the admin login form before directly including it in SQL queries. This allows unauthenticated attackers to inject arbitrary SQL payloads and bypass authentication, gaining unauthorized administrative access. The vulnerability is triggered when an attacker supplies specially crafted input in the username field, such as ' OR '1'='1, leading to complete compromise of the login mechanism and potential exposure of sensitive backend data.

- [https://github.com/tansique-17/CVE-2025-26198](https://github.com/tansique-17/CVE-2025-26198) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-26198.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-26198.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/kityzed2003/CVE-2025-25257](https://github.com/kityzed2003/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/kityzed2003/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/kityzed2003/CVE-2025-25257.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/x1ongsec/CVE-2025-24813](https://github.com/x1ongsec/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/x1ongsec/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/x1ongsec/CVE-2025-24813.svg)


## CVE-2025-24514
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/KimJuhyeong95/cve-2025-24514](https://github.com/KimJuhyeong95/cve-2025-24514) :  ![starts](https://img.shields.io/github/stars/KimJuhyeong95/cve-2025-24514.svg) ![forks](https://img.shields.io/github/forks/KimJuhyeong95/cve-2025-24514.svg)


## CVE-2025-24252
 A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.4, tvOS 18.4, macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sonoma 14.7.5, iOS 18.4 and iPadOS 18.4, visionOS 2.4. An attacker on the local network may be able to corrupt process memory.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-24252](https://github.com/B1ack4sh/Blackash-CVE-2025-24252) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24252.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24252.svg)


## CVE-2025-24076
 Improper access control in Windows Cross Device Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/mbanyamer/CVE-2025-24076](https://github.com/mbanyamer/CVE-2025-24076) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-24076.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-24076.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/TH-SecForge/CVE-2025-24071](https://github.com/TH-SecForge/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-24071.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-24071](https://github.com/B1ack4sh/Blackash-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24071.svg)
- [https://github.com/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-](https://github.com/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-) :  ![starts](https://img.shields.io/github/stars/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-.svg) ![forks](https://img.shields.io/github/forks/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/Yuri08loveElaina/CVE-2025-24054_POC](https://github.com/Yuri08loveElaina/CVE-2025-24054_POC) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-24054_POC.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-24054_POC.svg)


## CVE-2025-24035
 Sensitive data storage in improperly locked memory in Windows Remote Desktop Services allows an unauthorized attacker to execute code over a network.

- [https://github.com/MSeymenD/cve-2025-24035-rds-websocket-dos-test](https://github.com/MSeymenD/cve-2025-24035-rds-websocket-dos-test) :  ![starts](https://img.shields.io/github/stars/MSeymenD/cve-2025-24035-rds-websocket-dos-test.svg) ![forks](https://img.shields.io/github/forks/MSeymenD/cve-2025-24035-rds-websocket-dos-test.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/rxerium/CVE-2025-24016](https://github.com/rxerium/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-24016.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-24016](https://github.com/B1ack4sh/Blackash-CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24016.svg)


## CVE-2025-23245
 NVIDIA vGPU software for Windows and Linux contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where it allows a guest to access global resources. A successful exploit of this vulnerability might lead to denial of service.

- [https://github.com/cydragLINUX/CVE-2025-23245655](https://github.com/cydragLINUX/CVE-2025-23245655) :  ![starts](https://img.shields.io/github/stars/cydragLINUX/CVE-2025-23245655.svg) ![forks](https://img.shields.io/github/forks/cydragLINUX/CVE-2025-23245655.svg)


## CVE-2025-22870
 Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to "*.example.com", a request to "[::1%25.example.com]:80` will incorrectly match and not be proxied.

- [https://github.com/JoshuaProvoste/CVE-2025-22870](https://github.com/JoshuaProvoste/CVE-2025-22870) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/CVE-2025-22870.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/CVE-2025-22870.svg)


## CVE-2025-21756
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

- [https://github.com/KuanKuanQAQ/cve-testing](https://github.com/KuanKuanQAQ/cve-testing) :  ![starts](https://img.shields.io/github/stars/KuanKuanQAQ/cve-testing.svg) ![forks](https://img.shields.io/github/forks/KuanKuanQAQ/cve-testing.svg)


## CVE-2025-21420
 Windows Disk Cleanup Tool Elevation of Privilege Vulnerability

- [https://github.com/moiz-2x/CVE-2025-21420_POC](https://github.com/moiz-2x/CVE-2025-21420_POC) :  ![starts](https://img.shields.io/github/stars/moiz-2x/CVE-2025-21420_POC.svg) ![forks](https://img.shields.io/github/forks/moiz-2x/CVE-2025-21420_POC.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/B1ack4sh/Blackash-CVE-2025-21333](https://github.com/B1ack4sh/Blackash-CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-21333.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/fy-poc/full-poc-CVE-2025_21298](https://github.com/fy-poc/full-poc-CVE-2025_21298) :  ![starts](https://img.shields.io/github/stars/fy-poc/full-poc-CVE-2025_21298.svg) ![forks](https://img.shields.io/github/forks/fy-poc/full-poc-CVE-2025_21298.svg)


## CVE-2025-20265
Note: For this vulnerability to be exploited, Cisco Secure FMC Software must be configured for RADIUS authentication for the web-based management interface, SSH management, or both.

- [https://github.com/saruman9/cve_2025_20265](https://github.com/saruman9/cve_2025_20265) :  ![starts](https://img.shields.io/github/stars/saruman9/cve_2025_20265.svg) ![forks](https://img.shields.io/github/forks/saruman9/cve_2025_20265.svg)


## CVE-2025-20125
Note:&nbsp;To successfully exploit this vulnerability, the attacker must have valid read-only administrative credentials. In a single-node deployment, new devices will not be able to authenticate during the reload time.

- [https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125](https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg)


## CVE-2025-20124
Note:&nbsp;To successfully exploit this vulnerability, the attacker must have valid read-only administrative credentials. In a single-node deployment, new devices will not be able to authenticate during the reload time.

- [https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125](https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg)


## CVE-2025-9776
 The CatFolders – Tame Your WordPress Media Library by Category plugin for WordPress is vulnerable to time-based SQL Injection via the CSV Import contents in all versions up to, and including, 2.5.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Author-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/SnailSploit/CVE-2025-9776](https://github.com/SnailSploit/CVE-2025-9776) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2025-9776.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2025-9776.svg)


## CVE-2025-7775
CR virtual server with type HDX

- [https://github.com/Lakiya673/CVE-2025-5777](https://github.com/Lakiya673/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Lakiya673/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Lakiya673/CVE-2025-5777.svg)


## CVE-2025-7431
 The Knowledge Base plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin slug setting in all versions up to, and including, 2.3.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/NagisaYumaa/CVE-2025-7431](https://github.com/NagisaYumaa/CVE-2025-7431) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-7431.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-7431.svg)


## CVE-2025-6586
 The Download Plugin plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the dpwap_plugin_locInstall function in all versions up to, and including, 2.2.8. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-6586](https://github.com/d0n601/CVE-2025-6586) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6586.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6586.svg)


## CVE-2025-6543
 Memory overflow vulnerability leading to unintended control flow and Denial of Service in NetScaler ADC and NetScaler Gateway when configured as Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/grupooruss/Citrix-cve-2025-6543](https://github.com/grupooruss/Citrix-cve-2025-6543) :  ![starts](https://img.shields.io/github/stars/grupooruss/Citrix-cve-2025-6543.svg) ![forks](https://img.shields.io/github/forks/grupooruss/Citrix-cve-2025-6543.svg)
- [https://github.com/Lakiya673/CVE-2025-5777](https://github.com/Lakiya673/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Lakiya673/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Lakiya673/CVE-2025-5777.svg)


## CVE-2025-6335
 A vulnerability was found in DedeCMS up to 5.7.2 and classified as critical. This issue affects some unknown processing of the file /include/dedetag.class.php of the component Template Handler. The manipulation of the argument notes leads to command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/jujubooom/CVE-2025-6335](https://github.com/jujubooom/CVE-2025-6335) :  ![starts](https://img.shields.io/github/stars/jujubooom/CVE-2025-6335.svg) ![forks](https://img.shields.io/github/forks/jujubooom/CVE-2025-6335.svg)


## CVE-2025-6220
 The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'save_options' function in all versions up to, and including, 3.5.12. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-6220](https://github.com/d0n601/CVE-2025-6220) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6220.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6220.svg)


## CVE-2025-6169
 The WIMP website co-construction management platform from HAMASTAR Technology has a SQL Injection vulnerability, allowing unauthenticated remote attackers to inject arbitrary SQL commands to read, modify, and delete database contents.

- [https://github.com/Yuri08loveElaina/CVE_2025_6169](https://github.com/Yuri08loveElaina/CVE_2025_6169) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6169.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6169.svg)


## CVE-2025-6083
 In ExtremeCloud Universal ZTNA, a syntax error in the 'searchKeyword' condition caused queries to bypass the owner_id filter. This issue may allow users to search data across the entire table instead of being restricted to their specific owner_id.

- [https://github.com/Yuri08loveElaina/CVE_2025_6083](https://github.com/Yuri08loveElaina/CVE_2025_6083) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6083.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6083.svg)


## CVE-2025-6070
 The Restrict File Access plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and including, 1.1.2 via the output() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/Yuri08loveElaina/CVE_2025_6070](https://github.com/Yuri08loveElaina/CVE_2025_6070) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6070.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6070.svg)


## CVE-2025-6065
 The Image Resizer On The Fly plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'delete' task in all versions up to, and including, 1.1. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).

- [https://github.com/Yuri08loveElaina/CVE_2025_6065](https://github.com/Yuri08loveElaina/CVE_2025_6065) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6065.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6065.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/And-oss/CVE-2025-6019-exploit](https://github.com/And-oss/CVE-2025-6019-exploit) :  ![starts](https://img.shields.io/github/stars/And-oss/CVE-2025-6019-exploit.svg) ![forks](https://img.shields.io/github/forks/And-oss/CVE-2025-6019-exploit.svg)


## CVE-2025-5964
 A path traversal issue in the API endpoint in M-Files Server before version 25.6.14925.0 allows an authenticated user to read files in the server.

- [https://github.com/byteReaper77/CVE-2025-5964-](https://github.com/byteReaper77/CVE-2025-5964-) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-5964-.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-5964-.svg)


## CVE-2025-5961
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'wpvivid_upload_import_files' function in all versions up to, and including, 0.9.116. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: Uploaded files are only accessible on WordPress instances running on the NGINX web server as the existing .htaccess within the target file upload folder prevents access on Apache servers.

- [https://github.com/d0n601/CVE-2025-5961](https://github.com/d0n601/CVE-2025-5961) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-5961.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-5961.svg)


## CVE-2025-5840
 A vulnerability, which was classified as critical, was found in SourceCodester Client Database Management System 1.0. This affects an unknown part of the file /user_update_customer_order.php. The manipulation of the argument uploaded_file leads to unrestricted upload. It is possible to initiate the attack remotely.

- [https://github.com/haxerr9/CVE-2025-5840](https://github.com/haxerr9/CVE-2025-5840) :  ![starts](https://img.shields.io/github/stars/haxerr9/CVE-2025-5840.svg) ![forks](https://img.shields.io/github/forks/haxerr9/CVE-2025-5840.svg)


## CVE-2025-5815
 The Traffic Monitor plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the tfcm_maybe_set_bot_flags() function in all versions up to, and including, 3.2.2. This makes it possible for unauthenticated attackers to disabled bot logging.

- [https://github.com/RootHarpy/CVE-2025-5815-Nuclei-Template](https://github.com/RootHarpy/CVE-2025-5815-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-5815-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-5815-Nuclei-Template.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/Lakiya673/CVE-2025-5777](https://github.com/Lakiya673/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Lakiya673/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Lakiya673/CVE-2025-5777.svg)


## CVE-2025-5752
 The Vertical scroll image slideshow gallery plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘width’ parameter in all versions up to, and including, 11.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/songqb-xx/CVE-2025-57529](https://github.com/songqb-xx/CVE-2025-57529) :  ![starts](https://img.shields.io/github/stars/songqb-xx/CVE-2025-57529.svg) ![forks](https://img.shields.io/github/forks/songqb-xx/CVE-2025-57529.svg)


## CVE-2025-5701
 The HyperComments plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the hc_request_handler function in all versions up to, and including, 1.2.2. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.

- [https://github.com/RandomRobbieBF/CVE-2025-5701](https://github.com/RandomRobbieBF/CVE-2025-5701) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-5701.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-5701.svg)


## CVE-2025-5640
 A vulnerability was found in PX4-Autopilot 1.12.3. It has been classified as problematic. This affects the function MavlinkReceiver::handle_message_trajectory_representation_waypoints of the file mavlink_receiver.cpp of the component TRAJECTORY_REPRESENTATION_WAYPOINTS Message Handler. The manipulation leads to stack-based buffer overflow. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used.

- [https://github.com/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-](https://github.com/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-.svg)


## CVE-2025-5631
 A vulnerability was found in code-projects/anirbandutta9 Content Management System and News-Buzz 1.0. It has been classified as critical. Affected is an unknown function of the file /publicposts.php. The manipulation of the argument post leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/wrathfulDiety/CVE-2025-56311](https://github.com/wrathfulDiety/CVE-2025-56311) :  ![starts](https://img.shields.io/github/stars/wrathfulDiety/CVE-2025-56311.svg) ![forks](https://img.shields.io/github/forks/wrathfulDiety/CVE-2025-56311.svg)


## CVE-2025-5601
 Column handling crashes in Wireshark 4.4.0 to 4.4.6 and 4.2.0 to 4.2.12 allows denial of service via packet injection or crafted capture file

- [https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019](https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019) :  ![starts](https://img.shields.io/github/stars/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019.svg) ![forks](https://img.shields.io/github/forks/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/itsShotgun/chrome_v8_cve_checker](https://github.com/itsShotgun/chrome_v8_cve_checker) :  ![starts](https://img.shields.io/github/stars/itsShotgun/chrome_v8_cve_checker.svg) ![forks](https://img.shields.io/github/forks/itsShotgun/chrome_v8_cve_checker.svg)


## CVE-2025-5309
 The chat feature within Remote Support (RS) and Privileged Remote Access (PRA) is vulnerable to a Server-Side Template Injection vulnerability which can lead to remote code execution.

- [https://github.com/issamjr/CVE-2025-5309-Scanner](https://github.com/issamjr/CVE-2025-5309-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-5309-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-5309-Scanner.svg)


## CVE-2025-5288
 The REST API | Custom API Generator For Cross Platform And Import Export In WP plugin for WordPress is vulnerable to Privilege Escalation due to a missing capability check on the process_handler() function in versions 1.0.0 to 2.0.3. This makes it possible for unauthenticated attackers to POST an arbitrary import_api URL, import specially crafted JSON, and thereby create a new user with full Administrator privileges.

- [https://github.com/Nxploited/CVE-2025-5288](https://github.com/Nxploited/CVE-2025-5288) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5288.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5288.svg)


## CVE-2025-5287
 The Likes and Dislikes Plugin plugin for WordPress is vulnerable to SQL Injection via the 'post' parameter in all versions up to, and including, 1.0.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2025-5287](https://github.com/RandomRobbieBF/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-5287.svg)
- [https://github.com/RootHarpy/CVE-2025-5287](https://github.com/RootHarpy/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-5287.svg)


## CVE-2025-5222
 A stack buffer overflow was found in Internationl components for unicode (ICU ). While running the genrb binary, the 'subtag' struct overflowed at the SRBRoot::addTag function. This issue may lead to memory corruption and local arbitrary code execution.

- [https://github.com/berkley4/icu-74-debian](https://github.com/berkley4/icu-74-debian) :  ![starts](https://img.shields.io/github/stars/berkley4/icu-74-debian.svg) ![forks](https://img.shields.io/github/forks/berkley4/icu-74-debian.svg)


## CVE-2025-5104
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/0xMesh-X/CVE-2025-51046](https://github.com/0xMesh-X/CVE-2025-51046) :  ![starts](https://img.shields.io/github/stars/0xMesh-X/CVE-2025-51046.svg) ![forks](https://img.shields.io/github/forks/0xMesh-X/CVE-2025-51046.svg)


## CVE-2025-5054
When handling a crash, the function `_check_global_pid_and_forward`, which detects if the crashing process resided in a container, was being called before `consistency_checks`, which attempts to detect if the crashing process had been replaced. Because of this, if a process crashed and was quickly replaced with a containerized one, apport could be made to forward the core dump to the container, potentially leaking sensitive information. `consistency_checks` is now being called before `_check_global_pid_and_forward`. Additionally, given that the PID-reuse race condition cannot be reliably detected from userspace alone, crashes are only forwarded to containers if the kernel provided a pidfd, or if the crashing process was unprivileged (i.e., if dump mode == 1).

- [https://github.com/daryllundy/cve-2025-5054](https://github.com/daryllundy/cve-2025-5054) :  ![starts](https://img.shields.io/github/stars/daryllundy/cve-2025-5054.svg) ![forks](https://img.shields.io/github/forks/daryllundy/cve-2025-5054.svg)


## CVE-2025-4601
 The "RH - Real Estate WordPress Theme" theme for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.4.0. This is due to the theme not properly restricting user roles that can be updated as part of the inspiry_update_profile() function. This makes it possible for authenticated attackers, with subscriber-level access and above, to set their role to that of an administrator. The vulnerability was partially patched in version 4.4.0, and fully patched in version 4.4.1.

- [https://github.com/Yucaerin/CVE-2025-4601](https://github.com/Yucaerin/CVE-2025-4601) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4601.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4601.svg)


## CVE-2025-4571
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to unauthorized view and modification of data due to an insufficient capability check on the permissionsCheck functions in all versions up to, and including, 4.3.0. This makes it possible for authenticated attackers, with Contributor-level access and above, to view or delete fundraising campaigns, view donors' data, modify campaign events, etc.

- [https://github.com/partywavesec/CVE-2025-45710](https://github.com/partywavesec/CVE-2025-45710) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2025-45710.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2025-45710.svg)


## CVE-2025-4334
 The Simple User Registration plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3. This is due to insufficient restrictions on user meta values that can be supplied during registration. This makes it possible for unauthenticated attackers to register as an administrator.

- [https://github.com/Nxploited/CVE-2025-4334](https://github.com/Nxploited/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-4334.svg)


## CVE-2025-4322
 The Motors theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 5.6.67. This is due to the theme not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user passwords, including those of administrators, and leverage that to gain access to their account.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-4322](https://github.com/B1ack4sh/Blackash-CVE-2025-4322) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4322.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4322.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/punitdarji/Grafana-cve-2025-4123](https://github.com/punitdarji/Grafana-cve-2025-4123) :  ![starts](https://img.shields.io/github/stars/punitdarji/Grafana-cve-2025-4123.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Grafana-cve-2025-4123.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-4123](https://github.com/B1ack4sh/Blackash-CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4123.svg)
- [https://github.com/DesDoTvl/CVE-2025-4123grafana](https://github.com/DesDoTvl/CVE-2025-4123grafana) :  ![starts](https://img.shields.io/github/stars/DesDoTvl/CVE-2025-4123grafana.svg) ![forks](https://img.shields.io/github/forks/DesDoTvl/CVE-2025-4123grafana.svg)


## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.

- [https://github.com/Professor6T9/CVE-2025-3515](https://github.com/Professor6T9/CVE-2025-3515) :  ![starts](https://img.shields.io/github/stars/Professor6T9/CVE-2025-3515.svg) ![forks](https://img.shields.io/github/forks/Professor6T9/CVE-2025-3515.svg)


## CVE-2025-3248
code.

- [https://github.com/ynsmroztas/CVE-2025-3248-Langflow-RCE](https://github.com/ynsmroztas/CVE-2025-3248-Langflow-RCE) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/CVE-2025-3248-Langflow-RCE.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/CVE-2025-3248-Langflow-RCE.svg)
- [https://github.com/0-d3y/langflow-rce-exploit](https://github.com/0-d3y/langflow-rce-exploit) :  ![starts](https://img.shields.io/github/stars/0-d3y/langflow-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/0-d3y/langflow-rce-exploit.svg)
- [https://github.com/dennisec/Mass-CVE-2025-3248](https://github.com/dennisec/Mass-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/dennisec/Mass-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/dennisec/Mass-CVE-2025-3248.svg)
- [https://github.com/issamjr/CVE-2025-3248-Scanner](https://github.com/issamjr/CVE-2025-3248-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-3248-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-3248-Scanner.svg)
- [https://github.com/zapstiko/CVE-2025-3248](https://github.com/zapstiko/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/zapstiko/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/zapstiko/CVE-2025-3248.svg)
- [https://github.com/imbas007/CVE-2025-3248](https://github.com/imbas007/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-3248.svg)
- [https://github.com/dennisec/CVE-2025-3248](https://github.com/dennisec/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2025-3248.svg)
- [https://github.com/0xgh057r3c0n/CVE-2025-3248](https://github.com/0xgh057r3c0n/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-3248.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-3248](https://github.com/B1ack4sh/Blackash-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-3248.svg)
- [https://github.com/ill-deed/Langflow-CVE-2025-3248-Multi-target](https://github.com/ill-deed/Langflow-CVE-2025-3248-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/Langflow-CVE-2025-3248-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/Langflow-CVE-2025-3248-Multi-target.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/baribut/CVE-2025-3102](https://github.com/baribut/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/baribut/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/baribut/CVE-2025-3102.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/byteReaper77/CVE-2025-2783](https://github.com/byteReaper77/CVE-2025-2783) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-2783.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-2783.svg)


## CVE-2025-2539
 The File Away plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the ajax() function in all versions up to, and including, 3.9.9.0.1. This makes it possible for unauthenticated attackers, leveraging the use of a reversible weak algorithm,  to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/Yucaerin/CVE-2025-2539](https://github.com/Yucaerin/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2539.svg)
- [https://github.com/d4rkh0rse/CVE-2025-2539](https://github.com/d4rkh0rse/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/d4rkh0rse/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/d4rkh0rse/CVE-2025-2539.svg)


## CVE-2025-2135
 Type Confusion in V8 in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/sangnguyenthien/CVE-2025-2135](https://github.com/sangnguyenthien/CVE-2025-2135) :  ![starts](https://img.shields.io/github/stars/sangnguyenthien/CVE-2025-2135.svg) ![forks](https://img.shields.io/github/forks/sangnguyenthien/CVE-2025-2135.svg)


## CVE-2025-2082
The specific flaw exists within the VCSEC module. By manipulating the certificate response sent from the Tire Pressure Monitoring System (TPMS), an attacker can trigger an integer overflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the VCSEC module and send arbitrary messages to the vehicle CAN bus. Was ZDI-CAN-23800.

- [https://github.com/Burak1320demiroz/cve-2025-2082](https://github.com/Burak1320demiroz/cve-2025-2082) :  ![starts](https://img.shields.io/github/stars/Burak1320demiroz/cve-2025-2082.svg) ![forks](https://img.shields.io/github/forks/Burak1320demiroz/cve-2025-2082.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-1974](https://github.com/B1ack4sh/Blackash-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-1974.svg)


## CVE-2025-1793
 Multiple vector store integrations in run-llama/llama_index version v0.12.21 have SQL injection vulnerabilities. These vulnerabilities allow an attacker to read and write data using SQL, potentially leading to unauthorized access to data of other users depending on the usage of the llama-index library in a web application.

- [https://github.com/Usama-Figueira/-CVE-2025-1793-poc](https://github.com/Usama-Figueira/-CVE-2025-1793-poc) :  ![starts](https://img.shields.io/github/stars/Usama-Figueira/-CVE-2025-1793-poc.svg) ![forks](https://img.shields.io/github/forks/Usama-Figueira/-CVE-2025-1793-poc.svg)


## CVE-2025-1718
 An authenticated user with file access privilege via FTP access can cause the Relion 670/650 and SAM600-IO series device to reboot due to improper disk space management.

- [https://github.com/issamjr/CVE-2025-1718-Scanner](https://github.com/issamjr/CVE-2025-1718-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-1718-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-1718-Scanner.svg)


## CVE-2025-1562
 The Recover WooCommerce Cart Abandonment, Newsletter, Email Marketing, Marketing Automation By FunnelKit plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the install_or_activate_addon_plugins() function and a weak nonce hash in all versions up to, and including, 3.5.3. This makes it possible for unauthenticated attackers to install arbitrary plugins on the site that can be leveraged to further infect a vulnerable site.

- [https://github.com/gmh5225/CVE-2025-1562](https://github.com/gmh5225/CVE-2025-1562) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-1562.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-1562.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-1094](https://github.com/B1ack4sh/Blackash-CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-1094.svg)
- [https://github.com/aninfosec/CVE-2025-1094](https://github.com/aninfosec/CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/aninfosec/CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/aninfosec/CVE-2025-1094.svg)


## CVE-2025-1058
inoperable when malicious firmware is downloaded.

- [https://github.com/callinston/CVE-2025-10585](https://github.com/callinston/CVE-2025-10585) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-10585.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-10585.svg)


## CVE-2025-0411
The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.

- [https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC](https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-0282](https://github.com/B1ack4sh/Blackash-CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-0282.svg)


## CVE-2025-0133
For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.

- [https://github.com/wiseep/CVE-2025-0133](https://github.com/wiseep/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/wiseep/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/wiseep/CVE-2025-0133.svg)


## CVE-2025-0108
This issue does not affect Cloud NGFW or Prisma Access software.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-0108](https://github.com/B1ack4sh/Blackash-CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-0108.svg)


## CVE-2024-57378
 Wazuh SIEM version 4.8.2 is affected by a broken access control vulnerability. This issue allows the unauthorized creation of internal users without assigning any existing user role, potentially leading to privilege escalation or unauthorized access to sensitive resources.

- [https://github.com/rxerium/CVE-2024-57378](https://github.com/rxerium/CVE-2024-57378) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-57378.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-57378.svg)


## CVE-2024-55890
 D-Tale is a visualizer for pandas data structures. Prior to version 3.16.1, users hosting D-Tale publicly can be vulnerable to remote code execution allowing attackers to run malicious code on the server. Users should upgrade to version 3.16.1 where the `update-settings` endpoint blocks the ability for users to update the `enable_custom_filters` flag. The only workaround for versions earlier than 3.16.1 is to only host D-Tale to trusted users.

- [https://github.com/samh4cks/CVE-2024-55890](https://github.com/samh4cks/CVE-2024-55890) :  ![starts](https://img.shields.io/github/stars/samh4cks/CVE-2024-55890.svg) ![forks](https://img.shields.io/github/forks/samh4cks/CVE-2024-55890.svg)


## CVE-2024-54772
 An issue was discovered in the Winbox service of MikroTik RouterOS long-term release v6.43.13 through v6.49.13 and stable v6.43 through v7.17.2. A patch is available in the stable release v6.49.18. A discrepancy in response size between connection attempts made with a valid username and those with an invalid username allows attackers to enumerate for valid accounts.

- [https://github.com/Seven11Eleven/CVE-2024-54772](https://github.com/Seven11Eleven/CVE-2024-54772) :  ![starts](https://img.shields.io/github/stars/Seven11Eleven/CVE-2024-54772.svg) ![forks](https://img.shields.io/github/forks/Seven11Eleven/CVE-2024-54772.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/BwithE/CVE-2024-51482](https://github.com/BwithE/CVE-2024-51482) :  ![starts](https://img.shields.io/github/stars/BwithE/CVE-2024-51482.svg) ![forks](https://img.shields.io/github/forks/BwithE/CVE-2024-51482.svg)


## CVE-2024-50562
 An Insufficient Session Expiration vulnerability [CWE-613] in FortiOS SSL-VPN version 7.6.0, version 7.4.6 and below, version 7.2.10 and below, 7.0 all versions, 6.4 all versions may allow an attacker in possession of a cookie used to log in the SSL-VPN portal to log in again, although the session has expired or was logged out.

- [https://github.com/Shahid-BugB/fortinet-cve-2024-50562](https://github.com/Shahid-BugB/fortinet-cve-2024-50562) :  ![starts](https://img.shields.io/github/stars/Shahid-BugB/fortinet-cve-2024-50562.svg) ![forks](https://img.shields.io/github/forks/Shahid-BugB/fortinet-cve-2024-50562.svg)


## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/Yuri08loveElaina/CVE-2024-50379](https://github.com/Yuri08loveElaina/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2024-50379.svg)
- [https://github.com/Yuri08loveElaina/CVE-2024-50379-POC](https://github.com/Yuri08loveElaina/CVE-2024-50379-POC) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2024-50379-POC.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2024-50379-POC.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/onixgod/SOC335-Event-ID-313-CVE-2024-49138-Exploitation-Detected--Lest-Defend-Writeup](https://github.com/onixgod/SOC335-Event-ID-313-CVE-2024-49138-Exploitation-Detected--Lest-Defend-Writeup) :  ![starts](https://img.shields.io/github/stars/onixgod/SOC335-Event-ID-313-CVE-2024-49138-Exploitation-Detected--Lest-Defend-Writeup.svg) ![forks](https://img.shields.io/github/forks/onixgod/SOC335-Event-ID-313-CVE-2024-49138-Exploitation-Detected--Lest-Defend-Writeup.svg)


## CVE-2024-43917
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in TemplateInvaders TI WooCommerce Wishlist allows SQL Injection.This issue affects TI WooCommerce Wishlist: from n/a through 2.8.2.

- [https://github.com/sug4r-wr41th/CVE-2024-43917](https://github.com/sug4r-wr41th/CVE-2024-43917) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2024-43917.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2024-43917.svg)


## CVE-2024-43570
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/jayesther/KTM_POCS](https://github.com/jayesther/KTM_POCS) :  ![starts](https://img.shields.io/github/stars/jayesther/KTM_POCS.svg) ![forks](https://img.shields.io/github/forks/jayesther/KTM_POCS.svg)


## CVE-2024-43535
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/jayesther/KTM_POCS](https://github.com/jayesther/KTM_POCS) :  ![starts](https://img.shields.io/github/stars/jayesther/KTM_POCS.svg) ![forks](https://img.shields.io/github/forks/jayesther/KTM_POCS.svg)


## CVE-2024-42049
 TightVNC (Server for Windows) before 2.8.84 allows attackers to connect to the control pipe via a network connection.

- [https://github.com/zeved/CVE-2024-42049-PoC](https://github.com/zeved/CVE-2024-42049-PoC) :  ![starts](https://img.shields.io/github/stars/zeved/CVE-2024-42049-PoC.svg) ![forks](https://img.shields.io/github/forks/zeved/CVE-2024-42049-PoC.svg)


## CVE-2024-41817
 ImageMagick is a free and open-source software suite, used for editing and manipulating digital images. The `AppImage` version `ImageMagick` might use an empty path when setting `MAGICK_CONFIGURE_PATH` and `LD_LIBRARY_PATH` environment variables while executing, which might lead to arbitrary code execution by loading malicious configuration files or shared libraries in the current working directory while executing `ImageMagick`. The vulnerability is fixed in 7.11-36.

- [https://github.com/maikneysm/AutoPwn-Titanic.htb](https://github.com/maikneysm/AutoPwn-Titanic.htb) :  ![starts](https://img.shields.io/github/stars/maikneysm/AutoPwn-Titanic.htb.svg) ![forks](https://img.shields.io/github/forks/maikneysm/AutoPwn-Titanic.htb.svg)


## CVE-2024-40898
Users are recommended to upgrade to version 2.4.62 which fixes this issue. 

- [https://github.com/anilpatel199n/CVE-2024-40898](https://github.com/anilpatel199n/CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/anilpatel199n/CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/anilpatel199n/CVE-2024-40898.svg)


## CVE-2024-40453
 squirrellyjs squirrelly v9.0.0 and fixed in v.9.0.1 was discovered to contain a code injection vulnerability via the component options.varName.

- [https://github.com/BwithE/CVE-2024-40453](https://github.com/BwithE/CVE-2024-40453) :  ![starts](https://img.shields.io/github/stars/BwithE/CVE-2024-40453.svg) ![forks](https://img.shields.io/github/forks/BwithE/CVE-2024-40453.svg)


## CVE-2024-38819
 Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is running.

- [https://github.com/vishalnoza/CVE-2024-38819-POC2](https://github.com/vishalnoza/CVE-2024-38819-POC2) :  ![starts](https://img.shields.io/github/stars/vishalnoza/CVE-2024-38819-POC2.svg) ![forks](https://img.shields.io/github/forks/vishalnoza/CVE-2024-38819-POC2.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/O-Carneiro/cve_2024_32002_hook](https://github.com/O-Carneiro/cve_2024_32002_hook) :  ![starts](https://img.shields.io/github/stars/O-Carneiro/cve_2024_32002_hook.svg) ![forks](https://img.shields.io/github/forks/O-Carneiro/cve_2024_32002_hook.svg)
- [https://github.com/O-Carneiro/cve_2024_32002_rce](https://github.com/O-Carneiro/cve_2024_32002_rce) :  ![starts](https://img.shields.io/github/stars/O-Carneiro/cve_2024_32002_rce.svg) ![forks](https://img.shields.io/github/forks/O-Carneiro/cve_2024_32002_rce.svg)


## CVE-2024-28995
SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.    

- [https://github.com/ibrahmsql/CVE-2024-28995](https://github.com/ibrahmsql/CVE-2024-28995) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-28995.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-28995.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/CyberBibs/Event-ID-263-Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-](https://github.com/CyberBibs/Event-ID-263-Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-) :  ![starts](https://img.shields.io/github/stars/CyberBibs/Event-ID-263-Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-.svg) ![forks](https://img.shields.io/github/forks/CyberBibs/Event-ID-263-Arbitrary-File-Read-on-Checkpoint-Security-Gateway-CVE-2024-24919-.svg)


## CVE-2024-22371
Users are recommended to upgrade to version 3.21.4, 3.22.1, 4.0.4 or 4.4.0, which fixes the issue.

- [https://github.com/vishalborkar7/POC_for_-CVE-2024-22371](https://github.com/vishalborkar7/POC_for_-CVE-2024-22371) :  ![starts](https://img.shields.io/github/stars/vishalborkar7/POC_for_-CVE-2024-22371.svg) ![forks](https://img.shields.io/github/forks/vishalborkar7/POC_for_-CVE-2024-22371.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/yass2400012/Email-exploit-Moniker-Link-CVE-2024-21413-](https://github.com/yass2400012/Email-exploit-Moniker-Link-CVE-2024-21413-) :  ![starts](https://img.shields.io/github/stars/yass2400012/Email-exploit-Moniker-Link-CVE-2024-21413-.svg) ![forks](https://img.shields.io/github/forks/yass2400012/Email-exploit-Moniker-Link-CVE-2024-21413-.svg)


## CVE-2024-21006
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/d3fudd/CVE-2024-21006_POC](https://github.com/d3fudd/CVE-2024-21006_POC) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2024-21006_POC.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2024-21006_POC.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/ademto/wordpress-cve-2024-10924-pentest](https://github.com/ademto/wordpress-cve-2024-10924-pentest) :  ![starts](https://img.shields.io/github/stars/ademto/wordpress-cve-2024-10924-pentest.svg) ![forks](https://img.shields.io/github/forks/ademto/wordpress-cve-2024-10924-pentest.svg)


## CVE-2024-10914
 A vulnerability was found in D-Link DNS-320, DNS-320LW, DNS-325 and DNS-340L up to 20241028. It has been declared as critical. Affected by this vulnerability is the function cgi_user_add of the file /cgi-bin/account_mgr.cgi?cmd=cgi_user_add. The manipulation of the argument name leads to os command injection. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used.

- [https://github.com/TH-SecForge/CVE-2024-10914](https://github.com/TH-SecForge/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2024-10914.svg)


## CVE-2024-9796
 The WP-Advanced-Search WordPress plugin before 3.3.9.2 does not sanitize and escape the t parameter before using it in a SQL statement, allowing unauthenticated users to perform SQL injection attacks

- [https://github.com/BwithE/CVE-2024-9796](https://github.com/BwithE/CVE-2024-9796) :  ![starts](https://img.shields.io/github/stars/BwithE/CVE-2024-9796.svg) ![forks](https://img.shields.io/github/forks/BwithE/CVE-2024-9796.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/Exerrdev/CVE-2024-9264-Fixed](https://github.com/Exerrdev/CVE-2024-9264-Fixed) :  ![starts](https://img.shields.io/github/stars/Exerrdev/CVE-2024-9264-Fixed.svg) ![forks](https://img.shields.io/github/forks/Exerrdev/CVE-2024-9264-Fixed.svg)


## CVE-2024-8232
authentication.

- [https://github.com/z3usx01/CVE-2024-8232](https://github.com/z3usx01/CVE-2024-8232) :  ![starts](https://img.shields.io/github/stars/z3usx01/CVE-2024-8232.svg) ![forks](https://img.shields.io/github/forks/z3usx01/CVE-2024-8232.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/ibrahmsql/CVE-2024-4577](https://github.com/ibrahmsql/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-4577.svg)
- [https://github.com/byteReaper77/CVE-2024-4577](https://github.com/byteReaper77/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2024-4577.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/CyberBibs/SOC274---Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400-](https://github.com/CyberBibs/SOC274---Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400-) :  ![starts](https://img.shields.io/github/stars/CyberBibs/SOC274---Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400-.svg) ![forks](https://img.shields.io/github/forks/CyberBibs/SOC274---Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400-.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/24Owais/threat-intel-cve-2024-3094](https://github.com/24Owais/threat-intel-cve-2024-3094) :  ![starts](https://img.shields.io/github/stars/24Owais/threat-intel-cve-2024-3094.svg) ![forks](https://img.shields.io/github/forks/24Owais/threat-intel-cve-2024-3094.svg)
- [https://github.com/Dermot-lab/TryHack](https://github.com/Dermot-lab/TryHack) :  ![starts](https://img.shields.io/github/stars/Dermot-lab/TryHack.svg) ![forks](https://img.shields.io/github/forks/Dermot-lab/TryHack.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/ibrahmsql/CVE-2024-0204](https://github.com/ibrahmsql/CVE-2024-0204) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-0204.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-0204.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/hunntr/CVE-2023-46818](https://github.com/hunntr/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/hunntr/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/hunntr/CVE-2023-46818.svg)
- [https://github.com/SyFi/CVE-2023-46818](https://github.com/SyFi/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2023-46818.svg)


## CVE-2023-37273
 Auto-GPT is an experimental open-source application showcasing the capabilities of the GPT-4 language model. Running Auto-GPT version prior to 0.4.3 by cloning the git repo and executing `docker compose run auto-gpt` in the repo root uses a different docker-compose.yml file from the one suggested in the official docker set up instructions. The docker-compose.yml file located in the repo root mounts itself into the docker container without write protection. This means that if malicious custom python code is executed via the `execute_python_file` and `execute_python_code` commands, it can overwrite the docker-compose.yml file and abuse it to gain control of the host system the next time Auto-GPT is started. The issue has been patched in version 0.4.3.

- [https://github.com/gdesantis01/instructions-summarizing](https://github.com/gdesantis01/instructions-summarizing) :  ![starts](https://img.shields.io/github/stars/gdesantis01/instructions-summarizing.svg) ![forks](https://img.shields.io/github/forks/gdesantis01/instructions-summarizing.svg)


## CVE-2023-33538
 TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a command injection vulnerability via the component /userRpm/WlanNetworkRpm .

- [https://github.com/explxx/CVE-2023-33538](https://github.com/explxx/CVE-2023-33538) :  ![starts](https://img.shields.io/github/stars/explxx/CVE-2023-33538.svg) ![forks](https://img.shields.io/github/forks/explxx/CVE-2023-33538.svg)
- [https://github.com/mrowkoob/CVE-2023-33538-msf](https://github.com/mrowkoob/CVE-2023-33538-msf) :  ![starts](https://img.shields.io/github/stars/mrowkoob/CVE-2023-33538-msf.svg) ![forks](https://img.shields.io/github/forks/mrowkoob/CVE-2023-33538-msf.svg)


## CVE-2023-30333
 An arbitrary file upload vulnerability in the component /admin/ThemeController.java of PerfreeBlog v3.1.2 allows attackers to execute arbitrary code via a crafted file.

- [https://github.com/tuaandatt/CVE-2023-30333---Zimbra-UnRAR](https://github.com/tuaandatt/CVE-2023-30333---Zimbra-UnRAR) :  ![starts](https://img.shields.io/github/stars/tuaandatt/CVE-2023-30333---Zimbra-UnRAR.svg) ![forks](https://img.shields.io/github/forks/tuaandatt/CVE-2023-30333---Zimbra-UnRAR.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/theopaid/CVE-2023-27163-Request-Baskets-Local-Ports-Bruteforcer](https://github.com/theopaid/CVE-2023-27163-Request-Baskets-Local-Ports-Bruteforcer) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2023-27163-Request-Baskets-Local-Ports-Bruteforcer.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2023-27163-Request-Baskets-Local-Ports-Bruteforcer.svg)


## CVE-2023-26136
 Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode. This issue arises from the manner in which the objects are initialized.

- [https://github.com/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix](https://github.com/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix) :  ![starts](https://img.shields.io/github/stars/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix.svg) ![forks](https://img.shields.io/github/forks/uriyahav/tough-cookie-2.5.0-cve-2023-26136-fix.svg)


## CVE-2023-24249
 An arbitrary file upload vulnerability in laravel-admin v1.8.19 allows attackers to execute arbitrary code via a crafted PHP file.

- [https://github.com/ldb33/CVE-2023-24249-PoC](https://github.com/ldb33/CVE-2023-24249-PoC) :  ![starts](https://img.shields.io/github/stars/ldb33/CVE-2023-24249-PoC.svg) ![forks](https://img.shields.io/github/forks/ldb33/CVE-2023-24249-PoC.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/Arshit01/CVE-2023-20198](https://github.com/Arshit01/CVE-2023-20198) :  ![starts](https://img.shields.io/github/stars/Arshit01/CVE-2023-20198.svg) ![forks](https://img.shields.io/github/forks/Arshit01/CVE-2023-20198.svg)


## CVE-2023-20048
 A vulnerability in the web services interface of Cisco Firepower Management Center (FMC) Software could allow an authenticated, remote attacker to execute certain unauthorized configuration commands on a Firepower Threat Defense (FTD) device that is managed by the FMC Software. This vulnerability is due to insufficient authorization of configuration commands that are sent through the web service interface. An attacker could exploit this vulnerability by authenticating to the FMC web services interface and sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to execute certain configuration commands on the targeted FTD device. To successfully exploit this vulnerability, an attacker would need valid credentials on the FMC Software.

- [https://github.com/oguzhanozuzun301/cisco-rv-rce-poc](https://github.com/oguzhanozuzun301/cisco-rv-rce-poc) :  ![starts](https://img.shields.io/github/stars/oguzhanozuzun301/cisco-rv-rce-poc.svg) ![forks](https://img.shields.io/github/forks/oguzhanozuzun301/cisco-rv-rce-poc.svg)


## CVE-2023-6401
 A vulnerability classified as problematic was found in NotePad++ up to 8.1. Affected by this vulnerability is an unknown functionality of the file dbghelp.exe. The manipulation leads to uncontrolled search path. An attack has to be approached locally. The identifier VDB-246421 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/mekitoci/CVE-2023-6401](https://github.com/mekitoci/CVE-2023-6401) :  ![starts](https://img.shields.io/github/stars/mekitoci/CVE-2023-6401.svg) ![forks](https://img.shields.io/github/forks/mekitoci/CVE-2023-6401.svg)


## CVE-2023-5180
code in the context of the current process.

- [https://github.com/superswan/HeimShell](https://github.com/superswan/HeimShell) :  ![starts](https://img.shields.io/github/stars/superswan/HeimShell.svg) ![forks](https://img.shields.io/github/forks/superswan/HeimShell.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30,  8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/dadosneurais/cve-2023-3824](https://github.com/dadosneurais/cve-2023-3824) :  ![starts](https://img.shields.io/github/stars/dadosneurais/cve-2023-3824.svg) ![forks](https://img.shields.io/github/forks/dadosneurais/cve-2023-3824.svg)


## CVE-2023-1698
 In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.

- [https://github.com/ibrahmsql/CVE-2023-1698](https://github.com/ibrahmsql/CVE-2023-1698) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2023-1698.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2023-1698.svg)


## CVE-2022-37969
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/grass341/CVE-2022-37969](https://github.com/grass341/CVE-2022-37969) :  ![starts](https://img.shields.io/github/stars/grass341/CVE-2022-37969.svg) ![forks](https://img.shields.io/github/forks/grass341/CVE-2022-37969.svg)


## CVE-2022-32250
 net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.

- [https://github.com/KuanKuanQAQ/cve-testing](https://github.com/KuanKuanQAQ/cve-testing) :  ![starts](https://img.shields.io/github/stars/KuanKuanQAQ/cve-testing.svg) ![forks](https://img.shields.io/github/forks/KuanKuanQAQ/cve-testing.svg)


## CVE-2022-30333
 RARLAB UnRAR before 6.12 on Linux and UNIX allows directory traversal to write to files during an extract (aka unpack) operation, as demonstrated by creating a ~/.ssh/authorized_keys file. NOTE: WinRAR and Android RAR are unaffected.

- [https://github.com/tuaandatt/CVE-2022-30333---UnRAR](https://github.com/tuaandatt/CVE-2022-30333---UnRAR) :  ![starts](https://img.shields.io/github/stars/tuaandatt/CVE-2022-30333---UnRAR.svg) ![forks](https://img.shields.io/github/forks/tuaandatt/CVE-2022-30333---UnRAR.svg)


## CVE-2022-25581
 Classcms v2.5 and below contains an arbitrary file upload via the component \class\classupload. This vulnerability allows attackers to execute code injection via a crafted .txt file.

- [https://github.com/wooluo/CVE-2022-25581](https://github.com/wooluo/CVE-2022-25581) :  ![starts](https://img.shields.io/github/stars/wooluo/CVE-2022-25581.svg) ![forks](https://img.shields.io/github/forks/wooluo/CVE-2022-25581.svg)


## CVE-2022-2588
 It was discovered that the cls_route filter implementation in the Linux kernel would not remove an old filter from the hashtable before freeing it if its handle had the value 0.

- [https://github.com/Igr1s-red/CVE-2022-2588](https://github.com/Igr1s-red/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/Igr1s-red/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/Igr1s-red/CVE-2022-2588.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker](https://github.com/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker) :  ![starts](https://img.shields.io/github/stars/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker.svg) ![forks](https://img.shields.io/github/forks/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker.svg)


## CVE-2022-1257
 Insecure storage of sensitive information vulnerability in MA for Linux, macOS, and Windows prior to 5.7.6 allows a local user to gain access to sensitive information through storage in ma.db. The sensitive information has been moved to encrypted database files.

- [https://github.com/kayes817/CVE-2022-1257](https://github.com/kayes817/CVE-2022-1257) :  ![starts](https://img.shields.io/github/stars/kayes817/CVE-2022-1257.svg) ![forks](https://img.shields.io/github/forks/kayes817/CVE-2022-1257.svg)


## CVE-2022-0995
 An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

- [https://github.com/A1b2rt/cve-2022-0995](https://github.com/A1b2rt/cve-2022-0995) :  ![starts](https://img.shields.io/github/stars/A1b2rt/cve-2022-0995.svg) ![forks](https://img.shields.io/github/forks/A1b2rt/cve-2022-0995.svg)


## CVE-2015-6668
 The Job Manager plugin before 0.7.25 allows remote attackers to read arbitrary CV files via a brute force attack to the WordPress upload directory structure, related to an insecure direct object reference.

- [https://github.com/nika0x38/CVE-2015-6668](https://github.com/nika0x38/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/nika0x38/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/nika0x38/CVE-2015-6668.svg)

