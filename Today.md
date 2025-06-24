# Update 2025-06-24
## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/Zen-kun04/CVE-2025-49132](https://github.com/Zen-kun04/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/Zen-kun04/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/Zen-kun04/CVE-2025-49132.svg)
- [https://github.com/nfoltc/CVE-2025-49132](https://github.com/nfoltc/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/nfoltc/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/nfoltc/CVE-2025-49132.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/issamjr/CVE-2025-49113-Scanner](https://github.com/issamjr/CVE-2025-49113-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-49113-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-49113-Scanner.svg)


## CVE-2025-30401
 A spoofing issue in WhatsApp for Windows prior to version 2.2450.6 displayed attachments according to their MIME type but selected the file opening handler based on the attachment’s filename extension. A maliciously crafted mismatch could have caused the recipient to inadvertently execute arbitrary code rather than view the attachment when manually opening the attachment inside WhatsApp. We have not seen evidence of exploitation in the wild.

- [https://github.com/allinsthon/CVE-2025-30401](https://github.com/allinsthon/CVE-2025-30401) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-30401.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-30401.svg)


## CVE-2025-26909
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in John Darrel Hide My WP Ghost allows PHP Local File Inclusion.This issue affects Hide My WP Ghost: from n/a through 5.4.01.

- [https://github.com/issamjr/CVE-2025-26909-Scanner](https://github.com/issamjr/CVE-2025-26909-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-26909-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-26909-Scanner.svg)


## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.

- [https://github.com/Professor6T9/CVE-2025-3515](https://github.com/Professor6T9/CVE-2025-3515) :  ![starts](https://img.shields.io/github/stars/Professor6T9/CVE-2025-3515.svg) ![forks](https://img.shields.io/github/forks/Professor6T9/CVE-2025-3515.svg)


## CVE-2025-3248
code.

- [https://github.com/issamjr/CVE-2025-3248-Scanner](https://github.com/issamjr/CVE-2025-3248-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-3248-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-3248-Scanner.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-3248](https://github.com/B1ack4sh/Blackash-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-3248.svg)


## CVE-2025-1562
 The Recover WooCommerce Cart Abandonment, Newsletter, Email Marketing, Marketing Automation By FunnelKit plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the install_or_activate_addon_plugins() function and a weak nonce hash in all versions up to, and including, 3.5.3. This makes it possible for unauthenticated attackers to install arbitrary plugins on the site that can be leveraged to further infect a vulnerable site.

- [https://github.com/maximo896/CVE-2025-1562](https://github.com/maximo896/CVE-2025-1562) :  ![starts](https://img.shields.io/github/stars/maximo896/CVE-2025-1562.svg) ![forks](https://img.shields.io/github/forks/maximo896/CVE-2025-1562.svg)


## CVE-2025-1265
 An OS command injection vulnerability exists in Vinci Protocol Analyzer that could allow an attacker to escalate privileges and perform code execution on affected system.

- [https://github.com/Taowmz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Taowmz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder) :  ![starts](https://img.shields.io/github/stars/Taowmz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg) ![forks](https://img.shields.io/github/forks/Taowmz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg)


## CVE-2023-33538
 TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a command injection vulnerability via the component /userRpm/WlanNetworkRpm .

- [https://github.com/explxx/CVE-2023-33538](https://github.com/explxx/CVE-2023-33538) :  ![starts](https://img.shields.io/github/stars/explxx/CVE-2023-33538.svg) ![forks](https://img.shields.io/github/forks/explxx/CVE-2023-33538.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/e21-AS/telstra-cybersecurity-experience](https://github.com/e21-AS/telstra-cybersecurity-experience) :  ![starts](https://img.shields.io/github/stars/e21-AS/telstra-cybersecurity-experience.svg) ![forks](https://img.shields.io/github/forks/e21-AS/telstra-cybersecurity-experience.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/retrymp3/apache2.4.49VulnerableLabSetup](https://github.com/retrymp3/apache2.4.49VulnerableLabSetup) :  ![starts](https://img.shields.io/github/stars/retrymp3/apache2.4.49VulnerableLabSetup.svg) ![forks](https://img.shields.io/github/forks/retrymp3/apache2.4.49VulnerableLabSetup.svg)


## CVE-2021-22600
 A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755

- [https://github.com/sendINUX/CVE-2021-22600__DirtyPagetable](https://github.com/sendINUX/CVE-2021-22600__DirtyPagetable) :  ![starts](https://img.shields.io/github/stars/sendINUX/CVE-2021-22600__DirtyPagetable.svg) ![forks](https://img.shields.io/github/forks/sendINUX/CVE-2021-22600__DirtyPagetable.svg)

