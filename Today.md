# Update 2024-10-30
## CVE-2024-34716
 PrestaShop is an open source e-commerce web application. A cross-site scripting (XSS) vulnerability that only affects PrestaShops with customer-thread feature flag enabled is present starting from PrestaShop 8.1.0 and prior to PrestaShop 8.1.6. When the customer thread feature flag is enabled through the front-office contact form, a hacker can upload a malicious file containing an XSS that will be executed when an admin opens the attached file in back office. The script injected can access the session and the security token, which allows it to perform any authenticated action in the scope of the administrator's right. This vulnerability is patched in 8.1.6. A workaround is to disable the customer-thread feature-flag.

- [https://github.com/TanveerS1ngh/Prestashop-CVE-2024-34716](https://github.com/TanveerS1ngh/Prestashop-CVE-2024-34716) :  ![starts](https://img.shields.io/github/stars/TanveerS1ngh/Prestashop-CVE-2024-34716.svg) ![forks](https://img.shields.io/github/forks/TanveerS1ngh/Prestashop-CVE-2024-34716.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/sar-3mar/CVE-2024-24919_POC](https://github.com/sar-3mar/CVE-2024-24919_POC) :  ![starts](https://img.shields.io/github/stars/sar-3mar/CVE-2024-24919_POC.svg) ![forks](https://img.shields.io/github/forks/sar-3mar/CVE-2024-24919_POC.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/cc3305/CVE-2024-23897](https://github.com/cc3305/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/cc3305/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/cc3305/CVE-2024-23897.svg)


## CVE-2024-5143
 A user with device administrative privileges can change existing SMTP server settings on the device, without having to re-enter SMTP server credentials. By redirecting send-to-email traffic to the new server, the original SMTP server credentials may potentially be exposed.

- [https://github.com/bevennyamande/CVE-2024-51435](https://github.com/bevennyamande/CVE-2024-51435) :  ![starts](https://img.shields.io/github/stars/bevennyamande/CVE-2024-51435.svg) ![forks](https://img.shields.io/github/forks/bevennyamande/CVE-2024-51435.svg)


## CVE-2024-4757
 The Logo Manager For Enamad WordPress plugin through 0.7.0 does not have CSRF check in some places, and is missing sanitisation as well as escaping, which could allow attackers to make logged in admin add Stored XSS payloads via a CSRF attack

- [https://github.com/hazesecurity/CVE-2024-47575](https://github.com/hazesecurity/CVE-2024-47575) :  ![starts](https://img.shields.io/github/stars/hazesecurity/CVE-2024-47575.svg) ![forks](https://img.shields.io/github/forks/hazesecurity/CVE-2024-47575.svg)
- [https://github.com/groshi/CVE-2024-47575-POC](https://github.com/groshi/CVE-2024-47575-POC) :  ![starts](https://img.shields.io/github/stars/groshi/CVE-2024-47575-POC.svg) ![forks](https://img.shields.io/github/forks/groshi/CVE-2024-47575-POC.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/0xbd2/CVE-2024-4577](https://github.com/0xbd2/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/0xbd2/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/0xbd2/CVE-2024-4577.svg)


## CVE-2024-1044
 The Customer Reviews for WooCommerce plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'submit_review' function in all versions up to, and including, 5.38.12. This makes it possible for unauthenticated attackers to submit reviews with arbitrary email addresses regardless of whether reviews are globally enabled.

- [https://github.com/bevennyamande/CVE-2024-10448](https://github.com/bevennyamande/CVE-2024-10448) :  ![starts](https://img.shields.io/github/stars/bevennyamande/CVE-2024-10448.svg) ![forks](https://img.shields.io/github/forks/bevennyamande/CVE-2024-10448.svg)


## CVE-2023-50564
 An arbitrary file upload vulnerability in the component /inc/modules_install.php of Pluck-CMS v4.7.18 allows attackers to execute arbitrary code via uploading a crafted ZIP file.

- [https://github.com/TanveerS1ngh/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564](https://github.com/TanveerS1ngh/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564) :  ![starts](https://img.shields.io/github/stars/TanveerS1ngh/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564.svg) ![forks](https://img.shields.io/github/forks/TanveerS1ngh/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564.svg)


## CVE-2023-33669
 Tenda AC8V4.0-V16.03.34.06 was discovered to contain a stack overflow via the timeZone parameter in the sub_44db3c function.

- [https://github.com/Mohammaddvd/CVE-2023-33669](https://github.com/Mohammaddvd/CVE-2023-33669) :  ![starts](https://img.shields.io/github/stars/Mohammaddvd/CVE-2023-33669.svg) ![forks](https://img.shields.io/github/forks/Mohammaddvd/CVE-2023-33669.svg)


## CVE-2022-48565
 An XML External Entity (XXE) issue was discovered in Python through 3.9.1. The plistlib module no longer accepts entity declarations in XML plist files to avoid XML vulnerabilities.

- [https://github.com/Einstein2150/CVE-2022-48565-POC](https://github.com/Einstein2150/CVE-2022-48565-POC) :  ![starts](https://img.shields.io/github/stars/Einstein2150/CVE-2022-48565-POC.svg) ![forks](https://img.shields.io/github/forks/Einstein2150/CVE-2022-48565-POC.svg)


## CVE-2019-19842
 emfd in Ruckus Wireless Unleashed through 200.7.10.102.64 allows remote attackers to execute OS commands via a POST request with the attribute xcmd=spectra-analysis to admin/_cmdstat.jsp via the mac attribute.

- [https://github.com/bdunlap9/CVE-2019-19842](https://github.com/bdunlap9/CVE-2019-19842) :  ![starts](https://img.shields.io/github/stars/bdunlap9/CVE-2019-19842.svg) ![forks](https://img.shields.io/github/forks/bdunlap9/CVE-2019-19842.svg)


## CVE-2018-6789
 An issue was discovered in the base64d function in the SMTP listener in Exim before 4.90.1. By sending a handcrafted message, a buffer overflow may happen. This can be used to execute code remotely.

- [https://github.com/thistehneisen/CVE-2018-6789-Python3](https://github.com/thistehneisen/CVE-2018-6789-Python3) :  ![starts](https://img.shields.io/github/stars/thistehneisen/CVE-2018-6789-Python3.svg) ![forks](https://img.shields.io/github/forks/thistehneisen/CVE-2018-6789-Python3.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/brosck/CVE-2006-3392](https://github.com/brosck/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/brosck/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/brosck/CVE-2006-3392.svg)

