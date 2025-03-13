# Update 2025-03-13
## CVE-2025-27893
 In Archer Platform 6 through 6.14.00202.10024, an authenticated user with record creation privileges can manipulate immutable fields, such as the creation date, by intercepting and modifying a Copy request via a GenericContent/Record.aspx?id= URI. This enables unauthorized modification of system-generated metadata, compromising data integrity and potentially impacting auditing, compliance, and security controls.

- [https://github.com/NastyCrow/CVE-2025-27893](https://github.com/NastyCrow/CVE-2025-27893) :  ![starts](https://img.shields.io/github/stars/NastyCrow/CVE-2025-27893.svg) ![forks](https://img.shields.io/github/forks/NastyCrow/CVE-2025-27893.svg)


## CVE-2025-25749
 An issue in HotelDruid version 3.0.7 and earlier allows users to set weak passwords due to the lack of enforcement of password strength policies.

- [https://github.com/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7](https://github.com/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7.svg)


## CVE-2025-25748
 A CSRF vulnerability in the gestione_utenti.php endpoint of HotelDruid 3.0.7 allows attackers to perform unauthorized actions (e.g., modifying user passwords) on behalf of authenticated users by exploiting the lack of origin or referrer validation and the absence of CSRF tokens.

- [https://github.com/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7](https://github.com/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7.svg)


## CVE-2025-25747
 Cross Site Scripting vulnerability in DigitalDruid HotelDruid v.3.0.7 allows an attacker to execute arbitrary code and obtain sensitive information via the ripristina_backup parameter in the crea_backup.php endpoint

- [https://github.com/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS](https://github.com/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/aleongx/KQL_sentinel_CVE-2025-21333](https://github.com/aleongx/KQL_sentinel_CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/aleongx/KQL_sentinel_CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/aleongx/KQL_sentinel_CVE-2025-21333.svg)


## CVE-2024-54383
 Incorrect Privilege Assignment vulnerability in wpweb WooCommerce PDF Vouchers allows Privilege Escalation.This issue affects WooCommerce PDF Vouchers: from n/a before 4.9.9.

- [https://github.com/pashayogi/CVE-2024-54383](https://github.com/pashayogi/CVE-2024-54383) :  ![starts](https://img.shields.io/github/stars/pashayogi/CVE-2024-54383.svg) ![forks](https://img.shields.io/github/forks/pashayogi/CVE-2024-54383.svg)


## CVE-2024-34370
 Improper Privilege Management vulnerability in WPFactory EAN for WooCommerce allows Privilege Escalation.This issue affects EAN for WooCommerce: from n/a through 4.8.9.

- [https://github.com/pashayogi/CVE-2024-34370](https://github.com/pashayogi/CVE-2024-34370) :  ![starts](https://img.shields.io/github/stars/pashayogi/CVE-2024-34370.svg) ![forks](https://img.shields.io/github/forks/pashayogi/CVE-2024-34370.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/AiK1d/CVE-2024-23897](https://github.com/AiK1d/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2024-23897.svg)


## CVE-2024-12365
 The W3 Total Cache plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the is_w3tc_admin_page function in all versions up to, and including, 2.8.1. This makes it possible for authenticated attackers, with Subscriber-level access and above, to obtain the plugin's nonce value and perform unauthorized actions, resulting in information disclosure, service plan limits consumption as well as making web requests to arbitrary locations originating from the web application that can be used to query information from internal services, including instance metadata on cloud-based applications.

- [https://github.com/spyata123/W3TotalChache](https://github.com/spyata123/W3TotalChache) :  ![starts](https://img.shields.io/github/stars/spyata123/W3TotalChache.svg) ![forks](https://img.shields.io/github/forks/spyata123/W3TotalChache.svg)


## CVE-2024-12008
Note: the debug feature must be enabled for this to be a concern, and it is disabled by default.

- [https://github.com/spyata123/CVE-2024-12008-information-exposure-vulnerability-in-W3-Total-Cache](https://github.com/spyata123/CVE-2024-12008-information-exposure-vulnerability-in-W3-Total-Cache) :  ![starts](https://img.shields.io/github/stars/spyata123/CVE-2024-12008-information-exposure-vulnerability-in-W3-Total-Cache.svg) ![forks](https://img.shields.io/github/forks/spyata123/CVE-2024-12008-information-exposure-vulnerability-in-W3-Total-Cache.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/sharafu-sblsec/CVE-2024-10924](https://github.com/sharafu-sblsec/CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/sharafu-sblsec/CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/sharafu-sblsec/CVE-2024-10924.svg)


## CVE-2024-9756
 The Order Attachments for WooCommerce plugin for WordPress is vulnerable to unauthorized limited arbitrary file uploads due to a missing capability check on the wcoa_add_attachment AJAX action in versions 2.0 to 2.4.1. This makes it possible for authenticated attackers, with subscriber-level access and above, to upload limited file types.

- [https://github.com/Nxploited/CVE-2024-9756](https://github.com/Nxploited/CVE-2024-9756) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9756.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9756.svg)


## CVE-2024-8289
 The MultiVendorX – The Ultimate WooCommerce Multivendor Marketplace Solution plugin for WordPress is vulnerable to privilege escalation/de-escalation and account takeover due to an insufficient capability check on the update_item_permissions_check and create_item_permissions_check functions in all versions up to, and including, 4.2.0. This makes it possible for unauthenticated attackers to change the password of any user with the vendor role, create new users with the vendor role, and demote other users like administrators to the vendor role.

- [https://github.com/pashayogi/CVE-2024-8289](https://github.com/pashayogi/CVE-2024-8289) :  ![starts](https://img.shields.io/github/stars/pashayogi/CVE-2024-8289.svg) ![forks](https://img.shields.io/github/forks/pashayogi/CVE-2024-8289.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/AiK1d/CVE-2024-6387](https://github.com/AiK1d/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2024-6387.svg)


## CVE-2024-6132
 The Pexels: Free Stock Photos plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'pexels_fsp_images_options_validate' function in all versions up to, and including, 1.2.2. This makes it possible for authenticated attackers, with contributor-level and above permissions, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2024-6132](https://github.com/Nxploited/CVE-2024-6132) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-6132.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-6132.svg)


## CVE-2023-36845
  *  23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/AiK1d/ansible-cve-2023-36845](https://github.com/AiK1d/ansible-cve-2023-36845) :  ![starts](https://img.shields.io/github/stars/AiK1d/ansible-cve-2023-36845.svg) ![forks](https://img.shields.io/github/forks/AiK1d/ansible-cve-2023-36845.svg)


## CVE-2023-33829
 A stored cross-site scripting (XSS) vulnerability in Cloudogu GmbH SCM Manager v1.2 to v1.60 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Description text field.

- [https://github.com/AiK1d/CVE-2023-33829-POC](https://github.com/AiK1d/CVE-2023-33829-POC) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-33829-POC.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-33829-POC.svg)


## CVE-2023-33246
To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/AiK1d/CVE-2023-33246](https://github.com/AiK1d/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-33246.svg)


## CVE-2023-29923
 PowerJob V4.3.1 is vulnerable to Insecure Permissions. via the list job interface.

- [https://github.com/AiK1d/CVE-2023-29923-Scan](https://github.com/AiK1d/CVE-2023-29923-Scan) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-29923-Scan.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-29923-Scan.svg)


## CVE-2023-29922
 PowerJob V4.3.1 is vulnerable to Incorrect Access Control via the create user/save interface.

- [https://github.com/AiK1d/CVE-2023-29923-Scan](https://github.com/AiK1d/CVE-2023-29923-Scan) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-29923-Scan.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-29923-Scan.svg)


## CVE-2023-23638
This issue affects Apache Dubbo 2.7.x version 2.7.21 and prior versions; Apache Dubbo 3.0.x version 3.0.13 and prior versions; Apache Dubbo 3.1.x version 3.1.5 and prior versions. 

- [https://github.com/AiK1d/CVE-2023-23638-Tools](https://github.com/AiK1d/CVE-2023-23638-Tools) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-23638-Tools.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-23638-Tools.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/AiK1d/CVE-2023-23397-POC](https://github.com/AiK1d/CVE-2023-23397-POC) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-23397-POC.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-23397-POC.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/AiK1d/CVE-2023-22809-sudo-POC](https://github.com/AiK1d/CVE-2023-22809-sudo-POC) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-22809-sudo-POC.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-22809-sudo-POC.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/AiK1d/CVE-2023-21768-POC](https://github.com/AiK1d/CVE-2023-21768-POC) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-21768-POC.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-21768-POC.svg)


## CVE-2023-21716
 Microsoft Word Remote Code Execution Vulnerability

- [https://github.com/AiK1d/CVE-2023-21716-POC](https://github.com/AiK1d/CVE-2023-21716-POC) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-21716-POC.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-21716-POC.svg)


## CVE-2023-5359
 The W3 Total Cache plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 2.7.5 via Google OAuth API secrets stored in plaintext in the publicly visible plugin source. This can allow unauthenticated attackers to impersonate W3 Total Cache and gain access to user account information in successful conditions. This would not impact the WordPress users site in any way.

- [https://github.com/spyata123/Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache](https://github.com/spyata123/Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache) :  ![starts](https://img.shields.io/github/stars/spyata123/Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache.svg) ![forks](https://img.shields.io/github/forks/spyata123/Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache.svg)


## CVE-2023-1454
 A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-223299.

- [https://github.com/AiK1d/CVE-2023-1454-EXP](https://github.com/AiK1d/CVE-2023-1454-EXP) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-1454-EXP.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-1454-EXP.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/AiK1d/CVE-2023-0386](https://github.com/AiK1d/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2023-0386.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier  and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/AiK1d/CVE-2022-42475-RCE-POC](https://github.com/AiK1d/CVE-2022-42475-RCE-POC) :  ![starts](https://img.shields.io/github/stars/AiK1d/CVE-2022-42475-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/AiK1d/CVE-2022-42475-RCE-POC.svg)


## CVE-2022-29056
 A improper restriction of excessive authentication attempts vulnerability [CWE-307] in Fortinet FortiMail version 6.4.0, version 6.2.0 through 6.2.4 and before 6.0.9 allows  a remote unauthenticated attacker to partially exhaust CPU and memory via sending numerous HTTP requests to the login form.

- [https://github.com/cnetsec/CVE-2022-29056](https://github.com/cnetsec/CVE-2022-29056) :  ![starts](https://img.shields.io/github/stars/cnetsec/CVE-2022-29056.svg) ![forks](https://img.shields.io/github/forks/cnetsec/CVE-2022-29056.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/surprisedmo/log4shell-tools](https://github.com/surprisedmo/log4shell-tools) :  ![starts](https://img.shields.io/github/stars/surprisedmo/log4shell-tools.svg) ![forks](https://img.shields.io/github/forks/surprisedmo/log4shell-tools.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Vanshuk-Bhagat/Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013](https://github.com/Vanshuk-Bhagat/Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/Vanshuk-Bhagat/Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/Vanshuk-Bhagat/Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013.svg)


## CVE-2021-37787
 The unprivileged administrative interface in ABO.CMS version 5.8 through v.5.9.3 is affected by a SQL Injection vulnerability via a HTTP POST request to the TinyMCE module

- [https://github.com/vasykor/CVE-2021-37787](https://github.com/vasykor/CVE-2021-37787) :  ![starts](https://img.shields.io/github/stars/vasykor/CVE-2021-37787.svg) ![forks](https://img.shields.io/github/forks/vasykor/CVE-2021-37787.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/gps1949/CVE-2021-25646](https://github.com/gps1949/CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/gps1949/CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/gps1949/CVE-2021-25646.svg)


## CVE-2019-6715
 pub/sns.php in the W3 Total Cache plugin before 0.9.4 for WordPress allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data.

- [https://github.com/spyata123/W3TotalChache](https://github.com/spyata123/W3TotalChache) :  ![starts](https://img.shields.io/github/stars/spyata123/W3TotalChache.svg) ![forks](https://img.shields.io/github/forks/spyata123/W3TotalChache.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/xdrake1010/CVE-2017-11882-Preventer](https://github.com/xdrake1010/CVE-2017-11882-Preventer) :  ![starts](https://img.shields.io/github/stars/xdrake1010/CVE-2017-11882-Preventer.svg) ![forks](https://img.shields.io/github/forks/xdrake1010/CVE-2017-11882-Preventer.svg)

