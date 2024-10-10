# Update 2024-10-10
## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/becrevex/CVE-2024-38063](https://github.com/becrevex/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2024-38063.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/bka/magento-cve-2024-34102-exploit-cosmicstring](https://github.com/bka/magento-cve-2024-34102-exploit-cosmicstring) :  ![starts](https://img.shields.io/github/stars/bka/magento-cve-2024-34102-exploit-cosmicstring.svg) ![forks](https://img.shields.io/github/forks/bka/magento-cve-2024-34102-exploit-cosmicstring.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/Julian-gmz/hook_CVE-2024-32002](https://github.com/Julian-gmz/hook_CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/Julian-gmz/hook_CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/Julian-gmz/hook_CVE-2024-32002.svg)


## CVE-2024-22024
 An XML external entity or XXE vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x), Ivanti Policy Secure (9.x, 22.x) and ZTA gateways which allows an attacker to access certain restricted resources without authentication.

- [https://github.com/tequilasunsh1ne/ivanti_CVE_2024_22024](https://github.com/tequilasunsh1ne/ivanti_CVE_2024_22024) :  ![starts](https://img.shields.io/github/stars/tequilasunsh1ne/ivanti_CVE_2024_22024.svg) ![forks](https://img.shields.io/github/forks/tequilasunsh1ne/ivanti_CVE_2024_22024.svg)


## CVE-2024-5057
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/enter0x13/poc-CVE-2024-5057](https://github.com/enter0x13/poc-CVE-2024-5057) :  ![starts](https://img.shields.io/github/stars/enter0x13/poc-CVE-2024-5057.svg) ![forks](https://img.shields.io/github/forks/enter0x13/poc-CVE-2024-5057.svg)


## CVE-2024-1207
 The WP Booking Calendar plugin for WordPress is vulnerable to SQL Injection via the 'calendar_request_params[dates_ddmmyy_csv]' parameter in all versions up to, and including, 9.9 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/sahar042/CVE-2024-1207](https://github.com/sahar042/CVE-2024-1207) :  ![starts](https://img.shields.io/github/stars/sahar042/CVE-2024-1207.svg) ![forks](https://img.shields.io/github/forks/sahar042/CVE-2024-1207.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/canyie/CVE-2024-0044](https://github.com/canyie/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/canyie/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/canyie/CVE-2024-0044.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/bipbopbup/CVE-2023-46818-python-exploit](https://github.com/bipbopbup/CVE-2023-46818-python-exploit) :  ![starts](https://img.shields.io/github/stars/bipbopbup/CVE-2023-46818-python-exploit.svg) ![forks](https://img.shields.io/github/forks/bipbopbup/CVE-2023-46818-python-exploit.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/Chedrian07/CVE-2023-45866-POC](https://github.com/Chedrian07/CVE-2023-45866-POC) :  ![starts](https://img.shields.io/github/stars/Chedrian07/CVE-2023-45866-POC.svg) ![forks](https://img.shields.io/github/forks/Chedrian07/CVE-2023-45866-POC.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/fa-rrel/CVE-2023-7028](https://github.com/fa-rrel/CVE-2023-7028) :  ![starts](https://img.shields.io/github/stars/fa-rrel/CVE-2023-7028.svg) ![forks](https://img.shields.io/github/forks/fa-rrel/CVE-2023-7028.svg)


## CVE-2022-20699
 Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/rohan-flutterint/CVE-2022-20699](https://github.com/rohan-flutterint/CVE-2022-20699) :  ![starts](https://img.shields.io/github/stars/rohan-flutterint/CVE-2022-20699.svg) ![forks](https://img.shields.io/github/forks/rohan-flutterint/CVE-2022-20699.svg)


## CVE-2021-33026
 ** DISPUTED ** The Flask-Caching extension through 1.10.1 for Flask relies on Pickle for serialization, which may lead to remote code execution or local privilege escalation. If an attacker gains access to cache storage (e.g., filesystem, Memcached, Redis, etc.), they can construct a crafted payload, poison the cache, and execute Python code. NOTE: a third party indicates that exploitation is extremely unlikely unless the machine is already compromised; in other cases, the attacker would be unable to write their payload to the cache and generate the required collision.

- [https://github.com/Agilevatester/FlaskCache_CVE-2021-33026_POC](https://github.com/Agilevatester/FlaskCache_CVE-2021-33026_POC) :  ![starts](https://img.shields.io/github/stars/Agilevatester/FlaskCache_CVE-2021-33026_POC.svg) ![forks](https://img.shields.io/github/forks/Agilevatester/FlaskCache_CVE-2021-33026_POC.svg)


## CVE-2020-14179
 Affected versions of Atlassian Jira Server and Data Center allow remote, unauthenticated attackers to view custom field names and custom SLA names via an Information Disclosure vulnerability in the /secure/QueryComponent!Default.jspa endpoint. The affected versions are before version 8.5.8, and from version 8.6.0 before 8.11.1.

- [https://github.com/0x0060/CVE-2020-14179](https://github.com/0x0060/CVE-2020-14179) :  ![starts](https://img.shields.io/github/stars/0x0060/CVE-2020-14179.svg) ![forks](https://img.shields.io/github/forks/0x0060/CVE-2020-14179.svg)


## CVE-2018-7284
 A Buffer Overflow issue was discovered in Asterisk through 13.19.1, 14.x through 14.7.5, and 15.x through 15.2.1, and Certified Asterisk through 13.18-cert2. When processing a SUBSCRIBE request, the res_pjsip_pubsub module stores the accepted formats present in the Accept headers of the request. This code did not limit the number of headers it processed, despite having a fixed limit of 32. If more than 32 Accept headers were present, the code would write outside of its memory and cause a crash.

- [https://github.com/Rodrigo-D/astDoS](https://github.com/Rodrigo-D/astDoS) :  ![starts](https://img.shields.io/github/stars/Rodrigo-D/astDoS.svg) ![forks](https://img.shields.io/github/forks/Rodrigo-D/astDoS.svg)


## CVE-2018-7273
 In the Linux kernel through 4.15.4, the floppy driver reveals the addresses of kernel functions and global variables using printk calls within the function show_floppy in drivers/block/floppy.c. An attacker can read this information from dmesg and use the addresses to find the locations of kernel code and data and bypass kernel security protections such as KASLR.

- [https://github.com/jedai47/CVE-2018-7273](https://github.com/jedai47/CVE-2018-7273) :  ![starts](https://img.shields.io/github/stars/jedai47/CVE-2018-7273.svg) ![forks](https://img.shields.io/github/forks/jedai47/CVE-2018-7273.svg)


## CVE-2018-7250
 An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. An uninitialized kernel pool allocation in IOCTL 0xCA002813 allows a local unprivileged attacker to leak 16 bits of uninitialized kernel PagedPool data.

- [https://github.com/Elvin9/SecDrvPoolLeak](https://github.com/Elvin9/SecDrvPoolLeak) :  ![starts](https://img.shields.io/github/stars/Elvin9/SecDrvPoolLeak.svg) ![forks](https://img.shields.io/github/forks/Elvin9/SecDrvPoolLeak.svg)


## CVE-2018-7249
 An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. Two carefully timed calls to IOCTL 0xCA002813 can cause a race condition that leads to a use-after-free. When exploited, an unprivileged attacker can run arbitrary code in the kernel.

- [https://github.com/Elvin9/NotSecDrv](https://github.com/Elvin9/NotSecDrv) :  ![starts](https://img.shields.io/github/stars/Elvin9/NotSecDrv.svg) ![forks](https://img.shields.io/github/forks/Elvin9/NotSecDrv.svg)


## CVE-2018-7211
 An issue was discovered in iDashboards 9.6b. The SSO implementation is affected by a weak obfuscation library, allowing man-in-the-middle attackers to discover credentials.

- [https://github.com/c3r34lk1ll3r/CVE-2018-7211-PoC](https://github.com/c3r34lk1ll3r/CVE-2018-7211-PoC) :  ![starts](https://img.shields.io/github/stars/c3r34lk1ll3r/CVE-2018-7211-PoC.svg) ![forks](https://img.shields.io/github/forks/c3r34lk1ll3r/CVE-2018-7211-PoC.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/dream434/CVE-2017-9841-](https://github.com/dream434/CVE-2017-9841-) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2017-9841-.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2017-9841-.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/dream434/CVE-2017-5487](https://github.com/dream434/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2017-5487.svg)

