# Update 2024-05-28
## CVE-2024-32651
 changedetection.io is an open source web page change detection, website watcher, restock monitor and notification service. There is a Server Side Template Injection (SSTI) in Jinja2 that allows Remote Command Execution on the server host. Attackers can run any system command without any restriction and they could use a reverse shell. The impact is critical as the attacker can completely takeover the server machine. This can be reduced if changedetection is behind a login page, but this isn't required by the application (not by default and not enforced).

- [https://github.com/zcrosman/cve-2024-32651](https://github.com/zcrosman/cve-2024-32651) :  ![starts](https://img.shields.io/github/stars/zcrosman/cve-2024-32651.svg) ![forks](https://img.shields.io/github/forks/zcrosman/cve-2024-32651.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/Surko888/Surko-Exploit-Jenkins-CVE-2024-23897](https://github.com/Surko888/Surko-Exploit-Jenkins-CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/Surko888/Surko-Exploit-Jenkins-CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/Surko888/Surko-Exploit-Jenkins-CVE-2024-23897.svg)


## CVE-2024-21306
 Microsoft Bluetooth Driver Spoofing Vulnerability

- [https://github.com/PhucHauDeveloper/BadBlue](https://github.com/PhucHauDeveloper/BadBlue) :  ![starts](https://img.shields.io/github/stars/PhucHauDeveloper/BadBlue.svg) ![forks](https://img.shields.io/github/forks/PhucHauDeveloper/BadBlue.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/pulentoski/CVE-2023-51467-and-CVE-2023-49070](https://github.com/pulentoski/CVE-2023-51467-and-CVE-2023-49070) :  ![starts](https://img.shields.io/github/stars/pulentoski/CVE-2023-51467-and-CVE-2023-49070.svg) ![forks](https://img.shields.io/github/forks/pulentoski/CVE-2023-51467-and-CVE-2023-49070.svg)


## CVE-2023-49070
 Pre-auth RCE in Apache Ofbiz 18.12.09. It's due to XML-RPC no longer maintained still present. This issue affects Apache OFBiz: before 18.12.10. Users are recommended to upgrade to version 18.12.10

- [https://github.com/pulentoski/CVE-2023-51467-and-CVE-2023-49070](https://github.com/pulentoski/CVE-2023-51467-and-CVE-2023-49070) :  ![starts](https://img.shields.io/github/stars/pulentoski/CVE-2023-51467-and-CVE-2023-49070.svg) ![forks](https://img.shields.io/github/forks/pulentoski/CVE-2023-51467-and-CVE-2023-49070.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/sn130hk/CVE-2023-44487](https://github.com/sn130hk/CVE-2023-44487) :  ![starts](https://img.shields.io/github/stars/sn130hk/CVE-2023-44487.svg) ![forks](https://img.shields.io/github/forks/sn130hk/CVE-2023-44487.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/junnythemarksman/CVE-2023-42793](https://github.com/junnythemarksman/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/junnythemarksman/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/junnythemarksman/CVE-2023-42793.svg)


## CVE-2023-30253
 Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: &lt;?PHP instead of &lt;?php in injected data.

- [https://github.com/Rubikcuv5/cve-2023-30253](https://github.com/Rubikcuv5/cve-2023-30253) :  ![starts](https://img.shields.io/github/stars/Rubikcuv5/cve-2023-30253.svg) ![forks](https://img.shields.io/github/forks/Rubikcuv5/cve-2023-30253.svg)


## CVE-2023-24044
 ** DISPUTED ** A Host Header Injection issue on the Login page of Plesk Obsidian through 18.0.49 allows attackers to redirect users to malicious websites via a Host request header. NOTE: the vendor's position is &quot;the ability to use arbitrary domain names to access the panel is an intended feature.&quot;

- [https://github.com/Cappricio-Securities/CVE-2023-24044](https://github.com/Cappricio-Securities/CVE-2023-24044) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2023-24044.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2023-24044.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/Nuki2u/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK](https://github.com/Nuki2u/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK) :  ![starts](https://img.shields.io/github/stars/Nuki2u/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg) ![forks](https://img.shields.io/github/forks/Nuki2u/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/joelindra/htmlawedchekcer](https://github.com/joelindra/htmlawedchekcer) :  ![starts](https://img.shields.io/github/stars/joelindra/htmlawedchekcer.svg) ![forks](https://img.shields.io/github/forks/joelindra/htmlawedchekcer.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/ZTK-009/CVE-2021-21972](https://github.com/ZTK-009/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/ZTK-009/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/ZTK-009/CVE-2021-21972.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/ZTK-009/CVE-2021-3156](https://github.com/ZTK-009/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/ZTK-009/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/ZTK-009/CVE-2021-3156.svg)


## CVE-2020-1337
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system. An attacker who successfully exploited this vulnerability could run arbitrary code with elevated system privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. To exploit this vulnerability, an attacker would have to log on to an affected system and run a specially crafted script or application. The update addresses the vulnerability by correcting how the Windows Print Spooler Component writes to the file system.

- [https://github.com/ZTK-009/cve-2020-1337-poc](https://github.com/ZTK-009/cve-2020-1337-poc) :  ![starts](https://img.shields.io/github/stars/ZTK-009/cve-2020-1337-poc.svg) ![forks](https://img.shields.io/github/forks/ZTK-009/cve-2020-1337-poc.svg)


## CVE-2019-16889
 Ubiquiti EdgeMAX devices before 2.0.3 allow remote attackers to cause a denial of service (disk consumption) because *.cache files in /var/run/beaker/container_file/ are created when providing a valid length payload of 249 characters or fewer to the beaker.session.id cookie in a GET header. The attacker can use a long series of unique session IDs.

- [https://github.com/grampae/CVE-2019-16889-poc](https://github.com/grampae/CVE-2019-16889-poc) :  ![starts](https://img.shields.io/github/stars/grampae/CVE-2019-16889-poc.svg) ![forks](https://img.shields.io/github/forks/grampae/CVE-2019-16889-poc.svg)


## CVE-2018-11784
 When the default servlet in Apache Tomcat versions 9.0.0.M1 to 9.0.11, 8.5.0 to 8.5.33 and 7.0.23 to 7.0.90 returned a redirect to a directory (e.g. redirecting to '/foo/' when the user requested '/foo') a specially crafted URL could be used to cause the redirect to be generated to any URI of the attackers choice.

- [https://github.com/Cappricio-Securities/CVE-2018-11784](https://github.com/Cappricio-Securities/CVE-2018-11784) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2018-11784.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2018-11784.svg)


## CVE-2018-2893
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/artofwar344/CVE-2018-2893](https://github.com/artofwar344/CVE-2018-2893) :  ![starts](https://img.shields.io/github/stars/artofwar344/CVE-2018-2893.svg) ![forks](https://img.shields.io/github/forks/artofwar344/CVE-2018-2893.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/Jhonsonwannaa/CVE-2017-5487](https://github.com/Jhonsonwannaa/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/Jhonsonwannaa/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/Jhonsonwannaa/CVE-2017-5487.svg)

