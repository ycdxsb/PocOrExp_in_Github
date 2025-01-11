# Update 2025-01-11
## CVE-2025-22510
 Deserialization of Untrusted Data vulnerability in Konrad Karpieszuk WC Price History for Omnibus allows Object Injection.This issue affects WC Price History for Omnibus: from n/a through 2.1.4.

- [https://github.com/DoTTak/CVE-2025-22510](https://github.com/DoTTak/CVE-2025-22510) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22510.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22510.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/securexploit1/CVE-2025-0282](https://github.com/securexploit1/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/securexploit1/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/securexploit1/CVE-2025-0282.svg)


## CVE-2024-56662
call_pkg, including the nd_reserved2 array.

- [https://github.com/nimosec/cve-2024-56662](https://github.com/nimosec/cve-2024-56662) :  ![starts](https://img.shields.io/github/stars/nimosec/cve-2024-56662.svg) ![forks](https://img.shields.io/github/forks/nimosec/cve-2024-56662.svg)


## CVE-2024-56512
This vulnerability is limited in scope to authenticated users authorized to create Process Groups. The scope is further limited to deployments with component-based authorization policies. Upgrading to Apache NiFi 2.1.0 is the recommended mitigation, which includes authorization checking for Parameter and Controller Service references on Process Group creation.

- [https://github.com/absholi7ly/CVE-2024-56512-Apache-NiFi-Exploit](https://github.com/absholi7ly/CVE-2024-56512-Apache-NiFi-Exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2024-56512-Apache-NiFi-Exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2024-56512-Apache-NiFi-Exploit.svg)


## CVE-2024-56433
 shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.

- [https://github.com/JonnyWhatshisface/CVE-2024-56433](https://github.com/JonnyWhatshisface/CVE-2024-56433) :  ![starts](https://img.shields.io/github/stars/JonnyWhatshisface/CVE-2024-56433.svg) ![forks](https://img.shields.io/github/forks/JonnyWhatshisface/CVE-2024-56433.svg)


## CVE-2024-56431
 oc_huff_tree_unpack in huffdec.c in libtheora in Theora through 1.0 7180717 has an invalid negative left shift.

- [https://github.com/UnionTech-Software/libtheora-CVE-2024-56431-PoC](https://github.com/UnionTech-Software/libtheora-CVE-2024-56431-PoC) :  ![starts](https://img.shields.io/github/stars/UnionTech-Software/libtheora-CVE-2024-56431-PoC.svg) ![forks](https://img.shields.io/github/forks/UnionTech-Software/libtheora-CVE-2024-56431-PoC.svg)


## CVE-2024-56337
Tomcat 11.0.3, 10.1.35 and 9.0.99 onwards will include checks that sun.io.useCanonCaches is set appropriately before allowing the default servlet to be write enabled on a case insensitive file system. Tomcat will also set sun.io.useCanonCaches to false by default where it can.

- [https://github.com/SleepingBag945/CVE-2024-50379](https://github.com/SleepingBag945/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/SleepingBag945/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/SleepingBag945/CVE-2024-50379.svg)


## CVE-2024-56331
 Uptime Kuma is an open source, self-hosted monitoring tool. An **Improper URL Handling Vulnerability** allows an attacker to access sensitive local files on the server by exploiting the `file:///` protocol. This vulnerability is triggered via the **"real-browser"** request type, which takes a screenshot of the URL provided by the attacker. By supplying local file paths, such as `file:///etc/passwd`, an attacker can read sensitive data from the server. This vulnerability arises because the system does not properly validate or sanitize the user input for the URL field. Specifically: 1. The URL input (`input data-v-5f5c86d7="" id="url" type="url" class="form-control" pattern="https?://.+" required=""`) allows users to input arbitrary file paths, including those using the `file:///` protocol, without server-side validation. 2. The server then uses the user-provided URL to make a request, passing it to a browser instance that performs the "real-browser" request, which takes a screenshot of the content at the given URL. If a local file path is entered (e.g., `file:///etc/passwd`), the browser fetches and captures the file’s content. Since the user input is not validated, an attacker can manipulate the URL to request local files (e.g., `file:///etc/passwd`), and the system will capture a screenshot of the file's content, potentially exposing sensitive data. Any **authenticated user** who can submit a URL in "real-browser" mode is at risk of exposing sensitive data through screenshots of these files. This issue has been addressed in version 1.23.16 and all users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/griisemine/CVE-2024-56331](https://github.com/griisemine/CVE-2024-56331) :  ![starts](https://img.shields.io/github/stars/griisemine/CVE-2024-56331.svg) ![forks](https://img.shields.io/github/forks/griisemine/CVE-2024-56331.svg)


## CVE-2024-56289
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Groundhogg Inc. Groundhogg allows Reflected XSS.This issue affects Groundhogg: from n/a through 3.7.3.3.

- [https://github.com/DoTTak/CVE-2024-56289](https://github.com/DoTTak/CVE-2024-56289) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2024-56289.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2024-56289.svg)


## CVE-2024-56278
 Improper Control of Generation of Code ('Code Injection') vulnerability in Smackcoders WP Ultimate Exporter allows PHP Remote File Inclusion.This issue affects WP Ultimate Exporter: from n/a through 2.9.1.

- [https://github.com/DoTTak/CVE-2024-56278](https://github.com/DoTTak/CVE-2024-56278) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2024-56278.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2024-56278.svg)


## CVE-2024-56145
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Users of affected versions are affected by this vulnerability if their php.ini configuration has `register_argc_argv` enabled. For these users an unspecified remote code execution vector is present. Users are advised to update to version 3.9.14, 4.13.2, or 5.5.2. Users unable to upgrade should disable `register_argc_argv` to mitigate the issue.

- [https://github.com/Chocapikk/CVE-2024-56145](https://github.com/Chocapikk/CVE-2024-56145) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-56145.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-56145.svg)
- [https://github.com/Sachinart/CVE-2024-56145-craftcms-rce](https://github.com/Sachinart/CVE-2024-56145-craftcms-rce) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2024-56145-craftcms-rce.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2024-56145-craftcms-rce.svg)


## CVE-2024-56116
 A Cross-Site Request Forgery vulnerability in Amiro.CMS before 7.8.4 allows remote attackers to create an administrator account.

- [https://github.com/ComplianceControl/CVE-2024-56116](https://github.com/ComplianceControl/CVE-2024-56116) :  ![starts](https://img.shields.io/github/stars/ComplianceControl/CVE-2024-56116.svg) ![forks](https://img.shields.io/github/forks/ComplianceControl/CVE-2024-56116.svg)


## CVE-2024-56115
 A vulnerability in Amiro.CMS before 7.8.4 exists due to the failure to take measures to neutralize special elements. It allows remote attackers to conduct a Cross-Site Scripting (XSS) attack.

- [https://github.com/ComplianceControl/CVE-2024-56115](https://github.com/ComplianceControl/CVE-2024-56115) :  ![starts](https://img.shields.io/github/stars/ComplianceControl/CVE-2024-56115.svg) ![forks](https://img.shields.io/github/forks/ComplianceControl/CVE-2024-56115.svg)


## CVE-2024-55988
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Amol Nirmala Waman Navayan CSV Export allows Blind SQL Injection.This issue affects Navayan CSV Export: from n/a through 1.0.9.

- [https://github.com/RandomRobbieBF/CVE-2024-55988](https://github.com/RandomRobbieBF/CVE-2024-55988) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55988.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55988.svg)


## CVE-2024-55982
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in richteam Share Buttons – Social Media allows Blind SQL Injection.This issue affects Share Buttons – Social Media: from n/a through 1.0.2.

- [https://github.com/RandomRobbieBF/CVE-2024-55982](https://github.com/RandomRobbieBF/CVE-2024-55982) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55982.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55982.svg)


## CVE-2024-55981
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Nabajit Roy Nabz Image Gallery allows SQL Injection.This issue affects Nabz Image Gallery: from n/a through v1.00.

- [https://github.com/RandomRobbieBF/CVE-2024-55981](https://github.com/RandomRobbieBF/CVE-2024-55981) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55981.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55981.svg)


## CVE-2024-55980
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Webriderz Wr Age Verification allows SQL Injection.This issue affects Wr Age Verification: from n/a through 2.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-55980](https://github.com/RandomRobbieBF/CVE-2024-55980) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55980.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55980.svg)


## CVE-2024-55978
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WalletStation.com Code Generator Pro allows SQL Injection.This issue affects Code Generator Pro: from n/a through 1.2.

- [https://github.com/RandomRobbieBF/CVE-2024-55978](https://github.com/RandomRobbieBF/CVE-2024-55978) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55978.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55978.svg)


## CVE-2024-55976
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Mike Leembruggen Critical Site Intel allows SQL Injection.This issue affects Critical Site Intel: from n/a through 1.0.

- [https://github.com/RandomRobbieBF/CVE-2024-55976](https://github.com/RandomRobbieBF/CVE-2024-55976) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55976.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55976.svg)


## CVE-2024-55972
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Chris Carvache eTemplates allows SQL Injection.This issue affects eTemplates: from n/a through 0.2.1.

- [https://github.com/RandomRobbieBF/CVE-2024-55972](https://github.com/RandomRobbieBF/CVE-2024-55972) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-55972.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-55972.svg)


## CVE-2024-55875
 http4k is a functional toolkit for Kotlin HTTP applications. Prior to version 5.41.0.0, there is a potential XXE (XML External Entity Injection) vulnerability when http4k handling malicious XML contents within requests, which might allow attackers to read local sensitive information on server, trigger Server-side Request Forgery and even execute code under some circumstances. Version 5.41.0.0 contains a patch for the issue.

- [https://github.com/JAckLosingHeart/CVE-2024-55875](https://github.com/JAckLosingHeart/CVE-2024-55875) :  ![starts](https://img.shields.io/github/stars/JAckLosingHeart/CVE-2024-55875.svg) ![forks](https://img.shields.io/github/forks/JAckLosingHeart/CVE-2024-55875.svg)


## CVE-2024-55587
 python-libarchive through 4.2.1 allows directory traversal (to create files) in extract in zip.py for ZipFile.extractall and ZipFile.extract.

- [https://github.com/CSIRTTrizna/CVE-2024-55587](https://github.com/CSIRTTrizna/CVE-2024-55587) :  ![starts](https://img.shields.io/github/stars/CSIRTTrizna/CVE-2024-55587.svg) ![forks](https://img.shields.io/github/forks/CSIRTTrizna/CVE-2024-55587.svg)


## CVE-2024-55557
 ui/pref/ProxyPrefView.java in weasis-core in Weasis 4.5.1 has a hardcoded key for symmetric encryption of proxy credentials.

- [https://github.com/partywavesec/CVE-2024-55557](https://github.com/partywavesec/CVE-2024-55557) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2024-55557.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2024-55557.svg)


## CVE-2024-55099
 A SQL Injection vulnerability was found in /admin/index.php in phpgurukul Online Nurse Hiring System v1.0, which allows remote attackers to execute arbitrary SQL commands to get unauthorized database access via the username parameter.

- [https://github.com/ugurkarakoc1/CVE-2024-55099-Online-Nurse-Hiring-System-v1.0-SQL-Injection-Vulnerability-](https://github.com/ugurkarakoc1/CVE-2024-55099-Online-Nurse-Hiring-System-v1.0-SQL-Injection-Vulnerability-) :  ![starts](https://img.shields.io/github/stars/ugurkarakoc1/CVE-2024-55099-Online-Nurse-Hiring-System-v1.0-SQL-Injection-Vulnerability-.svg) ![forks](https://img.shields.io/github/forks/ugurkarakoc1/CVE-2024-55099-Online-Nurse-Hiring-System-v1.0-SQL-Injection-Vulnerability-.svg)


## CVE-2024-54819
 I, Librarian before and including 5.11.1 is vulnerable to Server-Side Request Forgery (SSRF) due to improper input validation in classes/security/validation.php

- [https://github.com/partywavesec/CVE-2024-54819](https://github.com/partywavesec/CVE-2024-54819) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2024-54819.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2024-54819.svg)


## CVE-2024-54761
 BigAnt Office Messenger 5.6.06 is vulnerable to SQL Injection via the 'dev_code' parameter.

- [https://github.com/nscan9/CVE-2024-54761-BigAnt-Office-Messenger-5.6.06-RCE-via-SQL-Injection](https://github.com/nscan9/CVE-2024-54761-BigAnt-Office-Messenger-5.6.06-RCE-via-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/nscan9/CVE-2024-54761-BigAnt-Office-Messenger-5.6.06-RCE-via-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/nscan9/CVE-2024-54761-BigAnt-Office-Messenger-5.6.06-RCE-via-SQL-Injection.svg)


## CVE-2024-54679
 CyberPanel (aka Cyber Panel) before 6778ad1 does not require the FilemanagerAdmin capability for restartMySQL actions.

- [https://github.com/hotplugin0x01/CVE-2024-54679](https://github.com/hotplugin0x01/CVE-2024-54679) :  ![starts](https://img.shields.io/github/stars/hotplugin0x01/CVE-2024-54679.svg) ![forks](https://img.shields.io/github/forks/hotplugin0x01/CVE-2024-54679.svg)


## CVE-2024-54498
 A path handling issue was addressed with improved validation. This issue is fixed in macOS Sequoia 15.2, macOS Ventura 13.7.2, macOS Sonoma 14.7.2. An app may be able to break out of its sandbox.

- [https://github.com/wh1te4ever/CVE-2024-54498-PoC](https://github.com/wh1te4ever/CVE-2024-54498-PoC) :  ![starts](https://img.shields.io/github/stars/wh1te4ever/CVE-2024-54498-PoC.svg) ![forks](https://img.shields.io/github/forks/wh1te4ever/CVE-2024-54498-PoC.svg)


## CVE-2024-54385
 Server-Side Request Forgery (SSRF) vulnerability in SoftLab Radio Player allows Server Side Request Forgery.This issue affects Radio Player: from n/a through 2.0.82.

- [https://github.com/RandomRobbieBF/CVE-2024-54385](https://github.com/RandomRobbieBF/CVE-2024-54385) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54385.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54385.svg)


## CVE-2024-54378
 Missing Authorization vulnerability in Quietly Quietly Insights allows Privilege Escalation.This issue affects Quietly Insights: from n/a through 1.2.2.

- [https://github.com/RandomRobbieBF/CVE-2024-54378](https://github.com/RandomRobbieBF/CVE-2024-54378) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54378.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54378.svg)


## CVE-2024-54374
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Sabri Taieb Sogrid allows PHP Local File Inclusion.This issue affects Sogrid: from n/a through 1.5.6.

- [https://github.com/RandomRobbieBF/CVE-2024-54374](https://github.com/RandomRobbieBF/CVE-2024-54374) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54374.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54374.svg)


## CVE-2024-54369
 Missing Authorization vulnerability in ThemeHunk Zita Site Builder allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects Zita Site Builder: from n/a through 1.0.2.

- [https://github.com/RandomRobbieBF/CVE-2024-54369](https://github.com/RandomRobbieBF/CVE-2024-54369) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54369.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54369.svg)


## CVE-2024-54363
 Incorrect Privilege Assignment vulnerability in nssTheme Wp NssUser Register allows Privilege Escalation.This issue affects Wp NssUser Register: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-54363](https://github.com/RandomRobbieBF/CVE-2024-54363) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54363.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54363.svg)


## CVE-2024-54330
 Server-Side Request Forgery (SSRF) vulnerability in Hep Hep Hurra (HHH) Hurrakify allows Server Side Request Forgery.This issue affects Hurrakify: from n/a through 2.4.

- [https://github.com/RandomRobbieBF/CVE-2024-54330](https://github.com/RandomRobbieBF/CVE-2024-54330) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54330.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54330.svg)


## CVE-2024-54262
 Unrestricted Upload of File with Dangerous Type vulnerability in Siddharth Nagar Import Export For WooCommerce allows Upload a Web Shell to a Web Server.This issue affects Import Export For WooCommerce: from n/a through 1.5.

- [https://github.com/RandomRobbieBF/CVE-2024-54262](https://github.com/RandomRobbieBF/CVE-2024-54262) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54262.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54262.svg)


## CVE-2024-54152
 Angular Expressions provides expressions for the Angular.JS web framework as a standalone module. Prior to version 1.4.3, an attacker can write a malicious expression that escapes the sandbox to execute arbitrary code on the system. With a more complex (undisclosed) payload, one can get full access to Arbitrary code execution on the system. The problem has been patched in version 1.4.3 of Angular Expressions. Two possible workarounds are available. One may either disable access to `__proto__` globally or make sure that one uses the function with just one argument.

- [https://github.com/math-x-io/CVE-2024-54152-poc](https://github.com/math-x-io/CVE-2024-54152-poc) :  ![starts](https://img.shields.io/github/stars/math-x-io/CVE-2024-54152-poc.svg) ![forks](https://img.shields.io/github/forks/math-x-io/CVE-2024-54152-poc.svg)


## CVE-2024-53677
You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067

- [https://github.com/TAM-K592/CVE-2024-53677-S2-067](https://github.com/TAM-K592/CVE-2024-53677-S2-067) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-53677-S2-067.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-53677-S2-067.svg)
- [https://github.com/cloudwafs/s2-067-CVE-2024-53677](https://github.com/cloudwafs/s2-067-CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/cloudwafs/s2-067-CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/cloudwafs/s2-067-CVE-2024-53677.svg)
- [https://github.com/XiaomingX/CVE-2024-53677-S2-067](https://github.com/XiaomingX/CVE-2024-53677-S2-067) :  ![starts](https://img.shields.io/github/stars/XiaomingX/CVE-2024-53677-S2-067.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/CVE-2024-53677-S2-067.svg)
- [https://github.com/EQSTLab/CVE-2024-53677](https://github.com/EQSTLab/CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-53677.svg)
- [https://github.com/c4oocO/CVE-2024-53677-Docker](https://github.com/c4oocO/CVE-2024-53677-Docker) :  ![starts](https://img.shields.io/github/stars/c4oocO/CVE-2024-53677-Docker.svg) ![forks](https://img.shields.io/github/forks/c4oocO/CVE-2024-53677-Docker.svg)
- [https://github.com/dustblessnotdust/CVE-2024-53677-S2-067-thread](https://github.com/dustblessnotdust/CVE-2024-53677-S2-067-thread) :  ![starts](https://img.shields.io/github/stars/dustblessnotdust/CVE-2024-53677-S2-067-thread.svg) ![forks](https://img.shields.io/github/forks/dustblessnotdust/CVE-2024-53677-S2-067-thread.svg)
- [https://github.com/yangyanglo/CVE-2024-53677](https://github.com/yangyanglo/CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/yangyanglo/CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/yangyanglo/CVE-2024-53677.svg)
- [https://github.com/Q0LT/VM-CVE-2024-53677](https://github.com/Q0LT/VM-CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/Q0LT/VM-CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/Q0LT/VM-CVE-2024-53677.svg)
- [https://github.com/0xdeviner/CVE-2024-53677](https://github.com/0xdeviner/CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/0xdeviner/CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/0xdeviner/CVE-2024-53677.svg)
- [https://github.com/0xPThree/struts_cve-2024-53677](https://github.com/0xPThree/struts_cve-2024-53677) :  ![starts](https://img.shields.io/github/stars/0xPThree/struts_cve-2024-53677.svg) ![forks](https://img.shields.io/github/forks/0xPThree/struts_cve-2024-53677.svg)
- [https://github.com/punitdarji/Apache-struts-cve-2024-53677](https://github.com/punitdarji/Apache-struts-cve-2024-53677) :  ![starts](https://img.shields.io/github/stars/punitdarji/Apache-struts-cve-2024-53677.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Apache-struts-cve-2024-53677.svg)


## CVE-2024-53617
 A Cross Site Scripting vulnerability in LibrePhotos before commit 32237 allows attackers to takeover any account via uploading an HTML file on behalf of the admin user using IDOR in file upload.

- [https://github.com/ii5mai1/CVE-2024-53617](https://github.com/ii5mai1/CVE-2024-53617) :  ![starts](https://img.shields.io/github/stars/ii5mai1/CVE-2024-53617.svg) ![forks](https://img.shields.io/github/forks/ii5mai1/CVE-2024-53617.svg)


## CVE-2024-53522
 Bangkok Medical Software HOSxP XE v4.64.11.3 was discovered to contain a hardcoded IDEA Key-IV pair in the HOSxPXE4.exe and HOS-WIN32.INI components. This allows attackers to access sensitive information.

- [https://github.com/Safecloudth/CVE-2024-53522](https://github.com/Safecloudth/CVE-2024-53522) :  ![starts](https://img.shields.io/github/stars/Safecloudth/CVE-2024-53522.svg) ![forks](https://img.shields.io/github/forks/Safecloudth/CVE-2024-53522.svg)


## CVE-2024-53476
 A race condition vulnerability in SimplCommerce at commit 230310c8d7a0408569b292c5a805c459d47a1d8f allows attackers to bypass inventory restrictions by simultaneously submitting purchase requests from multiple accounts for the same product. This can lead to overselling when stock is limited, as the system fails to accurately track inventory under high concurrency, resulting in potential loss and unfulfilled orders.

- [https://github.com/AbdullahAlmutawa/CVE-2024-53476](https://github.com/AbdullahAlmutawa/CVE-2024-53476) :  ![starts](https://img.shields.io/github/stars/AbdullahAlmutawa/CVE-2024-53476.svg) ![forks](https://img.shields.io/github/forks/AbdullahAlmutawa/CVE-2024-53476.svg)


## CVE-2024-53376
 CyberPanel before 2.3.8 allows remote authenticated users to execute arbitrary commands via shell metacharacters in the phpSelection field to the websites/submitWebsiteCreation URI.

- [https://github.com/ThottySploity/CVE-2024-53376](https://github.com/ThottySploity/CVE-2024-53376) :  ![starts](https://img.shields.io/github/stars/ThottySploity/CVE-2024-53376.svg) ![forks](https://img.shields.io/github/forks/ThottySploity/CVE-2024-53376.svg)


## CVE-2024-53375
 An Authenticated Remote Code Execution (RCE) vulnerability affects the TP-Link Archer router series. A vulnerability exists in the "tmp_get_sites" function of the HomeShield functionality provided by TP-Link. This vulnerability is still exploitable without the activation of the HomeShield functionality.

- [https://github.com/ThottySploity/CVE-2024-53375](https://github.com/ThottySploity/CVE-2024-53375) :  ![starts](https://img.shields.io/github/stars/ThottySploity/CVE-2024-53375.svg) ![forks](https://img.shields.io/github/forks/ThottySploity/CVE-2024-53375.svg)


## CVE-2024-53345
 An authenticated arbitrary file upload vulnerability in Car Rental Management System v1.0 to v1.3 allows attackers to execute arbitrary code via uploading a crafted file.

- [https://github.com/ShadowByte1/CVE-2024-53345](https://github.com/ShadowByte1/CVE-2024-53345) :  ![starts](https://img.shields.io/github/stars/ShadowByte1/CVE-2024-53345.svg) ![forks](https://img.shields.io/github/forks/ShadowByte1/CVE-2024-53345.svg)


## CVE-2024-53259
 quic-go is an implementation of the QUIC protocol in Go. An off-path attacker can inject an ICMP Packet Too Large packet. Since affected quic-go versions used IP_PMTUDISC_DO, the kernel would then return a "message too large" error on sendmsg, i.e. when quic-go attempts to send a packet that exceeds the MTU claimed in that ICMP packet. By setting this value to smaller than 1200 bytes (the minimum MTU for QUIC), the attacker can disrupt a QUIC connection. Crucially, this can be done after completion of the handshake, thereby circumventing any TCP fallback that might be implemented on the application layer (for example, many browsers fall back to HTTP over TCP if they're unable to establish a QUIC connection). The attacker needs to at least know the client's IP and port tuple to mount an attack. This vulnerability is fixed in 0.48.2.

- [https://github.com/kota-yata/cve-2024-53259](https://github.com/kota-yata/cve-2024-53259) :  ![starts](https://img.shields.io/github/stars/kota-yata/cve-2024-53259.svg) ![forks](https://img.shields.io/github/forks/kota-yata/cve-2024-53259.svg)


## CVE-2024-53255
 BoidCMS is a free and open-source flat file CMS for building simple websites and blogs, developed using PHP and uses JSON as a database. In affected versions a reflected Cross-site Scripting (XSS) vulnerability exists in the /admin?page=media endpoint in the file parameter, allowing an attacker to inject arbitrary JavaScript code. This code could be used to steal the user's session cookie, perform phishing attacks, or deface the website. This issue has been addressed in version 2.1.2 and all users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/0x4M3R/CVE-2024-53255](https://github.com/0x4M3R/CVE-2024-53255) :  ![starts](https://img.shields.io/github/stars/0x4M3R/CVE-2024-53255.svg) ![forks](https://img.shields.io/github/forks/0x4M3R/CVE-2024-53255.svg)


## CVE-2024-52940
 AnyDesk through 8.1.0 on Windows, when Allow Direct Connections is enabled, inadvertently exposes a public IP address within network traffic. The attacker must know the victim's AnyDesk ID.

- [https://github.com/ebrasha/abdal-anydesk-remote-ip-detector](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector) :  ![starts](https://img.shields.io/github/stars/ebrasha/abdal-anydesk-remote-ip-detector.svg) ![forks](https://img.shields.io/github/forks/ebrasha/abdal-anydesk-remote-ip-detector.svg)
- [https://github.com/MKultra6969/AnySniff](https://github.com/MKultra6969/AnySniff) :  ![starts](https://img.shields.io/github/stars/MKultra6969/AnySniff.svg) ![forks](https://img.shields.io/github/forks/MKultra6969/AnySniff.svg)


## CVE-2024-52800
 veraPDF is an open source PDF/A validation library. Executing policy checks using custom schematron files via the CLI invokes an XSL transformation that may theoretically lead to a remote code execution (RCE) vulnerability. This doesn't affect the standard validation and policy checks functionality, veraPDF's common use cases. Most veraPDF users don't insert any custom XSLT code into policy profiles, which are based on Schematron syntax rather than direct XSL transforms. For users who do, only load custom policy files from sources you trust. This issue has not yet been patched. Users are advised to be cautious of XSLT code until a patch is available.

- [https://github.com/JAckLosingHeart/GHSA-4cx5-89vm-833x-POC](https://github.com/JAckLosingHeart/GHSA-4cx5-89vm-833x-POC) :  ![starts](https://img.shields.io/github/stars/JAckLosingHeart/GHSA-4cx5-89vm-833x-POC.svg) ![forks](https://img.shields.io/github/forks/JAckLosingHeart/GHSA-4cx5-89vm-833x-POC.svg)


## CVE-2024-52711
 DI-8100 v16.07.26A1 is vulnerable to Buffer Overflow In the ip_position_asp function via the ip parameter.

- [https://github.com/14mb1v45h/cyberspace-CVE-2024-52711](https://github.com/14mb1v45h/cyberspace-CVE-2024-52711) :  ![starts](https://img.shields.io/github/stars/14mb1v45h/cyberspace-CVE-2024-52711.svg) ![forks](https://img.shields.io/github/forks/14mb1v45h/cyberspace-CVE-2024-52711.svg)


## CVE-2024-52475
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Automation Web Platform Wawp allows Authentication Bypass.This issue affects Wawp: from n/a before 3.0.18.

- [https://github.com/ubaii/CVE-2024-52475](https://github.com/ubaii/CVE-2024-52475) :  ![starts](https://img.shields.io/github/stars/ubaii/CVE-2024-52475.svg) ![forks](https://img.shields.io/github/forks/ubaii/CVE-2024-52475.svg)


## CVE-2024-52433
 Deserialization of Untrusted Data vulnerability in Mindstien Technologies My Geo Posts Free allows Object Injection.This issue affects My Geo Posts Free: from n/a through 1.2.

- [https://github.com/RandomRobbieBF/CVE-2024-52433](https://github.com/RandomRobbieBF/CVE-2024-52433) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52433.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52433.svg)


## CVE-2024-52430
 Deserialization of Untrusted Data vulnerability in Lis Lis Video Gallery allows Object Injection.This issue affects Lis Video Gallery: from n/a through 0.2.1.

- [https://github.com/RandomRobbieBF/CVE-2024-52430](https://github.com/RandomRobbieBF/CVE-2024-52430) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52430.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52430.svg)


## CVE-2024-52429
 Unrestricted Upload of File with Dangerous Type vulnerability in Anton Hoelstad WP Quick Setup allows Upload a Web Shell to a Web Server.This issue affects WP Quick Setup: from n/a through 2.0.

- [https://github.com/RandomRobbieBF/CVE-2024-52429](https://github.com/RandomRobbieBF/CVE-2024-52429) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52429.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52429.svg)


## CVE-2024-52382
 Missing Authorization vulnerability in Medma Technologies Matix Popup Builder allows Privilege Escalation.This issue affects Matix Popup Builder: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-52382](https://github.com/RandomRobbieBF/CVE-2024-52382) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52382.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52382.svg)


## CVE-2024-52380
 Unrestricted Upload of File with Dangerous Type vulnerability in Softpulse Infotech Picsmize allows Upload a Web Shell to a Web Server.This issue affects Picsmize: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-52380](https://github.com/RandomRobbieBF/CVE-2024-52380) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52380.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52380.svg)
- [https://github.com/0xshoriful/CVE-2024-52380](https://github.com/0xshoriful/CVE-2024-52380) :  ![starts](https://img.shields.io/github/stars/0xshoriful/CVE-2024-52380.svg) ![forks](https://img.shields.io/github/forks/0xshoriful/CVE-2024-52380.svg)


## CVE-2024-52318
Users are recommended to upgrade to version 11.0.1, 10.1.32 or 9.0.97, which fixes the issue.

- [https://github.com/TAM-K592/CVE-2024-52318](https://github.com/TAM-K592/CVE-2024-52318) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-52318.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-52318.svg)


## CVE-2024-52317
Users are recommended to upgrade to version 11.0.0, 10.1.31 or 9.0.96, which fixes the issue.

- [https://github.com/TAM-K592/CVE-2024-52317](https://github.com/TAM-K592/CVE-2024-52317) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-52317.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-52317.svg)


## CVE-2024-52316
Users are recommended to upgrade to version 11.0.0, 10.1.31 or 9.0.96, which fix the issue.

- [https://github.com/TAM-K592/CVE-2024-52316](https://github.com/TAM-K592/CVE-2024-52316) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-52316.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-52316.svg)


## CVE-2024-52302
 common-user-management is a robust Spring Boot application featuring user management services designed to control user access dynamically. There is a critical security vulnerability in the application endpoint /api/v1/customer/profile-picture. This endpoint allows file uploads without proper validation or restrictions, enabling attackers to upload malicious files that can lead to Remote Code Execution (RCE).

- [https://github.com/d3sca/CVE-2024-52302](https://github.com/d3sca/CVE-2024-52302) :  ![starts](https://img.shields.io/github/stars/d3sca/CVE-2024-52302.svg) ![forks](https://img.shields.io/github/forks/d3sca/CVE-2024-52302.svg)


## CVE-2024-52301
 Laravel is a web application framework. When the register_argc_argv php directive is set to on , and users call any URL with a special crafted query string, they are able to change the environment used by the framework when handling the request. The vulnerability fixed in 6.20.45, 7.30.7, 8.83.28, 9.52.17, 10.48.23, and 11.31.0. The framework now ignores argv values for environment detection on non-cli SAPIs.

- [https://github.com/Nyamort/CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301) :  ![starts](https://img.shields.io/github/stars/Nyamort/CVE-2024-52301.svg) ![forks](https://img.shields.io/github/forks/Nyamort/CVE-2024-52301.svg)
- [https://github.com/nanwinata/CVE-2024-52301](https://github.com/nanwinata/CVE-2024-52301) :  ![starts](https://img.shields.io/github/stars/nanwinata/CVE-2024-52301.svg) ![forks](https://img.shields.io/github/forks/nanwinata/CVE-2024-52301.svg)
- [https://github.com/martinhaunschmid/CVE-2024-52301-Research](https://github.com/martinhaunschmid/CVE-2024-52301-Research) :  ![starts](https://img.shields.io/github/stars/martinhaunschmid/CVE-2024-52301-Research.svg) ![forks](https://img.shields.io/github/forks/martinhaunschmid/CVE-2024-52301-Research.svg)


## CVE-2024-52033
 Exposure of sensitive system information to an unauthorized control sphere issue exists in Rakuten Turbo 5G firmware version V1.3.18 and earlier. If this vulnerability is exploited, a remote unauthenticated attacker may obtain information of the other devices connected through the Wi-Fi.

- [https://github.com/0xNslabs/Rakuten5GTurboAPI](https://github.com/0xNslabs/Rakuten5GTurboAPI) :  ![starts](https://img.shields.io/github/stars/0xNslabs/Rakuten5GTurboAPI.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/Rakuten5GTurboAPI.svg)


## CVE-2024-52002
 Combodo iTop is a simple, web based IT Service Management tool. Several url endpoints are subject to a Cross-Site Request Forgery (CSRF) vulnerability. Please refer to the linked GHSA for the complete list. This issue has been addressed in version 3.2.0 and all users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Harshit-Mashru/iTop-CVEs-exploit](https://github.com/Harshit-Mashru/iTop-CVEs-exploit) :  ![starts](https://img.shields.io/github/stars/Harshit-Mashru/iTop-CVEs-exploit.svg) ![forks](https://img.shields.io/github/forks/Harshit-Mashru/iTop-CVEs-exploit.svg)


## CVE-2024-51747
 Kanboard is project management software that focuses on the Kanban methodology. An authenticated Kanboard admin can read and delete arbitrary files from the server. File attachments, that are viewable or downloadable in Kanboard are resolved through its `path` entry in the `project_has_files`  SQLite db. Thus, an attacker who can upload a modified sqlite.db through the dedicated feature, can set arbitrary file links, by abusing path traversals. Once the modified db is uploaded and the project page is accessed, a file download can be triggered and all files, readable in the context of the Kanboard application permissions, can be downloaded. This issue has been addressed in version 1.2.42 and all users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/l20170217b/CVE-2024-51747](https://github.com/l20170217b/CVE-2024-51747) :  ![starts](https://img.shields.io/github/stars/l20170217b/CVE-2024-51747.svg) ![forks](https://img.shields.io/github/forks/l20170217b/CVE-2024-51747.svg)


## CVE-2024-51665
 Server-Side Request Forgery (SSRF) vulnerability in Noor alam Magical Addons For Elementor allows Server Side Request Forgery.This issue affects Magical Addons For Elementor: from n/a through 1.2.1.

- [https://github.com/RandomRobbieBF/CVE-2024-51665](https://github.com/RandomRobbieBF/CVE-2024-51665) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-51665.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-51665.svg)


## CVE-2024-51567
 upgrademysqlstatus in databases/views.py in CyberPanel (aka Cyber Panel) before 5b08cd6 allows remote attackers to bypass authentication and execute arbitrary commands via /dataBases/upgrademysqlstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

- [https://github.com/XiaomingX/cve-2024-51567-poc](https://github.com/XiaomingX/cve-2024-51567-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-51567-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-51567-poc.svg)
- [https://github.com/ajayalf/CVE-2024-51567](https://github.com/ajayalf/CVE-2024-51567) :  ![starts](https://img.shields.io/github/stars/ajayalf/CVE-2024-51567.svg) ![forks](https://img.shields.io/github/forks/ajayalf/CVE-2024-51567.svg)
- [https://github.com/thehash007/CVE-2024-51567-RCE-EXPLOIT](https://github.com/thehash007/CVE-2024-51567-RCE-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/thehash007/CVE-2024-51567-RCE-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/thehash007/CVE-2024-51567-RCE-EXPLOIT.svg)


## CVE-2024-51442
 Command Injection in Minidlna version v1.3.3 and before allows an attacker to execute arbitrary OS commands via a specially crafted minidlna.conf configuration file.

- [https://github.com/mselbrede/CVE-2024-51442](https://github.com/mselbrede/CVE-2024-51442) :  ![starts](https://img.shields.io/github/stars/mselbrede/CVE-2024-51442.svg) ![forks](https://img.shields.io/github/forks/mselbrede/CVE-2024-51442.svg)


## CVE-2024-51430
 Cross Site Scripting vulnerability in online diagnostic lab management system using php v.1.0 allows a remote attacker to execute arbitrary code via the Test Name parameter on the diagnostic/add-test.php component.

- [https://github.com/BLACK-SCORP10/CVE-2024-51430](https://github.com/BLACK-SCORP10/CVE-2024-51430) :  ![starts](https://img.shields.io/github/stars/BLACK-SCORP10/CVE-2024-51430.svg) ![forks](https://img.shields.io/github/forks/BLACK-SCORP10/CVE-2024-51430.svg)


## CVE-2024-51378
 getresetstatus in dns/views.py and ftp/views.py in CyberPanel (aka Cyber Panel) before 1c0c6cb allows remote attackers to bypass authentication and execute arbitrary commands via /dns/getresetstatus or /ftp/getresetstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

- [https://github.com/refr4g/CVE-2024-51378](https://github.com/refr4g/CVE-2024-51378) :  ![starts](https://img.shields.io/github/stars/refr4g/CVE-2024-51378.svg) ![forks](https://img.shields.io/github/forks/refr4g/CVE-2024-51378.svg)
- [https://github.com/i0x29A/CVE-2024-51378](https://github.com/i0x29A/CVE-2024-51378) :  ![starts](https://img.shields.io/github/stars/i0x29A/CVE-2024-51378.svg) ![forks](https://img.shields.io/github/forks/i0x29A/CVE-2024-51378.svg)


## CVE-2024-51358
 An issue in Linux Server Heimdall v.2.6.1 allows a remote attacker to execute arbitrary code via a crafted script to the Add new application.

- [https://github.com/Kov404/CVE-2024-51358](https://github.com/Kov404/CVE-2024-51358) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2024-51358.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2024-51358.svg)


## CVE-2024-51228
 An issue in TOTOLINK-CX-A3002RU V1.0.4-B20171106.1512 and TOTOLINK-CX-N150RT V2.1.6-B20171121.1002 and TOTOLINK-CX-N300RT V2.1.6-B20170724.1420 and TOTOLINK-CX-N300RT V2.1.8-B20171113.1408 and TOTOLINK-CX-N300RT V2.1.8-B20191010.1107 and TOTOLINK-CX-N302RE V2.0.2-B20170511.1523 allows a remote attacker to execute arbitrary code via the /boafrm/formSysCmd component.

- [https://github.com/tequilasunsh1ne/CVE_2024_51228](https://github.com/tequilasunsh1ne/CVE_2024_51228) :  ![starts](https://img.shields.io/github/stars/tequilasunsh1ne/CVE_2024_51228.svg) ![forks](https://img.shields.io/github/forks/tequilasunsh1ne/CVE_2024_51228.svg)


## CVE-2024-51179
 An issue in Open 5GS v.2.7.1 allows a remote attacker to cause a denial of service via the Network Function Virtualizations (NFVs) such as the User Plane Function (UPF) and the Session Management Function (SMF), The Packet Data Unit (PDU) session establishment process.

- [https://github.com/Lakshmirnr/CVE-2024-51179](https://github.com/Lakshmirnr/CVE-2024-51179) :  ![starts](https://img.shields.io/github/stars/Lakshmirnr/CVE-2024-51179.svg) ![forks](https://img.shields.io/github/forks/Lakshmirnr/CVE-2024-51179.svg)


## CVE-2024-51132
 An XML External Entity (XXE) vulnerability in HAPI FHIR before v6.4.0 allows attackers to access sensitive information or execute arbitrary code via supplying a crafted request containing malicious XML entities.

- [https://github.com/JAckLosingHeart/CVE-2024-51132-POC](https://github.com/JAckLosingHeart/CVE-2024-51132-POC) :  ![starts](https://img.shields.io/github/stars/JAckLosingHeart/CVE-2024-51132-POC.svg) ![forks](https://img.shields.io/github/forks/JAckLosingHeart/CVE-2024-51132-POC.svg)


## CVE-2024-51032
 A Cross-site Scripting (XSS) vulnerability in manage_recipient.php of Sourcecodester Toll Tax Management System 1.0 allows remote authenticated users to inject arbitrary web scripts via the "owner" input field.

- [https://github.com/Shree-Chandragiri/CVE-2024-51032](https://github.com/Shree-Chandragiri/CVE-2024-51032) :  ![starts](https://img.shields.io/github/stars/Shree-Chandragiri/CVE-2024-51032.svg) ![forks](https://img.shields.io/github/forks/Shree-Chandragiri/CVE-2024-51032.svg)


## CVE-2024-51031
 A Cross-site Scripting (XSS) vulnerability in manage_account.php in Sourcecodester Cab Management System 1.0 allows remote authenticated users to inject arbitrary web scripts via the "First Name," "Middle Name," and "Last Name" fields.

- [https://github.com/vighneshnair7/CVE-2024-51031](https://github.com/vighneshnair7/CVE-2024-51031) :  ![starts](https://img.shields.io/github/stars/vighneshnair7/CVE-2024-51031.svg) ![forks](https://img.shields.io/github/forks/vighneshnair7/CVE-2024-51031.svg)


## CVE-2024-51030
 A SQL injection vulnerability in manage_client.php and view_cab.php of Sourcecodester Cab Management System 1.0 allows remote attackers to execute arbitrary SQL commands via the id parameter, leading to unauthorized access and potential compromise of sensitive data within the database.

- [https://github.com/vighneshnair7/CVE-2024-51030](https://github.com/vighneshnair7/CVE-2024-51030) :  ![starts](https://img.shields.io/github/stars/vighneshnair7/CVE-2024-51030.svg) ![forks](https://img.shields.io/github/forks/vighneshnair7/CVE-2024-51030.svg)


## CVE-2024-51026
 The NetAdmin IAM system (version 4.0.30319) has a Cross Site Scripting (XSS) vulnerability in the /BalloonSave.ashx endpoint, where it is possible to inject a malicious payload into the Content= field.

- [https://github.com/BrotherOfJhonny/CVE-2024-51026_Overview](https://github.com/BrotherOfJhonny/CVE-2024-51026_Overview) :  ![starts](https://img.shields.io/github/stars/BrotherOfJhonny/CVE-2024-51026_Overview.svg) ![forks](https://img.shields.io/github/forks/BrotherOfJhonny/CVE-2024-51026_Overview.svg)


## CVE-2024-50986
 An issue in Clementine v.1.3.1 allows a local attacker to execute arbitrary code via a crafted DLL file.

- [https://github.com/riftsandroses/CVE-2024-50986](https://github.com/riftsandroses/CVE-2024-50986) :  ![starts](https://img.shields.io/github/stars/riftsandroses/CVE-2024-50986.svg) ![forks](https://img.shields.io/github/forks/riftsandroses/CVE-2024-50986.svg)


## CVE-2024-50972
 A SQL injection vulnerability in printtool.php of Itsourcecode Construction Management System 1.0 allows remote attackers to execute arbitrary SQL commands via the borrow_id parameter.

- [https://github.com/Akhlak2511/CVE-2024-50972](https://github.com/Akhlak2511/CVE-2024-50972) :  ![starts](https://img.shields.io/github/stars/Akhlak2511/CVE-2024-50972.svg) ![forks](https://img.shields.io/github/forks/Akhlak2511/CVE-2024-50972.svg)


## CVE-2024-50971
 A SQL injection vulnerability in print.php of Itsourcecode Construction Management System 1.0 allows remote attackers to execute arbitrary SQL commands via the map_id parameter.

- [https://github.com/Akhlak2511/CVE-2024-50971](https://github.com/Akhlak2511/CVE-2024-50971) :  ![starts](https://img.shields.io/github/stars/Akhlak2511/CVE-2024-50971.svg) ![forks](https://img.shields.io/github/forks/Akhlak2511/CVE-2024-50971.svg)


## CVE-2024-50970
 A SQL injection vulnerability in orderview1.php of Itsourcecode Online Furniture Shopping Project 1.0 allows remote attackers to execute arbitrary SQL commands via the id parameter.

- [https://github.com/Akhlak2511/CVE-2024-50970](https://github.com/Akhlak2511/CVE-2024-50970) :  ![starts](https://img.shields.io/github/stars/Akhlak2511/CVE-2024-50970.svg) ![forks](https://img.shields.io/github/forks/Akhlak2511/CVE-2024-50970.svg)


## CVE-2024-50969
 A Reflected cross-site scripting (XSS) vulnerability in browse.php of Code-projects Jonnys Liquor 1.0 allows remote attackers to inject arbitrary web scripts or HTML via the search parameter.

- [https://github.com/Akhlak2511/CVE-2024-50969](https://github.com/Akhlak2511/CVE-2024-50969) :  ![starts](https://img.shields.io/github/stars/Akhlak2511/CVE-2024-50969.svg) ![forks](https://img.shields.io/github/forks/Akhlak2511/CVE-2024-50969.svg)


## CVE-2024-50968
 A business logic vulnerability exists in the Add to Cart function of itsourcecode Agri-Trading Online Shopping System 1.0, which allows remote attackers to manipulate the quant parameter when adding a product to the cart. By setting the quantity value to -0, an attacker can exploit a flaw in the application's total price calculation logic. This vulnerability causes the total price to be reduced to zero, allowing the attacker to add items to the cart and proceed to checkout.

- [https://github.com/Akhlak2511/CVE-2024-50968](https://github.com/Akhlak2511/CVE-2024-50968) :  ![starts](https://img.shields.io/github/stars/Akhlak2511/CVE-2024-50968.svg) ![forks](https://img.shields.io/github/forks/Akhlak2511/CVE-2024-50968.svg)


## CVE-2024-50945
 An improper access control vulnerability exists in SimplCommerce at commit 230310c8d7a0408569b292c5a805c459d47a1d8f, allowing users to submit reviews without verifying if they have purchased the product.

- [https://github.com/AbdullahAlmutawa/CVE-2024-50945](https://github.com/AbdullahAlmutawa/CVE-2024-50945) :  ![starts](https://img.shields.io/github/stars/AbdullahAlmutawa/CVE-2024-50945.svg) ![forks](https://img.shields.io/github/forks/AbdullahAlmutawa/CVE-2024-50945.svg)


## CVE-2024-50944
 Integer overflow vulnerability exists in SimplCommerce at commit 230310c8d7a0408569b292c5a805c459d47a1d8f in the shopping cart functionality. The issue lies in the quantity parameter in the CartController's AddToCart method.

- [https://github.com/AbdullahAlmutawa/CVE-2024-50944](https://github.com/AbdullahAlmutawa/CVE-2024-50944) :  ![starts](https://img.shields.io/github/stars/AbdullahAlmutawa/CVE-2024-50944.svg) ![forks](https://img.shields.io/github/forks/AbdullahAlmutawa/CVE-2024-50944.svg)


## CVE-2024-50849
 A Stored Cross-Site Scripting (XSS) vulnerability in the "Rules" functionality of WorldServer v11.8.2 allows a remote authenticated attacker to execute arbitrary JavaScript code.

- [https://github.com/Wh1teSnak3/CVE-2024-50849](https://github.com/Wh1teSnak3/CVE-2024-50849) :  ![starts](https://img.shields.io/github/stars/Wh1teSnak3/CVE-2024-50849.svg) ![forks](https://img.shields.io/github/forks/Wh1teSnak3/CVE-2024-50849.svg)


## CVE-2024-50848
 An XML External Entity (XXE) vulnerability in the Import object and Translation Memory import functionalities of WorldServer v11.8.2 to access sensitive information and execute arbitrary commands via supplying a crafted .tmx file.

- [https://github.com/Wh1teSnak3/CVE-2024-50848](https://github.com/Wh1teSnak3/CVE-2024-50848) :  ![starts](https://img.shields.io/github/stars/Wh1teSnak3/CVE-2024-50848.svg) ![forks](https://img.shields.io/github/forks/Wh1teSnak3/CVE-2024-50848.svg)


## CVE-2024-50804
 Insecure Permissions vulnerability in Micro-star International MSI Center Pro 2.1.37.0 allows a local attacker to execute arbitrary code via the Device_DeviceID.dat.bak file within the C:\ProgramData\MSI\One Dragon Center\Data folder

- [https://github.com/g3tsyst3m/CVE-2024-50804](https://github.com/g3tsyst3m/CVE-2024-50804) :  ![starts](https://img.shields.io/github/stars/g3tsyst3m/CVE-2024-50804.svg) ![forks](https://img.shields.io/github/forks/g3tsyst3m/CVE-2024-50804.svg)


## CVE-2024-50803
 The mediapool feature of the Redaxo Core CMS application v 5.17.1 is vulnerable to Cross Site Scripting(XSS) which allows a remote attacker to escalate privileges

- [https://github.com/Praison001/CVE-2024-50803-Redaxo](https://github.com/Praison001/CVE-2024-50803-Redaxo) :  ![starts](https://img.shields.io/github/stars/Praison001/CVE-2024-50803-Redaxo.svg) ![forks](https://img.shields.io/github/forks/Praison001/CVE-2024-50803-Redaxo.svg)


## CVE-2024-50677
 A cross-site scripting (XSS) vulnerability in OroPlatform CMS v5.1 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Search parameter.

- [https://github.com/ZumiYumi/CVE-2024-50677](https://github.com/ZumiYumi/CVE-2024-50677) :  ![starts](https://img.shields.io/github/stars/ZumiYumi/CVE-2024-50677.svg) ![forks](https://img.shields.io/github/forks/ZumiYumi/CVE-2024-50677.svg)


## CVE-2024-50657
 An issue in Owncloud android apk v.4.3.1 allows a physically proximate attacker to escalate privileges via the PassCodeViewModel class, specifically in the checkPassCodeIsValid method

- [https://github.com/SAHALLL/CVE-2024-50657](https://github.com/SAHALLL/CVE-2024-50657) :  ![starts](https://img.shields.io/github/stars/SAHALLL/CVE-2024-50657.svg) ![forks](https://img.shields.io/github/forks/SAHALLL/CVE-2024-50657.svg)


## CVE-2024-50623
 In Cleo Harmony before 5.8.0.21, VLTrader before 5.8.0.21, and LexiCom before 5.8.0.21, there is an unrestricted file upload and download that could lead to remote code execution.

- [https://github.com/watchtowrlabs/CVE-2024-50623](https://github.com/watchtowrlabs/CVE-2024-50623) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2024-50623.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2024-50623.svg)
- [https://github.com/verylazytech/CVE-2024-50623](https://github.com/verylazytech/CVE-2024-50623) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-50623.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-50623.svg)
- [https://github.com/iSee857/Cleo-CVE-2024-50623-PoC](https://github.com/iSee857/Cleo-CVE-2024-50623-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/Cleo-CVE-2024-50623-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/Cleo-CVE-2024-50623-PoC.svg)


## CVE-2024-50603
 An issue was discovered in Aviatrix Controller before 7.1.4191 and 7.2.x before 7.2.4996. Due to the improper neutralization of special elements used in an OS command, an unauthenticated attacker is able to execute arbitrary code. Shell metacharacters can be sent to /v1/api in cloud_type for list_flightpath_destination_instances, or src_cloud_type for flightpath_connection_test.

- [https://github.com/newlinesec/CVE-2024-50603](https://github.com/newlinesec/CVE-2024-50603) :  ![starts](https://img.shields.io/github/stars/newlinesec/CVE-2024-50603.svg) ![forks](https://img.shields.io/github/forks/newlinesec/CVE-2024-50603.svg)


## CVE-2024-50510
 Unrestricted Upload of File with Dangerous Type vulnerability in Web and Print Design AR For Woocommerce allows Upload a Web Shell to a Web Server.This issue affects AR For Woocommerce: from n/a through 6.2.

- [https://github.com/RandomRobbieBF/CVE-2024-50510](https://github.com/RandomRobbieBF/CVE-2024-50510) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50510.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50510.svg)


## CVE-2024-50509
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Chetan Khandla Woocommerce Product Design allows Path Traversal.This issue affects Woocommerce Product Design: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-50509](https://github.com/RandomRobbieBF/CVE-2024-50509) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50509.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50509.svg)


## CVE-2024-50508
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Chetan Khandla Woocommerce Product Design allows Path Traversal.This issue affects Woocommerce Product Design: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-50508](https://github.com/RandomRobbieBF/CVE-2024-50508) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50508.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50508.svg)


## CVE-2024-50507
 Deserialization of Untrusted Data vulnerability in Daniel Schmitzer DS.DownloadList allows Object Injection.This issue affects DS.DownloadList: from n/a through 1.3.

- [https://github.com/RandomRobbieBF/CVE-2024-50507](https://github.com/RandomRobbieBF/CVE-2024-50507) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50507.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50507.svg)


## CVE-2024-50498
 Improper Control of Generation of Code ('Code Injection') vulnerability in LUBUS WP Query Console allows Code Injection.This issue affects WP Query Console: from n/a through 1.0.

- [https://github.com/RandomRobbieBF/CVE-2024-50498](https://github.com/RandomRobbieBF/CVE-2024-50498) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50498.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50498.svg)
- [https://github.com/p0et08/CVE-2024-50498](https://github.com/p0et08/CVE-2024-50498) :  ![starts](https://img.shields.io/github/stars/p0et08/CVE-2024-50498.svg) ![forks](https://img.shields.io/github/forks/p0et08/CVE-2024-50498.svg)
- [https://github.com/Nxploited/CVE-2024-50498](https://github.com/Nxploited/CVE-2024-50498) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-50498.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-50498.svg)


## CVE-2024-50493
 Unrestricted Upload of File with Dangerous Type vulnerability in masterhomepage Automatic Translation allows Upload a Web Shell to a Web Server.This issue affects Automatic Translation: from n/a through 1.0.4.

- [https://github.com/RandomRobbieBF/CVE-2024-50493](https://github.com/RandomRobbieBF/CVE-2024-50493) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50493.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50493.svg)


## CVE-2024-50490
 Missing Authorization vulnerability in Szabolcs Szecsenyi PegaPoll allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects PegaPoll: from n/a through 1.0.2.

- [https://github.com/RandomRobbieBF/CVE-2024-50490](https://github.com/RandomRobbieBF/CVE-2024-50490) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50490.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50490.svg)


## CVE-2024-50488
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Priyabrata Sarkar Token Login allows Authentication Bypass.This issue affects Token Login: from n/a through 1.0.3.

- [https://github.com/RandomRobbieBF/CVE-2024-50488](https://github.com/RandomRobbieBF/CVE-2024-50488) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50488.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50488.svg)


## CVE-2024-50485
 : Incorrect Privilege Assignment vulnerability in Udit Rawat Exam Matrix allows Privilege Escalation.This issue affects Exam Matrix: from n/a through 1.5.

- [https://github.com/RandomRobbieBF/CVE-2024-50485](https://github.com/RandomRobbieBF/CVE-2024-50485) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50485.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50485.svg)


## CVE-2024-50483
 Authorization Bypass Through User-Controlled Key vulnerability in Meetup allows Privilege Escalation.This issue affects Meetup: from n/a through 0.1.

- [https://github.com/RandomRobbieBF/CVE-2024-50483](https://github.com/RandomRobbieBF/CVE-2024-50483) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50483.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50483.svg)


## CVE-2024-50482
 Unrestricted Upload of File with Dangerous Type vulnerability in Chetan Khandla Woocommerce Product Design allows Upload a Web Shell to a Web Server.This issue affects Woocommerce Product Design: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-50482](https://github.com/RandomRobbieBF/CVE-2024-50482) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50482.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50482.svg)


## CVE-2024-50478
 Authentication Bypass by Primary Weakness vulnerability in Swoop 1-Click Login: Passwordless Authentication allows Authentication Bypass.This issue affects 1-Click Login: Passwordless Authentication: 1.4.5.

- [https://github.com/RandomRobbieBF/CVE-2024-50478](https://github.com/RandomRobbieBF/CVE-2024-50478) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50478.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50478.svg)


## CVE-2024-50477
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Stacks Stacks Mobile App Builder stacks-mobile-app-builder allows Authentication Bypass.This issue affects Stacks Mobile App Builder: from n/a through 5.2.3.

- [https://github.com/RandomRobbieBF/CVE-2024-50477](https://github.com/RandomRobbieBF/CVE-2024-50477) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50477.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50477.svg)


## CVE-2024-50476
 Missing Authorization vulnerability in GRÜN Software Group GmbH GRÜN spendino Spendenformular allows Privilege Escalation.This issue affects GRÜN spendino Spendenformular: from n/a through 1.0.1.

- [https://github.com/RandomRobbieBF/CVE-2024-50476](https://github.com/RandomRobbieBF/CVE-2024-50476) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50476.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50476.svg)


## CVE-2024-50475
 Missing Authorization vulnerability in Scott Gamon Signup Page allows Privilege Escalation.This issue affects Signup Page: from n/a through 1.0.

- [https://github.com/RandomRobbieBF/CVE-2024-50475](https://github.com/RandomRobbieBF/CVE-2024-50475) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50475.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50475.svg)


## CVE-2024-50473
 Unrestricted Upload of File with Dangerous Type vulnerability in Ajar Productions Ajar in5 Embed allows Upload a Web Shell to a Web Server.This issue affects Ajar in5 Embed: from n/a through 3.1.3.

- [https://github.com/RandomRobbieBF/CVE-2024-50473](https://github.com/RandomRobbieBF/CVE-2024-50473) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50473.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50473.svg)


## CVE-2024-50450
 Improper Control of Generation of Code ('Code Injection') vulnerability in realmag777 WordPress Meta Data and Taxonomies Filter (MDTF) allows Code Injection.This issue affects WordPress Meta Data and Taxonomies Filter (MDTF): from n/a through 1.3.3.4.

- [https://github.com/RandomRobbieBF/CVE-2024-50450](https://github.com/RandomRobbieBF/CVE-2024-50450) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50450.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50450.svg)


## CVE-2024-50427
 Unrestricted Upload of File with Dangerous Type vulnerability in Devsoft Baltic OÜ SurveyJS: Drag & Drop WordPress Form Builder.This issue affects SurveyJS: Drag & Drop WordPress Form Builder: from n/a through 1.9.136.

- [https://github.com/RandomRobbieBF/CVE-2024-50427](https://github.com/RandomRobbieBF/CVE-2024-50427) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50427.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50427.svg)


## CVE-2024-50395
Media Streaming add-on 500.1.1.6 ( 2024/08/02 ) and later

- [https://github.com/neko-hat/CVE-2024-50395](https://github.com/neko-hat/CVE-2024-50395) :  ![starts](https://img.shields.io/github/stars/neko-hat/CVE-2024-50395.svg) ![forks](https://img.shields.io/github/forks/neko-hat/CVE-2024-50395.svg)


## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/SleepingBag945/CVE-2024-50379](https://github.com/SleepingBag945/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/SleepingBag945/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/SleepingBag945/CVE-2024-50379.svg)
- [https://github.com/ph0ebus/Tomcat-CVE-2024-50379-Poc](https://github.com/ph0ebus/Tomcat-CVE-2024-50379-Poc) :  ![starts](https://img.shields.io/github/stars/ph0ebus/Tomcat-CVE-2024-50379-Poc.svg) ![forks](https://img.shields.io/github/forks/ph0ebus/Tomcat-CVE-2024-50379-Poc.svg)
- [https://github.com/iSee857/CVE-2024-50379-PoC](https://github.com/iSee857/CVE-2024-50379-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2024-50379-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2024-50379-PoC.svg)
- [https://github.com/lizhianyuguangming/CVE-2024-50379-exp](https://github.com/lizhianyuguangming/CVE-2024-50379-exp) :  ![starts](https://img.shields.io/github/stars/lizhianyuguangming/CVE-2024-50379-exp.svg) ![forks](https://img.shields.io/github/forks/lizhianyuguangming/CVE-2024-50379-exp.svg)
- [https://github.com/JFOZ1010/Nuclei-Template-CVE-2024-50379](https://github.com/JFOZ1010/Nuclei-Template-CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/JFOZ1010/Nuclei-Template-CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/JFOZ1010/Nuclei-Template-CVE-2024-50379.svg)
- [https://github.com/yiliufeng168/CVE-2024-50379-POC](https://github.com/yiliufeng168/CVE-2024-50379-POC) :  ![starts](https://img.shields.io/github/stars/yiliufeng168/CVE-2024-50379-POC.svg) ![forks](https://img.shields.io/github/forks/yiliufeng168/CVE-2024-50379-POC.svg)
- [https://github.com/v3153/CVE-2024-50379-POC](https://github.com/v3153/CVE-2024-50379-POC) :  ![starts](https://img.shields.io/github/stars/v3153/CVE-2024-50379-POC.svg) ![forks](https://img.shields.io/github/forks/v3153/CVE-2024-50379-POC.svg)
- [https://github.com/dragonked2/CVE-2024-50379-POC](https://github.com/dragonked2/CVE-2024-50379-POC) :  ![starts](https://img.shields.io/github/stars/dragonked2/CVE-2024-50379-POC.svg) ![forks](https://img.shields.io/github/forks/dragonked2/CVE-2024-50379-POC.svg)
- [https://github.com/dear-cell/CVE-2024-50379](https://github.com/dear-cell/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/dear-cell/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/dear-cell/CVE-2024-50379.svg)
- [https://github.com/Alchemist3dot14/CVE-2024-50379](https://github.com/Alchemist3dot14/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/Alchemist3dot14/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/Alchemist3dot14/CVE-2024-50379.svg)
- [https://github.com/bigb0x/CVE-2024-50379](https://github.com/bigb0x/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-50379.svg)


## CVE-2024-50340
 symfony/runtime is a module for the Symphony PHP framework which enables decoupling PHP applications from global state. When the `register_argv_argc` php directive is set to `on` , and users call any URL with a special crafted query string, they are able to change the environment or debug mode used by the kernel when handling the request. As of versions 5.4.46, 6.4.14, and 7.1.7 the `SymfonyRuntime` now ignores the `argv` values for non-SAPI PHP runtimes. All users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Nyamort/CVE-2024-50340](https://github.com/Nyamort/CVE-2024-50340) :  ![starts](https://img.shields.io/github/stars/Nyamort/CVE-2024-50340.svg) ![forks](https://img.shields.io/github/forks/Nyamort/CVE-2024-50340.svg)


## CVE-2024-50335
 SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. The "Publish Key" field in SuiteCRM's Edit Profile page is vulnerable to Reflected Cross-Site Scripting (XSS), allowing an attacker to inject malicious JavaScript code. This can be exploited to steal CSRF tokens and perform unauthorized actions, such as creating new administrative users without proper authentication. The vulnerability arises due to insufficient input validation and sanitization of the Publish Key field within the SuiteCRM application. When an attacker injects a malicious script, it gets executed within the context of an authenticated user's session. The injected script (o.js) then leverages the captured CSRF token to forge requests that create new administrative users, effectively compromising the integrity and security of the CRM instance. This issue has been addressed in versions 7.14.6 and 8.7.1. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/shellkraft/CVE-2024-50335](https://github.com/shellkraft/CVE-2024-50335) :  ![starts](https://img.shields.io/github/stars/shellkraft/CVE-2024-50335.svg) ![forks](https://img.shields.io/github/forks/shellkraft/CVE-2024-50335.svg)


## CVE-2024-50251
length to be included in the checksum calculation is fully consumed.

- [https://github.com/slavin-ayu/CVE-2024-50251-PoC](https://github.com/slavin-ayu/CVE-2024-50251-PoC) :  ![starts](https://img.shields.io/github/stars/slavin-ayu/CVE-2024-50251-PoC.svg) ![forks](https://img.shields.io/github/forks/slavin-ayu/CVE-2024-50251-PoC.svg)


## CVE-2024-49681
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in SWIT WP Sessions Time Monitoring Full Automatic allows SQL Injection.This issue affects WP Sessions Time Monitoring Full Automatic: from n/a through 1.0.9.

- [https://github.com/RandomRobbieBF/CVE-2024-49681](https://github.com/RandomRobbieBF/CVE-2024-49681) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-49681.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-49681.svg)


## CVE-2024-49607
 Unrestricted Upload of File with Dangerous Type vulnerability in Redwan Hilali WP Dropbox Dropins allows Upload a Web Shell to a Web Server.This issue affects WP Dropbox Dropins: from n/a through 1.0.

- [https://github.com/RandomRobbieBF/CVE-2024-49607](https://github.com/RandomRobbieBF/CVE-2024-49607) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-49607.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-49607.svg)


## CVE-2024-49379
 Umbrel is a home server OS for self-hosting. The login functionality of Umbrel before version 1.2.2 contains a reflected cross-site scripting (XSS) vulnerability in use-auth.tsx. An attacker can specify a malicious redirect query parameter to trigger the vulnerability. If a JavaScript URL is passed to the redirect parameter the attacker provided JavaScript will be executed after the user entered their password and clicked on login. This vulnerability is fixed in 1.2.2.

- [https://github.com/OHDUDEOKNICE/CVE-2024-49379](https://github.com/OHDUDEOKNICE/CVE-2024-49379) :  ![starts](https://img.shields.io/github/stars/OHDUDEOKNICE/CVE-2024-49379.svg) ![forks](https://img.shields.io/github/forks/OHDUDEOKNICE/CVE-2024-49379.svg)


## CVE-2024-49369
 Icinga is a monitoring system which checks the availability of network resources, notifies users of outages, and generates performance data for reporting. The TLS certificate validation in all Icinga 2 versions starting from 2.4.0 was flawed, allowing an attacker to impersonate both trusted cluster nodes as well as any API users that use TLS client certificates for authentication (ApiUser objects with the client_cn attribute set). This vulnerability has been fixed in v2.14.3, v2.13.10, v2.12.11, and v2.11.12.

- [https://github.com/Quantum-Sicarius/CVE-2024-49369](https://github.com/Quantum-Sicarius/CVE-2024-49369) :  ![starts](https://img.shields.io/github/stars/Quantum-Sicarius/CVE-2024-49369.svg) ![forks](https://img.shields.io/github/forks/Quantum-Sicarius/CVE-2024-49369.svg)


## CVE-2024-49368
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.0.0-beta.36, when Nginx UI configures logrotate, it does not verify the input and directly passes it to exec.Command, causing arbitrary command execution. Version 2.0.0-beta.36 fixes this issue.

- [https://github.com/Aashay221999/CVE-2024-49368](https://github.com/Aashay221999/CVE-2024-49368) :  ![starts](https://img.shields.io/github/stars/Aashay221999/CVE-2024-49368.svg) ![forks](https://img.shields.io/github/forks/Aashay221999/CVE-2024-49368.svg)


## CVE-2024-49328
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Vivek Tamrakar WP REST API FNS allows Authentication Bypass.This issue affects WP REST API FNS: from n/a through 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-49328](https://github.com/RandomRobbieBF/CVE-2024-49328) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-49328.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-49328.svg)


## CVE-2024-49203
 Querydsl 5.1.0 and OpenFeign Querydsl 6.8 allows SQL/HQL injection in orderBy in JPAQuery.

- [https://github.com/CSIRTTrizna/CVE-2024-49203](https://github.com/CSIRTTrizna/CVE-2024-49203) :  ![starts](https://img.shields.io/github/stars/CSIRTTrizna/CVE-2024-49203.svg) ![forks](https://img.shields.io/github/forks/CSIRTTrizna/CVE-2024-49203.svg)


## CVE-2024-49124
 Lightweight Directory Access Protocol (LDAP) Client Remote Code Execution Vulnerability

- [https://github.com/mutkus/Microsoft-2024-December-Update-Control](https://github.com/mutkus/Microsoft-2024-December-Update-Control) :  ![starts](https://img.shields.io/github/stars/mutkus/Microsoft-2024-December-Update-Control.svg) ![forks](https://img.shields.io/github/forks/mutkus/Microsoft-2024-December-Update-Control.svg)


## CVE-2024-49122
 Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability

- [https://github.com/mutkus/Microsoft-2024-December-Update-Control](https://github.com/mutkus/Microsoft-2024-December-Update-Control) :  ![starts](https://img.shields.io/github/stars/mutkus/Microsoft-2024-December-Update-Control.svg) ![forks](https://img.shields.io/github/forks/mutkus/Microsoft-2024-December-Update-Control.svg)


## CVE-2024-49118
 Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability

- [https://github.com/mutkus/Microsoft-2024-December-Update-Control](https://github.com/mutkus/Microsoft-2024-December-Update-Control) :  ![starts](https://img.shields.io/github/stars/mutkus/Microsoft-2024-December-Update-Control.svg) ![forks](https://img.shields.io/github/forks/mutkus/Microsoft-2024-December-Update-Control.svg)


## CVE-2024-49117
 Windows Hyper-V Remote Code Execution Vulnerability

- [https://github.com/mutkus/Microsoft-2024-December-Update-Control](https://github.com/mutkus/Microsoft-2024-December-Update-Control) :  ![starts](https://img.shields.io/github/stars/mutkus/Microsoft-2024-December-Update-Control.svg) ![forks](https://img.shields.io/github/forks/mutkus/Microsoft-2024-December-Update-Control.svg)


## CVE-2024-49113
 Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability

- [https://github.com/SafeBreach-Labs/CVE-2024-49113](https://github.com/SafeBreach-Labs/CVE-2024-49113) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/CVE-2024-49113.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/CVE-2024-49113.svg)
- [https://github.com/barcrange/CVE-2024-49113-Checker](https://github.com/barcrange/CVE-2024-49113-Checker) :  ![starts](https://img.shields.io/github/stars/barcrange/CVE-2024-49113-Checker.svg) ![forks](https://img.shields.io/github/forks/barcrange/CVE-2024-49113-Checker.svg)
- [https://github.com/Sachinart/CVE-2024-49113-Checker](https://github.com/Sachinart/CVE-2024-49113-Checker) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2024-49113-Checker.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2024-49113-Checker.svg)


## CVE-2024-49112
 Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability

- [https://github.com/tnkr/poc_monitor](https://github.com/tnkr/poc_monitor) :  ![starts](https://img.shields.io/github/stars/tnkr/poc_monitor.svg) ![forks](https://img.shields.io/github/forks/tnkr/poc_monitor.svg)
- [https://github.com/CCIEVoice2009/CVE-2024-49112](https://github.com/CCIEVoice2009/CVE-2024-49112) :  ![starts](https://img.shields.io/github/stars/CCIEVoice2009/CVE-2024-49112.svg) ![forks](https://img.shields.io/github/forks/CCIEVoice2009/CVE-2024-49112.svg)
- [https://github.com/bo0l3an/CVE-2024-49112-PoC](https://github.com/bo0l3an/CVE-2024-49112-PoC) :  ![starts](https://img.shields.io/github/stars/bo0l3an/CVE-2024-49112-PoC.svg) ![forks](https://img.shields.io/github/forks/bo0l3an/CVE-2024-49112-PoC.svg)


## CVE-2024-49039
 Windows Task Scheduler Elevation of Privilege Vulnerability

- [https://github.com/je5442804/WPTaskScheduler_CVE-2024-49039](https://github.com/je5442804/WPTaskScheduler_CVE-2024-49039) :  ![starts](https://img.shields.io/github/stars/je5442804/WPTaskScheduler_CVE-2024-49039.svg) ![forks](https://img.shields.io/github/forks/je5442804/WPTaskScheduler_CVE-2024-49039.svg)
- [https://github.com/Alexandr-bit253/CVE-2024-49039](https://github.com/Alexandr-bit253/CVE-2024-49039) :  ![starts](https://img.shields.io/github/stars/Alexandr-bit253/CVE-2024-49039.svg) ![forks](https://img.shields.io/github/forks/Alexandr-bit253/CVE-2024-49039.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/makuga01/CVE-2024-48990-PoC](https://github.com/makuga01/CVE-2024-48990-PoC) :  ![starts](https://img.shields.io/github/stars/makuga01/CVE-2024-48990-PoC.svg) ![forks](https://img.shields.io/github/forks/makuga01/CVE-2024-48990-PoC.svg)
- [https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing](https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing) :  ![starts](https://img.shields.io/github/stars/pentestfunctions/CVE-2024-48990-PoC-Testing.svg) ![forks](https://img.shields.io/github/forks/pentestfunctions/CVE-2024-48990-PoC-Testing.svg)
- [https://github.com/ns989/CVE-2024-48990](https://github.com/ns989/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/ns989/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/ns989/CVE-2024-48990.svg)
- [https://github.com/Cyb3rFr0g/CVE-2024-48990-PoC](https://github.com/Cyb3rFr0g/CVE-2024-48990-PoC) :  ![starts](https://img.shields.io/github/stars/Cyb3rFr0g/CVE-2024-48990-PoC.svg) ![forks](https://img.shields.io/github/forks/Cyb3rFr0g/CVE-2024-48990-PoC.svg)
- [https://github.com/ally-petitt/CVE-2024-48990-Exploit](https://github.com/ally-petitt/CVE-2024-48990-Exploit) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2024-48990-Exploit.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2024-48990-Exploit.svg)
- [https://github.com/r0xdeadbeef/CVE-2024-48990](https://github.com/r0xdeadbeef/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/r0xdeadbeef/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/r0xdeadbeef/CVE-2024-48990.svg)
- [https://github.com/NullByte-7w7/CVE-2024-48990](https://github.com/NullByte-7w7/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/NullByte-7w7/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/NullByte-7w7/CVE-2024-48990.svg)
- [https://github.com/CyberCrowCC/CVE-2024-48990](https://github.com/CyberCrowCC/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/CyberCrowCC/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/CyberCrowCC/CVE-2024-48990.svg)
- [https://github.com/felmoltor/CVE-2024-48990](https://github.com/felmoltor/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/felmoltor/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/felmoltor/CVE-2024-48990.svg)


## CVE-2024-48955
 Broken access control in NetAdmin 4.030319 returns data with functionalities on the endpoint that "assembles" the functionalities menus, the return of this call is not encrypted and as the system does not validate the session authorization, an attacker can copy the content of the browser of a user with greater privileges having access to the functionalities of the user that the code was copied.

- [https://github.com/BrotherOfJhonny/CVE-2024-48955_Overview](https://github.com/BrotherOfJhonny/CVE-2024-48955_Overview) :  ![starts](https://img.shields.io/github/stars/BrotherOfJhonny/CVE-2024-48955_Overview.svg) ![forks](https://img.shields.io/github/forks/BrotherOfJhonny/CVE-2024-48955_Overview.svg)


## CVE-2024-48914
 Vendure is an open-source headless commerce platform. Prior to versions 3.0.5 and 2.3.3, a vulnerability in Vendure's asset server plugin allows an attacker to craft a request which is able to traverse the server file system and retrieve the contents of arbitrary files, including sensitive data such as configuration files, environment variables, and other critical data stored on the server. In the same code path is an additional vector for crashing the server via a malformed URI. Patches are available in versions 3.0.5 and 2.3.3. Some workarounds are also available. One may use object storage rather than the local file system, e.g. MinIO or S3, or define middleware which detects and blocks requests with urls containing `/../`.

- [https://github.com/EQSTLab/CVE-2024-48914](https://github.com/EQSTLab/CVE-2024-48914) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-48914.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-48914.svg)


## CVE-2024-48895
 Improper neutralization of special elements used in an OS command ('OS Command Injection') issue exists in Rakuten Turbo 5G firmware version V1.3.18 and earlier. If this vulnerability is exploited, a remote authenticated attacker may execute an arbitrary OS command.

- [https://github.com/0xNslabs/Rakuten5GTurboAPI](https://github.com/0xNslabs/Rakuten5GTurboAPI) :  ![starts](https://img.shields.io/github/stars/0xNslabs/Rakuten5GTurboAPI.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/Rakuten5GTurboAPI.svg)


## CVE-2024-48652
 Cross Site Scripting vulnerability in camaleon-cms v.2.7.5 allows remote attacker to execute arbitrary code via the content group name field.

- [https://github.com/paragbagul111/CVE-2024-48652](https://github.com/paragbagul111/CVE-2024-48652) :  ![starts](https://img.shields.io/github/stars/paragbagul111/CVE-2024-48652.svg) ![forks](https://img.shields.io/github/forks/paragbagul111/CVE-2024-48652.svg)


## CVE-2024-48644
 Accounts enumeration vulnerability in the Login Component of Reolink Duo 2 WiFi Camera (Firmware Version v3.0.0.1889_23031701) allows remote attackers to determine valid user accounts via login attempts. This can lead to the enumeration of user accounts and potentially facilitate other attacks, such as brute-forcing of passwords. The vulnerability arises from the application responding differently to login attempts with valid and invalid usernames.

- [https://github.com/rosembergpro/CVE-2024-48644](https://github.com/rosembergpro/CVE-2024-48644) :  ![starts](https://img.shields.io/github/stars/rosembergpro/CVE-2024-48644.svg) ![forks](https://img.shields.io/github/forks/rosembergpro/CVE-2024-48644.svg)


## CVE-2024-48605
 An issue in Helakuru Desktop Application v1.1 allows a local attacker to execute arbitrary code via the lack of proper validation of the wow64log.dll file.

- [https://github.com/surajhacx/HelakuruV.1.1-DLLHijack](https://github.com/surajhacx/HelakuruV.1.1-DLLHijack) :  ![starts](https://img.shields.io/github/stars/surajhacx/HelakuruV.1.1-DLLHijack.svg) ![forks](https://img.shields.io/github/forks/surajhacx/HelakuruV.1.1-DLLHijack.svg)


## CVE-2024-48569
 Proactive Risk Manager version 9.1.1.0 is affected by multiple Cross-Site Scripting (XSS) vulnerabilities in the add/edit form fields, at the urls starting with the subpaths: /ar/config/configuation/ and /ar/config/risk-strategy-control/

- [https://github.com/MarioTesoro/CVE-2024-48569](https://github.com/MarioTesoro/CVE-2024-48569) :  ![starts](https://img.shields.io/github/stars/MarioTesoro/CVE-2024-48569.svg) ![forks](https://img.shields.io/github/forks/MarioTesoro/CVE-2024-48569.svg)


## CVE-2024-48427
 A SQL injection vulnerability in Sourcecodester Packers and Movers Management System v1.0 allows remote authenticated users to execute arbitrary SQL commands via the id parameter in /mpms/admin/?page=services/manage_service&id

- [https://github.com/vighneshnair7/CVE-2024-48427](https://github.com/vighneshnair7/CVE-2024-48427) :  ![starts](https://img.shields.io/github/stars/vighneshnair7/CVE-2024-48427.svg) ![forks](https://img.shields.io/github/forks/vighneshnair7/CVE-2024-48427.svg)


## CVE-2024-48415
 itsourcecode Loan Management System v1.0 is vulnerable to Cross Site Scripting (XSS) via a crafted payload to the lastname, firstname, middlename, address, contact_no, email and tax_id parameters in new borrowers functionality on the Borrowers page.

- [https://github.com/khaliquesX/CVE-2024-48415](https://github.com/khaliquesX/CVE-2024-48415) :  ![starts](https://img.shields.io/github/stars/khaliquesX/CVE-2024-48415.svg) ![forks](https://img.shields.io/github/forks/khaliquesX/CVE-2024-48415.svg)


## CVE-2024-48360
 Qualitor v8.24 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /request/viewValidacao.php.

- [https://github.com/OpenXP-Research/CVE-2024-48360](https://github.com/OpenXP-Research/CVE-2024-48360) :  ![starts](https://img.shields.io/github/stars/OpenXP-Research/CVE-2024-48360.svg) ![forks](https://img.shields.io/github/forks/OpenXP-Research/CVE-2024-48360.svg)


## CVE-2024-48359
 Qualitor v8.24 was discovered to contain a remote code execution (RCE) vulnerability via the gridValoresPopHidden parameter.

- [https://github.com/OpenXP-Research/CVE-2024-48359](https://github.com/OpenXP-Research/CVE-2024-48359) :  ![starts](https://img.shields.io/github/stars/OpenXP-Research/CVE-2024-48359.svg) ![forks](https://img.shields.io/github/forks/OpenXP-Research/CVE-2024-48359.svg)


## CVE-2024-48336
 The install() function of ProviderInstaller.java in Magisk App before canary version 27007 does not verify the GMS app before loading it, which allows a local untrusted app with no additional privileges to silently execute arbitrary code in the Magisk app and escalate privileges to root via a crafted package, aka Bug #8279. User interaction is not needed for exploitation.

- [https://github.com/canyie/MagiskEoP](https://github.com/canyie/MagiskEoP) :  ![starts](https://img.shields.io/github/stars/canyie/MagiskEoP.svg) ![forks](https://img.shields.io/github/forks/canyie/MagiskEoP.svg)


## CVE-2024-48325
 Portabilis i-Educar 2.8.0 is vulnerable to SQL Injection in the "getDocuments" function of the "InstituicaoDocumentacaoController" class. The "instituicao_id" parameter in "/module/Api/InstituicaoDocumentacao?oper=get&resource=getDocuments&instituicao_id" is not properly sanitized, allowing an unauthenticated remote attacker to inject malicious SQL commands.

- [https://github.com/osvaldotenorio/cve-2024-48325](https://github.com/osvaldotenorio/cve-2024-48325) :  ![starts](https://img.shields.io/github/stars/osvaldotenorio/cve-2024-48325.svg) ![forks](https://img.shields.io/github/forks/osvaldotenorio/cve-2024-48325.svg)


## CVE-2024-48322
 UsersController.php in Run.codes 1.5.2 and older has a reset password race condition vulnerability.

- [https://github.com/trqt/CVE-2024-48322](https://github.com/trqt/CVE-2024-48322) :  ![starts](https://img.shields.io/github/stars/trqt/CVE-2024-48322.svg) ![forks](https://img.shields.io/github/forks/trqt/CVE-2024-48322.svg)


## CVE-2024-48245
 Vehicle Management System 1.0 is vulnerable to SQL Injection. A guest user can exploit vulnerable POST parameters in various administrative actions, such as booking a vehicle or confirming a booking. The affected parameters include "Booking ID", "Action Name", and "Payment Confirmation ID", which are present in /newvehicle.php and /newdriver.php.

- [https://github.com/ShadowByte1/CVE-2024-48245](https://github.com/ShadowByte1/CVE-2024-48245) :  ![starts](https://img.shields.io/github/stars/ShadowByte1/CVE-2024-48245.svg) ![forks](https://img.shields.io/github/forks/ShadowByte1/CVE-2024-48245.svg)


## CVE-2024-48217
 An Insecure Direct Object Reference (IDOR) in the dashboard of SiSMART v7.4.0 allows attackers to execute a horizontal-privilege escalation.

- [https://github.com/ajrielrm/CVE-2024-48217](https://github.com/ajrielrm/CVE-2024-48217) :  ![starts](https://img.shields.io/github/stars/ajrielrm/CVE-2024-48217.svg) ![forks](https://img.shields.io/github/forks/ajrielrm/CVE-2024-48217.svg)


## CVE-2024-48208
 pure-ftpd before 1.0.52 is vulnerable to Buffer Overflow. There is an out of bounds read in the domlsd() function of the ls.c file.

- [https://github.com/rohilchaudhry/CVE-2024-48208](https://github.com/rohilchaudhry/CVE-2024-48208) :  ![starts](https://img.shields.io/github/stars/rohilchaudhry/CVE-2024-48208.svg) ![forks](https://img.shields.io/github/forks/rohilchaudhry/CVE-2024-48208.svg)


## CVE-2024-48197
 Cross Site Scripting vulnerability in Audiocodes MP-202b v.4.4.3 allows a remote attacker to escalate privileges via the login page of the web interface.

- [https://github.com/GCatt-AS/CVE-2024-48197](https://github.com/GCatt-AS/CVE-2024-48197) :  ![starts](https://img.shields.io/github/stars/GCatt-AS/CVE-2024-48197.svg) ![forks](https://img.shields.io/github/forks/GCatt-AS/CVE-2024-48197.svg)


## CVE-2024-47865
 Missing authentication for critical function vulnerability exists in Rakuten Turbo 5G firmware version V1.3.18 and earlier. If this vulnerability is exploited, a remote unauthenticated attacker may update or downgrade the firmware on the device.

- [https://github.com/0xNslabs/Rakuten5GTurboAPI](https://github.com/0xNslabs/Rakuten5GTurboAPI) :  ![starts](https://img.shields.io/github/stars/0xNslabs/Rakuten5GTurboAPI.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/Rakuten5GTurboAPI.svg)


## CVE-2024-47854
 An XSS vulnerability was discovered in Veritas Data Insight before 7.1. It allows a remote attacker to inject an arbitrary web script into an HTTP request that could reflect back to an authenticated user without sanitization if executed by that user.

- [https://github.com/MarioTesoro/CVE-2024-47854](https://github.com/MarioTesoro/CVE-2024-47854) :  ![starts](https://img.shields.io/github/stars/MarioTesoro/CVE-2024-47854.svg) ![forks](https://img.shields.io/github/forks/MarioTesoro/CVE-2024-47854.svg)


## CVE-2024-47799
 Exposure of sensitive system information to an unauthorized control sphere issue exists in Mesh Wi-Fi router RP562B firmware version v1.0.2 and earlier. If this vulnerability is exploited, a network-adjacent authenticated attacker may obtain information of the other devices connected through the Wi-Fi.

- [https://github.com/0xNslabs/SoftBankMeshAPI](https://github.com/0xNslabs/SoftBankMeshAPI) :  ![starts](https://img.shields.io/github/stars/0xNslabs/SoftBankMeshAPI.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/SoftBankMeshAPI.svg)


## CVE-2024-47575
 A missing authentication for critical function in FortiManager 7.6.0, FortiManager 7.4.0 through 7.4.4, FortiManager 7.2.0 through 7.2.7, FortiManager 7.0.0 through 7.0.12, FortiManager 6.4.0 through 6.4.14, FortiManager 6.2.0 through 6.2.12, Fortinet FortiManager Cloud 7.4.1 through 7.4.4, FortiManager Cloud 7.2.1 through 7.2.7, FortiManager Cloud 7.0.1 through 7.0.12, FortiManager Cloud 6.4.1 through 6.4.7 allows attacker to execute arbitrary code or commands via specially crafted requests.

- [https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575](https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575.svg)
- [https://github.com/XiaomingX/cve-2024-47575-exp](https://github.com/XiaomingX/cve-2024-47575-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-47575-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-47575-exp.svg)
- [https://github.com/expl0itsecurity/CVE-2024-47575](https://github.com/expl0itsecurity/CVE-2024-47575) :  ![starts](https://img.shields.io/github/stars/expl0itsecurity/CVE-2024-47575.svg) ![forks](https://img.shields.io/github/forks/expl0itsecurity/CVE-2024-47575.svg)
- [https://github.com/skyalliance/exploit-cve-2024-47575](https://github.com/skyalliance/exploit-cve-2024-47575) :  ![starts](https://img.shields.io/github/stars/skyalliance/exploit-cve-2024-47575.svg) ![forks](https://img.shields.io/github/forks/skyalliance/exploit-cve-2024-47575.svg)
- [https://github.com/Laonhearts/CVE-2024-47575-POC](https://github.com/Laonhearts/CVE-2024-47575-POC) :  ![starts](https://img.shields.io/github/stars/Laonhearts/CVE-2024-47575-POC.svg) ![forks](https://img.shields.io/github/forks/Laonhearts/CVE-2024-47575-POC.svg)
- [https://github.com/krmxd/CVE-2024-47575](https://github.com/krmxd/CVE-2024-47575) :  ![starts](https://img.shields.io/github/stars/krmxd/CVE-2024-47575.svg) ![forks](https://img.shields.io/github/forks/krmxd/CVE-2024-47575.svg)


## CVE-2024-47177
 CUPS is a standards-based, open-source printing system, and cups-filters provides backends, filters, and other software for CUPS 2.x to use on non-Mac OS systems. Any value passed to `FoomaticRIPCommandLine` via a PPD file will be executed as a user controlled command. When combined with other logic bugs as described in CVE_2024-47176, this can lead to remote command execution.

- [https://github.com/referefref/cupspot-2024-47177](https://github.com/referefref/cupspot-2024-47177) :  ![starts](https://img.shields.io/github/stars/referefref/cupspot-2024-47177.svg) ![forks](https://img.shields.io/github/forks/referefref/cupspot-2024-47177.svg)
- [https://github.com/lkarlslund/jugular](https://github.com/lkarlslund/jugular) :  ![starts](https://img.shields.io/github/stars/lkarlslund/jugular.svg) ![forks](https://img.shields.io/github/forks/lkarlslund/jugular.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/MalwareTech/CVE-2024-47176-Scanner](https://github.com/MalwareTech/CVE-2024-47176-Scanner) :  ![starts](https://img.shields.io/github/stars/MalwareTech/CVE-2024-47176-Scanner.svg) ![forks](https://img.shields.io/github/forks/MalwareTech/CVE-2024-47176-Scanner.svg)
- [https://github.com/l0n3m4n/CVE-2024-47176](https://github.com/l0n3m4n/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-47176.svg)
- [https://github.com/mr-r3b00t/CVE-2024-47176](https://github.com/mr-r3b00t/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2024-47176.svg)
- [https://github.com/GO0dspeed/spill](https://github.com/GO0dspeed/spill) :  ![starts](https://img.shields.io/github/stars/GO0dspeed/spill.svg) ![forks](https://img.shields.io/github/forks/GO0dspeed/spill.svg)
- [https://github.com/lkarlslund/jugular](https://github.com/lkarlslund/jugular) :  ![starts](https://img.shields.io/github/stars/lkarlslund/jugular.svg) ![forks](https://img.shields.io/github/forks/lkarlslund/jugular.svg)
- [https://github.com/aytackalinci/CVE-2024-47176](https://github.com/aytackalinci/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/aytackalinci/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/aytackalinci/CVE-2024-47176.svg)
- [https://github.com/gianlu111/CUPS-CVE-2024-47176](https://github.com/gianlu111/CUPS-CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/gianlu111/CUPS-CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/gianlu111/CUPS-CVE-2024-47176.svg)
- [https://github.com/nma-io/CVE-2024-47176](https://github.com/nma-io/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/nma-io/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/nma-io/CVE-2024-47176.svg)
- [https://github.com/workabhiwin09/CVE-2024-47176](https://github.com/workabhiwin09/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/workabhiwin09/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/workabhiwin09/CVE-2024-47176.svg)
- [https://github.com/AxthonyV/CVE-2024-47176](https://github.com/AxthonyV/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/AxthonyV/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/AxthonyV/CVE-2024-47176.svg)
- [https://github.com/0x7556/CVE-2024-47176](https://github.com/0x7556/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2024-47176.svg)
- [https://github.com/gumerzzzindo/CVE-2024-47176](https://github.com/gumerzzzindo/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/gumerzzzindo/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/gumerzzzindo/CVE-2024-47176.svg)
- [https://github.com/tonyarris/CVE-2024-47176-Scanner](https://github.com/tonyarris/CVE-2024-47176-Scanner) :  ![starts](https://img.shields.io/github/stars/tonyarris/CVE-2024-47176-Scanner.svg) ![forks](https://img.shields.io/github/forks/tonyarris/CVE-2024-47176-Scanner.svg)


## CVE-2024-47175
 CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.

- [https://github.com/lkarlslund/jugular](https://github.com/lkarlslund/jugular) :  ![starts](https://img.shields.io/github/stars/lkarlslund/jugular.svg) ![forks](https://img.shields.io/github/forks/lkarlslund/jugular.svg)


## CVE-2024-47076
 CUPS is a standards-based, open-source printing system, and `libcupsfilters` contains the code of the filters of the former `cups-filters` package as library functions to be used for the data format conversion tasks needed in Printer Applications. The `cfGetPrinterAttributes5` function in `libcupsfilters` does not sanitize IPP attributes returned from an IPP server. When these IPP attributes are used, for instance, to generate a PPD file, this can lead to attacker controlled data to be provided to the rest of the CUPS system.

- [https://github.com/lkarlslund/jugular](https://github.com/lkarlslund/jugular) :  ![starts](https://img.shields.io/github/stars/lkarlslund/jugular.svg) ![forks](https://img.shields.io/github/forks/lkarlslund/jugular.svg)
- [https://github.com/mutkus/CVE-2024-47076](https://github.com/mutkus/CVE-2024-47076) :  ![starts](https://img.shields.io/github/stars/mutkus/CVE-2024-47076.svg) ![forks](https://img.shields.io/github/forks/mutkus/CVE-2024-47076.svg)


## CVE-2024-47066
 Lobe Chat is an open-source artificial intelligence chat framework. Prior to version 1.19.13, server-side request forgery protection implemented in `src/app/api/proxy/route.ts` does not consider redirect and could be bypassed when attacker provides an external malicious URL which redirects to internal resources like a private network or loopback address. Version 1.19.13 contains an improved fix for the issue.

- [https://github.com/l8BL/CVE-2024-47066](https://github.com/l8BL/CVE-2024-47066) :  ![starts](https://img.shields.io/github/stars/l8BL/CVE-2024-47066.svg) ![forks](https://img.shields.io/github/forks/l8BL/CVE-2024-47066.svg)


## CVE-2024-47062
 Navidrome is an open source web-based music collection server and streamer. Navidrome automatically adds parameters in the URL to SQL queries. This can be exploited to access information by adding parameters like `password=...` in the URL (ORM Leak). Furthermore, the names of the parameters are not properly escaped, leading to SQL Injections. Finally, the username is used in a `LIKE` statement, allowing people to log in with `%` instead of their username. When adding parameters to the URL, they are automatically included in an SQL `LIKE` statement (depending on the parameter's name). This allows attackers to potentially retrieve arbitrary information. For example, attackers can use the following request to test whether some encrypted passwords start with `AAA`. This results in an SQL query like `password LIKE 'AAA%'`, allowing attackers to slowly brute-force passwords. When adding parameters to the URL, they are automatically added to an SQL query. The names of the parameters are not properly escaped. This behavior can be used to inject arbitrary SQL code (SQL Injection). These vulnerabilities can be used to leak information and dump the contents of the database and have been addressed in release version 0.53.0. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/saisathvik1/CVE-2024-47062](https://github.com/saisathvik1/CVE-2024-47062) :  ![starts](https://img.shields.io/github/stars/saisathvik1/CVE-2024-47062.svg) ![forks](https://img.shields.io/github/forks/saisathvik1/CVE-2024-47062.svg)


## CVE-2024-46986
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. An arbitrary file write vulnerability accessible via the upload method of the MediaController allows authenticated users to write arbitrary files to any location on the web server Camaleon CMS is running on (depending on the permissions of the underlying filesystem). E.g. This can lead to a delayed remote code execution in case an attacker is able to write a Ruby file into the config/initializers/ subfolder of the Ruby on Rails application. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/vidura2/CVE-2024-46986](https://github.com/vidura2/CVE-2024-46986) :  ![starts](https://img.shields.io/github/stars/vidura2/CVE-2024-46986.svg) ![forks](https://img.shields.io/github/forks/vidura2/CVE-2024-46986.svg)


## CVE-2024-46982
 Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, & 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.

- [https://github.com/CodePontiff/next_js_poisoning](https://github.com/CodePontiff/next_js_poisoning) :  ![starts](https://img.shields.io/github/stars/CodePontiff/next_js_poisoning.svg) ![forks](https://img.shields.io/github/forks/CodePontiff/next_js_poisoning.svg)


## CVE-2024-46901
Repositories served via other access methods are not affected.

- [https://github.com/devhaozi/CVE-2024-46901](https://github.com/devhaozi/CVE-2024-46901) :  ![starts](https://img.shields.io/github/stars/devhaozi/CVE-2024-46901.svg) ![forks](https://img.shields.io/github/forks/devhaozi/CVE-2024-46901.svg)


## CVE-2024-46658
 Syrotech SY-GOPON-8OLT-L3 v1.6.0_240629 was discovered to contain an authenticated command injection vulnerability.

- [https://github.com/jackalkarlos/CVE-2024-46658](https://github.com/jackalkarlos/CVE-2024-46658) :  ![starts](https://img.shields.io/github/stars/jackalkarlos/CVE-2024-46658.svg) ![forks](https://img.shields.io/github/forks/jackalkarlos/CVE-2024-46658.svg)


## CVE-2024-46635
 An issue in the API endpoint /AccountMaster/GetCurrentUserInfo of INROAD before v202402060 allows attackers to access sensitive information via a crafted payload to the UserNameOrPhoneNumber parameter.

- [https://github.com/h1thub/CVE-2024-46635](https://github.com/h1thub/CVE-2024-46635) :  ![starts](https://img.shields.io/github/stars/h1thub/CVE-2024-46635.svg) ![forks](https://img.shields.io/github/forks/h1thub/CVE-2024-46635.svg)


## CVE-2024-46627
 Incorrect access control in BECN DATAGERRY v2.2 allows attackers to execute arbitrary commands via crafted web requests.

- [https://github.com/d4lyw/CVE-2024-46627](https://github.com/d4lyw/CVE-2024-46627) :  ![starts](https://img.shields.io/github/stars/d4lyw/CVE-2024-46627.svg) ![forks](https://img.shields.io/github/forks/d4lyw/CVE-2024-46627.svg)


## CVE-2024-46542
 Veritas / Arctera Data Insight before 7.1.1 allows Application Administrators to conduct SQL injection attacks.

- [https://github.com/MarioTesoro/CVE-2024-46542](https://github.com/MarioTesoro/CVE-2024-46542) :  ![starts](https://img.shields.io/github/stars/MarioTesoro/CVE-2024-46542.svg) ![forks](https://img.shields.io/github/forks/MarioTesoro/CVE-2024-46542.svg)


## CVE-2024-46538
 A cross-site scripting (XSS) vulnerability in pfsense v2.5.2 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the $pconfig variable at interfaces_groups_edit.php.

- [https://github.com/EQSTLab/CVE-2024-46538](https://github.com/EQSTLab/CVE-2024-46538) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-46538.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-46538.svg)
- [https://github.com/LauLeysen/CVE-2024-46538](https://github.com/LauLeysen/CVE-2024-46538) :  ![starts](https://img.shields.io/github/stars/LauLeysen/CVE-2024-46538.svg) ![forks](https://img.shields.io/github/forks/LauLeysen/CVE-2024-46538.svg)
- [https://github.com/EQSTLab/CVE-2024-53677](https://github.com/EQSTLab/CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-53677.svg)


## CVE-2024-46532
 SQL Injection vulnerability in OpenHIS v.1.0 allows an attacker to execute arbitrary code via the refund function in the PayController.class.php component.

- [https://github.com/KamenRiderDarker/CVE-2024-46532](https://github.com/KamenRiderDarker/CVE-2024-46532) :  ![starts](https://img.shields.io/github/stars/KamenRiderDarker/CVE-2024-46532.svg) ![forks](https://img.shields.io/github/forks/KamenRiderDarker/CVE-2024-46532.svg)


## CVE-2024-46483
 Xlight FTP Server 3.9.4.3 has an integer overflow vulnerability in the packet parsing logic of the SFTP server, which can lead to a heap overflow with attacker-controlled content.

- [https://github.com/kn32/cve-2024-46483](https://github.com/kn32/cve-2024-46483) :  ![starts](https://img.shields.io/github/stars/kn32/cve-2024-46483.svg) ![forks](https://img.shields.io/github/forks/kn32/cve-2024-46483.svg)


## CVE-2024-46451
 TOTOLINK AC1200 T8 v4.1.5cu.861_B20230220 has a buffer overflow vulnerability in the setWiFiAclRules function via the desc parameter.

- [https://github.com/vidura2/CVE-2024-46451](https://github.com/vidura2/CVE-2024-46451) :  ![starts](https://img.shields.io/github/stars/vidura2/CVE-2024-46451.svg) ![forks](https://img.shields.io/github/forks/vidura2/CVE-2024-46451.svg)


## CVE-2024-46383
 Hathway Skyworth Router CM5100-511 v4.1.1.24 was discovered to store sensitive information about USB and Wifi connected devices in plaintext.

- [https://github.com/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383](https://github.com/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383) :  ![starts](https://img.shields.io/github/stars/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383.svg) ![forks](https://img.shields.io/github/forks/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383.svg)


## CVE-2024-46377
 Best House Rental Management System 1.0 contains an arbitrary file upload vulnerability in the save_settings() function of the file rental/admin_class.php.

- [https://github.com/vidura2/CVE-2024-46377](https://github.com/vidura2/CVE-2024-46377) :  ![starts](https://img.shields.io/github/stars/vidura2/CVE-2024-46377.svg) ![forks](https://img.shields.io/github/forks/vidura2/CVE-2024-46377.svg)


## CVE-2024-46278
 Teedy 1.11 is vulnerable to Cross Site Scripting (XSS) via the management console.

- [https://github.com/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover](https://github.com/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover) :  ![starts](https://img.shields.io/github/stars/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover.svg) ![forks](https://img.shields.io/github/forks/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover.svg)


## CVE-2024-46256
 A Command injection vulnerability in requestLetsEncryptSsl in NginxProxyManager 2.11.3 allows an attacker to RCE via Add Let's Encrypt Certificate.

- [https://github.com/barttran2k/POC_CVE-2024-46256](https://github.com/barttran2k/POC_CVE-2024-46256) :  ![starts](https://img.shields.io/github/stars/barttran2k/POC_CVE-2024-46256.svg) ![forks](https://img.shields.io/github/forks/barttran2k/POC_CVE-2024-46256.svg)


## CVE-2024-46209
 A stored cross-site scripting (XSS) vulnerability in the component /media/test.html of REDAXO CMS v5.17.1 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the password parameter.

- [https://github.com/h4ckr4v3n/CVE-2024-46209](https://github.com/h4ckr4v3n/CVE-2024-46209) :  ![starts](https://img.shields.io/github/stars/h4ckr4v3n/CVE-2024-46209.svg) ![forks](https://img.shields.io/github/forks/h4ckr4v3n/CVE-2024-46209.svg)


## CVE-2024-45827
 Improper neutralization of special elements used in an OS command ('OS Command Injection') issue exists in Mesh Wi-Fi router RP562B firmware version v1.0.2 and earlier. If this vulnerability is exploited, a network-adjacent authenticated attacker may execute an arbitrary OS command.

- [https://github.com/0xNslabs/SoftBankMeshAPI](https://github.com/0xNslabs/SoftBankMeshAPI) :  ![starts](https://img.shields.io/github/stars/0xNslabs/SoftBankMeshAPI.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/SoftBankMeshAPI.svg)


## CVE-2024-45622
 ASIS (aka Aplikasi Sistem Sekolah using CodeIgniter 3) 3.0.0 through 3.2.0 allows index.php username SQL injection for Authentication Bypass.

- [https://github.com/atoz-chevara/cve](https://github.com/atoz-chevara/cve) :  ![starts](https://img.shields.io/github/stars/atoz-chevara/cve.svg) ![forks](https://img.shields.io/github/forks/atoz-chevara/cve.svg)


## CVE-2024-45614
 Puma is a Ruby/Rack web server built for parallelism. In affected versions clients could clobber values set by intermediate proxies (such as X-Forwarded-For) by providing a underscore version of the same header (X-Forwarded_For). Any users relying on proxy set variables is affected. v6.4.3/v5.6.9 now discards any headers using underscores if the non-underscore version also exists. Effectively, allowing the proxy defined headers to always win. Users are advised to upgrade. Nginx has a underscores_in_headers configuration variable to discard these headers at the proxy level as a mitigation. Any users that are implicitly trusting the proxy defined headers for security should immediately cease doing so until upgraded to the fixed versions.

- [https://github.com/ooooooo-q/puma_header_normalization-CVE-2024-45614](https://github.com/ooooooo-q/puma_header_normalization-CVE-2024-45614) :  ![starts](https://img.shields.io/github/stars/ooooooo-q/puma_header_normalization-CVE-2024-45614.svg) ![forks](https://img.shields.io/github/forks/ooooooo-q/puma_header_normalization-CVE-2024-45614.svg)


## CVE-2024-45589
 RapidIdentity LTS through 2023.0.2 and Cloud through 2024.08.0 improperly restricts excessive authentication attempts and allows a remote attacker to cause a denial of service via the username parameters.

- [https://github.com/BenRogozinski/CVE-2024-45589](https://github.com/BenRogozinski/CVE-2024-45589) :  ![starts](https://img.shields.io/github/stars/BenRogozinski/CVE-2024-45589.svg) ![forks](https://img.shields.io/github/forks/BenRogozinski/CVE-2024-45589.svg)


## CVE-2024-45519
 The postjournal service in Zimbra Collaboration (ZCS) before 8.8.15 Patch 46, 9 before 9.0.0 Patch 41, 10 before 10.0.9, and 10.1 before 10.1.1 sometimes allows unauthenticated users to execute commands.

- [https://github.com/Chocapikk/CVE-2024-45519](https://github.com/Chocapikk/CVE-2024-45519) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-45519.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-45519.svg)
- [https://github.com/p33d/CVE-2024-45519](https://github.com/p33d/CVE-2024-45519) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2024-45519.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2024-45519.svg)
- [https://github.com/XiaomingX/cve-2024-45519-poc](https://github.com/XiaomingX/cve-2024-45519-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-45519-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-45519-poc.svg)
- [https://github.com/whiterose7777/CVE-2024-45519](https://github.com/whiterose7777/CVE-2024-45519) :  ![starts](https://img.shields.io/github/stars/whiterose7777/CVE-2024-45519.svg) ![forks](https://img.shields.io/github/forks/whiterose7777/CVE-2024-45519.svg)


## CVE-2024-45507
Users are recommended to upgrade to version 18.12.16, which fixes the issue.

- [https://github.com/Avento/CVE-2024-45507_Behinder_Webshell](https://github.com/Avento/CVE-2024-45507_Behinder_Webshell) :  ![starts](https://img.shields.io/github/stars/Avento/CVE-2024-45507_Behinder_Webshell.svg) ![forks](https://img.shields.io/github/forks/Avento/CVE-2024-45507_Behinder_Webshell.svg)


## CVE-2024-45492
 An issue was discovered in libexpat before 2.6.3. nextScaffoldPart in xmlparse.c can have an integer overflow for m_groupSize on 32-bit platforms (where UINT_MAX equals SIZE_MAX).

- [https://github.com/nidhihcl75/external_expat_2.6.2_CVE-2024-45492](https://github.com/nidhihcl75/external_expat_2.6.2_CVE-2024-45492) :  ![starts](https://img.shields.io/github/stars/nidhihcl75/external_expat_2.6.2_CVE-2024-45492.svg) ![forks](https://img.shields.io/github/forks/nidhihcl75/external_expat_2.6.2_CVE-2024-45492.svg)


## CVE-2024-45440
 core/authorize.php in Drupal 11.x-dev allows Full Path Disclosure (even when error logging is None) if the value of hash_salt is file_get_contents of a file that does not exist.

- [https://github.com/w0r1i0g1ht/CVE-2024-45440](https://github.com/w0r1i0g1ht/CVE-2024-45440) :  ![starts](https://img.shields.io/github/stars/w0r1i0g1ht/CVE-2024-45440.svg) ![forks](https://img.shields.io/github/forks/w0r1i0g1ht/CVE-2024-45440.svg)


## CVE-2024-45436
 extractFromZipFile in model.go in Ollama before 0.1.47 can extract members of a ZIP archive outside of the parent directory.

- [https://github.com/XiaomingX/cve-2024-45436-exp](https://github.com/XiaomingX/cve-2024-45436-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-45436-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-45436-exp.svg)
- [https://github.com/pankass/CVE-2024-45436](https://github.com/pankass/CVE-2024-45436) :  ![starts](https://img.shields.io/github/stars/pankass/CVE-2024-45436.svg) ![forks](https://img.shields.io/github/forks/pankass/CVE-2024-45436.svg)


## CVE-2024-45410
 Traefik is a golang, Cloud Native Application Proxy. When a HTTP request is processed by Traefik, certain HTTP headers such as X-Forwarded-Host or X-Forwarded-Port are added by Traefik before the request is routed to the application. For a HTTP client, it should not be possible to remove or modify these headers. Since the application trusts the value of these headers, security implications might arise, if they can be modified. For HTTP/1.1, however, it was found that some of theses custom headers can indeed be removed and in certain cases manipulated. The attack relies on the HTTP/1.1 behavior, that headers can be defined as hop-by-hop via the HTTP Connection header. This issue has been addressed in release versions 2.11.9 and 3.1.3. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/jphetphoumy/traefik-CVE-2024-45410-poc](https://github.com/jphetphoumy/traefik-CVE-2024-45410-poc) :  ![starts](https://img.shields.io/github/stars/jphetphoumy/traefik-CVE-2024-45410-poc.svg) ![forks](https://img.shields.io/github/forks/jphetphoumy/traefik-CVE-2024-45410-poc.svg)


## CVE-2024-45409
 The Ruby SAML library is for implementing the client side of a SAML authorization. Ruby-SAML in = 12.2 and 1.13.0 = 1.16.0 does not properly verify the signature of the SAML Response. An unauthenticated attacker with access to any signed saml document (by the IdP) can thus forge a SAML Response/Assertion with arbitrary contents. This would allow the attacker to log in as arbitrary user within the vulnerable system. This vulnerability is fixed in 1.17.0 and 1.12.3.

- [https://github.com/synacktiv/CVE-2024-45409](https://github.com/synacktiv/CVE-2024-45409) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2024-45409.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2024-45409.svg)


## CVE-2024-45388
 Hoverfly is a lightweight service virtualization/ API simulation / API mocking tool for developers and testers. The `/api/v2/simulation` POST handler allows users to create new simulation views from the contents of a user-specified file. This feature can be abused by an attacker to read arbitrary files from the Hoverfly server. Note that, although the code prevents absolute paths from being specified, an attacker can escape out of the `hf.Cfg.ResponsesBodyFilesPath` base path by using `../` segments and reach any arbitrary files. This issue was found using the Uncontrolled data used in path expression CodeQL query for python. Users are advised to make sure the final path (`filepath.Join(hf.Cfg.ResponsesBodyFilesPath, filePath)`) is contained within the expected base path (`filepath.Join(hf.Cfg.ResponsesBodyFilesPath, "/")`). This issue is also tracked as GHSL-2023-274.

- [https://github.com/codeb0ss/CVE-2024-45388-PoC](https://github.com/codeb0ss/CVE-2024-45388-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-45388-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-45388-PoC.svg)


## CVE-2024-45383
 A mishandling of IRP requests vulnerability exists in the HDAudBus_DMA interface of Microsoft High Definition Audio Bus Driver 10.0.19041.3636 (WinBuild.160101.0800). A specially crafted application can issue multiple IRP Complete requests which leads to a local denial-of-service. An attacker can execute malicious script/application to trigger this vulnerability.

- [https://github.com/SpiralBL0CK/CVE-2024-45383](https://github.com/SpiralBL0CK/CVE-2024-45383) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-45383.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-45383.svg)


## CVE-2024-45337
 Applications and libraries which misuse the ServerConfig.PublicKeyCallback callback may be susceptible to an authorization bypass. The documentation for ServerConfig.PublicKeyCallback says that "A call to this function does not guarantee that the key offered is in fact used to authenticate." Specifically, the SSH protocol allows clients to inquire about whether a public key is acceptable before proving control of the corresponding private key. PublicKeyCallback may be called with multiple keys, and the order in which the keys were provided cannot be used to infer which key the client successfully authenticated with, if any. Some applications, which store the key(s) passed to PublicKeyCallback (or derived information) and make security relevant determinations based on it once the connection is established, may make incorrect assumptions. For example, an attacker may send public keys A and B, and then authenticate with A. PublicKeyCallback would be called only twice, first with A and then with B. A vulnerable application may then make authorization decisions based on key B for which the attacker does not actually control the private key. Since this API is widely misused, as a partial mitigation golang.org/x/cry...@v0.31.0 enforces the property that, when successfully authenticating via public key, the last key passed to ServerConfig.PublicKeyCallback will be the key used to authenticate the connection. PublicKeyCallback will now be called multiple times with the same key, if necessary. Note that the client may still not control the last key passed to PublicKeyCallback if the connection is then authenticated with a different method, such as PasswordCallback, KeyboardInteractiveCallback, or NoClientAuth. Users should be using the Extensions field of the Permissions return value from the various authentication callbacks to record data associated with the authentication attempt instead of referencing external state. Once the connection is established the state corresponding to the successful authentication attempt can be retrieved via the ServerConn.Permissions field. Note that some third-party libraries misuse the Permissions type by sharing it across authentication attempts; users of third-party libraries should refer to the relevant projects for guidance.

- [https://github.com/NHAS/CVE-2024-45337-POC](https://github.com/NHAS/CVE-2024-45337-POC) :  ![starts](https://img.shields.io/github/stars/NHAS/CVE-2024-45337-POC.svg) ![forks](https://img.shields.io/github/forks/NHAS/CVE-2024-45337-POC.svg)
- [https://github.com/NHAS/VULNERABLE-CVE-2024-45337](https://github.com/NHAS/VULNERABLE-CVE-2024-45337) :  ![starts](https://img.shields.io/github/stars/NHAS/VULNERABLE-CVE-2024-45337.svg) ![forks](https://img.shields.io/github/forks/NHAS/VULNERABLE-CVE-2024-45337.svg)


## CVE-2024-45265
 A SQL injection vulnerability in the poll component in SkySystem Arfa-CMS before 5.1.3124 allows remote attackers to execute arbitrary SQL commands via the psid parameter.

- [https://github.com/TheHermione/CVE-2024-45265](https://github.com/TheHermione/CVE-2024-45265) :  ![starts](https://img.shields.io/github/stars/TheHermione/CVE-2024-45265.svg) ![forks](https://img.shields.io/github/forks/TheHermione/CVE-2024-45265.svg)


## CVE-2024-45264
 A cross-site request forgery (CSRF) vulnerability in the admin panel in SkySystem Arfa-CMS before 5.1.3124 allows remote attackers to add a new administrator, leading to escalation of privileges.

- [https://github.com/TheHermione/CVE-2024-45264](https://github.com/TheHermione/CVE-2024-45264) :  ![starts](https://img.shields.io/github/stars/TheHermione/CVE-2024-45264.svg) ![forks](https://img.shields.io/github/forks/TheHermione/CVE-2024-45264.svg)


## CVE-2024-45244
 Hyperledger Fabric through 2.5.9 does not verify that a request has a timestamp within the expected time window.

- [https://github.com/shanker-sec/hlf-time-oracle](https://github.com/shanker-sec/hlf-time-oracle) :  ![starts](https://img.shields.io/github/stars/shanker-sec/hlf-time-oracle.svg) ![forks](https://img.shields.io/github/forks/shanker-sec/hlf-time-oracle.svg)
- [https://github.com/shanker-sec/HLF_TxTime_spoofing](https://github.com/shanker-sec/HLF_TxTime_spoofing) :  ![starts](https://img.shields.io/github/stars/shanker-sec/HLF_TxTime_spoofing.svg) ![forks](https://img.shields.io/github/forks/shanker-sec/HLF_TxTime_spoofing.svg)


## CVE-2024-45241
 A traversal vulnerability in GeneralDocs.aspx in CentralSquare CryWolf (False Alarm Management) through 2024-08-09 allows unauthenticated attackers to read files outside of the working web directory via the rpt parameter, leading to the disclosure of sensitive information.

- [https://github.com/verylazytech/CVE-2024-45241](https://github.com/verylazytech/CVE-2024-45241) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-45241.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-45241.svg)
- [https://github.com/d4lyw/CVE-2024-45241](https://github.com/d4lyw/CVE-2024-45241) :  ![starts](https://img.shields.io/github/stars/d4lyw/CVE-2024-45241.svg) ![forks](https://img.shields.io/github/forks/d4lyw/CVE-2024-45241.svg)


## CVE-2024-45216
Users are recommended to upgrade to version 9.7.0, or 8.11.4, which fix the issue.

- [https://github.com/congdong007/CVE-2024-45216-Poc](https://github.com/congdong007/CVE-2024-45216-Poc) :  ![starts](https://img.shields.io/github/stars/congdong007/CVE-2024-45216-Poc.svg) ![forks](https://img.shields.io/github/forks/congdong007/CVE-2024-45216-Poc.svg)


## CVE-2024-45200
 In Nintendo Mario Kart 8 Deluxe before 3.0.3, the LAN/LDN local multiplayer implementation allows a remote attacker to exploit a stack-based buffer overflow upon deserialization of session information via a malformed browse-reply packet, aka KartLANPwn. The victim is not required to join a game session with an attacker. The victim must open the "Wireless Play" (or "LAN Play") menu from the game's title screen, and an attacker nearby (LDN) or on the same LAN network as the victim can send a crafted reply packet to the victim's console. This enables a remote attacker to obtain complete denial-of-service on the game's process, or potentially, remote code execution on the victim's console. The issue is caused by incorrect use of the Nintendo Pia library,

- [https://github.com/latte-soft/kartlanpwn](https://github.com/latte-soft/kartlanpwn) :  ![starts](https://img.shields.io/github/stars/latte-soft/kartlanpwn.svg) ![forks](https://img.shields.io/github/forks/latte-soft/kartlanpwn.svg)


## CVE-2024-45058
 i-Educar is free, fully online school management software that can be used by school secretaries, teachers, coordinators, and area managers. Prior to the 2.9 branch, an attacker with only minimal viewing privileges in the settings section is able to change their user type to Administrator (or another type with super-permissions) through a specifically crafted POST request to `/intranet/educar_usuario_cad.php`, modifying the `nivel_usuario_` parameter. The vulnerability occurs in the file located at `ieducar/intranet/educar_usuario_cad.php`, which does not check the user's current permission level before allowing changes. Commit c25910cdf11ab50e50162a49dd44bef544422b6e contains a patch for the issue.

- [https://github.com/0xbhsu/CVE-2024-45058](https://github.com/0xbhsu/CVE-2024-45058) :  ![starts](https://img.shields.io/github/stars/0xbhsu/CVE-2024-45058.svg) ![forks](https://img.shields.io/github/forks/0xbhsu/CVE-2024-45058.svg)


## CVE-2024-44947
corresponding kernel command line parameter).

- [https://github.com/Abdurahmon3236/CVE-2024-44947](https://github.com/Abdurahmon3236/CVE-2024-44947) :  ![starts](https://img.shields.io/github/stars/Abdurahmon3236/CVE-2024-44947.svg) ![forks](https://img.shields.io/github/forks/Abdurahmon3236/CVE-2024-44947.svg)


## CVE-2024-44946
---truncated---

- [https://github.com/Abdurahmon3236/CVE-2024-44946](https://github.com/Abdurahmon3236/CVE-2024-44946) :  ![starts](https://img.shields.io/github/stars/Abdurahmon3236/CVE-2024-44946.svg) ![forks](https://img.shields.io/github/forks/Abdurahmon3236/CVE-2024-44946.svg)


## CVE-2024-44902
 A deserialization vulnerability in Thinkphp v6.1.3 to v8.0.4 allows attackers to execute arbitrary code.

- [https://github.com/fru1ts/CVE-2024-44902](https://github.com/fru1ts/CVE-2024-44902) :  ![starts](https://img.shields.io/github/stars/fru1ts/CVE-2024-44902.svg) ![forks](https://img.shields.io/github/forks/fru1ts/CVE-2024-44902.svg)


## CVE-2024-44867
 phpok v3.0 was discovered to contain an arbitrary file read vulnerability via the component /autoload/file.php.

- [https://github.com/ChengZyin/CVE-2024-44867](https://github.com/ChengZyin/CVE-2024-44867) :  ![starts](https://img.shields.io/github/stars/ChengZyin/CVE-2024-44867.svg) ![forks](https://img.shields.io/github/forks/ChengZyin/CVE-2024-44867.svg)


## CVE-2024-44849
 Qualitor up to 8.24 is vulnerable to Remote Code Execution (RCE) via Arbitrary File Upload in checkAcesso.php.

- [https://github.com/extencil/CVE-2024-44849](https://github.com/extencil/CVE-2024-44849) :  ![starts](https://img.shields.io/github/stars/extencil/CVE-2024-44849.svg) ![forks](https://img.shields.io/github/forks/extencil/CVE-2024-44849.svg)


## CVE-2024-44825
 Directory Traversal vulnerability in Centro de Tecnologia da Informaco Renato Archer InVesalius3 v3.1.99995 allows attackers to write arbitrary files unto the system via a crafted .inv3 file.

- [https://github.com/partywavesec/invesalius3_vulnerabilities](https://github.com/partywavesec/invesalius3_vulnerabilities) :  ![starts](https://img.shields.io/github/stars/partywavesec/invesalius3_vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/partywavesec/invesalius3_vulnerabilities.svg)


## CVE-2024-44815
 Vulnerability in Hathway Skyworth Router CM5100 v.4.1.1.24 allows a physically proximate attacker to obtain user credentials via SPI flash Firmware W25Q64JV.

- [https://github.com/nitinronge91/Extracting-User-credentials-For-Web-portal-and-WiFi-AP-For-Hathway-Router-CVE-2024-44815-](https://github.com/nitinronge91/Extracting-User-credentials-For-Web-portal-and-WiFi-AP-For-Hathway-Router-CVE-2024-44815-) :  ![starts](https://img.shields.io/github/stars/nitinronge91/Extracting-User-credentials-For-Web-portal-and-WiFi-AP-For-Hathway-Router-CVE-2024-44815-.svg) ![forks](https://img.shields.io/github/forks/nitinronge91/Extracting-User-credentials-For-Web-portal-and-WiFi-AP-For-Hathway-Router-CVE-2024-44815-.svg)


## CVE-2024-44812
 SQL Injection vulnerability in Online Complaint Site v.1.0 allows a remote attacker to escalate privileges via the username and password parameters in the /admin.index.php component.

- [https://github.com/b1u3st0rm/CVE-2024-44812-PoC](https://github.com/b1u3st0rm/CVE-2024-44812-PoC) :  ![starts](https://img.shields.io/github/stars/b1u3st0rm/CVE-2024-44812-PoC.svg) ![forks](https://img.shields.io/github/forks/b1u3st0rm/CVE-2024-44812-PoC.svg)


## CVE-2024-44765
 An Improper Authorization (Access Control Misconfiguration) vulnerability in MGT-COMMERCE GmbH CloudPanel v2.0.0 to v2.4.2 allows low-privilege users to bypass access controls and gain unauthorized access to sensitive configuration files and administrative functionality.

- [https://github.com/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery](https://github.com/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery) :  ![starts](https://img.shields.io/github/stars/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery.svg) ![forks](https://img.shields.io/github/forks/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery.svg)


## CVE-2024-44625
 Gogs =0.13.0 is vulnerable to Directory Traversal via the editFilePost function of internal/route/repo/editor.go.

- [https://github.com/Fysac/CVE-2024-44625](https://github.com/Fysac/CVE-2024-44625) :  ![starts](https://img.shields.io/github/stars/Fysac/CVE-2024-44625.svg) ![forks](https://img.shields.io/github/forks/Fysac/CVE-2024-44625.svg)


## CVE-2024-44623
 An issue in TuomoKu SPx-GC v.1.3.0 and before allows a remote attacker to execute arbitrary code via the child_process.js function.

- [https://github.com/merbinr/CVE-2024-44623](https://github.com/merbinr/CVE-2024-44623) :  ![starts](https://img.shields.io/github/stars/merbinr/CVE-2024-44623.svg) ![forks](https://img.shields.io/github/forks/merbinr/CVE-2024-44623.svg)


## CVE-2024-44610
 PCAN-Ethernet Gateway FD before 1.3.0 and PCAN-Ethernet Gateway before 2.11.0 are vulnerable to Command injection via shell metacharacters in a Software Update to processing.php.

- [https://github.com/BertoldVdb/PcanExploit](https://github.com/BertoldVdb/PcanExploit) :  ![starts](https://img.shields.io/github/stars/BertoldVdb/PcanExploit.svg) ![forks](https://img.shields.io/github/forks/BertoldVdb/PcanExploit.svg)


## CVE-2024-44542
 SQL Injection vulnerability in todesk v.1.1 allows a remote attacker to execute arbitrary code via the /todesk.com/news.html parameter.

- [https://github.com/alphandbelt/CVE-2024-44542](https://github.com/alphandbelt/CVE-2024-44542) :  ![starts](https://img.shields.io/github/stars/alphandbelt/CVE-2024-44542.svg) ![forks](https://img.shields.io/github/forks/alphandbelt/CVE-2024-44542.svg)


## CVE-2024-44541
 evilnapsis Inventio Lite Versions v4 and before is vulnerable to SQL Injection via the "username" parameter in "/?action=processlogin."

- [https://github.com/pointedsec/CVE-2024-44541](https://github.com/pointedsec/CVE-2024-44541) :  ![starts](https://img.shields.io/github/stars/pointedsec/CVE-2024-44541.svg) ![forks](https://img.shields.io/github/forks/pointedsec/CVE-2024-44541.svg)


## CVE-2024-44450
 Multiple functions are vulnerable to Authorization Bypass in AIMS eCrew. The issue was fixed in version JUN23 #190.

- [https://github.com/VoidSecOrg/CVE-2024-44450](https://github.com/VoidSecOrg/CVE-2024-44450) :  ![starts](https://img.shields.io/github/stars/VoidSecOrg/CVE-2024-44450.svg) ![forks](https://img.shields.io/github/forks/VoidSecOrg/CVE-2024-44450.svg)


## CVE-2024-44349
 A SQL injection vulnerability in login portal in AnteeoWMS before v4.7.34 allows unauthenticated attackers to execute arbitrary SQL commands via the username parameter and disclosure of some data in the underlying DB.

- [https://github.com/AndreaF17/PoC-CVE-2024-44349](https://github.com/AndreaF17/PoC-CVE-2024-44349) :  ![starts](https://img.shields.io/github/stars/AndreaF17/PoC-CVE-2024-44349.svg) ![forks](https://img.shields.io/github/forks/AndreaF17/PoC-CVE-2024-44349.svg)


## CVE-2024-44337
 The package `github.com/gomarkdown/markdown` is a Go library for parsing Markdown text and rendering as HTML. Prior to pseudoversion `v0.0.0-20240729232818-a2a9c4f`, which corresponds with commit `a2a9c4f76ef5a5c32108e36f7c47f8d310322252`, there was a logical problem in the paragraph function of the parser/block.go file, which allowed a remote attacker to cause a denial of service (DoS) condition by providing a tailor-made input that caused an infinite loop, causing the program to hang and consume resources indefinitely. Submit `a2a9c4f76ef5a5c32108e36f7c47f8d310322252` contains fixes to this problem.

- [https://github.com/Brinmon/CVE-2024-44337](https://github.com/Brinmon/CVE-2024-44337) :  ![starts](https://img.shields.io/github/stars/Brinmon/CVE-2024-44337.svg) ![forks](https://img.shields.io/github/forks/Brinmon/CVE-2024-44337.svg)


## CVE-2024-44285
 A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 18.1 and iPadOS 18.1, watchOS 11.1, visionOS 2.1, tvOS 18.1. An app may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/slds1/explt](https://github.com/slds1/explt) :  ![starts](https://img.shields.io/github/stars/slds1/explt.svg) ![forks](https://img.shields.io/github/forks/slds1/explt.svg)


## CVE-2024-44258
 This issue was addressed with improved handling of symlinks. This issue is fixed in iOS 18.1 and iPadOS 18.1, iOS 17.7.1 and iPadOS 17.7.1, visionOS 2.1, tvOS 18.1. Restoring a maliciously crafted backup file may lead to modification of protected system files.

- [https://github.com/ifpdz/CVE-2024-44258](https://github.com/ifpdz/CVE-2024-44258) :  ![starts](https://img.shields.io/github/stars/ifpdz/CVE-2024-44258.svg) ![forks](https://img.shields.io/github/forks/ifpdz/CVE-2024-44258.svg)


## CVE-2024-44193
 A logic issue was addressed with improved restrictions. This issue is fixed in iTunes 12.13.3 for Windows. A local attacker may be able to elevate  their privileges.

- [https://github.com/mbog14/CVE-2024-44193](https://github.com/mbog14/CVE-2024-44193) :  ![starts](https://img.shields.io/github/stars/mbog14/CVE-2024-44193.svg) ![forks](https://img.shields.io/github/forks/mbog14/CVE-2024-44193.svg)


## CVE-2024-44133
 This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sequoia 15. On MDM managed devices, an app may be able to bypass certain Privacy preferences.

- [https://github.com/Ununp3ntium115/prevent_cve_2024_44133](https://github.com/Ununp3ntium115/prevent_cve_2024_44133) :  ![starts](https://img.shields.io/github/stars/Ununp3ntium115/prevent_cve_2024_44133.svg) ![forks](https://img.shields.io/github/forks/Ununp3ntium115/prevent_cve_2024_44133.svg)


## CVE-2024-44083
 ida64.dll in Hex-Rays IDA Pro through 8.4 crashes when there is a section that has many jumps linked, and the final jump corresponds to the payload from where the actual entry point will be invoked. NOTE: in many use cases, this is an inconvenience but not a security issue.

- [https://github.com/Azvanzed/CVE-2024-44083](https://github.com/Azvanzed/CVE-2024-44083) :  ![starts](https://img.shields.io/github/stars/Azvanzed/CVE-2024-44083.svg) ![forks](https://img.shields.io/github/forks/Azvanzed/CVE-2024-44083.svg)


## CVE-2024-44000
 Insufficiently Protected Credentials vulnerability in LiteSpeed Technologies LiteSpeed Cache allows Authentication Bypass.This issue affects LiteSpeed Cache: from n/a before 6.5.0.1.

- [https://github.com/absholi7ly/CVE-2024-44000-LiteSpeed-Cache](https://github.com/absholi7ly/CVE-2024-44000-LiteSpeed-Cache) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2024-44000-LiteSpeed-Cache.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2024-44000-LiteSpeed-Cache.svg)
- [https://github.com/geniuszly/CVE-2024-44000](https://github.com/geniuszly/CVE-2024-44000) :  ![starts](https://img.shields.io/github/stars/geniuszly/CVE-2024-44000.svg) ![forks](https://img.shields.io/github/forks/geniuszly/CVE-2024-44000.svg)
- [https://github.com/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache](https://github.com/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache) :  ![starts](https://img.shields.io/github/stars/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache.svg) ![forks](https://img.shields.io/github/forks/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache.svg)
- [https://github.com/gbrsh/CVE-2024-44000](https://github.com/gbrsh/CVE-2024-44000) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2024-44000.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2024-44000.svg)


## CVE-2024-43998
 Missing Authorization vulnerability in WebsiteinWP Blogpoet allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects Blogpoet: from n/a through 1.0.3.

- [https://github.com/RandomRobbieBF/CVE-2024-43998](https://github.com/RandomRobbieBF/CVE-2024-43998) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-43998.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-43998.svg)


## CVE-2024-43965
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Smackcoders SendGrid for WordPress allows SQL Injection.This issue affects SendGrid for WordPress: from n/a through 1.4.

- [https://github.com/RandomRobbieBF/CVE-2024-43965](https://github.com/RandomRobbieBF/CVE-2024-43965) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-43965.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-43965.svg)


## CVE-2024-43919
This issue affects YARPP: from n/a through 5.30.10.

- [https://github.com/RandomRobbieBF/CVE-2024-43919](https://github.com/RandomRobbieBF/CVE-2024-43919) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-43919.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-43919.svg)


## CVE-2024-43918
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WBW WBW Product Table PRO allows SQL Injection.This issue affects WBW Product Table PRO: from n/a through 1.9.4.

- [https://github.com/KTN1990/CVE-2024-43918](https://github.com/KTN1990/CVE-2024-43918) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2024-43918.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2024-43918.svg)


## CVE-2024-43917
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in TemplateInvaders TI WooCommerce Wishlist allows SQL Injection.This issue affects TI WooCommerce Wishlist: from n/a through 2.8.2.

- [https://github.com/p33d/CVE-2024-43917](https://github.com/p33d/CVE-2024-43917) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2024-43917.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2024-43917.svg)


## CVE-2024-43609
 Microsoft Office Spoofing Vulnerability

- [https://github.com/passtheticket/CVE-2024-38200](https://github.com/passtheticket/CVE-2024-38200) :  ![starts](https://img.shields.io/github/stars/passtheticket/CVE-2024-38200.svg) ![forks](https://img.shields.io/github/forks/passtheticket/CVE-2024-38200.svg)


## CVE-2024-43532
 Remote Registry Service Elevation of Privilege Vulnerability

- [https://github.com/expl0itsecurity/CVE-2024-43532](https://github.com/expl0itsecurity/CVE-2024-43532) :  ![starts](https://img.shields.io/github/stars/expl0itsecurity/CVE-2024-43532.svg) ![forks](https://img.shields.io/github/forks/expl0itsecurity/CVE-2024-43532.svg)


## CVE-2024-43468
 Microsoft Configuration Manager Remote Code Execution Vulnerability

- [https://github.com/tadash10/Detailed-Analysis-and-Mitigation-Strategies-for-CVE-2024-38124-and-CVE-2024-43468](https://github.com/tadash10/Detailed-Analysis-and-Mitigation-Strategies-for-CVE-2024-38124-and-CVE-2024-43468) :  ![starts](https://img.shields.io/github/stars/tadash10/Detailed-Analysis-and-Mitigation-Strategies-for-CVE-2024-38124-and-CVE-2024-43468.svg) ![forks](https://img.shields.io/github/forks/tadash10/Detailed-Analysis-and-Mitigation-Strategies-for-CVE-2024-38124-and-CVE-2024-43468.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/RedTeamPentesting/moodle-rce-calculatedquestions](https://github.com/RedTeamPentesting/moodle-rce-calculatedquestions) :  ![starts](https://img.shields.io/github/stars/RedTeamPentesting/moodle-rce-calculatedquestions.svg) ![forks](https://img.shields.io/github/forks/RedTeamPentesting/moodle-rce-calculatedquestions.svg)


## CVE-2024-43416
 GLPI is a free asset and IT management software package. Starting in version 0.80 and prior to version 10.0.17, an unauthenticated user can use an application endpoint to check if an email address corresponds to a valid GLPI user. Version 10.0.17 fixes the issue.

- [https://github.com/0xmupa/CVE-2024-43416-PoC](https://github.com/0xmupa/CVE-2024-43416-PoC) :  ![starts](https://img.shields.io/github/stars/0xmupa/CVE-2024-43416-PoC.svg) ![forks](https://img.shields.io/github/forks/0xmupa/CVE-2024-43416-PoC.svg)


## CVE-2024-43363
 Cacti is an open source performance and fault management framework. An admin user can create a device with a malicious hostname containing php code and repeat the installation process (completing only step 5 of the installation process is enough, no need to complete the steps before or after it) to use a php file as the cacti log file. After having the malicious hostname end up in the logs (log poisoning), one can simply go to the log file url to execute commands to achieve RCE. This issue has been addressed in version 1.2.28 and all users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/p33d/CVE-2024-43363](https://github.com/p33d/CVE-2024-43363) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2024-43363.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2024-43363.svg)


## CVE-2024-43160
 Unrestricted Upload of File with Dangerous Type vulnerability in BerqWP allows Code Injection.This issue affects BerqWP: from n/a through 1.7.6.

- [https://github.com/KTN1990/CVE-2024-43160](https://github.com/KTN1990/CVE-2024-43160) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2024-43160.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2024-43160.svg)


## CVE-2024-43044
 Jenkins 2.470 and earlier, LTS 2.452.3 and earlier allows agent processes to read arbitrary files from the Jenkins controller file system by using the `ClassLoaderProxy#fetchJar` method in the Remoting library.

- [https://github.com/convisolabs/CVE-2024-43044-jenkins](https://github.com/convisolabs/CVE-2024-43044-jenkins) :  ![starts](https://img.shields.io/github/stars/convisolabs/CVE-2024-43044-jenkins.svg) ![forks](https://img.shields.io/github/forks/convisolabs/CVE-2024-43044-jenkins.svg)
- [https://github.com/v9d0g/CVE-2024-43044-POC](https://github.com/v9d0g/CVE-2024-43044-POC) :  ![starts](https://img.shields.io/github/stars/v9d0g/CVE-2024-43044-POC.svg) ![forks](https://img.shields.io/github/forks/v9d0g/CVE-2024-43044-POC.svg)
- [https://github.com/HwMex0/CVE-2024-43044](https://github.com/HwMex0/CVE-2024-43044) :  ![starts](https://img.shields.io/github/stars/HwMex0/CVE-2024-43044.svg) ![forks](https://img.shields.io/github/forks/HwMex0/CVE-2024-43044.svg)
- [https://github.com/jenkinsci-cert/SECURITY-3430](https://github.com/jenkinsci-cert/SECURITY-3430) :  ![starts](https://img.shields.io/github/stars/jenkinsci-cert/SECURITY-3430.svg) ![forks](https://img.shields.io/github/forks/jenkinsci-cert/SECURITY-3430.svg)


## CVE-2024-42992
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/thanhh23/CVE-2024-42992](https://github.com/thanhh23/CVE-2024-42992) :  ![starts](https://img.shields.io/github/stars/thanhh23/CVE-2024-42992.svg) ![forks](https://img.shields.io/github/forks/thanhh23/CVE-2024-42992.svg)


## CVE-2024-42919
 eScan Management Console 14.0.1400.2281 is vulnerable to Incorrect Access Control via acteScanAVReport.

- [https://github.com/jeyabalaji711/CVE-2024-42919](https://github.com/jeyabalaji711/CVE-2024-42919) :  ![starts](https://img.shields.io/github/stars/jeyabalaji711/CVE-2024-42919.svg) ![forks](https://img.shields.io/github/forks/jeyabalaji711/CVE-2024-42919.svg)


## CVE-2024-42861
 An issue in IEEE 802.1AS linuxptp v.4.2 and before allowing a remote attacker to cause a denial of service via a crafted Pdelay_Req message to the time synchronization function

- [https://github.com/qiupy123/CVE-2024-42861](https://github.com/qiupy123/CVE-2024-42861) :  ![starts](https://img.shields.io/github/stars/qiupy123/CVE-2024-42861.svg) ![forks](https://img.shields.io/github/forks/qiupy123/CVE-2024-42861.svg)


## CVE-2024-42850
 An issue in the password change function of Silverpeas v6.4.2 and lower allows for the bypassing of password complexity requirements.

- [https://github.com/njmbb8/CVE-2024-42850](https://github.com/njmbb8/CVE-2024-42850) :  ![starts](https://img.shields.io/github/stars/njmbb8/CVE-2024-42850.svg) ![forks](https://img.shields.io/github/forks/njmbb8/CVE-2024-42850.svg)


## CVE-2024-42849
 An issue in Silverpeas v.6.4.2 and lower allows a remote attacker to cause a denial of service via the password change function.

- [https://github.com/njmbb8/CVE-2024-42849](https://github.com/njmbb8/CVE-2024-42849) :  ![starts](https://img.shields.io/github/stars/njmbb8/CVE-2024-42849.svg) ![forks](https://img.shields.io/github/forks/njmbb8/CVE-2024-42849.svg)


## CVE-2024-42845
 An eval Injection vulnerability in the component invesalius/reader/dicom.py of InVesalius 3.1.99991 through 3.1.99998 allows attackers to execute arbitrary code via loading a crafted DICOM file.

- [https://github.com/partywavesec/invesalius3_vulnerabilities](https://github.com/partywavesec/invesalius3_vulnerabilities) :  ![starts](https://img.shields.io/github/stars/partywavesec/invesalius3_vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/partywavesec/invesalius3_vulnerabilities.svg)


## CVE-2024-42834
 A stored cross-site scripting (XSS) vulnerability in the Create Customer API in Incognito Service Activation Center (SAC) UI v14.11 allows authenticated attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the lastName parameter.

- [https://github.com/CyberSec-Supra/CVE-2024-42834](https://github.com/CyberSec-Supra/CVE-2024-42834) :  ![starts](https://img.shields.io/github/stars/CyberSec-Supra/CVE-2024-42834.svg) ![forks](https://img.shields.io/github/forks/CyberSec-Supra/CVE-2024-42834.svg)


## CVE-2024-42758
 A Cross-site Scripting (XSS) vulnerability exists in version v2024-01-05 of the indexmenu plugin when is used and enabled in Dokuwiki (Open Source Wiki Engine). A malicious attacker can input XSS payloads for example when creating or editing existing page, to trigger the XSS on Dokuwiki, which is then stored in .txt file (due to nature of how Dokuwiki is designed), which presents stored XSS.

- [https://github.com/1s1ldur/CVE-2024-42758](https://github.com/1s1ldur/CVE-2024-42758) :  ![starts](https://img.shields.io/github/stars/1s1ldur/CVE-2024-42758.svg) ![forks](https://img.shields.io/github/forks/1s1ldur/CVE-2024-42758.svg)


## CVE-2024-42658
 An issue in wishnet Nepstech Wifi Router NTPL-XPON1GFEVN v1.0 allows a remote attacker to obtain sensitive information via the cookie's parameter

- [https://github.com/sudo-subho/CVE-2024-42658](https://github.com/sudo-subho/CVE-2024-42658) :  ![starts](https://img.shields.io/github/stars/sudo-subho/CVE-2024-42658.svg) ![forks](https://img.shields.io/github/forks/sudo-subho/CVE-2024-42658.svg)


## CVE-2024-42657
 An issue in wishnet Nepstech Wifi Router NTPL-XPON1GFEVN v1.0 allows a remote attacker to obtain sensitive information via the lack of encryption during login process

- [https://github.com/sudo-subho/CVE-2024-42657](https://github.com/sudo-subho/CVE-2024-42657) :  ![starts](https://img.shields.io/github/stars/sudo-subho/CVE-2024-42657.svg) ![forks](https://img.shields.io/github/forks/sudo-subho/CVE-2024-42657.svg)


## CVE-2024-42642
 Micron Crucial MX500 Series Solid State Drives M3CR046 is vulnerable to Buffer Overflow, which can be triggered by sending specially crafted ATA packets from the host to the drive controller.

- [https://github.com/VL4DR/CVE-2024-42642](https://github.com/VL4DR/CVE-2024-42642) :  ![starts](https://img.shields.io/github/stars/VL4DR/CVE-2024-42642.svg) ![forks](https://img.shields.io/github/forks/VL4DR/CVE-2024-42642.svg)


## CVE-2024-42640
 angular-base64-upload prior to v0.1.21 is vulnerable to unauthenticated remote code execution via demo/server.php. Exploiting this vulnerability allows an attacker to upload arbitrary content to the server, which can subsequently be accessed through demo/uploads. This leads to the execution of previously uploaded content and enables the attacker to achieve code execution on the server. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/rvizx/CVE-2024-42640](https://github.com/rvizx/CVE-2024-42640) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2024-42640.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2024-42640.svg)
- [https://github.com/KTN1990/CVE-2024-42640](https://github.com/KTN1990/CVE-2024-42640) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2024-42640.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2024-42640.svg)


## CVE-2024-42461
 In the Elliptic package 6.5.6 for Node.js, ECDSA signature malleability occurs because BER-encoded signatures are allowed.

- [https://github.com/fevar54/CVE-2024-42461](https://github.com/fevar54/CVE-2024-42461) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2024-42461.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2024-42461.svg)


## CVE-2024-42448
 From the VSPC management agent machine, under condition that the management agent is authorized on the server, it is possible to perform Remote Code Execution (RCE) on the VSPC server machine.

- [https://github.com/h3lye/CVE-2024-42448-RCE](https://github.com/h3lye/CVE-2024-42448-RCE) :  ![starts](https://img.shields.io/github/stars/h3lye/CVE-2024-42448-RCE.svg) ![forks](https://img.shields.io/github/forks/h3lye/CVE-2024-42448-RCE.svg)


## CVE-2024-42346
 Galaxy is a free, open-source system for analyzing data, authoring workflows, training and education, publishing tools, managing infrastructure, and more. The editor visualization, /visualizations endpoint, can be used to store HTML tags and trigger javascript execution upon edit operation. All supported branches of Galaxy (and more back to release_20.05) were amended with the supplied patches. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/partywavesec/CVE-2024-42346](https://github.com/partywavesec/CVE-2024-42346) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2024-42346.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2024-42346.svg)


## CVE-2024-42327
 A non-admin user account on the Zabbix frontend with the default User role, or with any other role that gives API access can exploit this vulnerability. An SQLi exists in the CUser class in the addRelatedObjects function, this function is being called from the CUser.get function which is available for every user who has API access.

- [https://github.com/BridgerAlderson/Zabbix-CVE-2024-42327-SQL-Injection-RCE](https://github.com/BridgerAlderson/Zabbix-CVE-2024-42327-SQL-Injection-RCE) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/Zabbix-CVE-2024-42327-SQL-Injection-RCE.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/Zabbix-CVE-2024-42327-SQL-Injection-RCE.svg)
- [https://github.com/aramosf/cve-2024-42327](https://github.com/aramosf/cve-2024-42327) :  ![starts](https://img.shields.io/github/stars/aramosf/cve-2024-42327.svg) ![forks](https://img.shields.io/github/forks/aramosf/cve-2024-42327.svg)
- [https://github.com/compr00t/CVE-2024-42327](https://github.com/compr00t/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/compr00t/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/compr00t/CVE-2024-42327.svg)
- [https://github.com/watchdog1337/CVE-2024-42327_Zabbix_SQLI](https://github.com/watchdog1337/CVE-2024-42327_Zabbix_SQLI) :  ![starts](https://img.shields.io/github/stars/watchdog1337/CVE-2024-42327_Zabbix_SQLI.svg) ![forks](https://img.shields.io/github/forks/watchdog1337/CVE-2024-42327_Zabbix_SQLI.svg)
- [https://github.com/depers-rus/CVE-2024-42327](https://github.com/depers-rus/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/depers-rus/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/depers-rus/CVE-2024-42327.svg)
- [https://github.com/igorbf495/CVE-2024-42327](https://github.com/igorbf495/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/igorbf495/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/igorbf495/CVE-2024-42327.svg)
- [https://github.com/itform-fr/Zabbix---CVE-2024-42327](https://github.com/itform-fr/Zabbix---CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/itform-fr/Zabbix---CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/itform-fr/Zabbix---CVE-2024-42327.svg)


## CVE-2024-41992
 Wi-Fi Alliance wfa_dut (in Wi-Fi Test Suite) through 9.0.0 allows OS command injection via 802.11x frames because the system() library function is used. For example, on Arcadyan FMIMG51AX000J devices, this leads to wfaTGSendPing remote code execution as root via traffic to TCP port 8000 or 8080 on a LAN interface. On other devices, this may be exploitable over a WAN interface.

- [https://github.com/fj016/CVE-2024-41992-PoC](https://github.com/fj016/CVE-2024-41992-PoC) :  ![starts](https://img.shields.io/github/stars/fj016/CVE-2024-41992-PoC.svg) ![forks](https://img.shields.io/github/forks/fj016/CVE-2024-41992-PoC.svg)


## CVE-2024-41958
 mailcow: dockerized is an open source groupware/email suite based on docker. A vulnerability has been discovered in the two-factor authentication (2FA) mechanism. This flaw allows an authenticated attacker to bypass the 2FA protection, enabling unauthorized access to other accounts that are otherwise secured with 2FA. To exploit this vulnerability, the attacker must first have access to an account within the system and possess the credentials of the target account that has 2FA enabled. By leveraging these credentials, the attacker can circumvent the 2FA process and gain access to the protected account. This issue has been addressed in the `2024-07` release. All users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/OrangeJuiceHU/CVE-2024-41958-PoC](https://github.com/OrangeJuiceHU/CVE-2024-41958-PoC) :  ![starts](https://img.shields.io/github/stars/OrangeJuiceHU/CVE-2024-41958-PoC.svg) ![forks](https://img.shields.io/github/forks/OrangeJuiceHU/CVE-2024-41958-PoC.svg)


## CVE-2024-41713
 A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations.

- [https://github.com/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713](https://github.com/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713.svg)
- [https://github.com/Sanandd/cve-2024-CVE-2024-41713](https://github.com/Sanandd/cve-2024-CVE-2024-41713) :  ![starts](https://img.shields.io/github/stars/Sanandd/cve-2024-CVE-2024-41713.svg) ![forks](https://img.shields.io/github/forks/Sanandd/cve-2024-CVE-2024-41713.svg)
- [https://github.com/zxj-hub/CVE-2024-41713POC](https://github.com/zxj-hub/CVE-2024-41713POC) :  ![starts](https://img.shields.io/github/stars/zxj-hub/CVE-2024-41713POC.svg) ![forks](https://img.shields.io/github/forks/zxj-hub/CVE-2024-41713POC.svg)


## CVE-2024-41662
 VNote is a note-taking platform. A Cross-Site Scripting (XSS) vulnerability has been identified in the Markdown rendering functionality of versions 3.18.1 and prior of the VNote note-taking application. This vulnerability allows the injection and execution of arbitrary JavaScript code through which remote code execution can be achieved. A patch for this issue is available at commit f1af78573a0ef51d6ef6a0bc4080cddc8f30a545. Other mitigation strategies include implementing rigorous input sanitization for all Markdown content and utilizing a secure Markdown parser that appropriately escapes or strips potentially dangerous content.

- [https://github.com/sh3bu/CVE-2024-41662](https://github.com/sh3bu/CVE-2024-41662) :  ![starts](https://img.shields.io/github/stars/sh3bu/CVE-2024-41662.svg) ![forks](https://img.shields.io/github/forks/sh3bu/CVE-2024-41662.svg)


## CVE-2024-41651
 An issue in Prestashop v.8.1.7 and before allows a remote attacker to execute arbitrary code via the module upgrade functionality. NOTE: this is disputed by multiple parties, who report that exploitation requires that an attacker be able to hijack network requests made by an admin user (who, by design, is allowed to change the code that is running on the server).

- [https://github.com/Fckroun/CVE-2024-41651](https://github.com/Fckroun/CVE-2024-41651) :  ![starts](https://img.shields.io/github/stars/Fckroun/CVE-2024-41651.svg) ![forks](https://img.shields.io/github/forks/Fckroun/CVE-2024-41651.svg)


## CVE-2024-41640
 Cross Site Scripting (XSS) vulnerability in AML Surety Eco up to 3.5 allows an attacker to run arbitrary code via crafted GET request using the id parameter.

- [https://github.com/alemusix/CVE-2024-41640](https://github.com/alemusix/CVE-2024-41640) :  ![starts](https://img.shields.io/github/stars/alemusix/CVE-2024-41640.svg) ![forks](https://img.shields.io/github/forks/alemusix/CVE-2024-41640.svg)


## CVE-2024-41628
 Directory Traversal vulnerability in Severalnines Cluster Control 1.9.8 before 1.9.8-9778, 2.0.0 before 2.0.0-9779, and 2.1.0 before 2.1.0-9780 allows a remote attacker to include and display file content in an HTTP request via the CMON API.

- [https://github.com/Redshift-CyberSecurity/CVE-2024-41628](https://github.com/Redshift-CyberSecurity/CVE-2024-41628) :  ![starts](https://img.shields.io/github/stars/Redshift-CyberSecurity/CVE-2024-41628.svg) ![forks](https://img.shields.io/github/forks/Redshift-CyberSecurity/CVE-2024-41628.svg)


## CVE-2024-41570
 An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

- [https://github.com/chebuya/Havoc-C2-SSRF-poc](https://github.com/chebuya/Havoc-C2-SSRF-poc) :  ![starts](https://img.shields.io/github/stars/chebuya/Havoc-C2-SSRF-poc.svg) ![forks](https://img.shields.io/github/forks/chebuya/Havoc-C2-SSRF-poc.svg)


## CVE-2024-41319
 TOTOLINK A6000R V1.0.1-B20201211.2000 was discovered to contain a command injection vulnerability via the cmd parameter in the webcmd function.

- [https://github.com/NingXin2002/TOTOLINK_poc](https://github.com/NingXin2002/TOTOLINK_poc) :  ![starts](https://img.shields.io/github/stars/NingXin2002/TOTOLINK_poc.svg) ![forks](https://img.shields.io/github/forks/NingXin2002/TOTOLINK_poc.svg)


## CVE-2024-41290
 FlatPress CMS v1.3.1 1.3 was discovered to use insecure methods to store authentication data via the cookie's component.

- [https://github.com/paragbagul111/CVE-2024-41290](https://github.com/paragbagul111/CVE-2024-41290) :  ![starts](https://img.shields.io/github/stars/paragbagul111/CVE-2024-41290.svg) ![forks](https://img.shields.io/github/forks/paragbagul111/CVE-2024-41290.svg)


## CVE-2024-41276
 A vulnerability in Kaiten version 57.131.12 and earlier allows attackers to bypass the PIN code authentication mechanism. The application requires users to input a 6-digit PIN code sent to their email for authorization after entering their login credentials. However, the request limiting mechanism can be easily bypassed, enabling attackers to perform a brute force attack to guess the correct PIN and gain unauthorized access to the application.

- [https://github.com/artemy-ccrsky/CVE-2024-41276](https://github.com/artemy-ccrsky/CVE-2024-41276) :  ![starts](https://img.shields.io/github/stars/artemy-ccrsky/CVE-2024-41276.svg) ![forks](https://img.shields.io/github/forks/artemy-ccrsky/CVE-2024-41276.svg)


## CVE-2024-41110
docker-ce v27.1.1 containes patches to fix the vulnerability. Patches have also been merged into the master, 19.03, 20.0, 23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is unable to upgrade immediately, avoid using AuthZ plugins and/or restrict access to the Docker API to trusted parties, following the principle of least privilege.

- [https://github.com/vvpoglazov/cve-2024-41110-checker](https://github.com/vvpoglazov/cve-2024-41110-checker) :  ![starts](https://img.shields.io/github/stars/vvpoglazov/cve-2024-41110-checker.svg) ![forks](https://img.shields.io/github/forks/vvpoglazov/cve-2024-41110-checker.svg)
- [https://github.com/PauloParoPP/CVE-2024-41110-SCAN](https://github.com/PauloParoPP/CVE-2024-41110-SCAN) :  ![starts](https://img.shields.io/github/stars/PauloParoPP/CVE-2024-41110-SCAN.svg) ![forks](https://img.shields.io/github/forks/PauloParoPP/CVE-2024-41110-SCAN.svg)


## CVE-2024-41107
Affected users are recommended to disable the SAML authentication plugin by setting the "saml2.enabled" global setting to "false", or upgrade to version 4.18.2.2, 4.19.1.0 or later, which addresses this issue.

- [https://github.com/d0rb/CVE-2024-41107](https://github.com/d0rb/CVE-2024-41107) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2024-41107.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2024-41107.svg)


## CVE-2024-40898
Users are recommended to upgrade to version 2.4.62 which fixes this issue. 

- [https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898](https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg)
- [https://github.com/whiterose7777/CVE-2024-40725-CVE-2024-40898](https://github.com/whiterose7777/CVE-2024-40725-CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/whiterose7777/CVE-2024-40725-CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/whiterose7777/CVE-2024-40725-CVE-2024-40898.svg)


## CVE-2024-40893
attacker that is authenticated to the Bluetooth Low-Energy (BTLE) interface can use the network configuration service to inject commands in various configuration parameters including networkConfig.Interface.Phy.Eth0.Extra.PingTestIP, networkConfig.Interface.Phy.Eth0.Extra.DNSTestDomain, and networkConfig.Interface.Phy.Eth0.Gateway6. Additionally, because the configuration can be synced to the Firewalla cloud, the attacker may be able to persist access even after hardware resets and firmware re-flashes.

- [https://github.com/xen0bit/fwbt](https://github.com/xen0bit/fwbt) :  ![starts](https://img.shields.io/github/stars/xen0bit/fwbt.svg) ![forks](https://img.shields.io/github/forks/xen0bit/fwbt.svg)


## CVE-2024-40892
 A weak credential vulnerability exists in Firewalla Box Software versions before 1.979. This vulnerability allows a physically close attacker to use the license UUID for authentication and provision SSH credentials over the Bluetooth Low-Energy (BTLE) interface. Once an attacker gains access to the LAN, they could log into the SSH interface using the provisioned credentials. The license UUID can be acquired through plain-text Bluetooth sniffing, reading the QR code on the bottom of the device, or brute-forcing the UUID (though this is less likely).

- [https://github.com/xen0bit/fwbt](https://github.com/xen0bit/fwbt) :  ![starts](https://img.shields.io/github/stars/xen0bit/fwbt.svg) ![forks](https://img.shields.io/github/forks/xen0bit/fwbt.svg)


## CVE-2024-40725
Users are recommended to upgrade to version 2.4.62, which fixes this issue.

- [https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898](https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg)
- [https://github.com/soltanali0/CVE-2024-40725](https://github.com/soltanali0/CVE-2024-40725) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2024-40725.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2024-40725.svg)
- [https://github.com/whiterose7777/CVE-2024-40725-CVE-2024-40898](https://github.com/whiterose7777/CVE-2024-40725-CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/whiterose7777/CVE-2024-40725-CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/whiterose7777/CVE-2024-40725-CVE-2024-40898.svg)


## CVE-2024-40711
 A deserialization of untrusted data vulnerability with a malicious payload can allow an unauthenticated remote code execution (RCE).

- [https://github.com/watchtowrlabs/CVE-2024-40711](https://github.com/watchtowrlabs/CVE-2024-40711) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2024-40711.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2024-40711.svg)
- [https://github.com/realstatus/CVE-2024-40711-Exp](https://github.com/realstatus/CVE-2024-40711-Exp) :  ![starts](https://img.shields.io/github/stars/realstatus/CVE-2024-40711-Exp.svg) ![forks](https://img.shields.io/github/forks/realstatus/CVE-2024-40711-Exp.svg)
- [https://github.com/XiaomingX/cve-2024-40711-poc](https://github.com/XiaomingX/cve-2024-40711-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-40711-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-40711-poc.svg)


## CVE-2024-40662
 In scheme of Uri.java, there is a possible way to craft a malformed Uri object due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Aakashmom/net_G2.5_CVE-2024-40662](https://github.com/Aakashmom/net_G2.5_CVE-2024-40662) :  ![starts](https://img.shields.io/github/stars/Aakashmom/net_G2.5_CVE-2024-40662.svg) ![forks](https://img.shields.io/github/forks/Aakashmom/net_G2.5_CVE-2024-40662.svg)


## CVE-2024-40658
 In getConfig of SoftVideoDecoderOMXComponent.cpp, there is a possible out of bounds write due to a heap buffer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-40658](https://github.com/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-40658) :  ![starts](https://img.shields.io/github/stars/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-40658.svg) ![forks](https://img.shields.io/github/forks/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-40658.svg)


## CVE-2024-40617
 Path traversal vulnerability exists in FUJITSU Network Edgiot GW1500 (M2M-GW for FENICS). If a remote authenticated attacker with User Class privilege sends a specially crafted request to the affected product, access restricted files containing sensitive information may be accessed. As a result, Administrator Class privileges of the product may be hijacked.

- [https://github.com/KyssK00L/CVE-2024-40617](https://github.com/KyssK00L/CVE-2024-40617) :  ![starts](https://img.shields.io/github/stars/KyssK00L/CVE-2024-40617.svg) ![forks](https://img.shields.io/github/forks/KyssK00L/CVE-2024-40617.svg)


## CVE-2024-40512
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMReporting.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40512](https://github.com/Jansen-C-Moreira/CVE-2024-40512) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40512.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40512.svg)


## CVE-2024-40511
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMServerAdmin.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40511](https://github.com/Jansen-C-Moreira/CVE-2024-40511) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40511.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40511.svg)


## CVE-2024-40510
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMCommon.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40510](https://github.com/Jansen-C-Moreira/CVE-2024-40510) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40510.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40510.svg)


## CVE-2024-40509
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMFinDev.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40509](https://github.com/Jansen-C-Moreira/CVE-2024-40509) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40509.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40509.svg)


## CVE-2024-40508
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMConference.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40508](https://github.com/Jansen-C-Moreira/CVE-2024-40508) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40508.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40508.svg)


## CVE-2024-40507
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMPersonnel.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40507](https://github.com/Jansen-C-Moreira/CVE-2024-40507) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40507.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40507.svg)


## CVE-2024-40506
 Cross Site Scripting vulnerability in openPetra v.2023.02 allows a remote attacker to obtain sensitive information via the serverMHospitality.asmx function.

- [https://github.com/Jansen-C-Moreira/CVE-2024-40506](https://github.com/Jansen-C-Moreira/CVE-2024-40506) :  ![starts](https://img.shields.io/github/stars/Jansen-C-Moreira/CVE-2024-40506.svg) ![forks](https://img.shields.io/github/forks/Jansen-C-Moreira/CVE-2024-40506.svg)


## CVE-2024-40500
 Cross Site Scripting vulnerability in Martin Kucej i-librarian v.5.11.0 and before allows a local attacker to execute arbitrary code via the search function in the import component.

- [https://github.com/nitipoom-jar/CVE-2024-40500](https://github.com/nitipoom-jar/CVE-2024-40500) :  ![starts](https://img.shields.io/github/stars/nitipoom-jar/CVE-2024-40500.svg) ![forks](https://img.shields.io/github/forks/nitipoom-jar/CVE-2024-40500.svg)


## CVE-2024-40498
 SQL Injection vulnerability in PuneethReddyHC Online Shopping sysstem advanced v.1.0 allows an attacker to execute arbitrary code via the register.php

- [https://github.com/Dirac231/CVE-2024-40498](https://github.com/Dirac231/CVE-2024-40498) :  ![starts](https://img.shields.io/github/stars/Dirac231/CVE-2024-40498.svg) ![forks](https://img.shields.io/github/forks/Dirac231/CVE-2024-40498.svg)


## CVE-2024-40492
 Cross Site Scripting vulnerability in Heartbeat Chat v.15.2.1 allows a remote attacker to execute arbitrary code via the setname function.

- [https://github.com/minendie/POC_CVE-2024-40492](https://github.com/minendie/POC_CVE-2024-40492) :  ![starts](https://img.shields.io/github/stars/minendie/POC_CVE-2024-40492.svg) ![forks](https://img.shields.io/github/forks/minendie/POC_CVE-2024-40492.svg)


## CVE-2024-40457
 No-IP Dynamic Update Client (DUC) v3.x uses cleartext credentials that may occur on a command line or in a file. NOTE: the vendor's position is that cleartext in /etc/default/noip-duc is recommended and is the intentional behavior.

- [https://github.com/jeppojeps/CVE-2024-40457-PoC](https://github.com/jeppojeps/CVE-2024-40457-PoC) :  ![starts](https://img.shields.io/github/stars/jeppojeps/CVE-2024-40457-PoC.svg) ![forks](https://img.shields.io/github/forks/jeppojeps/CVE-2024-40457-PoC.svg)


## CVE-2024-40443
 SQL Injection vulnerability in Simple Laboratory Management System using PHP and MySQL v.1.0 allows a remote attacker to cause a denial of service via the delete_users function in the Useres.php

- [https://github.com/Yuma-Tsushima07/CVE-2024-40443](https://github.com/Yuma-Tsushima07/CVE-2024-40443) :  ![starts](https://img.shields.io/github/stars/Yuma-Tsushima07/CVE-2024-40443.svg) ![forks](https://img.shields.io/github/forks/Yuma-Tsushima07/CVE-2024-40443.svg)


## CVE-2024-40431
 A lack of input validation in Realtek SD card reader driver before 10.0.26100.21374 through the implementation of the IOCTL_SCSI_PASS_THROUGH control of the SD card reader driver allows an attacker to write to predictable kernel memory locations, even as a low-privileged user.

- [https://github.com/SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN](https://github.com/SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN.svg)


## CVE-2024-40422
 The snapshot_path parameter in the /api/get-browser-snapshot endpoint in stitionai devika v1 is susceptible to a path traversal attack. An attacker can manipulate the snapshot_path parameter to traverse directories and access sensitive files on the server. This can potentially lead to unauthorized access to critical system files and compromise the confidentiality and integrity of the system.

- [https://github.com/alpernae/CVE-2024-40422](https://github.com/alpernae/CVE-2024-40422) :  ![starts](https://img.shields.io/github/stars/alpernae/CVE-2024-40422.svg) ![forks](https://img.shields.io/github/forks/alpernae/CVE-2024-40422.svg)
- [https://github.com/j3r1ch0123/CVE-2024-40422](https://github.com/j3r1ch0123/CVE-2024-40422) :  ![starts](https://img.shields.io/github/stars/j3r1ch0123/CVE-2024-40422.svg) ![forks](https://img.shields.io/github/forks/j3r1ch0123/CVE-2024-40422.svg)
- [https://github.com/codeb0ss/CVE-2024-40422-PoC](https://github.com/codeb0ss/CVE-2024-40422-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-40422-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-40422-PoC.svg)


## CVE-2024-40348
 An issue in the component /api/swaggerui/static of Bazaar v1.4.3 allows unauthenticated attackers to execute a directory traversal.

- [https://github.com/bigb0x/CVE-2024-40348](https://github.com/bigb0x/CVE-2024-40348) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-40348.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-40348.svg)
- [https://github.com/codeb0ss/CVEploiterv2](https://github.com/codeb0ss/CVEploiterv2) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVEploiterv2.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVEploiterv2.svg)
- [https://github.com/codeb0ss/CVE-2024-40348-PoC](https://github.com/codeb0ss/CVE-2024-40348-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-40348-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-40348-PoC.svg)
- [https://github.com/NingXin2002/Bazaar_poc](https://github.com/NingXin2002/Bazaar_poc) :  ![starts](https://img.shields.io/github/stars/NingXin2002/Bazaar_poc.svg) ![forks](https://img.shields.io/github/forks/NingXin2002/Bazaar_poc.svg)


## CVE-2024-40324
 A CRLF injection vulnerability in E-Staff v5.1 allows attackers to insert Carriage Return (CR) and Line Feed (LF) characters into input fields, leading to HTTP response splitting and header manipulation.

- [https://github.com/aleksey-vi/CVE-2024-40324](https://github.com/aleksey-vi/CVE-2024-40324) :  ![starts](https://img.shields.io/github/stars/aleksey-vi/CVE-2024-40324.svg) ![forks](https://img.shields.io/github/forks/aleksey-vi/CVE-2024-40324.svg)


## CVE-2024-40318
 An arbitrary file upload vulnerability in Webkul Qloapps v1.6.0.0 allows attackers to execute arbitrary code via uploading a crafted file.

- [https://github.com/3v1lC0d3/RCE-QloApps-CVE-2024-40318](https://github.com/3v1lC0d3/RCE-QloApps-CVE-2024-40318) :  ![starts](https://img.shields.io/github/stars/3v1lC0d3/RCE-QloApps-CVE-2024-40318.svg) ![forks](https://img.shields.io/github/forks/3v1lC0d3/RCE-QloApps-CVE-2024-40318.svg)


## CVE-2024-40119
 Nepstech Wifi Router xpon (terminal) model NTPL-Xpon1GFEVN v.1.0 Firmware V2.0.1 contains a Cross-Site Request Forgery (CSRF) vulnerability in the password change function, which allows remote attackers to change the admin password without the user's consent, leading to a potential account takeover.

- [https://github.com/sudo-subho/nepstech-xpon-router-CVE-2024-40119](https://github.com/sudo-subho/nepstech-xpon-router-CVE-2024-40119) :  ![starts](https://img.shields.io/github/stars/sudo-subho/nepstech-xpon-router-CVE-2024-40119.svg) ![forks](https://img.shields.io/github/forks/sudo-subho/nepstech-xpon-router-CVE-2024-40119.svg)


## CVE-2024-40110
 Sourcecodester Poultry Farm Management System v1.0 contains an Unauthenticated Remote Code Execution (RCE) vulnerability via the productimage parameter at /farm/product.php.

- [https://github.com/Abdurahmon3236/CVE-2024-40110](https://github.com/Abdurahmon3236/CVE-2024-40110) :  ![starts](https://img.shields.io/github/stars/Abdurahmon3236/CVE-2024-40110.svg) ![forks](https://img.shields.io/github/forks/Abdurahmon3236/CVE-2024-40110.svg)


## CVE-2024-39943
 rejetto HFS (aka HTTP File Server) 3 before 0.52.10 on Linux, UNIX, and macOS allows OS command execution by remote authenticated users (if they have Upload permissions). This occurs because a shell is used to execute df (i.e., with execSync instead of spawnSync in child_process in Node.js).

- [https://github.com/truonghuuphuc/CVE-2024-39943-Poc](https://github.com/truonghuuphuc/CVE-2024-39943-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-39943-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-39943-Poc.svg)
- [https://github.com/tequilasunsh1ne/CVE_2024_39943](https://github.com/tequilasunsh1ne/CVE_2024_39943) :  ![starts](https://img.shields.io/github/stars/tequilasunsh1ne/CVE_2024_39943.svg) ![forks](https://img.shields.io/github/forks/tequilasunsh1ne/CVE_2024_39943.svg)


## CVE-2024-39929
 Exim through 4.97.1 misparses a multiline RFC 2231 header filename, and thus remote attackers can bypass a $mime_filename extension-blocking protection mechanism, and potentially deliver executable attachments to the mailboxes of end users.

- [https://github.com/rxerium/CVE-2024-39929](https://github.com/rxerium/CVE-2024-39929) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-39929.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-39929.svg)
- [https://github.com/michael-david-fry/CVE-2024-39929](https://github.com/michael-david-fry/CVE-2024-39929) :  ![starts](https://img.shields.io/github/stars/michael-david-fry/CVE-2024-39929.svg) ![forks](https://img.shields.io/github/forks/michael-david-fry/CVE-2024-39929.svg)


## CVE-2024-39914
 FOG is a cloning/imaging/rescue suite/inventory management system. Prior to 1.5.10.34, packages/web/lib/fog/reportmaker.class.php in FOG was affected by a command injection via the filename parameter to /fog/management/export.php. This vulnerability is fixed in 1.5.10.34.

- [https://github.com/9874621368/FOG-Project](https://github.com/9874621368/FOG-Project) :  ![starts](https://img.shields.io/github/stars/9874621368/FOG-Project.svg) ![forks](https://img.shields.io/github/forks/9874621368/FOG-Project.svg)


## CVE-2024-39908
  REXML is an XML toolkit for Ruby. The REXML gem before 3.3.1 has some DoS vulnerabilities when it parses an XML that has many specific characters such as ``, `0` and `%`. If you need to parse untrusted XMLs, you many be impacted to these vulnerabilities. The REXML gem 3.3.2 or later include the patches to fix these vulnerabilities. Users are advised to upgrade. Users unable to upgrade should avoid parsing untrusted XML strings.

- [https://github.com/SpiralBL0CK/CVE-2024-39908](https://github.com/SpiralBL0CK/CVE-2024-39908) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-39908.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-39908.svg)


## CVE-2024-39844
 In ZNC before 1.9.1, remote code execution can occur in modtcl via a KICK.

- [https://github.com/ph1ns/CVE-2024-39844](https://github.com/ph1ns/CVE-2024-39844) :  ![starts](https://img.shields.io/github/stars/ph1ns/CVE-2024-39844.svg) ![forks](https://img.shields.io/github/forks/ph1ns/CVE-2024-39844.svg)


## CVE-2024-39700
 JupyterLab extension template is a  `copier` template for JupyterLab extensions. Repositories created using this template with `test` option include `update-integration-tests.yml` workflow which has an RCE vulnerability. Extension authors hosting their code on GitHub are urged to upgrade the template to the latest version. Users who made changes to `update-integration-tests.yml`, accept overwriting of this file and re-apply your changes later. Users may wish to temporarily disable GitHub Actions while working on the upgrade. We recommend rebasing all open pull requests from untrusted users as actions may run using the version from the `main` branch at the time when the pull request was created. Users who are upgrading from template version prior to 4.3.0 may wish to leave out proposed changes to the release workflow for now as it requires additional configuration.

- [https://github.com/LOURC0D3/CVE-2024-39700-PoC](https://github.com/LOURC0D3/CVE-2024-39700-PoC) :  ![starts](https://img.shields.io/github/stars/LOURC0D3/CVE-2024-39700-PoC.svg) ![forks](https://img.shields.io/github/forks/LOURC0D3/CVE-2024-39700-PoC.svg)


## CVE-2024-39689
 Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi starting in 2021.05.30 and prior to 2024.07.4 recognized root certificates from `GLOBALTRUST`. Certifi 2024.07.04 removes root certificates from `GLOBALTRUST` from the root store. These are in the process of being removed from Mozilla's trust store. `GLOBALTRUST`'s root certificates are being removed pursuant to an investigation which identified "long-running and unresolved compliance issues."

- [https://github.com/roy-aladin/InfraTest](https://github.com/roy-aladin/InfraTest) :  ![starts](https://img.shields.io/github/stars/roy-aladin/InfraTest.svg) ![forks](https://img.shields.io/github/forks/roy-aladin/InfraTest.svg)


## CVE-2024-39614
 An issue was discovered in Django 5.0 before 5.0.7 and 4.2 before 4.2.14. get_supported_language_variant() was subject to a potential denial-of-service attack when used with very long strings containing specific characters.

- [https://github.com/Abdurahmon3236/-CVE-2024-39614](https://github.com/Abdurahmon3236/-CVE-2024-39614) :  ![starts](https://img.shields.io/github/stars/Abdurahmon3236/-CVE-2024-39614.svg) ![forks](https://img.shields.io/github/forks/Abdurahmon3236/-CVE-2024-39614.svg)


## CVE-2024-39573
Users are recommended to upgrade to version 2.4.60, which fixes this issue.

- [https://github.com/mrmtwoj/apache-vulnerability-testing](https://github.com/mrmtwoj/apache-vulnerability-testing) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/apache-vulnerability-testing.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/apache-vulnerability-testing.svg)


## CVE-2024-29075
 Active debug code vulnerability exists in Mesh Wi-Fi router RP562B firmware version v1.0.2 and earlier. If this vulnerability is exploited, a network-adjacent authenticated attacker may obtain or alter the settings of the device .

- [https://github.com/0xNslabs/SoftBankMeshAPI](https://github.com/0xNslabs/SoftBankMeshAPI) :  ![starts](https://img.shields.io/github/stars/0xNslabs/SoftBankMeshAPI.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/SoftBankMeshAPI.svg)


## CVE-2024-12986
 A vulnerability, which was classified as critical, has been found in DrayTek Vigor2960 and Vigor300B 1.5.1.3/1.5.1.4. This issue affects some unknown processing of the file /cgi-bin/mainfunction.cgi/apmcfgupptim of the component Web Management Interface. The manipulation of the argument session leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.5.1.5 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/Aether-0/CVE-2024-12986](https://github.com/Aether-0/CVE-2024-12986) :  ![starts](https://img.shields.io/github/stars/Aether-0/CVE-2024-12986.svg) ![forks](https://img.shields.io/github/forks/Aether-0/CVE-2024-12986.svg)


## CVE-2024-12970
 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in TUBITAK BILGEM Pardus OS My Computer allows OS Command Injection.This issue affects Pardus OS My Computer: before 0.7.2.

- [https://github.com/osmancanvural/CVE-2024-12970](https://github.com/osmancanvural/CVE-2024-12970) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2024-12970.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2024-12970.svg)


## CVE-2024-12883
 A vulnerability was found in code-projects Job Recruitment 1.0. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file /_email.php. The manipulation of the argument email leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/mhtsec/cve-2024-12883](https://github.com/mhtsec/cve-2024-12883) :  ![starts](https://img.shields.io/github/stars/mhtsec/cve-2024-12883.svg) ![forks](https://img.shields.io/github/forks/mhtsec/cve-2024-12883.svg)


## CVE-2024-12849
 The Error Log Viewer By WP Guru plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 1.0.1.3 via the wp_ajax_nopriv_elvwp_log_download AJAX action. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/RandomRobbieBF/CVE-2024-12849](https://github.com/RandomRobbieBF/CVE-2024-12849) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12849.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12849.svg)
- [https://github.com/Nxploited/CVE-2024-12849-Poc](https://github.com/Nxploited/CVE-2024-12849-Poc) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-12849-Poc.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-12849-Poc.svg)


## CVE-2024-12484
 A vulnerability classified as critical was found in Codezips Technical Discussion Forum 1.0. This vulnerability affects unknown code of the file /signuppost.php. The manipulation of the argument Username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/LiChaser/CVE-2024-12484](https://github.com/LiChaser/CVE-2024-12484) :  ![starts](https://img.shields.io/github/stars/LiChaser/CVE-2024-12484.svg) ![forks](https://img.shields.io/github/forks/LiChaser/CVE-2024-12484.svg)


## CVE-2024-12270
 The Beautiful taxonomy filters plugin for WordPress is vulnerable to SQL Injection via the 'selects[0][term]' parameter in all versions up to, and including, 2.4.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-12270](https://github.com/RandomRobbieBF/CVE-2024-12270) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12270.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12270.svg)


## CVE-2024-12209
 The WP Umbrella: Update Backup Restore & Monitoring plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.17.0 via the 'filename' parameter of the 'umbrella-restore' action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/Nxploited/CVE-2024-12209](https://github.com/Nxploited/CVE-2024-12209) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-12209.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-12209.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-12209](https://github.com/RandomRobbieBF/CVE-2024-12209) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12209.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12209.svg)


## CVE-2024-12172
 The WP Courses LMS – Online Courses Builder, eLearning Courses, Courses Solution, Education Courses plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on the wpc_update_user_meta_option() function in all versions up to, and including, 3.2.21. This makes it possible for authenticated attackers, with Subscriber-level access and above, to update arbitrary user's metadata which can be levereged to block an administrator from accessing their site when wp_capabilities is set to 0.

- [https://github.com/RandomRobbieBF/CVE-2024-12172](https://github.com/RandomRobbieBF/CVE-2024-12172) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12172.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12172.svg)


## CVE-2024-12155
 The SV100 Companion plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the settings_import() function in all versions up to, and including, 2.0.02. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.

- [https://github.com/McTavishSue/CVE-2024-12155](https://github.com/McTavishSue/CVE-2024-12155) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2024-12155.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2024-12155.svg)


## CVE-2024-12025
 The Collapsing Categories plugin for WordPress is vulnerable to SQL Injection via the 'taxonomy' parameter of the /wp-json/collapsing-categories/v1/get REST API in all versions up to, and including, 3.0.8 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-12025](https://github.com/RandomRobbieBF/CVE-2024-12025) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12025.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12025.svg)


## CVE-2024-11972
 The Hunk Companion WordPress plugin before 1.9.0 does not correctly authorize some REST API endpoints, allowing unauthenticated requests to install and activate arbitrary Hunk Companion WordPress plugin before 1.9.0 from the WordPress.org repo, including vulnerable Hunk Companion WordPress plugin before 1.9.0 that have been closed.

- [https://github.com/JunTakemura/exploit-CVE-2024-11972](https://github.com/JunTakemura/exploit-CVE-2024-11972) :  ![starts](https://img.shields.io/github/stars/JunTakemura/exploit-CVE-2024-11972.svg) ![forks](https://img.shields.io/github/forks/JunTakemura/exploit-CVE-2024-11972.svg)


## CVE-2024-11728
 The KiviCare – Clinic & Patient Management System (EHR) plugin for WordPress is vulnerable to SQL Injection via the 'visit_type[service_id]' parameter of the tax_calculated_data AJAX action in all versions up to, and including, 3.6.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/samogod/CVE-2024-11728](https://github.com/samogod/CVE-2024-11728) :  ![starts](https://img.shields.io/github/stars/samogod/CVE-2024-11728.svg) ![forks](https://img.shields.io/github/forks/samogod/CVE-2024-11728.svg)


## CVE-2024-11680
 ProjectSend versions prior to r1720 are affected by an improper authentication vulnerability. Remote, unauthenticated attackers can exploit this flaw by sending crafted HTTP requests to options.php, enabling unauthorized modification of the application's configuration. Successful exploitation allows attackers to create accounts, upload webshells, and embed malicious JavaScript.

- [https://github.com/D3N14LD15K/CVE-2024-11680_PoC_Exploit](https://github.com/D3N14LD15K/CVE-2024-11680_PoC_Exploit) :  ![starts](https://img.shields.io/github/stars/D3N14LD15K/CVE-2024-11680_PoC_Exploit.svg) ![forks](https://img.shields.io/github/forks/D3N14LD15K/CVE-2024-11680_PoC_Exploit.svg)


## CVE-2024-11643
 The Accessibility by AllAccessible plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the 'AllAccessible_save_settings' function in all versions up to, and including, 1.3.4. This makes it possible for authenticated attackers, with Subscriber-level access and above, to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.

- [https://github.com/RandomRobbieBF/CVE-2024-11643](https://github.com/RandomRobbieBF/CVE-2024-11643) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-11643.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-11643.svg)


## CVE-2024-11616
This issue affects Endpoint DLP version below R119.

- [https://github.com/inb1ts/CVE-2024-11616](https://github.com/inb1ts/CVE-2024-11616) :  ![starts](https://img.shields.io/github/stars/inb1ts/CVE-2024-11616.svg) ![forks](https://img.shields.io/github/forks/inb1ts/CVE-2024-11616.svg)


## CVE-2024-11613
 The WordPress File Upload plugin for WordPress is vulnerable to Remote Code Execution, Arbitrary File Read, and Arbitrary File Deletion in all versions up to, and including, 4.24.15 via the 'wfu_file_downloader.php' file. This is due to lack of proper sanitization of the 'source' parameter and allowing a user-defined directory path. This makes it possible for unauthenticated attackers to execute code on the server.

- [https://github.com/Sachinart/CVE-2024-11613-wp-file-upload](https://github.com/Sachinart/CVE-2024-11613-wp-file-upload) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2024-11613-wp-file-upload.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2024-11613-wp-file-upload.svg)


## CVE-2024-11477
The specific flaw exists within the implementation of Zstandard decompression. The issue results from the lack of proper validation of user-supplied data, which can result in an integer underflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-24346.

- [https://github.com/TheN00bBuilder/cve-2024-11477-writeup](https://github.com/TheN00bBuilder/cve-2024-11477-writeup) :  ![starts](https://img.shields.io/github/stars/TheN00bBuilder/cve-2024-11477-writeup.svg) ![forks](https://img.shields.io/github/forks/TheN00bBuilder/cve-2024-11477-writeup.svg)


## CVE-2024-11432
 The SuevaFree Essential Kit plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'counter' shortcode in all versions up to, and including, 1.1.3 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11432](https://github.com/windz3r0day/CVE-2024-11432) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11432.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11432.svg)


## CVE-2024-11428
 The Lazy load videos and sticky control plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'lazy-load-videos-and-sticky-control' shortcode in all versions up to, and including, 3.0.0 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11428](https://github.com/windz3r0day/CVE-2024-11428) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11428.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11428.svg)


## CVE-2024-11423
 The Ultimate Gift Cards for WooCommerce – Create WooCommerce Gift Cards, Gift Vouchers, Redeem & Manage Digital Gift Coupons. Offer Gift Certificates, Schedule Gift Cards, and Use Advance Coupons With Personalized Templates plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on several REST API endpoints such as /wp-json/gifting/recharge-giftcard in all versions up to, and including, 3.0.6. This makes it possible for unauthenticated attackers to recharge a gift card balance, without making a payment along with reducing gift card balances without purchasing anything.

- [https://github.com/RandomRobbieBF/CVE-2024-11423](https://github.com/RandomRobbieBF/CVE-2024-11423) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-11423.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-11423.svg)


## CVE-2024-11412
 The Shine PDF Embeder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'shinepdf' shortcode in all versions up to, and including, 1.0 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11412](https://github.com/windz3r0day/CVE-2024-11412) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11412.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11412.svg)


## CVE-2024-11394
The specific flaw exists within the handling of model files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25012.

- [https://github.com/Piyush-Bhor/CVE-2024-11394](https://github.com/Piyush-Bhor/CVE-2024-11394) :  ![starts](https://img.shields.io/github/stars/Piyush-Bhor/CVE-2024-11394.svg) ![forks](https://img.shields.io/github/forks/Piyush-Bhor/CVE-2024-11394.svg)


## CVE-2024-11393
The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25191.

- [https://github.com/Piyush-Bhor/CVE-2024-11393](https://github.com/Piyush-Bhor/CVE-2024-11393) :  ![starts](https://img.shields.io/github/stars/Piyush-Bhor/CVE-2024-11393.svg) ![forks](https://img.shields.io/github/forks/Piyush-Bhor/CVE-2024-11393.svg)


## CVE-2024-11392
The specific flaw exists within the handling of configuration files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-24322.

- [https://github.com/Piyush-Bhor/CVE-2024-11392](https://github.com/Piyush-Bhor/CVE-2024-11392) :  ![starts](https://img.shields.io/github/stars/Piyush-Bhor/CVE-2024-11392.svg) ![forks](https://img.shields.io/github/forks/Piyush-Bhor/CVE-2024-11392.svg)


## CVE-2024-11388
 The Dino Game – Embed Google Chrome Dinosaur Game in WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'dino-game' shortcode in all versions up to, and including, 1.1.0 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11388](https://github.com/windz3r0day/CVE-2024-11388) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11388.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11388.svg)


## CVE-2024-11387
 The Easy Liveblogs plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'elb_liveblog' shortcode in all versions up to, and including, 2.3.5 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11387](https://github.com/windz3r0day/CVE-2024-11387) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11387.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11387.svg)


## CVE-2024-11381
 The Control horas plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'ch_registro' shortcode in all versions up to, and including, 1.0.1 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11381](https://github.com/windz3r0day/CVE-2024-11381) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11381.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11381.svg)


## CVE-2024-11320
 Arbitrary commands execution on the server by exploiting a command injection vulnerability in the LDAP authentication mechanism. This issue affects Pandora FMS: from 700 through =777.4

- [https://github.com/mhaskar/CVE-2024-11320](https://github.com/mhaskar/CVE-2024-11320) :  ![starts](https://img.shields.io/github/stars/mhaskar/CVE-2024-11320.svg) ![forks](https://img.shields.io/github/forks/mhaskar/CVE-2024-11320.svg)


## CVE-2024-11318
 An IDOR (Insecure Direct Object Reference) vulnerability has been discovered in AbsysNet, affecting version 2.3.1. This vulnerability could allow a remote attacker to obtain the session of an unauthenticated user by brute-force attacking the session identifier on the "/cgi-bin/ocap/" endpoint.

- [https://github.com/xthalach/CVE-2024-11318](https://github.com/xthalach/CVE-2024-11318) :  ![starts](https://img.shields.io/github/stars/xthalach/CVE-2024-11318.svg) ![forks](https://img.shields.io/github/forks/xthalach/CVE-2024-11318.svg)


## CVE-2024-11281
 The WooCommerce Point of Sale plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 6.1.0. This is due to insufficient validation on the 'logged_in_user_id' value when option values are empty and the ability for attackers to change the email of arbitrary user accounts. This makes it possible for unauthenticated attackers to change the email of arbitrary user accounts, including administrators, and reset their password to gain access to the account.

- [https://github.com/McTavishSue/CVE-2024-11281](https://github.com/McTavishSue/CVE-2024-11281) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2024-11281.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2024-11281.svg)


## CVE-2024-11252
 The Social Sharing Plugin – Sassy Social Share plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the heateor_mastodon_share parameter in all versions up to, and including, 3.3.69 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/reinh3rz/CVE-2024-11252-Sassy-Social-Share-XSS](https://github.com/reinh3rz/CVE-2024-11252-Sassy-Social-Share-XSS) :  ![starts](https://img.shields.io/github/stars/reinh3rz/CVE-2024-11252-Sassy-Social-Share-XSS.svg) ![forks](https://img.shields.io/github/forks/reinh3rz/CVE-2024-11252-Sassy-Social-Share-XSS.svg)


## CVE-2024-11201
 The myCred – Loyalty Points and Rewards plugin for WordPress and WooCommerce – Give Points, Ranks, Badges, Cashback, WooCommerce rewards, and WooCommerce credits for Gamification plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's mycred_send shortcode in all versions up to, and including, 2.7.5.2 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/NSQAQ/CVE-2024-11201](https://github.com/NSQAQ/CVE-2024-11201) :  ![starts](https://img.shields.io/github/stars/NSQAQ/CVE-2024-11201.svg) ![forks](https://img.shields.io/github/forks/NSQAQ/CVE-2024-11201.svg)


## CVE-2024-11199
 The Rescue Shortcodes plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's rescue_progressbar shortcode in all versions up to, and including, 2.9 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-11199](https://github.com/windz3r0day/CVE-2024-11199) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11199.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11199.svg)


## CVE-2024-11003
 Qualys discovered that needrestart, before version 3.8, passes unsanitized data to a library (Modules::ScanDeps) which expects safe input. This could allow a local attacker to execute arbitrary shell commands. Please see the related CVE-2024-10224 in Modules::ScanDeps.

- [https://github.com/unknown-user-from/CVE-2024-11003-PoC](https://github.com/unknown-user-from/CVE-2024-11003-PoC) :  ![starts](https://img.shields.io/github/stars/unknown-user-from/CVE-2024-11003-PoC.svg) ![forks](https://img.shields.io/github/forks/unknown-user-from/CVE-2024-11003-PoC.svg)


## CVE-2024-10958
 The The WP Photo Album Plus plugin for WordPress is vulnerable to arbitrary shortcode execution via getshortcodedrenderedfenodelay AJAX action in all versions up to, and including, 8.8.08.007 . This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes.

- [https://github.com/reinh3rz/CVE-2024-10958-WPPA-Exploit](https://github.com/reinh3rz/CVE-2024-10958-WPPA-Exploit) :  ![starts](https://img.shields.io/github/stars/reinh3rz/CVE-2024-10958-WPPA-Exploit.svg) ![forks](https://img.shields.io/github/forks/reinh3rz/CVE-2024-10958-WPPA-Exploit.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/m3ssap0/wordpress-really-simple-security-authn-bypass-exploit](https://github.com/m3ssap0/wordpress-really-simple-security-authn-bypass-exploit) :  ![starts](https://img.shields.io/github/stars/m3ssap0/wordpress-really-simple-security-authn-bypass-exploit.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/wordpress-really-simple-security-authn-bypass-exploit.svg)
- [https://github.com/m3ssap0/wordpress-really-simple-security-authn-bypass-vulnerable-application](https://github.com/m3ssap0/wordpress-really-simple-security-authn-bypass-vulnerable-application) :  ![starts](https://img.shields.io/github/stars/m3ssap0/wordpress-really-simple-security-authn-bypass-vulnerable-application.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/wordpress-really-simple-security-authn-bypass-vulnerable-application.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-10924](https://github.com/RandomRobbieBF/CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10924.svg)
- [https://github.com/Maalfer/CVE-2024-10924-PoC](https://github.com/Maalfer/CVE-2024-10924-PoC) :  ![starts](https://img.shields.io/github/stars/Maalfer/CVE-2024-10924-PoC.svg) ![forks](https://img.shields.io/github/forks/Maalfer/CVE-2024-10924-PoC.svg)
- [https://github.com/Trackflaw/CVE-2024-10924-Wordpress-Docker](https://github.com/Trackflaw/CVE-2024-10924-Wordpress-Docker) :  ![starts](https://img.shields.io/github/stars/Trackflaw/CVE-2024-10924-Wordpress-Docker.svg) ![forks](https://img.shields.io/github/forks/Trackflaw/CVE-2024-10924-Wordpress-Docker.svg)
- [https://github.com/D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB](https://github.com/D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB) :  ![starts](https://img.shields.io/github/stars/D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB.svg) ![forks](https://img.shields.io/github/forks/D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB.svg)
- [https://github.com/MattJButler/CVE-2024-10924](https://github.com/MattJButler/CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/MattJButler/CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/MattJButler/CVE-2024-10924.svg)
- [https://github.com/Hunt3r850/CVE-2024-10924-Wordpress-Docker](https://github.com/Hunt3r850/CVE-2024-10924-Wordpress-Docker) :  ![starts](https://img.shields.io/github/stars/Hunt3r850/CVE-2024-10924-Wordpress-Docker.svg) ![forks](https://img.shields.io/github/forks/Hunt3r850/CVE-2024-10924-Wordpress-Docker.svg)
- [https://github.com/Hunt3r850/CVE-2024-10924-PoC](https://github.com/Hunt3r850/CVE-2024-10924-PoC) :  ![starts](https://img.shields.io/github/stars/Hunt3r850/CVE-2024-10924-PoC.svg) ![forks](https://img.shields.io/github/forks/Hunt3r850/CVE-2024-10924-PoC.svg)


## CVE-2024-10914
 A vulnerability was found in D-Link DNS-320, DNS-320LW, DNS-325 and DNS-340L up to 20241028. It has been declared as critical. Affected by this vulnerability is the function cgi_user_add of the file /cgi-bin/account_mgr.cgi?cmd=cgi_user_add. The manipulation of the argument name leads to os command injection. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used.

- [https://github.com/verylazytech/CVE-2024-10914](https://github.com/verylazytech/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-10914.svg)
- [https://github.com/imnotcha0s/CVE-2024-10914](https://github.com/imnotcha0s/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/imnotcha0s/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/imnotcha0s/CVE-2024-10914.svg)
- [https://github.com/redspy-sec/D-Link](https://github.com/redspy-sec/D-Link) :  ![starts](https://img.shields.io/github/stars/redspy-sec/D-Link.svg) ![forks](https://img.shields.io/github/forks/redspy-sec/D-Link.svg)
- [https://github.com/ThemeHackers/CVE-2024-10914](https://github.com/ThemeHackers/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2024-10914.svg)
- [https://github.com/Bu0uCat/D-Link-NAS-CVE-2024-10914-](https://github.com/Bu0uCat/D-Link-NAS-CVE-2024-10914-) :  ![starts](https://img.shields.io/github/stars/Bu0uCat/D-Link-NAS-CVE-2024-10914-.svg) ![forks](https://img.shields.io/github/forks/Bu0uCat/D-Link-NAS-CVE-2024-10914-.svg)
- [https://github.com/Egi08/CVE-2024-10914](https://github.com/Egi08/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/Egi08/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/Egi08/CVE-2024-10914.svg)
- [https://github.com/dragonXZH/CVE-2024-10914](https://github.com/dragonXZH/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/dragonXZH/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/dragonXZH/CVE-2024-10914.svg)
- [https://github.com/retuci0/cve-2024-10914-port](https://github.com/retuci0/cve-2024-10914-port) :  ![starts](https://img.shields.io/github/stars/retuci0/cve-2024-10914-port.svg) ![forks](https://img.shields.io/github/forks/retuci0/cve-2024-10914-port.svg)
- [https://github.com/jahithoque/CVE-2024-10914-Exploit](https://github.com/jahithoque/CVE-2024-10914-Exploit) :  ![starts](https://img.shields.io/github/stars/jahithoque/CVE-2024-10914-Exploit.svg) ![forks](https://img.shields.io/github/forks/jahithoque/CVE-2024-10914-Exploit.svg)
- [https://github.com/K3ysTr0K3R/CVE-2024-10914-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-10914-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-10914-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-10914-EXPLOIT.svg)


## CVE-2024-10793
 The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the user_id parameter in all versions up to, and including, 5.2.1 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever an administrative user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-10793](https://github.com/windz3r0day/CVE-2024-10793) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-10793.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-10793.svg)
- [https://github.com/MAHajian/CVE-2024-10793](https://github.com/MAHajian/CVE-2024-10793) :  ![starts](https://img.shields.io/github/stars/MAHajian/CVE-2024-10793.svg) ![forks](https://img.shields.io/github/forks/MAHajian/CVE-2024-10793.svg)


## CVE-2024-10728
 The Post Grid Gutenberg Blocks and WordPress Blog Plugin – PostX plugin for WordPress is vulnerable to unauthorized plugin installation/activation due to a missing capability check on the 'install_required_plugin_callback' function in all versions up to, and including, 4.1.16. This makes it possible for authenticated attackers, with Subscriber-level access and above, to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated.

- [https://github.com/RandomRobbieBF/CVE-2024-10728](https://github.com/RandomRobbieBF/CVE-2024-10728) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10728.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10728.svg)


## CVE-2024-10654
 A vulnerability has been found in TOTOLINK LR350 up to 9.3.5u.6369 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /formLoginAuth.htm. The manipulation of the argument authCode with the input 1 leads to authorization bypass. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 9.3.5u.6698_B20230810 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/c0nyy/IoT_vuln](https://github.com/c0nyy/IoT_vuln) :  ![starts](https://img.shields.io/github/stars/c0nyy/IoT_vuln.svg) ![forks](https://img.shields.io/github/forks/c0nyy/IoT_vuln.svg)


## CVE-2024-10629
 The GPX Viewer plugin for WordPress is vulnerable to arbitrary file creation due to a missing capability check and file type validation in the gpxv_file_upload() function in all versions up to, and including, 2.2.8. This makes it possible for authenticated attackers, with subscriber-level access and above, to create arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/RandomRobbieBF/CVE-2024-10629](https://github.com/RandomRobbieBF/CVE-2024-10629) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10629.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10629.svg)


## CVE-2024-10605
 A vulnerability was found in code-projects Blood Bank Management System 1.0. It has been classified as problematic. This affects an unknown part of the file /file/request.php. The manipulation leads to cross-site request forgery. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/bevennyamande/CVE-2024-10605](https://github.com/bevennyamande/CVE-2024-10605) :  ![starts](https://img.shields.io/github/stars/bevennyamande/CVE-2024-10605.svg) ![forks](https://img.shields.io/github/forks/bevennyamande/CVE-2024-10605.svg)


## CVE-2024-10592
 The Mapster WP Maps plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the popup class parameter in all versions up to, and including, 1.6.0 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-10592](https://github.com/windz3r0day/CVE-2024-10592) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-10592.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-10592.svg)


## CVE-2024-10586
 The Debug Tool plugin for WordPress is vulnerable to arbitrary file creation due to a missing capability check on the dbt_pull_image() function and missing file type validation in all versions up to, and including, 2.2. This makes it possible for unauthenticated attackers to to create arbitrary files such as .php files that can be leveraged for remote code execution.

- [https://github.com/RandomRobbieBF/CVE-2024-10586](https://github.com/RandomRobbieBF/CVE-2024-10586) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10586.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10586.svg)


## CVE-2024-10557
 A vulnerability has been found in code-projects Blood Bank Management System 1.0 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file /file/updateprofile.php. The manipulation leads to cross-site request forgery. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/bevennyamande/CVE-2024-10557](https://github.com/bevennyamande/CVE-2024-10557) :  ![starts](https://img.shields.io/github/stars/bevennyamande/CVE-2024-10557.svg) ![forks](https://img.shields.io/github/forks/bevennyamande/CVE-2024-10557.svg)


## CVE-2024-10542
 The Spam protection, Anti-Spam, FireWall by CleanTalk plugin for WordPress is vulnerable to unauthorized Arbitrary Plugin Installation due to an authorization bypass via reverse DNS spoofing on the checkWithoutToken function in all versions up to, and including, 6.43.2. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated.

- [https://github.com/ubaii/CVE-2024-10542](https://github.com/ubaii/CVE-2024-10542) :  ![starts](https://img.shields.io/github/stars/ubaii/CVE-2024-10542.svg) ![forks](https://img.shields.io/github/forks/ubaii/CVE-2024-10542.svg)


## CVE-2024-10516
 The Swift Performance Lite plugin for WordPress is vulnerable to Local PHP File Inclusion in all versions up to, and including, 2.3.7.1 via the 'ajaxify' function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/RandomRobbieBF/CVE-2024-10516](https://github.com/RandomRobbieBF/CVE-2024-10516) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10516.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10516.svg)


## CVE-2024-10511
when someone on the local network repeatedly requests the /accessdenied URL.

- [https://github.com/revengsmK/CVE-2024-10511](https://github.com/revengsmK/CVE-2024-10511) :  ![starts](https://img.shields.io/github/stars/revengsmK/CVE-2024-10511.svg) ![forks](https://img.shields.io/github/forks/revengsmK/CVE-2024-10511.svg)


## CVE-2024-10508
 The RegistrationMagic – User Registration Plugin with Custom Registration Forms plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 6.0.2.6. This is due to the plugin not properly validating the password reset token prior to updating a user's password. This makes it possible for unauthenticated attackers to reset the password of arbitrary users, including administrators, and gain access to these accounts.

- [https://github.com/Jenderal92/CVE-2024-10508](https://github.com/Jenderal92/CVE-2024-10508) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2024-10508.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2024-10508.svg)
- [https://github.com/ubaii/CVE-2024-10508](https://github.com/ubaii/CVE-2024-10508) :  ![starts](https://img.shields.io/github/stars/ubaii/CVE-2024-10508.svg) ![forks](https://img.shields.io/github/forks/ubaii/CVE-2024-10508.svg)


## CVE-2024-10470
 The WPLMS Learning Management System for WordPress, WordPress LMS theme for WordPress is vulnerable to arbitrary file read and deletion due to insufficient file path validation and permissions checks in the readfile and unlink functions in all versions up to, and including, 4.962. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php). The theme is vulnerable even when it is not activated.

- [https://github.com/0xshoriful/CVE-2024-10470](https://github.com/0xshoriful/CVE-2024-10470) :  ![starts](https://img.shields.io/github/stars/0xshoriful/CVE-2024-10470.svg) ![forks](https://img.shields.io/github/forks/0xshoriful/CVE-2024-10470.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-10470](https://github.com/RandomRobbieBF/CVE-2024-10470) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10470.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10470.svg)


## CVE-2024-10449
 A vulnerability, which was classified as critical, was found in Codezips Hospital Appointment System 1.0. This affects an unknown part of the file /loginAction.php. The manipulation of the argument Username leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/g-u-i-d/CVE-2024-10449-patch](https://github.com/g-u-i-d/CVE-2024-10449-patch) :  ![starts](https://img.shields.io/github/stars/g-u-i-d/CVE-2024-10449-patch.svg) ![forks](https://img.shields.io/github/forks/g-u-i-d/CVE-2024-10449-patch.svg)


## CVE-2024-10448
 A vulnerability, which was classified as problematic, has been found in code-projects Blood Bank Management System 1.0. Affected by this issue is some unknown functionality of the file /file/delete.php. The manipulation of the argument bid leads to cross-site request forgery. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Other endpoints might be affected as well.

- [https://github.com/bevennyamande/CVE-2024-10448](https://github.com/bevennyamande/CVE-2024-10448) :  ![starts](https://img.shields.io/github/stars/bevennyamande/CVE-2024-10448.svg) ![forks](https://img.shields.io/github/forks/bevennyamande/CVE-2024-10448.svg)


## CVE-2024-10410
 A vulnerability classified as critical was found in SourceCodester Online Hotel Reservation System 1.0. Affected by this vulnerability is the function upload of the file /admin/mod_room/controller.php?action=add. The manipulation of the argument image leads to unrestricted upload. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/K1nakoo/CVE-2024-10410](https://github.com/K1nakoo/CVE-2024-10410) :  ![starts](https://img.shields.io/github/stars/K1nakoo/CVE-2024-10410.svg) ![forks](https://img.shields.io/github/forks/K1nakoo/CVE-2024-10410.svg)


## CVE-2024-10400
 The Tutor LMS plugin for WordPress is vulnerable to SQL Injection via the ‘rating_filter’ parameter in all versions up to, and including, 2.7.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/k0ns0l/CVE-2024-10400](https://github.com/k0ns0l/CVE-2024-10400) :  ![starts](https://img.shields.io/github/stars/k0ns0l/CVE-2024-10400.svg) ![forks](https://img.shields.io/github/forks/k0ns0l/CVE-2024-10400.svg)


## CVE-2024-10355
 A vulnerability, which was classified as critical, has been found in SourceCodester Petrol Pump Management Software 1.0. Affected by this issue is some unknown functionality of the file /admin/invoice.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/K1nakoo/CVE-2024-10355](https://github.com/K1nakoo/CVE-2024-10355) :  ![starts](https://img.shields.io/github/stars/K1nakoo/CVE-2024-10355.svg) ![forks](https://img.shields.io/github/forks/K1nakoo/CVE-2024-10355.svg)


## CVE-2024-10354
 A vulnerability classified as critical was found in SourceCodester Petrol Pump Management Software 1.0. Affected by this vulnerability is an unknown functionality of the file /admin/print.php. The manipulation of the argument id leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/K1nakoo/CVE-2024-10354](https://github.com/K1nakoo/CVE-2024-10354) :  ![starts](https://img.shields.io/github/stars/K1nakoo/CVE-2024-10354.svg) ![forks](https://img.shields.io/github/forks/K1nakoo/CVE-2024-10354.svg)


## CVE-2024-10245
 The Relais 2FA plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 1.0. This is due to incorrect authentication and capability checking in the 'rl_do_ajax' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the email.

- [https://github.com/RandomRobbieBF/CVE-2024-10245](https://github.com/RandomRobbieBF/CVE-2024-10245) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10245.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10245.svg)


## CVE-2024-10220
 The Kubernetes kubelet component allows arbitrary command execution via specially crafted gitRepo volumes.This issue affects kubelet: through 1.28.11, from 1.29.0 through 1.29.6, from 1.30.0 through 1.30.2.

- [https://github.com/XiaomingX/cve-2024-10220-githooks](https://github.com/XiaomingX/cve-2024-10220-githooks) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-10220-githooks.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-10220-githooks.svg)
- [https://github.com/mochizuki875/CVE-2024-10220-githooks](https://github.com/mochizuki875/CVE-2024-10220-githooks) :  ![starts](https://img.shields.io/github/stars/mochizuki875/CVE-2024-10220-githooks.svg) ![forks](https://img.shields.io/github/forks/mochizuki875/CVE-2024-10220-githooks.svg)
- [https://github.com/candranapits/poc-CVE-2024-10220](https://github.com/candranapits/poc-CVE-2024-10220) :  ![starts](https://img.shields.io/github/stars/candranapits/poc-CVE-2024-10220.svg) ![forks](https://img.shields.io/github/forks/candranapits/poc-CVE-2024-10220.svg)
- [https://github.com/any2sec/cve-2024-10220](https://github.com/any2sec/cve-2024-10220) :  ![starts](https://img.shields.io/github/stars/any2sec/cve-2024-10220.svg) ![forks](https://img.shields.io/github/forks/any2sec/cve-2024-10220.svg)
- [https://github.com/filipzag/CVE-2024-10220](https://github.com/filipzag/CVE-2024-10220) :  ![starts](https://img.shields.io/github/stars/filipzag/CVE-2024-10220.svg) ![forks](https://img.shields.io/github/forks/filipzag/CVE-2024-10220.svg)


## CVE-2024-10140
 A vulnerability, which was classified as critical, has been found in code-projects Pharmacy Management System 1.0. Affected by this issue is some unknown functionality of the file /manage_supplier.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/holypryx/CVE-2024-10140](https://github.com/holypryx/CVE-2024-10140) :  ![starts](https://img.shields.io/github/stars/holypryx/CVE-2024-10140.svg) ![forks](https://img.shields.io/github/forks/holypryx/CVE-2024-10140.svg)


## CVE-2024-10124
 The Vayu Blocks – Gutenberg Blocks for WordPress & WooCommerce plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation and activation due to a missing capability check on the tp_install() function in all versions up to, and including, 1.1.1. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated. This vulnerability was partially patched in version 1.1.1.

- [https://github.com/RandomRobbieBF/CVE-2024-10124](https://github.com/RandomRobbieBF/CVE-2024-10124) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10124.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10124.svg)
- [https://github.com/Nxploited/CVE-2024-10124-Poc](https://github.com/Nxploited/CVE-2024-10124-Poc) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-10124-Poc.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-10124-Poc.svg)


## CVE-2024-10015
 The ConvertCalculator for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'id' and 'type' parameters in all versions up to, and including, 1.1.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/windz3r0day/CVE-2024-10015](https://github.com/windz3r0day/CVE-2024-10015) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-10015.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-10015.svg)


## CVE-2024-9955
 Use after free in WebAuthentication in Google Chrome prior to 130.0.6723.58 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/amfg145/CVE-2024-9955-POC](https://github.com/amfg145/CVE-2024-9955-POC) :  ![starts](https://img.shields.io/github/stars/amfg145/CVE-2024-9955-POC.svg) ![forks](https://img.shields.io/github/forks/amfg145/CVE-2024-9955-POC.svg)


## CVE-2024-9935
 The PDF Generator Addon for Elementor Page Builder plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.7.5 via the rtw_pgaepb_dwnld_pdf() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/verylazytech/CVE-2024-9935](https://github.com/verylazytech/CVE-2024-9935) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-9935.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-9935.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-9935](https://github.com/RandomRobbieBF/CVE-2024-9935) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9935.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9935.svg)
- [https://github.com/Nxploited/CVE-2024-9935](https://github.com/Nxploited/CVE-2024-9935) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9935.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9935.svg)


## CVE-2024-9933
 The WatchTowerHQ plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.6. This is due to the 'watchtower_ota_token' default value is empty, and the not empty check is missing in the 'Password_Less_Access::login' function. This makes it possible for unauthenticated attackers to log in to the WatchTowerHQ client administrator user.

- [https://github.com/Nxploited/CVE-2024-9933](https://github.com/Nxploited/CVE-2024-9933) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9933.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9933.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-9933](https://github.com/RandomRobbieBF/CVE-2024-9933) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9933.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9933.svg)


## CVE-2024-9932
 The Wux Blog Editor plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in the 'wuxbt_insertImageNew' function in versions up to, and including, 3.0.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/RandomRobbieBF/CVE-2024-9932](https://github.com/RandomRobbieBF/CVE-2024-9932) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9932.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9932.svg)


## CVE-2024-9926
 The Jetpack WordPress plugin does not have proper authorisation in one of its REST endpoint, allowing any authenticated users, such as subscriber to read arbitrary feedbacks data sent via the Jetpack Contact Form

- [https://github.com/m3ssap0/wordpress-jetpack-broken-access-control-exploit](https://github.com/m3ssap0/wordpress-jetpack-broken-access-control-exploit) :  ![starts](https://img.shields.io/github/stars/m3ssap0/wordpress-jetpack-broken-access-control-exploit.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/wordpress-jetpack-broken-access-control-exploit.svg)
- [https://github.com/m3ssap0/wordpress-jetpack-broken-access-control-vulnerable-application](https://github.com/m3ssap0/wordpress-jetpack-broken-access-control-vulnerable-application) :  ![starts](https://img.shields.io/github/stars/m3ssap0/wordpress-jetpack-broken-access-control-vulnerable-application.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/wordpress-jetpack-broken-access-control-vulnerable-application.svg)


## CVE-2024-9890
 The User Toolkit plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 1.2.3. This is due to an improper capability check in the 'switchUser' function. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to log in as any existing user on the site, such as an administrator.

- [https://github.com/RandomRobbieBF/CVE-2024-9890](https://github.com/RandomRobbieBF/CVE-2024-9890) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9890.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9890.svg)


## CVE-2024-9822
 The Pedalo Connector plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.0.5. This is due to insufficient restriction on the 'login_admin_user' function. This makes it possible for unauthenticated attackers to log to the first user, who is usually the administrator, or if it does not exist, then to the first administrator.

- [https://github.com/RandomRobbieBF/CVE-2024-9822](https://github.com/RandomRobbieBF/CVE-2024-9822) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9822.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9822.svg)


## CVE-2024-9821
 The Bot for Telegram on WooCommerce plugin for WordPress is vulnerable to sensitive information disclosure due to missing authorization checks on the 'stm_wpcfto_get_settings' AJAX action in all versions up to, and including, 1.2.4. This makes it possible for authenticated attackers, with subscriber-level access and above, to view the Telegram Bot Token, a secret token used to control the bot, which can then be used to log in as any existing user on the site, such as an administrator, if they know the username, due to the Login with Telegram feature.

- [https://github.com/RandomRobbieBF/CVE-2024-9821](https://github.com/RandomRobbieBF/CVE-2024-9821) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9821.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9821.svg)


## CVE-2024-9796
 The WP-Advanced-Search WordPress plugin before 3.3.9.2 does not sanitize and escape the t parameter before using it in a SQL statement, allowing unauthenticated users to perform SQL injection attacks

- [https://github.com/issamjr/CVE-2024-9796](https://github.com/issamjr/CVE-2024-9796) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2024-9796.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2024-9796.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-9796](https://github.com/RandomRobbieBF/CVE-2024-9796) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9796.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9796.svg)


## CVE-2024-9707
 The Hunk Companion plugin for WordPress is vulnerable to unauthorized plugin installation/activation due to a missing capability check on the /wp-json/hc/v1/themehunk-import REST API endpoint in all versions up to, and including, 1.8.4. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated.

- [https://github.com/RandomRobbieBF/CVE-2024-9707](https://github.com/RandomRobbieBF/CVE-2024-9707) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9707.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9707.svg)


## CVE-2024-9680
 An attacker was able to achieve code execution in the content process by exploiting a use-after-free in Animation timelines. We have had reports of this vulnerability being exploited in the wild. This vulnerability affects Firefox  131.0.2, Firefox ESR  128.3.1, Firefox ESR  115.16.1, Thunderbird  131.0.1, Thunderbird  128.3.1, and Thunderbird  115.16.0.

- [https://github.com/tdonaworth/Firefox-CVE-2024-9680](https://github.com/tdonaworth/Firefox-CVE-2024-9680) :  ![starts](https://img.shields.io/github/stars/tdonaworth/Firefox-CVE-2024-9680.svg) ![forks](https://img.shields.io/github/forks/tdonaworth/Firefox-CVE-2024-9680.svg)
- [https://github.com/PraiseImafidon/Version_Vulnerability_Scanner](https://github.com/PraiseImafidon/Version_Vulnerability_Scanner) :  ![starts](https://img.shields.io/github/stars/PraiseImafidon/Version_Vulnerability_Scanner.svg) ![forks](https://img.shields.io/github/forks/PraiseImafidon/Version_Vulnerability_Scanner.svg)


## CVE-2024-9593
 The Time Clock plugin and Time Clock Pro plugin for WordPress are vulnerable to Remote Code Execution in versions up to, and including, 1.2.2 (for Time Clock) and 1.1.4 (for Time Clock Pro) via the 'etimeclockwp_load_function_callback' function. This allows unauthenticated attackers to execute code on the server. The invoked function's parameters cannot be specified.

- [https://github.com/RandomRobbieBF/CVE-2024-9593](https://github.com/RandomRobbieBF/CVE-2024-9593) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9593.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9593.svg)
- [https://github.com/0x4f5da2-venom/CVE-2024-9593-EXP](https://github.com/0x4f5da2-venom/CVE-2024-9593-EXP) :  ![starts](https://img.shields.io/github/stars/0x4f5da2-venom/CVE-2024-9593-EXP.svg) ![forks](https://img.shields.io/github/forks/0x4f5da2-venom/CVE-2024-9593-EXP.svg)
- [https://github.com/Nxploited/CVE-2024-9593-Exploit](https://github.com/Nxploited/CVE-2024-9593-Exploit) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9593-Exploit.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9593-Exploit.svg)


## CVE-2024-9570
 A vulnerability was found in D-Link DIR-619L B1 2.06 and classified as critical. Affected by this issue is the function formEasySetTimezone of the file /goform/formEasySetTimezone. The manipulation of the argument curTime leads to buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/dylvie/CVE-2024-9570_D-Link-DIR-619L-bof](https://github.com/dylvie/CVE-2024-9570_D-Link-DIR-619L-bof) :  ![starts](https://img.shields.io/github/stars/dylvie/CVE-2024-9570_D-Link-DIR-619L-bof.svg) ![forks](https://img.shields.io/github/forks/dylvie/CVE-2024-9570_D-Link-DIR-619L-bof.svg)


## CVE-2024-9474
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/Chocapikk/CVE-2024-9474](https://github.com/Chocapikk/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-9474.svg)
- [https://github.com/k4nfr3/CVE-2024-9474](https://github.com/k4nfr3/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/k4nfr3/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/k4nfr3/CVE-2024-9474.svg)
- [https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC](https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC) :  ![starts](https://img.shields.io/github/stars/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC.svg) ![forks](https://img.shields.io/github/forks/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC.svg)
- [https://github.com/coskper-papa/PAN-OS_CVE-2024-9474](https://github.com/coskper-papa/PAN-OS_CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/coskper-papa/PAN-OS_CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/coskper-papa/PAN-OS_CVE-2024-9474.svg)
- [https://github.com/XiaomingX/cve-2024-0012-poc](https://github.com/XiaomingX/cve-2024-0012-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-0012-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-0012-poc.svg)
- [https://github.com/deathvu/CVE-2024-9474](https://github.com/deathvu/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/deathvu/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/deathvu/CVE-2024-9474.svg)


## CVE-2024-9466
 A cleartext storage of sensitive information vulnerability in Palo Alto Networks Expedition allows an authenticated attacker to reveal firewall usernames, passwords, and API keys generated using those credentials.

- [https://github.com/holypryx/CVE-2024-9466](https://github.com/holypryx/CVE-2024-9466) :  ![starts](https://img.shields.io/github/stars/holypryx/CVE-2024-9466.svg) ![forks](https://img.shields.io/github/forks/holypryx/CVE-2024-9466.svg)


## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/horizon3ai/CVE-2024-9465](https://github.com/horizon3ai/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2024-9465.svg)
- [https://github.com/XiaomingX/cve-2024-9465-poc](https://github.com/XiaomingX/cve-2024-9465-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-9465-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-9465-poc.svg)
- [https://github.com/mustafaakalin/CVE-2024-9465](https://github.com/mustafaakalin/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/mustafaakalin/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/mustafaakalin/CVE-2024-9465.svg)


## CVE-2024-9464
 An OS command injection vulnerability in Palo Alto Networks Expedition allows an authenticated attacker to run arbitrary OS commands as root in Expedition, resulting in disclosure of usernames, cleartext passwords, device configurations, and device API keys of PAN-OS firewalls.

- [https://github.com/horizon3ai/CVE-2024-9464](https://github.com/horizon3ai/CVE-2024-9464) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2024-9464.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2024-9464.svg)
- [https://github.com/p33d/Palo-Alto-Expedition-Remote-Code-Execution-Exploit-CVE-2024-5910-CVE-2024-9464](https://github.com/p33d/Palo-Alto-Expedition-Remote-Code-Execution-Exploit-CVE-2024-5910-CVE-2024-9464) :  ![starts](https://img.shields.io/github/stars/p33d/Palo-Alto-Expedition-Remote-Code-Execution-Exploit-CVE-2024-5910-CVE-2024-9464.svg) ![forks](https://img.shields.io/github/forks/p33d/Palo-Alto-Expedition-Remote-Code-Execution-Exploit-CVE-2024-5910-CVE-2024-9464.svg)


## CVE-2024-9441
 The Linear eMerge e3-Series through version 1.00-07 is vulnerable to an OS command injection vulnerability. A remote and unauthenticated attacker can execute arbitrary OS commands via the login_id parameter when invoking the forgot_password functionality over HTTP.

- [https://github.com/p33d/CVE-2024-9441](https://github.com/p33d/CVE-2024-9441) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2024-9441.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2024-9441.svg)
- [https://github.com/XiaomingX/cve-2024-9441-poc](https://github.com/XiaomingX/cve-2024-9441-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-9441-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-9441-poc.svg)
- [https://github.com/adhikara13/CVE-2024-9441](https://github.com/adhikara13/CVE-2024-9441) :  ![starts](https://img.shields.io/github/stars/adhikara13/CVE-2024-9441.svg) ![forks](https://img.shields.io/github/forks/adhikara13/CVE-2024-9441.svg)
- [https://github.com/jk-mayne/CVE-2024-9441-Checker](https://github.com/jk-mayne/CVE-2024-9441-Checker) :  ![starts](https://img.shields.io/github/stars/jk-mayne/CVE-2024-9441-Checker.svg) ![forks](https://img.shields.io/github/forks/jk-mayne/CVE-2024-9441-Checker.svg)


## CVE-2024-9326
 A vulnerability classified as critical was found in PHPGurukul Online Shopping Portal 2.0. This vulnerability affects unknown code of the file /shopping/admin/index.php of the component Admin Panel. The manipulation of the argument username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ghostwirez/CVE-2024-9326-PoC](https://github.com/ghostwirez/CVE-2024-9326-PoC) :  ![starts](https://img.shields.io/github/stars/ghostwirez/CVE-2024-9326-PoC.svg) ![forks](https://img.shields.io/github/forks/ghostwirez/CVE-2024-9326-PoC.svg)


## CVE-2024-9290
 The Super Backup & Clone - Migrate for WordPress plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation and a missing capability check on the ibk_restore_migrate_check() function in all versions up to, and including, 2.3.3. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Jenderal92/CVE-2024-9290](https://github.com/Jenderal92/CVE-2024-9290) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2024-9290.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2024-9290.svg)
- [https://github.com/RandomRobbieBF/CVE-2024-9290](https://github.com/RandomRobbieBF/CVE-2024-9290) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9290.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9290.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/nollium/CVE-2024-9264](https://github.com/nollium/CVE-2024-9264) :  ![starts](https://img.shields.io/github/stars/nollium/CVE-2024-9264.svg) ![forks](https://img.shields.io/github/forks/nollium/CVE-2024-9264.svg)
- [https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit](https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/z3k0sec/CVE-2024-9264-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/z3k0sec/CVE-2024-9264-RCE-Exploit.svg)
- [https://github.com/z3k0sec/File-Read-CVE-2024-9264](https://github.com/z3k0sec/File-Read-CVE-2024-9264) :  ![starts](https://img.shields.io/github/stars/z3k0sec/File-Read-CVE-2024-9264.svg) ![forks](https://img.shields.io/github/forks/z3k0sec/File-Read-CVE-2024-9264.svg)
- [https://github.com/punitdarji/Grafana-CVE-2024-9264](https://github.com/punitdarji/Grafana-CVE-2024-9264) :  ![starts](https://img.shields.io/github/stars/punitdarji/Grafana-CVE-2024-9264.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Grafana-CVE-2024-9264.svg)


## CVE-2024-9234
 The GutenKit – Page Builder Blocks, Patterns, and Templates for Gutenberg Block Editor plugin for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the install_and_activate_plugin_from_external() function  (install-active-plugin REST API endpoint) in all versions up to, and including, 2.1.0. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins, or utilize the functionality to upload arbitrary files spoofed like plugins.

- [https://github.com/RandomRobbieBF/CVE-2024-9234](https://github.com/RandomRobbieBF/CVE-2024-9234) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9234.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9234.svg)
- [https://github.com/Nxploited/CVE-2024-9234](https://github.com/Nxploited/CVE-2024-9234) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9234.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9234.svg)
- [https://github.com/CallMeBatosay/CVE-2024-9234](https://github.com/CallMeBatosay/CVE-2024-9234) :  ![starts](https://img.shields.io/github/stars/CallMeBatosay/CVE-2024-9234.svg) ![forks](https://img.shields.io/github/forks/CallMeBatosay/CVE-2024-9234.svg)


## CVE-2024-9224
 The Hello World plugin for WordPress is vulnerable to Arbitrary File Reading in all versions up to, and including, 2.1.1 via the hello_world_lyric() function. This makes it possible for authenticated attackers, with subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/RandomRobbieBF/CVE-2024-9224](https://github.com/RandomRobbieBF/CVE-2024-9224) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9224.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9224.svg)


## CVE-2024-9166
 The device enables an unauthorized attacker to execute system commands with elevated privileges. This exploit is facilitated through the use of the 'getcommand' query within the application, allowing the attacker to gain root access.

- [https://github.com/Andrysqui/CVE-2024-9166](https://github.com/Andrysqui/CVE-2024-9166) :  ![starts](https://img.shields.io/github/stars/Andrysqui/CVE-2024-9166.svg) ![forks](https://img.shields.io/github/forks/Andrysqui/CVE-2024-9166.svg)


## CVE-2024-9162
 The All-in-One WP Migration and Backup plugin for WordPress is vulnerable to arbitrary PHP Code Injection due to missing file type validation during the export in all versions up to, and including, 7.86. This makes it possible for authenticated attackers, with Administrator-level access and above, to create an export file with the .php extension on the affected site's server, adding an arbitrary PHP code to it, which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2024-9162](https://github.com/d0n601/CVE-2024-9162) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2024-9162.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2024-9162.svg)


## CVE-2024-9106
 The Wechat Social login plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 1.3.0. This is due to insufficient verification on the user being supplied during the social login. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the user id. This is only exploitable if the app secret is not set, so it has a default empty value.

- [https://github.com/RandomRobbieBF/CVE-2024-9106](https://github.com/RandomRobbieBF/CVE-2024-9106) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9106.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9106.svg)


## CVE-2024-9061
 The The WP Popup Builder – Popup Forms and Marketing Lead Generation plugin for WordPress is vulnerable to arbitrary shortcode execution via the wp_ajax_nopriv_shortcode_Api_Add AJAX action in all versions up to, and including, 1.3.5. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes. NOTE: This vulnerability was partially fixed in version 1.3.5 with a nonce check, which effectively prevented access to the affected function. However, version 1.3.6 incorporates the correct authorization check to prevent unauthorized access.

- [https://github.com/RandomRobbieBF/CVE-2024-9061](https://github.com/RandomRobbieBF/CVE-2024-9061) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-9061.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-9061.svg)


## CVE-2024-9047
 The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.

- [https://github.com/iSee857/CVE-2024-9047-PoC](https://github.com/iSee857/CVE-2024-9047-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2024-9047-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2024-9047-PoC.svg)
- [https://github.com/verylazytech/CVE-2024-9047](https://github.com/verylazytech/CVE-2024-9047) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-9047.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-9047.svg)


## CVE-2024-9014
 pgAdmin versions 8.11 and earlier are vulnerable to a security flaw in OAuth2 authentication. This vulnerability allows an attacker to potentially obtain the client ID and secret, leading to unauthorized access to user data.

- [https://github.com/EQSTLab/CVE-2024-9014](https://github.com/EQSTLab/CVE-2024-9014) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-9014.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-9014.svg)


## CVE-2024-8963
 Path Traversal in the Ivanti CSA before 4.6 Patch 519 allows a remote unauthenticated attacker to access restricted functionality.

- [https://github.com/patfire94/CVE-2024-8963](https://github.com/patfire94/CVE-2024-8963) :  ![starts](https://img.shields.io/github/stars/patfire94/CVE-2024-8963.svg) ![forks](https://img.shields.io/github/forks/patfire94/CVE-2024-8963.svg)


## CVE-2024-8949
 A vulnerability classified as critical has been found in SourceCodester Online Eyewear Shop 1.0. This affects an unknown part of the file /classes/Master.php of the component Cart Content Handler. The manipulation of the argument cart_id/id leads to improper ownership management. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/gh-ost00/CVE-2024-8949-POC](https://github.com/gh-ost00/CVE-2024-8949-POC) :  ![starts](https://img.shields.io/github/stars/gh-ost00/CVE-2024-8949-POC.svg) ![forks](https://img.shields.io/github/forks/gh-ost00/CVE-2024-8949-POC.svg)


## CVE-2024-8868
 A vulnerability was found in code-projects Crud Operation System 1.0. It has been rated as critical. This issue affects some unknown processing of the file savedata.php. The manipulation of the argument sname leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/M0onc/CVE-2024-8868](https://github.com/M0onc/CVE-2024-8868) :  ![starts](https://img.shields.io/github/stars/M0onc/CVE-2024-8868.svg) ![forks](https://img.shields.io/github/forks/M0onc/CVE-2024-8868.svg)


## CVE-2024-8856
 The Backup and Staging by WP Time Capsule plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the the UploadHandler.php file and no direct file access prevention in all versions up to, and including, 1.22.21. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/ubaii/CVE-2024-8856](https://github.com/ubaii/CVE-2024-8856) :  ![starts](https://img.shields.io/github/stars/ubaii/CVE-2024-8856.svg) ![forks](https://img.shields.io/github/forks/ubaii/CVE-2024-8856.svg)
- [https://github.com/Jenderal92/CVE-2024-8856](https://github.com/Jenderal92/CVE-2024-8856) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2024-8856.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2024-8856.svg)


## CVE-2024-8752
 The Windows version of WebIQ 2.15.9 is affected by a directory traversal vulnerability that allows remote attackers to read any file on the system.

- [https://github.com/D3anSPGDMS/CVE-2024-8752](https://github.com/D3anSPGDMS/CVE-2024-8752) :  ![starts](https://img.shields.io/github/stars/D3anSPGDMS/CVE-2024-8752.svg) ![forks](https://img.shields.io/github/forks/D3anSPGDMS/CVE-2024-8752.svg)


## CVE-2024-8743
 The Bit File Manager – 100% Free & Open Source File Manager and Code Editor for WordPress plugin for WordPress is vulnerable to Limited JavaScript File Upload in all versions up to, and including, 6.5.7. This is due to a lack of proper checks on allowed file types. This makes it possible for authenticated attackers, with Subscriber-level access and above, and granted permissions by an administrator, to upload .css and .js files, which could lead to Stored Cross-Site Scripting.

- [https://github.com/siunam321/CVE-2024-8743-PoC](https://github.com/siunam321/CVE-2024-8743-PoC) :  ![starts](https://img.shields.io/github/stars/siunam321/CVE-2024-8743-PoC.svg) ![forks](https://img.shields.io/github/forks/siunam321/CVE-2024-8743-PoC.svg)


## CVE-2024-8698
 A flaw exists in the SAML signature validation method within the Keycloak XMLSignatureUtil class. The method incorrectly determines whether a SAML signature is for the full document or only for specific assertions based on the position of the signature in the XML document, rather than the Reference element used to specify the signed element. This flaw allows attackers to create crafted responses that can bypass the validation, potentially leading to privilege escalation or impersonation attacks.

- [https://github.com/huydoppaz/CVE-2024-8698-POC](https://github.com/huydoppaz/CVE-2024-8698-POC) :  ![starts](https://img.shields.io/github/stars/huydoppaz/CVE-2024-8698-POC.svg) ![forks](https://img.shields.io/github/forks/huydoppaz/CVE-2024-8698-POC.svg)


## CVE-2024-8672
 The Widget Options – The #1 WordPress Widget & Block Control Plugin plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.0.7 via the display logic functionality that extends several page builders. This is due to the plugin allowing users to supply input that will be passed through eval() without any filtering or capability checks. This makes it possible for authenticated attackers, with contributor-level access and above, to execute code on the server. Special note: We suggested the vendor implement an allowlist of functions and limit the ability to execute commands to just administrators, however, they did not take our advice. We are considering this patched, however, we believe it could still be further hardened and there may be residual risk with how the issue is currently patched.

- [https://github.com/Chocapikk/CVE-2024-8672](https://github.com/Chocapikk/CVE-2024-8672) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8672.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8672.svg)


## CVE-2024-8529
 The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable to SQL Injection via the 'c_fields' parameter of the /wp-json/lp/v1/courses/archive-course REST API endpoint in all versions up to, and including, 4.2.7 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-8529](https://github.com/RandomRobbieBF/CVE-2024-8529) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-8529.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-8529.svg)


## CVE-2024-8522
 The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable to SQL Injection via the 'c_only_fields' parameter of the /wp-json/learnpress/v1/courses REST API endpoint in all versions up to, and including, 4.2.7 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Avento/CVE-2024-8522](https://github.com/Avento/CVE-2024-8522) :  ![starts](https://img.shields.io/github/stars/Avento/CVE-2024-8522.svg) ![forks](https://img.shields.io/github/forks/Avento/CVE-2024-8522.svg)


## CVE-2024-8517
remote and unauthenticated attacker can execute arbitrary operating system commands by sending a crafted multipart file upload HTTP request.

- [https://github.com/Chocapikk/CVE-2024-8517](https://github.com/Chocapikk/CVE-2024-8517) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8517.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8517.svg)


## CVE-2024-8504
 An attacker with authenticated access to VICIdial as an "agent" can execute arbitrary shell commands as the "root" user. This attack can be chained with CVE-2024-8503 to execute arbitrary shell commands starting from an unauthenticated perspective.

- [https://github.com/Chocapikk/CVE-2024-8504](https://github.com/Chocapikk/CVE-2024-8504) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8504.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8504.svg)
- [https://github.com/havokzero/ViciDial](https://github.com/havokzero/ViciDial) :  ![starts](https://img.shields.io/github/stars/havokzero/ViciDial.svg) ![forks](https://img.shields.io/github/forks/havokzero/ViciDial.svg)


## CVE-2024-8503
 An unauthenticated attacker can leverage a time-based SQL injection vulnerability in VICIdial to enumerate database records. By default, VICIdial stores plaintext credentials within the database.

- [https://github.com/Chocapikk/CVE-2024-8504](https://github.com/Chocapikk/CVE-2024-8504) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8504.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8504.svg)


## CVE-2024-8484
 The REST API TO MiniProgram plugin for WordPress is vulnerable to SQL Injection via the 'order' parameter of the /wp-json/watch-life-net/v1/comment/getcomments REST API endpoint in all versions up to, and including, 4.7.1 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-8484](https://github.com/RandomRobbieBF/CVE-2024-8484) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-8484.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-8484.svg)


## CVE-2024-8353
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.16.1 via deserialization of untrusted input via several parameters like 'give_title' and 'card_address'. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to delete arbitrary files and achieve remote code execution. This is essentially the same vulnerability as CVE-2024-5932, however, it was discovered the the presence of stripslashes_deep on user_info allows the is_serialized check to be bypassed. This issue was mostly patched in 3.16.1, but further hardening was added in 3.16.2.

- [https://github.com/EQSTLab/CVE-2024-8353](https://github.com/EQSTLab/CVE-2024-8353) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-8353.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-8353.svg)


## CVE-2024-8350
 The Uncanny Groups for LearnDash plugin for WordPress is vulnerable to user group add due to a missing capability check on the /wp-json/ulgm_management/v1/add_user/ REST API endpoint in all versions up to, and including, 6.1.0.1. This makes it possible for authenticated attackers, with group leader-level access and above, to add users to their group which ultimately allows them to leverage CVE-2024-8349 and gain admin access to the site.

- [https://github.com/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350](https://github.com/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350) :  ![starts](https://img.shields.io/github/stars/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350.svg) ![forks](https://img.shields.io/github/forks/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350.svg)


## CVE-2024-8349
 The Uncanny Groups for LearnDash plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 6.1.0.1. This is due to the plugin not properly restricting what users a group leader can edit. This makes it possible for authenticated attackers, with group leader-level access and above, to change admin account email addresses which can subsequently lead to admin account access.

- [https://github.com/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350](https://github.com/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350) :  ![starts](https://img.shields.io/github/stars/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350.svg) ![forks](https://img.shields.io/github/forks/karlemilnikka/CVE-2024-8349-and-CVE-2024-8350.svg)


## CVE-2024-8309
 A vulnerability in the GraphCypherQAChain class of langchain-ai/langchain version 0.2.5 allows for SQL injection through prompt injection. This vulnerability can lead to unauthorized data manipulation, data exfiltration, denial of service (DoS) by deleting all data, breaches in multi-tenant security environments, and data integrity issues. Attackers can create, update, or delete nodes and relationships without proper authorization, extract sensitive data, disrupt services, access data across different tenants, and compromise the integrity of the database.

- [https://github.com/liadlevy/CVE-2024-8309](https://github.com/liadlevy/CVE-2024-8309) :  ![starts](https://img.shields.io/github/stars/liadlevy/CVE-2024-8309.svg) ![forks](https://img.shields.io/github/forks/liadlevy/CVE-2024-8309.svg)


## CVE-2024-8277
 The WooCommerce Photo Reviews Premium plugin for WordPress is vulnerable to authentication bypass in all versions up to, and including, 1.3.13.2. This is due to the plugin not properly validating what user transient is being used in the login() function and not properly verifying the user's identity. This makes it possible for unauthenticated attackers to log in as user that has dismissed an admin notice in the past 30 days, which is often an administrator. Alternatively, a user can log in as any user with any transient that has a valid user_id as the value, though it would be more difficult to exploit this successfully.

- [https://github.com/PolatBey/CVE-2024-8277](https://github.com/PolatBey/CVE-2024-8277) :  ![starts](https://img.shields.io/github/stars/PolatBey/CVE-2024-8277.svg) ![forks](https://img.shields.io/github/forks/PolatBey/CVE-2024-8277.svg)


## CVE-2024-8275
 The The Events Calendar plugin for WordPress is vulnerable to SQL Injection via the 'order' parameter of the 'tribe_has_next_event' function in all versions up to, and including, 6.6.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. Only sites that have manually added tribe_has_next_event() will be vulnerable to this SQL injection.

- [https://github.com/whiterose7777/CVE-2024-8275](https://github.com/whiterose7777/CVE-2024-8275) :  ![starts](https://img.shields.io/github/stars/whiterose7777/CVE-2024-8275.svg) ![forks](https://img.shields.io/github/forks/whiterose7777/CVE-2024-8275.svg)
- [https://github.com/p33d/CVE-2024-8275](https://github.com/p33d/CVE-2024-8275) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2024-8275.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2024-8275.svg)


## CVE-2024-8190
 An OS command injection vulnerability in Ivanti Cloud Services Appliance versions 4.6 Patch 518 and before allows a remote authenticated attacker to obtain remote code execution. The attacker must have admin level privileges to exploit this vulnerability.

- [https://github.com/horizon3ai/CVE-2024-8190](https://github.com/horizon3ai/CVE-2024-8190) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2024-8190.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2024-8190.svg)
- [https://github.com/tequilasunsh1ne/ivanti_CVE_2024_8190](https://github.com/tequilasunsh1ne/ivanti_CVE_2024_8190) :  ![starts](https://img.shields.io/github/stars/tequilasunsh1ne/ivanti_CVE_2024_8190.svg) ![forks](https://img.shields.io/github/forks/tequilasunsh1ne/ivanti_CVE_2024_8190.svg)


## CVE-2024-8069
 Limited remote code execution with privilege of a NetworkService Account access in Citrix Session Recording if the attacker is an authenticated user on the same intranet as the session recording server

- [https://github.com/XiaomingX/cve-2024-8069-exp-Citrix-Virtual-Apps-XEN](https://github.com/XiaomingX/cve-2024-8069-exp-Citrix-Virtual-Apps-XEN) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-8069-exp-Citrix-Virtual-Apps-XEN.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-8069-exp-Citrix-Virtual-Apps-XEN.svg)


## CVE-2024-8030
 The Ultimate Store Kit Elementor Addons, Woocommerce Builder, EDD Builder, Elementor Store Builder, Product Grid, Product Table, Woocommerce Slider plugin is vulnerable to PHP Object Injection via deserialization of untrusted input via the _ultimate_store_kit_wishlist cookie in versions up to , and including, 2.0.3. This makes it possible for an unauthenticated attacker to inject a PHP Object. No POP chain is present in the vulnerable plugin. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker or above to delete arbitrary files, retrieve sensitive data, or execute code.

- [https://github.com/codeb0ss/CVE-2024-8030-PoC](https://github.com/codeb0ss/CVE-2024-8030-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-8030-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-8030-PoC.svg)


## CVE-2024-7965
 Inappropriate implementation in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/bi-zone/CVE-2024-7965](https://github.com/bi-zone/CVE-2024-7965) :  ![starts](https://img.shields.io/github/stars/bi-zone/CVE-2024-7965.svg) ![forks](https://img.shields.io/github/forks/bi-zone/CVE-2024-7965.svg)
- [https://github.com/XiaomingX/cve-2024-7965-poc](https://github.com/XiaomingX/cve-2024-7965-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-7965-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-7965-poc.svg)


## CVE-2024-7954
 The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.

- [https://github.com/Chocapikk/CVE-2024-7954](https://github.com/Chocapikk/CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-7954.svg)
- [https://github.com/gh-ost00/CVE-2024-7954-RCE](https://github.com/gh-ost00/CVE-2024-7954-RCE) :  ![starts](https://img.shields.io/github/stars/gh-ost00/CVE-2024-7954-RCE.svg) ![forks](https://img.shields.io/github/forks/gh-ost00/CVE-2024-7954-RCE.svg)
- [https://github.com/bigb0x/CVE-2024-7954](https://github.com/bigb0x/CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-7954.svg)
- [https://github.com/MuhammadWaseem29/RCE-CVE-2024-7954](https://github.com/MuhammadWaseem29/RCE-CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/RCE-CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/RCE-CVE-2024-7954.svg)
- [https://github.com/TheCyberguy-17/RCE_CVE-2024-7954](https://github.com/TheCyberguy-17/RCE_CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/TheCyberguy-17/RCE_CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/TheCyberguy-17/RCE_CVE-2024-7954.svg)
- [https://github.com/issamjr/CVE-2024-7954](https://github.com/issamjr/CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2024-7954.svg)
- [https://github.com/0dayan0n/RCE_CVE-2024-7954-](https://github.com/0dayan0n/RCE_CVE-2024-7954-) :  ![starts](https://img.shields.io/github/stars/0dayan0n/RCE_CVE-2024-7954-.svg) ![forks](https://img.shields.io/github/forks/0dayan0n/RCE_CVE-2024-7954-.svg)
- [https://github.com/zxj-hub/CVE-2024-7954POC](https://github.com/zxj-hub/CVE-2024-7954POC) :  ![starts](https://img.shields.io/github/stars/zxj-hub/CVE-2024-7954POC.svg) ![forks](https://img.shields.io/github/forks/zxj-hub/CVE-2024-7954POC.svg)


## CVE-2024-7928
 A vulnerability, which was classified as problematic, has been found in FastAdmin up to 1.3.3.20220121. Affected by this issue is some unknown functionality of the file /index/ajax/lang. The manipulation of the argument lang leads to path traversal. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.3.4.20220530 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/bigb0x/CVE-2024-7928](https://github.com/bigb0x/CVE-2024-7928) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-7928.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-7928.svg)
- [https://github.com/gh-ost00/CVE-2024-7928](https://github.com/gh-ost00/CVE-2024-7928) :  ![starts](https://img.shields.io/github/stars/gh-ost00/CVE-2024-7928.svg) ![forks](https://img.shields.io/github/forks/gh-ost00/CVE-2024-7928.svg)
- [https://github.com/th3gokul/CVE-2024-7928](https://github.com/th3gokul/CVE-2024-7928) :  ![starts](https://img.shields.io/github/stars/th3gokul/CVE-2024-7928.svg) ![forks](https://img.shields.io/github/forks/th3gokul/CVE-2024-7928.svg)
- [https://github.com/wh6amiGit/CVE-2024-7928](https://github.com/wh6amiGit/CVE-2024-7928) :  ![starts](https://img.shields.io/github/stars/wh6amiGit/CVE-2024-7928.svg) ![forks](https://img.shields.io/github/forks/wh6amiGit/CVE-2024-7928.svg)


## CVE-2024-7856
 The MP3 Audio Player – Music Player, Podcast Player & Radio by Sonaar plugin for WordPress is vulnerable to unauthorized arbitrary file deletion due to a missing capability check on the removeTempFiles() function and insufficient path validation on the 'file' parameter in all versions up to, and including, 5.7.0.1. This makes it possible for authenticated attackers, with subscriber-level access and above, to delete arbitrary files which can make remote code execution possible when wp-config.php is deleted.

- [https://github.com/l8BL/CVE-2024-7856](https://github.com/l8BL/CVE-2024-7856) :  ![starts](https://img.shields.io/github/stars/l8BL/CVE-2024-7856.svg) ![forks](https://img.shields.io/github/forks/l8BL/CVE-2024-7856.svg)


## CVE-2024-7854
 The Woo Inquiry plugin for WordPress is vulnerable to SQL Injection in all versions up to, and including, 0.1 due to insufficient escaping on the user supplied parameter 'dbid' and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-7854](https://github.com/RandomRobbieBF/CVE-2024-7854) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-7854.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-7854.svg)


## CVE-2024-7808
 A vulnerability was found in code-projects Job Portal 1.0. It has been classified as critical. Affected is an unknown function of the file logindbc.php. The manipulation of the argument email leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/TheUnknownSoul/CVE-2024-7808](https://github.com/TheUnknownSoul/CVE-2024-7808) :  ![starts](https://img.shields.io/github/stars/TheUnknownSoul/CVE-2024-7808.svg) ![forks](https://img.shields.io/github/forks/TheUnknownSoul/CVE-2024-7808.svg)


## CVE-2024-7703
 The ARMember – Membership Plugin, Content Restriction, Member Levels, User Profile & User signup plugin for WordPress is vulnerable to Stored Cross-Site Scripting via SVG File uploads in all versions up to, and including, 4.0.37 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Subscriber-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses the SVG file.

- [https://github.com/lfillaz/CVE-2024-7703](https://github.com/lfillaz/CVE-2024-7703) :  ![starts](https://img.shields.io/github/stars/lfillaz/CVE-2024-7703.svg) ![forks](https://img.shields.io/github/forks/lfillaz/CVE-2024-7703.svg)


## CVE-2024-7646
 A security issue was discovered in ingress-nginx where an actor with permission to create Ingress objects (in the `networking.k8s.io` or `extensions` API group) can bypass annotation validation to inject arbitrary commands and obtain the credentials of the ingress-nginx controller. In the default configuration, that credential has access to all secrets in the cluster.

- [https://github.com/dovics/cve-2024-7646](https://github.com/dovics/cve-2024-7646) :  ![starts](https://img.shields.io/github/stars/dovics/cve-2024-7646.svg) ![forks](https://img.shields.io/github/forks/dovics/cve-2024-7646.svg)
- [https://github.com/r0binak/CVE-2024-7646](https://github.com/r0binak/CVE-2024-7646) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2024-7646.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2024-7646.svg)


## CVE-2024-7627
 The Bit File Manager plugin for WordPress is vulnerable to Remote Code Execution in versions 6.0 to 6.5.5 via the 'checkSyntax' function. This is due to writing a temporary file to a publicly accessible directory before performing file validation. This makes it possible for unauthenticated attackers to execute code on the server if an administrator has allowed Guest User read permissions.

- [https://github.com/siunam321/CVE-2024-7627-PoC](https://github.com/siunam321/CVE-2024-7627-PoC) :  ![starts](https://img.shields.io/github/stars/siunam321/CVE-2024-7627-PoC.svg) ![forks](https://img.shields.io/github/forks/siunam321/CVE-2024-7627-PoC.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/D3N14LD15K/CVE-2024-7593_PoC_Exploit](https://github.com/D3N14LD15K/CVE-2024-7593_PoC_Exploit) :  ![starts](https://img.shields.io/github/stars/D3N14LD15K/CVE-2024-7593_PoC_Exploit.svg) ![forks](https://img.shields.io/github/forks/D3N14LD15K/CVE-2024-7593_PoC_Exploit.svg)
- [https://github.com/codeb0ss/CVE-2024-7593-PoC](https://github.com/codeb0ss/CVE-2024-7593-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-7593-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-7593-PoC.svg)
- [https://github.com/rxerium/CVE-2024-7593](https://github.com/rxerium/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-7593.svg)
- [https://github.com/skyrowalker/CVE-2024-7593](https://github.com/skyrowalker/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/skyrowalker/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/skyrowalker/CVE-2024-7593.svg)


## CVE-2024-7514
The issue was partially fixed in version 2.3.8 and fully fixed in 2.3.9

- [https://github.com/RandomRobbieBF/CVE-2024-7514](https://github.com/RandomRobbieBF/CVE-2024-7514) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-7514.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-7514.svg)


## CVE-2024-7481
 Improper verification of cryptographic signature during installation of a Printer driver via the TeamViewer_service.exe component of TeamViewer Remote Clients prior version 15.58.4 for Windows allows an attacker with local unprivileged access on a Windows system to elevate their privileges and install drivers.

- [https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481](https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481) :  ![starts](https://img.shields.io/github/stars/PeterGabaldon/CVE-2024-7479_CVE-2024-7481.svg) ![forks](https://img.shields.io/github/forks/PeterGabaldon/CVE-2024-7479_CVE-2024-7481.svg)


## CVE-2024-7479
 Improper verification of cryptographic signature during installation of a VPN driver via the TeamViewer_service.exe component of TeamViewer Remote Clients prior version 15.58.4 for Windows allows an attacker with local unprivileged access on a Windows system to elevate their privileges and install drivers.

- [https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481](https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481) :  ![starts](https://img.shields.io/github/stars/PeterGabaldon/CVE-2024-7479_CVE-2024-7481.svg) ![forks](https://img.shields.io/github/forks/PeterGabaldon/CVE-2024-7479_CVE-2024-7481.svg)


## CVE-2024-7456
 A SQL injection vulnerability exists in the `/api/v1/external-users` route of lunary-ai/lunary version v1.4.2. The `order by` clause of the SQL query uses `sql.unsafe` without prior sanitization, allowing for SQL injection. The `orderByClause` variable is constructed without server-side validation or sanitization, enabling an attacker to execute arbitrary SQL commands. Successful exploitation can lead to complete data loss, modification, or corruption.

- [https://github.com/77Philly/CVE-2024-7456scripts](https://github.com/77Philly/CVE-2024-7456scripts) :  ![starts](https://img.shields.io/github/stars/77Philly/CVE-2024-7456scripts.svg) ![forks](https://img.shields.io/github/forks/77Philly/CVE-2024-7456scripts.svg)


## CVE-2024-7339
 A vulnerability has been found in TVT DVR TD-2104TS-CL, DVR TD-2108TS-HP, Provision-ISR DVR SH-4050A5-5L(MM) and AVISION DVR AV108T and classified as problematic. This vulnerability affects unknown code of the file /queryDevInfo. The manipulation leads to information disclosure. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-273262 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/RevoltSecurities/CVE-2024-7339](https://github.com/RevoltSecurities/CVE-2024-7339) :  ![starts](https://img.shields.io/github/stars/RevoltSecurities/CVE-2024-7339.svg) ![forks](https://img.shields.io/github/forks/RevoltSecurities/CVE-2024-7339.svg)


## CVE-2024-7313
 The Shield Security  WordPress plugin before 20.0.6 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin.

- [https://github.com/Wayne-Ker/CVE-2024-7313](https://github.com/Wayne-Ker/CVE-2024-7313) :  ![starts](https://img.shields.io/github/stars/Wayne-Ker/CVE-2024-7313.svg) ![forks](https://img.shields.io/github/forks/Wayne-Ker/CVE-2024-7313.svg)


## CVE-2024-7188
 A vulnerability was found in Bylancer Quicklancer 2.4. It has been rated as critical. This issue affects some unknown processing of the file /listing of the component GET Parameter Handler. The manipulation of the argument range2 leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-272609 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/codeb0ss/CVE-2024-7188-PoC](https://github.com/codeb0ss/CVE-2024-7188-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-7188-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-7188-PoC.svg)


## CVE-2024-7135
 The Tainacan plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the 'get_file' function in all versions up to, and including, 0.21.7. The function is also vulnerable to directory traversal. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/RandomRobbieBF/CVE-2024-7135](https://github.com/RandomRobbieBF/CVE-2024-7135) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-7135.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-7135.svg)
- [https://github.com/Nxploited/CVE-2024-7135](https://github.com/Nxploited/CVE-2024-7135) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-7135.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-7135.svg)


## CVE-2024-7124
 Improper Neutralization of Input During Web Page Generation vulnerability in DInGO dLibra software in the parameter 'filter' in the endpoint 'indexsearch' allows a Reflected Cross-Site Scripting (XSS). An attacker might trick somebody into using a crafted URL, which will cause a script to be run in user's browser. This issue affects DInGO dLibra software in versions from 6.0 before 6.3.20.

- [https://github.com/kac89/CVE-2024-7124](https://github.com/kac89/CVE-2024-7124) :  ![starts](https://img.shields.io/github/stars/kac89/CVE-2024-7124.svg) ![forks](https://img.shields.io/github/forks/kac89/CVE-2024-7124.svg)


## CVE-2024-7120
 A vulnerability, which was classified as critical, was found in Raisecom MSG1200, MSG2100E, MSG2200 and MSG2300 3.90. This affects an unknown part of the file list_base_config.php of the component Web Interface. The manipulation of the argument template leads to os command injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-272451.

- [https://github.com/gh-ost00/CVE-2024-7120](https://github.com/gh-ost00/CVE-2024-7120) :  ![starts](https://img.shields.io/github/stars/gh-ost00/CVE-2024-7120.svg) ![forks](https://img.shields.io/github/forks/gh-ost00/CVE-2024-7120.svg)
- [https://github.com/codeb0ss/CVE-2024-7120-PoC](https://github.com/codeb0ss/CVE-2024-7120-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-7120-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-7120-PoC.svg)


## CVE-2024-7094
 The JS Help Desk – The Ultimate Help Desk & Support Plugin plugin for WordPress is vulnerable to PHP Code Injection leading to Remote Code Execution in all versions up to, and including, 2.8.6 via the 'storeTheme' function. This is due to a lack of sanitization on user-supplied values, which replace values in the style.php file, along with missing capability checks. This makes it possible for unauthenticated attackers to execute code on the server. This issue was partially patched in 2.8.6 when the code injection issue was resolved, and fully patched in 2.8.7 when the missing authorization and cross-site request forgery protection was added.

- [https://github.com/nastar-id/CVE-2024-7094](https://github.com/nastar-id/CVE-2024-7094) :  ![starts](https://img.shields.io/github/stars/nastar-id/CVE-2024-7094.svg) ![forks](https://img.shields.io/github/forks/nastar-id/CVE-2024-7094.svg)


## CVE-2024-7029
 Commands can be injected over the network and executed without authentication.

- [https://github.com/geniuszly/CVE-2024-7029](https://github.com/geniuszly/CVE-2024-7029) :  ![starts](https://img.shields.io/github/stars/geniuszly/CVE-2024-7029.svg) ![forks](https://img.shields.io/github/forks/geniuszly/CVE-2024-7029.svg)
- [https://github.com/bigherocenter/CVE-2024-7029-EXPLOIT](https://github.com/bigherocenter/CVE-2024-7029-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/bigherocenter/CVE-2024-7029-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/bigherocenter/CVE-2024-7029-EXPLOIT.svg)
- [https://github.com/ebrasha/CVE-2024-7029](https://github.com/ebrasha/CVE-2024-7029) :  ![starts](https://img.shields.io/github/stars/ebrasha/CVE-2024-7029.svg) ![forks](https://img.shields.io/github/forks/ebrasha/CVE-2024-7029.svg)


## CVE-2024-6893
 The "soap_cgi.pyc" API handler allows the XML body of SOAP requests to contain references to external entities. This allows an unauthenticated attacker to read local files, perform server-side request forgery, and overwhelm the web server resources.

- [https://github.com/codeb0ss/CVE-2024-6893-PoC](https://github.com/codeb0ss/CVE-2024-6893-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-6893-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-6893-PoC.svg)


## CVE-2024-6782
 Improper access control in Calibre 6.9.0 ~ 7.14.0 allow unauthenticated attackers to achieve remote code execution.

- [https://github.com/zangjiahe/CVE-2024-6782](https://github.com/zangjiahe/CVE-2024-6782) :  ![starts](https://img.shields.io/github/stars/zangjiahe/CVE-2024-6782.svg) ![forks](https://img.shields.io/github/forks/zangjiahe/CVE-2024-6782.svg)
- [https://github.com/NketiahGodfred/CVE-2024-6782](https://github.com/NketiahGodfred/CVE-2024-6782) :  ![starts](https://img.shields.io/github/stars/NketiahGodfred/CVE-2024-6782.svg) ![forks](https://img.shields.io/github/forks/NketiahGodfred/CVE-2024-6782.svg)
- [https://github.com/jdpsl/CVE-2024-6782](https://github.com/jdpsl/CVE-2024-6782) :  ![starts](https://img.shields.io/github/stars/jdpsl/CVE-2024-6782.svg) ![forks](https://img.shields.io/github/forks/jdpsl/CVE-2024-6782.svg)
- [https://github.com/0xB0y426/CVE-2024-6782-PoC](https://github.com/0xB0y426/CVE-2024-6782-PoC) :  ![starts](https://img.shields.io/github/stars/0xB0y426/CVE-2024-6782-PoC.svg) ![forks](https://img.shields.io/github/forks/0xB0y426/CVE-2024-6782-PoC.svg)


## CVE-2024-6778
 Race in DevTools in Google Chrome prior to 126.0.6478.182 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)

- [https://github.com/ading2210/CVE-2024-6778-POC](https://github.com/ading2210/CVE-2024-6778-POC) :  ![starts](https://img.shields.io/github/stars/ading2210/CVE-2024-6778-POC.svg) ![forks](https://img.shields.io/github/forks/ading2210/CVE-2024-6778-POC.svg)
- [https://github.com/r00tjunip3r1/POC-CVE-2024-6778](https://github.com/r00tjunip3r1/POC-CVE-2024-6778) :  ![starts](https://img.shields.io/github/stars/r00tjunip3r1/POC-CVE-2024-6778.svg) ![forks](https://img.shields.io/github/forks/r00tjunip3r1/POC-CVE-2024-6778.svg)


## CVE-2024-6769
 A DLL Hijacking caused by drive remapping combined with a poisoning of the activation cache in Microsoft Windows 10, Windows 11, Windows Server 2016, Windows Server 2019, and Windows Server 2022 allows a malicious authenticated attacker to elevate from a medium integrity process to a high integrity process without the intervention of a UAC prompt.

- [https://github.com/fortra/CVE-2024-6769](https://github.com/fortra/CVE-2024-6769) :  ![starts](https://img.shields.io/github/stars/fortra/CVE-2024-6769.svg) ![forks](https://img.shields.io/github/forks/fortra/CVE-2024-6769.svg)


## CVE-2024-6768
 A Denial of Service in CLFS.sys in Microsoft Windows 10, Windows 11, Windows Server 2016, Windows Server 2019, and Windows Server 2022 allows a malicious authenticated low-privilege user to cause a Blue Screen of Death via a forced call to the KeBugCheckEx function.

- [https://github.com/fortra/CVE-2024-6768](https://github.com/fortra/CVE-2024-6768) :  ![starts](https://img.shields.io/github/stars/fortra/CVE-2024-6768.svg) ![forks](https://img.shields.io/github/forks/fortra/CVE-2024-6768.svg)


## CVE-2024-6704
 The Comments – wpDiscuz plugin for WordPress is vulnerable to HTML Injection in all versions up to, and including, 7.6.21. This is due to a lack of filtering of HTML tags in comments. This makes it possible for unauthenticated attackers to add HTML such as hyperlinks to comments when rich editing is disabled.

- [https://github.com/codeb0ss/CVE-2024-6704](https://github.com/codeb0ss/CVE-2024-6704) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-6704.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-6704.svg)


## CVE-2024-6694
 The WP Mail SMTP plugin for WordPress is vulnerable to information exposure in all versions up to, and including, 4.0.1. This is due to plugin providing the SMTP password in the SMTP Password field when viewing the settings. This makes it possible for authenticated attackers, with administrative-level access and above, to view the SMTP password for the supplied server. Although this would not be useful for attackers in most cases, if an administrator account becomes compromised this could be useful information to an attacker in a limited environment.

- [https://github.com/codeb0ss/CVE-2024-6694-PoC](https://github.com/codeb0ss/CVE-2024-6694-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-6694-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-6694-PoC.svg)


## CVE-2024-6670
 In WhatsUp Gold versions released before 2024.0.0, a SQL Injection vulnerability allows an unauthenticated attacker to retrieve the users encrypted password.

- [https://github.com/sinsinology/CVE-2024-6670](https://github.com/sinsinology/CVE-2024-6670) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2024-6670.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2024-6670.svg)


## CVE-2024-6624
 The JSON API User plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 3.9.3. This is due to improper controls on custom user meta fields. This makes it possible for unauthenticated attackers to register as administrators on the site. The plugin requires the JSON API plugin to also be installed.

- [https://github.com/RandomRobbieBF/CVE-2024-6624](https://github.com/RandomRobbieBF/CVE-2024-6624) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-6624.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-6624.svg)


## CVE-2024-6594
This issue affects Single Sign-On Client: through 12.7.

- [https://github.com/RedTeamPentesting/watchguard-sso-client](https://github.com/RedTeamPentesting/watchguard-sso-client) :  ![starts](https://img.shields.io/github/stars/RedTeamPentesting/watchguard-sso-client.svg) ![forks](https://img.shields.io/github/forks/RedTeamPentesting/watchguard-sso-client.svg)


## CVE-2024-6593
This issue affects Authentication Gateway: through 12.10.2.

- [https://github.com/RedTeamPentesting/watchguard-sso-client](https://github.com/RedTeamPentesting/watchguard-sso-client) :  ![starts](https://img.shields.io/github/stars/RedTeamPentesting/watchguard-sso-client.svg) ![forks](https://img.shields.io/github/forks/RedTeamPentesting/watchguard-sso-client.svg)


## CVE-2024-6592
 Incorrect Authorization vulnerability in the protocol communication between the WatchGuard Authentication Gateway (aka Single Sign-On Agent) on Windows and the WatchGuard Single Sign-On Client on Windows and MacOS allows Authentication Bypass.This issue affects the Authentication Gateway: through 12.10.2; Windows Single Sign-On Client: through 12.7; MacOS Single Sign-On Client: through 12.5.4.

- [https://github.com/RedTeamPentesting/watchguard-sso-client](https://github.com/RedTeamPentesting/watchguard-sso-client) :  ![starts](https://img.shields.io/github/stars/RedTeamPentesting/watchguard-sso-client.svg) ![forks](https://img.shields.io/github/forks/RedTeamPentesting/watchguard-sso-client.svg)


## CVE-2024-6536
 The Zephyr Project Manager WordPress plugin before 3.3.99 does not sanitise and escape some of its settings, which could allow high privilege users such as editors and admins to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/apena-ba/CVE-2024-6536](https://github.com/apena-ba/CVE-2024-6536) :  ![starts](https://img.shields.io/github/stars/apena-ba/CVE-2024-6536.svg) ![forks](https://img.shields.io/github/forks/apena-ba/CVE-2024-6536.svg)


## CVE-2024-6529
 The Ultimate Classified Listings WordPress plugin before 1.4 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin

- [https://github.com/Abdurahmon3236/CVE-2024-6529](https://github.com/Abdurahmon3236/CVE-2024-6529) :  ![starts](https://img.shields.io/github/stars/Abdurahmon3236/CVE-2024-6529.svg) ![forks](https://img.shields.io/github/forks/Abdurahmon3236/CVE-2024-6529.svg)


## CVE-2024-6523
 A vulnerability was found in ZKTeco BioTime up to 9.5.2. It has been classified as problematic. Affected is an unknown function of the component system-group-add Handler. The manipulation of the argument user with the input scriptalert('XSS')/script leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-270366 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/CBaekhyunC/cve-2024-65230](https://github.com/CBaekhyunC/cve-2024-65230) :  ![starts](https://img.shields.io/github/stars/CBaekhyunC/cve-2024-65230.svg) ![forks](https://img.shields.io/github/forks/CBaekhyunC/cve-2024-65230.svg)


## CVE-2024-6473
 Yandex Browser for Desktop before 24.7.1.380 has a DLL Hijacking Vulnerability because an untrusted search path is used.

- [https://github.com/12345qwert123456/CVE-2024-6473-PoC](https://github.com/12345qwert123456/CVE-2024-6473-PoC) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2024-6473-PoC.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2024-6473-PoC.svg)


## CVE-2024-6409
 A race condition vulnerability was discovered in how signals are handled by OpenSSH's server (sshd). If a remote attacker does not authenticate within a set time period, then sshd's SIGALRM handler is called asynchronously. However, this signal handler calls various functions that are not async-signal-safe, for example, syslog(). As a consequence of a successful attack, in the worst case scenario, an attacker may be able to perform a remote code execution (RCE) as an unprivileged user running the sshd server.

- [https://github.com/password123456/cve-security-response-guidelines](https://github.com/password123456/cve-security-response-guidelines) :  ![starts](https://img.shields.io/github/stars/password123456/cve-security-response-guidelines.svg) ![forks](https://img.shields.io/github/forks/password123456/cve-security-response-guidelines.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/zgzhang/cve-2024-6387-poc](https://github.com/zgzhang/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/zgzhang/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/zgzhang/cve-2024-6387-poc.svg)
- [https://github.com/xaitax/CVE-2024-6387_Check](https://github.com/xaitax/CVE-2024-6387_Check) :  ![starts](https://img.shields.io/github/stars/xaitax/CVE-2024-6387_Check.svg) ![forks](https://img.shields.io/github/forks/xaitax/CVE-2024-6387_Check.svg)
- [https://github.com/acrono/cve-2024-6387-poc](https://github.com/acrono/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/acrono/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/acrono/cve-2024-6387-poc.svg)
- [https://github.com/lflare/cve-2024-6387-poc](https://github.com/lflare/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/lflare/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/lflare/cve-2024-6387-poc.svg)
- [https://github.com/filipi86/CVE-2024-6387-Vulnerability-Checker](https://github.com/filipi86/CVE-2024-6387-Vulnerability-Checker) :  ![starts](https://img.shields.io/github/stars/filipi86/CVE-2024-6387-Vulnerability-Checker.svg) ![forks](https://img.shields.io/github/forks/filipi86/CVE-2024-6387-Vulnerability-Checker.svg)
- [https://github.com/l0n3m4n/CVE-2024-6387](https://github.com/l0n3m4n/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-6387.svg)
- [https://github.com/asterictnl-lvdw/CVE-2024-6387](https://github.com/asterictnl-lvdw/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/asterictnl-lvdw/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/asterictnl-lvdw/CVE-2024-6387.svg)
- [https://github.com/theaog/spirit](https://github.com/theaog/spirit) :  ![starts](https://img.shields.io/github/stars/theaog/spirit.svg) ![forks](https://img.shields.io/github/forks/theaog/spirit.svg)
- [https://github.com/d0rb/CVE-2024-6387](https://github.com/d0rb/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2024-6387.svg)
- [https://github.com/xonoxitron/regreSSHion](https://github.com/xonoxitron/regreSSHion) :  ![starts](https://img.shields.io/github/stars/xonoxitron/regreSSHion.svg) ![forks](https://img.shields.io/github/forks/xonoxitron/regreSSHion.svg)
- [https://github.com/bigb0x/CVE-2024-6387](https://github.com/bigb0x/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-6387.svg)
- [https://github.com/getdrive/CVE-2024-6387-PoC](https://github.com/getdrive/CVE-2024-6387-PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/CVE-2024-6387-PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/CVE-2024-6387-PoC.svg)
- [https://github.com/thegenetic/CVE-2024-6387-exploit](https://github.com/thegenetic/CVE-2024-6387-exploit) :  ![starts](https://img.shields.io/github/stars/thegenetic/CVE-2024-6387-exploit.svg) ![forks](https://img.shields.io/github/forks/thegenetic/CVE-2024-6387-exploit.svg)
- [https://github.com/devarshishimpi/CVE-2024-6387-Check](https://github.com/devarshishimpi/CVE-2024-6387-Check) :  ![starts](https://img.shields.io/github/stars/devarshishimpi/CVE-2024-6387-Check.svg) ![forks](https://img.shields.io/github/forks/devarshishimpi/CVE-2024-6387-Check.svg)
- [https://github.com/sxlmnwb/CVE-2024-6387](https://github.com/sxlmnwb/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/sxlmnwb/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/sxlmnwb/CVE-2024-6387.svg)
- [https://github.com/AiGptCode/ssh_exploiter_CVE-2024-6387](https://github.com/AiGptCode/ssh_exploiter_CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/AiGptCode/ssh_exploiter_CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/AiGptCode/ssh_exploiter_CVE-2024-6387.svg)
- [https://github.com/TAM-K592/CVE-2024-6387](https://github.com/TAM-K592/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-6387.svg)
- [https://github.com/YassDEV221608/CVE-2024-6387_PoC](https://github.com/YassDEV221608/CVE-2024-6387_PoC) :  ![starts](https://img.shields.io/github/stars/YassDEV221608/CVE-2024-6387_PoC.svg) ![forks](https://img.shields.io/github/forks/YassDEV221608/CVE-2024-6387_PoC.svg)
- [https://github.com/l-urk/CVE-2024-6387](https://github.com/l-urk/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/l-urk/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/l-urk/CVE-2024-6387.svg)
- [https://github.com/0x4D31/cve-2024-6387_hassh](https://github.com/0x4D31/cve-2024-6387_hassh) :  ![starts](https://img.shields.io/github/stars/0x4D31/cve-2024-6387_hassh.svg) ![forks](https://img.shields.io/github/forks/0x4D31/cve-2024-6387_hassh.svg)
- [https://github.com/wiggels/regresshion-check](https://github.com/wiggels/regresshion-check) :  ![starts](https://img.shields.io/github/stars/wiggels/regresshion-check.svg) ![forks](https://img.shields.io/github/forks/wiggels/regresshion-check.svg)
- [https://github.com/kuffsit/check_cve_2024_6387](https://github.com/kuffsit/check_cve_2024_6387) :  ![starts](https://img.shields.io/github/stars/kuffsit/check_cve_2024_6387.svg) ![forks](https://img.shields.io/github/forks/kuffsit/check_cve_2024_6387.svg)
- [https://github.com/th3gokul/CVE-2024-6387](https://github.com/th3gokul/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/th3gokul/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/th3gokul/CVE-2024-6387.svg)
- [https://github.com/azurejoga/CVE-2024-6387-how-to-fix](https://github.com/azurejoga/CVE-2024-6387-how-to-fix) :  ![starts](https://img.shields.io/github/stars/azurejoga/CVE-2024-6387-how-to-fix.svg) ![forks](https://img.shields.io/github/forks/azurejoga/CVE-2024-6387-how-to-fix.svg)
- [https://github.com/3yujw7njai/CVE-2024-6387](https://github.com/3yujw7njai/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/3yujw7njai/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/3yujw7njai/CVE-2024-6387.svg)
- [https://github.com/xonoxitron/regreSSHion-checker](https://github.com/xonoxitron/regreSSHion-checker) :  ![starts](https://img.shields.io/github/stars/xonoxitron/regreSSHion-checker.svg) ![forks](https://img.shields.io/github/forks/xonoxitron/regreSSHion-checker.svg)
- [https://github.com/paradessia/CVE-2024-6387-nmap](https://github.com/paradessia/CVE-2024-6387-nmap) :  ![starts](https://img.shields.io/github/stars/paradessia/CVE-2024-6387-nmap.svg) ![forks](https://img.shields.io/github/forks/paradessia/CVE-2024-6387-nmap.svg)
- [https://github.com/awusan125/test_for6387](https://github.com/awusan125/test_for6387) :  ![starts](https://img.shields.io/github/stars/awusan125/test_for6387.svg) ![forks](https://img.shields.io/github/forks/awusan125/test_for6387.svg)
- [https://github.com/lala-amber/CVE-2024-6387](https://github.com/lala-amber/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/lala-amber/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/lala-amber/CVE-2024-6387.svg)
- [https://github.com/BrandonLynch2402/cve-2024-6387-nuclei-template](https://github.com/BrandonLynch2402/cve-2024-6387-nuclei-template) :  ![starts](https://img.shields.io/github/stars/BrandonLynch2402/cve-2024-6387-nuclei-template.svg) ![forks](https://img.shields.io/github/forks/BrandonLynch2402/cve-2024-6387-nuclei-template.svg)
- [https://github.com/harshinsecurity/sentinelssh](https://github.com/harshinsecurity/sentinelssh) :  ![starts](https://img.shields.io/github/stars/harshinsecurity/sentinelssh.svg) ![forks](https://img.shields.io/github/forks/harshinsecurity/sentinelssh.svg)
- [https://github.com/MaulikxLakhani/SSHScout](https://github.com/MaulikxLakhani/SSHScout) :  ![starts](https://img.shields.io/github/stars/MaulikxLakhani/SSHScout.svg) ![forks](https://img.shields.io/github/forks/MaulikxLakhani/SSHScout.svg)
- [https://github.com/prelearn-code/CVE-2024-6387](https://github.com/prelearn-code/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/prelearn-code/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/prelearn-code/CVE-2024-6387.svg)
- [https://github.com/betancour/OpenSSH-Vulnerability-test](https://github.com/betancour/OpenSSH-Vulnerability-test) :  ![starts](https://img.shields.io/github/stars/betancour/OpenSSH-Vulnerability-test.svg) ![forks](https://img.shields.io/github/forks/betancour/OpenSSH-Vulnerability-test.svg)
- [https://github.com/Symbolexe/CVE-2024-6387](https://github.com/Symbolexe/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/Symbolexe/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/Symbolexe/CVE-2024-6387.svg)
- [https://github.com/ahlfors/CVE-2024-6387](https://github.com/ahlfors/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/ahlfors/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/ahlfors/CVE-2024-6387.svg)
- [https://github.com/ThatNotEasy/CVE-2024-6387](https://github.com/ThatNotEasy/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2024-6387.svg)
- [https://github.com/ACHUX21/checker-CVE-2024-6387](https://github.com/ACHUX21/checker-CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/ACHUX21/checker-CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/ACHUX21/checker-CVE-2024-6387.svg)
- [https://github.com/muyuanlove/CVE-2024-6387fixshell](https://github.com/muyuanlove/CVE-2024-6387fixshell) :  ![starts](https://img.shields.io/github/stars/muyuanlove/CVE-2024-6387fixshell.svg) ![forks](https://img.shields.io/github/forks/muyuanlove/CVE-2024-6387fixshell.svg)
- [https://github.com/identity-threat-labs/CVE-2024-6387-Vulnerability-Checker](https://github.com/identity-threat-labs/CVE-2024-6387-Vulnerability-Checker) :  ![starts](https://img.shields.io/github/stars/identity-threat-labs/CVE-2024-6387-Vulnerability-Checker.svg) ![forks](https://img.shields.io/github/forks/identity-threat-labs/CVE-2024-6387-Vulnerability-Checker.svg)
- [https://github.com/MrR0b0t19/CVE-2024-6387-Exploit-POC](https://github.com/MrR0b0t19/CVE-2024-6387-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/MrR0b0t19/CVE-2024-6387-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/MrR0b0t19/CVE-2024-6387-Exploit-POC.svg)
- [https://github.com/PrincipalAnthony/CVE-2024-6387-Updated-x64bit](https://github.com/PrincipalAnthony/CVE-2024-6387-Updated-x64bit) :  ![starts](https://img.shields.io/github/stars/PrincipalAnthony/CVE-2024-6387-Updated-x64bit.svg) ![forks](https://img.shields.io/github/forks/PrincipalAnthony/CVE-2024-6387-Updated-x64bit.svg)
- [https://github.com/rumochnaya/openssh-cve-2024-6387.sh](https://github.com/rumochnaya/openssh-cve-2024-6387.sh) :  ![starts](https://img.shields.io/github/stars/rumochnaya/openssh-cve-2024-6387.sh.svg) ![forks](https://img.shields.io/github/forks/rumochnaya/openssh-cve-2024-6387.sh.svg)
- [https://github.com/Sibijo/mitigate_ssh](https://github.com/Sibijo/mitigate_ssh) :  ![starts](https://img.shields.io/github/stars/Sibijo/mitigate_ssh.svg) ![forks](https://img.shields.io/github/forks/Sibijo/mitigate_ssh.svg)
- [https://github.com/R4Tw1z/CVE-2024-6387](https://github.com/R4Tw1z/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/R4Tw1z/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/R4Tw1z/CVE-2024-6387.svg)
- [https://github.com/grupooruss/CVE-2024-6387](https://github.com/grupooruss/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/grupooruss/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/grupooruss/CVE-2024-6387.svg)
- [https://github.com/SecWithMoh/CVE-2024-6387](https://github.com/SecWithMoh/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/SecWithMoh/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/SecWithMoh/CVE-2024-6387.svg)
- [https://github.com/shamo0/CVE-2024-6387_PoC](https://github.com/shamo0/CVE-2024-6387_PoC) :  ![starts](https://img.shields.io/github/stars/shamo0/CVE-2024-6387_PoC.svg) ![forks](https://img.shields.io/github/forks/shamo0/CVE-2024-6387_PoC.svg)
- [https://github.com/passwa11/cve-2024-6387-poc](https://github.com/passwa11/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/passwa11/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/passwa11/cve-2024-6387-poc.svg)
- [https://github.com/n1cks0n/Test_CVE-2024-6387](https://github.com/n1cks0n/Test_CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/n1cks0n/Test_CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/n1cks0n/Test_CVE-2024-6387.svg)
- [https://github.com/identity-threat-labs/Article-RegreSSHion-CVE-2024-6387](https://github.com/identity-threat-labs/Article-RegreSSHion-CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/identity-threat-labs/Article-RegreSSHion-CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/identity-threat-labs/Article-RegreSSHion-CVE-2024-6387.svg)
- [https://github.com/turbobit/CVE-2024-6387-OpenSSH-Vulnerability-Checker](https://github.com/turbobit/CVE-2024-6387-OpenSSH-Vulnerability-Checker) :  ![starts](https://img.shields.io/github/stars/turbobit/CVE-2024-6387-OpenSSH-Vulnerability-Checker.svg) ![forks](https://img.shields.io/github/forks/turbobit/CVE-2024-6387-OpenSSH-Vulnerability-Checker.svg)
- [https://github.com/teamos-hub/regreSSHion](https://github.com/teamos-hub/regreSSHion) :  ![starts](https://img.shields.io/github/stars/teamos-hub/regreSSHion.svg) ![forks](https://img.shields.io/github/forks/teamos-hub/regreSSHion.svg)
- [https://github.com/X-Projetion/CVE-2023-4596-OpenSSH-Multi-Checker](https://github.com/X-Projetion/CVE-2023-4596-OpenSSH-Multi-Checker) :  ![starts](https://img.shields.io/github/stars/X-Projetion/CVE-2023-4596-OpenSSH-Multi-Checker.svg) ![forks](https://img.shields.io/github/forks/X-Projetion/CVE-2023-4596-OpenSSH-Multi-Checker.svg)
- [https://github.com/password123456/cve-security-response-guidelines](https://github.com/password123456/cve-security-response-guidelines) :  ![starts](https://img.shields.io/github/stars/password123456/cve-security-response-guidelines.svg) ![forks](https://img.shields.io/github/forks/password123456/cve-security-response-guidelines.svg)
- [https://github.com/hssmo/cve-2024-6387_AImade](https://github.com/hssmo/cve-2024-6387_AImade) :  ![starts](https://img.shields.io/github/stars/hssmo/cve-2024-6387_AImade.svg) ![forks](https://img.shields.io/github/forks/hssmo/cve-2024-6387_AImade.svg)
- [https://github.com/FerasAlrimali/CVE-2024-6387-POC](https://github.com/FerasAlrimali/CVE-2024-6387-POC) :  ![starts](https://img.shields.io/github/stars/FerasAlrimali/CVE-2024-6387-POC.svg) ![forks](https://img.shields.io/github/forks/FerasAlrimali/CVE-2024-6387-POC.svg)
- [https://github.com/SiberianHacker/CVE-2024-6387-Finder](https://github.com/SiberianHacker/CVE-2024-6387-Finder) :  ![starts](https://img.shields.io/github/stars/SiberianHacker/CVE-2024-6387-Finder.svg) ![forks](https://img.shields.io/github/forks/SiberianHacker/CVE-2024-6387-Finder.svg)
- [https://github.com/no-one-sec/CVE-2024-6387](https://github.com/no-one-sec/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/no-one-sec/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/no-one-sec/CVE-2024-6387.svg)
- [https://github.com/imv7/CVE-2024-6387](https://github.com/imv7/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/imv7/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/imv7/CVE-2024-6387.svg)
- [https://github.com/jack0we/CVE-2024-6387](https://github.com/jack0we/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/jack0we/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/jack0we/CVE-2024-6387.svg)
- [https://github.com/dawnl3ss/CVE-2024-6387](https://github.com/dawnl3ss/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/dawnl3ss/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/dawnl3ss/CVE-2024-6387.svg)
- [https://github.com/sms2056/CVE-2024-6387](https://github.com/sms2056/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/sms2056/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/sms2056/CVE-2024-6387.svg)
- [https://github.com/YassDEV221608/CVE-2024-6387](https://github.com/YassDEV221608/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/YassDEV221608/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/YassDEV221608/CVE-2024-6387.svg)
- [https://github.com/mrmtwoj/CVE-2024-6387](https://github.com/mrmtwoj/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/CVE-2024-6387.svg)
- [https://github.com/zql-gif/CVE-2024-6387](https://github.com/zql-gif/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/zql-gif/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/zql-gif/CVE-2024-6387.svg)
- [https://github.com/dream434/CVE-2024-6387](https://github.com/dream434/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2024-6387.svg)
- [https://github.com/DimaMend/cve-2024-6387-poc](https://github.com/DimaMend/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/DimaMend/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/DimaMend/cve-2024-6387-poc.svg)
- [https://github.com/Mufti22/CVE-2024-6387-checkher](https://github.com/Mufti22/CVE-2024-6387-checkher) :  ![starts](https://img.shields.io/github/stars/Mufti22/CVE-2024-6387-checkher.svg) ![forks](https://img.shields.io/github/forks/Mufti22/CVE-2024-6387-checkher.svg)
- [https://github.com/shyrwall/cve-2024-6387-poc](https://github.com/shyrwall/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/shyrwall/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/shyrwall/cve-2024-6387-poc.svg)
- [https://github.com/HadesNull123/CVE-2024-6387_Check](https://github.com/HadesNull123/CVE-2024-6387_Check) :  ![starts](https://img.shields.io/github/stars/HadesNull123/CVE-2024-6387_Check.svg) ![forks](https://img.shields.io/github/forks/HadesNull123/CVE-2024-6387_Check.svg)
- [https://github.com/t3rry327/cve-2024-6387-poc](https://github.com/t3rry327/cve-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/t3rry327/cve-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/t3rry327/cve-2024-6387-poc.svg)
- [https://github.com/dgourillon/mitigate-CVE-2024-6387](https://github.com/dgourillon/mitigate-CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/dgourillon/mitigate-CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/dgourillon/mitigate-CVE-2024-6387.svg)
- [https://github.com/edsonjt81/CVE-2024-6387_Check](https://github.com/edsonjt81/CVE-2024-6387_Check) :  ![starts](https://img.shields.io/github/stars/edsonjt81/CVE-2024-6387_Check.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/CVE-2024-6387_Check.svg)
- [https://github.com/CognisysGroup/CVE-2024-6387-Checker](https://github.com/CognisysGroup/CVE-2024-6387-Checker) :  ![starts](https://img.shields.io/github/stars/CognisysGroup/CVE-2024-6387-Checker.svg) ![forks](https://img.shields.io/github/forks/CognisysGroup/CVE-2024-6387-Checker.svg)
- [https://github.com/zenzue/CVE-2024-6387-Mitigation](https://github.com/zenzue/CVE-2024-6387-Mitigation) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2024-6387-Mitigation.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2024-6387-Mitigation.svg)
- [https://github.com/sardine-web/CVE-2024-6387_Check](https://github.com/sardine-web/CVE-2024-6387_Check) :  ![starts](https://img.shields.io/github/stars/sardine-web/CVE-2024-6387_Check.svg) ![forks](https://img.shields.io/github/forks/sardine-web/CVE-2024-6387_Check.svg)
- [https://github.com/sardine-web/CVE-2024-6387-template](https://github.com/sardine-web/CVE-2024-6387-template) :  ![starts](https://img.shields.io/github/stars/sardine-web/CVE-2024-6387-template.svg) ![forks](https://img.shields.io/github/forks/sardine-web/CVE-2024-6387-template.svg)
- [https://github.com/skyalliance/CVE-2024-6387-POC](https://github.com/skyalliance/CVE-2024-6387-POC) :  ![starts](https://img.shields.io/github/stars/skyalliance/CVE-2024-6387-POC.svg) ![forks](https://img.shields.io/github/forks/skyalliance/CVE-2024-6387-POC.svg)
- [https://github.com/RickGeex/CVE-2024-6387-Checker](https://github.com/RickGeex/CVE-2024-6387-Checker) :  ![starts](https://img.shields.io/github/stars/RickGeex/CVE-2024-6387-Checker.svg) ![forks](https://img.shields.io/github/forks/RickGeex/CVE-2024-6387-Checker.svg)
- [https://github.com/jocker2410/CVE-2024-6387_poc](https://github.com/jocker2410/CVE-2024-6387_poc) :  ![starts](https://img.shields.io/github/stars/jocker2410/CVE-2024-6387_poc.svg) ![forks](https://img.shields.io/github/forks/jocker2410/CVE-2024-6387_poc.svg)
- [https://github.com/anhvutuan/CVE-2024-6387-poc-1](https://github.com/anhvutuan/CVE-2024-6387-poc-1) :  ![starts](https://img.shields.io/github/stars/anhvutuan/CVE-2024-6387-poc-1.svg) ![forks](https://img.shields.io/github/forks/anhvutuan/CVE-2024-6387-poc-1.svg)
- [https://github.com/JackSparrowhk/ssh-CVE-2024-6387-poc](https://github.com/JackSparrowhk/ssh-CVE-2024-6387-poc) :  ![starts](https://img.shields.io/github/stars/JackSparrowhk/ssh-CVE-2024-6387-poc.svg) ![forks](https://img.shields.io/github/forks/JackSparrowhk/ssh-CVE-2024-6387-poc.svg)
- [https://github.com/kubota/CVE-2024-6387-Vulnerability-Checker](https://github.com/kubota/CVE-2024-6387-Vulnerability-Checker) :  ![starts](https://img.shields.io/github/stars/kubota/CVE-2024-6387-Vulnerability-Checker.svg) ![forks](https://img.shields.io/github/forks/kubota/CVE-2024-6387-Vulnerability-Checker.svg)
- [https://github.com/invaderslabs/regreSSHion-CVE-2024-6387-](https://github.com/invaderslabs/regreSSHion-CVE-2024-6387-) :  ![starts](https://img.shields.io/github/stars/invaderslabs/regreSSHion-CVE-2024-6387-.svg) ![forks](https://img.shields.io/github/forks/invaderslabs/regreSSHion-CVE-2024-6387-.svg)
- [https://github.com/4lxprime/regreSSHive](https://github.com/4lxprime/regreSSHive) :  ![starts](https://img.shields.io/github/stars/4lxprime/regreSSHive.svg) ![forks](https://img.shields.io/github/forks/4lxprime/regreSSHive.svg)
- [https://github.com/daniel-odrinski/CVE-2024-6387-Mitigation-Ansible-Playbook](https://github.com/daniel-odrinski/CVE-2024-6387-Mitigation-Ansible-Playbook) :  ![starts](https://img.shields.io/github/stars/daniel-odrinski/CVE-2024-6387-Mitigation-Ansible-Playbook.svg) ![forks](https://img.shields.io/github/forks/daniel-odrinski/CVE-2024-6387-Mitigation-Ansible-Playbook.svg)
- [https://github.com/almogopp/OpenSSH-CVE-2024-6387-Fix](https://github.com/almogopp/OpenSSH-CVE-2024-6387-Fix) :  ![starts](https://img.shields.io/github/stars/almogopp/OpenSSH-CVE-2024-6387-Fix.svg) ![forks](https://img.shields.io/github/forks/almogopp/OpenSSH-CVE-2024-6387-Fix.svg)
- [https://github.com/Passyed/regreSSHion-Fix](https://github.com/Passyed/regreSSHion-Fix) :  ![starts](https://img.shields.io/github/stars/Passyed/regreSSHion-Fix.svg) ![forks](https://img.shields.io/github/forks/Passyed/regreSSHion-Fix.svg)
- [https://github.com/vkaushik-chef/regreSSHion](https://github.com/vkaushik-chef/regreSSHion) :  ![starts](https://img.shields.io/github/stars/vkaushik-chef/regreSSHion.svg) ![forks](https://img.shields.io/github/forks/vkaushik-chef/regreSSHion.svg)
- [https://github.com/liqhtnd/sshd-logingracetime0](https://github.com/liqhtnd/sshd-logingracetime0) :  ![starts](https://img.shields.io/github/stars/liqhtnd/sshd-logingracetime0.svg) ![forks](https://img.shields.io/github/forks/liqhtnd/sshd-logingracetime0.svg)
- [https://github.com/CiderAndWhisky/regression-scanner](https://github.com/CiderAndWhisky/regression-scanner) :  ![starts](https://img.shields.io/github/stars/CiderAndWhisky/regression-scanner.svg) ![forks](https://img.shields.io/github/forks/CiderAndWhisky/regression-scanner.svg)
- [https://github.com/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH](https://github.com/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH) :  ![starts](https://img.shields.io/github/stars/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH.svg) ![forks](https://img.shields.io/github/forks/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH.svg)
- [https://github.com/alex14324/ssh_poc2024](https://github.com/alex14324/ssh_poc2024) :  ![starts](https://img.shields.io/github/stars/alex14324/ssh_poc2024.svg) ![forks](https://img.shields.io/github/forks/alex14324/ssh_poc2024.svg)
- [https://github.com/xristos8574/regreSSHion-nmap-scanner](https://github.com/xristos8574/regreSSHion-nmap-scanner) :  ![starts](https://img.shields.io/github/stars/xristos8574/regreSSHion-nmap-scanner.svg) ![forks](https://img.shields.io/github/forks/xristos8574/regreSSHion-nmap-scanner.svg)


## CVE-2024-6386
 The WPML plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.6.12 via the Twig Server-Side Template Injection. This is due to missing input validation and sanitization on the render function. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server.

- [https://github.com/argendo/CVE-2024-6386](https://github.com/argendo/CVE-2024-6386) :  ![starts](https://img.shields.io/github/stars/argendo/CVE-2024-6386.svg) ![forks](https://img.shields.io/github/forks/argendo/CVE-2024-6386.svg)


## CVE-2024-6366
 The User Profile Builder  WordPress plugin before 3.11.8 does not have proper authorisation, allowing unauthenticated users to upload media files via the async upload functionality of WP.

- [https://github.com/Abdurahmon3236/CVE-2024-6366](https://github.com/Abdurahmon3236/CVE-2024-6366) :  ![starts](https://img.shields.io/github/stars/Abdurahmon3236/CVE-2024-6366.svg) ![forks](https://img.shields.io/github/forks/Abdurahmon3236/CVE-2024-6366.svg)


## CVE-2024-6330
 The GEO my WP WordPress plugin before 4.5.0.2 does not prevent unauthenticated attackers from including arbitrary files in PHP's execution context, which leads to Remote Code Execution.

- [https://github.com/RandomRobbieBF/CVE-2024-6330](https://github.com/RandomRobbieBF/CVE-2024-6330) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-6330.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-6330.svg)


## CVE-2024-3684
 A server side request forgery vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin access to the appliance when configuring the Artifacts & Logs and Migrations Storage. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.12.2, 3.11.8, 3.10.10, and 3.9.13. This vulnerability was reported via the GitHub Bug Bounty program.

- [https://github.com/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-](https://github.com/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-) :  ![starts](https://img.shields.io/github/stars/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-.svg) ![forks](https://img.shields.io/github/forks/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/XiaomingX/CVE-2024-3400-poc](https://github.com/XiaomingX/CVE-2024-3400-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/CVE-2024-3400-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/CVE-2024-3400-poc.svg)


## CVE-2024-3393
 A Denial of Service vulnerability in the DNS Security feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to send a malicious packet through the data plane of the firewall that reboots the firewall. Repeated attempts to trigger this condition will cause the firewall to enter maintenance mode.

- [https://github.com/waived/CVE-2024-3393](https://github.com/waived/CVE-2024-3393) :  ![starts](https://img.shields.io/github/stars/waived/CVE-2024-3393.svg) ![forks](https://img.shields.io/github/forks/waived/CVE-2024-3393.svg)


## CVE-2024-3264
 Use of a Broken or Risky Cryptographic Algorithm vulnerability in Mia Technology Inc. Mia-Med Health Aplication allows Signature Spoofing by Improper Validation.This issue affects Mia-Med Health Aplication: before 1.0.14.

- [https://github.com/Stuub/CVE-2024-32640-SQLI-MuraCMS](https://github.com/Stuub/CVE-2024-32640-SQLI-MuraCMS) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2024-32640-SQLI-MuraCMS.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2024-32640-SQLI-MuraCMS.svg)
- [https://github.com/pizza-power/CVE-2024-32640](https://github.com/pizza-power/CVE-2024-32640) :  ![starts](https://img.shields.io/github/stars/pizza-power/CVE-2024-32640.svg) ![forks](https://img.shields.io/github/forks/pizza-power/CVE-2024-32640.svg)
- [https://github.com/0xYumeko/CVE-2024-32640-SQLI-MuraCMS](https://github.com/0xYumeko/CVE-2024-32640-SQLI-MuraCMS) :  ![starts](https://img.shields.io/github/stars/0xYumeko/CVE-2024-32640-SQLI-MuraCMS.svg) ![forks](https://img.shields.io/github/forks/0xYumeko/CVE-2024-32640-SQLI-MuraCMS.svg)
- [https://github.com/sammings/CVE-2024-32640](https://github.com/sammings/CVE-2024-32640) :  ![starts](https://img.shields.io/github/stars/sammings/CVE-2024-32640.svg) ![forks](https://img.shields.io/github/forks/sammings/CVE-2024-32640.svg)


## CVE-2024-3171
 Use after free in Accessibility in Google Chrome prior to 122.0.6261.57 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI gestures. (Chromium security severity: Medium)

- [https://github.com/VoltaireYoung/CVE-2024-31719----AMI-Aptio-5-Vulnerability](https://github.com/VoltaireYoung/CVE-2024-31719----AMI-Aptio-5-Vulnerability) :  ![starts](https://img.shields.io/github/stars/VoltaireYoung/CVE-2024-31719----AMI-Aptio-5-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/VoltaireYoung/CVE-2024-31719----AMI-Aptio-5-Vulnerability.svg)


## CVE-2024-3095
 A Server-Side Request Forgery (SSRF) vulnerability exists in the Web Research Retriever component of langchain-ai/langchain version 0.1.5. The vulnerability arises because the Web Research Retriever does not restrict requests to remote internet addresses, allowing it to reach local addresses. This flaw enables attackers to execute port scans, access local services, and in some scenarios, read instance metadata from cloud environments. The vulnerability is particularly concerning as it can be exploited to abuse the Web Explorer server as a proxy for web attacks on third parties and interact with servers in the local network, including reading their response data. This could potentially lead to arbitrary code execution, depending on the nature of the local services. The vulnerability is limited to GET requests, as POST requests are not possible, but the impact on confidentiality, integrity, and availability is significant due to the potential for stolen credentials and state-changing interactions with internal APIs.

- [https://github.com/leoCottret/CVE-2024-30956](https://github.com/leoCottret/CVE-2024-30956) :  ![starts](https://img.shields.io/github/stars/leoCottret/CVE-2024-30956.svg) ![forks](https://img.shields.io/github/forks/leoCottret/CVE-2024-30956.svg)


## CVE-2024-2769
 A vulnerability was found in Campcodes Complete Online Beauty Parlor Management System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /admin/admin-profile.php. The manipulation of the argument adminname leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-257605 was assigned to this vulnerability.

- [https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697](https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697) :  ![starts](https://img.shields.io/github/stars/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697.svg) ![forks](https://img.shields.io/github/forks/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697.svg)


## CVE-2024-2656
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting via a CSV import in all versions up to, and including, 5.7.14 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/sajaljat/CVE-2024-26560](https://github.com/sajaljat/CVE-2024-26560) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-26560.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-26560.svg)


## CVE-2024-2653
 amphp/http will collect CONTINUATION frames in an unbounded buffer and will not check a limit until it has received the set END_HEADERS flag, resulting in an OOM crash.

- [https://github.com/sajaljat/CVE-2024-26535](https://github.com/sajaljat/CVE-2024-26535) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-26535.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-26535.svg)
- [https://github.com/sajaljat/CVE-2024-26534](https://github.com/sajaljat/CVE-2024-26534) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-26534.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-26534.svg)


## CVE-2024-2580
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in FunnelKit Automation By Autonami allows Stored XSS.This issue affects Automation By Autonami: from n/a through 2.8.2.

- [https://github.com/sajaljat/CVE-2024-25809](https://github.com/sajaljat/CVE-2024-25809) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25809.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25809.svg)


## CVE-2024-2528
 A vulnerability was found in MAGESH-K21 Online-College-Event-Hall-Reservation-System 1.0. It has been classified as critical. This affects an unknown part of the file /admin/update-rooms.php. The manipulation of the argument room_id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-256965 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/sajaljat/CVE-2024-25281](https://github.com/sajaljat/CVE-2024-25281) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25281.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25281.svg)
- [https://github.com/sajaljat/CVE-2024-25280](https://github.com/sajaljat/CVE-2024-25280) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25280.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25280.svg)


## CVE-2024-2527
 A vulnerability was found in MAGESH-K21 Online-College-Event-Hall-Reservation-System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /admin/rooms.php. The manipulation of the argument room_id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-256964. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/maen08/CVE-2024-25277](https://github.com/maen08/CVE-2024-25277) :  ![starts](https://img.shields.io/github/stars/maen08/CVE-2024-25277.svg) ![forks](https://img.shields.io/github/forks/maen08/CVE-2024-25277.svg)
- [https://github.com/sajaljat/CVE-2024-25279](https://github.com/sajaljat/CVE-2024-25279) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25279.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25279.svg)
- [https://github.com/sajaljat/CVE-2024-25278](https://github.com/sajaljat/CVE-2024-25278) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2024-25278.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2024-25278.svg)


## CVE-2024-2420
 LenelS2 NetBox access control and event monitoring system was discovered to contain Hardcoded Credentials in versions prior to and including 5.6.1 which allows an attacker to bypass authentication requirements.

- [https://github.com/l00neyhacker/CVE-2024-24204](https://github.com/l00neyhacker/CVE-2024-24204) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-24204.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-24204.svg)
- [https://github.com/l00neyhacker/CVE-2024-24203](https://github.com/l00neyhacker/CVE-2024-24203) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-24203.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-24203.svg)
- [https://github.com/l00neyhacker/CVE-2024-24206](https://github.com/l00neyhacker/CVE-2024-24206) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-24206.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-24206.svg)


## CVE-2024-2413
 Intumit SmartRobot uses a fixed encryption key for authentication. Remote attackers can use this key to encrypt a string composed of the user's name and timestamp to generate an authentication code. With this authentication code, they can obtain administrator privileges and subsequently execute arbitrary code on the remote server using built-in system functionality.

- [https://github.com/BurakSevben/CVE-2024-24137](https://github.com/BurakSevben/CVE-2024-24137) :  ![starts](https://img.shields.io/github/stars/BurakSevben/CVE-2024-24137.svg) ![forks](https://img.shields.io/github/forks/BurakSevben/CVE-2024-24137.svg)
- [https://github.com/BurakSevben/CVE-2024-24138](https://github.com/BurakSevben/CVE-2024-24138) :  ![starts](https://img.shields.io/github/stars/BurakSevben/CVE-2024-24138.svg) ![forks](https://img.shields.io/github/forks/BurakSevben/CVE-2024-24138.svg)


## CVE-2024-2410
 The JsonToBinaryStream() function is part of the protocol buffers C++ implementation and is used to parse JSON from a stream. If the input is broken up into separate chunks in a certain way, the parser will attempt to read bytes from a chunk that has already been freed. 

- [https://github.com/ASR511-OO7/CVE-2024-24108](https://github.com/ASR511-OO7/CVE-2024-24108) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2024-24108.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2024-24108.svg)
- [https://github.com/ASR511-OO7/CVE-2024-24103](https://github.com/ASR511-OO7/CVE-2024-24103) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2024-24103.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2024-24103.svg)
- [https://github.com/ASR511-OO7/CVE-2024-24102](https://github.com/ASR511-OO7/CVE-2024-24102) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2024-24102.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2024-24102.svg)
- [https://github.com/ASR511-OO7/CVE-2024-24104](https://github.com/ASR511-OO7/CVE-2024-24104) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2024-24104.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2024-24104.svg)


## CVE-2024-2409
 The MasterStudy LMS plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.3.1. This is due to insufficient validation checks within the _register_user() function called by the 'wp_ajax_nopriv_stm_lms_register' AJAX action. This makes it possible for unauthenticated attackers to register a user with administrator-level privileges when MasterStudy LMS Pro is installed and the LMS Forms Editor add-on is enabled.

- [https://github.com/ASR511-OO7/CVE-2024-24094](https://github.com/ASR511-OO7/CVE-2024-24094) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2024-24094.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2024-24094.svg)


## CVE-2024-2378
 A vulnerability exists in the web-authentication component of the SDM600. If exploited an attacker could escalate privileges on af-fected installations.

- [https://github.com/HazardLab-IO/CVE-2024-23780](https://github.com/HazardLab-IO/CVE-2024-23780) :  ![starts](https://img.shields.io/github/stars/HazardLab-IO/CVE-2024-23780.svg) ![forks](https://img.shields.io/github/forks/HazardLab-IO/CVE-2024-23780.svg)


## CVE-2024-2319
 Cross-Site Scripting (XSS) vulnerability in the Django MarkdownX project, affecting version 4.0.2. An attacker could store a specially crafted JavaScript payload in the upload functionality due to lack of proper sanitisation of JavaScript elements.

- [https://github.com/l00neyhacker/CVE-2024-23199](https://github.com/l00neyhacker/CVE-2024-23199) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-23199.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-23199.svg)


## CVE-2024-2300
 HP Advance Mobile Applications for iOS and Android are potentially vulnerable to information disclosure when using an outdated version of the application via mobile devices.

- [https://github.com/xiaomaoxxx/CVE-2024-23002](https://github.com/xiaomaoxxx/CVE-2024-23002) :  ![starts](https://img.shields.io/github/stars/xiaomaoxxx/CVE-2024-23002.svg) ![forks](https://img.shields.io/github/forks/xiaomaoxxx/CVE-2024-23002.svg)


## CVE-2024-2290
 The Advanced Ads plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 1.52.1 via deserialization of untrusted input in the 'placement_slug' parameter. This makes it possible for authenticated attackers to inject a PHP Object. No POP chain is present in the vulnerable plugin. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code.

- [https://github.com/BurakSevben/CVE-2024-22909](https://github.com/BurakSevben/CVE-2024-22909) :  ![starts](https://img.shields.io/github/stars/BurakSevben/CVE-2024-22909.svg) ![forks](https://img.shields.io/github/forks/BurakSevben/CVE-2024-22909.svg)


## CVE-2024-2289
 The PowerPack Lite for Beaver Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the link in multiple elements in all versions up to, and including, 1.3.0 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers with contributor-level and above permissions to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/BurakSevben/CVE-2024-22890](https://github.com/BurakSevben/CVE-2024-22890) :  ![starts](https://img.shields.io/github/stars/BurakSevben/CVE-2024-22890.svg) ![forks](https://img.shields.io/github/forks/BurakSevben/CVE-2024-22890.svg)


## CVE-2024-2286
 The Sky Addons for Elementor (Free Templates Library, Live Copy, Animations, Post Grid, Post Carousel, Particles, Sliders, Chart) plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the wrapper link URL value in all versions up to, and including, 2.4.0 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers with contributor-level and above permissions to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/brandon-t-elliott/CVE-2024-22867](https://github.com/brandon-t-elliott/CVE-2024-22867) :  ![starts](https://img.shields.io/github/stars/brandon-t-elliott/CVE-2024-22867.svg) ![forks](https://img.shields.io/github/forks/brandon-t-elliott/CVE-2024-22867.svg)


## CVE-2024-2267
 A vulnerability was found in keerti1924 Online-Book-Store-Website 1.0 and classified as problematic. This issue affects some unknown processing of the file /shop.php. The manipulation of the argument product_price leads to business logic errors. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-256037 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/l00neyhacker/CVE-2024-22676](https://github.com/l00neyhacker/CVE-2024-22676) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-22676.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-22676.svg)
- [https://github.com/l00neyhacker/CVE-2024-22675](https://github.com/l00neyhacker/CVE-2024-22675) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-22675.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-22675.svg)
- [https://github.com/l00neyhacker/CVE-2024-22678](https://github.com/l00neyhacker/CVE-2024-22678) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-22678.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-22678.svg)


## CVE-2024-2253
 The Testimonial Carousel For Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via URL values the plugin's carousel widgets in all versions up to, and including, 10.2.1 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers with contributor-level and above permissions to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/austino2000/CVE-2024-22534](https://github.com/austino2000/CVE-2024-22534) :  ![starts](https://img.shields.io/github/stars/austino2000/CVE-2024-22534.svg) ![forks](https://img.shields.io/github/forks/austino2000/CVE-2024-22534.svg)


## CVE-2023-36163
 Cross Site Scripting vulnerability in IP-DOT BuildaGate v.BuildaGate5 allows a remote attacker to execute arbitrary code via a crafted script to the mc parameter of the URL.

- [https://github.com/TraiLeR2/CVE-2023-36163](https://github.com/TraiLeR2/CVE-2023-36163) :  ![starts](https://img.shields.io/github/stars/TraiLeR2/CVE-2023-36163.svg) ![forks](https://img.shields.io/github/forks/TraiLeR2/CVE-2023-36163.svg)


## CVE-2023-24709
 An issue found in Paradox Security Systems IPR512 allows attackers to cause a denial of service via the login.html and login.xml parameters.

- [https://github.com/DRAGOWN/CVE-2023-24709-PoC](https://github.com/DRAGOWN/CVE-2023-24709-PoC) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2023-24709-PoC.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2023-24709-PoC.svg)


## CVE-2023-5270
 A vulnerability was found in SourceCodester Best Courier Management System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file view_parcel.php. The manipulation of the argument id leads to sql injection. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-240883.

- [https://github.com/KevinMitchell-OSWP-CISSP/CVE-2023-52709-PoC](https://github.com/KevinMitchell-OSWP-CISSP/CVE-2023-52709-PoC) :  ![starts](https://img.shields.io/github/stars/KevinMitchell-OSWP-CISSP/CVE-2023-52709-PoC.svg) ![forks](https://img.shields.io/github/forks/KevinMitchell-OSWP-CISSP/CVE-2023-52709-PoC.svg)


## CVE-2023-5121
 The Migration, Backup, Staging – WPvivid plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings (the backup path parameter) in versions up to, and including, 0.9.89 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/chandraprarikraj/CVE-2023-51214](https://github.com/chandraprarikraj/CVE-2023-51214) :  ![starts](https://img.shields.io/github/stars/chandraprarikraj/CVE-2023-51214.svg) ![forks](https://img.shields.io/github/forks/chandraprarikraj/CVE-2023-51214.svg)


## CVE-2023-5111
potentially leading to unauthorized execution of scripts within a user's web browser.

- [https://github.com/OscarAkaElvis/CVE-2023-51119](https://github.com/OscarAkaElvis/CVE-2023-51119) :  ![starts](https://img.shields.io/github/stars/OscarAkaElvis/CVE-2023-51119.svg) ![forks](https://img.shields.io/github/forks/OscarAkaElvis/CVE-2023-51119.svg)


## CVE-2023-5100
that is not encrypted.

- [https://github.com/Team-Byerus/CVE-2023-51000](https://github.com/Team-Byerus/CVE-2023-51000) :  ![starts](https://img.shields.io/github/stars/Team-Byerus/CVE-2023-51000.svg) ![forks](https://img.shields.io/github/forks/Team-Byerus/CVE-2023-51000.svg)


## CVE-2023-5059
Santesoft Sante FFT Imaging lacks proper validation of user-supplied data when parsing DICOM files. This could lead to an out-of-bounds read. An attacker could leverage this vulnerability to execute arbitrary code in the context of the current process.

- [https://github.com/chandraprarikraj/CVE-2023-50596](https://github.com/chandraprarikraj/CVE-2023-50596) :  ![starts](https://img.shields.io/github/stars/chandraprarikraj/CVE-2023-50596.svg) ![forks](https://img.shields.io/github/forks/chandraprarikraj/CVE-2023-50596.svg)


## CVE-2023-5013
 A vulnerability has been found in Pluck CMS 4.7.18 and classified as problematic. This vulnerability affects unknown code of the file install.php of the component Installation Handler. The manipulation of the argument contents with the input scriptalert('xss')/script leads to cross site scripting. The attack can be initiated remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. VDB-239854 is the identifier assigned to this vulnerability.

- [https://github.com/sajaljat/CVE-2023-50131](https://github.com/sajaljat/CVE-2023-50131) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2023-50131.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2023-50131.svg)
- [https://github.com/sajaljat/CVE-2023-50132](https://github.com/sajaljat/CVE-2023-50132) :  ![starts](https://img.shields.io/github/stars/sajaljat/CVE-2023-50132.svg) ![forks](https://img.shields.io/github/forks/sajaljat/CVE-2023-50132.svg)


## CVE-2023-4949
 An attacker with local access to a system (either through a disk or external drive) can present a modified XFS partition to grub-legacy in such a way to exploit a memory corruption in grub’s XFS file system implementation.

- [https://github.com/HuangYanQwQ/CVE-2023-49496](https://github.com/HuangYanQwQ/CVE-2023-49496) :  ![starts](https://img.shields.io/github/stars/HuangYanQwQ/CVE-2023-49496.svg) ![forks](https://img.shields.io/github/forks/HuangYanQwQ/CVE-2023-49496.svg)


## CVE-2023-4898
 Authentication Bypass by Primary Weakness in GitHub repository mintplex-labs/anything-llm prior to 0.0.1.

- [https://github.com/tristao-marinho/CVE-2023-48983](https://github.com/tristao-marinho/CVE-2023-48983) :  ![starts](https://img.shields.io/github/stars/tristao-marinho/CVE-2023-48983.svg) ![forks](https://img.shields.io/github/forks/tristao-marinho/CVE-2023-48983.svg)
- [https://github.com/l00neyhacker/CVE-2023-48984](https://github.com/l00neyhacker/CVE-2023-48984) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-48984.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-48984.svg)
- [https://github.com/tristao-marinho/CVE-2023-48982](https://github.com/tristao-marinho/CVE-2023-48982) :  ![starts](https://img.shields.io/github/stars/tristao-marinho/CVE-2023-48982.svg) ![forks](https://img.shields.io/github/forks/tristao-marinho/CVE-2023-48982.svg)
- [https://github.com/tristao-marinho/CVE-2023-48981](https://github.com/tristao-marinho/CVE-2023-48981) :  ![starts](https://img.shields.io/github/stars/tristao-marinho/CVE-2023-48981.svg) ![forks](https://img.shields.io/github/forks/tristao-marinho/CVE-2023-48981.svg)


## CVE-2023-4740
 A vulnerability, which was classified as critical, was found in IBOS OA 4.5.5. This affects an unknown part of the file ?r=email/api/delDraft&archiveId=0 of the component Delete Draft Handler. The manipulation leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-238629 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/LucasVanHaaren/CVE-2023-47400](https://github.com/LucasVanHaaren/CVE-2023-47400) :  ![starts](https://img.shields.io/github/stars/LucasVanHaaren/CVE-2023-47400.svg) ![forks](https://img.shields.io/github/forks/LucasVanHaaren/CVE-2023-47400.svg)


## CVE-2023-4241
 lol-html can cause panics on certain HTML inputs. Anyone processing arbitrary 3rd party HTML with the library is affected.

- [https://github.com/chenghao-hao/cve-2023-42413](https://github.com/chenghao-hao/cve-2023-42413) :  ![starts](https://img.shields.io/github/stars/chenghao-hao/cve-2023-42413.svg) ![forks](https://img.shields.io/github/forks/chenghao-hao/cve-2023-42413.svg)


## CVE-2023-4153
 The BAN Users plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 1.5.3 due to a missing capability check on the 'w3dev_save_ban_user_settings_callback' function. This makes it possible for authenticated attackers, with minimal permissions such as a subscriber, to modify the plugin settings to access the ban and unban functionality and set the role of the unbanned user.

- [https://github.com/Sh33talUmath/CVE-2023-41534](https://github.com/Sh33talUmath/CVE-2023-41534) :  ![starts](https://img.shields.io/github/stars/Sh33talUmath/CVE-2023-41534.svg) ![forks](https://img.shields.io/github/forks/Sh33talUmath/CVE-2023-41534.svg)
- [https://github.com/Sh33talUmath/CVE-2023-41533](https://github.com/Sh33talUmath/CVE-2023-41533) :  ![starts](https://img.shields.io/github/stars/Sh33talUmath/CVE-2023-41533.svg) ![forks](https://img.shields.io/github/forks/Sh33talUmath/CVE-2023-41533.svg)
- [https://github.com/Sh33talUmath/CVE-2023-41535](https://github.com/Sh33talUmath/CVE-2023-41535) :  ![starts](https://img.shields.io/github/stars/Sh33talUmath/CVE-2023-41535.svg) ![forks](https://img.shields.io/github/forks/Sh33talUmath/CVE-2023-41535.svg)


## CVE-2023-4150
 The User Activity Tracking and Log WordPress plugin before 4.0.9 does not have proper CSRF checks when managing its license, which could allow attackers to make logged in admins update and deactivate the plugin's license via CSRF attacks

- [https://github.com/ASR511-OO7/CVE-2023-41500](https://github.com/ASR511-OO7/CVE-2023-41500) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2023-41500.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2023-41500.svg)
- [https://github.com/ASR511-OO7/CVE-2023-41501](https://github.com/ASR511-OO7/CVE-2023-41501) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2023-41501.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2023-41501.svg)


## CVE-2023-4149
 A vulnerability in the web-based management allows an unauthenticated remote attacker to inject arbitrary system commands and gain full system control. Those commands are executed with root privileges. The vulnerability is located in the user request handling of the web-based management.

- [https://github.com/ASR511-OO7/CVE-2023-41498](https://github.com/ASR511-OO7/CVE-2023-41498) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2023-41498.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2023-41498.svg)
- [https://github.com/ASR511-OO7/CVE-2023-41499](https://github.com/ASR511-OO7/CVE-2023-41499) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2023-41499.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2023-41499.svg)
- [https://github.com/ASR511-OO7/CVE-2023-41497](https://github.com/ASR511-OO7/CVE-2023-41497) :  ![starts](https://img.shields.io/github/stars/ASR511-OO7/CVE-2023-41497.svg) ![forks](https://img.shields.io/github/forks/ASR511-OO7/CVE-2023-41497.svg)


## CVE-2023-3972
 A vulnerability was found in insights-client. This security issue occurs because of insecure file operations or unsafe handling of temporary files and directories that lead to local privilege escalation. Before the insights-client has been registered on the system by root, an unprivileged local user or attacker could create the /var/tmp/insights-client directory (owning the directory with read, write, and execute permissions) on the system. After the insights-client is registered by root, an attacker could then control the directory content that insights are using by putting malicious scripts into it and executing arbitrary code as root (trivially bypassing SELinux protections because insights processes are allowed to disable SELinux system-wide).

- [https://github.com/anky-123/CVE-2023-39725](https://github.com/anky-123/CVE-2023-39725) :  ![starts](https://img.shields.io/github/stars/anky-123/CVE-2023-39725.svg) ![forks](https://img.shields.io/github/forks/anky-123/CVE-2023-39725.svg)


## CVE-2023-3882
 A vulnerability, which was classified as critical, has been found in Campcodes Beauty Salon Management System 1.0. Affected by this issue is some unknown functionality of the file /admin/edit-accepted-appointment.php. The manipulation of the argument contactno leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-235244.

- [https://github.com/TraiLeR2/Corsair---DLL-Planting-CVE-2023-38822](https://github.com/TraiLeR2/Corsair---DLL-Planting-CVE-2023-38822) :  ![starts](https://img.shields.io/github/stars/TraiLeR2/Corsair---DLL-Planting-CVE-2023-38822.svg) ![forks](https://img.shields.io/github/forks/TraiLeR2/Corsair---DLL-Planting-CVE-2023-38822.svg)
- [https://github.com/TraiLeR2/CoD-MW-Warzone-2---CVE-2023-38821](https://github.com/TraiLeR2/CoD-MW-Warzone-2---CVE-2023-38821) :  ![starts](https://img.shields.io/github/stars/TraiLeR2/CoD-MW-Warzone-2---CVE-2023-38821.svg) ![forks](https://img.shields.io/github/forks/TraiLeR2/CoD-MW-Warzone-2---CVE-2023-38821.svg)
- [https://github.com/TraiLeR2/DLL-Planting-Slack-4.33.73-CVE-2023-38820](https://github.com/TraiLeR2/DLL-Planting-Slack-4.33.73-CVE-2023-38820) :  ![starts](https://img.shields.io/github/stars/TraiLeR2/DLL-Planting-Slack-4.33.73-CVE-2023-38820.svg) ![forks](https://img.shields.io/github/forks/TraiLeR2/DLL-Planting-Slack-4.33.73-CVE-2023-38820.svg)


## CVE-2023-3777
We recommend upgrading past commit 6eaf41e87a223ae6f8e7a28d6e78384ad7e407f8.

- [https://github.com/jyoti818680/CVE-2023-37778](https://github.com/jyoti818680/CVE-2023-37778) :  ![starts](https://img.shields.io/github/stars/jyoti818680/CVE-2023-37778.svg) ![forks](https://img.shields.io/github/forks/jyoti818680/CVE-2023-37778.svg)
- [https://github.com/jyoti818680/CVE-2023-37779](https://github.com/jyoti818680/CVE-2023-37779) :  ![starts](https://img.shields.io/github/stars/jyoti818680/CVE-2023-37779.svg) ![forks](https://img.shields.io/github/forks/jyoti818680/CVE-2023-37779.svg)


## CVE-2023-3707
 The ActivityPub WordPress plugin before 1.0.0 does not ensure that post contents to be displayed are public and belong to the plugin, allowing any authenticated user, such as subscriber to retrieve the content of arbitrary post (such as draft and private) via an IDOR vector. Password protected posts are not affected by this issue.

- [https://github.com/Hamza0X/CVE-2023-37073](https://github.com/Hamza0X/CVE-2023-37073) :  ![starts](https://img.shields.io/github/stars/Hamza0X/CVE-2023-37073.svg) ![forks](https://img.shields.io/github/forks/Hamza0X/CVE-2023-37073.svg)


## CVE-2023-3458
 A vulnerability was found in SourceCodester Shopping Website 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file forgot-password.php. The manipulation of the argument contact leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-232675.

- [https://github.com/fu2x2000/-CVE-2023-34584](https://github.com/fu2x2000/-CVE-2023-34584) :  ![starts](https://img.shields.io/github/stars/fu2x2000/-CVE-2023-34584.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/-CVE-2023-34584.svg)


## CVE-2023-3171
 A flaw was found in EAP-7 during deserialization of certain classes, which permits instantiation of HashMap and HashTable with no checks on resources consumed. This issue could allow an attacker to submit malicious requests using these classes, which could eventually exhaust the heap and result in a Denial of Service.

- [https://github.com/HritikThapa7/CVE-2023-31711](https://github.com/HritikThapa7/CVE-2023-31711) :  ![starts](https://img.shields.io/github/stars/HritikThapa7/CVE-2023-31711.svg) ![forks](https://img.shields.io/github/forks/HritikThapa7/CVE-2023-31711.svg)


## CVE-2023-3144
 A vulnerability classified as problematic was found in SourceCodester Online Discussion Forum Site 1.0. Affected by this vulnerability is an unknown functionality of the file admin\posts\manage_post.php. The manipulation of the argument title leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-231013 was assigned to this vulnerability.

- [https://github.com/MaherAzzouzi/CVE-2023-31443](https://github.com/MaherAzzouzi/CVE-2023-31443) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2023-31443.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2023-31443.svg)


## CVE-2023-3107
 A set of carefully crafted ipv6 packets can trigger an integer overflow in the calculation of a fragment reassembled packet's payload length field. This allows an attacker to trigger a kernel panic, resulting in a denial of service.

- [https://github.com/bugprove/cve-2023-31070](https://github.com/bugprove/cve-2023-31070) :  ![starts](https://img.shields.io/github/stars/bugprove/cve-2023-31070.svg) ![forks](https://img.shields.io/github/forks/bugprove/cve-2023-31070.svg)


## CVE-2023-3019
 A DMA reentrancy issue leading to a use-after-free error was found in the e1000e NIC emulation code in QEMU. This issue could allow a privileged guest user to crash the QEMU process on the host, resulting in a denial of service.

- [https://github.com/MojithaR/CVE-2023-30190-FOLLINA](https://github.com/MojithaR/CVE-2023-30190-FOLLINA) :  ![starts](https://img.shields.io/github/stars/MojithaR/CVE-2023-30190-FOLLINA.svg) ![forks](https://img.shields.io/github/forks/MojithaR/CVE-2023-30190-FOLLINA.svg)


## CVE-2023-3003
 A vulnerability classified as critical was found in SourceCodester Train Station Ticketing System 1.0. Affected by this vulnerability is an unknown functionality of the file manage_prices.php of the component GET Parameter Handler. The manipulation of the argument id leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-230347.

- [https://github.com/phucodeexp/CVE-2023-30033](https://github.com/phucodeexp/CVE-2023-30033) :  ![starts](https://img.shields.io/github/stars/phucodeexp/CVE-2023-30033.svg) ![forks](https://img.shields.io/github/forks/phucodeexp/CVE-2023-30033.svg)


## CVE-2023-2561
 The Gallery Metabox for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the gallery_remove function in versions up to, and including, 1.5. This makes it possible for subscriber-level attackers to modify galleries attached to posts and pages with this plugin.

- [https://github.com/qi4L/CVE-2023-25610](https://github.com/qi4L/CVE-2023-25610) :  ![starts](https://img.shields.io/github/stars/qi4L/CVE-2023-25610.svg) ![forks](https://img.shields.io/github/forks/qi4L/CVE-2023-25610.svg)


## CVE-2023-2520
 A vulnerability was found in Caton Prime 2.1.2.51.e8d7225049(202303031001) and classified as critical. This issue affects some unknown processing of the file cgi-bin/tools_ping.cgi?action=Command of the component Ping Handler. The manipulation of the argument Destination leads to command injection. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-228011. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Trackflaw/CVE-2023-25202](https://github.com/Trackflaw/CVE-2023-25202) :  ![starts](https://img.shields.io/github/stars/Trackflaw/CVE-2023-25202.svg) ![forks](https://img.shields.io/github/forks/Trackflaw/CVE-2023-25202.svg)
- [https://github.com/Trackflaw/CVE-2023-25203](https://github.com/Trackflaw/CVE-2023-25203) :  ![starts](https://img.shields.io/github/stars/Trackflaw/CVE-2023-25203.svg) ![forks](https://img.shields.io/github/forks/Trackflaw/CVE-2023-25203.svg)


## CVE-2023-2470
 The Add to Feedly WordPress plugin through 1.2.11 does not sanitize and escape its settings, allowing high-privilege users such as admin to perform Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/hatjwe/CVE-2023-24706](https://github.com/hatjwe/CVE-2023-24706) :  ![starts](https://img.shields.io/github/stars/hatjwe/CVE-2023-24706.svg) ![forks](https://img.shields.io/github/forks/hatjwe/CVE-2023-24706.svg)


## CVE-2023-2410
 A vulnerability has been found in SourceCodester AC Repair and Services System 1.0 and classified as critical. This vulnerability affects unknown code of the file /admin/bookings/view_booking.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-227704.

- [https://github.com/badboycxcc/CVE-2023-24100](https://github.com/badboycxcc/CVE-2023-24100) :  ![starts](https://img.shields.io/github/stars/badboycxcc/CVE-2023-24100.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/CVE-2023-24100.svg)


## CVE-2023-2313
 Inappropriate implementation in Sandbox in Google Chrome on Windows prior to 112.0.5615.49 allowed a remote attacker who had compromised the renderer process to perform arbitrary read/write via a malicious file. (Chromium security severity: High)

- [https://github.com/OmarAtallahh/CVE-2023-23138](https://github.com/OmarAtallahh/CVE-2023-23138) :  ![starts](https://img.shields.io/github/stars/OmarAtallahh/CVE-2023-23138.svg) ![forks](https://img.shields.io/github/forks/OmarAtallahh/CVE-2023-23138.svg)


## CVE-2022-28108
 Selenium Server (Grid) before 4 allows CSRF because it permits non-JSON content types such as application/x-www-form-urlencoded, multipart/form-data, and text/plain.

- [https://github.com/ZeroEthical/CVE-2022-28108](https://github.com/ZeroEthical/CVE-2022-28108) :  ![starts](https://img.shields.io/github/stars/ZeroEthical/CVE-2022-28108.svg) ![forks](https://img.shields.io/github/forks/ZeroEthical/CVE-2022-28108.svg)


## CVE-2022-4663
 The Members Import plugin for WordPress is vulnerable to Self Cross-Site Scripting via the user_login parameter in an imported CSV file in versions up to, and including, 1.4.2 due to insufficient input sanitization and output escaping. This makes it possible for attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a site's administrator into uploading a CSV file with the malicious payload.

- [https://github.com/naonymous101/CVE-2022-46638](https://github.com/naonymous101/CVE-2022-46638) :  ![starts](https://img.shields.io/github/stars/naonymous101/CVE-2022-46638.svg) ![forks](https://img.shields.io/github/forks/naonymous101/CVE-2022-46638.svg)


## CVE-2022-4610
 A vulnerability, which was classified as problematic, has been found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome. Affected by this issue is some unknown functionality. The manipulation leads to risky cryptographic algorithm. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-216272.

- [https://github.com/NurSec747/CVE-2022-46104---POC](https://github.com/NurSec747/CVE-2022-46104---POC) :  ![starts](https://img.shields.io/github/stars/NurSec747/CVE-2022-46104---POC.svg) ![forks](https://img.shields.io/github/forks/NurSec747/CVE-2022-46104---POC.svg)


## CVE-2022-4526
 A vulnerability was found in django-photologue up to 3.15.1 and classified as problematic. Affected by this issue is some unknown functionality of the file photologue/templates/photologue/photo_detail.html of the component Default Template Handler. The manipulation of the argument object.caption leads to cross site scripting. The attack may be launched remotely. Upgrading to version 3.16 is able to address this issue. The name of the patch is 960cb060ce5e2964e6d716ff787c72fc18a371e7. It is recommended to apply a patch to fix this issue. VDB-215906 is the identifier assigned to this vulnerability.

- [https://github.com/maikroservice/CVE-2022-45265](https://github.com/maikroservice/CVE-2022-45265) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2022-45265.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2022-45265.svg)


## CVE-2022-4091
 A vulnerability was found in SourceCodester Canteen Management System. It has been classified as problematic. This affects the function query of the file food.php. The manipulation of the argument product_name leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214359.

- [https://github.com/whitej3rry/CVE-2022-40916](https://github.com/whitej3rry/CVE-2022-40916) :  ![starts](https://img.shields.io/github/stars/whitej3rry/CVE-2022-40916.svg) ![forks](https://img.shields.io/github/forks/whitej3rry/CVE-2022-40916.svg)


## CVE-2022-4049
 The WP User WordPress plugin through 7.0 does not properly sanitize and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users.

- [https://github.com/whitej3rry/CVE-2022-40490](https://github.com/whitej3rry/CVE-2022-40490) :  ![starts](https://img.shields.io/github/stars/whitej3rry/CVE-2022-40490.svg) ![forks](https://img.shields.io/github/forks/whitej3rry/CVE-2022-40490.svg)


## CVE-2022-3984
 The Flowplayer Video Player WordPress plugin before 1.0.5 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks

- [https://github.com/stealthcopter/CVE-2022-39841](https://github.com/stealthcopter/CVE-2022-39841) :  ![starts](https://img.shields.io/github/stars/stealthcopter/CVE-2022-39841.svg) ![forks](https://img.shields.io/github/forks/stealthcopter/CVE-2022-39841.svg)


## CVE-2022-3869
 Code Injection in GitHub repository froxlor/froxlor prior to 0.10.38.2.

- [https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader) :  ![starts](https://img.shields.io/github/stars/TomKing062/CVE-2022-38694_unlock_bootloader.svg) ![forks](https://img.shields.io/github/forks/TomKing062/CVE-2022-38694_unlock_bootloader.svg)
- [https://github.com/TomKing062/CVE-2022-38691_38692](https://github.com/TomKing062/CVE-2022-38691_38692) :  ![starts](https://img.shields.io/github/stars/TomKing062/CVE-2022-38691_38692.svg) ![forks](https://img.shields.io/github/forks/TomKing062/CVE-2022-38691_38692.svg)


## CVE-2022-3860
 The Visual Email Designer for WooCommerce WordPress plugin before 1.7.2 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by users with a role as low as author.

- [https://github.com/jet-pentest/CVE-2022-38601](https://github.com/jet-pentest/CVE-2022-38601) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2022-38601.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2022-38601.svg)


## CVE-2022-3721
 Code Injection in GitHub repository froxlor/froxlor prior to 0.10.39.

- [https://github.com/AgainstTheLight/CVE-2022-37210](https://github.com/AgainstTheLight/CVE-2022-37210) :  ![starts](https://img.shields.io/github/stars/AgainstTheLight/CVE-2022-37210.svg) ![forks](https://img.shields.io/github/forks/AgainstTheLight/CVE-2022-37210.svg)


## CVE-2022-3720
 The Event Monster WordPress plugin before 1.2.0 does not validate and escape some parameters before using them in SQL statements, which could lead to SQL Injection exploitable by high privilege users

- [https://github.com/AgainstTheLight/CVE-2022-37206](https://github.com/AgainstTheLight/CVE-2022-37206) :  ![starts](https://img.shields.io/github/stars/AgainstTheLight/CVE-2022-37206.svg) ![forks](https://img.shields.io/github/forks/AgainstTheLight/CVE-2022-37206.svg)


## CVE-2022-3616
 Attackers can create long chains of CAs that would lead to OctoRPKI exceeding its max iterations parameter. In consequence it would cause the program to crash, preventing it from finishing the validation and leading to a denial of service. Credits to Donika Mirdita and Haya Shulman - Fraunhofer SIT, ATHENE, who discovered and reported this vulnerability.

- [https://github.com/MaherAzzouzi/CVE-2022-36162](https://github.com/MaherAzzouzi/CVE-2022-36162) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-36162.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-36162.svg)
- [https://github.com/MaherAzzouzi/CVE-2022-36163](https://github.com/MaherAzzouzi/CVE-2022-36163) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-36163.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-36163.svg)


## CVE-2022-3213
 A heap buffer overflow issue was found in ImageMagick. When an application processes a malformed TIFF file, it could lead to undefined behavior or a crash causing a denial of service.

- [https://github.com/reewardius/CVE-2022-32132](https://github.com/reewardius/CVE-2022-32132) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2022-32132.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2022-32132.svg)


## CVE-2022-3174
 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository ikus060/rdiffweb prior to 2.4.2.

- [https://github.com/iveresk/cve-2022-31749](https://github.com/iveresk/cve-2022-31749) :  ![starts](https://img.shields.io/github/stars/iveresk/cve-2022-31749.svg) ![forks](https://img.shields.io/github/forks/iveresk/cve-2022-31749.svg)


## CVE-2022-3129
 A vulnerability was found in codeprojects Online Driving School. It has been rated as critical. Affected by this issue is some unknown functionality of the file /registration.php. The manipulation leads to unrestricted upload. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-207872.

- [https://github.com/bigzooooz/CVE-2022-31297](https://github.com/bigzooooz/CVE-2022-31297) :  ![starts](https://img.shields.io/github/stars/bigzooooz/CVE-2022-31297.svg) ![forks](https://img.shields.io/github/forks/bigzooooz/CVE-2022-31297.svg)


## CVE-2022-3050
 Heap buffer overflow in WebUI in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted UI interactions.

- [https://github.com/yosef0x01/CVE-2022-30507-PoC](https://github.com/yosef0x01/CVE-2022-30507-PoC) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2022-30507-PoC.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2022-30507-PoC.svg)


## CVE-2022-3000
 Cross-site Scripting (XSS) - Stored in GitHub repository yetiforcecompany/yetiforcecrm prior to 6.4.0.

- [https://github.com/ComparedArray/printix-CVE-2022-30006](https://github.com/ComparedArray/printix-CVE-2022-30006) :  ![starts](https://img.shields.io/github/stars/ComparedArray/printix-CVE-2022-30006.svg) ![forks](https://img.shields.io/github/forks/ComparedArray/printix-CVE-2022-30006.svg)


## CVE-2022-2946
 Use After Free in GitHub repository vim/vim prior to 9.0.0246.

- [https://github.com/S4muraiMelayu1337/CVE-2022-29469](https://github.com/S4muraiMelayu1337/CVE-2022-29469) :  ![starts](https://img.shields.io/github/stars/S4muraiMelayu1337/CVE-2022-29469.svg) ![forks](https://img.shields.io/github/forks/S4muraiMelayu1337/CVE-2022-29469.svg)


## CVE-2022-2894
 Measuresoft ScadaPro Server (All Versions) uses unmaintained ActiveX controls. The controls may allow seven untrusted pointer deference instances while processing a specific project file.

- [https://github.com/zhefox/CVE-2022-28943](https://github.com/zhefox/CVE-2022-28943) :  ![starts](https://img.shields.io/github/stars/zhefox/CVE-2022-28943.svg) ![forks](https://img.shields.io/github/forks/zhefox/CVE-2022-28943.svg)


## CVE-2022-2741
 The denial-of-service can be triggered by transmitting a carefully crafted CAN frame on the same CAN network as the vulnerable node. The frame must have a CAN ID matching an installed filter in the vulnerable node (this can easily be guessed based on CAN traffic analyses). The frame must contain the opposite RTR bit as what the filter installed in the vulnerable node contains (if the filter matches RTR frames, the frame must be a data frame or vice versa).

- [https://github.com/lus33rr/CVE-2022-27414](https://github.com/lus33rr/CVE-2022-27414) :  ![starts](https://img.shields.io/github/stars/lus33rr/CVE-2022-27414.svg) ![forks](https://img.shields.io/github/forks/lus33rr/CVE-2022-27414.svg)


## CVE-2022-2725
 A vulnerability was found in SourceCodester Company Website CMS. It has been rated as problematic. Affected by this issue is some unknown functionality of the file add-blog.php. The manipulation leads to cross site scripting. The attack may be launched remotely. VDB-205838 is the identifier assigned to this vulnerability.

- [https://github.com/TheCyberGeek/CVE-2022-27251](https://github.com/TheCyberGeek/CVE-2022-27251) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2022-27251.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2022-27251.svg)


## CVE-2022-2525
 Improper Restriction of Excessive Authentication Attempts in GitHub repository janeczku/calibre-web prior to 0.6.20.

- [https://github.com/polling-repo-continua/CVE-2022-25257](https://github.com/polling-repo-continua/CVE-2022-25257) :  ![starts](https://img.shields.io/github/stars/polling-repo-continua/CVE-2022-25257.svg) ![forks](https://img.shields.io/github/forks/polling-repo-continua/CVE-2022-25257.svg)
- [https://github.com/RobertDra/CVE-2022-25257](https://github.com/RobertDra/CVE-2022-25257) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25257.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25257.svg)


## CVE-2022-2408
 The Guest account feature in Mattermost version 6.7.0 and earlier fails to properly restrict the permissions, which allows a guest user to fetch a list of all public channels in the team, in spite of not being part of those channels.

- [https://github.com/Neimar47574/CVE-2022-24087](https://github.com/Neimar47574/CVE-2022-24087) :  ![starts](https://img.shields.io/github/stars/Neimar47574/CVE-2022-24087.svg) ![forks](https://img.shields.io/github/forks/Neimar47574/CVE-2022-24087.svg)


## CVE-2022-2336
 Softing Secure Integration Server, edgeConnector, and edgeAggregator software ships with the default administrator credentials as `admin` and password as `admin`. This allows Softing to log in to the server directly to perform administrative functions. Upon installation or upon first login, the application does not ask the user to change the `admin` password. There is no warning or prompt to ask the user to change the default password, and to change the password, many steps are required.

- [https://github.com/ViNi0608/CVE-2022-23361](https://github.com/ViNi0608/CVE-2022-23361) :  ![starts](https://img.shields.io/github/stars/ViNi0608/CVE-2022-23361.svg) ![forks](https://img.shields.io/github/forks/ViNi0608/CVE-2022-23361.svg)


## CVE-2021-40845
 The web part of Zenitel AlphaCom XE Audio Server through 11.2.3.10, called AlphaWeb XE, does not restrict file upload in the Custom Scripts section at php/index.php. Neither the content nor extension of the uploaded files is checked, allowing execution of PHP code under the /cmd directory.

- [https://github.com/ricardojoserf/CVE-2021-40845](https://github.com/ricardojoserf/CVE-2021-40845) :  ![starts](https://img.shields.io/github/stars/ricardojoserf/CVE-2021-40845.svg) ![forks](https://img.shields.io/github/forks/ricardojoserf/CVE-2021-40845.svg)


## CVE-2021-4427
 The Vuukle Comments, Reactions, Share Bar, Revenue plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.4.31. This is due to missing or incorrect nonce validation in the /admin/partials/free-comments-for-wordpress-vuukle-admin-display.php file. This makes it possible for unauthenticated attackers to edit the plugins settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/pinpinsec/CVE-2021-44270](https://github.com/pinpinsec/CVE-2021-44270) :  ![starts](https://img.shields.io/github/stars/pinpinsec/CVE-2021-44270.svg) ![forks](https://img.shields.io/github/forks/pinpinsec/CVE-2021-44270.svg)


## CVE-2021-4182
 Crash in the RFC 7468 dissector in Wireshark 3.6.0 and 3.4.0 to 3.4.10 allows denial of service via packet injection or crafted capture file

- [https://github.com/badboycxcc/CVE-2021-41822](https://github.com/badboycxcc/CVE-2021-41822) :  ![starts](https://img.shields.io/github/stars/badboycxcc/CVE-2021-41822.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/CVE-2021-41822.svg)


## CVE-2021-4173
 vim is vulnerable to Use After Free

- [https://github.com/yezeting/CVE-2021-41730](https://github.com/yezeting/CVE-2021-41730) :  ![starts](https://img.shields.io/github/stars/yezeting/CVE-2021-41730.svg) ![forks](https://img.shields.io/github/forks/yezeting/CVE-2021-41730.svg)


## CVE-2021-4170
 calibre-web is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/Yanoro/CVE-2021-41703](https://github.com/Yanoro/CVE-2021-41703) :  ![starts](https://img.shields.io/github/stars/Yanoro/CVE-2021-41703.svg) ![forks](https://img.shields.io/github/forks/Yanoro/CVE-2021-41703.svg)


## CVE-2021-4107
 yetiforcecrm is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/dillonkirsch/CVE-2021-41074](https://github.com/dillonkirsch/CVE-2021-41074) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2021-41074.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2021-41074.svg)


## CVE-2021-3947
 A stack-buffer-overflow was found in QEMU in the NVME component. The flaw lies in nvme_changed_nslist() where a malicious guest controlling certain input can read out of bounds memory. A malicious user could use this flaw leading to disclosure of sensitive information.

- [https://github.com/W4RCL0UD/CVE-2021-39475](https://github.com/W4RCL0UD/CVE-2021-39475) :  ![starts](https://img.shields.io/github/stars/W4RCL0UD/CVE-2021-39475.svg) ![forks](https://img.shields.io/github/forks/W4RCL0UD/CVE-2021-39475.svg)
- [https://github.com/W4RCL0UD/CVE-2021-39476](https://github.com/W4RCL0UD/CVE-2021-39476) :  ![starts](https://img.shields.io/github/stars/W4RCL0UD/CVE-2021-39476.svg) ![forks](https://img.shields.io/github/forks/W4RCL0UD/CVE-2021-39476.svg)


## CVE-2021-3928
 vim is vulnerable to Use of Uninitialized Variable

- [https://github.com/Fearless523/CVE-2021-39287-Stored-XSS](https://github.com/Fearless523/CVE-2021-39287-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/Fearless523/CVE-2021-39287-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/Fearless523/CVE-2021-39287-Stored-XSS.svg)


## CVE-2021-3881
 libmobi is vulnerable to Out-of-bounds Read

- [https://github.com/HuskyHacks/CVE-2021-38817-Remote-OS-Command-Injection](https://github.com/HuskyHacks/CVE-2021-38817-Remote-OS-Command-Injection) :  ![starts](https://img.shields.io/github/stars/HuskyHacks/CVE-2021-38817-Remote-OS-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/HuskyHacks/CVE-2021-38817-Remote-OS-Command-Injection.svg)


## CVE-2021-3528
 A flaw was found in noobaa-operator in versions before 5.7.0, where internal RPC AuthTokens between the noobaa operator and the noobaa core are leaked into log files. An attacker with access to the log files could use this AuthToken to gain additional access into noobaa deployment and can read/modify system configuration.

- [https://github.com/l00neyhacker/CVE-2021-35287](https://github.com/l00neyhacker/CVE-2021-35287) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-35287.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-35287.svg)
- [https://github.com/l00neyhacker/CVE-2021-35286](https://github.com/l00neyhacker/CVE-2021-35286) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-35286.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-35286.svg)


## CVE-2021-3404
 In ytnef 1.9.3, the SwapWord function in lib/ytnef.c allows remote attackers to cause a denial-of-service (and potentially code execution) due to a heap buffer overflow which can be triggered via a crafted file.

- [https://github.com/Al1ex/CVE-2021-34045](https://github.com/Al1ex/CVE-2021-34045) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-34045.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-34045.svg)
- [https://github.com/kenuosec/CVE-2021-34045](https://github.com/kenuosec/CVE-2021-34045) :  ![starts](https://img.shields.io/github/stars/kenuosec/CVE-2021-34045.svg) ![forks](https://img.shields.io/github/forks/kenuosec/CVE-2021-34045.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/qaisarafridi/cve-2021-31290](https://github.com/qaisarafridi/cve-2021-31290) :  ![starts](https://img.shields.io/github/stars/qaisarafridi/cve-2021-31290.svg) ![forks](https://img.shields.io/github/forks/qaisarafridi/cve-2021-31290.svg)


## CVE-2020-2814
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.6.47 and prior, 5.7.28 and prior and 8.0.18 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/fengchenzxc/CVE-2020-28148](https://github.com/fengchenzxc/CVE-2020-28148) :  ![starts](https://img.shields.io/github/stars/fengchenzxc/CVE-2020-28148.svg) ![forks](https://img.shields.io/github/forks/fengchenzxc/CVE-2020-28148.svg)


## CVE-2020-2719
 Vulnerability in the Oracle Banking Corporate Lending product of Oracle Financial Services Applications (component: Core). Supported versions that are affected are 12.3.0-12.4.0 and 14.0.0-14.3.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Banking Corporate Lending. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle Banking Corporate Lending accessible data. CVSS 3.0 Base Score 4.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/qlh831/x-CVE-2020-27190](https://github.com/qlh831/x-CVE-2020-27190) :  ![starts](https://img.shields.io/github/stars/qlh831/x-CVE-2020-27190.svg) ![forks](https://img.shields.io/github/forks/qlh831/x-CVE-2020-27190.svg)


## CVE-2020-2576
 Vulnerability in the Oracle Outside In Technology product of Oracle Fusion Middleware (component: Outside In Filters). The supported version that is affected is 8.5.4. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Outside In Technology. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Outside In Technology accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Outside In Technology. Note: Outside In Technology is a suite of software development kits (SDKs). The protocol and CVSS score depend on the software that uses the Outside In Technology code. The CVSS score assumes that the software passes data received over a network directly to Outside In Technology code, but if data is not received over a network the CVSS score may be lower. CVSS 3.0 Base Score 6.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L).

- [https://github.com/defrancescojp/CVE-2020-25769](https://github.com/defrancescojp/CVE-2020-25769) :  ![starts](https://img.shields.io/github/stars/defrancescojp/CVE-2020-25769.svg) ![forks](https://img.shields.io/github/forks/defrancescojp/CVE-2020-25769.svg)


## CVE-2020-2548
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). The supported version that is affected is 10.3.6.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data as well as unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/Ko-kn3t/CVE-2020-25488](https://github.com/Ko-kn3t/CVE-2020-25488) :  ![starts](https://img.shields.io/github/stars/Ko-kn3t/CVE-2020-25488.svg) ![forks](https://img.shields.io/github/forks/Ko-kn3t/CVE-2020-25488.svg)


## CVE-2020-2547
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data as well as unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack](https://github.com/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack) :  ![starts](https://img.shields.io/github/stars/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack.svg) ![forks](https://img.shields.io/github/forks/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/bash3rt3am/poc-cve](https://github.com/bash3rt3am/poc-cve) :  ![starts](https://img.shields.io/github/stars/bash3rt3am/poc-cve.svg) ![forks](https://img.shields.io/github/forks/bash3rt3am/poc-cve.svg)


## CVE-2020-1700
 A flaw was found in the way the Ceph RGW Beast front-end handles unexpected disconnects. An authenticated attacker can abuse this flaw by making multiple disconnect attempts resulting in a permanent leak of a socket connection by radosgw. This flaw could lead to a denial of service condition by pile up of CLOSE_WAIT sockets, eventually leading to the exhaustion of available resources, preventing legitimate users from connecting to the system.

- [https://github.com/jas502n/CVE-2020-17008](https://github.com/jas502n/CVE-2020-17008) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2020-17008.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2020-17008.svg)


## CVE-2020-1584
The security update addresses the vulnerability by ensuring the dnsrslvr.dll properly handles objects in memory.

- [https://github.com/faklad/CVE-2020-15848](https://github.com/faklad/CVE-2020-15848) :  ![starts](https://img.shields.io/github/stars/faklad/CVE-2020-15848.svg) ![forks](https://img.shields.io/github/forks/faklad/CVE-2020-15848.svg)


## CVE-2020-1539
The security update addresses the vulnerability by correcting how the Windows Backup Engine handles memory.

- [https://github.com/mkelepce/CVE-2020-15399](https://github.com/mkelepce/CVE-2020-15399) :  ![starts](https://img.shields.io/github/stars/mkelepce/CVE-2020-15399.svg) ![forks](https://img.shields.io/github/forks/mkelepce/CVE-2020-15399.svg)


## CVE-2020-1345
pThe security update addresses the vulnerability by helping to ensure that SharePoint Server properly sanitizes web requests./p

- [https://github.com/alt3kx/CVE-2020-13457](https://github.com/alt3kx/CVE-2020-13457) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2020-13457.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2020-13457.svg)


## CVE-2020-1179
 An information disclosure vulnerability exists when the Windows GDI component improperly discloses the contents of its memory, aka 'Windows GDI Information Disclosure Vulnerability'. This CVE ID is unique from CVE-2020-0963, CVE-2020-1141, CVE-2020-1145.

- [https://github.com/w4cky/CVE-2020-11794](https://github.com/w4cky/CVE-2020-11794) :  ![starts](https://img.shields.io/github/stars/w4cky/CVE-2020-11794.svg) ![forks](https://img.shields.io/github/forks/w4cky/CVE-2020-11794.svg)


## CVE-2019-11248
 The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. The go pprof endpoint is exposed over the Kubelet's healthz port. This debugging endpoint can potentially leak sensitive information such as internal Kubelet memory addresses and configuration, or for limited denial of service. Versions prior to 1.15.0, 1.14.4, 1.13.8, and 1.12.10 are affected. The issue is of medium severity, but not exposed by the default configuration.

- [https://github.com/bash3rt3am/poc-cve](https://github.com/bash3rt3am/poc-cve) :  ![starts](https://img.shields.io/github/stars/bash3rt3am/poc-cve.svg) ![forks](https://img.shields.io/github/forks/bash3rt3am/poc-cve.svg)


## CVE-2019-1987
 In onSetSampleX of SkSwizzler.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9. Android ID: A-118143775.

- [https://github.com/VDISEC/CVE-2019-19871-AuditGuide](https://github.com/VDISEC/CVE-2019-19871-AuditGuide) :  ![starts](https://img.shields.io/github/stars/VDISEC/CVE-2019-19871-AuditGuide.svg) ![forks](https://img.shields.io/github/forks/VDISEC/CVE-2019-19871-AuditGuide.svg)


## CVE-2019-1965
 A vulnerability in the Virtual Shell (VSH) session management for Cisco NX-OS Software could allow an authenticated, remote attacker to cause a VSH process to fail to delete upon termination. This can lead to a build-up of VSH processes that overtime can deplete system memory. When there is no system memory available, this can cause unexpected system behaviors and crashes. The vulnerability is due to the VSH process not being properly deleted when a remote management connection to the device is disconnected. An attacker could exploit this vulnerability by repeatedly performing a remote management connection to the device and terminating the connection in an unexpected manner. A successful exploit could allow the attacker to cause the VSH processes to fail to delete, which can lead to a system-wide denial of service (DoS) condition. The attacker must have valid user credentials to log in to the device using the remote management connection.

- [https://github.com/jra89/CVE-2019-19651](https://github.com/jra89/CVE-2019-19651) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19651.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19651.svg)
- [https://github.com/jra89/CVE-2019-19658](https://github.com/jra89/CVE-2019-19658) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19658.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19658.svg)
- [https://github.com/jra89/CVE-2019-19654](https://github.com/jra89/CVE-2019-19654) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19654.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19654.svg)
- [https://github.com/jra89/CVE-2019-19653](https://github.com/jra89/CVE-2019-19653) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19653.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19653.svg)
- [https://github.com/jra89/CVE-2019-19652](https://github.com/jra89/CVE-2019-19652) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19652.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19652.svg)


## CVE-2019-1963
 A vulnerability in the Simple Network Management Protocol (SNMP) input packet processor of Cisco FXOS Software and Cisco NX-OS Software could allow an authenticated, remote attacker to cause the SNMP application on an affected device to restart unexpectedly. The vulnerability is due to improper validation of Abstract Syntax Notation One (ASN.1)-encoded variables in SNMP packets. An attacker could exploit this vulnerability by sending a crafted SNMP packet to the SNMP daemon on the affected device. A successful exploit could allow the attacker to cause the SNMP application to restart multiple times, leading to a system-level restart and a denial of service (DoS) condition.

- [https://github.com/jra89/CVE-2019-19633](https://github.com/jra89/CVE-2019-19633) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19633.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19633.svg)


## CVE-2019-1951
 A vulnerability in the packet filtering features of Cisco SD-WAN Solution could allow an unauthenticated, remote attacker to bypass L3 and L4 traffic filters. The vulnerability is due to improper traffic filtering conditions on an affected device. An attacker could exploit this vulnerability by crafting a malicious TCP packet with specific characteristics and sending it to a target device. A successful exploit could allow the attacker to bypass the L3 and L4 traffic filters and inject an arbitrary packet in the network.

- [https://github.com/jra89/CVE-2019-19511](https://github.com/jra89/CVE-2019-19511) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19511.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19511.svg)


## CVE-2019-1936
 A vulnerability in the web-based management interface of Cisco Integrated Management Controller (IMC) Supervisor, Cisco UCS Director, and Cisco UCS Director Express for Big Data could allow an authenticated, remote attacker to execute arbitrary commands on the underlying Linux shell as the root user. Exploitation of this vulnerability requires privileged access to an affected device. The vulnerability is due to insufficient validation of user-supplied input by the web-based management interface. An attacker could exploit this vulnerability by logging in to the web-based management interface with administrator privileges and then sending a malicious request to a certain part of the interface.

- [https://github.com/TheCyberGeek/CVE-2019-19369](https://github.com/TheCyberGeek/CVE-2019-19369) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2019-19369.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2019-19369.svg)


## CVE-2019-1926
 Multiple vulnerabilities in Cisco Webex Network Recording Player for Microsoft Windows and Cisco Webex Player for Microsoft Windows could allow an attacker to execute arbitrary code on an affected system. The vulnerabilities exist because the affected software improperly validates Advanced Recording Format (ARF) and Webex Recording Format (WRF) files. An attacker could exploit these vulnerabilities by sending a user a malicious ARF or WRF file through a link or email attachment and persuading the user to open the file with the affected software on the local system. A successful exploit could allow the attacker to execute arbitrary code on the affected system with the privileges of the targeted user.

- [https://github.com/TheCyberGeek/CVE-2019-19268](https://github.com/TheCyberGeek/CVE-2019-19268) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2019-19268.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2019-19268.svg)


## CVE-2019-1279
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2019. Notes: none

- [https://github.com/PeterUpfold/CVE-2019-12796](https://github.com/PeterUpfold/CVE-2019-12796) :  ![starts](https://img.shields.io/github/stars/PeterUpfold/CVE-2019-12796.svg) ![forks](https://img.shields.io/github/forks/PeterUpfold/CVE-2019-12796.svg)


## CVE-2018-1634
 IBM Informix Dynamic Server Enterprise Edition 12.1 could allow a local user logged in with database administrator user to gain root privileges through a symbolic link vulnerability in infos.DBSERVERNAME. IBM X-Force ID: 144437.

- [https://github.com/mpgn/CVE-2018-16341](https://github.com/mpgn/CVE-2018-16341) :  ![starts](https://img.shields.io/github/stars/mpgn/CVE-2018-16341.svg) ![forks](https://img.shields.io/github/forks/mpgn/CVE-2018-16341.svg)
- [https://github.com/CN016/Nuxeo-CVE-2018-16341](https://github.com/CN016/Nuxeo-CVE-2018-16341) :  ![starts](https://img.shields.io/github/stars/CN016/Nuxeo-CVE-2018-16341.svg) ![forks](https://img.shields.io/github/forks/CN016/Nuxeo-CVE-2018-16341.svg)


## CVE-2018-1259
 Spring Data Commons, versions 1.13 prior to 1.13.12 and 2.0 prior to 2.0.7, used in combination with XMLBeam 1.4.14 or earlier versions, contains a property binder vulnerability caused by improper restriction of XML external entity references as underlying library XMLBeam does not restrict external reference expansion. An unauthenticated remote malicious user can supply specially crafted request parameters against Spring Data's projection-based request payload binding to access arbitrary files on the system.

- [https://github.com/alt3kx/CVE-2018-12597](https://github.com/alt3kx/CVE-2018-12597) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2018-12597.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2018-12597.svg)
- [https://github.com/alt3kx/CVE-2018-12598](https://github.com/alt3kx/CVE-2018-12598) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2018-12598.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2018-12598.svg)


## CVE-2018-1099
 DNS rebinding vulnerability found in etcd 3.3.1 and earlier. An attacker can control his DNS records to direct to localhost, and trick the browser into sending requests to localhost (or any other address).

- [https://github.com/nicolastsk/cve-2018-10993](https://github.com/nicolastsk/cve-2018-10993) :  ![starts](https://img.shields.io/github/stars/nicolastsk/cve-2018-10993.svg) ![forks](https://img.shields.io/github/forks/nicolastsk/cve-2018-10993.svg)


## CVE-2018-1071
 zsh through version 5.4.2 is vulnerable to a stack-based buffer overflow in the exec.c:hashcmd() function. A local attacker could exploit this to cause a denial of service.

- [https://github.com/alt3kx/CVE-2018-10715](https://github.com/alt3kx/CVE-2018-10715) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2018-10715.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2018-10715.svg)


## CVE-2018-1046
 pdns before version 4.1.2 is vulnerable to a buffer overflow in dnsreplay. In the dnsreplay tool provided with PowerDNS Authoritative, replaying a specially crafted PCAP file can trigger a stack-based buffer overflow, leading to a crash and potentially arbitrary code execution. This buffer overflow only occurs when the -ecs-stamp option of dnsreplay is used.

- [https://github.com/alt3kx/CVE-2018-10467](https://github.com/alt3kx/CVE-2018-10467) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2018-10467.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2018-10467.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882](https://github.com/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882.svg)


## CVE-2017-1624
 IBM QRadar 7.3 and 7.3.1 specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors. IBM X-Force ID: 133122.

- [https://github.com/AOCorsaire/CVE-2017-16245](https://github.com/AOCorsaire/CVE-2017-16245) :  ![starts](https://img.shields.io/github/stars/AOCorsaire/CVE-2017-16245.svg) ![forks](https://img.shields.io/github/forks/AOCorsaire/CVE-2017-16245.svg)


## CVE-2017-1608
 IBM Rational Quality Manager and IBM Rational Collaborative Lifecycle Management 5.0 through 5.0.2 and 6.0 through 6.0.5 are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 132928.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16087](https://github.com/ossf-cve-benchmark/CVE-2017-16087) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16087.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16087.svg)


## CVE-2017-1079
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017. Notes: none

- [https://github.com/n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE-2017-10797.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE-2017-10797.svg)


## CVE-2001-1473
 The SSH-1 protocol allows remote servers to conduct man-in-the-middle attacks and replay a client challenge response to a target server by creating a Session ID that matches the Session ID of the target, but which uses a public key pair that is weaker than the target's public key, which allows the attacker to compute the corresponding private key and use the target's Session ID with the compromised key pair to masquerade as the target.

- [https://github.com/bash3rt3am/poc-cve](https://github.com/bash3rt3am/poc-cve) :  ![starts](https://img.shields.io/github/stars/bash3rt3am/poc-cve.svg) ![forks](https://img.shields.io/github/forks/bash3rt3am/poc-cve.svg)

