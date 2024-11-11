# Update 2024-11-11
## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/Arc4he/CVE-2024-23334-PoC](https://github.com/Arc4he/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/Arc4he/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/Arc4he/CVE-2024-23334-PoC.svg)


## CVE-2024-5113
 A vulnerability was found in Campcodes Complete Web-Based School Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /view/student_profile1.php. The manipulation of the argument std_index leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-265103.

- [https://github.com/JAckLosingHeart/CVE-2024-51135](https://github.com/JAckLosingHeart/CVE-2024-51135) :  ![starts](https://img.shields.io/github/stars/JAckLosingHeart/CVE-2024-51135.svg) ![forks](https://img.shields.io/github/forks/JAckLosingHeart/CVE-2024-51135.svg)


## CVE-2024-5048
 A vulnerability classified as critical was found in code-projects Budget Management 1.0. Affected by this vulnerability is an unknown functionality of the file /index.php. The manipulation of the argument edit leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-264745 was assigned to this vulnerability.

- [https://github.com/RandomRobbieBF/CVE-2024-50488](https://github.com/RandomRobbieBF/CVE-2024-50488) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50488.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50488.svg)


## CVE-2024-5047
 A vulnerability classified as critical has been found in SourceCodester Student Management System 1.0. Affected is an unknown function of the file /student/controller.php. The manipulation of the argument photo leads to unrestricted upload. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-264744.

- [https://github.com/RandomRobbieBF/CVE-2024-50473](https://github.com/RandomRobbieBF/CVE-2024-50473) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50473.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50473.svg)


## CVE-2024-4968
 A vulnerability was found in SourceCodester Interactive Map with Marker 1.0. It has been rated as problematic. Affected by this issue is some unknown functionality of the file Marker Name of the component Add Marker. The manipulation leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-264536.

- [https://github.com/RandomRobbieBF/CVE-2024-49681](https://github.com/RandomRobbieBF/CVE-2024-49681) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-49681.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-49681.svg)


## CVE-2024-4832
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/trqt/CVE-2024-48322](https://github.com/trqt/CVE-2024-48322) :  ![starts](https://img.shields.io/github/stars/trqt/CVE-2024-48322.svg) ![forks](https://img.shields.io/github/forks/trqt/CVE-2024-48322.svg)


## CVE-2024-4413
 The Hotel Booking Lite plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 4.11.1 via deserialization of untrusted input. This makes it possible for unauthenticated attackers to inject a PHP Object. No known POP chain is present in the vulnerable plugin. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code.

- [https://github.com/Ununp3ntium115/prevent_cve_2024_44133](https://github.com/Ununp3ntium115/prevent_cve_2024_44133) :  ![starts](https://img.shields.io/github/stars/Ununp3ntium115/prevent_cve_2024_44133.svg) ![forks](https://img.shields.io/github/forks/Ununp3ntium115/prevent_cve_2024_44133.svg)


## CVE-2024-1091
 The ImageRecycle pdf &amp; image compression plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the reinitialize function in all versions up to, and including, 3.1.13. This makes it possible for authenticated attackers, with subscriber-level access and above, to remove all plugin data.

- [https://github.com/imnotcha0s/CVE-2024-10914](https://github.com/imnotcha0s/CVE-2024-10914) :  ![starts](https://img.shields.io/github/stars/imnotcha0s/CVE-2024-10914.svg) ![forks](https://img.shields.io/github/forks/imnotcha0s/CVE-2024-10914.svg)


## CVE-2024-1000
 A vulnerability was found in Totolink N200RE 9.3.5u.6139_B20201216. It has been rated as critical. This issue affects the function setTracerouteCfg of the file /cgi-bin/cstecgi.cgi. The manipulation of the argument command leads to stack-based buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-252269 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/RandomRobbieBF/CVE-2024-10008](https://github.com/RandomRobbieBF/CVE-2024-10008) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10008.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10008.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/sea-middle/cve-2023-25813](https://github.com/sea-middle/cve-2023-25813) :  ![starts](https://img.shields.io/github/stars/sea-middle/cve-2023-25813.svg) ![forks](https://img.shields.io/github/forks/sea-middle/cve-2023-25813.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS &lt;= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/thefizzyfish/CVE-2023-4220_Chamilo_RCE](https://github.com/thefizzyfish/CVE-2023-4220_Chamilo_RCE) :  ![starts](https://img.shields.io/github/stars/thefizzyfish/CVE-2023-4220_Chamilo_RCE.svg) ![forks](https://img.shields.io/github/forks/thefizzyfish/CVE-2023-4220_Chamilo_RCE.svg)


## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

- [https://github.com/lamcodeofpwnosec/CVE-2021-20837](https://github.com/lamcodeofpwnosec/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/lamcodeofpwnosec/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/lamcodeofpwnosec/CVE-2021-20837.svg)


## CVE-2015-1427
 The Groovy scripting engine in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.

- [https://github.com/Sebikea/CVE-2015-1427-for-trixie](https://github.com/Sebikea/CVE-2015-1427-for-trixie) :  ![starts](https://img.shields.io/github/stars/Sebikea/CVE-2015-1427-for-trixie.svg) ![forks](https://img.shields.io/github/forks/Sebikea/CVE-2015-1427-for-trixie.svg)

