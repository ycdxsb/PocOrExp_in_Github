# Update 2025-01-27
## CVE-2025-0411
The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.

- [https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC](https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg)
- [https://github.com/CastroJared/7-Zip-CVE-2025-0411-POC](https://github.com/CastroJared/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/CastroJared/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/CastroJared/7-Zip-CVE-2025-0411-POC.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/robomusk52/exp-cmd-add-admin-vpn-CVE-2024-55591](https://github.com/robomusk52/exp-cmd-add-admin-vpn-CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/robomusk52/exp-cmd-add-admin-vpn-CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/robomusk52/exp-cmd-add-admin-vpn-CVE-2024-55591.svg)


## CVE-2024-9047
 The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.

- [https://github.com/Nxploited/CVE-2024-9047-Exploit](https://github.com/Nxploited/CVE-2024-9047-Exploit) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9047-Exploit.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9047-Exploit.svg)


## CVE-2023-40029
 Argo CD is a declarative continuous deployment for Kubernetes. Argo CD Cluster secrets might be managed declaratively using Argo CD / kubectl apply. As a result, the full secret body is stored in`kubectl.kubernetes.io/last-applied-configuration` annotation. pull request #7139 introduced the ability to manage cluster labels and annotations. Since clusters are stored as secrets it also exposes the `kubectl.kubernetes.io/last-applied-configuration` annotation which includes full secret body. In order to view the cluster annotations via the Argo CD API, the user must have `clusters, get` RBAC access. **Note:** In many cases, cluster secrets do not contain any actually-secret information. But sometimes, as in bearer-token auth, the contents might be very sensitive. The bug has been patched in versions 2.8.3, 2.7.14, and 2.6.15. Users are advised to upgrade. Users unable to upgrade should update/deploy cluster secret with `server-side-apply` flag which does not use or rely on `kubectl.kubernetes.io/last-applied-configuration` annotation. Note: annotation for existing secrets will require manual removal.

- [https://github.com/guobei233/CVE-2023-40029](https://github.com/guobei233/CVE-2023-40029) :  ![starts](https://img.shields.io/github/stars/guobei233/CVE-2023-40029.svg) ![forks](https://img.shields.io/github/forks/guobei233/CVE-2023-40029.svg)


## CVE-2021-22893
 Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway. This vulnerability has been exploited in the wild.

- [https://github.com/MRLEE123456/CVE-2021-22893](https://github.com/MRLEE123456/CVE-2021-22893) :  ![starts](https://img.shields.io/github/stars/MRLEE123456/CVE-2021-22893.svg) ![forks](https://img.shields.io/github/forks/MRLEE123456/CVE-2021-22893.svg)


## CVE-2016-2555
 SQL injection vulnerability in include/lib/mysql_connect.inc.php in ATutor 2.2.1 allows remote attackers to execute arbitrary SQL commands via the searchFriends function to friends.inc.php.

- [https://github.com/HussainFathy/CVE-2016-2555](https://github.com/HussainFathy/CVE-2016-2555) :  ![starts](https://img.shields.io/github/stars/HussainFathy/CVE-2016-2555.svg) ![forks](https://img.shields.io/github/forks/HussainFathy/CVE-2016-2555.svg)

