# Update 2024-12-09
## CVE-2024-4232
 This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to lack of encryption or hashing in storing of passwords within the router's firmware/ database. An attacker with physical access could exploit this by extracting the firmware and reverse engineer the binary data to access the plaintext passwords on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to gain unauthorized access to the targeted system.

- [https://github.com/watchdog1337/CVE-2024-42327_Zabbix_SQLI](https://github.com/watchdog1337/CVE-2024-42327_Zabbix_SQLI) :  ![starts](https://img.shields.io/github/stars/watchdog1337/CVE-2024-42327_Zabbix_SQLI.svg) ![forks](https://img.shields.io/github/forks/watchdog1337/CVE-2024-42327_Zabbix_SQLI.svg)


## CVE-2024-1139
 A credentials leak vulnerability was found in the cluster monitoring operator in OCP. This issue may allow a remote attacker who has basic login credentials to check the pod manifest to discover a repository pull secret.

- [https://github.com/Piyush-Bhor/CVE-2024-11393](https://github.com/Piyush-Bhor/CVE-2024-11393) :  ![starts](https://img.shields.io/github/stars/Piyush-Bhor/CVE-2024-11393.svg) ![forks](https://img.shields.io/github/forks/Piyush-Bhor/CVE-2024-11393.svg)
- [https://github.com/Piyush-Bhor/CVE-2024-11392](https://github.com/Piyush-Bhor/CVE-2024-11392) :  ![starts](https://img.shields.io/github/stars/Piyush-Bhor/CVE-2024-11392.svg) ![forks](https://img.shields.io/github/forks/Piyush-Bhor/CVE-2024-11392.svg)
- [https://github.com/Piyush-Bhor/CVE-2024-11394](https://github.com/Piyush-Bhor/CVE-2024-11394) :  ![starts](https://img.shields.io/github/stars/Piyush-Bhor/CVE-2024-11394.svg) ![forks](https://img.shields.io/github/forks/Piyush-Bhor/CVE-2024-11394.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)

