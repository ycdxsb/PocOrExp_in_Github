# Update 2021-09-24
## CVE-2021-40875
 Improper Access Control in Gurock TestRail versions &lt; 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list of application files and the corresponding file paths. The corresponding file paths can be tested, and in some cases, result in the disclosure of hardcoded credentials, API keys, or other sensitive data.

- [https://github.com/SakuraSamuraii/derailed](https://github.com/SakuraSamuraii/derailed) :  ![starts](https://img.shields.io/github/stars/SakuraSamuraii/derailed.svg) ![forks](https://img.shields.io/github/forks/SakuraSamuraii/derailed.svg)


## CVE-2021-38647
 Open Management Infrastructure Remote Code Execution Vulnerability

- [https://github.com/abousteif/cve-2021-38647](https://github.com/abousteif/cve-2021-38647) :  ![starts](https://img.shields.io/github/stars/abousteif/cve-2021-38647.svg) ![forks](https://img.shields.io/github/forks/abousteif/cve-2021-38647.svg)


## CVE-2021-22005
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/1ZRR4H/CVE-2021-22005](https://github.com/1ZRR4H/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/1ZRR4H/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/1ZRR4H/CVE-2021-22005.svg)
- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape](https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape) :  ![starts](https://img.shields.io/github/stars/Sauercloud/RWCTF21-VirtualBox-61-escape.svg) ![forks](https://img.shields.io/github/forks/Sauercloud/RWCTF21-VirtualBox-61-escape.svg)


## CVE-2020-8793
 OpenSMTPD before 6.6.4 allows local users to read arbitrary files (e.g., on some Linux distributions) because of a combination of an untrusted search path in makemap.c and race conditions in the offline functionality in smtpd.c.

- [https://github.com/optionalg/OpenSMTPD](https://github.com/optionalg/OpenSMTPD) :  ![starts](https://img.shields.io/github/stars/optionalg/OpenSMTPD.svg) ![forks](https://img.shields.io/github/forks/optionalg/OpenSMTPD.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/Apasys/Apasys-CVE-2020-0796](https://github.com/Apasys/Apasys-CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/Apasys/Apasys-CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/Apasys/Apasys-CVE-2020-0796.svg)


## CVE-2019-7238
 Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.

- [https://github.com/magicming200/CVE-2019-7238_Nexus_RCE_Tool](https://github.com/magicming200/CVE-2019-7238_Nexus_RCE_Tool) :  ![starts](https://img.shields.io/github/stars/magicming200/CVE-2019-7238_Nexus_RCE_Tool.svg) ![forks](https://img.shields.io/github/forks/magicming200/CVE-2019-7238_Nexus_RCE_Tool.svg)


## CVE-2019-6340
 Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)

- [https://github.com/Apasys/Apasys-CVE-2019-6340](https://github.com/Apasys/Apasys-CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/Apasys/Apasys-CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/Apasys/Apasys-CVE-2019-6340.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/RyouYoo/CVE-2018-11235](https://github.com/RyouYoo/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/RyouYoo/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/RyouYoo/CVE-2018-11235.svg)

