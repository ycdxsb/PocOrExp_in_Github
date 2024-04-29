# Update 2024-04-29
## CVE-2024-27956
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/truonghuuphuc/CVE-2024-27956](https://github.com/truonghuuphuc/CVE-2024-27956) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-27956.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-27956.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/brian-edgar-re/poc-cve-2024-23334](https://github.com/brian-edgar-re/poc-cve-2024-23334) :  ![starts](https://img.shields.io/github/stars/brian-edgar-re/poc-cve-2024-23334.svg) ![forks](https://img.shields.io/github/forks/brian-edgar-re/poc-cve-2024-23334.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/Codeb3af/CVE-2023-20198-RCE](https://github.com/Codeb3af/CVE-2023-20198-RCE) :  ![starts](https://img.shields.io/github/stars/Codeb3af/CVE-2023-20198-RCE.svg) ![forks](https://img.shields.io/github/forks/Codeb3af/CVE-2023-20198-RCE.svg)


## CVE-2023-2255
 Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used &quot;floating frames&quot; linked to external files, would load the contents of those frames without prompting the user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.

- [https://github.com/SaintMichae64/CVE-2023-2255](https://github.com/SaintMichae64/CVE-2023-2255) :  ![starts](https://img.shields.io/github/stars/SaintMichae64/CVE-2023-2255.svg) ![forks](https://img.shields.io/github/forks/SaintMichae64/CVE-2023-2255.svg)


## CVE-2021-42063
 A security vulnerability has been discovered in the SAP Knowledge Warehouse - versions 7.30, 7.31, 7.40, 7.50. The usage of one SAP KW component within a Web browser enables unauthorized attackers to conduct XSS attacks, which might lead to disclose sensitive data.

- [https://github.com/Cappricio-Securities/CVE-2021-42063](https://github.com/Cappricio-Securities/CVE-2021-42063) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2021-42063.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2021-42063.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/nahcusira/CVE-2021-26084](https://github.com/nahcusira/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/nahcusira/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/nahcusira/CVE-2021-26084.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/Jeromeyoung/VMWare-CVE-Check](https://github.com/Jeromeyoung/VMWare-CVE-Check) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/VMWare-CVE-Check.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/VMWare-CVE-Check.svg)

