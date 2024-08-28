# Update 2024-08-28
## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Sachinart/CVE-2024-38063-simulation](https://github.com/Sachinart/CVE-2024-38063-simulation) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2024-38063-simulation.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2024-38063-simulation.svg)


## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the &quot;Package Import&quot; feature, allows authenticated users having the &quot;Import Templates&quot; permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/5ma1l/CVE-2024-25641](https://github.com/5ma1l/CVE-2024-25641) :  ![starts](https://img.shields.io/github/stars/5ma1l/CVE-2024-25641.svg) ![forks](https://img.shields.io/github/forks/5ma1l/CVE-2024-25641.svg)


## CVE-2024-4526
 A vulnerability was found in Campcodes Complete Web-Based School Management System 1.0 and classified as problematic. This issue affects some unknown processing of the file /view/student_payment_details3.php. The manipulation of the argument month leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-263129 was assigned to this vulnerability.

- [https://github.com/TheHermione/CVE-2024-45265](https://github.com/TheHermione/CVE-2024-45265) :  ![starts](https://img.shields.io/github/stars/TheHermione/CVE-2024-45265.svg) ![forks](https://img.shields.io/github/forks/TheHermione/CVE-2024-45265.svg)
- [https://github.com/TheHermione/CVE-2024-45264](https://github.com/TheHermione/CVE-2024-45264) :  ![starts](https://img.shields.io/github/stars/TheHermione/CVE-2024-45264.svg) ![forks](https://img.shields.io/github/forks/TheHermione/CVE-2024-45264.svg)


## CVE-2024-4131
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Amal264882/CVE-2024-41312.](https://github.com/Amal264882/CVE-2024-41312.) :  ![starts](https://img.shields.io/github/stars/Amal264882/CVE-2024-41312..svg) ![forks](https://img.shields.io/github/forks/Amal264882/CVE-2024-41312..svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/laxmiyamkolu/SUDO-privilege-escalation](https://github.com/laxmiyamkolu/SUDO-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/laxmiyamkolu/SUDO-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/laxmiyamkolu/SUDO-privilege-escalation.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/sanan2004/CVE-2023-20198](https://github.com/sanan2004/CVE-2023-20198) :  ![starts](https://img.shields.io/github/stars/sanan2004/CVE-2023-20198.svg) ![forks](https://img.shields.io/github/forks/sanan2004/CVE-2023-20198.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xc4t/CVE-2021-41773](https://github.com/0xc4t/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xc4t/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xc4t/CVE-2021-41773.svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/elit3pwner/CVE-2015-1328-GoldenEye](https://github.com/elit3pwner/CVE-2015-1328-GoldenEye) :  ![starts](https://img.shields.io/github/stars/elit3pwner/CVE-2015-1328-GoldenEye.svg) ![forks](https://img.shields.io/github/forks/elit3pwner/CVE-2015-1328-GoldenEye.svg)

