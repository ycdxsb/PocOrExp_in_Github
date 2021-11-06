# Update 2021-11-06
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Hydragyrum/CVE-2021-41773-Playground](https://github.com/Hydragyrum/CVE-2021-41773-Playground) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/CVE-2021-41773-Playground.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/CVE-2021-41773-Playground.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Hydragyrum/CVE-2021-41773-Playground](https://github.com/Hydragyrum/CVE-2021-41773-Playground) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/CVE-2021-41773-Playground.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/CVE-2021-41773-Playground.svg)


## CVE-2021-40539
 Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution.

- [https://github.com/synacktiv/CVE-2021-40539](https://github.com/synacktiv/CVE-2021-40539) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-40539.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-40539.svg)


## CVE-2021-38001
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc](https://github.com/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc) :  ![starts](https://img.shields.io/github/stars/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg) ![forks](https://img.shields.io/github/forks/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/devdanqtuan/CVE-2021-22205](https://github.com/devdanqtuan/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/devdanqtuan/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/devdanqtuan/CVE-2021-22205.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/ph-arm/CVE-2021-22204-Gitlab](https://github.com/ph-arm/CVE-2021-22204-Gitlab) :  ![starts](https://img.shields.io/github/stars/ph-arm/CVE-2021-22204-Gitlab.svg) ![forks](https://img.shields.io/github/forks/ph-arm/CVE-2021-22204-Gitlab.svg)


## CVE-2017-10148
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.8 (Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue allows remote attackers to inject special data into log files via a crafted T3 request.

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/zkhalidul/GrabberWP-CVE-2017-5487](https://github.com/zkhalidul/GrabberWP-CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/zkhalidul/GrabberWP-CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/zkhalidul/GrabberWP-CVE-2017-5487.svg)

