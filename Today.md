# Update 2023-10-22
## CVE-2023-45657
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RandomRobbieBF/CVE-2023-45657](https://github.com/RandomRobbieBF/CVE-2023-45657) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-45657.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-45657.svg)


## CVE-2023-42442
 JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication. Session replays stored in S3, OSS, or other cloud storage are not affected. The api `/api/v1/terminal/sessions/` permission control is broken and can be accessed anonymously. SessionViewSet permission classes set to `[RBACPermission | IsSessionAssignee]`, relation is or, so any permission matched will be allowed. Versions 3.5.5 and 3.6.4 have a fix. After upgrading, visit the api `$HOST/api/v1/terminal/sessions/?limit=1`. The expected http response code is 401 (`not_authenticated`).

- [https://github.com/C1ph3rX13/CVE-2023-42442](https://github.com/C1ph3rX13/CVE-2023-42442) :  ![starts](https://img.shields.io/github/stars/C1ph3rX13/CVE-2023-42442.svg) ![forks](https://img.shields.io/github/forks/C1ph3rX13/CVE-2023-42442.svg)


## CVE-2023-41993
 The issue was addressed with improved checks. This issue is fixed in Safari 17, iOS 16.7 and iPadOS 16.7, macOS Sonoma 14. Processing web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/Mangaia/cve-test](https://github.com/Mangaia/cve-test) :  ![starts](https://img.shields.io/github/stars/Mangaia/cve-test.svg) ![forks](https://img.shields.io/github/forks/Mangaia/cve-test.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/AnvithLobo/CVE-2023-38646](https://github.com/AnvithLobo/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/AnvithLobo/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/AnvithLobo/CVE-2023-38646.svg)


## CVE-2023-34051
 VMware Aria Operations for Logs contains an authentication bypass vulnerability. An unauthenticated, malicious actor can inject files into the operating system of an impacted appliance which can result in remote code execution.

- [https://github.com/horizon3ai/CVE-2023-34051](https://github.com/horizon3ai/CVE-2023-34051) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-34051.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-34051.svg)


## CVE-2023-34050
 In spring AMQP versions 1.0.0 to 2.4.16 and 3.0.0 to 3.0.9 , allowed list patterns for deserializable class names were added to Spring AMQP, allowing users to lock down deserialization of data in messages from untrusted sources; however by default, when no allowed list was provided, all classes could be deserialized. Specifically, an application is vulnerable if * the SimpleMessageConverter or SerializerMessageConverter is used * the user does not configure allowed list patterns * untrusted message originators gain permissions to write messages to the RabbitMQ broker to send malicious content

- [https://github.com/X1r0z/spring-amqp-deserialization](https://github.com/X1r0z/spring-amqp-deserialization) :  ![starts](https://img.shields.io/github/stars/X1r0z/spring-amqp-deserialization.svg) ![forks](https://img.shields.io/github/forks/X1r0z/spring-amqp-deserialization.svg)


## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/yTxZx/CVE-2023-28432](https://github.com/yTxZx/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/yTxZx/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/yTxZx/CVE-2023-28432.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/yTxZx/CVE-2023-23752](https://github.com/yTxZx/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/yTxZx/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/yTxZx/CVE-2023-23752.svg)
- [https://github.com/AlissoftCodes/CVE-2023-23752](https://github.com/AlissoftCodes/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/AlissoftCodes/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/AlissoftCodes/CVE-2023-23752.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/youcannotseemeagain/CVE-2023-22515_RCE](https://github.com/youcannotseemeagain/CVE-2023-22515_RCE) :  ![starts](https://img.shields.io/github/stars/youcannotseemeagain/CVE-2023-22515_RCE.svg) ![forks](https://img.shields.io/github/forks/youcannotseemeagain/CVE-2023-22515_RCE.svg)


## CVE-2023-20963
 In WorkSource, there is a possible parcel mismatch. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-220302519

- [https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963.svg)


## CVE-2023-20198
 Cisco is aware of active exploitation of a previously unknown vulnerability in the web UI feature of Cisco IOS XE Software when exposed to the internet or to untrusted networks. This vulnerability allows a remote, unauthenticated attacker to create an account on an affected system with privilege level 15 access. The attacker can then use that account to gain control of the affected system. For steps to close the attack vector for this vulnerability, see the Recommendations section of this advisory Cisco will provide updates on the status of this investigation and when a software patch is available.

- [https://github.com/iveresk/cve-2023-20198](https://github.com/iveresk/cve-2023-20198) :  ![starts](https://img.shields.io/github/stars/iveresk/cve-2023-20198.svg) ![forks](https://img.shields.io/github/forks/iveresk/cve-2023-20198.svg)
- [https://github.com/sohaibeb/CVE-2023-20198](https://github.com/sohaibeb/CVE-2023-20198) :  ![starts](https://img.shields.io/github/stars/sohaibeb/CVE-2023-20198.svg) ![forks](https://img.shields.io/github/forks/sohaibeb/CVE-2023-20198.svg)
- [https://github.com/reket99/Cisco_CVE-2023-20198](https://github.com/reket99/Cisco_CVE-2023-20198) :  ![starts](https://img.shields.io/github/stars/reket99/Cisco_CVE-2023-20198.svg) ![forks](https://img.shields.io/github/forks/reket99/Cisco_CVE-2023-20198.svg)
- [https://github.com/m474r5/CVE-2023-20198-RCE](https://github.com/m474r5/CVE-2023-20198-RCE) :  ![starts](https://img.shields.io/github/stars/m474r5/CVE-2023-20198-RCE.svg) ![forks](https://img.shields.io/github/forks/m474r5/CVE-2023-20198-RCE.svg)


## CVE-2023-3971
 An HTML injection flaw was found in Controller in the user interface settings. This flaw allows an attacker to capture credentials by creating a custom login page by injecting HTML, resulting in a complete compromise.

- [https://github.com/ashangp923/CVE-2023-3971](https://github.com/ashangp923/CVE-2023-3971) :  ![starts](https://img.shields.io/github/stars/ashangp923/CVE-2023-3971.svg) ![forks](https://img.shields.io/github/forks/ashangp923/CVE-2023-3971.svg)


## CVE-2023-1698
 In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.

- [https://github.com/thedarknessdied/WAGO-CVE-2023-1698](https://github.com/thedarknessdied/WAGO-CVE-2023-1698) :  ![starts](https://img.shields.io/github/stars/thedarknessdied/WAGO-CVE-2023-1698.svg) ![forks](https://img.shields.io/github/forks/thedarknessdied/WAGO-CVE-2023-1698.svg)
- [https://github.com/deIndra/CVE-2023-1698](https://github.com/deIndra/CVE-2023-1698) :  ![starts](https://img.shields.io/github/stars/deIndra/CVE-2023-1698.svg) ![forks](https://img.shields.io/github/forks/deIndra/CVE-2023-1698.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-23017
 A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.

- [https://github.com/ShivamDey/CVE-2021-23017](https://github.com/ShivamDey/CVE-2021-23017) :  ![starts](https://img.shields.io/github/stars/ShivamDey/CVE-2021-23017.svg) ![forks](https://img.shields.io/github/forks/ShivamDey/CVE-2021-23017.svg)


## CVE-2018-10097
 XSS exists in Domain Trader 2.5.3 via the recoverlogin.php email_address parameter.

- [https://github.com/ashangp923/CVE-2018-10097](https://github.com/ashangp923/CVE-2018-10097) :  ![starts](https://img.shields.io/github/stars/ashangp923/CVE-2018-10097.svg) ![forks](https://img.shields.io/github/forks/ashangp923/CVE-2018-10097.svg)


## CVE-2017-7410
 Multiple SQL injection vulnerabilities in account/signup.php and account/signup2.php in WebsiteBaker 2.10.0 and earlier allow remote attackers to execute arbitrary SQL commands via the (1) username, (2) display_name parameter.

- [https://github.com/ashangp923/CVE-2017-7410](https://github.com/ashangp923/CVE-2017-7410) :  ![starts](https://img.shields.io/github/stars/ashangp923/CVE-2017-7410.svg) ![forks](https://img.shields.io/github/forks/ashangp923/CVE-2017-7410.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/ShivamDey/Samba-CVE-2007-2447-Exploit](https://github.com/ShivamDey/Samba-CVE-2007-2447-Exploit) :  ![starts](https://img.shields.io/github/stars/ShivamDey/Samba-CVE-2007-2447-Exploit.svg) ![forks](https://img.shields.io/github/forks/ShivamDey/Samba-CVE-2007-2447-Exploit.svg)

