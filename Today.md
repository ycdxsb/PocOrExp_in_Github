# Update 2021-11-10
## CVE-2021-43361
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/bartutku/CVE-2021-43361](https://github.com/bartutku/CVE-2021-43361) :  ![starts](https://img.shields.io/github/stars/bartutku/CVE-2021-43361.svg) ![forks](https://img.shields.io/github/forks/bartutku/CVE-2021-43361.svg)


## CVE-2021-43267
 An issue was discovered in net/tipc/crypto.c in the Linux kernel before 5.14.16. The Transparent Inter-Process Communication (TIPC) functionality allows remote attackers to exploit insufficient validation of user-supplied sizes for the MSG_CRYPTO message type.

- [https://github.com/DarkSprings/CVE-2021-43267-POC](https://github.com/DarkSprings/CVE-2021-43267-POC) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-43267-POC.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-43267-POC.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit](https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ahmad4fifz/docker-cve-2021-41773](https://github.com/ahmad4fifz/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/ahmad4fifz/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ahmad4fifz/docker-cve-2021-41773.svg)
- [https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit](https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg)


## CVE-2021-40346
 An integer overflow exists in HAProxy 2.0 through 2.5 in htx_add_header that can be exploited to perform an HTTP request smuggling attack, allowing an attacker to bypass all configured http-request HAProxy ACLs and possibly other ACLs.

- [https://github.com/Vulnmachines/HAProxy_CVE-2021-40346](https://github.com/Vulnmachines/HAProxy_CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/HAProxy_CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/HAProxy_CVE-2021-40346.svg)


## CVE-2021-30657
 A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.3, Security Update 2021-002 Catalina. A malicious application may bypass Gatekeeper checks. Apple is aware of a report that this issue may have been actively exploited..

- [https://github.com/shubham0d/CVE-2021-30657](https://github.com/shubham0d/CVE-2021-30657) :  ![starts](https://img.shields.io/github/stars/shubham0d/CVE-2021-30657.svg) ![forks](https://img.shields.io/github/forks/shubham0d/CVE-2021-30657.svg)


## CVE-2021-3229
 Denial of service in ASUSWRT ASUS RT-AX3000 firmware versions 3.0.0.4.384_10177 and earlier versions allows an attacker to disrupt the use of device setup services via continuous login error.

- [https://github.com/fullbbadda1208/CVE-2021-3229](https://github.com/fullbbadda1208/CVE-2021-3229) :  ![starts](https://img.shields.io/github/stars/fullbbadda1208/CVE-2021-3229.svg) ![forks](https://img.shields.io/github/forks/fullbbadda1208/CVE-2021-3229.svg)


## CVE-2020-17519
 A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.

- [https://github.com/thebatmanfuture/apacheflink----POC](https://github.com/thebatmanfuture/apacheflink----POC) :  ![starts](https://img.shields.io/github/stars/thebatmanfuture/apacheflink----POC.svg) ![forks](https://img.shields.io/github/forks/thebatmanfuture/apacheflink----POC.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xlane/CVE-2020-2551](https://github.com/0xlane/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/0xlane/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/0xlane/CVE-2020-2551.svg)

