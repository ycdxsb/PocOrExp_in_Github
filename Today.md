# Update 2023-08-13
## CVE-2023-36899
 ASP.NET Elevation of Privilege Vulnerability

- [https://github.com/d0rb/CVE-2023-36899](https://github.com/d0rb/CVE-2023-36899) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2023-36899.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2023-36899.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/d0rb/CVE-2023-33246](https://github.com/d0rb/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2023-33246.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/kaotickj/Check-for-CVE-2023-32629-GameOver-lay](https://github.com/kaotickj/Check-for-CVE-2023-32629-GameOver-lay) :  ![starts](https://img.shields.io/github/stars/kaotickj/Check-for-CVE-2023-32629-GameOver-lay.svg) ![forks](https://img.shields.io/github/forks/kaotickj/Check-for-CVE-2023-32629-GameOver-lay.svg)


## CVE-2023-4174
 A vulnerability has been found in mooSocial mooStore 3.1.6 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross site scripting. The attack can be launched remotely. The identifier VDB-236209 was assigned to this vulnerability.

- [https://github.com/d0rb/CVE-2023-4174](https://github.com/d0rb/CVE-2023-4174) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2023-4174.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2023-4174.svg)


## CVE-2022-26631
 Automatic Question Paper Generator v1.0 contains a Time-Based Blind SQL injection vulnerability via the id GET parameter.

- [https://github.com/5l1v3r1/CVE-2022-26631](https://github.com/5l1v3r1/CVE-2022-26631) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-26631.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-26631.svg)


## CVE-2022-23302
 JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration or if the configuration references an LDAP service the attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2022-4510
 A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included.

- [https://github.com/Kalagious/BadPfs](https://github.com/Kalagious/BadPfs) :  ![starts](https://img.shields.io/github/stars/Kalagious/BadPfs.svg) ![forks](https://img.shields.io/github/forks/Kalagious/BadPfs.svg)


## CVE-2022-2586
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/konoha279/2022-LPE-UAF](https://github.com/konoha279/2022-LPE-UAF) :  ![starts](https://img.shields.io/github/stars/konoha279/2022-LPE-UAF.svg) ![forks](https://img.shields.io/github/forks/konoha279/2022-LPE-UAF.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/belajarqywok/cve-2021-41773-msf](https://github.com/belajarqywok/cve-2021-41773-msf) :  ![starts](https://img.shields.io/github/stars/belajarqywok/cve-2021-41773-msf.svg) ![forks](https://img.shields.io/github/forks/belajarqywok/cve-2021-41773-msf.svg)


## CVE-2020-8558
 The Kubelet and kube-proxy components in versions 1.1.0-1.16.10, 1.17.0-1.17.6, and 1.18.0-1.18.3 were found to contain a security issue which allows adjacent hosts to reach TCP and UDP services bound to 127.0.0.1 running on the node or in the node's network namespace. Such a service is generally thought to be reachable only by other processes on the same host, but due to this defeect, could be reachable by other hosts on the same LAN as the node, or by containers running on the same node as the service.

- [https://github.com/tabbysable/POC-2020-8558](https://github.com/tabbysable/POC-2020-8558) :  ![starts](https://img.shields.io/github/stars/tabbysable/POC-2020-8558.svg) ![forks](https://img.shields.io/github/forks/tabbysable/POC-2020-8558.svg)
- [https://github.com/rhysemmas/martian-packets](https://github.com/rhysemmas/martian-packets) :  ![starts](https://img.shields.io/github/stars/rhysemmas/martian-packets.svg) ![forks](https://img.shields.io/github/forks/rhysemmas/martian-packets.svg)


## CVE-2020-8012
 CA Unified Infrastructure Management (Nimsoft/UIM) 20.1, 20.3.x, and 9.20 and below contains a buffer overflow vulnerability in the robot (controller) component. A remote attacker can execute arbitrary code.

- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)


## CVE-2020-8004
 STMicroelectronics STM32F1 devices have Incorrect Access Control.

- [https://github.com/wuxx/CVE-2020-8004](https://github.com/wuxx/CVE-2020-8004) :  ![starts](https://img.shields.io/github/stars/wuxx/CVE-2020-8004.svg) ![forks](https://img.shields.io/github/forks/wuxx/CVE-2020-8004.svg)


## CVE-2020-6364
 SAP Solution Manager and SAP Focused Run (update provided in WILY_INTRO_ENTERPRISE 9.7, 10.1, 10.5, 10.7), allows an attacker to modify a cookie in a way that OS commands can be executed and potentially gain control over the host running the CA Introscope Enterprise Manager,leading to Code Injection. With this, the attacker is able to read and modify all system files and also impact system availability.

- [https://github.com/gquere/CVE-2020-6364](https://github.com/gquere/CVE-2020-6364) :  ![starts](https://img.shields.io/github/stars/gquere/CVE-2020-6364.svg) ![forks](https://img.shields.io/github/forks/gquere/CVE-2020-6364.svg)


## CVE-2020-1956
 Apache Kylin 2.3.0, and releases up to 2.6.5 and 3.0.1 has some restful apis which will concatenate os command with the user input string, a user is likely to be able to execute any os command without any protection or validation.

- [https://github.com/b510/CVE-2020-1956](https://github.com/b510/CVE-2020-1956) :  ![starts](https://img.shields.io/github/stars/b510/CVE-2020-1956.svg) ![forks](https://img.shields.io/github/forks/b510/CVE-2020-1956.svg)


## CVE-2019-2017
 In rw_t2t_handle_tlv_detect_rsp of rw_t2t_ndef.cc, there is a possible out-of-bound write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-121035711

- [https://github.com/grmono/CVE2019-2017_POC](https://github.com/grmono/CVE2019-2017_POC) :  ![starts](https://img.shields.io/github/stars/grmono/CVE2019-2017_POC.svg) ![forks](https://img.shields.io/github/forks/grmono/CVE2019-2017_POC.svg)


## CVE-2017-12629
 Remote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.

- [https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262](https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262) :  ![starts](https://img.shields.io/github/stars/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg) ![forks](https://img.shields.io/github/forks/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg)


## CVE-2017-3164
 Server Side Request Forgery in Apache Solr, versions 1.3 until 7.6 (inclusive). Since the &quot;shards&quot; parameter does not have a corresponding whitelist mechanism, a remote attacker with access to the server could make Solr perform an HTTP GET request to any reachable URL.

- [https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262](https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262) :  ![starts](https://img.shields.io/github/stars/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg) ![forks](https://img.shields.io/github/forks/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg)

