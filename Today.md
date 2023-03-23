# Update 2023-03-23
## CVE-2023-28343
 OS command injection affects Altenergy Power Control Software C1.2.5 via shell metacharacters in the index.php/management/set_timezone timezone parameter, because of set_timezone in models/management_model.php.

- [https://github.com/gobysec/CVE-2023-28343](https://github.com/gobysec/CVE-2023-28343) :  ![starts](https://img.shields.io/github/stars/gobysec/CVE-2023-28343.svg) ![forks](https://img.shields.io/github/forks/gobysec/CVE-2023-28343.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/tiepologian/CVE-2023-23397](https://github.com/tiepologian/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/tiepologian/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/tiepologian/CVE-2023-23397.svg)


## CVE-2023-21036
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/qixils/anticropalypse](https://github.com/qixils/anticropalypse) :  ![starts](https://img.shields.io/github/stars/qixils/anticropalypse.svg) ![forks](https://img.shields.io/github/forks/qixils/anticropalypse.svg)


## CVE-2023-0286
 There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName. X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these inputs, the other input must already contain an X.400 address as a CRL distribution point, which is uncommon. As such, this vulnerability is most likely to only affect applications which have implemented their own functionality for retrieving CRLs over a network.

- [https://github.com/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2023-0286](https://github.com/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2023-0286) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2023-0286.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2023-0286.svg)


## CVE-2022-46463
 ** DISPUTED ** An access control issue in Harbor v1.X.X to v2.5.3 allows attackers to access public and private image repositories without authentication. NOTE: the vendor's position is that this &quot;is clearly described in the documentation as a feature.&quot;

- [https://github.com/404tk/CVE-2022-46463](https://github.com/404tk/CVE-2022-46463) :  ![starts](https://img.shields.io/github/stars/404tk/CVE-2022-46463.svg) ![forks](https://img.shields.io/github/forks/404tk/CVE-2022-46463.svg)


## CVE-2022-46087
 CloudSchool v3.0.1 is vulnerable to Cross Site Scripting (XSS). A normal user can steal session cookies of the admin users through notification received by the admin user.

- [https://github.com/G37SYS73M/CVE-2022-46087](https://github.com/G37SYS73M/CVE-2022-46087) :  ![starts](https://img.shields.io/github/stars/G37SYS73M/CVE-2022-46087.svg) ![forks](https://img.shields.io/github/forks/G37SYS73M/CVE-2022-46087.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/Mustafa1986/cve-2022-42475-Fortinet](https://github.com/Mustafa1986/cve-2022-42475-Fortinet) :  ![starts](https://img.shields.io/github/stars/Mustafa1986/cve-2022-42475-Fortinet.svg) ![forks](https://img.shields.io/github/forks/Mustafa1986/cve-2022-42475-Fortinet.svg)


## CVE-2022-36193
 SQL injection in School Management System 1.0 allows remote attackers to modify or delete data, causing persistent changes to the application's content or behavior by using malicious SQL queries.

- [https://github.com/G37SYS73M/CVE-2022-36193](https://github.com/G37SYS73M/CVE-2022-36193) :  ![starts](https://img.shields.io/github/stars/G37SYS73M/CVE-2022-36193.svg) ![forks](https://img.shields.io/github/forks/G37SYS73M/CVE-2022-36193.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/Mustafa1986/CVE-2022-22963](https://github.com/Mustafa1986/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/Mustafa1986/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/Mustafa1986/CVE-2022-22963.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/4bhishek0/CVE-2022-0847](https://github.com/4bhishek0/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/4bhishek0/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/4bhishek0/CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2020-11059
 In AEgir greater than or equal to 21.7.0 and less than 21.10.1, aegir publish and aegir build may leak secrets from environment variables in the browser bundle published to npm. This has been fixed in 21.10.1.

- [https://github.com/ossf-cve-benchmark/CVE-2020-11059](https://github.com/ossf-cve-benchmark/CVE-2020-11059) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-11059.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-11059.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/dirkjanm/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/dirkjanm/CVE-2020-1472.svg)
- [https://github.com/carlos55ml/zerologon](https://github.com/carlos55ml/zerologon) :  ![starts](https://img.shields.io/github/stars/carlos55ml/zerologon.svg) ![forks](https://img.shields.io/github/forks/carlos55ml/zerologon.svg)


## CVE-2019-1367
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2019-1221.

- [https://github.com/mandarenmanman/CVE-2019-1367](https://github.com/mandarenmanman/CVE-2019-1367) :  ![starts](https://img.shields.io/github/stars/mandarenmanman/CVE-2019-1367.svg) ![forks](https://img.shields.io/github/forks/mandarenmanman/CVE-2019-1367.svg)


## CVE-2017-7651
 In Eclipse Mosquitto 1.4.14, a user can shutdown the Mosquitto server simply by filling the RAM memory with a lot of connections with large payload. This can be done without authentications if occur in connection phase of MQTT protocol.

- [https://github.com/mukkul007/MqttAttack](https://github.com/mukkul007/MqttAttack) :  ![starts](https://img.shields.io/github/stars/mukkul007/MqttAttack.svg) ![forks](https://img.shields.io/github/forks/mukkul007/MqttAttack.svg)


## CVE-2013-0229
 The ProcessSSDPRequest function in minissdp.c in the SSDP handler in MiniUPnP MiniUPnPd before 1.4 allows remote attackers to cause a denial of service (service crash) via a crafted request that triggers a buffer over-read.

- [https://github.com/lochiiconnectivity/vulnupnp](https://github.com/lochiiconnectivity/vulnupnp) :  ![starts](https://img.shields.io/github/stars/lochiiconnectivity/vulnupnp.svg) ![forks](https://img.shields.io/github/forks/lochiiconnectivity/vulnupnp.svg)

