# Update 2024-05-29
## CVE-2024-30056
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/absholi7ly/Microsoft-Edge-Information-Disclosure](https://github.com/absholi7ly/Microsoft-Edge-Information-Disclosure) :  ![starts](https://img.shields.io/github/stars/absholi7ly/Microsoft-Edge-Information-Disclosure.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/Microsoft-Edge-Information-Disclosure.svg)


## CVE-2024-21683
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/phucrio/CVE-2024-21683-RCE](https://github.com/phucrio/CVE-2024-21683-RCE) :  ![starts](https://img.shields.io/github/stars/phucrio/CVE-2024-21683-RCE.svg) ![forks](https://img.shields.io/github/forks/phucrio/CVE-2024-21683-RCE.svg)


## CVE-2024-3552
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/truonghuuphuc/CVE-2024-3552-Poc](https://github.com/truonghuuphuc/CVE-2024-3552-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-3552-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-3552-Poc.svg)


## CVE-2024-3495
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/zomasec/CVE-2024-3495-POC](https://github.com/zomasec/CVE-2024-3495-POC) :  ![starts](https://img.shields.io/github/stars/zomasec/CVE-2024-3495-POC.svg) ![forks](https://img.shields.io/github/forks/zomasec/CVE-2024-3495-POC.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits) :  ![starts](https://img.shields.io/github/stars/ambionics/cnext-exploits.svg) ![forks](https://img.shields.io/github/forks/ambionics/cnext-exploits.svg)


## CVE-2024-0582
 A memory leak flaw was found in the Linux kernel&#8217;s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/0ptyx/cve-2024-0582](https://github.com/0ptyx/cve-2024-0582) :  ![starts](https://img.shields.io/github/stars/0ptyx/cve-2024-0582.svg) ![forks](https://img.shields.io/github/forks/0ptyx/cve-2024-0582.svg)


## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/c0deur/CVE-2023-51385](https://github.com/c0deur/CVE-2023-51385) :  ![starts](https://img.shields.io/github/stars/c0deur/CVE-2023-51385.svg) ![forks](https://img.shields.io/github/forks/c0deur/CVE-2023-51385.svg)


## CVE-2023-50868
 The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped) allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC responses in a random subdomain attack, aka the &quot;NSEC3&quot; issue. The RFC 5155 specification implies that an algorithm must perform thousands of iterations of a hash function in certain situations.

- [https://github.com/Goethe-Universitat-Cybersecurity/NSEC3-Encloser-Attack](https://github.com/Goethe-Universitat-Cybersecurity/NSEC3-Encloser-Attack) :  ![starts](https://img.shields.io/github/stars/Goethe-Universitat-Cybersecurity/NSEC3-Encloser-Attack.svg) ![forks](https://img.shields.io/github/forks/Goethe-Universitat-Cybersecurity/NSEC3-Encloser-Attack.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/xchg-rax-rax/CVE-2023-38646](https://github.com/xchg-rax-rax/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/xchg-rax-rax/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/xchg-rax-rax/CVE-2023-38646.svg)


## CVE-2023-34040
 In Spring for Apache Kafka 3.0.9 and earlier and versions 2.9.10 and earlier, a possible deserialization attack vector existed, but only if unusual configuration was applied. An attacker would have to construct a malicious serialized object in one of the deserialization exception record headers. Specifically, an application is vulnerable when all of the following are true: * The user does not configure an ErrorHandlingDeserializer for the key and/or value of the record * The user explicitly sets container properties checkDeserExWhenKeyNull and/or checkDeserExWhenValueNull container properties to true. * The user allows untrusted sources to publish to a Kafka topic By default, these properties are false, and the container only attempts to deserialize the headers if an ErrorHandlingDeserializer is configured. The ErrorHandlingDeserializer prevents the vulnerability by removing any such malicious headers before processing the record.

- [https://github.com/huyennhat-dev/cve-2023-34040](https://github.com/huyennhat-dev/cve-2023-34040) :  ![starts](https://img.shields.io/github/stars/huyennhat-dev/cve-2023-34040.svg) ![forks](https://img.shields.io/github/forks/huyennhat-dev/cve-2023-34040.svg)


## CVE-2023-30253
 Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: &lt;?PHP instead of &lt;?php in injected data.

- [https://github.com/04Shivam/CVE-2023-30253-Exploit](https://github.com/04Shivam/CVE-2023-30253-Exploit) :  ![starts](https://img.shields.io/github/stars/04Shivam/CVE-2023-30253-Exploit.svg) ![forks](https://img.shields.io/github/forks/04Shivam/CVE-2023-30253-Exploit.svg)
- [https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253) :  ![starts](https://img.shields.io/github/stars/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253.svg) ![forks](https://img.shields.io/github/forks/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253.svg)


## CVE-2023-1829
 A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate filters in case of a perfect hashes while deleting the underlying structure which can later lead to double freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root. We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28.

- [https://github.com/lanleft/CVE-2023-1829](https://github.com/lanleft/CVE-2023-1829) :  ![starts](https://img.shields.io/github/stars/lanleft/CVE-2023-1829.svg) ![forks](https://img.shields.io/github/forks/lanleft/CVE-2023-1829.svg)


## CVE-2022-27927
 A SQL injection vulnerability exists in Microfinance Management System 1.0 when MySQL is being used as the application database. An attacker can issue SQL commands to the MySQL database through the vulnerable course_code and/or customer_number parameter.

- [https://github.com/erengozaydin/Microfinance-Management-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated](https://github.com/erengozaydin/Microfinance-Management-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated) :  ![starts](https://img.shields.io/github/stars/erengozaydin/Microfinance-Management-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated.svg) ![forks](https://img.shields.io/github/forks/erengozaydin/Microfinance-Management-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/vnhacker1337/CVE-2022-27925-PoC](https://github.com/vnhacker1337/CVE-2022-27925-PoC) :  ![starts](https://img.shields.io/github/stars/vnhacker1337/CVE-2022-27925-PoC.svg) ![forks](https://img.shields.io/github/forks/vnhacker1337/CVE-2022-27925-PoC.svg)
- [https://github.com/mohamedbenchikh/CVE-2022-27925](https://github.com/mohamedbenchikh/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/mohamedbenchikh/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/mohamedbenchikh/CVE-2022-27925.svg)
- [https://github.com/Josexv1/CVE-2022-27925](https://github.com/Josexv1/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/Josexv1/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/Josexv1/CVE-2022-27925.svg)
- [https://github.com/Inplex-sys/CVE-2022-27925](https://github.com/Inplex-sys/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/Inplex-sys/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/Inplex-sys/CVE-2022-27925.svg)
- [https://github.com/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925](https://github.com/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925.svg)
- [https://github.com/jam620/Zimbra](https://github.com/jam620/Zimbra) :  ![starts](https://img.shields.io/github/stars/jam620/Zimbra.svg) ![forks](https://img.shields.io/github/forks/jam620/Zimbra.svg)
- [https://github.com/Chocapikk/CVE-2022-27925-Revshell](https://github.com/Chocapikk/CVE-2022-27925-Revshell) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2022-27925-Revshell.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2022-27925-Revshell.svg)
- [https://github.com/touchmycrazyredhat/CVE-2022-27925-Revshell](https://github.com/touchmycrazyredhat/CVE-2022-27925-Revshell) :  ![starts](https://img.shields.io/github/stars/touchmycrazyredhat/CVE-2022-27925-Revshell.svg) ![forks](https://img.shields.io/github/forks/touchmycrazyredhat/CVE-2022-27925-Revshell.svg)
- [https://github.com/akincibor/CVE-2022-27925](https://github.com/akincibor/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/akincibor/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/akincibor/CVE-2022-27925.svg)
- [https://github.com/lolminerxmrig/CVE-2022-27925-Revshell](https://github.com/lolminerxmrig/CVE-2022-27925-Revshell) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/CVE-2022-27925-Revshell.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/CVE-2022-27925-Revshell.svg)
- [https://github.com/miko550/CVE-2022-27925](https://github.com/miko550/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/miko550/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/miko550/CVE-2022-27925.svg)
- [https://github.com/navokus/CVE-2022-27925](https://github.com/navokus/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/navokus/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/navokus/CVE-2022-27925.svg)
- [https://github.com/onlyHerold22/CVE-2022-27925-PoC](https://github.com/onlyHerold22/CVE-2022-27925-PoC) :  ![starts](https://img.shields.io/github/stars/onlyHerold22/CVE-2022-27925-PoC.svg) ![forks](https://img.shields.io/github/forks/onlyHerold22/CVE-2022-27925-PoC.svg)


## CVE-2022-27772
 ** UNSUPPORTED WHEN ASSIGNED ** spring-boot versions prior to version v2.2.11.RELEASE was vulnerable to temporary directory hijacking. This vulnerability impacted the org.springframework.boot.web.server.AbstractConfigurableWebServerFactory.createTempDir method. NOTE: This vulnerability only affects products and/or versions that are no longer supported by the maintainer.

- [https://github.com/puneetbehl/grails3-cve-2022-27772](https://github.com/puneetbehl/grails3-cve-2022-27772) :  ![starts](https://img.shields.io/github/stars/puneetbehl/grails3-cve-2022-27772.svg) ![forks](https://img.shields.io/github/forks/puneetbehl/grails3-cve-2022-27772.svg)


## CVE-2021-41805
 HashiCorp Consul Enterprise before 1.8.17, 1.9.x before 1.9.11, and 1.10.x before 1.10.4 has Incorrect Access Control. An ACL token (with the default operator:write permissions) in one namespace can be used for unintended privilege escalation in a different namespace.

- [https://github.com/blackm4c/CVE-2021-41805](https://github.com/blackm4c/CVE-2021-41805) :  ![starts](https://img.shields.io/github/stars/blackm4c/CVE-2021-41805.svg) ![forks](https://img.shields.io/github/forks/blackm4c/CVE-2021-41805.svg)


## CVE-2019-10092
 In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.

- [https://github.com/mbadanoiu/CVE-2019-10092](https://github.com/mbadanoiu/CVE-2019-10092) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-10092.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-10092.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/Cappricio-Securities/CVE-2015-1635](https://github.com/Cappricio-Securities/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2015-1635.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/Fatalitysec/CVE-2012-1823](https://github.com/Fatalitysec/CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/Fatalitysec/CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/Fatalitysec/CVE-2012-1823.svg)

