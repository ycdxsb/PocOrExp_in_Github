# Update 2024-03-19
## CVE-2024-24520
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/xF-9979/CVE-2024-24520](https://github.com/xF-9979/CVE-2024-24520) :  ![starts](https://img.shields.io/github/stars/xF-9979/CVE-2024-24520.svg) ![forks](https://img.shields.io/github/forks/xF-9979/CVE-2024-24520.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/TheRedDevil1/CVE-2024-23897](https://github.com/TheRedDevil1/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/TheRedDevil1/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/TheRedDevil1/CVE-2024-23897.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream](https://github.com/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/d0rb/CVE-2024-21762](https://github.com/d0rb/CVE-2024-21762) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2024-21762.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2024-21762.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem (&quot;attack 2&quot;). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run (&quot;attack 1&quot;). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes (&quot;attack 3a&quot; and &quot;attack 3b&quot;). runc 1.1.12 includes patches for this issue.

- [https://github.com/Sk3pper/CVE-2024-21626](https://github.com/Sk3pper/CVE-2024-21626) :  ![starts](https://img.shields.io/github/stars/Sk3pper/CVE-2024-21626.svg) ![forks](https://img.shields.io/github/forks/Sk3pper/CVE-2024-21626.svg)


## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/LtmThink/CVE-2023-51385_test](https://github.com/LtmThink/CVE-2023-51385_test) :  ![starts](https://img.shields.io/github/stars/LtmThink/CVE-2023-51385_test.svg) ![forks](https://img.shields.io/github/forks/LtmThink/CVE-2023-51385_test.svg)


## CVE-2023-48788
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TheRedDevil1/CVE-2023-48788](https://github.com/TheRedDevil1/CVE-2023-48788) :  ![starts](https://img.shields.io/github/stars/TheRedDevil1/CVE-2023-48788.svg) ![forks](https://img.shields.io/github/forks/TheRedDevil1/CVE-2023-48788.svg)


## CVE-2023-37679
 A remote command execution (RCE) vulnerability in NextGen Mirth Connect v4.3.0 allows attackers to execute arbitrary commands on the hosting server.

- [https://github.com/jakabakos/CVE-2023-37679-mirth-connect-rce-poc](https://github.com/jakabakos/CVE-2023-37679-mirth-connect-rce-poc) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2023-37679-mirth-connect-rce-poc.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2023-37679-mirth-connect-rce-poc.svg)


## CVE-2023-33747
 CloudPanel v2.2.2 allows attackers to execute a path traversal.

- [https://github.com/0xWhoami35/CloudPanel-CVE-2023-33747](https://github.com/0xWhoami35/CloudPanel-CVE-2023-33747) :  ![starts](https://img.shields.io/github/stars/0xWhoami35/CloudPanel-CVE-2023-33747.svg) ![forks](https://img.shields.io/github/forks/0xWhoami35/CloudPanel-CVE-2023-33747.svg)


## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.

- [https://github.com/rxerium/CVE-2022-41352](https://github.com/rxerium/CVE-2022-41352) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2022-41352.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2022-41352.svg)


## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/rxerium/CVE-2022-24086](https://github.com/rxerium/CVE-2022-24086) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2022-24086.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2022-24086.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/McKinnonIT/zabbix-template-CVE-2020-1472](https://github.com/McKinnonIT/zabbix-template-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/McKinnonIT/zabbix-template-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/McKinnonIT/zabbix-template-CVE-2020-1472.svg)


## CVE-2019-11707
 A type confusion vulnerability can occur when manipulating JavaScript objects due to issues in Array.pop. This can allow for an exploitable crash. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR &lt; 60.7.1, Firefox &lt; 67.0.3, and Thunderbird &lt; 60.7.2.

- [https://github.com/flabbergastedbd/cve-2019-11707](https://github.com/flabbergastedbd/cve-2019-11707) :  ![starts](https://img.shields.io/github/stars/flabbergastedbd/cve-2019-11707.svg) ![forks](https://img.shields.io/github/forks/flabbergastedbd/cve-2019-11707.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/jftierno/-CVE-2018-6574](https://github.com/jftierno/-CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/jftierno/-CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/jftierno/-CVE-2018-6574.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/K3ysTr0K3R/CVE-2017-12615-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-12615-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-12615-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-12615-EXPLOIT.svg)


## CVE-2014-3470
 The ssl3_send_client_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h, when an anonymous ECDH cipher suite is used, allows remote attackers to cause a denial of service (NULL pointer dereference and client crash) by triggering a NULL certificate value.

- [https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3470](https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3470) :  ![starts](https://img.shields.io/github/stars/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3470.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/OpenSSL_1.0.1g_CVE-2014-3470.svg)

