# Update 2022-01-21
## CVE-2022-0185
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Crusaders-of-Rust/CVE-2022-0185](https://github.com/Crusaders-of-Rust/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/Crusaders-of-Rust/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/Crusaders-of-Rust/CVE-2022-0185.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/puzzlepeaches/Log4jHorizon](https://github.com/puzzlepeaches/Log4jHorizon) :  ![starts](https://img.shields.io/github/stars/puzzlepeaches/Log4jHorizon.svg) ![forks](https://img.shields.io/github/forks/puzzlepeaches/Log4jHorizon.svg)


## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/frknktlca/Metabase_Nmap_Script](https://github.com/frknktlca/Metabase_Nmap_Script) :  ![starts](https://img.shields.io/github/stars/frknktlca/Metabase_Nmap_Script.svg) ![forks](https://img.shields.io/github/forks/frknktlca/Metabase_Nmap_Script.svg)


## CVE-2021-26411
 Internet Explorer Memory Corruption Vulnerability

- [https://github.com/CrackerCat/CVE-2021-26411](https://github.com/CrackerCat/CVE-2021-26411) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-26411.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-26411.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/30579096/Confluence-CVE-2021-26084](https://github.com/30579096/Confluence-CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/30579096/Confluence-CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/30579096/Confluence-CVE-2021-26084.svg)


## CVE-2021-25741
 A security issue was discovered in Kubernetes where a user may be able to create a container with subpath volume mounts to access files &amp; directories outside of the volume, including on the host filesystem.

- [https://github.com/Betep0k/CVE-2021-25741](https://github.com/Betep0k/CVE-2021-25741) :  ![starts](https://img.shields.io/github/stars/Betep0k/CVE-2021-25741.svg) ![forks](https://img.shields.io/github/forks/Betep0k/CVE-2021-25741.svg)


## CVE-2021-21425
 Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.

- [https://github.com/frknktlca/GravCMS_Nmap_Script](https://github.com/frknktlca/GravCMS_Nmap_Script) :  ![starts](https://img.shields.io/github/stars/frknktlca/GravCMS_Nmap_Script.svg) ![forks](https://img.shields.io/github/forks/frknktlca/GravCMS_Nmap_Script.svg)


## CVE-2020-12078
 An issue was discovered in Open-AudIT 3.3.1. There is shell metacharacter injection via attributes to an open-audit/configuration/ URI. An attacker can exploit this by adding an excluded IP address to the global discovery settings (internally called exclude_ip). This exclude_ip value is passed to the exec function in the discoveries_helper.php file (inside the all_ip_list function) without being filtered, which means that the attacker can provide a payload instead of a valid IP address.

- [https://github.com/mhaskar/CVE-2020-12078](https://github.com/mhaskar/CVE-2020-12078) :  ![starts](https://img.shields.io/github/stars/mhaskar/CVE-2020-12078.svg) ![forks](https://img.shields.io/github/forks/mhaskar/CVE-2020-12078.svg)
- [https://github.com/84KaliPleXon3/CVE-2020-12078](https://github.com/84KaliPleXon3/CVE-2020-12078) :  ![starts](https://img.shields.io/github/stars/84KaliPleXon3/CVE-2020-12078.svg) ![forks](https://img.shields.io/github/forks/84KaliPleXon3/CVE-2020-12078.svg)


## CVE-2019-13506
 @nuxt/devalue before 1.2.3, as used in Nuxt.js before 2.6.2, mishandles object keys, leading to XSS.

- [https://github.com/ossf-cve-benchmark/CVE-2019-13506](https://github.com/ossf-cve-benchmark/CVE-2019-13506) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-13506.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-13506.svg)


## CVE-2018-18955
 In the Linux kernel 4.15.x through 4.19.x before 4.19.2, map_write() in kernel/user_namespace.c allows privilege escalation because it mishandles nested user namespaces with more than 5 UID or GID ranges. A user who has CAP_SYS_ADMIN in an affected user namespace can bypass access controls on resources outside the namespace, as demonstrated by reading /etc/shadow. This occurs because an ID transformation takes place properly for the namespaced-to-kernel direction but not for the kernel-to-namespaced direction.

- [https://github.com/scheatkode/CVE-2018-18955](https://github.com/scheatkode/CVE-2018-18955) :  ![starts](https://img.shields.io/github/stars/scheatkode/CVE-2018-18955.svg) ![forks](https://img.shields.io/github/forks/scheatkode/CVE-2018-18955.svg)

