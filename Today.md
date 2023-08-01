# Update 2023-08-01
## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/securezeron/CVE-2023-38646](https://github.com/securezeron/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/securezeron/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/securezeron/CVE-2023-38646.svg)
- [https://github.com/Xuxfff/CVE-2023-38646-Poc](https://github.com/Xuxfff/CVE-2023-38646-Poc) :  ![starts](https://img.shields.io/github/stars/Xuxfff/CVE-2023-38646-Poc.svg) ![forks](https://img.shields.io/github/forks/Xuxfff/CVE-2023-38646-Poc.svg)
- [https://github.com/hheeyywweellccoommee/CVE-2023-38646-glwax](https://github.com/hheeyywweellccoommee/CVE-2023-38646-glwax) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-38646-glwax.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-38646-glwax.svg)
- [https://github.com/LazyySec/Poc-Metabase-Preauth-CVE-2023-38646](https://github.com/LazyySec/Poc-Metabase-Preauth-CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/LazyySec/Poc-Metabase-Preauth-CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/LazyySec/Poc-Metabase-Preauth-CVE-2023-38646.svg)


## CVE-2023-36884
 Microsoft is investigating reports of a series of remote code execution vulnerabilities impacting Windows and Office products. Microsoft is aware of targeted attacks that attempt to exploit these vulnerabilities by using specially-crafted Microsoft Office documents. An attacker could create a specially crafted Microsoft Office document that enables them to perform remote code execution in the context of the victim. However, an attacker would have to convince the victim to open the malicious file. Upon completion of this investigation, Microsoft will take the appropriate action to help protect our customers. This might include providing a security update through our monthly release process or providing an out-of-cycle security update, depending on customer needs. Please see the Microsoft Threat Intelligence Blog https://aka.ms/Storm-0978 Entry for important information about steps you can take to protect your system from this vulnerability. This CVE will be updated with new information and links to security updates when they become available.

- [https://github.com/raresteak/CVE-2023-36884](https://github.com/raresteak/CVE-2023-36884) :  ![starts](https://img.shields.io/github/stars/raresteak/CVE-2023-36884.svg) ![forks](https://img.shields.io/github/forks/raresteak/CVE-2023-36884.svg)


## CVE-2023-35078
 Ivanti Endpoint Manager Mobile (EPMM), formerly MobileIron Core, through 11.10 allows remote attackers to obtain PII, add an administrative account, and change the configuration because of an authentication bypass, as exploited in the wild in July 2023. A patch is available.

- [https://github.com/peller-crot/CVE-2023-35078-Poc-Exploit](https://github.com/peller-crot/CVE-2023-35078-Poc-Exploit) :  ![starts](https://img.shields.io/github/stars/peller-crot/CVE-2023-35078-Poc-Exploit.svg) ![forks](https://img.shields.io/github/forks/peller-crot/CVE-2023-35078-Poc-Exploit.svg)


## CVE-2023-34035
 Spring Security versions 5.8 prior to 5.8.5, 6.0 prior to 6.0.5, and 6.1 prior to 6.1.2 could be susceptible to authorization rule misconfiguration if the application uses requestMatchers(String) and multiple servlets, one of them being Spring MVC&#8217;s DispatcherServlet. (DispatcherServlet is a Spring MVC component that maps HTTP endpoints to methods on @Controller-annotated classes.) Specifically, an application is vulnerable when all of the following are true: * Spring MVC is on the classpath * Spring Security is securing more than one servlet in a single application (one of them being Spring MVC&#8217;s DispatcherServlet) * The application uses requestMatchers(String) to refer to endpoints that are not Spring MVC endpoints An application is not vulnerable if any of the following is true: * The application does not have Spring MVC on the classpath * The application secures no servlets other than Spring MVC&#8217;s DispatcherServlet * The application uses requestMatchers(String) only for Spring MVC endpoints

- [https://github.com/mouadk/CVE-2023-34035-Poc](https://github.com/mouadk/CVE-2023-34035-Poc) :  ![starts](https://img.shields.io/github/stars/mouadk/CVE-2023-34035-Poc.svg) ![forks](https://img.shields.io/github/forks/mouadk/CVE-2023-34035-Poc.svg)


## CVE-2023-30799
 MikroTik RouterOS stable before 6.49.7 and long-term through 6.48.6 are vulnerable to a privilege escalation issue. A remote and authenticated attacker can escalate privileges from admin to super-admin on the Winbox or HTTP interface. The attacker can abuse this vulnerability to execute arbitrary code on the system.

- [https://github.com/Untrust3dX/cve_2023_30799](https://github.com/Untrust3dX/cve_2023_30799) :  ![starts](https://img.shields.io/github/stars/Untrust3dX/cve_2023_30799.svg) ![forks](https://img.shields.io/github/forks/Untrust3dX/cve_2023_30799.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols. CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/EmmanuelCruzL/CVE-2023-25157](https://github.com/EmmanuelCruzL/CVE-2023-25157) :  ![starts](https://img.shields.io/github/stars/EmmanuelCruzL/CVE-2023-25157.svg) ![forks](https://img.shields.io/github/forks/EmmanuelCruzL/CVE-2023-25157.svg)


## CVE-2023-2868
 A remote command injection vulnerability exists in the Barracuda Email Security Gateway (appliance form factor only) product effecting versions 5.1.3.001-9.2.0.006. The vulnerability arises out of a failure to comprehensively sanitize the processing of .tar file (tape archives). The vulnerability stems from incomplete input validation of a user-supplied .tar file as it pertains to the names of the files contained within the archive. As a consequence, a remote attacker can specifically format these file names in a particular manner that will result in remotely executing a system command through Perl's qx operator with the privileges of the Email Security Gateway product. This issue was fixed as part of BNSF-36456 patch. This patch was automatically applied to all customer appliances.

- [https://github.com/cashapp323232/CVE-2023-2868CVE-2023-2868](https://github.com/cashapp323232/CVE-2023-2868CVE-2023-2868) :  ![starts](https://img.shields.io/github/stars/cashapp323232/CVE-2023-2868CVE-2023-2868.svg) ![forks](https://img.shields.io/github/forks/cashapp323232/CVE-2023-2868CVE-2023-2868.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/Muhammad-Ali007/Atlassian_CVE-2022-26134](https://github.com/Muhammad-Ali007/Atlassian_CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/Muhammad-Ali007/Atlassian_CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/Muhammad-Ali007/Atlassian_CVE-2022-26134.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/0xr1l3s/CVE-2022-22965](https://github.com/0xr1l3s/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/0xr1l3s/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/0xr1l3s/CVE-2022-22965.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/0xr1l3s/CVE-2022-0847](https://github.com/0xr1l3s/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/0xr1l3s/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/0xr1l3s/CVE-2022-0847.svg)


## CVE-2020-26226
 In the npm package semantic-release before version 17.2.3, secrets that would normally be masked by `semantic-release` can be accidentally disclosed if they contain characters that become encoded when included in a URL. Secrets that do not contain characters that become encoded when included in a URL are already masked properly. The issue is fixed in version 17.2.3.

- [https://github.com/ossf-cve-benchmark/CVE-2020-26226](https://github.com/ossf-cve-benchmark/CVE-2020-26226) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-26226.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-26226.svg)


## CVE-2018-0708
 Command injection vulnerability in networking of QNAP Q'center Virtual Appliance version 1.7.1063 and earlier could allow authenticated users to run arbitrary commands.

- [https://github.com/ntkernel0/CVE-2019-0708](https://github.com/ntkernel0/CVE-2019-0708) :  ![starts](https://img.shields.io/github/stars/ntkernel0/CVE-2019-0708.svg) ![forks](https://img.shields.io/github/forks/ntkernel0/CVE-2019-0708.svg)


## CVE-2016-4655
 The kernel in Apple iOS before 9.3.5 allows attackers to obtain sensitive information from memory via a crafted app.

- [https://github.com/hheeyywweellccoommee/CVE-2016-4655-xoajc](https://github.com/hheeyywweellccoommee/CVE-2016-4655-xoajc) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2016-4655-xoajc.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2016-4655-xoajc.svg)


## CVE-2014-7169
 GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271.

- [https://github.com/Gobinath-B/SHELL-SCHOCK](https://github.com/Gobinath-B/SHELL-SCHOCK) :  ![starts](https://img.shields.io/github/stars/Gobinath-B/SHELL-SCHOCK.svg) ![forks](https://img.shields.io/github/forks/Gobinath-B/SHELL-SCHOCK.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/J0hnTh3Kn1ght/CVE-2014-6271](https://github.com/J0hnTh3Kn1ght/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/J0hnTh3Kn1ght/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/J0hnTh3Kn1ght/CVE-2014-6271.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/timsonner/cve-2014-0160-heartbleed](https://github.com/timsonner/cve-2014-0160-heartbleed) :  ![starts](https://img.shields.io/github/stars/timsonner/cve-2014-0160-heartbleed.svg) ![forks](https://img.shields.io/github/forks/timsonner/cve-2014-0160-heartbleed.svg)

