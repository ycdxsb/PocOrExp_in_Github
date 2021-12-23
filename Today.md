# Update 2021-12-23
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)
- [https://github.com/mergebase/log4j-samples](https://github.com/mergebase/log4j-samples) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-samples.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-samples.svg)
- [https://github.com/KeysAU/Get-log4j-Windows-local](https://github.com/KeysAU/Get-log4j-Windows-local) :  ![starts](https://img.shields.io/github/stars/KeysAU/Get-log4j-Windows-local.svg) ![forks](https://img.shields.io/github/forks/KeysAU/Get-log4j-Windows-local.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/gps1949/CVE-2021-43798](https://github.com/gps1949/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/gps1949/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/gps1949/CVE-2021-43798.svg)
- [https://github.com/halencarjunior/grafana-CVE-2021-43798](https://github.com/halencarjunior/grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/halencarjunior/grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/halencarjunior/grafana-CVE-2021-43798.svg)


## CVE-2021-3560
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/STEALTH-Z/CVE-2021-3560](https://github.com/STEALTH-Z/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/STEALTH-Z/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/STEALTH-Z/CVE-2021-3560.svg)


## CVE-2020-10977
 GitLab EE/CE 8.5 to 12.9 is vulnerable to a an path traversal when moving an issue between projects.

- [https://github.com/vandycknick/gitlab-cve-2020-10977](https://github.com/vandycknick/gitlab-cve-2020-10977) :  ![starts](https://img.shields.io/github/stars/vandycknick/gitlab-cve-2020-10977.svg) ![forks](https://img.shields.io/github/forks/vandycknick/gitlab-cve-2020-10977.svg)


## CVE-2019-16516
 An issue was discovered in ConnectWise Control (formerly known as ScreenConnect) 19.3.25270.7185. There is a user enumeration vulnerability, allowing an unauthenticated attacker to determine with certainty if an account exists for a given username.

- [https://github.com/czz/ScreenConnect-UserEnum](https://github.com/czz/ScreenConnect-UserEnum) :  ![starts](https://img.shields.io/github/stars/czz/ScreenConnect-UserEnum.svg) ![forks](https://img.shields.io/github/forks/czz/ScreenConnect-UserEnum.svg)


## CVE-2019-6693
 Use of a hard-coded cryptographic key to cipher sensitive data in FortiOS configuration backup file may allow an attacker with access to the backup file to decipher the sensitive data, via knowledge of the hard-coded key. The aforementioned sensitive data includes users' passwords (except the administrator's password), private keys' passphrases and High Availability password (when set).

- [https://github.com/gquere/CVE-2019-6693](https://github.com/gquere/CVE-2019-6693) :  ![starts](https://img.shields.io/github/stars/gquere/CVE-2019-6693.svg) ![forks](https://img.shields.io/github/forks/gquere/CVE-2019-6693.svg)


## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

- [https://github.com/CarlosDelRosario7/sploit-bX](https://github.com/CarlosDelRosario7/sploit-bX) :  ![starts](https://img.shields.io/github/stars/CarlosDelRosario7/sploit-bX.svg) ![forks](https://img.shields.io/github/forks/CarlosDelRosario7/sploit-bX.svg)


## CVE-2017-0781
 A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.

- [https://github.com/CarlosDelRosario7/sploit-bX](https://github.com/CarlosDelRosario7/sploit-bX) :  ![starts](https://img.shields.io/github/stars/CarlosDelRosario7/sploit-bX.svg) ![forks](https://img.shields.io/github/forks/CarlosDelRosario7/sploit-bX.svg)


## CVE-2016-10140
 Information disclosure and authentication bypass vulnerability exists in the Apache HTTP Server configuration bundled with ZoneMinder v1.30 and v1.29, which allows a remote unauthenticated attacker to browse all directories in the web root, e.g., a remote unauthenticated attacker can view all CCTV images on the server via the /events URI.

- [https://github.com/asaotomo/CVE-2016-10140-Zoneminder-Poc](https://github.com/asaotomo/CVE-2016-10140-Zoneminder-Poc) :  ![starts](https://img.shields.io/github/stars/asaotomo/CVE-2016-10140-Zoneminder-Poc.svg) ![forks](https://img.shields.io/github/forks/asaotomo/CVE-2016-10140-Zoneminder-Poc.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/whoamins/vsftpd_2.3.4_exploit](https://github.com/whoamins/vsftpd_2.3.4_exploit) :  ![starts](https://img.shields.io/github/stars/whoamins/vsftpd_2.3.4_exploit.svg) ![forks](https://img.shields.io/github/forks/whoamins/vsftpd_2.3.4_exploit.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/windsormoreira/CVE-2006-3392](https://github.com/windsormoreira/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/windsormoreira/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/windsormoreira/CVE-2006-3392.svg)

