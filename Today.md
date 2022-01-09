# Update 2022-01-09
## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/atnetws/fail2ban-log4j](https://github.com/atnetws/fail2ban-log4j) :  ![starts](https://img.shields.io/github/stars/atnetws/fail2ban-log4j.svg) ![forks](https://img.shields.io/github/forks/atnetws/fail2ban-log4j.svg)


## CVE-2021-43858
 MinIO is a Kubernetes native application for cloud storage. Prior to version `RELEASE.2021-12-27T07-23-18Z`, a malicious client can hand-craft an HTTP API call that allows for updating policy for a user and gaining higher privileges. The patch in version `RELEASE.2021-12-27T07-23-18Z` changes the accepted request body type and removes the ability to apply policy changes through this API. There is a workaround for this vulnerability: Changing passwords can be disabled by adding an explicit `Deny` rule to disable the API for users.

- [https://github.com/morhax/cve-2021-43858](https://github.com/morhax/cve-2021-43858) :  ![starts](https://img.shields.io/github/stars/morhax/cve-2021-43858.svg) ![forks](https://img.shields.io/github/forks/morhax/cve-2021-43858.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/rodpwn/CVE-2021-43798-mass_scanner](https://github.com/rodpwn/CVE-2021-43798-mass_scanner) :  ![starts](https://img.shields.io/github/stars/rodpwn/CVE-2021-43798-mass_scanner.svg) ![forks](https://img.shields.io/github/forks/rodpwn/CVE-2021-43798-mass_scanner.svg)


## CVE-2021-3157
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/CrackerCat/cve-2021-3157](https://github.com/CrackerCat/cve-2021-3157) :  ![starts](https://img.shields.io/github/stars/CrackerCat/cve-2021-3157.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/cve-2021-3157.svg)


## CVE-2020-14066
 IceWarp Email Server 12.3.0.1 allows remote attackers to upload JavaScript files that are dangerous for clients to access.

- [https://github.com/pinpinsec/Icewarp-Email-Server-12.3.0.1-insecure_permissions](https://github.com/pinpinsec/Icewarp-Email-Server-12.3.0.1-insecure_permissions) :  ![starts](https://img.shields.io/github/stars/pinpinsec/Icewarp-Email-Server-12.3.0.1-insecure_permissions.svg) ![forks](https://img.shields.io/github/forks/pinpinsec/Icewarp-Email-Server-12.3.0.1-insecure_permissions.svg)


## CVE-2020-14065
 IceWarp Email Server 12.3.0.1 allows remote attackers to upload files and consume disk space.

- [https://github.com/pinpinsec/Icewarp-Email-Server-12.3.0.1-unlimited_file_upload](https://github.com/pinpinsec/Icewarp-Email-Server-12.3.0.1-unlimited_file_upload) :  ![starts](https://img.shields.io/github/stars/pinpinsec/Icewarp-Email-Server-12.3.0.1-unlimited_file_upload.svg) ![forks](https://img.shields.io/github/forks/pinpinsec/Icewarp-Email-Server-12.3.0.1-unlimited_file_upload.svg)


## CVE-2020-14064
 IceWarp Email Server 12.3.0.1 has Incorrect Access Control for user accounts.

- [https://github.com/pinpinsec/Icewarp-Mail-Server-12.3.0.1-incorrect_access_control-](https://github.com/pinpinsec/Icewarp-Mail-Server-12.3.0.1-incorrect_access_control-) :  ![starts](https://img.shields.io/github/stars/pinpinsec/Icewarp-Mail-Server-12.3.0.1-incorrect_access_control-.svg) ![forks](https://img.shields.io/github/forks/pinpinsec/Icewarp-Mail-Server-12.3.0.1-incorrect_access_control-.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/1nf1n17yk1ng/CVE-2018-16763](https://github.com/1nf1n17yk1ng/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/1nf1n17yk1ng/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/1nf1n17yk1ng/CVE-2018-16763.svg)

