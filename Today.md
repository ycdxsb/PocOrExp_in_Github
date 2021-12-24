# Update 2021-12-24
## CVE-2021-44659
 Adding a new pipeline in GoCD server version 21.3.0 has a functionality that could be abused to do an un-intended action in order to achieve a Server Side Request Forgery (SSRF)

- [https://github.com/Mesh3l911/CVE-2021-44659](https://github.com/Mesh3l911/CVE-2021-44659) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-44659.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-44659.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/palantir/log4j-sniffer](https://github.com/palantir/log4j-sniffer) :  ![starts](https://img.shields.io/github/stars/palantir/log4j-sniffer.svg) ![forks](https://img.shields.io/github/forks/palantir/log4j-sniffer.svg)
- [https://github.com/lucab85/log4j-cve-2021-44228](https://github.com/lucab85/log4j-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/lucab85/log4j-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/lucab85/log4j-cve-2021-44228.svg)
- [https://github.com/ossie-git/log4shell_sentinel](https://github.com/ossie-git/log4shell_sentinel) :  ![starts](https://img.shields.io/github/stars/ossie-git/log4shell_sentinel.svg) ![forks](https://img.shields.io/github/forks/ossie-git/log4shell_sentinel.svg)
- [https://github.com/sassoftware/loguccino](https://github.com/sassoftware/loguccino) :  ![starts](https://img.shields.io/github/stars/sassoftware/loguccino.svg) ![forks](https://img.shields.io/github/forks/sassoftware/loguccino.svg)


## CVE-2021-39316
 The Zoomsounds plugin &lt;= 6.45 for WordPress allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.

- [https://github.com/anggoroexe/Mass_CVE-2021-39316](https://github.com/anggoroexe/Mass_CVE-2021-39316) :  ![starts](https://img.shields.io/github/stars/anggoroexe/Mass_CVE-2021-39316.svg) ![forks](https://img.shields.io/github/forks/anggoroexe/Mass_CVE-2021-39316.svg)


## CVE-2021-33739
 Microsoft DWM Core Library Elevation of Privilege Vulnerability

- [https://github.com/giwon9977/CVE-2021-33739_PoC_Analysis](https://github.com/giwon9977/CVE-2021-33739_PoC_Analysis) :  ![starts](https://img.shields.io/github/stars/giwon9977/CVE-2021-33739_PoC_Analysis.svg) ![forks](https://img.shields.io/github/forks/giwon9977/CVE-2021-33739_PoC_Analysis.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/gardenWhy/Gitlab-CVE-2021-22205](https://github.com/gardenWhy/Gitlab-CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/gardenWhy/Gitlab-CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/gardenWhy/Gitlab-CVE-2021-22205.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/puckiestyle/CVE-2021-3493](https://github.com/puckiestyle/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-3493.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the &quot;-crl_download&quot; option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/Metztli/debian-openssl-1.1.1i](https://github.com/Metztli/debian-openssl-1.1.1i) :  ![starts](https://img.shields.io/github/stars/Metztli/debian-openssl-1.1.1i.svg) ![forks](https://img.shields.io/github/forks/Metztli/debian-openssl-1.1.1i.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/psc4re/NSE-scripts](https://github.com/psc4re/NSE-scripts) :  ![starts](https://img.shields.io/github/stars/psc4re/NSE-scripts.svg) ![forks](https://img.shields.io/github/forks/psc4re/NSE-scripts.svg)


## CVE-2015-5477
 named in ISC BIND 9.x before 9.9.7-P2 and 9.10.x before 9.10.2-P3 allows remote attackers to cause a denial of service (REQUIRE assertion failure and daemon exit) via TKEY queries.

- [https://github.com/robertdavidgraham/cve-2015-5477](https://github.com/robertdavidgraham/cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/robertdavidgraham/cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/robertdavidgraham/cve-2015-5477.svg)
- [https://github.com/elceef/tkeypoc](https://github.com/elceef/tkeypoc) :  ![starts](https://img.shields.io/github/stars/elceef/tkeypoc.svg) ![forks](https://img.shields.io/github/forks/elceef/tkeypoc.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/whoamins/vsFTPd-2.3.4-exploit](https://github.com/whoamins/vsFTPd-2.3.4-exploit) :  ![starts](https://img.shields.io/github/stars/whoamins/vsFTPd-2.3.4-exploit.svg) ![forks](https://img.shields.io/github/forks/whoamins/vsFTPd-2.3.4-exploit.svg)

