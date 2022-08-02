# Update 2022-08-02
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iyamrotrix/CVE-2022-22965](https://github.com/iyamrotrix/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iyamrotrix/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iyamrotrix/CVE-2022-22965.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/QWERTYisme/CVE-2022-21661](https://github.com/QWERTYisme/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/QWERTYisme/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/QWERTYisme/CVE-2022-21661.svg)


## CVE-2021-45043
 HD-Network Real-time Monitoring System 2.0 allows ../ directory traversal to read /etc/shadow via the /language/lang s_Language parameter.

- [https://github.com/crypt0g30rgy/cve-2021-45043](https://github.com/crypt0g30rgy/cve-2021-45043) :  ![starts](https://img.shields.io/github/stars/crypt0g30rgy/cve-2021-45043.svg) ![forks](https://img.shields.io/github/forks/crypt0g30rgy/cve-2021-45043.svg)


## CVE-2019-12255
 Wind River VxWorks has a Buffer Overflow in the TCP component (issue 1 of 4). This is a IPNET security vulnerability: TCP Urgent Pointer = 0 that leads to an integer underflow.

- [https://github.com/sud0woodo/Urgent11-Suricata-LUA-scripts](https://github.com/sud0woodo/Urgent11-Suricata-LUA-scripts) :  ![starts](https://img.shields.io/github/stars/sud0woodo/Urgent11-Suricata-LUA-scripts.svg) ![forks](https://img.shields.io/github/forks/sud0woodo/Urgent11-Suricata-LUA-scripts.svg)


## CVE-2016-0728
 The join_session_keyring function in security/keys/process_keys.c in the Linux kernel before 4.4.1 mishandles object references in a certain error case, which allows local users to gain privileges or cause a denial of service (integer overflow and use-after-free) via crafted keyctl commands.

- [https://github.com/tndud042713/cve-2016-0728](https://github.com/tndud042713/cve-2016-0728) :  ![starts](https://img.shields.io/github/stars/tndud042713/cve-2016-0728.svg) ![forks](https://img.shields.io/github/forks/tndud042713/cve-2016-0728.svg)


## CVE-2016-0189
 The Microsoft (1) JScript 5.8 and (2) VBScript 5.7 and 5.8 engines, as used in Internet Explorer 9 through 11 and other products, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-0187.

- [https://github.com/deamwork/MS16-051-poc](https://github.com/deamwork/MS16-051-poc) :  ![starts](https://img.shields.io/github/stars/deamwork/MS16-051-poc.svg) ![forks](https://img.shields.io/github/forks/deamwork/MS16-051-poc.svg)


## CVE-2015-5531
 Directory traversal vulnerability in Elasticsearch before 1.6.1 allows remote attackers to read arbitrary files via unspecified vectors related to snapshot API calls.

- [https://github.com/xpgdgit/CVE-2015-5531](https://github.com/xpgdgit/CVE-2015-5531) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2015-5531.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2015-5531.svg)


## CVE-2014-3120
 The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.

- [https://github.com/xpgdgit/CVE-2014-3120](https://github.com/xpgdgit/CVE-2014-3120) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2014-3120.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2014-3120.svg)

