# Update 2022-06-28
## CVE-2022-30136
 Windows Network File System Remote Code Execution Vulnerability.

- [https://github.com/oturu/CVE-2022-30136-POC](https://github.com/oturu/CVE-2022-30136-POC) :  ![starts](https://img.shields.io/github/stars/oturu/CVE-2022-30136-POC.svg) ![forks](https://img.shields.io/github/forks/oturu/CVE-2022-30136-POC.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/c0ff33b34n/CVE-2021-38314](https://github.com/c0ff33b34n/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/c0ff33b34n/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/c0ff33b34n/CVE-2021-38314.svg)


## CVE-2021-25003
 The WPCargo Track &amp; Trace WordPress plugin before 6.9.0 contains a file which could allow unauthenticated attackers to write a PHP file anywhere on the web server, leading to RCE

- [https://github.com/biulove0x/CVE-2021-25003](https://github.com/biulove0x/CVE-2021-25003) :  ![starts](https://img.shields.io/github/stars/biulove0x/CVE-2021-25003.svg) ![forks](https://img.shields.io/github/forks/biulove0x/CVE-2021-25003.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2020-29667
 In Lan ATMService M3 ATM Monitoring System 6.1.0, a remote attacker able to use a default cookie value, such as PHPSESSID=LANIT-IMANAGER, can achieve control over the system because of Insufficient Session Expiration.

- [https://github.com/jet-pentest/CVE-2020-29667](https://github.com/jet-pentest/CVE-2020-29667) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2020-29667.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2020-29667.svg)


## CVE-2019-19653
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jra89/CVE-2019-19653](https://github.com/jra89/CVE-2019-19653) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19653.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19653.svg)


## CVE-2018-1259
 Spring Data Commons, versions 1.13 prior to 1.13.12 and 2.0 prior to 2.0.7, used in combination with XMLBeam 1.4.14 or earlier versions, contains a property binder vulnerability caused by improper restriction of XML external entity references as underlying library XMLBeam does not restrict external reference expansion. An unauthenticated remote malicious user can supply specially crafted request parameters against Spring Data's projection-based request payload binding to access arbitrary files on the system.

- [https://github.com/tafamace/CVE-2018-1259](https://github.com/tafamace/CVE-2018-1259) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1259.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1259.svg)

