# Update 2021-10-28
## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Balgogan/CVE-2021-41773](https://github.com/Balgogan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Balgogan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Balgogan/CVE-2021-41773.svg)
- [https://github.com/mr-exo/CVE-2021-41773](https://github.com/mr-exo/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mr-exo/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mr-exo/CVE-2021-41773.svg)


## CVE-2021-37748
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/SECFORCE/CVE-2021-37748](https://github.com/SECFORCE/CVE-2021-37748) :  ![starts](https://img.shields.io/github/stars/SECFORCE/CVE-2021-37748.svg) ![forks](https://img.shields.io/github/forks/SECFORCE/CVE-2021-37748.svg)


## CVE-2021-32789
 woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.

- [https://github.com/andnorack/CVE-2021-32789](https://github.com/andnorack/CVE-2021-32789) :  ![starts](https://img.shields.io/github/stars/andnorack/CVE-2021-32789.svg) ![forks](https://img.shields.io/github/forks/andnorack/CVE-2021-32789.svg)


## CVE-2021-30573
 Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/kh4sh3i/CVE-2021-30573](https://github.com/kh4sh3i/CVE-2021-30573) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2021-30573.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2021-30573.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/lleavesl/CVE-2021-26084](https://github.com/lleavesl/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/lleavesl/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/lleavesl/CVE-2021-26084.svg)


## CVE-2020-7471
 Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2020-4464
 IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0 traditional could allow a remote attacker to execute arbitrary code on a system with a specially-crafted sequence of serialized objects over the SOAP connector. IBM X-Force ID: 181489.

- [https://github.com/silentsignal/WebSphere-WSIF-gadget](https://github.com/silentsignal/WebSphere-WSIF-gadget) :  ![starts](https://img.shields.io/github/stars/silentsignal/WebSphere-WSIF-gadget.svg) ![forks](https://img.shields.io/github/forks/silentsignal/WebSphere-WSIF-gadget.svg)


## CVE-2019-19844
 Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Trushal2004/CVE-2019-9053](https://github.com/Trushal2004/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/Trushal2004/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/Trushal2004/CVE-2019-9053.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/volysandro/cve_2019-6447](https://github.com/volysandro/cve_2019-6447) :  ![starts](https://img.shields.io/github/stars/volysandro/cve_2019-6447.svg) ![forks](https://img.shields.io/github/forks/volysandro/cve_2019-6447.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/rafaelcaria/drupalgeddon2-CVE-2018-7600](https://github.com/rafaelcaria/drupalgeddon2-CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/rafaelcaria/drupalgeddon2-CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/rafaelcaria/drupalgeddon2-CVE-2018-7600.svg)

