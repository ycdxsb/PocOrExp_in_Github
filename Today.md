# Update 2022-10-25
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/cxzero/CVE-2022-42889-text4shell](https://github.com/cxzero/CVE-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/cxzero/CVE-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/cxzero/CVE-2022-42889-text4shell.svg)
- [https://github.com/smileostrich/Text4Shell-Scanner](https://github.com/smileostrich/Text4Shell-Scanner) :  ![starts](https://img.shields.io/github/stars/smileostrich/Text4Shell-Scanner.svg) ![forks](https://img.shields.io/github/forks/smileostrich/Text4Shell-Scanner.svg)
- [https://github.com/0xmaximus/Apache-Commons-Text-CVE-2022-42889](https://github.com/0xmaximus/Apache-Commons-Text-CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/0xmaximus/Apache-Commons-Text-CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/0xmaximus/Apache-Commons-Text-CVE-2022-42889.svg)


## CVE-2022-42045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ReCryptLLC/CVE-2022-42045](https://github.com/ReCryptLLC/CVE-2022-42045) :  ![starts](https://img.shields.io/github/stars/ReCryptLLC/CVE-2022-42045.svg) ![forks](https://img.shields.io/github/forks/ReCryptLLC/CVE-2022-42045.svg)


## CVE-2022-38813
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RashidKhanPathan/CVE-2022-38813](https://github.com/RashidKhanPathan/CVE-2022-38813) :  ![starts](https://img.shields.io/github/stars/RashidKhanPathan/CVE-2022-38813.svg) ![forks](https://img.shields.io/github/forks/RashidKhanPathan/CVE-2022-38813.svg)


## CVE-2022-37705
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/MaherAzzouzi/CVE-2022-37705](https://github.com/MaherAzzouzi/CVE-2022-37705) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-37705.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-37705.svg)


## CVE-2022-37704
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/MaherAzzouzi/CVE-2022-37704](https://github.com/MaherAzzouzi/CVE-2022-37704) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-37704.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-37704.svg)


## CVE-2022-36663
 Gluu Oxauth before v4.4.1 allows attackers to execute blind SSRF (Server-Side Request Forgery) attacks via a crafted request_uri parameter.

- [https://github.com/aqeisi/CVE-2022-36663-PoC](https://github.com/aqeisi/CVE-2022-36663-PoC) :  ![starts](https://img.shields.io/github/stars/aqeisi/CVE-2022-36663-PoC.svg) ![forks](https://img.shields.io/github/forks/aqeisi/CVE-2022-36663-PoC.svg)


## CVE-2022-31629
 In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or `__Secure-` cookie by PHP applications.

- [https://github.com/silnex/CVE-2022-31629-poc](https://github.com/silnex/CVE-2022-31629-poc) :  ![starts](https://img.shields.io/github/stars/silnex/CVE-2022-31629-poc.svg) ![forks](https://img.shields.io/github/forks/silnex/CVE-2022-31629-poc.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/WilsonFung414/CVE-2022-30190](https://github.com/WilsonFung414/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/WilsonFung414/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/WilsonFung414/CVE-2022-30190.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/r00tVen0m/CVE-2021-41773](https://github.com/r00tVen0m/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/r00tVen0m/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/r00tVen0m/CVE-2021-41773.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/WilsonFung414/CVE-2021-40438_Docker](https://github.com/WilsonFung414/CVE-2021-40438_Docker) :  ![starts](https://img.shields.io/github/stars/WilsonFung414/CVE-2021-40438_Docker.svg) ![forks](https://img.shields.io/github/forks/WilsonFung414/CVE-2021-40438_Docker.svg)
- [https://github.com/WilsonFung414/CVE-2021-27928_Docker](https://github.com/WilsonFung414/CVE-2021-27928_Docker) :  ![starts](https://img.shields.io/github/stars/WilsonFung414/CVE-2021-27928_Docker.svg) ![forks](https://img.shields.io/github/forks/WilsonFung414/CVE-2021-27928_Docker.svg)


## CVE-2021-27928
 A remote code execution issue was discovered in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL. An untrusted search path leads to eval injection, in which a database SUPER user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd. NOTE: this does not affect an Oracle product.

- [https://github.com/WilsonFung414/CVE-2021-27928_Docker](https://github.com/WilsonFung414/CVE-2021-27928_Docker) :  ![starts](https://img.shields.io/github/stars/WilsonFung414/CVE-2021-27928_Docker.svg) ![forks](https://img.shields.io/github/forks/WilsonFung414/CVE-2021-27928_Docker.svg)


## CVE-2020-11652
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.

- [https://github.com/rossengeorgiev/salt-security-backports](https://github.com/rossengeorgiev/salt-security-backports) :  ![starts](https://img.shields.io/github/stars/rossengeorgiev/salt-security-backports.svg) ![forks](https://img.shields.io/github/forks/rossengeorgiev/salt-security-backports.svg)


## CVE-2020-10977
 GitLab EE/CE 8.5 to 12.9 is vulnerable to a an path traversal when moving an issue between projects.

- [https://github.com/dotPY-hax/gitlab_RCE](https://github.com/dotPY-hax/gitlab_RCE) :  ![starts](https://img.shields.io/github/stars/dotPY-hax/gitlab_RCE.svg) ![forks](https://img.shields.io/github/forks/dotPY-hax/gitlab_RCE.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/e-renna/CVE-2019-9053](https://github.com/e-renna/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/e-renna/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/e-renna/CVE-2019-9053.svg)

