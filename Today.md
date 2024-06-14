# Update 2024-06-14
## CVE-2024-31210
 WordPress is an open publishing platform for the Web. It's possible for a file of a type other than a zip file to be submitted as a new plugin by an administrative user on the Plugins -&gt; Add New -&gt; Upload Plugin screen in WordPress. If FTP credentials are requested for installation (in order to move the file into place outside of the `uploads` directory) then the uploaded file remains temporary available in the Media Library despite it not being allowed. If the `DISALLOW_FILE_EDIT` constant is set to `true` on the site _and_ FTP credentials are required when uploading a new theme or plugin, then this technically allows an RCE when the user would otherwise have no means of executing arbitrary PHP code. This issue _only_ affects Administrator level users on single site installations, and Super Admin level users on Multisite installations where it's otherwise expected that the user does not have permission to upload or execute arbitrary PHP code. Lower level users are not affected. Sites where the `DISALLOW_FILE_MODS` constant is set to `true` are not affected. Sites where an administrative user either does not need to enter FTP credentials or they have access to the valid FTP credentials, are not affected. The issue was fixed in WordPress 6.4.3 on January 30, 2024 and backported to versions 6.3.3, 6.2.4, 6.1.5, 6.0.7, 5.9.9, 5.8.9, 5.7.11, 5.6.13, 5.5.14, 5.4.15, 5.3.17, 5.2.20, 5.1.18, 5.0.21, 4.9.25, 2.8.24, 4.7.28, 4.6.28, 4.5.31, 4.4.32, 4.3.33, 4.2.37, and 4.1.40. A workaround is available. If the `DISALLOW_FILE_MODS` constant is defined as `true` then it will not be possible for any user to upload a plugin and therefore this issue will not be exploitable.

- [https://github.com/Abo5/CVE-2024-31210](https://github.com/Abo5/CVE-2024-31210) :  ![starts](https://img.shields.io/github/stars/Abo5/CVE-2024-31210.svg) ![forks](https://img.shields.io/github/forks/Abo5/CVE-2024-31210.svg)


## CVE-2024-29824
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/horizon3ai/CVE-2024-29824](https://github.com/horizon3ai/CVE-2024-29824) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2024-29824.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2024-29824.svg)


## CVE-2024-27956
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/TadashiJei/Valve-Press-CVE-2024-27956-RCE](https://github.com/TadashiJei/Valve-Press-CVE-2024-27956-RCE) :  ![starts](https://img.shields.io/github/stars/TadashiJei/Valve-Press-CVE-2024-27956-RCE.svg) ![forks](https://img.shields.io/github/forks/TadashiJei/Valve-Press-CVE-2024-27956-RCE.svg)


## CVE-2024-27348
 RCE-Remote Command Execution vulnerability in Apache HugeGraph-Server.This issue affects Apache HugeGraph-Server: from 1.0.0 before 1.3.0 in Java8 &amp; Java11 Users are recommended to upgrade to version 1.3.0 with Java11 &amp; enable the Auth system, which fixes the issue.

- [https://github.com/jakabakos/CVE-2024-27348-Apache-HugeGraph-RCE](https://github.com/jakabakos/CVE-2024-27348-Apache-HugeGraph-RCE) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2024-27348-Apache-HugeGraph-RCE.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2024-27348-Apache-HugeGraph-RCE.svg)


## CVE-2024-27282
 An issue was discovered in Ruby 3.x through 3.3.0. If attacker-supplied data is provided to the Ruby regex compiler, it is possible to extract arbitrary heap data relative to the start of the text, including pointers and sensitive strings. The fixed versions are 3.0.7, 3.1.5, 3.2.4, and 3.3.1.

- [https://github.com/Abo5/CVE-2024-27282](https://github.com/Abo5/CVE-2024-27282) :  ![starts](https://img.shields.io/github/stars/Abo5/CVE-2024-27282.svg) ![forks](https://img.shields.io/github/forks/Abo5/CVE-2024-27282.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/0XJ175/DRive](https://github.com/0XJ175/DRive) :  ![starts](https://img.shields.io/github/stars/0XJ175/DRive.svg) ![forks](https://img.shields.io/github/forks/0XJ175/DRive.svg)


## CVE-2024-24590
 Deserialization of untrusted data can occur in versions 0.17.0 to 1.14.2 of the client SDK of Allegro AI&#8217;s ClearML platform, enabling a maliciously uploaded artifact to run arbitrary code on an end user&#8217;s system when interacted with.

- [https://github.com/OxyDeV2/ClearML-CVE-2024-24590](https://github.com/OxyDeV2/ClearML-CVE-2024-24590) :  ![starts](https://img.shields.io/github/stars/OxyDeV2/ClearML-CVE-2024-24590.svg) ![forks](https://img.shields.io/github/forks/OxyDeV2/ClearML-CVE-2024-24590.svg)
- [https://github.com/DemonPandaz2763/CVE-2024-24590](https://github.com/DemonPandaz2763/CVE-2024-24590) :  ![starts](https://img.shields.io/github/stars/DemonPandaz2763/CVE-2024-24590.svg) ![forks](https://img.shields.io/github/forks/DemonPandaz2763/CVE-2024-24590.svg)


## CVE-2024-4898
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/truonghuuphuc/CVE-2024-4898-Poc](https://github.com/truonghuuphuc/CVE-2024-4898-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-4898-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-4898-Poc.svg)


## CVE-2024-4577
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/XiangDongCJC/CVE-2024-4577-PHP-CGI-RCE](https://github.com/XiangDongCJC/CVE-2024-4577-PHP-CGI-RCE) :  ![starts](https://img.shields.io/github/stars/XiangDongCJC/CVE-2024-4577-PHP-CGI-RCE.svg) ![forks](https://img.shields.io/github/forks/XiangDongCJC/CVE-2024-4577-PHP-CGI-RCE.svg)
- [https://github.com/d3ck4/Shodan-CVE-2024-4577](https://github.com/d3ck4/Shodan-CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/d3ck4/Shodan-CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/d3ck4/Shodan-CVE-2024-4577.svg)
- [https://github.com/Entropt/CVE-2024-4577_Analysis](https://github.com/Entropt/CVE-2024-4577_Analysis) :  ![starts](https://img.shields.io/github/stars/Entropt/CVE-2024-4577_Analysis.svg) ![forks](https://img.shields.io/github/forks/Entropt/CVE-2024-4577_Analysis.svg)


## CVE-2024-4484
 The The Plus Addons for Elementor &#8211; Elementor Addons, Page Templates, Widgets, Mega Menu, WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the &#8216;xai_username&#8217; parameter in versions up to, and including, 5.5.2 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Abo5/CVE-2024-4484](https://github.com/Abo5/CVE-2024-4484) :  ![starts](https://img.shields.io/github/stars/Abo5/CVE-2024-4484.svg) ![forks](https://img.shields.io/github/forks/Abo5/CVE-2024-4484.svg)


## CVE-2024-0352
 A vulnerability classified as critical was found in Likeshop up to 2.5.7.20210311. This vulnerability affects the function FileServer::userFormImage of the file server/application/api/controller/File.php of the component HTTP POST Request Handler. The manipulation of the argument file leads to unrestricted upload. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-250120.

- [https://github.com/Cappricio-Securities/CVE-2024-0352](https://github.com/Cappricio-Securities/CVE-2024-0352) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2024-0352.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2024-0352.svg)


## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/endasugrue/CVE-2023-51385_poc](https://github.com/endasugrue/CVE-2023-51385_poc) :  ![starts](https://img.shields.io/github/stars/endasugrue/CVE-2023-51385_poc.svg) ![forks](https://img.shields.io/github/forks/endasugrue/CVE-2023-51385_poc.svg)


## CVE-2023-1151
 A vulnerability was found in SourceCodester Electronic Medical Records System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file administrator.php of the component Cookie Handler. The manipulation of the argument userid leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-222163.

- [https://github.com/ISH2YU/CVE-2023-11518](https://github.com/ISH2YU/CVE-2023-11518) :  ![starts](https://img.shields.io/github/stars/ISH2YU/CVE-2023-11518.svg) ![forks](https://img.shields.io/github/forks/ISH2YU/CVE-2023-11518.svg)


## CVE-2020-0014
 It is possible for a malicious application to construct a TYPE_TOAST window manually and make that window clickable. This could lead to a local escalation of privilege with no additional execution privileges needed. User action is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-128674520

- [https://github.com/ASIFASSU/CVE-2020-0014](https://github.com/ASIFASSU/CVE-2020-0014) :  ![starts](https://img.shields.io/github/stars/ASIFASSU/CVE-2020-0014.svg) ![forks](https://img.shields.io/github/forks/ASIFASSU/CVE-2020-0014.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/yZ1337/CVE-2018-15473](https://github.com/yZ1337/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/yZ1337/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/yZ1337/CVE-2018-15473.svg)

