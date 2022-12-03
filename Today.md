# Update 2022-12-03
## CVE-2022-31007
 eLabFTW is an electronic lab notebook manager for research teams. Prior to version 4.3.0, a vulnerability allows an authenticated user with an administrator role in a team to assign itself system administrator privileges within the application, or create a new system administrator account. The issue has been corrected in eLabFTW version 4.3.0. In the context of eLabFTW, an administrator is a user account with certain privileges to manage users and content in their assigned team/teams. A system administrator account can manage all accounts, teams and edit system-wide settings within the application. The impact is not deemed as high, as it requires the attacker to have access to an administrator account. Regular user accounts cannot exploit this to gain admin rights. A workaround for one if the issues is removing the ability of administrators to create accounts.

- [https://github.com/gscharf/CVE-2022-31007-Python-POC](https://github.com/gscharf/CVE-2022-31007-Python-POC) :  ![starts](https://img.shields.io/github/stars/gscharf/CVE-2022-31007-Python-POC.svg) ![forks](https://img.shields.io/github/forks/gscharf/CVE-2022-31007-Python-POC.svg)


## CVE-2022-26265
 Contao Managed Edition v1.5.0 was discovered to contain a remote command execution (RCE) vulnerability via the component php_cli parameter.

- [https://github.com/Inplex-sys/CVE-2022-26265](https://github.com/Inplex-sys/CVE-2022-26265) :  ![starts](https://img.shields.io/github/stars/Inplex-sys/CVE-2022-26265.svg) ![forks](https://img.shields.io/github/forks/Inplex-sys/CVE-2022-26265.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)


## CVE-2020-3833
 An inconsistent user interface issue was addressed with improved state management. This issue is fixed in Safari 13.0.5. Visiting a malicious website may lead to address bar spoofing.

- [https://github.com/5l1v3r1/Safari-Address-Bar-Spoof-CVE-2020-3833-](https://github.com/5l1v3r1/Safari-Address-Bar-Spoof-CVE-2020-3833-) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/Safari-Address-Bar-Spoof-CVE-2020-3833-.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/Safari-Address-Bar-Spoof-CVE-2020-3833-.svg)


## CVE-2019-0678
 An elevation of privilege vulnerability exists when Microsoft Edge does not properly enforce cross-domain policies, which could allow an attacker to access information from one domain and inject it into another domain.In a web-based attack scenario, an attacker could host a website that is used to attempt to exploit the vulnerability, aka 'Microsoft Edge Elevation of Privilege Vulnerability'.

- [https://github.com/sharmasandeepkr/CVE-2019-0678](https://github.com/sharmasandeepkr/CVE-2019-0678) :  ![starts](https://img.shields.io/github/stars/sharmasandeepkr/CVE-2019-0678.svg) ![forks](https://img.shields.io/github/forks/sharmasandeepkr/CVE-2019-0678.svg)


## CVE-2018-16135
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/5l1v3r1/CVE-2018-16135](https://github.com/5l1v3r1/CVE-2018-16135) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2018-16135.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2018-16135.svg)


## CVE-2018-12386
 A vulnerability in register allocation in JavaScript can lead to type confusion, allowing for an arbitrary read and write. This leads to remote code execution inside the sandboxed content process when triggered. This vulnerability affects Firefox ESR &lt; 60.2.2 and Firefox &lt; 62.0.3.

- [https://github.com/0xLyte/cve-2018-12386](https://github.com/0xLyte/cve-2018-12386) :  ![starts](https://img.shields.io/github/stars/0xLyte/cve-2018-12386.svg) ![forks](https://img.shields.io/github/forks/0xLyte/cve-2018-12386.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/SilasSpringer/CVE-2018-10933](https://github.com/SilasSpringer/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/SilasSpringer/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/SilasSpringer/CVE-2018-10933.svg)


## CVE-2014-0196
 The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel through 3.14.3 does not properly manage tty driver access in the &quot;LECHO &amp; !OPOST&quot; case, which allows local users to cause a denial of service (memory corruption and system crash) or gain privileges by triggering a race condition involving read and write operations with long strings.

- [https://github.com/netwid/CVE-2014-0196](https://github.com/netwid/CVE-2014-0196) :  ![starts](https://img.shields.io/github/stars/netwid/CVE-2014-0196.svg) ![forks](https://img.shields.io/github/forks/netwid/CVE-2014-0196.svg)

