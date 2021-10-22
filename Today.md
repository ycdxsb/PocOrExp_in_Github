# Update 2021-10-22
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/BincangSiber/CVE-2021-42013](https://github.com/BincangSiber/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/BincangSiber/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/BincangSiber/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/BincangSiber/CVE-2021-41773](https://github.com/BincangSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/BincangSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/BincangSiber/CVE-2021-41773.svg)
- [https://github.com/qwutony/CVE-2021-41773](https://github.com/qwutony/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/qwutony/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/qwutony/CVE-2021-41773.svg)


## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-40450, CVE-2021-41357.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)
- [https://github.com/KaLendsi/CVE-2021-40449-Exploit](https://github.com/KaLendsi/CVE-2021-40449-Exploit) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2021-40449-Exploit.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2021-40449-Exploit.svg)


## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/ConMiko/CVE-2021-31166-exploit](https://github.com/ConMiko/CVE-2021-31166-exploit) :  ![starts](https://img.shields.io/github/stars/ConMiko/CVE-2021-31166-exploit.svg) ![forks](https://img.shields.io/github/forks/ConMiko/CVE-2021-31166-exploit.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/Bubleh21/CVE-2021-3156](https://github.com/Bubleh21/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Bubleh21/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Bubleh21/CVE-2021-3156.svg)


## CVE-2020-10915
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of VEEAM One Agent 9.5.4.4587. Authentication is not required to exploit this vulnerability. The specific flaw exists within the HandshakeResult method. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-10401.

- [https://github.com/Cinnamon1212/Modified-CVE-2020-10915-MsfModule](https://github.com/Cinnamon1212/Modified-CVE-2020-10915-MsfModule) :  ![starts](https://img.shields.io/github/stars/Cinnamon1212/Modified-CVE-2020-10915-MsfModule.svg) ![forks](https://img.shields.io/github/forks/Cinnamon1212/Modified-CVE-2020-10915-MsfModule.svg)


## CVE-2020-1362
 An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.

- [https://github.com/Q4n/CVE-2020-1362](https://github.com/Q4n/CVE-2020-1362) :  ![starts](https://img.shields.io/github/stars/Q4n/CVE-2020-1362.svg) ![forks](https://img.shields.io/github/forks/Q4n/CVE-2020-1362.svg)


## CVE-2019-9081
 The Illuminate component of Laravel Framework 5.7.x has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the PendingCommand class in PendingCommand.php.

- [https://github.com/nth347/CVE-2019-9081_PoC](https://github.com/nth347/CVE-2019-9081_PoC) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2019-9081_PoC.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2019-9081_PoC.svg)


## CVE-2018-14772
 Pydio 4.2.1 through 8.2.1 has an authenticated remote code execution vulnerability in which an attacker with administrator access to the web application can execute arbitrary code on the underlying system via Command Injection.

- [https://github.com/killvxk/CVE-2018-14772](https://github.com/killvxk/CVE-2018-14772) :  ![starts](https://img.shields.io/github/stars/killvxk/CVE-2018-14772.svg) ![forks](https://img.shields.io/github/forks/killvxk/CVE-2018-14772.svg)


## CVE-2018-12636
 The iThemes Security (better-wp-security) plugin before 7.0.3 for WordPress allows SQL Injection (by attackers with Admin privileges) via the logs page.

- [https://github.com/nth347/CVE-2018-12636_exploit](https://github.com/nth347/CVE-2018-12636_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2018-12636_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2018-12636_exploit.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/ItsFadinG/CVE-2018-11235](https://github.com/ItsFadinG/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/ItsFadinG/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/ItsFadinG/CVE-2018-11235.svg)


## CVE-2018-3810
 Authentication Bypass vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages served by WordPress. The saveGoogleCode() function in smartgooglecode.php does not check if the current request is made by an authorized user, thus allowing any unauthenticated user to successfully update the inserted code.

- [https://github.com/nth347/CVE-2018-3810_exploit](https://github.com/nth347/CVE-2018-3810_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2018-3810_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2018-3810_exploit.svg)

