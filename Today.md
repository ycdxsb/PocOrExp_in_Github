# Update 2023-08-19
## CVE-2023-34853
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/risuxx/CVE-2023-34853](https://github.com/risuxx/CVE-2023-34853) :  ![starts](https://img.shields.io/github/stars/risuxx/CVE-2023-34853.svg) ![forks](https://img.shields.io/github/forks/risuxx/CVE-2023-34853.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/0SPwn/CVE-2023-27372-PoC](https://github.com/0SPwn/CVE-2023-27372-PoC) :  ![starts](https://img.shields.io/github/stars/0SPwn/CVE-2023-27372-PoC.svg) ![forks](https://img.shields.io/github/forks/0SPwn/CVE-2023-27372-PoC.svg)


## CVE-2023-24329
 An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.

- [https://github.com/H4R335HR/CVE-2023-24329-PoC](https://github.com/H4R335HR/CVE-2023-24329-PoC) :  ![starts](https://img.shields.io/github/stars/H4R335HR/CVE-2023-24329-PoC.svg) ![forks](https://img.shields.io/github/forks/H4R335HR/CVE-2023-24329-PoC.svg)


## CVE-2023-20073
 A vulnerability in the web-based management interface of Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers could allow an unauthenticated, remote attacker to upload arbitrary files to an affected device. This vulnerability is due to insufficient authorization enforcement mechanisms in the context of file uploads. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to upload arbitrary files to the affected device.

- [https://github.com/RegularITCat/CVE-2023-20073](https://github.com/RegularITCat/CVE-2023-20073) :  ![starts](https://img.shields.io/github/stars/RegularITCat/CVE-2023-20073.svg) ![forks](https://img.shields.io/github/forks/RegularITCat/CVE-2023-20073.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/deadyP00l/CVE-2022-46169](https://github.com/deadyP00l/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/deadyP00l/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/deadyP00l/CVE-2022-46169.svg)


## CVE-2022-37153
 An issue was discovered in Artica Proxy 4.30.000000. There is a XSS vulnerability via the password parameter in /fw.login.php.

- [https://github.com/5l1v3r1/CVE-2022-37153](https://github.com/5l1v3r1/CVE-2022-37153) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-37153.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-37153.svg)


## CVE-2022-26488
 In Python before 3.10.3 on Windows, local users can gain privileges because the search path is inadequately secured. The installer may allow a local attacker to add user-writable directories to the system search path. To exploit, an administrator must have installed Python for all users and enabled PATH entries. A non-administrative user can trigger a repair that incorrectly adds user-writable paths into PATH, enabling search-path hijacking of other users and system services. This affects Python (CPython) through 3.7.12, 3.8.x through 3.8.12, 3.9.x through 3.9.10, and 3.10.x through 3.10.2.

- [https://github.com/techspence/PyPATHPwner](https://github.com/techspence/PyPATHPwner) :  ![starts](https://img.shields.io/github/stars/techspence/PyPATHPwner.svg) ![forks](https://img.shields.io/github/forks/techspence/PyPATHPwner.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/asepsaepdin/CVE-2022-21907](https://github.com/asepsaepdin/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/CVE-2022-21907.svg)


## CVE-2022-20009
 In various functions of the USB gadget subsystem, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-213172319References: Upstream kernel

- [https://github.com/szymonh/android-gadget](https://github.com/szymonh/android-gadget) :  ![starts](https://img.shields.io/github/stars/szymonh/android-gadget.svg) ![forks](https://img.shields.io/github/forks/szymonh/android-gadget.svg)


## CVE-2021-43857
 Gerapy is a distributed crawler management framework. Gerapy prior to version 0.9.8 is vulnerable to remote code execution, and this issue is patched in version 0.9.8.

- [https://github.com/LongWayHomie/CVE-2021-43857](https://github.com/LongWayHomie/CVE-2021-43857) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2021-43857.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2021-43857.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)


## CVE-2021-33909
 fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an unprivileged user, aka CID-8cae8cd89f05.

- [https://github.com/ChrisTheCoolHut/CVE-2021-33909](https://github.com/ChrisTheCoolHut/CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/ChrisTheCoolHut/CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/ChrisTheCoolHut/CVE-2021-33909.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/An00bRektn/CVE-2021-4034](https://github.com/An00bRektn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/An00bRektn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/An00bRektn/CVE-2021-4034.svg)
- [https://github.com/sofire/polkit-0.96-CVE-2021-4034](https://github.com/sofire/polkit-0.96-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sofire/polkit-0.96-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sofire/polkit-0.96-CVE-2021-4034.svg)
- [https://github.com/deoxykev/CVE-2021-4034-Rust](https://github.com/deoxykev/CVE-2021-4034-Rust) :  ![starts](https://img.shields.io/github/stars/deoxykev/CVE-2021-4034-Rust.svg) ![forks](https://img.shields.io/github/forks/deoxykev/CVE-2021-4034-Rust.svg)
- [https://github.com/Nosferatuvjr/PwnKit](https://github.com/Nosferatuvjr/PwnKit) :  ![starts](https://img.shields.io/github/stars/Nosferatuvjr/PwnKit.svg) ![forks](https://img.shields.io/github/forks/Nosferatuvjr/PwnKit.svg)
- [https://github.com/puckiestyle/CVE-2021-4034](https://github.com/puckiestyle/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-4034.svg)
- [https://github.com/0x01-sec/CVE-2021-4034-](https://github.com/0x01-sec/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/0x01-sec/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/0x01-sec/CVE-2021-4034-.svg)
- [https://github.com/mutur4/CVE-2021-4034](https://github.com/mutur4/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-4034.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/1N53C/CVE-2021-3156-PoC](https://github.com/1N53C/CVE-2021-3156-PoC) :  ![starts](https://img.shields.io/github/stars/1N53C/CVE-2021-3156-PoC.svg) ![forks](https://img.shields.io/github/forks/1N53C/CVE-2021-3156-PoC.svg)
- [https://github.com/baka9moe/CVE-2021-3156-TestReport](https://github.com/baka9moe/CVE-2021-3156-TestReport) :  ![starts](https://img.shields.io/github/stars/baka9moe/CVE-2021-3156-TestReport.svg) ![forks](https://img.shields.io/github/forks/baka9moe/CVE-2021-3156-TestReport.svg)
- [https://github.com/Y3A/CVE-2021-3156](https://github.com/Y3A/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Y3A/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Y3A/CVE-2021-3156.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/freeide/CVE-2021-2394](https://github.com/freeide/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/freeide/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/freeide/CVE-2021-2394.svg)


## CVE-2020-1956
 Apache Kylin 2.3.0, and releases up to 2.6.5 and 3.0.1 has some restful apis which will concatenate os command with the user input string, a user is likely to be able to execute any os command without any protection or validation.

- [https://github.com/b510/CVE-2020-1956](https://github.com/b510/CVE-2020-1956) :  ![starts](https://img.shields.io/github/stars/b510/CVE-2020-1956.svg) ![forks](https://img.shields.io/github/forks/b510/CVE-2020-1956.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/deadyP00l/ZeroLogon-to-Shell](https://github.com/deadyP00l/ZeroLogon-to-Shell) :  ![starts](https://img.shields.io/github/stars/deadyP00l/ZeroLogon-to-Shell.svg) ![forks](https://img.shields.io/github/forks/deadyP00l/ZeroLogon-to-Shell.svg)


## CVE-2018-20162
 Digi TransPort LR54 4.4.0.26 and possible earlier devices have Improper Input Validation that allows users with 'super' CLI access privileges to bypass a restricted shell and execute arbitrary commands as root.

- [https://github.com/stigtsp/CVE-2018-20162-digi-lr54-restricted-shell-escape](https://github.com/stigtsp/CVE-2018-20162-digi-lr54-restricted-shell-escape) :  ![starts](https://img.shields.io/github/stars/stigtsp/CVE-2018-20162-digi-lr54-restricted-shell-escape.svg) ![forks](https://img.shields.io/github/forks/stigtsp/CVE-2018-20162-digi-lr54-restricted-shell-escape.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/hook-s3c/CVE-2018-10933](https://github.com/hook-s3c/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/hook-s3c/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/hook-s3c/CVE-2018-10933.svg)
- [https://github.com/throwawayaccount12312312/precompiled-CVE-2018-10933](https://github.com/throwawayaccount12312312/precompiled-CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/throwawayaccount12312312/precompiled-CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/throwawayaccount12312312/precompiled-CVE-2018-10933.svg)
- [https://github.com/crispy-peppers/Libssh-server-CVE-2018-10933](https://github.com/crispy-peppers/Libssh-server-CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/crispy-peppers/Libssh-server-CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/crispy-peppers/Libssh-server-CVE-2018-10933.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/arthurvmbl/nodejshell](https://github.com/arthurvmbl/nodejshell) :  ![starts](https://img.shields.io/github/stars/arthurvmbl/nodejshell.svg) ![forks](https://img.shields.io/github/forks/arthurvmbl/nodejshell.svg)

