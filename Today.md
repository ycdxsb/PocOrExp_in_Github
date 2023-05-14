# Update 2023-05-14
## CVE-2023-28772
 An issue was discovered in the Linux kernel before 5.13.3. lib/seq_buf.c has a seq_buf_putmem_hex buffer overflow.

- [https://github.com/hshivhare67/kernel_v4.1.15_CVE-2023-28772](https://github.com/hshivhare67/kernel_v4.1.15_CVE-2023-28772) :  ![starts](https://img.shields.io/github/stars/hshivhare67/kernel_v4.1.15_CVE-2023-28772.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/kernel_v4.1.15_CVE-2023-28772.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/Rickster5555/EH2-PoC](https://github.com/Rickster5555/EH2-PoC) :  ![starts](https://img.shields.io/github/stars/Rickster5555/EH2-PoC.svg) ![forks](https://img.shields.io/github/forks/Rickster5555/EH2-PoC.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/eatscrayon/CVE-2022-3602-poc](https://github.com/eatscrayon/CVE-2022-3602-poc) :  ![starts](https://img.shields.io/github/stars/eatscrayon/CVE-2022-3602-poc.svg) ![forks](https://img.shields.io/github/forks/eatscrayon/CVE-2022-3602-poc.svg)
- [https://github.com/micr0sh0ft/certscare-openssl3-exploit](https://github.com/micr0sh0ft/certscare-openssl3-exploit) :  ![starts](https://img.shields.io/github/stars/micr0sh0ft/certscare-openssl3-exploit.svg) ![forks](https://img.shields.io/github/forks/micr0sh0ft/certscare-openssl3-exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/PurpleOzone/PE_CVE-CVE-2021-3156](https://github.com/PurpleOzone/PE_CVE-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/PurpleOzone/PE_CVE-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/PurpleOzone/PE_CVE-CVE-2021-3156.svg)


## CVE-2020-17087
 Windows Kernel Local Elevation of Privilege Vulnerability

- [https://github.com/raiden757/CVE-2020-17087](https://github.com/raiden757/CVE-2020-17087) :  ![starts](https://img.shields.io/github/stars/raiden757/CVE-2020-17087.svg) ![forks](https://img.shields.io/github/forks/raiden757/CVE-2020-17087.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/KaLendsi/CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1054.svg)


## CVE-2019-8605
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1. A malicious application may be able to execute arbitrary code with system privileges.

- [https://github.com/1nteger-c/CVE-2019-8605](https://github.com/1nteger-c/CVE-2019-8605) :  ![starts](https://img.shields.io/github/stars/1nteger-c/CVE-2019-8605.svg) ![forks](https://img.shields.io/github/forks/1nteger-c/CVE-2019-8605.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133](https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133) :  ![starts](https://img.shields.io/github/stars/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg) ![forks](https://img.shields.io/github/forks/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg)


## CVE-2018-3245
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)


## CVE-2018-1042
 Moodle 3.x has Server Side Request Forgery in the filepicker.

- [https://github.com/UDPsycho/Moodle-CVE-2018-1042](https://github.com/UDPsycho/Moodle-CVE-2018-1042) :  ![starts](https://img.shields.io/github/stars/UDPsycho/Moodle-CVE-2018-1042.svg) ![forks](https://img.shields.io/github/forks/UDPsycho/Moodle-CVE-2018-1042.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133](https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133) :  ![starts](https://img.shields.io/github/stars/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg) ![forks](https://img.shields.io/github/forks/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg)


## CVE-2016-7200
 The Chakra JavaScript scripting engine in Microsoft Edge allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-7201, CVE-2016-7202, CVE-2016-7203, CVE-2016-7208, CVE-2016-7240, CVE-2016-7242, and CVE-2016-7243.

- [https://github.com/theori-io/chakra-2016-11](https://github.com/theori-io/chakra-2016-11) :  ![starts](https://img.shields.io/github/stars/theori-io/chakra-2016-11.svg) ![forks](https://img.shields.io/github/forks/theori-io/chakra-2016-11.svg)

