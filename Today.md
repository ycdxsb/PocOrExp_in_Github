# Update 2023-05-10
## CVE-2023-30092
 SourceCodester Online Pizza Ordering System v1.0 is vulnerable to SQL Injection via the QTY parameter.

- [https://github.com/nawed20002/CVE-2023-30092](https://github.com/nawed20002/CVE-2023-30092) :  ![starts](https://img.shields.io/github/stars/nawed20002/CVE-2023-30092.svg) ![forks](https://img.shields.io/github/forks/nawed20002/CVE-2023-30092.svg)


## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.

- [https://github.com/TardC/CVE-2023-27524](https://github.com/TardC/CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/TardC/CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/TardC/CVE-2023-27524.svg)


## CVE-2023-25002
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nokn0wthing/CVE-2023-25002](https://github.com/nokn0wthing/CVE-2023-25002) :  ![starts](https://img.shields.io/github/stars/nokn0wthing/CVE-2023-25002.svg) ![forks](https://img.shields.io/github/forks/nokn0wthing/CVE-2023-25002.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/wibuheker/Joomla-CVE-2023-23752](https://github.com/wibuheker/Joomla-CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/wibuheker/Joomla-CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/wibuheker/Joomla-CVE-2023-23752.svg)


## CVE-2023-20052
 On Feb 15, 2023, the following vulnerability in the ClamAV scanning library was disclosed: A vulnerability in the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and earlier could allow an unauthenticated, remote attacker to access sensitive information on an affected device. This vulnerability is due to enabling XML entity substitution that may result in XML external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file that may be read by the ClamAV scanning process.

- [https://github.com/nokn0wthing/CVE-2023-25002](https://github.com/nokn0wthing/CVE-2023-25002) :  ![starts](https://img.shields.io/github/stars/nokn0wthing/CVE-2023-25002.svg) ![forks](https://img.shields.io/github/forks/nokn0wthing/CVE-2023-25002.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/ruycr4ft/CVE-2022-46169](https://github.com/ruycr4ft/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/ruycr4ft/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/ruycr4ft/CVE-2022-46169.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/c0derpwner/HTB-pwned](https://github.com/c0derpwner/HTB-pwned) :  ![starts](https://img.shields.io/github/stars/c0derpwner/HTB-pwned.svg) ![forks](https://img.shields.io/github/forks/c0derpwner/HTB-pwned.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.

- [https://github.com/falconkei/snakeyaml_cve_poc](https://github.com/falconkei/snakeyaml_cve_poc) :  ![starts](https://img.shields.io/github/stars/falconkei/snakeyaml_cve_poc.svg) ![forks](https://img.shields.io/github/forks/falconkei/snakeyaml_cve_poc.svg)


## CVE-2021-38001
 Type confusion in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/glavstroy/CVE-2021-38001](https://github.com/glavstroy/CVE-2021-38001) :  ![starts](https://img.shields.io/github/stars/glavstroy/CVE-2021-38001.svg) ![forks](https://img.shields.io/github/forks/glavstroy/CVE-2021-38001.svg)


## CVE-2021-31805
 The fix issued for CVE-2020-17530 was incomplete. So from Apache Struts 2.0.0 to 2.5.29, still some of the tag&#8217;s attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security degradation.

- [https://github.com/pyroxenites/s2-062](https://github.com/pyroxenites/s2-062) :  ![starts](https://img.shields.io/github/stars/pyroxenites/s2-062.svg) ![forks](https://img.shields.io/github/forks/pyroxenites/s2-062.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/stong/CVE-2021-3156](https://github.com/stong/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/stong/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/stong/CVE-2021-3156.svg)
- [https://github.com/elbee-cyber/CVE-2021-3156-PATCHER](https://github.com/elbee-cyber/CVE-2021-3156-PATCHER) :  ![starts](https://img.shields.io/github/stars/elbee-cyber/CVE-2021-3156-PATCHER.svg) ![forks](https://img.shields.io/github/forks/elbee-cyber/CVE-2021-3156-PATCHER.svg)
- [https://github.com/musergi/CVE-2021-3156](https://github.com/musergi/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/musergi/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/musergi/CVE-2021-3156.svg)
- [https://github.com/AbdullahRizwan101/Baron-Samedit](https://github.com/AbdullahRizwan101/Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/AbdullahRizwan101/Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/AbdullahRizwan101/Baron-Samedit.svg)
- [https://github.com/gmldbd94/cve-2021-3156](https://github.com/gmldbd94/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/gmldbd94/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/gmldbd94/cve-2021-3156.svg)


## CVE-2020-1349
 A remote code execution vulnerability exists in Microsoft Outlook software when it fails to properly handle objects in memory, aka 'Microsoft Outlook Remote Code Execution Vulnerability'.

- [https://github.com/0neb1n/CVE-2020-1349](https://github.com/0neb1n/CVE-2020-1349) :  ![starts](https://img.shields.io/github/stars/0neb1n/CVE-2020-1349.svg) ![forks](https://img.shields.io/github/forks/0neb1n/CVE-2020-1349.svg)


## CVE-2018-4124
 An issue was discovered in certain Apple products. iOS before 11.2.6 is affected. macOS before 10.13.3 Supplemental Update is affected. tvOS before 11.2.6 is affected. watchOS before 4.2.3 is affected. The issue involves the &quot;CoreText&quot; component. It allows remote attackers to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact via a crafted string containing a certain Telugu character.

- [https://github.com/jamf/TELUGU_CVE-2018-4124_POC](https://github.com/jamf/TELUGU_CVE-2018-4124_POC) :  ![starts](https://img.shields.io/github/stars/jamf/TELUGU_CVE-2018-4124_POC.svg) ![forks](https://img.shields.io/github/forks/jamf/TELUGU_CVE-2018-4124_POC.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/Nigmaz/CVE-2018-1160](https://github.com/Nigmaz/CVE-2018-1160) :  ![starts](https://img.shields.io/github/stars/Nigmaz/CVE-2018-1160.svg) ![forks](https://img.shields.io/github/forks/Nigmaz/CVE-2018-1160.svg)


## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

- [https://github.com/pieterbork/blueborne](https://github.com/pieterbork/blueborne) :  ![starts](https://img.shields.io/github/stars/pieterbork/blueborne.svg) ![forks](https://img.shields.io/github/forks/pieterbork/blueborne.svg)
- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)
- [https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785](https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/RavSS/Bluetooth-Crash-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/RavSS/Bluetooth-Crash-CVE-2017-0785.svg)
- [https://github.com/sigbitsadmin/diff](https://github.com/sigbitsadmin/diff) :  ![starts](https://img.shields.io/github/stars/sigbitsadmin/diff.svg) ![forks](https://img.shields.io/github/forks/sigbitsadmin/diff.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Lynk4/CVE-2011-2523](https://github.com/Lynk4/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/Lynk4/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/Lynk4/CVE-2011-2523.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/ss0wl/distcc_v1_cve_2004_2687](https://github.com/ss0wl/distcc_v1_cve_2004_2687) :  ![starts](https://img.shields.io/github/stars/ss0wl/distcc_v1_cve_2004_2687.svg) ![forks](https://img.shields.io/github/forks/ss0wl/distcc_v1_cve_2004_2687.svg)

