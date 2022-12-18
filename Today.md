# Update 2022-12-18
## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/taythebot/CVE-2022-46169](https://github.com/taythebot/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/taythebot/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/taythebot/CVE-2022-46169.svg)


## CVE-2022-42096
 Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via Post content.

- [https://github.com/bypazs/CVE-2022-42096](https://github.com/bypazs/CVE-2022-42096) :  ![starts](https://img.shields.io/github/stars/bypazs/CVE-2022-42096.svg) ![forks](https://img.shields.io/github/forks/bypazs/CVE-2022-42096.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/LivingFree8/CVE-2022-41082-RCE-POC](https://github.com/LivingFree8/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/LivingFree8/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/LivingFree8/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/LivingFree8/CVE-2022-41082-RCE-POC](https://github.com/LivingFree8/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/LivingFree8/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/LivingFree8/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-28672
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-16640.

- [https://github.com/hacksysteam/CVE-2022-28672](https://github.com/hacksysteam/CVE-2022-28672) :  ![starts](https://img.shields.io/github/stars/hacksysteam/CVE-2022-28672.svg) ![forks](https://img.shields.io/github/forks/hacksysteam/CVE-2022-28672.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/metehangenel/MSHTML-CVE-2021-40444](https://github.com/metehangenel/MSHTML-CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/metehangenel/MSHTML-CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/metehangenel/MSHTML-CVE-2021-40444.svg)


## CVE-2021-26258
 Improper access control for the Intel(R) Killer(TM) Control Center software before version 2.4.3337.0 may allow an authorized user to potentially enable escalation of privilege via local access.

- [https://github.com/zwclose/CVE-2021-26258](https://github.com/zwclose/CVE-2021-26258) :  ![starts](https://img.shields.io/github/stars/zwclose/CVE-2021-26258.svg) ![forks](https://img.shields.io/github/forks/zwclose/CVE-2021-26258.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/r0lh/CVE-2018-7600](https://github.com/r0lh/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/r0lh/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/r0lh/CVE-2018-7600.svg)


## CVE-2017-9608
 The dnxhd decoder in FFmpeg before 3.2.6, and 3.3.x before 3.3.3 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted mov file.

- [https://github.com/LaCinquette/practice-22-23](https://github.com/LaCinquette/practice-22-23) :  ![starts](https://img.shields.io/github/stars/LaCinquette/practice-22-23.svg) ![forks](https://img.shields.io/github/forks/LaCinquette/practice-22-23.svg)

