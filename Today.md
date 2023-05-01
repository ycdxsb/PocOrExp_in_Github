# Update 2023-05-01
## CVE-2023-29983
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/zPrototype/CVE-2023-29983](https://github.com/zPrototype/CVE-2023-29983) :  ![starts](https://img.shields.io/github/stars/zPrototype/CVE-2023-29983.svg) ![forks](https://img.shields.io/github/forks/zPrototype/CVE-2023-29983.svg)


## CVE-2023-29489
 An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.

- [https://github.com/haxor1337x/Scanner-CVE-2023-29489](https://github.com/haxor1337x/Scanner-CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/haxor1337x/Scanner-CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/haxor1337x/Scanner-CVE-2023-29489.svg)
- [https://github.com/Mostafa-Elguerdawi/CVE-2023-29489.yaml](https://github.com/Mostafa-Elguerdawi/CVE-2023-29489.yaml) :  ![starts](https://img.shields.io/github/stars/Mostafa-Elguerdawi/CVE-2023-29489.yaml.svg) ![forks](https://img.shields.io/github/forks/Mostafa-Elguerdawi/CVE-2023-29489.yaml.svg)
- [https://github.com/Mostafa-Elguerdawi/CVE-2023-29489](https://github.com/Mostafa-Elguerdawi/CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/Mostafa-Elguerdawi/CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/Mostafa-Elguerdawi/CVE-2023-29489.svg)


## CVE-2023-2033
 Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/gretchenfrage/CVE-2023-2033-analysis](https://github.com/gretchenfrage/CVE-2023-2033-analysis) :  ![starts](https://img.shields.io/github/stars/gretchenfrage/CVE-2023-2033-analysis.svg) ![forks](https://img.shields.io/github/forks/gretchenfrage/CVE-2023-2033-analysis.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/devilgothies/CVE-2022-46169](https://github.com/devilgothies/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/devilgothies/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/devilgothies/CVE-2022-46169.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)


## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/Preventions/CVE-2021-36934](https://github.com/Preventions/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/Preventions/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/Preventions/CVE-2021-36934.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/MrE-Fog/CVE-2014-0160-Chrome-Plugin](https://github.com/MrE-Fog/CVE-2014-0160-Chrome-Plugin) :  ![starts](https://img.shields.io/github/stars/MrE-Fog/CVE-2014-0160-Chrome-Plugin.svg) ![forks](https://img.shields.io/github/forks/MrE-Fog/CVE-2014-0160-Chrome-Plugin.svg)

