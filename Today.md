# Update 2023-05-02
## CVE-2023-29809
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/zPrototype/CVE-2023-29809](https://github.com/zPrototype/CVE-2023-29809) :  ![starts](https://img.shields.io/github/stars/zPrototype/CVE-2023-29809.svg) ![forks](https://img.shields.io/github/forks/zPrototype/CVE-2023-29809.svg)


## CVE-2023-29489
 An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.

- [https://github.com/whalebone7/EagleEye](https://github.com/whalebone7/EagleEye) :  ![starts](https://img.shields.io/github/stars/whalebone7/EagleEye.svg) ![forks](https://img.shields.io/github/forks/whalebone7/EagleEye.svg)


## CVE-2023-27742
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/G37SYS73M/CVE-2023-27742](https://github.com/G37SYS73M/CVE-2023-27742) :  ![starts](https://img.shields.io/github/stars/G37SYS73M/CVE-2023-27742.svg) ![forks](https://img.shields.io/github/forks/G37SYS73M/CVE-2023-27742.svg)


## CVE-2023-27035
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/fivex3/CVE-2023-27035](https://github.com/fivex3/CVE-2023-27035) :  ![starts](https://img.shields.io/github/stars/fivex3/CVE-2023-27035.svg) ![forks](https://img.shields.io/github/forks/fivex3/CVE-2023-27035.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/yassinebk/CVE-2022-46169](https://github.com/yassinebk/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/yassinebk/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/yassinebk/CVE-2022-46169.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jonathanbest7/cve-2022-0847](https://github.com/jonathanbest7/cve-2022-0847) :  ![starts](https://img.shields.io/github/stars/jonathanbest7/cve-2022-0847.svg) ![forks](https://img.shields.io/github/forks/jonathanbest7/cve-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/Zoo1sondv/CVE-2021-3129](https://github.com/Zoo1sondv/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Zoo1sondv/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Zoo1sondv/CVE-2021-3129.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/Akash7350/CVE-2020-1472](https://github.com/Akash7350/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Akash7350/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Akash7350/CVE-2020-1472.svg)


## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;

- [https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464](https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/tuankiethkt020/Phat-hien-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/tuankiethkt020/Phat-hien-CVE-2017-8464.svg)

