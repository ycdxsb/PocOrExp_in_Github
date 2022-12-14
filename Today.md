# Update 2022-12-14
## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/0xf4n9x/CVE-2022-46169](https://github.com/0xf4n9x/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2022-46169.svg)


## CVE-2022-40674
 libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c.

- [https://github.com/nidhi7598/expat_2.1.0_CVE-2022-40674](https://github.com/nidhi7598/expat_2.1.0_CVE-2022-40674) :  ![starts](https://img.shields.io/github/stars/nidhi7598/expat_2.1.0_CVE-2022-40674.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/expat_2.1.0_CVE-2022-40674.svg)


## CVE-2022-39066
 There is a SQL injection vulnerability in ZTE MF286R. Due to insufficient validation of the input parameters of the phonebook interface, an authenticated attacker could use the vulnerability to execute arbitrary SQL injection.

- [https://github.com/v0lp3/CVE-2022-39066](https://github.com/v0lp3/CVE-2022-39066) :  ![starts](https://img.shields.io/github/stars/v0lp3/CVE-2022-39066.svg) ![forks](https://img.shields.io/github/forks/v0lp3/CVE-2022-39066.svg)


## CVE-2022-37042
 Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. By bypassing authentication (i.e., not having an authtoken), an attacker can upload arbitrary files to the system, leading to directory traversal and remote code execution. NOTE: this issue exists because of an incomplete fix for CVE-2022-27925.

- [https://github.com/0xf4n9x/CVE-2022-37042](https://github.com/0xf4n9x/CVE-2022-37042) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2022-37042.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2022-37042.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/0xGabe/CVE-2022-35914](https://github.com/0xGabe/CVE-2022-35914) :  ![starts](https://img.shields.io/github/stars/0xGabe/CVE-2022-35914.svg) ![forks](https://img.shields.io/github/forks/0xGabe/CVE-2022-35914.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/devengpk/CVE-2022-22965](https://github.com/devengpk/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/devengpk/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/devengpk/CVE-2022-22965.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2020-16846
 An issue was discovered in SaltStack Salt through 3002. Sending crafted web requests to the Salt API, with the SSH client enabled, can result in shell injection.

- [https://github.com/hamza-boudouche/projet-secu](https://github.com/hamza-boudouche/projet-secu) :  ![starts](https://img.shields.io/github/stars/hamza-boudouche/projet-secu.svg) ![forks](https://img.shields.io/github/forks/hamza-boudouche/projet-secu.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/trhacknon/CVE-2020-5902-Scanner](https://github.com/trhacknon/CVE-2020-5902-Scanner) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2020-5902-Scanner.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2020-5902-Scanner.svg)
- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/trhacknon/CVE-2019-19781](https://github.com/trhacknon/CVE-2019-19781) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2019-19781.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2019-19781.svg)
- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2019-11510
 In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability .

- [https://github.com/trhacknon/CVE-2019-11510](https://github.com/trhacknon/CVE-2019-11510) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2019-11510.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2019-11510.svg)
- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2013-2171
 The vm_map_lookup function in sys/vm/vm_map.c in the mmap implementation in the kernel in FreeBSD 9.0 through 9.1-RELEASE-p4 does not properly determine whether a task should have write access to a memory location, which allows local users to bypass filesystem write permissions and consequently gain privileges via a crafted application that leverages read permissions, and makes mmap and ptrace system calls.

- [https://github.com/0xGabe/FreeBSD-9.0-9.1-Privilege-Escalation](https://github.com/0xGabe/FreeBSD-9.0-9.1-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/0xGabe/FreeBSD-9.0-9.1-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/0xGabe/FreeBSD-9.0-9.1-Privilege-Escalation.svg)

