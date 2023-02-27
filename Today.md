# Update 2023-02-27
## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.

- [https://github.com/yosef0x01/Analysis4CVE-2023-0669](https://github.com/yosef0x01/Analysis4CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/yosef0x01/Analysis4CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/Analysis4CVE-2023-0669.svg)


## CVE-2022-48310
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nitschSB/CVE-2022-48309-and-CVE-2022-48310](https://github.com/nitschSB/CVE-2022-48309-and-CVE-2022-48310) :  ![starts](https://img.shields.io/github/stars/nitschSB/CVE-2022-48309-and-CVE-2022-48310.svg) ![forks](https://img.shields.io/github/forks/nitschSB/CVE-2022-48309-and-CVE-2022-48310.svg)


## CVE-2022-48309
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nitschSB/CVE-2022-48309-and-CVE-2022-48310](https://github.com/nitschSB/CVE-2022-48309-and-CVE-2022-48310) :  ![starts](https://img.shields.io/github/stars/nitschSB/CVE-2022-48309-and-CVE-2022-48310.svg) ![forks](https://img.shields.io/github/forks/nitschSB/CVE-2022-48309-and-CVE-2022-48310.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/Habib0x0/CVE-2022-46169](https://github.com/Habib0x0/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/Habib0x0/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/Habib0x0/CVE-2022-46169.svg)


## CVE-2022-40881
 SolarView Compact 6.00 was discovered to contain a command injection vulnerability via network_test.php

- [https://github.com/yilin1203/CVE-2022-40881](https://github.com/yilin1203/CVE-2022-40881) :  ![starts](https://img.shields.io/github/stars/yilin1203/CVE-2022-40881.svg) ![forks](https://img.shields.io/github/forks/yilin1203/CVE-2022-40881.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/Habib0x0/CVE-2022-26134](https://github.com/Habib0x0/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/Habib0x0/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/Habib0x0/CVE-2022-26134.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/polakow/CVE-2022-21907](https://github.com/polakow/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/polakow/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/polakow/CVE-2022-21907.svg)
- [https://github.com/0xmaximus/Home-Demolisher](https://github.com/0xmaximus/Home-Demolisher) :  ![starts](https://img.shields.io/github/stars/0xmaximus/Home-Demolisher.svg) ![forks](https://img.shields.io/github/forks/0xmaximus/Home-Demolisher.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Habib0x0/CVE-2021-41773](https://github.com/Habib0x0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Habib0x0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Habib0x0/CVE-2021-41773.svg)


## CVE-2021-36798
 A Denial-of-Service (DoS) vulnerability was discovered in Team Server in HelpSystems Cobalt Strike 4.2 and 4.3. It allows remote attackers to crash the C2 server thread and block beacons' communication with it.

- [https://github.com/sponkmonk/CobaltSploit](https://github.com/sponkmonk/CobaltSploit) :  ![starts](https://img.shields.io/github/stars/sponkmonk/CobaltSploit.svg) ![forks](https://img.shields.io/github/forks/sponkmonk/CobaltSploit.svg)


## CVE-2021-23358
 The package underscore from 1.13.0-0 and before 1.13.0-2, from 1.3.2 and before 1.12.1 are vulnerable to Arbitrary Code Injection via the template function, particularly when a variable property is passed as an argument as it is not sanitized.

- [https://github.com/EkamSinghWalia/Detection-script-for-cve-2021-23358](https://github.com/EkamSinghWalia/Detection-script-for-cve-2021-23358) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/Detection-script-for-cve-2021-23358.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/Detection-script-for-cve-2021-23358.svg)

