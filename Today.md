# Update 2023-03-14
## CVE-2023-0861
 NetModule NSRW web administration interface executes an OS command constructed with unsanitized user input. A successful exploit could allow an authenticated user to execute arbitrary commands with elevated privileges. This issue affects NSRW: from 4.3.0.0 before 4.3.0.119, from 4.4.0.0 before 4.4.0.118, from 4.6.0.0 before 4.6.0.105, from 4.7.0.0 before 4.7.0.103.

- [https://github.com/seifallahhomrani1/CVE-2023-0861-POC](https://github.com/seifallahhomrani1/CVE-2023-0861-POC) :  ![starts](https://img.shields.io/github/stars/seifallahhomrani1/CVE-2023-0861-POC.svg) ![forks](https://img.shields.io/github/forks/seifallahhomrani1/CVE-2023-0861-POC.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit](https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit) :  ![starts](https://img.shields.io/github/stars/ariyaadinatha/cacti-cve-2022-46169-exploit.svg) ![forks](https://img.shields.io/github/forks/ariyaadinatha/cacti-cve-2022-46169-exploit.svg)


## CVE-2022-30507
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/yosef0x01/CVE-2022-30507-PoC](https://github.com/yosef0x01/CVE-2022-30507-PoC) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2022-30507-PoC.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2022-30507-PoC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/gokul-ramesh/Spring4Shell-PoC-exploit](https://github.com/gokul-ramesh/Spring4Shell-PoC-exploit) :  ![starts](https://img.shields.io/github/stars/gokul-ramesh/Spring4Shell-PoC-exploit.svg) ![forks](https://img.shields.io/github/forks/gokul-ramesh/Spring4Shell-PoC-exploit.svg)


## CVE-2022-20186
 In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A

- [https://github.com/Bariskizilkaya/CVE-2022-20186_CTXZ](https://github.com/Bariskizilkaya/CVE-2022-20186_CTXZ) :  ![starts](https://img.shields.io/github/stars/Bariskizilkaya/CVE-2022-20186_CTXZ.svg) ![forks](https://img.shields.io/github/forks/Bariskizilkaya/CVE-2022-20186_CTXZ.svg)


## CVE-2021-3707
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to unauthorized configuration modification. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3708, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2020-25134
 An issue was discovered in Observium Professional, Enterprise &amp; Community 20.8.10631. It is vulnerable to directory traversal and local file inclusion due to the fact that there is an unrestricted possibility of loading any file with an inc.php extension. Inclusion of other files (even though limited to the mentioned extension) can lead to Remote Code Execution. This can occur via /settings/?format=../ URIs to pages/settings.inc.php.

- [https://github.com/ynsmroztas/CVE-2020-25134](https://github.com/ynsmroztas/CVE-2020-25134) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/CVE-2020-25134.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/CVE-2020-25134.svg)


## CVE-2020-7763
 This affects the package phantom-html-to-pdf before 0.6.1.

- [https://github.com/ossf-cve-benchmark/CVE-2020-7763](https://github.com/ossf-cve-benchmark/CVE-2020-7763) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-7763.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-7763.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP](https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP) :  ![starts](https://img.shields.io/github/stars/xiaokp7/Tomcat_PUT_GUI_EXP.svg) ![forks](https://img.shields.io/github/forks/xiaokp7/Tomcat_PUT_GUI_EXP.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/MrG3P5/CVE-2017-9841](https://github.com/MrG3P5/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/MrG3P5/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/MrG3P5/CVE-2017-9841.svg)


## CVE-2014-5460
 Unrestricted file upload vulnerability in the Tribulant Slideshow Gallery plugin before 1.4.7 for WordPress allows remote authenticated users to execute arbitrary code by uploading a PHP file, then accessing it via a direct request to the file in wp-content/uploads/slideshow-gallery/.

- [https://github.com/brookeses69/CVE-2014-5460](https://github.com/brookeses69/CVE-2014-5460) :  ![starts](https://img.shields.io/github/stars/brookeses69/CVE-2014-5460.svg) ![forks](https://img.shields.io/github/forks/brookeses69/CVE-2014-5460.svg)

