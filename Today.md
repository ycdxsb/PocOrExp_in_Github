# Update 2024-09-06
## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox &lt; 126, Firefox ESR &lt; 115.11, and Thunderbird &lt; 115.11.

- [https://github.com/Masamuneee/CVE-2024-4367-Analysis](https://github.com/Masamuneee/CVE-2024-4367-Analysis) :  ![starts](https://img.shields.io/github/stars/Masamuneee/CVE-2024-4367-Analysis.svg) ![forks](https://img.shields.io/github/forks/Masamuneee/CVE-2024-4367-Analysis.svg)


## CVE-2024-1212
 Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.

- [https://github.com/MuhammadWaseem29/CVE-2024-1212](https://github.com/MuhammadWaseem29/CVE-2024-1212) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2024-1212.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2024-1212.svg)


## CVE-2023-25356
 CoreDial sipXcom up to and including 21.04 is vulnerable to Improper Neutralization of Argument Delimiters in a Command. XMPP users are able to inject arbitrary arguments into a system command, which can be used to read files from, and write files to, the sipXcom server. This can also be leveraged to gain remote command execution.

- [https://github.com/glefait/CVE-2023-25355-25356](https://github.com/glefait/CVE-2023-25355-25356) :  ![starts](https://img.shields.io/github/stars/glefait/CVE-2023-25355-25356.svg) ![forks](https://img.shields.io/github/forks/glefait/CVE-2023-25355-25356.svg)


## CVE-2023-25355
 CoreDial sipXcom up to and including 21.04 is vulnerable to Insecure Permissions. A user who has the ability to run commands as the `daemon` user on a sipXcom server can overwrite a service file, and escalate their privileges to `root`.

- [https://github.com/glefait/CVE-2023-25355-25356](https://github.com/glefait/CVE-2023-25355-25356) :  ![starts](https://img.shields.io/github/stars/glefait/CVE-2023-25355-25356.svg) ![forks](https://img.shields.io/github/forks/glefait/CVE-2023-25355-25356.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/rockyroadonline/CVE-2022-46169](https://github.com/rockyroadonline/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/rockyroadonline/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/rockyroadonline/CVE-2022-46169.svg)


## CVE-2020-13945
 In Apache APISIX, the user enabled the Admin API and deleted the Admin API access IP restriction rules. Eventually, the default token is allowed to access APISIX management data. This affects versions 1.2, 1.3, 1.4, 1.5.

- [https://github.com/Pixelcraftch/CVE-2020-13945-EXPLOIT](https://github.com/Pixelcraftch/CVE-2020-13945-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/Pixelcraftch/CVE-2020-13945-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/Pixelcraftch/CVE-2020-13945-EXPLOIT.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/faqihudin13/CVE-2018-6574](https://github.com/faqihudin13/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/faqihudin13/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/faqihudin13/CVE-2018-6574.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/TheRealCiscoo/Tomcat_CVE201712617](https://github.com/TheRealCiscoo/Tomcat_CVE201712617) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/Tomcat_CVE201712617.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/Tomcat_CVE201712617.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/lizhianyuguangming/TomcatWeakPassChecker](https://github.com/lizhianyuguangming/TomcatWeakPassChecker) :  ![starts](https://img.shields.io/github/stars/lizhianyuguangming/TomcatWeakPassChecker.svg) ![forks](https://img.shields.io/github/forks/lizhianyuguangming/TomcatWeakPassChecker.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/kloutkake/CVE-2017-5638-PoC](https://github.com/kloutkake/CVE-2017-5638-PoC) :  ![starts](https://img.shields.io/github/stars/kloutkake/CVE-2017-5638-PoC.svg) ![forks](https://img.shields.io/github/forks/kloutkake/CVE-2017-5638-PoC.svg)


## CVE-2015-5711
 TIBCO Managed File Transfer Internet Server before 7.2.5, Managed File Transfer Command Center before 7.2.5, Slingshot before 1.9.4, and Vault before 2.0.1 allow remote authenticated users to obtain sensitive information via a crafted HTTP request.

- [https://github.com/TrixSec/CVE-2015-57115](https://github.com/TrixSec/CVE-2015-57115) :  ![starts](https://img.shields.io/github/stars/TrixSec/CVE-2015-57115.svg) ![forks](https://img.shields.io/github/forks/TrixSec/CVE-2015-57115.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/TheRealCiscoo/Shellshock](https://github.com/TheRealCiscoo/Shellshock) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/Shellshock.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/Shellshock.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/everythingBlackkk/vsFTPd-Backdoor-Exploit-CVE-2011-2523-](https://github.com/everythingBlackkk/vsFTPd-Backdoor-Exploit-CVE-2011-2523-) :  ![starts](https://img.shields.io/github/stars/everythingBlackkk/vsFTPd-Backdoor-Exploit-CVE-2011-2523-.svg) ![forks](https://img.shields.io/github/forks/everythingBlackkk/vsFTPd-Backdoor-Exploit-CVE-2011-2523-.svg)

