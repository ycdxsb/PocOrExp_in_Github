# Update 2023-05-26
## CVE-2023-32243
 Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.

- [https://github.com/YouGina/CVE-2023-32243](https://github.com/YouGina/CVE-2023-32243) :  ![starts](https://img.shields.io/github/stars/YouGina/CVE-2023-32243.svg) ![forks](https://img.shields.io/github/forks/YouGina/CVE-2023-32243.svg)


## CVE-2023-32163
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LucaBarile/ZDI-CAN-16857](https://github.com/LucaBarile/ZDI-CAN-16857) :  ![starts](https://img.shields.io/github/stars/LucaBarile/ZDI-CAN-16857.svg) ![forks](https://img.shields.io/github/forks/LucaBarile/ZDI-CAN-16857.svg)


## CVE-2023-32162
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LucaBarile/ZDI-CAN-16318](https://github.com/LucaBarile/ZDI-CAN-16318) :  ![starts](https://img.shields.io/github/stars/LucaBarile/ZDI-CAN-16318.svg) ![forks](https://img.shields.io/github/forks/LucaBarile/ZDI-CAN-16318.svg)


## CVE-2023-31747
 Wondershare Filmora 12 (Build 12.2.1.2088) was discovered to contain an unquoted service path vulnerability via the component NativePushService. This vulnerability allows attackers to launch processes with elevated privileges.

- [https://github.com/msd0pe-1/CVE-2023-31747_filmora-unquoted](https://github.com/msd0pe-1/CVE-2023-31747_filmora-unquoted) :  ![starts](https://img.shields.io/github/stars/msd0pe-1/CVE-2023-31747_filmora-unquoted.svg) ![forks](https://img.shields.io/github/forks/msd0pe-1/CVE-2023-31747_filmora-unquoted.svg)


## CVE-2023-31047
 In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible to bypass validation when using one form field to upload multiple files. This multiple upload has never been supported by forms.FileField or forms.ImageField (only the last uploaded file was validated). However, Django's &quot;Uploading multiple files&quot; documentation suggested otherwise.

- [https://github.com/xzsec/Django_rce](https://github.com/xzsec/Django_rce) :  ![starts](https://img.shields.io/github/stars/xzsec/Django_rce.svg) ![forks](https://img.shields.io/github/forks/xzsec/Django_rce.svg)


## CVE-2023-29923
 PowerJob V4.3.1 is vulnerable to Insecure Permissions. via the list job interface.

- [https://github.com/CKevens/CVE-2023-29923-Scan](https://github.com/CKevens/CVE-2023-29923-Scan) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-29923-Scan.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-29923-Scan.svg)


## CVE-2023-29922
 PowerJob V4.3.1 is vulnerable to Incorrect Access Control via the create user/save interface.

- [https://github.com/CKevens/CVE-2023-29923-Scan](https://github.com/CKevens/CVE-2023-29923-Scan) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-29923-Scan.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-29923-Scan.svg)


## CVE-2023-2859
 Code Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.9.

- [https://github.com/mnqazi/CVE-2023-2859](https://github.com/mnqazi/CVE-2023-2859) :  ![starts](https://img.shields.io/github/stars/mnqazi/CVE-2023-2859.svg) ![forks](https://img.shields.io/github/forks/mnqazi/CVE-2023-2859.svg)


## CVE-2023-2591
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in GitHub repository nilsteampassnet/teampass prior to 3.0.7.

- [https://github.com/mnqazi/CVE-2023-2591](https://github.com/mnqazi/CVE-2023-2591) :  ![starts](https://img.shields.io/github/stars/mnqazi/CVE-2023-2591.svg) ![forks](https://img.shields.io/github/forks/mnqazi/CVE-2023-2591.svg)


## CVE-2023-2516
 Cross-site Scripting (XSS) - Stored in GitHub repository nilsteampassnet/teampass prior to 3.0.7.

- [https://github.com/mnqazi/CVE-2023-2516](https://github.com/mnqazi/CVE-2023-2516) :  ![starts](https://img.shields.io/github/stars/mnqazi/CVE-2023-2516.svg) ![forks](https://img.shields.io/github/forks/mnqazi/CVE-2023-2516.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/ahanel13/CVE-2022-4616-POC](https://github.com/ahanel13/CVE-2022-4616-POC) :  ![starts](https://img.shields.io/github/stars/ahanel13/CVE-2022-4616-POC.svg) ![forks](https://img.shields.io/github/forks/ahanel13/CVE-2022-4616-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)
- [https://github.com/open-AIMS/log4j](https://github.com/open-AIMS/log4j) :  ![starts](https://img.shields.io/github/stars/open-AIMS/log4j.svg) ![forks](https://img.shields.io/github/forks/open-AIMS/log4j.svg)


## CVE-2019-8341
 ** DISPUTED ** An issue was discovered in Jinja2 2.10. The from_string function is prone to Server Side Template Injection (SSTI) where it takes the &quot;source&quot; parameter as a template object, renders it, and then returns it. The attacker can exploit it with {{INJECTION COMMANDS}} in a URI. NOTE: The maintainer and multiple third parties believe that this vulnerability isn't valid because users shouldn't use untrusted templates without sandboxing.

- [https://github.com/adindrabkin/llama_facts](https://github.com/adindrabkin/llama_facts) :  ![starts](https://img.shields.io/github/stars/adindrabkin/llama_facts.svg) ![forks](https://img.shields.io/github/forks/adindrabkin/llama_facts.svg)


## CVE-2015-8562
 Joomla! 1.5.x, 2.x, and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header, as exploited in the wild in December 2015.

- [https://github.com/ZaleHack/joomla_rce_CVE-2015-8562](https://github.com/ZaleHack/joomla_rce_CVE-2015-8562) :  ![starts](https://img.shields.io/github/stars/ZaleHack/joomla_rce_CVE-2015-8562.svg) ![forks](https://img.shields.io/github/forks/ZaleHack/joomla_rce_CVE-2015-8562.svg)
- [https://github.com/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC](https://github.com/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC) :  ![starts](https://img.shields.io/github/stars/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC.svg) ![forks](https://img.shields.io/github/forks/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC.svg)

