# Update 2023-11-25
## CVE-2023-44353
 Adobe ColdFusion versions 2023.5 (and earlier) and 2021.11 (and earlier) are affected by an Deserialization of Untrusted Data vulnerability that could result in Arbitrary code execution. Exploitation of this issue does not require user interaction.

- [https://github.com/JC175/CVE-2023-44353-Nuclei-Template](https://github.com/JC175/CVE-2023-44353-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/JC175/CVE-2023-44353-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/JC175/CVE-2023-44353-Nuclei-Template.svg)


## CVE-2023-40037
 Apache NiFi 1.21.0 through 1.23.0 support JDBC and JNDI JMS access in several Processors and Controller Services with connection URL validation that does not provide sufficient protection against crafted inputs. An authenticated and authorized user can bypass connection URL validation using custom input formatting. The resolution enhances connection URL validation and introduces validation for additional related properties. Upgrading to Apache NiFi 1.23.1 is the recommended mitigation.

- [https://github.com/mbadanoiu/CVE-2023-40037](https://github.com/mbadanoiu/CVE-2023-40037) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2023-40037.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2023-40037.svg)


## CVE-2023-34212
 The JndiJmsConnectionFactoryProvider Controller Service, along with the ConsumeJMS and PublishJMS Processors, in Apache NiFi 1.8.0 through 1.21.0 allow an authenticated and authorized user to configure URL and library properties that enable deserialization of untrusted data from a remote location. The resolution validates the JNDI URL and restricts locations to a set of allowed schemes. You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/mbadanoiu/CVE-2023-34212](https://github.com/mbadanoiu/CVE-2023-34212) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2023-34212.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2023-34212.svg)


## CVE-2023-32571
 Dynamic Linq 1.0.7.10 through 1.2.25 before 1.3.0 allows attackers to execute arbitrary code and commands when untrusted input to methods including Where, Select, OrderBy is parsed.

- [https://github.com/Tris0n/CVE-2023-32571-POC](https://github.com/Tris0n/CVE-2023-32571-POC) :  ![starts](https://img.shields.io/github/stars/Tris0n/CVE-2023-32571-POC.svg) ![forks](https://img.shields.io/github/forks/Tris0n/CVE-2023-32571-POC.svg)


## CVE-2023-28252
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/726232111/CVE-2023-28252](https://github.com/726232111/CVE-2023-28252) :  ![starts](https://img.shields.io/github/stars/726232111/CVE-2023-28252.svg) ![forks](https://img.shields.io/github/forks/726232111/CVE-2023-28252.svg)


## CVE-2023-26269
 Apache James server version 3.7.3 and earlier provides a JMX management service without authentication by default. This allows privilege escalation by a malicious local user. Administrators are advised to disable JMX, or set up a JMX password. Note that version 3.7.4 onward will set up a JMX password automatically for Guice users.

- [https://github.com/mbadanoiu/CVE-2023-26269](https://github.com/mbadanoiu/CVE-2023-26269) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2023-26269.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2023-26269.svg)


## CVE-2023-3452
 The Canto plugin for WordPress is vulnerable to Remote File Inclusion in versions up to, and including, 3.0.4 via the 'wp_abspath' parameter. This allows unauthenticated attackers to include and execute arbitrary remote code on the server, provided that allow_url_include is enabled. Local File Inclusion is also possible, albeit less useful because it requires that the attacker be able to upload a malicious php file via FTP or some other means into a directory readable by the web server.

- [https://github.com/leoanggal1/CVE-2023-3452-PoC](https://github.com/leoanggal1/CVE-2023-3452-PoC) :  ![starts](https://img.shields.io/github/stars/leoanggal1/CVE-2023-3452-PoC.svg) ![forks](https://img.shields.io/github/forks/leoanggal1/CVE-2023-3452-PoC.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/0xN7y/CVE-2022-46169](https://github.com/0xN7y/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/0xN7y/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/0xN7y/CVE-2022-46169.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/W01fh4cker/VcenterKit](https://github.com/W01fh4cker/VcenterKit) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/VcenterKit.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/VcenterKit.svg)
- [https://github.com/mamba-2021/EXP-POC](https://github.com/mamba-2021/EXP-POC) :  ![starts](https://img.shields.io/github/stars/mamba-2021/EXP-POC.svg) ![forks](https://img.shields.io/github/forks/mamba-2021/EXP-POC.svg)
- [https://github.com/b4dboy17/CVE-2022-22954](https://github.com/b4dboy17/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/b4dboy17/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/b4dboy17/CVE-2022-22954.svg)
- [https://github.com/nguyenv1nK/CVE-2022-22954](https://github.com/nguyenv1nK/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/nguyenv1nK/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/nguyenv1nK/CVE-2022-22954.svg)


## CVE-2021-46364
 A vulnerability in the Snake YAML parser of Magnolia CMS v6.2.3 and below allows attackers to execute arbitrary code via a crafted YAML file.

- [https://github.com/mbadanoiu/CVE-2021-46364](https://github.com/mbadanoiu/CVE-2021-46364) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2021-46364.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2021-46364.svg)


## CVE-2021-4154
 A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.

- [https://github.com/Markakd/CVE-2021-4154](https://github.com/Markakd/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/Markakd/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/Markakd/CVE-2021-4154.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the &quot;manage files&quot; functionality, which may result in remote code execution.

- [https://github.com/0xN7y/CVE-2020-29607](https://github.com/0xN7y/CVE-2020-29607) :  ![starts](https://img.shields.io/github/stars/0xN7y/CVE-2020-29607.svg) ![forks](https://img.shields.io/github/forks/0xN7y/CVE-2020-29607.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/chleba124/vsftpd-exploit](https://github.com/chleba124/vsftpd-exploit) :  ![starts](https://img.shields.io/github/stars/chleba124/vsftpd-exploit.svg) ![forks](https://img.shields.io/github/forks/chleba124/vsftpd-exploit.svg)

