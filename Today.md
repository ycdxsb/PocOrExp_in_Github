# Update 2023-04-09
## CVE-2023-29478
 BiblioCraft before 2.4.6 does not sanitize path-traversal characters in filenames, allowing restricted write access to almost anywhere on the filesystem. This includes the Minecraft mods folder, which results in code execution.

- [https://github.com/Exopteron/BiblioRCE](https://github.com/Exopteron/BiblioRCE) :  ![starts](https://img.shields.io/github/stars/Exopteron/BiblioRCE.svg) ![forks](https://img.shields.io/github/forks/Exopteron/BiblioRCE.svg)


## CVE-2023-29017
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. Prior to version 3.9.15, vm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors. A threat actor could bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.15 of vm2. There are no known workarounds.

- [https://github.com/timb-machine-mirrors/gist-seongil-wi-CVE-2023-29017](https://github.com/timb-machine-mirrors/gist-seongil-wi-CVE-2023-29017) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/gist-seongil-wi-CVE-2023-29017.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/gist-seongil-wi-CVE-2023-29017.svg)


## CVE-2023-27100
 Improper restriction of excessive authentication attempts in the SSHGuard component of Netgate pfSense Plus software v22.05.1 and pfSense CE software v2.6.0 allows attackers to bypass brute force protection mechanisms via crafted web requests.

- [https://github.com/DarokNET/CVE-2023-27100](https://github.com/DarokNET/CVE-2023-27100) :  ![starts](https://img.shields.io/github/stars/DarokNET/CVE-2023-27100.svg) ![forks](https://img.shields.io/github/forks/DarokNET/CVE-2023-27100.svg)


## CVE-2023-21742
 Microsoft SharePoint Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21744.

- [https://github.com/ohnonoyesyes/CVE-2023-21742](https://github.com/ohnonoyesyes/CVE-2023-21742) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2023-21742.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2023-21742.svg)


## CVE-2023-21389
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sxsuperxuan/Weblogic_CVE-2023-21389](https://github.com/sxsuperxuan/Weblogic_CVE-2023-21389) :  ![starts](https://img.shields.io/github/stars/sxsuperxuan/Weblogic_CVE-2023-21389.svg) ![forks](https://img.shields.io/github/forks/sxsuperxuan/Weblogic_CVE-2023-21389.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/JacobEbben/CVE-2022-46169_unauth_remote_code_execution](https://github.com/JacobEbben/CVE-2022-46169_unauth_remote_code_execution) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2022-46169_unauth_remote_code_execution.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2022-46169_unauth_remote_code_execution.svg)


## CVE-2022-43293
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LucaBarile/CVE-2022-43293](https://github.com/LucaBarile/CVE-2022-43293) :  ![starts](https://img.shields.io/github/stars/LucaBarile/CVE-2022-43293.svg) ![forks](https://img.shields.io/github/forks/LucaBarile/CVE-2022-43293.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/ReachabilityOrg/cve-2022-42889-text4shell-docker](https://github.com/ReachabilityOrg/cve-2022-42889-text4shell-docker) :  ![starts](https://img.shields.io/github/stars/ReachabilityOrg/cve-2022-42889-text4shell-docker.svg) ![forks](https://img.shields.io/github/forks/ReachabilityOrg/cve-2022-42889-text4shell-docker.svg)


## CVE-2022-38604
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LucaBarile/CVE-2022-38604](https://github.com/LucaBarile/CVE-2022-38604) :  ![starts](https://img.shields.io/github/stars/LucaBarile/CVE-2022-38604.svg) ![forks](https://img.shields.io/github/forks/LucaBarile/CVE-2022-38604.svg)


## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/fardinbarashi/PsFix-CVE-2021-34527](https://github.com/fardinbarashi/PsFix-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/fardinbarashi/PsFix-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/fardinbarashi/PsFix-CVE-2021-34527.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/DaMinGshidashi/CVE-2020-2551](https://github.com/DaMinGshidashi/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/DaMinGshidashi/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/DaMinGshidashi/CVE-2020-2551.svg)

