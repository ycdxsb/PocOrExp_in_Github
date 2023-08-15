# Update 2023-08-15
## CVE-2023-27363
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/qwqdanchun/CVE-2023-27363](https://github.com/qwqdanchun/CVE-2023-27363) :  ![starts](https://img.shields.io/github/stars/qwqdanchun/CVE-2023-27363.svg) ![forks](https://img.shields.io/github/forks/qwqdanchun/CVE-2023-27363.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/0xFTW/CVE-2023-27163](https://github.com/0xFTW/CVE-2023-27163) :  ![starts](https://img.shields.io/github/stars/0xFTW/CVE-2023-27163.svg) ![forks](https://img.shields.io/github/forks/0xFTW/CVE-2023-27163.svg)


## CVE-2023-4029
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Halcy0nic/CVE-2023-40294-and-CVE-2023-40295](https://github.com/Halcy0nic/CVE-2023-40294-and-CVE-2023-40295) :  ![starts](https://img.shields.io/github/stars/Halcy0nic/CVE-2023-40294-and-CVE-2023-40295.svg) ![forks](https://img.shields.io/github/forks/Halcy0nic/CVE-2023-40294-and-CVE-2023-40295.svg)
- [https://github.com/Halcy0nic/CVE-2023-40296](https://github.com/Halcy0nic/CVE-2023-40296) :  ![starts](https://img.shields.io/github/stars/Halcy0nic/CVE-2023-40296.svg) ![forks](https://img.shields.io/github/forks/Halcy0nic/CVE-2023-40296.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/N1arut/CVE-2022-46169_POC](https://github.com/N1arut/CVE-2022-46169_POC) :  ![starts](https://img.shields.io/github/stars/N1arut/CVE-2022-46169_POC.svg) ![forks](https://img.shields.io/github/forks/N1arut/CVE-2022-46169_POC.svg)
- [https://github.com/devilgothies/CVE-2022-46169](https://github.com/devilgothies/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/devilgothies/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/devilgothies/CVE-2022-46169.svg)
- [https://github.com/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application](https://github.com/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application) :  ![starts](https://img.shields.io/github/stars/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application.svg)
- [https://github.com/sha-16/RCE-Cacti-1.2.22](https://github.com/sha-16/RCE-Cacti-1.2.22) :  ![starts](https://img.shields.io/github/stars/sha-16/RCE-Cacti-1.2.22.svg) ![forks](https://img.shields.io/github/forks/sha-16/RCE-Cacti-1.2.22.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/h4ck0rman/Spring4Shell-PoC](https://github.com/h4ck0rman/Spring4Shell-PoC) :  ![starts](https://img.shields.io/github/stars/h4ck0rman/Spring4Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/h4ck0rman/Spring4Shell-PoC.svg)


## CVE-2022-3457
 Origin Validation Error in GitHub repository ikus060/rdiffweb prior to 2.5.0a5.

- [https://github.com/Nithisssh/CVE-2022-3457](https://github.com/Nithisssh/CVE-2022-3457) :  ![starts](https://img.shields.io/github/stars/Nithisssh/CVE-2022-3457.svg) ![forks](https://img.shields.io/github/forks/Nithisssh/CVE-2022-3457.svg)


## CVE-2022-1036
 Able to create an account with long password leads to memory corruption / Integer Overflow in GitHub repository microweber/microweber prior to 1.2.12.

- [https://github.com/Nithisssh/CVE-2022-1036](https://github.com/Nithisssh/CVE-2022-1036) :  ![starts](https://img.shields.io/github/stars/Nithisssh/CVE-2022-1036.svg) ![forks](https://img.shields.io/github/forks/Nithisssh/CVE-2022-1036.svg)


## CVE-2022-0688
 Business Logic Errors in Packagist microweber/microweber prior to 1.2.11.

- [https://github.com/Nithisssh/CVE-2022-0688](https://github.com/Nithisssh/CVE-2022-0688) :  ![starts](https://img.shields.io/github/stars/Nithisssh/CVE-2022-0688.svg) ![forks](https://img.shields.io/github/forks/Nithisssh/CVE-2022-0688.svg)


## CVE-2022-0558
 Cross-site Scripting (XSS) - Stored in Packagist microweber/microweber prior to 1.2.11.

- [https://github.com/Nithisssh/CVE-2022-0558](https://github.com/Nithisssh/CVE-2022-0558) :  ![starts](https://img.shields.io/github/stars/Nithisssh/CVE-2022-0558.svg) ![forks](https://img.shields.io/github/forks/Nithisssh/CVE-2022-0558.svg)


## CVE-2022-0379
 Cross-site Scripting (XSS) - Stored in Packagist microweber/microweber prior to 1.2.11.

- [https://github.com/Nithisssh/CVE-2022-0379](https://github.com/Nithisssh/CVE-2022-0379) :  ![starts](https://img.shields.io/github/stars/Nithisssh/CVE-2022-0379.svg) ![forks](https://img.shields.io/github/forks/Nithisssh/CVE-2022-0379.svg)


## CVE-2021-44733
 A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11. This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory object.

- [https://github.com/pjlantz/optee-qemu](https://github.com/pjlantz/optee-qemu) :  ![starts](https://img.shields.io/github/stars/pjlantz/optee-qemu.svg) ![forks](https://img.shields.io/github/forks/pjlantz/optee-qemu.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2020-36184
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.

- [https://github.com/Al1ex/CVE-2020-36184](https://github.com/Al1ex/CVE-2020-36184) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2020-36184.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2020-36184.svg)


## CVE-2020-36109
 ASUS RT-AX86U router firmware below version under 9.0.0.4_386 has a buffer overflow in the blocking_request.cgi function of the httpd module that can cause code execution when an attacker constructs malicious data.

- [https://github.com/sunn1day/CVE-2020-36109-POC](https://github.com/sunn1day/CVE-2020-36109-POC) :  ![starts](https://img.shields.io/github/stars/sunn1day/CVE-2020-36109-POC.svg) ![forks](https://img.shields.io/github/forks/sunn1day/CVE-2020-36109-POC.svg)
- [https://github.com/tin-z/CVE-2020-36109-POC](https://github.com/tin-z/CVE-2020-36109-POC) :  ![starts](https://img.shields.io/github/stars/tin-z/CVE-2020-36109-POC.svg) ![forks](https://img.shields.io/github/forks/tin-z/CVE-2020-36109-POC.svg)


## CVE-2020-3766
 Adobe Genuine Integrity Service versions Version 6.4 and earlier have an insecure file permissions vulnerability. Successful exploitation could lead to privilege escalation.

- [https://github.com/hessandrew/CVE-2020-3766_APSB20-12](https://github.com/hessandrew/CVE-2020-3766_APSB20-12) :  ![starts](https://img.shields.io/github/stars/hessandrew/CVE-2020-3766_APSB20-12.svg) ![forks](https://img.shields.io/github/forks/hessandrew/CVE-2020-3766_APSB20-12.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/mstxq17/cve-2020-1472](https://github.com/mstxq17/cve-2020-1472) :  ![starts](https://img.shields.io/github/stars/mstxq17/cve-2020-1472.svg) ![forks](https://img.shields.io/github/forks/mstxq17/cve-2020-1472.svg)
- [https://github.com/k8gege/CVE-2020-1472-EXP](https://github.com/k8gege/CVE-2020-1472-EXP) :  ![starts](https://img.shields.io/github/stars/k8gege/CVE-2020-1472-EXP.svg) ![forks](https://img.shields.io/github/forks/k8gege/CVE-2020-1472-EXP.svg)
- [https://github.com/jiushill/CVE-2020-1472](https://github.com/jiushill/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/jiushill/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/jiushill/CVE-2020-1472.svg)
- [https://github.com/victim10wq3/CVE-2020-1472](https://github.com/victim10wq3/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/victim10wq3/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/victim10wq3/CVE-2020-1472.svg)
- [https://github.com/guglia001/MassZeroLogon](https://github.com/guglia001/MassZeroLogon) :  ![starts](https://img.shields.io/github/stars/guglia001/MassZeroLogon.svg) ![forks](https://img.shields.io/github/forks/guglia001/MassZeroLogon.svg)
- [https://github.com/Anthonyc3rb3ru5/ZeroLogon-to-Shell](https://github.com/Anthonyc3rb3ru5/ZeroLogon-to-Shell) :  ![starts](https://img.shields.io/github/stars/Anthonyc3rb3ru5/ZeroLogon-to-Shell.svg) ![forks](https://img.shields.io/github/forks/Anthonyc3rb3ru5/ZeroLogon-to-Shell.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/d4rkshell/go-get-rce](https://github.com/d4rkshell/go-get-rce) :  ![starts](https://img.shields.io/github/stars/d4rkshell/go-get-rce.svg) ![forks](https://img.shields.io/github/forks/d4rkshell/go-get-rce.svg)
- [https://github.com/it3x55/CVE-2018-6574](https://github.com/it3x55/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/it3x55/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/it3x55/CVE-2018-6574.svg)
- [https://github.com/yitingfan/CVE-2018-6574_demo](https://github.com/yitingfan/CVE-2018-6574_demo) :  ![starts](https://img.shields.io/github/stars/yitingfan/CVE-2018-6574_demo.svg) ![forks](https://img.shields.io/github/forks/yitingfan/CVE-2018-6574_demo.svg)
- [https://github.com/AnKItdo/CVE_2018-6574](https://github.com/AnKItdo/CVE_2018-6574) :  ![starts](https://img.shields.io/github/stars/AnKItdo/CVE_2018-6574.svg) ![forks](https://img.shields.io/github/forks/AnKItdo/CVE_2018-6574.svg)
- [https://github.com/NikolaT3sla/cve-2018-6574](https://github.com/NikolaT3sla/cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/NikolaT3sla/cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/NikolaT3sla/cve-2018-6574.svg)

