# Update 2024-03-30
## CVE-2024-21388
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability

- [https://github.com/d0rb/CVE-2024-21388](https://github.com/d0rb/CVE-2024-21388) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2024-21388.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2024-21388.svg)


## CVE-2024-20767
 ColdFusion versions 2023.6, 2021.12 and earlier are affected by an Improper Access Control vulnerability that could lead to arbitrary file system read. An attacker could leverage this vulnerability to bypass security measures and gain unauthorized access to sensitive files and perform arbitrary file system write. Exploitation of this issue does not require user interaction.

- [https://github.com/huyqa/cve-2024-20767](https://github.com/huyqa/cve-2024-20767) :  ![starts](https://img.shields.io/github/stars/huyqa/cve-2024-20767.svg) ![forks](https://img.shields.io/github/forks/huyqa/cve-2024-20767.svg)


## CVE-2024-2193
 A Speculative Race Condition (SRC) vulnerability that impacts modern CPU architectures supporting speculative execution (related to Spectre V1) has been disclosed. An unauthenticated attacker can exploit this vulnerability to disclose arbitrary data from the CPU using race conditions to access the speculative executable code paths.

- [https://github.com/uthrasri/CVE-2024-2193](https://github.com/uthrasri/CVE-2024-2193) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2024-2193.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2024-2193.svg)


## CVE-2023-42789
 A out-of-bounds write in Fortinet FortiOS 7.4.0 through 7.4.1, 7.2.0 through 7.2.5, 7.0.0 through 7.0.12, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, FortiProxy 7.4.0, 7.2.0 through 7.2.6, 7.0.0 through 7.0.12, 2.0.0 through 2.0.13 allows attacker to execute unauthorized code or commands via specially crafted HTTP requests.

- [https://github.com/jhonnybonny/CVE-2023-42789](https://github.com/jhonnybonny/CVE-2023-42789) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2023-42789.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2023-42789.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/mind2hex/CVE-2022-46169](https://github.com/mind2hex/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/mind2hex/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/mind2hex/CVE-2022-46169.svg)


## CVE-2022-39227
 python-jwt is a module for generating and verifying JSON Web Tokens. Versions prior to 3.3.4 are subject to Authentication Bypass by Spoofing, resulting in identity spoofing, session hijacking or authentication bypass. An attacker who obtains a JWT can arbitrarily forge its contents without knowing the secret key. Depending on the application, this may for example enable the attacker to spoof other user's identities, hijack their sessions, or bypass authentication. Users should upgrade to version 3.3.4. There are no known workarounds.

- [https://github.com/NoSpaceAvailable/CVE-2022-39227](https://github.com/NoSpaceAvailable/CVE-2022-39227) :  ![starts](https://img.shields.io/github/stars/NoSpaceAvailable/CVE-2022-39227.svg) ![forks](https://img.shields.io/github/forks/NoSpaceAvailable/CVE-2022-39227.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the &quot;Hardware Layer Code Box&quot; component on the &quot;/hardware&quot; page of the application.

- [https://github.com/thewhiteh4t/cve-2021-31630](https://github.com/thewhiteh4t/cve-2021-31630) :  ![starts](https://img.shields.io/github/stars/thewhiteh4t/cve-2021-31630.svg) ![forks](https://img.shields.io/github/forks/thewhiteh4t/cve-2021-31630.svg)


## CVE-2019-17240
 bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.

- [https://github.com/mind2hex/CVE-2019-17240](https://github.com/mind2hex/CVE-2019-17240) :  ![starts](https://img.shields.io/github/stars/mind2hex/CVE-2019-17240.svg) ![forks](https://img.shields.io/github/forks/mind2hex/CVE-2019-17240.svg)


## CVE-2019-16113
 Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

- [https://github.com/mind2hex/CVE-2019-16113](https://github.com/mind2hex/CVE-2019-16113) :  ![starts](https://img.shields.io/github/stars/mind2hex/CVE-2019-16113.svg) ![forks](https://img.shields.io/github/forks/mind2hex/CVE-2019-16113.svg)


## CVE-2019-1182
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1181, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2019-1181
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2017-16894
 In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.

- [https://github.com/ibnurusdianto/.env-cve2017](https://github.com/ibnurusdianto/.env-cve2017) :  ![starts](https://img.shields.io/github/stars/ibnurusdianto/.env-cve2017.svg) ![forks](https://img.shields.io/github/forks/ibnurusdianto/.env-cve2017.svg)


## CVE-2017-8759
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka &quot;.NET Framework Remote Code Execution Vulnerability.&quot;

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)

