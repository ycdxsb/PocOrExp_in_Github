# Update 2023-05-03
## CVE-2023-23169
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/S4nshine/CVE-2023-23169](https://github.com/S4nshine/CVE-2023-23169) :  ![starts](https://img.shields.io/github/stars/S4nshine/CVE-2023-23169.svg) ![forks](https://img.shields.io/github/forks/S4nshine/CVE-2023-23169.svg)


## CVE-2023-21563
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/Wack0/bitlocker-attacks](https://github.com/Wack0/bitlocker-attacks) :  ![starts](https://img.shields.io/github/stars/Wack0/bitlocker-attacks.svg) ![forks](https://img.shields.io/github/forks/Wack0/bitlocker-attacks.svg)


## CVE-2022-46718
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/biscuitehh/cve-2022-46718-leaky-location](https://github.com/biscuitehh/cve-2022-46718-leaky-location) :  ![starts](https://img.shields.io/github/stars/biscuitehh/cve-2022-46718-leaky-location.svg) ![forks](https://img.shields.io/github/forks/biscuitehh/cve-2022-46718-leaky-location.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22) :  ![starts](https://img.shields.io/github/stars/FredBrave/CVE-2022-46169-CACTI-1.2.22.svg) ![forks](https://img.shields.io/github/forks/FredBrave/CVE-2022-46169-CACTI-1.2.22.svg)
- [https://github.com/Ruycraft1514/CVE-2022-46169](https://github.com/Ruycraft1514/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/Ruycraft1514/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/Ruycraft1514/CVE-2022-46169.svg)
- [https://github.com/sha-16/RCE-Cacti-1.2.22](https://github.com/sha-16/RCE-Cacti-1.2.22) :  ![starts](https://img.shields.io/github/stars/sha-16/RCE-Cacti-1.2.22.svg) ![forks](https://img.shields.io/github/forks/sha-16/RCE-Cacti-1.2.22.svg)


## CVE-2022-29127
 BitLocker Security Feature Bypass Vulnerability.

- [https://github.com/Wack0/bitlocker-attacks](https://github.com/Wack0/bitlocker-attacks) :  ![starts](https://img.shields.io/github/stars/Wack0/bitlocker-attacks.svg) ![forks](https://img.shields.io/github/forks/Wack0/bitlocker-attacks.svg)


## CVE-2022-22048
 BitLocker Security Feature Bypass Vulnerability.

- [https://github.com/Wack0/bitlocker-attacks](https://github.com/Wack0/bitlocker-attacks) :  ![starts](https://img.shields.io/github/stars/Wack0/bitlocker-attacks.svg) ![forks](https://img.shields.io/github/forks/Wack0/bitlocker-attacks.svg)


## CVE-2021-41091
 Moby is an open-source project created by Docker to enable software containerization. A bug was found in Moby (Docker Engine) where the data directory (typically `/var/lib/docker`) contained subdirectories with insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and execute programs. When containers included executable programs with extended permission bits (such as `setuid`), unprivileged Linux users could discover and execute those programs. When the UID of an unprivileged Linux user on the host collided with the file owner or group inside a container, the unprivileged Linux user on the host could discover, read, and modify those files. This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade limit access to the host to trusted users. Limit access to host volumes to trusted containers.

- [https://github.com/UncleJ4ck/CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091) :  ![starts](https://img.shields.io/github/stars/UncleJ4ck/CVE-2021-41091.svg) ![forks](https://img.shields.io/github/forks/UncleJ4ck/CVE-2021-41091.svg)

