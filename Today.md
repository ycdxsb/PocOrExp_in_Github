# Update 2023-05-22
## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/vdohney/keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper) :  ![starts](https://img.shields.io/github/stars/vdohney/keepass-password-dumper.svg) ![forks](https://img.shields.io/github/forks/vdohney/keepass-password-dumper.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/Ag3nt047/CVE-2023-24055](https://github.com/Ag3nt047/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/Ag3nt047/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/Ag3nt047/CVE-2023-24055.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/antisecc/CVE-2022-46169](https://github.com/antisecc/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/antisecc/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/antisecc/CVE-2022-46169.svg)


## CVE-2022-24716
 Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2` configuration files with database credentials. This issue has been resolved in versions 2.9.6 and 2.10 of Icinga Web 2. Database credentials should be rotated.

- [https://github.com/antisecc/CVE-2022-24716](https://github.com/antisecc/CVE-2022-24716) :  ![starts](https://img.shields.io/github/stars/antisecc/CVE-2022-24716.svg) ![forks](https://img.shields.io/github/forks/antisecc/CVE-2022-24716.svg)


## CVE-2022-4931
 The BackupWordPress plugin for WordPress is vulnerable to information disclosure in versions up to, and including 3.12. This is due to missing authorization on the heartbeat_received() function that triggers on WordPress heartbeat. This makes it possible for authenticated attackers, with subscriber-level permissions and above to retrieve back-up paths that can subsequently be used to download the back-up.

- [https://github.com/ValeDecem10th/CVE-2022-4931](https://github.com/ValeDecem10th/CVE-2022-4931) :  ![starts](https://img.shields.io/github/stars/ValeDecem10th/CVE-2022-4931.svg) ![forks](https://img.shields.io/github/forks/ValeDecem10th/CVE-2022-4931.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-3516
 There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to confidentiality, integrity, and availability.

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-3516](https://github.com/dja2TaqkGEEfA45/CVE-2021-3516) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-3516.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-3516.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/smallkill/CVE-2021-3493](https://github.com/smallkill/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/smallkill/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/smallkill/CVE-2021-3493.svg)


## CVE-2021-3438
 A potential buffer overflow in the software drivers for certain HP LaserJet products and Samsung product printers could lead to an escalation of privilege.

- [https://github.com/Exploitables/CVE-2021-3438](https://github.com/Exploitables/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2021-3438.svg)


## CVE-2020-1206
 An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.

- [https://github.com/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit](https://github.com/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit) :  ![starts](https://img.shields.io/github/stars/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit.svg) ![forks](https://img.shields.io/github/forks/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit.svg)


## CVE-2019-6111
 An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client. However, the scp client only performs cursory validation of the object name returned (only directory traversal attacks are prevented). A malicious scp server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the scp client target directory. If recursive operation (-r) is performed, the server can manipulate subdirectories as well (for example, to overwrite the .ssh/authorized_keys file).

- [https://github.com/AntonVanAssche/CSV-NPE2223](https://github.com/AntonVanAssche/CSV-NPE2223) :  ![starts](https://img.shields.io/github/stars/AntonVanAssche/CSV-NPE2223.svg) ![forks](https://img.shields.io/github/forks/AntonVanAssche/CSV-NPE2223.svg)


## CVE-2018-8210
 A remote code execution vulnerability exists when Windows improperly handles objects in memory, aka &quot;Windows Remote Code Execution Vulnerability.&quot; This affects Windows Server 2012 R2, Windows RT 8.1, Windows Server 2012, Windows Server 2016, Windows 8.1, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8213.

- [https://github.com/rip1s/CVE-2018-8120](https://github.com/rip1s/CVE-2018-8120) :  ![starts](https://img.shields.io/github/stars/rip1s/CVE-2018-8120.svg) ![forks](https://img.shields.io/github/forks/rip1s/CVE-2018-8120.svg)


## CVE-2018-8120
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.

- [https://github.com/rip1s/CVE-2018-8120](https://github.com/rip1s/CVE-2018-8120) :  ![starts](https://img.shields.io/github/stars/rip1s/CVE-2018-8120.svg) ![forks](https://img.shields.io/github/forks/rip1s/CVE-2018-8120.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.

- [https://github.com/rip1s/CVE-2017-11882](https://github.com/rip1s/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/rip1s/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/rip1s/CVE-2017-11882.svg)

