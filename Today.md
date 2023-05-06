# Update 2023-05-06
## CVE-2023-29007
 Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, a specially crafted `.gitmodules` file with submodule URLs that are longer than 1024 characters can used to exploit a bug in `config.c::git_config_copy_or_rename_section_in_file()`. This bug can be used to inject arbitrary configuration into a user's `$GIT_DIR/config` when attempting to remove the configuration section associated with that submodule. When the attacker injects configuration values which specify executables to run (such as `core.pager`, `core.editor`, `core.sshCommand`, etc.) this can lead to a remote code execution. A fix A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid running `git submodule deinit` on untrusted repositories or without prior inspection of any submodule sections in `$GIT_DIR/config`.

- [https://github.com/x-Defender/git_for_windows-CVE-2023-29007](https://github.com/x-Defender/git_for_windows-CVE-2023-29007) :  ![starts](https://img.shields.io/github/stars/x-Defender/git_for_windows-CVE-2023-29007.svg) ![forks](https://img.shields.io/github/forks/x-Defender/git_for_windows-CVE-2023-29007.svg)


## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.

- [https://github.com/Pari-Malam/CVE-2023-27524](https://github.com/Pari-Malam/CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/Pari-Malam/CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/Pari-Malam/CVE-2023-27524.svg)
- [https://github.com/MaanVader/CVE-2023-27524-POC](https://github.com/MaanVader/CVE-2023-27524-POC) :  ![starts](https://img.shields.io/github/stars/MaanVader/CVE-2023-27524-POC.svg) ![forks](https://img.shields.io/github/forks/MaanVader/CVE-2023-27524-POC.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel&#8217;s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/Satheesh575555/linux-4.19.72_CVE-2023-0386](https://github.com/Satheesh575555/linux-4.19.72_CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/linux-4.19.72_CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/linux-4.19.72_CVE-2023-0386.svg)
- [https://github.com/xkaneiki/CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/xkaneiki/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/xkaneiki/CVE-2023-0386.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/BKreisel/CVE-2022-46169](https://github.com/BKreisel/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/BKreisel/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/BKreisel/CVE-2022-46169.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Slyguyluis92/microsoft-iis-zero-day-exploit-poc](https://github.com/Slyguyluis92/microsoft-iis-zero-day-exploit-poc) :  ![starts](https://img.shields.io/github/stars/Slyguyluis92/microsoft-iis-zero-day-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/Slyguyluis92/microsoft-iis-zero-day-exploit-poc.svg)
- [https://github.com/Slyguyluis92/instagram-zero-day-rce-poc](https://github.com/Slyguyluis92/instagram-zero-day-rce-poc) :  ![starts](https://img.shields.io/github/stars/Slyguyluis92/instagram-zero-day-rce-poc.svg) ![forks](https://img.shields.io/github/forks/Slyguyluis92/instagram-zero-day-rce-poc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/hakivvi/proxylogon](https://github.com/hakivvi/proxylogon) :  ![starts](https://img.shields.io/github/stars/hakivvi/proxylogon.svg) ![forks](https://img.shields.io/github/forks/hakivvi/proxylogon.svg)
- [https://github.com/mekhalleh/exchange_proxylogon](https://github.com/mekhalleh/exchange_proxylogon) :  ![starts](https://img.shields.io/github/stars/mekhalleh/exchange_proxylogon.svg) ![forks](https://img.shields.io/github/forks/mekhalleh/exchange_proxylogon.svg)
- [https://github.com/Immersive-Labs-Sec/ProxyLogon](https://github.com/Immersive-Labs-Sec/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/ProxyLogon.svg)
- [https://github.com/catmandx/CVE-2021-26855-Exchange-RCE](https://github.com/catmandx/CVE-2021-26855-Exchange-RCE) :  ![starts](https://img.shields.io/github/stars/catmandx/CVE-2021-26855-Exchange-RCE.svg) ![forks](https://img.shields.io/github/forks/catmandx/CVE-2021-26855-Exchange-RCE.svg)
- [https://github.com/sotiriskar/CVE-2021-26855](https://github.com/sotiriskar/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/sotiriskar/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/sotiriskar/CVE-2021-26855.svg)


## CVE-2020-1493
 An information disclosure vulnerability exists when attaching files to Outlook messages, aka 'Microsoft Outlook Information Disclosure Vulnerability'.

- [https://github.com/0neb1n/CVE-2020-1493](https://github.com/0neb1n/CVE-2020-1493) :  ![starts](https://img.shields.io/github/stars/0neb1n/CVE-2020-1493.svg) ![forks](https://img.shields.io/github/forks/0neb1n/CVE-2020-1493.svg)


## CVE-2019-16278
 Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.

- [https://github.com/FredBrave/CVE-2019-16278-Nostromo-1.9.6-RCE](https://github.com/FredBrave/CVE-2019-16278-Nostromo-1.9.6-RCE) :  ![starts](https://img.shields.io/github/stars/FredBrave/CVE-2019-16278-Nostromo-1.9.6-RCE.svg) ![forks](https://img.shields.io/github/forks/FredBrave/CVE-2019-16278-Nostromo-1.9.6-RCE.svg)


## CVE-2019-12384
 FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.

- [https://github.com/jas502n/CVE-2019-12384](https://github.com/jas502n/CVE-2019-12384) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-12384.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-12384.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/mclbn/docker-cve-2018-15473](https://github.com/mclbn/docker-cve-2018-15473) :  ![starts](https://img.shields.io/github/stars/mclbn/docker-cve-2018-15473.svg) ![forks](https://img.shields.io/github/forks/mclbn/docker-cve-2018-15473.svg)


## CVE-2018-7449
 SEGGER FTP Server for Windows before 3.22a allows remote attackers to cause a denial of service (daemon crash) via an invalid LIST, STOR, or RETR command.

- [https://github.com/antogit-sys/CVE-2018-7449](https://github.com/antogit-sys/CVE-2018-7449) :  ![starts](https://img.shields.io/github/stars/antogit-sys/CVE-2018-7449.svg) ![forks](https://img.shields.io/github/forks/antogit-sys/CVE-2018-7449.svg)


## CVE-2017-7308
 The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.

- [https://github.com/Nigmaz/CVE-2017-7308](https://github.com/Nigmaz/CVE-2017-7308) :  ![starts](https://img.shields.io/github/stars/Nigmaz/CVE-2017-7308.svg) ![forks](https://img.shields.io/github/forks/Nigmaz/CVE-2017-7308.svg)


## CVE-2016-1209
 The Ninja Forms plugin before 2.9.42.1 for WordPress allows remote attackers to conduct PHP object injection attacks via crafted serialized values in a POST request.

- [https://github.com/LeBlogDuHacker/vulnlab](https://github.com/LeBlogDuHacker/vulnlab) :  ![starts](https://img.shields.io/github/stars/LeBlogDuHacker/vulnlab.svg) ![forks](https://img.shields.io/github/forks/LeBlogDuHacker/vulnlab.svg)


## CVE-2015-6612
 libmedia in Android before 5.1.1 LMY48X and 6.0 before 2015-11-01 allows attackers to gain privileges via a crafted application, aka internal bug 23540426.

- [https://github.com/flankerhqd/cve-2015-6612poc-forM](https://github.com/flankerhqd/cve-2015-6612poc-forM) :  ![starts](https://img.shields.io/github/stars/flankerhqd/cve-2015-6612poc-forM.svg) ![forks](https://img.shields.io/github/forks/flankerhqd/cve-2015-6612poc-forM.svg)


## CVE-2008-5161
 Error handling in the SSH protocol in (1) SSH Tectia Client and Server and Connector 4.0 through 4.4.11, 5.0 through 5.2.4, and 5.3 through 5.3.8; Client and Server and ConnectSecure 6.0 through 6.0.4; Server for Linux on IBM System z 6.0.4; Server for IBM z/OS 5.5.1 and earlier, 6.0.0, and 6.0.1; and Client 4.0-J through 4.3.3-J and 4.0-K through 4.3.10-K; and (2) OpenSSH 4.7p1 and possibly other versions, when using a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to recover certain plaintext data from an arbitrary block of ciphertext in an SSH session via unknown vectors.

- [https://github.com/pankajjarial360/OpenSSH_4.7p1](https://github.com/pankajjarial360/OpenSSH_4.7p1) :  ![starts](https://img.shields.io/github/stars/pankajjarial360/OpenSSH_4.7p1.svg) ![forks](https://img.shields.io/github/forks/pankajjarial360/OpenSSH_4.7p1.svg)


## CVE-2002-0348
 service.cgi in Cobalt RAQ 4 allows remote attackers to cause a denial of service, and possibly execute arbitrary code, via a long service argument.

- [https://github.com/alt3kx/CVE-2002-0348](https://github.com/alt3kx/CVE-2002-0348) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2002-0348.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2002-0348.svg)

