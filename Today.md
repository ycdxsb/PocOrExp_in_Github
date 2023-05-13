# Update 2023-05-13
## CVE-2023-28772
 An issue was discovered in the Linux kernel before 5.13.3. lib/seq_buf.c has a seq_buf_putmem_hex buffer overflow.

- [https://github.com/Satheesh575555/linux-4.1.15_CVE-2023-28772](https://github.com/Satheesh575555/linux-4.1.15_CVE-2023-28772) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/linux-4.1.15_CVE-2023-28772.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/linux-4.1.15_CVE-2023-28772.svg)
- [https://github.com/hheeyywweellccoommee/linux-4.1.15_CVE-2023-28772-ipchu](https://github.com/hheeyywweellccoommee/linux-4.1.15_CVE-2023-28772-ipchu) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/linux-4.1.15_CVE-2023-28772-ipchu.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/linux-4.1.15_CVE-2023-28772-ipchu.svg)


## CVE-2023-23638
 A deserialization vulnerability existed when dubbo generic invoke, which could lead to malicious code execution. This issue affects Apache Dubbo 2.7.x version 2.7.21 and prior versions; Apache Dubbo 3.0.x version 3.0.13 and prior versions; Apache Dubbo 3.1.x version 3.1.5 and prior versions.

- [https://github.com/YYHYlh/Apache-Dubbo-CVE-2023-23638-exp](https://github.com/YYHYlh/Apache-Dubbo-CVE-2023-23638-exp) :  ![starts](https://img.shields.io/github/stars/YYHYlh/Apache-Dubbo-CVE-2023-23638-exp.svg) ![forks](https://img.shields.io/github/forks/YYHYlh/Apache-Dubbo-CVE-2023-23638-exp.svg)


## CVE-2023-0461
 There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this socket is disconnected and reused as a listener. If a new socket is created from the listener, the context is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c

- [https://github.com/hheeyywweellccoommee/linux-4.19.72_CVE-2023-0461-ycnbd](https://github.com/hheeyywweellccoommee/linux-4.19.72_CVE-2023-0461-ycnbd) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/linux-4.19.72_CVE-2023-0461-ycnbd.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/linux-4.19.72_CVE-2023-0461-ycnbd.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/ahanel13/ImprovedShell-for-CVE-2022-46169](https://github.com/ahanel13/ImprovedShell-for-CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/ahanel13/ImprovedShell-for-CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/ahanel13/ImprovedShell-for-CVE-2022-46169.svg)


## CVE-2022-30114
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/str0ng4le/CVE-2022-30114](https://github.com/str0ng4le/CVE-2022-30114) :  ![starts](https://img.shields.io/github/stars/str0ng4le/CVE-2022-30114.svg) ![forks](https://img.shields.io/github/forks/str0ng4le/CVE-2022-30114.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/4bhishek0/CVE-2022-0847-Poc](https://github.com/4bhishek0/CVE-2022-0847-Poc) :  ![starts](https://img.shields.io/github/stars/4bhishek0/CVE-2022-0847-Poc.svg) ![forks](https://img.shields.io/github/forks/4bhishek0/CVE-2022-0847-Poc.svg)
- [https://github.com/s3mPr1linux/CVE_2022_0847](https://github.com/s3mPr1linux/CVE_2022_0847) :  ![starts](https://img.shields.io/github/stars/s3mPr1linux/CVE_2022_0847.svg) ![forks](https://img.shields.io/github/forks/s3mPr1linux/CVE_2022_0847.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/FAOG99/GrafanaDirectoryScanner](https://github.com/FAOG99/GrafanaDirectoryScanner) :  ![starts](https://img.shields.io/github/stars/FAOG99/GrafanaDirectoryScanner.svg) ![forks](https://img.shields.io/github/forks/FAOG99/GrafanaDirectoryScanner.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)
- [https://github.com/K3ysTr0K3R/CVE-2021-41773-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-41773-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-41773-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-41773-EXPLOIT.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/mutur4/CVE-2021-3156](https://github.com/mutur4/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-3156.svg)


## CVE-2019-7839
 ColdFusion versions Update 3 and earlier, Update 10 and earlier, and Update 18 and earlier have a command injection vulnerability. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/securifera/CVE-2019-7839](https://github.com/securifera/CVE-2019-7839) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2019-7839.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2019-7839.svg)


## CVE-2019-7616
 Kibana versions before 6.8.2 and 7.2.1 contain a server side request forgery (SSRF) flaw in the graphite integration for Timelion visualizer. An attacker with administrative Kibana access could set the timelion:graphite.url configuration option to an arbitrary URL. This could possibly lead to an attacker accessing external URL resources as the Kibana process on the host system.

- [https://github.com/random-robbie/CVE-2019-7616](https://github.com/random-robbie/CVE-2019-7616) :  ![starts](https://img.shields.io/github/stars/random-robbie/CVE-2019-7616.svg) ![forks](https://img.shields.io/github/forks/random-robbie/CVE-2019-7616.svg)


## CVE-2019-7610
 Kibana versions before 6.6.1 contain an arbitrary code execution flaw in the security audit logger. If a Kibana instance has the setting xpack.security.audit.enabled set to true, an attacker could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/whoami0622/CVE-2019-7610](https://github.com/whoami0622/CVE-2019-7610) :  ![starts](https://img.shields.io/github/stars/whoami0622/CVE-2019-7610.svg) ![forks](https://img.shields.io/github/forks/whoami0622/CVE-2019-7610.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/LandGrey/CVE-2019-7609](https://github.com/LandGrey/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/LandGrey/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/LandGrey/CVE-2019-7609.svg)
- [https://github.com/jas502n/kibana-RCE](https://github.com/jas502n/kibana-RCE) :  ![starts](https://img.shields.io/github/stars/jas502n/kibana-RCE.svg) ![forks](https://img.shields.io/github/forks/jas502n/kibana-RCE.svg)
- [https://github.com/mpgn/CVE-2019-7609](https://github.com/mpgn/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/mpgn/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/mpgn/CVE-2019-7609.svg)
- [https://github.com/hekadan/CVE-2019-7609](https://github.com/hekadan/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/hekadan/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/hekadan/CVE-2019-7609.svg)
- [https://github.com/Cr4ckC4t/cve-2019-7609](https://github.com/Cr4ckC4t/cve-2019-7609) :  ![starts](https://img.shields.io/github/stars/Cr4ckC4t/cve-2019-7609.svg) ![forks](https://img.shields.io/github/forks/Cr4ckC4t/cve-2019-7609.svg)
- [https://github.com/rhbb/CVE-2019-7609](https://github.com/rhbb/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/rhbb/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/rhbb/CVE-2019-7609.svg)
- [https://github.com/dnr6419/CVE-2019-7609](https://github.com/dnr6419/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2019-7609.svg)
- [https://github.com/wolf1892/CVE-2019-7609](https://github.com/wolf1892/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2019-7609.svg)


## CVE-2019-7489
 A vulnerability in SonicWall Email Security appliance allow an unauthenticated user to perform remote code execution. This vulnerability affected Email Security Appliance version 10.0.2 and earlier.

- [https://github.com/nromsdahl/CVE-2019-7489](https://github.com/nromsdahl/CVE-2019-7489) :  ![starts](https://img.shields.io/github/stars/nromsdahl/CVE-2019-7489.svg) ![forks](https://img.shields.io/github/forks/nromsdahl/CVE-2019-7489.svg)


## CVE-2019-7406
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2019-7356
 Subrion CMS v4.2.1 allows XSS via the panel/phrases/ VALUE parameter.

- [https://github.com/ngpentest007/CVE-2019-7356](https://github.com/ngpentest007/CVE-2019-7356) :  ![starts](https://img.shields.io/github/stars/ngpentest007/CVE-2019-7356.svg) ![forks](https://img.shields.io/github/forks/ngpentest007/CVE-2019-7356.svg)


## CVE-2019-7238
 Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.

- [https://github.com/mpgn/CVE-2019-7238](https://github.com/mpgn/CVE-2019-7238) :  ![starts](https://img.shields.io/github/stars/mpgn/CVE-2019-7238.svg) ![forks](https://img.shields.io/github/forks/mpgn/CVE-2019-7238.svg)
- [https://github.com/jas502n/CVE-2019-7238](https://github.com/jas502n/CVE-2019-7238) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-7238.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-7238.svg)
- [https://github.com/verctor/nexus_rce_CVE-2019-7238](https://github.com/verctor/nexus_rce_CVE-2019-7238) :  ![starts](https://img.shields.io/github/stars/verctor/nexus_rce_CVE-2019-7238.svg) ![forks](https://img.shields.io/github/forks/verctor/nexus_rce_CVE-2019-7238.svg)
- [https://github.com/magicming200/CVE-2019-7238_Nexus_RCE_Tool](https://github.com/magicming200/CVE-2019-7238_Nexus_RCE_Tool) :  ![starts](https://img.shields.io/github/stars/magicming200/CVE-2019-7238_Nexus_RCE_Tool.svg) ![forks](https://img.shields.io/github/forks/magicming200/CVE-2019-7238_Nexus_RCE_Tool.svg)
- [https://github.com/smallpiggy/CVE-2019-7238](https://github.com/smallpiggy/CVE-2019-7238) :  ![starts](https://img.shields.io/github/stars/smallpiggy/CVE-2019-7238.svg) ![forks](https://img.shields.io/github/forks/smallpiggy/CVE-2019-7238.svg)


## CVE-2019-7219
 Unauthenticated reflected cross-site scripting (XSS) exists in Zarafa Webapp 2.0.1.47791 and earlier. NOTE: this is a discontinued product. The issue was fixed in later Zarafa Webapp versions; however, some former Zarafa Webapp customers use the related Kopano product instead.

- [https://github.com/verifysecurity/CVE-2019-7219](https://github.com/verifysecurity/CVE-2019-7219) :  ![starts](https://img.shields.io/github/stars/verifysecurity/CVE-2019-7219.svg) ![forks](https://img.shields.io/github/forks/verifysecurity/CVE-2019-7219.svg)


## CVE-2019-7216
 An issue was discovered in FileChucker 4.99e-free-e02. filechucker.cgi has a filter bypass that allows a malicious user to upload any type of file by using % characters within the extension, e.g., file.%ph%p becomes file.php.

- [https://github.com/Ekultek/CVE-2019-7216](https://github.com/Ekultek/CVE-2019-7216) :  ![starts](https://img.shields.io/github/stars/Ekultek/CVE-2019-7216.svg) ![forks](https://img.shields.io/github/forks/Ekultek/CVE-2019-7216.svg)


## CVE-2019-7192
 This improper access control vulnerability allows remote attackers to gain unauthorized access to the system. To fix these vulnerabilities, QNAP recommend updating Photo Station to their latest versions.

- [https://github.com/th3gundy/CVE-2019-7192_QNAP_Exploit](https://github.com/th3gundy/CVE-2019-7192_QNAP_Exploit) :  ![starts](https://img.shields.io/github/stars/th3gundy/CVE-2019-7192_QNAP_Exploit.svg) ![forks](https://img.shields.io/github/forks/th3gundy/CVE-2019-7192_QNAP_Exploit.svg)
- [https://github.com/cycraft-corp/cve-2019-7192-check](https://github.com/cycraft-corp/cve-2019-7192-check) :  ![starts](https://img.shields.io/github/stars/cycraft-corp/cve-2019-7192-check.svg) ![forks](https://img.shields.io/github/forks/cycraft-corp/cve-2019-7192-check.svg)


## CVE-2019-6977
 gdImageColorMatch in gd_color_match.c in the GD Graphics Library (aka LibGD) 2.2.5, as used in the imagecolormatch function in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1, has a heap-based buffer overflow. This can be exploited by an attacker who is able to trigger imagecolormatch calls with crafted image data.

- [https://github.com/ozkanbilge/Apache-Exploit-2019](https://github.com/ozkanbilge/Apache-Exploit-2019) :  ![starts](https://img.shields.io/github/stars/ozkanbilge/Apache-Exploit-2019.svg) ![forks](https://img.shields.io/github/forks/ozkanbilge/Apache-Exploit-2019.svg)


## CVE-2019-6715
 pub/sns.php in the W3 Total Cache plugin before 0.9.4 for WordPress allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data.

- [https://github.com/random-robbie/cve-2019-6715](https://github.com/random-robbie/cve-2019-6715) :  ![starts](https://img.shields.io/github/stars/random-robbie/cve-2019-6715.svg) ![forks](https://img.shields.io/github/forks/random-robbie/cve-2019-6715.svg)


## CVE-2019-6453
 mIRC before 7.55 allows remote command execution by using argument injection through custom URI protocol handlers. The attacker can specify an irc:// URI that loads an arbitrary .ini file from a UNC share pathname. Exploitation depends on browser-specific URI handling (Chrome is not exploitable).

- [https://github.com/andripwn/mIRC-CVE-2019-6453](https://github.com/andripwn/mIRC-CVE-2019-6453) :  ![starts](https://img.shields.io/github/stars/andripwn/mIRC-CVE-2019-6453.svg) ![forks](https://img.shields.io/github/forks/andripwn/mIRC-CVE-2019-6453.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/fs0c131y/ESFileExplorerOpenPortVuln](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln) :  ![starts](https://img.shields.io/github/stars/fs0c131y/ESFileExplorerOpenPortVuln.svg) ![forks](https://img.shields.io/github/forks/fs0c131y/ESFileExplorerOpenPortVuln.svg)
- [https://github.com/Nehal-Zaman/CVE-2019-6447](https://github.com/Nehal-Zaman/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/Nehal-Zaman/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/Nehal-Zaman/CVE-2019-6447.svg)
- [https://github.com/Chethine/EsFileExplorer-CVE-2019-6447](https://github.com/Chethine/EsFileExplorer-CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/Chethine/EsFileExplorer-CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/Chethine/EsFileExplorer-CVE-2019-6447.svg)
- [https://github.com/vino-theva/CVE-2019-6447](https://github.com/vino-theva/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/vino-theva/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/vino-theva/CVE-2019-6447.svg)
- [https://github.com/Kayky-cmd/CVE-2019-6447--.](https://github.com/Kayky-cmd/CVE-2019-6447--.) :  ![starts](https://img.shields.io/github/stars/Kayky-cmd/CVE-2019-6447--..svg) ![forks](https://img.shields.io/github/forks/Kayky-cmd/CVE-2019-6447--..svg)
- [https://github.com/Osuni-99/CVE-2019-6447](https://github.com/Osuni-99/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/Osuni-99/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/Osuni-99/CVE-2019-6447.svg)
- [https://github.com/c1ph3rm4st3r/CVE-2019-6447](https://github.com/c1ph3rm4st3r/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/c1ph3rm4st3r/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/c1ph3rm4st3r/CVE-2019-6447.svg)
- [https://github.com/volysandro/cve_2019-6447](https://github.com/volysandro/cve_2019-6447) :  ![starts](https://img.shields.io/github/stars/volysandro/cve_2019-6447.svg) ![forks](https://img.shields.io/github/forks/volysandro/cve_2019-6447.svg)
- [https://github.com/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447](https://github.com/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447.svg)
- [https://github.com/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation](https://github.com/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation) :  ![starts](https://img.shields.io/github/stars/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation.svg) ![forks](https://img.shields.io/github/forks/KasunPriyashan/CVE-2019_6447-ES-File-Explorer-Exploitation.svg)
- [https://github.com/VinuKalana/CVE-2019-6447-Android-Vulnerability-in-ES-File-Explorer](https://github.com/VinuKalana/CVE-2019-6447-Android-Vulnerability-in-ES-File-Explorer) :  ![starts](https://img.shields.io/github/stars/VinuKalana/CVE-2019-6447-Android-Vulnerability-in-ES-File-Explorer.svg) ![forks](https://img.shields.io/github/forks/VinuKalana/CVE-2019-6447-Android-Vulnerability-in-ES-File-Explorer.svg)
- [https://github.com/febinrev/CVE-2019-6447-ESfile-explorer-exploit](https://github.com/febinrev/CVE-2019-6447-ESfile-explorer-exploit) :  ![starts](https://img.shields.io/github/stars/febinrev/CVE-2019-6447-ESfile-explorer-exploit.svg) ![forks](https://img.shields.io/github/forks/febinrev/CVE-2019-6447-ESfile-explorer-exploit.svg)
- [https://github.com/KaviDk/CVE-2019-6447-in-Mobile-Application](https://github.com/KaviDk/CVE-2019-6447-in-Mobile-Application) :  ![starts](https://img.shields.io/github/stars/KaviDk/CVE-2019-6447-in-Mobile-Application.svg) ![forks](https://img.shields.io/github/forks/KaviDk/CVE-2019-6447-in-Mobile-Application.svg)
- [https://github.com/SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447](https://github.com/SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447.svg)


## CVE-2019-6440
 Zemana AntiMalware before 3.0.658 Beta mishandles update logic.

- [https://github.com/hexnone/CVE-2019-6440](https://github.com/hexnone/CVE-2019-6440) :  ![starts](https://img.shields.io/github/stars/hexnone/CVE-2019-6440.svg) ![forks](https://img.shields.io/github/forks/hexnone/CVE-2019-6440.svg)


## CVE-2019-6340
 Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/jas502n/CVE-2019-6340](https://github.com/jas502n/CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-6340.svg)
- [https://github.com/knqyf263/CVE-2019-6340](https://github.com/knqyf263/CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2019-6340.svg)
- [https://github.com/g0rx/Drupal-SA-CORE-2019-003](https://github.com/g0rx/Drupal-SA-CORE-2019-003) :  ![starts](https://img.shields.io/github/stars/g0rx/Drupal-SA-CORE-2019-003.svg) ![forks](https://img.shields.io/github/forks/g0rx/Drupal-SA-CORE-2019-003.svg)
- [https://github.com/oways/CVE-2019-6340](https://github.com/oways/CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/oways/CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/oways/CVE-2019-6340.svg)
- [https://github.com/ludy-dev/drupal8-REST-RCE](https://github.com/ludy-dev/drupal8-REST-RCE) :  ![starts](https://img.shields.io/github/stars/ludy-dev/drupal8-REST-RCE.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/drupal8-REST-RCE.svg)
- [https://github.com/DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass](https://github.com/DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass.svg)
- [https://github.com/cved-sources/cve-2019-6340](https://github.com/cved-sources/cve-2019-6340) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2019-6340.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2019-6340.svg)
- [https://github.com/honeybot/wtf-plugin-honeybot-cve_2019_6340](https://github.com/honeybot/wtf-plugin-honeybot-cve_2019_6340) :  ![starts](https://img.shields.io/github/stars/honeybot/wtf-plugin-honeybot-cve_2019_6340.svg) ![forks](https://img.shields.io/github/forks/honeybot/wtf-plugin-honeybot-cve_2019_6340.svg)
- [https://github.com/josehelps/cve-2019-6340-bits](https://github.com/josehelps/cve-2019-6340-bits) :  ![starts](https://img.shields.io/github/stars/josehelps/cve-2019-6340-bits.svg) ![forks](https://img.shields.io/github/forks/josehelps/cve-2019-6340-bits.svg)
- [https://github.com/nobodyatall648/CVE-2019-6340](https://github.com/nobodyatall648/CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2019-6340.svg)


## CVE-2019-6260
 The ASPEED ast2400 and ast2500 Baseband Management Controller (BMC) hardware and firmware implement Advanced High-performance Bus (AHB) bridges, which allow arbitrary read and write access to the BMC's physical address space from the host (or from the network in unusual cases where the BMC console uart is attached to a serial concentrator). This CVE applies to the specific cases of iLPC2AHB bridge Pt I, iLPC2AHB bridge Pt II, PCIe VGA P2A bridge, DMA from/to arbitrary BMC memory via X-DMA, UART-based SoC Debug interface, LPC2AHB bridge, PCIe BMC P2A bridge, and Watchdog setup.

- [https://github.com/nikitapbst/cve-2019-6260](https://github.com/nikitapbst/cve-2019-6260) :  ![starts](https://img.shields.io/github/stars/nikitapbst/cve-2019-6260.svg) ![forks](https://img.shields.io/github/forks/nikitapbst/cve-2019-6260.svg)


## CVE-2019-6249
 An issue was discovered in HuCart v5.7.4. There is a CSRF vulnerability that can add an admin account via /adminsys/index.php?load=admins&amp;act=edit_info&amp;act_type=add.

- [https://github.com/AlphabugX/CVE-2019-6249_Hucart-cms](https://github.com/AlphabugX/CVE-2019-6249_Hucart-cms) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2019-6249_Hucart-cms.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2019-6249_Hucart-cms.svg)


## CVE-2019-5827
 Integer overflow in SQLite via WebSQL in Google Chrome prior to 74.0.3729.131 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/farif/cve_2019-5827](https://github.com/farif/cve_2019-5827) :  ![starts](https://img.shields.io/github/stars/farif/cve_2019-5827.svg) ![forks](https://img.shields.io/github/forks/farif/cve_2019-5827.svg)


## CVE-2019-5822
 Inappropriate implementation in Blink in Google Chrome prior to 74.0.3729.108 allowed a remote attacker to bypass same origin policy via a crafted HTML page.

- [https://github.com/Silence-Rain/14-828_Exploitation_of_CVE-2019-5822](https://github.com/Silence-Rain/14-828_Exploitation_of_CVE-2019-5822) :  ![starts](https://img.shields.io/github/stars/Silence-Rain/14-828_Exploitation_of_CVE-2019-5822.svg) ![forks](https://img.shields.io/github/forks/Silence-Rain/14-828_Exploitation_of_CVE-2019-5822.svg)


## CVE-2019-5791
 Inappropriate optimization in V8 in Google Chrome prior to 73.0.3683.75 allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page.

- [https://github.com/cosdong7/chromium-v8-exploit](https://github.com/cosdong7/chromium-v8-exploit) :  ![starts](https://img.shields.io/github/stars/cosdong7/chromium-v8-exploit.svg) ![forks](https://img.shields.io/github/forks/cosdong7/chromium-v8-exploit.svg)


## CVE-2019-5737
 In Node.js including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1, an attacker can cause a Denial of Service (DoS) by establishing an HTTP or HTTPS connection in keep-alive mode and by sending headers very slowly. This keeps the connection and associated resources alive for a long period of time. Potential attacks are mitigated by the use of a load balancer or other proxy layer. This vulnerability is an extension of CVE-2018-12121, addressed in November and impacts all active Node.js release lines including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1.

- [https://github.com/beelzebruh/cve-2019-5737](https://github.com/beelzebruh/cve-2019-5737) :  ![starts](https://img.shields.io/github/stars/beelzebruh/cve-2019-5737.svg) ![forks](https://img.shields.io/github/forks/beelzebruh/cve-2019-5737.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/Frichetten/CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC) :  ![starts](https://img.shields.io/github/stars/Frichetten/CVE-2019-5736-PoC.svg) ![forks](https://img.shields.io/github/forks/Frichetten/CVE-2019-5736-PoC.svg)
- [https://github.com/q3k/cve-2019-5736-poc](https://github.com/q3k/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/q3k/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/q3k/cve-2019-5736-poc.svg)
- [https://github.com/twistlock/RunC-CVE-2019-5736](https://github.com/twistlock/RunC-CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/twistlock/RunC-CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/twistlock/RunC-CVE-2019-5736.svg)
- [https://github.com/jas502n/CVE-2019-5736](https://github.com/jas502n/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-5736.svg)
- [https://github.com/agppp/cve-2019-5736-poc](https://github.com/agppp/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/agppp/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/agppp/cve-2019-5736-poc.svg)
- [https://github.com/epsteina16/Docker-Escape-Miner](https://github.com/epsteina16/Docker-Escape-Miner) :  ![starts](https://img.shields.io/github/stars/epsteina16/Docker-Escape-Miner.svg) ![forks](https://img.shields.io/github/forks/epsteina16/Docker-Escape-Miner.svg)
- [https://github.com/milloni/cve-2019-5736-exp](https://github.com/milloni/cve-2019-5736-exp) :  ![starts](https://img.shields.io/github/stars/milloni/cve-2019-5736-exp.svg) ![forks](https://img.shields.io/github/forks/milloni/cve-2019-5736-exp.svg)
- [https://github.com/likescam/CVE-2019-5736](https://github.com/likescam/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2019-5736.svg)
- [https://github.com/b3d3c/poc-cve-2019-5736](https://github.com/b3d3c/poc-cve-2019-5736) :  ![starts](https://img.shields.io/github/stars/b3d3c/poc-cve-2019-5736.svg) ![forks](https://img.shields.io/github/forks/b3d3c/poc-cve-2019-5736.svg)
- [https://github.com/GiverOfGifts/CVE-2019-5736-Custom-Runtime](https://github.com/GiverOfGifts/CVE-2019-5736-Custom-Runtime) :  ![starts](https://img.shields.io/github/stars/GiverOfGifts/CVE-2019-5736-Custom-Runtime.svg) ![forks](https://img.shields.io/github/forks/GiverOfGifts/CVE-2019-5736-Custom-Runtime.svg)
- [https://github.com/panzouh/Docker-Runc-Exploit](https://github.com/panzouh/Docker-Runc-Exploit) :  ![starts](https://img.shields.io/github/stars/panzouh/Docker-Runc-Exploit.svg) ![forks](https://img.shields.io/github/forks/panzouh/Docker-Runc-Exploit.svg)
- [https://github.com/RyanNgWH/CVE-2019-5736-POC](https://github.com/RyanNgWH/CVE-2019-5736-POC) :  ![starts](https://img.shields.io/github/stars/RyanNgWH/CVE-2019-5736-POC.svg) ![forks](https://img.shields.io/github/forks/RyanNgWH/CVE-2019-5736-POC.svg)
- [https://github.com/shen54/IT19172088](https://github.com/shen54/IT19172088) :  ![starts](https://img.shields.io/github/stars/shen54/IT19172088.svg) ![forks](https://img.shields.io/github/forks/shen54/IT19172088.svg)
- [https://github.com/zyriuse75/CVE-2019-5736-PoC](https://github.com/zyriuse75/CVE-2019-5736-PoC) :  ![starts](https://img.shields.io/github/stars/zyriuse75/CVE-2019-5736-PoC.svg) ![forks](https://img.shields.io/github/forks/zyriuse75/CVE-2019-5736-PoC.svg)
- [https://github.com/geropl/CVE-2019-5736](https://github.com/geropl/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/geropl/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/geropl/CVE-2019-5736.svg)
- [https://github.com/si1ent-le/CVE-2019-5736](https://github.com/si1ent-le/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/si1ent-le/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/si1ent-le/CVE-2019-5736.svg)
- [https://github.com/takumak/cve-2019-5736-reproducer](https://github.com/takumak/cve-2019-5736-reproducer) :  ![starts](https://img.shields.io/github/stars/takumak/cve-2019-5736-reproducer.svg) ![forks](https://img.shields.io/github/forks/takumak/cve-2019-5736-reproducer.svg)
- [https://github.com/BBRathnayaka/POC-CVE-2019-5736](https://github.com/BBRathnayaka/POC-CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/BBRathnayaka/POC-CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/BBRathnayaka/POC-CVE-2019-5736.svg)
- [https://github.com/chosam2/cve-2019-5736-poc](https://github.com/chosam2/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/chosam2/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/chosam2/cve-2019-5736-poc.svg)
- [https://github.com/likescam/cve-2019-5736-poc](https://github.com/likescam/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/likescam/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/likescam/cve-2019-5736-poc.svg)
- [https://github.com/Asbatel/CVE-2019-5736_POC](https://github.com/Asbatel/CVE-2019-5736_POC) :  ![starts](https://img.shields.io/github/stars/Asbatel/CVE-2019-5736_POC.svg) ![forks](https://img.shields.io/github/forks/Asbatel/CVE-2019-5736_POC.svg)
- [https://github.com/Lee-SungYoung/cve-2019-5736-study](https://github.com/Lee-SungYoung/cve-2019-5736-study) :  ![starts](https://img.shields.io/github/stars/Lee-SungYoung/cve-2019-5736-study.svg) ![forks](https://img.shields.io/github/forks/Lee-SungYoung/cve-2019-5736-study.svg)
- [https://github.com/stillan00b/CVE-2019-5736](https://github.com/stillan00b/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/stillan00b/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/stillan00b/CVE-2019-5736.svg)
- [https://github.com/c1ph3rm4st3r/CVE-2019-5736](https://github.com/c1ph3rm4st3r/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/c1ph3rm4st3r/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/c1ph3rm4st3r/CVE-2019-5736.svg)
- [https://github.com/GiovanniCrudo00/Docker-Vulnerabilities-CVE-2019-5736](https://github.com/GiovanniCrudo00/Docker-Vulnerabilities-CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/GiovanniCrudo00/Docker-Vulnerabilities-CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/GiovanniCrudo00/Docker-Vulnerabilities-CVE-2019-5736.svg)
- [https://github.com/Billith/CVE-2019-5736-PoC](https://github.com/Billith/CVE-2019-5736-PoC) :  ![starts](https://img.shields.io/github/stars/Billith/CVE-2019-5736-PoC.svg) ![forks](https://img.shields.io/github/forks/Billith/CVE-2019-5736-PoC.svg)
- [https://github.com/yyqs2008/CVE-2019-5736-PoC-2](https://github.com/yyqs2008/CVE-2019-5736-PoC-2) :  ![starts](https://img.shields.io/github/stars/yyqs2008/CVE-2019-5736-PoC-2.svg) ![forks](https://img.shields.io/github/forks/yyqs2008/CVE-2019-5736-PoC-2.svg)
- [https://github.com/fahmifj/Docker-breakout-runc](https://github.com/fahmifj/Docker-breakout-runc) :  ![starts](https://img.shields.io/github/stars/fahmifj/Docker-breakout-runc.svg) ![forks](https://img.shields.io/github/forks/fahmifj/Docker-breakout-runc.svg)


## CVE-2019-5700
 NVIDIA Shield TV Experience prior to v8.0.1, NVIDIA Tegra software contains a vulnerability in the bootloader, where it does not validate the fields of the boot image, which may lead to code execution, denial of service, escalation of privileges, and information disclosure.

- [https://github.com/oscardagrach/CVE-2019-5700](https://github.com/oscardagrach/CVE-2019-5700) :  ![starts](https://img.shields.io/github/stars/oscardagrach/CVE-2019-5700.svg) ![forks](https://img.shields.io/github/forks/oscardagrach/CVE-2019-5700.svg)


## CVE-2019-5680
 In NVIDIA Jetson TX1 L4T R32 version branch prior to R32.2, Tegra bootloader contains a vulnerability in nvtboot in which the nvtboot-cpu image is loaded without the load address first being validated, which may lead to code execution, denial of service, or escalation of privileges.

- [https://github.com/balika011/selfblow](https://github.com/balika011/selfblow) :  ![starts](https://img.shields.io/github/stars/balika011/selfblow.svg) ![forks](https://img.shields.io/github/forks/balika011/selfblow.svg)


## CVE-2019-5624
 Rapid7 Metasploit Framework suffers from an instance of CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in the Zip import function of Metasploit. Exploiting this vulnerability can allow an attacker to execute arbitrary code in Metasploit at the privilege level of the user running Metasploit. This issue affects: Rapid7 Metasploit Framework version 4.14.0 and prior versions.

- [https://github.com/VoidSec/CVE-2019-5624](https://github.com/VoidSec/CVE-2019-5624) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2019-5624.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2019-5624.svg)


## CVE-2019-5596
 In FreeBSD 11.2-STABLE after r338618 and before r343786, 12.0-STABLE before r343781, and 12.0-RELEASE before 12.0-RELEASE-p3, a bug in the reference count implementation for UNIX domain sockets can cause a file structure to be incorrectly released potentially allowing a malicious local user to gain root privileges or escape from a jail.

- [https://github.com/raymontag/CVE-2019-5596](https://github.com/raymontag/CVE-2019-5596) :  ![starts](https://img.shields.io/github/stars/raymontag/CVE-2019-5596.svg) ![forks](https://img.shields.io/github/forks/raymontag/CVE-2019-5596.svg)


## CVE-2019-5544
 OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap overwrite issue. VMware has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.

- [https://github.com/dgh05t/VMware_ESXI_OpenSLP_PoCs](https://github.com/dgh05t/VMware_ESXI_OpenSLP_PoCs) :  ![starts](https://img.shields.io/github/stars/dgh05t/VMware_ESXI_OpenSLP_PoCs.svg) ![forks](https://img.shields.io/github/forks/dgh05t/VMware_ESXI_OpenSLP_PoCs.svg)
- [https://github.com/HynekPetrak/CVE-2019-5544_CVE-2020-3992](https://github.com/HynekPetrak/CVE-2019-5544_CVE-2020-3992) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/CVE-2019-5544_CVE-2020-3992.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/CVE-2019-5544_CVE-2020-3992.svg)


## CVE-2019-5484
 Bower before 1.8.8 has a path traversal vulnerability permitting file write in arbitrary locations via install command, which allows attackers to write arbitrary files when a malicious package is extracted.

- [https://github.com/ossf-cve-benchmark/CVE-2019-5484](https://github.com/ossf-cve-benchmark/CVE-2019-5484) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-5484.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-5484.svg)


## CVE-2019-5483
 Seneca &lt; 3.9.0 contains a vulnerability that could lead to exposing environment variables to unauthorized users.

- [https://github.com/ossf-cve-benchmark/CVE-2019-5483](https://github.com/ossf-cve-benchmark/CVE-2019-5483) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-5483.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-5483.svg)


## CVE-2019-5479
 An unintended require vulnerability in &lt;v0.5.5 larvitbase-api may allow an attacker to load arbitrary non-production code (JavaScript file).

- [https://github.com/ossf-cve-benchmark/CVE-2019-5479](https://github.com/ossf-cve-benchmark/CVE-2019-5479) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-5479.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-5479.svg)


## CVE-2019-5475
 The Nexus Yum Repository Plugin in v2 is vulnerable to Remote Code Execution when instances using CommandLineExecutor.java are supplied vulnerable data, such as the Yum Configuration Capability.

- [https://github.com/jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-](https://github.com/jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-) :  ![starts](https://img.shields.io/github/stars/jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-.svg) ![forks](https://img.shields.io/github/forks/jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-.svg)
- [https://github.com/rabbitmask/CVE-2019-5475-EXP](https://github.com/rabbitmask/CVE-2019-5475-EXP) :  ![starts](https://img.shields.io/github/stars/rabbitmask/CVE-2019-5475-EXP.svg) ![forks](https://img.shields.io/github/forks/rabbitmask/CVE-2019-5475-EXP.svg)
- [https://github.com/EXP-Docs/CVE-2019-5475](https://github.com/EXP-Docs/CVE-2019-5475) :  ![starts](https://img.shields.io/github/stars/EXP-Docs/CVE-2019-5475.svg) ![forks](https://img.shields.io/github/forks/EXP-Docs/CVE-2019-5475.svg)


## CVE-2019-5444
 Path traversal vulnerability in version up to v1.1.3 in serve-here.js npm module allows attackers to list any file in arbitrary folder.

- [https://github.com/ossf-cve-benchmark/CVE-2019-5444](https://github.com/ossf-cve-benchmark/CVE-2019-5444) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-5444.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-5444.svg)


## CVE-2019-5428
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2019-11358. Reason: This candidate is a duplicate of CVE-2019-11358. Notes: All CVE users should reference CVE-2019-11358 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/DanielRuf/snyk-js-jquery-174006](https://github.com/DanielRuf/snyk-js-jquery-174006) :  ![starts](https://img.shields.io/github/stars/DanielRuf/snyk-js-jquery-174006.svg) ![forks](https://img.shields.io/github/forks/DanielRuf/snyk-js-jquery-174006.svg)
- [https://github.com/DanielRuf/snyk-js-jquery-565129](https://github.com/DanielRuf/snyk-js-jquery-565129) :  ![starts](https://img.shields.io/github/stars/DanielRuf/snyk-js-jquery-565129.svg) ![forks](https://img.shields.io/github/forks/DanielRuf/snyk-js-jquery-565129.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)
- [https://github.com/mpgn/CVE-2019-5418](https://github.com/mpgn/CVE-2019-5418) :  ![starts](https://img.shields.io/github/stars/mpgn/CVE-2019-5418.svg) ![forks](https://img.shields.io/github/forks/mpgn/CVE-2019-5418.svg)
- [https://github.com/mpgn/Rails-doubletap-RCE](https://github.com/mpgn/Rails-doubletap-RCE) :  ![starts](https://img.shields.io/github/stars/mpgn/Rails-doubletap-RCE.svg) ![forks](https://img.shields.io/github/forks/mpgn/Rails-doubletap-RCE.svg)
- [https://github.com/brompwnie/CVE-2019-5418-Scanner](https://github.com/brompwnie/CVE-2019-5418-Scanner) :  ![starts](https://img.shields.io/github/stars/brompwnie/CVE-2019-5418-Scanner.svg) ![forks](https://img.shields.io/github/forks/brompwnie/CVE-2019-5418-Scanner.svg)
- [https://github.com/omarkurt/CVE-2019-5418](https://github.com/omarkurt/CVE-2019-5418) :  ![starts](https://img.shields.io/github/stars/omarkurt/CVE-2019-5418.svg) ![forks](https://img.shields.io/github/forks/omarkurt/CVE-2019-5418.svg)
- [https://github.com/random-robbie/CVE-2019-5418](https://github.com/random-robbie/CVE-2019-5418) :  ![starts](https://img.shields.io/github/stars/random-robbie/CVE-2019-5418.svg) ![forks](https://img.shields.io/github/forks/random-robbie/CVE-2019-5418.svg)
- [https://github.com/NotoriousRebel/RailRoadBandit](https://github.com/NotoriousRebel/RailRoadBandit) :  ![starts](https://img.shields.io/github/stars/NotoriousRebel/RailRoadBandit.svg) ![forks](https://img.shields.io/github/forks/NotoriousRebel/RailRoadBandit.svg)
- [https://github.com/takeokunn/CVE-2019-5418](https://github.com/takeokunn/CVE-2019-5418) :  ![starts](https://img.shields.io/github/stars/takeokunn/CVE-2019-5418.svg) ![forks](https://img.shields.io/github/forks/takeokunn/CVE-2019-5418.svg)
- [https://github.com/kailing0220/CVE-2019-5418](https://github.com/kailing0220/CVE-2019-5418) :  ![starts](https://img.shields.io/github/stars/kailing0220/CVE-2019-5418.svg) ![forks](https://img.shields.io/github/forks/kailing0220/CVE-2019-5418.svg)
- [https://github.com/Bad3r/RailroadBandit](https://github.com/Bad3r/RailroadBandit) :  ![starts](https://img.shields.io/github/stars/Bad3r/RailroadBandit.svg) ![forks](https://img.shields.io/github/forks/Bad3r/RailroadBandit.svg)
- [https://github.com/ztgrace/CVE-2019-5418-Rails3](https://github.com/ztgrace/CVE-2019-5418-Rails3) :  ![starts](https://img.shields.io/github/stars/ztgrace/CVE-2019-5418-Rails3.svg) ![forks](https://img.shields.io/github/forks/ztgrace/CVE-2019-5418-Rails3.svg)


## CVE-2019-5010
 An exploitable denial-of-service vulnerability exists in the X509 certificate parser of Python.org Python 2.7.11 / 3.6.6. A specially crafted X509 certificate can cause a NULL pointer dereference, resulting in a denial of service. An attacker can initiate or accept TLS connections using crafted certificates to trigger this vulnerability.

- [https://github.com/JonathanWilbur/CVE-2019-5010](https://github.com/JonathanWilbur/CVE-2019-5010) :  ![starts](https://img.shields.io/github/stars/JonathanWilbur/CVE-2019-5010.svg) ![forks](https://img.shields.io/github/forks/JonathanWilbur/CVE-2019-5010.svg)


## CVE-2019-4881
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2019. Notes: none.

- [https://github.com/wucj001/cve-2019-48814](https://github.com/wucj001/cve-2019-48814) :  ![starts](https://img.shields.io/github/stars/wucj001/cve-2019-48814.svg) ![forks](https://img.shields.io/github/forks/wucj001/cve-2019-48814.svg)


## CVE-2019-3810
 A flaw was found in moodle versions 3.6 to 3.6.1, 3.5 to 3.5.3, 3.4 to 3.4.6, 3.1 to 3.1.15 and earlier unsupported versions. The /userpix/ page did not escape users' full names, which are included as text when hovering over profile images. Note this page is not linked to by default and its access is restricted.

- [https://github.com/farisv/Moodle-CVE-2019-3810](https://github.com/farisv/Moodle-CVE-2019-3810) :  ![starts](https://img.shields.io/github/stars/farisv/Moodle-CVE-2019-3810.svg) ![forks](https://img.shields.io/github/forks/farisv/Moodle-CVE-2019-3810.svg)


## CVE-2019-3799
 Spring Cloud Config, versions 2.1.x prior to 2.1.2, versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead a directory traversal attack.

- [https://github.com/DSO-Lab/defvul](https://github.com/DSO-Lab/defvul) :  ![starts](https://img.shields.io/github/stars/DSO-Lab/defvul.svg) ![forks](https://img.shields.io/github/forks/DSO-Lab/defvul.svg)
- [https://github.com/mpgn/CVE-2019-3799](https://github.com/mpgn/CVE-2019-3799) :  ![starts](https://img.shields.io/github/stars/mpgn/CVE-2019-3799.svg) ![forks](https://img.shields.io/github/forks/mpgn/CVE-2019-3799.svg)
- [https://github.com/Corgizz/SpringCloud](https://github.com/Corgizz/SpringCloud) :  ![starts](https://img.shields.io/github/stars/Corgizz/SpringCloud.svg) ![forks](https://img.shields.io/github/forks/Corgizz/SpringCloud.svg)


## CVE-2019-3778
 Spring Security OAuth, versions 2.3 prior to 2.3.5, and 2.2 prior to 2.2.4, and 2.1 prior to 2.1.4, and 2.0 prior to 2.0.17, and older unsupported versions could be susceptible to an open redirector attack that can leak an authorization code. A malicious user or attacker can craft a request to the authorization endpoint using the authorization code grant type, and specify a manipulated redirection URI via the &quot;redirect_uri&quot; parameter. This can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the leaked authorization code. This vulnerability exposes applications that meet all of the following requirements: Act in the role of an Authorization Server (e.g. @EnableAuthorizationServer) and uses the DefaultRedirectResolver in the AuthorizationEndpoint. This vulnerability does not expose applications that: Act in the role of an Authorization Server and uses a different RedirectResolver implementation other than DefaultRedirectResolver, act in the role of a Resource Server only (e.g. @EnableResourceServer), act in the role of a Client only (e.g. @EnableOAuthClient).

- [https://github.com/BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection](https://github.com/BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection) :  ![starts](https://img.shields.io/github/stars/BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection.svg) ![forks](https://img.shields.io/github/forks/BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection.svg)


## CVE-2019-3398
 Confluence Server and Data Center had a path traversal vulnerability in the downloadallattachments resource. A remote attacker who has permission to add attachments to pages and / or blogs or to create a new space or a personal space or who has 'Admin' permissions for a space can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Confluence Server or Data Center. All versions of Confluence Server from 2.0.0 before 6.6.13 (the fixed version for 6.6.x), from 6.7.0 before 6.12.4 (the fixed version for 6.12.x), from 6.13.0 before 6.13.4 (the fixed version for 6.13.x), from 6.14.0 before 6.14.3 (the fixed version for 6.14.x), and from 6.15.0 before 6.15.2 are affected by this vulnerability.

- [https://github.com/superevr/cve-2019-3398](https://github.com/superevr/cve-2019-3398) :  ![starts](https://img.shields.io/github/stars/superevr/cve-2019-3398.svg) ![forks](https://img.shields.io/github/forks/superevr/cve-2019-3398.svg)


## CVE-2019-3396
 The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.

- [https://github.com/Yt1g3r/CVE-2019-3396_EXP](https://github.com/Yt1g3r/CVE-2019-3396_EXP) :  ![starts](https://img.shields.io/github/stars/Yt1g3r/CVE-2019-3396_EXP.svg) ![forks](https://img.shields.io/github/forks/Yt1g3r/CVE-2019-3396_EXP.svg)
- [https://github.com/jas502n/CVE-2019-3396](https://github.com/jas502n/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-3396.svg)
- [https://github.com/pyn3rd/CVE-2019-3396](https://github.com/pyn3rd/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/pyn3rd/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/pyn3rd/CVE-2019-3396.svg)
- [https://github.com/x-f1v3/CVE-2019-3396](https://github.com/x-f1v3/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/x-f1v3/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/x-f1v3/CVE-2019-3396.svg)
- [https://github.com/PetrusViet/cve-2019-3396](https://github.com/PetrusViet/cve-2019-3396) :  ![starts](https://img.shields.io/github/stars/PetrusViet/cve-2019-3396.svg) ![forks](https://img.shields.io/github/forks/PetrusViet/cve-2019-3396.svg)
- [https://github.com/abdallah-elsharif/cve-2019-3396](https://github.com/abdallah-elsharif/cve-2019-3396) :  ![starts](https://img.shields.io/github/stars/abdallah-elsharif/cve-2019-3396.svg) ![forks](https://img.shields.io/github/forks/abdallah-elsharif/cve-2019-3396.svg)
- [https://github.com/dothanthitiendiettiende/CVE-2019-3396](https://github.com/dothanthitiendiettiende/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/dothanthitiendiettiende/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/dothanthitiendiettiende/CVE-2019-3396.svg)
- [https://github.com/yuehanked/cve-2019-3396](https://github.com/yuehanked/cve-2019-3396) :  ![starts](https://img.shields.io/github/stars/yuehanked/cve-2019-3396.svg) ![forks](https://img.shields.io/github/forks/yuehanked/cve-2019-3396.svg)
- [https://github.com/JonathanZhou348/CVE-2019-3396TEST](https://github.com/JonathanZhou348/CVE-2019-3396TEST) :  ![starts](https://img.shields.io/github/stars/JonathanZhou348/CVE-2019-3396TEST.svg) ![forks](https://img.shields.io/github/forks/JonathanZhou348/CVE-2019-3396TEST.svg)
- [https://github.com/xiaoshuier/CVE-2019-3396](https://github.com/xiaoshuier/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/xiaoshuier/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/xiaoshuier/CVE-2019-3396.svg)
- [https://github.com/46o60/CVE-2019-3396_Confluence](https://github.com/46o60/CVE-2019-3396_Confluence) :  ![starts](https://img.shields.io/github/stars/46o60/CVE-2019-3396_Confluence.svg) ![forks](https://img.shields.io/github/forks/46o60/CVE-2019-3396_Confluence.svg)
- [https://github.com/vntest11/confluence_CVE-2019-3396](https://github.com/vntest11/confluence_CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/vntest11/confluence_CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/vntest11/confluence_CVE-2019-3396.svg)
- [https://github.com/s1xg0d/CVE-2019-3396](https://github.com/s1xg0d/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/s1xg0d/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/s1xg0d/CVE-2019-3396.svg)
- [https://github.com/quanpt103/CVE-2019-3396](https://github.com/quanpt103/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/quanpt103/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/quanpt103/CVE-2019-3396.svg)
- [https://github.com/am6539/CVE-2019-3396](https://github.com/am6539/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/am6539/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/am6539/CVE-2019-3396.svg)
- [https://github.com/W2Ning/CVE-2019-3396](https://github.com/W2Ning/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/W2Ning/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/W2Ning/CVE-2019-3396.svg)
- [https://github.com/skommando/CVE-2019-3396-confluence-poc](https://github.com/skommando/CVE-2019-3396-confluence-poc) :  ![starts](https://img.shields.io/github/stars/skommando/CVE-2019-3396-confluence-poc.svg) ![forks](https://img.shields.io/github/forks/skommando/CVE-2019-3396-confluence-poc.svg)
- [https://github.com/tanw923/test1](https://github.com/tanw923/test1) :  ![starts](https://img.shields.io/github/stars/tanw923/test1.svg) ![forks](https://img.shields.io/github/forks/tanw923/test1.svg)


## CVE-2019-3394
 There was a local file disclosure vulnerability in Confluence Server and Confluence Data Center via page exporting. An attacker with permission to editing a page is able to exploit this issue to read arbitrary file on the server under &lt;install-directory&gt;/confluence/WEB-INF directory, which may contain configuration files used for integrating with other services, which could potentially leak credentials or other sensitive information such as LDAP credentials. The LDAP credential will be potentially leaked only if the Confluence server is configured to use LDAP as user repository. All versions of Confluence Server from 6.1.0 before 6.6.16 (the fixed version for 6.6.x), from 6.7.0 before 6.13.7 (the fixed version for 6.13.x), and from 6.14.0 before 6.15.8 (the fixed version for 6.15.x) are affected by this vulnerability.

- [https://github.com/jas502n/CVE-2019-3394](https://github.com/jas502n/CVE-2019-3394) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-3394.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-3394.svg)


## CVE-2019-3010
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: XScreenSaver). The supported version that is affected is 11. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Solaris executes to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. CVSS 3.0 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/chaizeg/privilege-escalation-breach](https://github.com/chaizeg/privilege-escalation-breach) :  ![starts](https://img.shields.io/github/stars/chaizeg/privilege-escalation-breach.svg) ![forks](https://img.shields.io/github/forks/chaizeg/privilege-escalation-breach.svg)


## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

- [https://github.com/marcinguy/blueborne-CVE-2017-1000251](https://github.com/marcinguy/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/marcinguy/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/marcinguy/blueborne-CVE-2017-1000251.svg)


## CVE-2017-18486
 Jitbit Helpdesk before 9.0.3 allows remote attackers to escalate privileges because of mishandling of the User/AutoLogin userHash parameter. By inspecting the token value provided in a password reset link, a user can leverage a weak PRNG to recover the shared secret used by the server for remote authentication. The shared secret can be used to escalate privileges by forging new tokens for any user. These tokens can be used to automatically log in as the affected user.

- [https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass](https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass) :  ![starts](https://img.shields.io/github/stars/Kc57/JitBit_Helpdesk_Auth_Bypass.svg) ![forks](https://img.shields.io/github/forks/Kc57/JitBit_Helpdesk_Auth_Bypass.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/JohnHammond/CVE-2012-2982](https://github.com/JohnHammond/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2012-2982.svg)
- [https://github.com/Ari-Weinberg/CVE-2012-2982](https://github.com/Ari-Weinberg/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/Ari-Weinberg/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/Ari-Weinberg/CVE-2012-2982.svg)
- [https://github.com/wizardy0ga/CVE_2012-2982](https://github.com/wizardy0ga/CVE_2012-2982) :  ![starts](https://img.shields.io/github/stars/wizardy0ga/CVE_2012-2982.svg) ![forks](https://img.shields.io/github/forks/wizardy0ga/CVE_2012-2982.svg)

