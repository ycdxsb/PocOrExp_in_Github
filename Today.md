# Update 2024-05-31
## CVE-2024-35469
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/dovankha/CVE-2024-35469](https://github.com/dovankha/CVE-2024-35469) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-35469.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-35469.svg)


## CVE-2024-35468
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/dovankha/CVE-2024-35468](https://github.com/dovankha/CVE-2024-35468) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-35468.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-35468.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/TypicalModMaker/CVE-2024-4956](https://github.com/TypicalModMaker/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/TypicalModMaker/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/TypicalModMaker/CVE-2024-4956.svg)


## CVE-2024-3293
 The rtMedia for WordPress, BuddyPress and bbPress plugin for WordPress is vulnerable to blind SQL Injection via the rtmedia_gallery shortcode in all versions up to, and including, 4.6.18 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for authenticated attackers, with contributor-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/truonghuuphuc/CVE-2024-3293-Poc](https://github.com/truonghuuphuc/CVE-2024-3293-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-3293-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-3293-Poc.svg)


## CVE-2024-1086
 A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/rootkalilocalhost/CVE-2024-1086](https://github.com/rootkalilocalhost/CVE-2024-1086) :  ![starts](https://img.shields.io/github/stars/rootkalilocalhost/CVE-2024-1086.svg) ![forks](https://img.shields.io/github/forks/rootkalilocalhost/CVE-2024-1086.svg)


## CVE-2024-0039
 In attp_build_value_cmd of att_protocol.cc, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/41yn14/CVE-2024-0039-Exploit](https://github.com/41yn14/CVE-2024-0039-Exploit) :  ![starts](https://img.shields.io/github/stars/41yn14/CVE-2024-0039-Exploit.svg) ![forks](https://img.shields.io/github/forks/41yn14/CVE-2024-0039-Exploit.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/mranv/honeypot.rs](https://github.com/mranv/honeypot.rs) :  ![starts](https://img.shields.io/github/stars/mranv/honeypot.rs.svg) ![forks](https://img.shields.io/github/forks/mranv/honeypot.rs.svg)


## CVE-2023-43622
 An attacker, opening a HTTP/2 connection with an initial window size of 0, was able to block handling of that connection indefinitely in Apache HTTP Server. This could be used to exhaust worker resources in the server, similar to the well known &quot;slow loris&quot; attack pattern. This has been fixed in version 2.4.58, so that such connection are terminated properly after the configured connection timeout. This issue affects Apache HTTP Server: from 2.4.55 through 2.4.57. Users are recommended to upgrade to version 2.4.58, which fixes the issue.

- [https://github.com/visudade/CVE-2023-43622](https://github.com/visudade/CVE-2023-43622) :  ![starts](https://img.shields.io/github/stars/visudade/CVE-2023-43622.svg) ![forks](https://img.shields.io/github/forks/visudade/CVE-2023-43622.svg)


## CVE-2023-29489
 An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.

- [https://github.com/md-thalal/CVE-2023-29489](https://github.com/md-thalal/CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/md-thalal/CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/md-thalal/CVE-2023-29489.svg)


## CVE-2023-22726
 act is a project which allows for local running of github actions. The artifact server that stores artifacts from Github Action runs does not sanitize path inputs. This allows an attacker to download and overwrite arbitrary files on the host from a Github Action. This issue may lead to privilege escalation. The /upload endpoint is vulnerable to path traversal as filepath is user controlled, and ultimately flows into os.Mkdir and os.Open. The /artifact endpoint is vulnerable to path traversal as the path is variable is user controlled, and the specified file is ultimately returned by the server. This has been addressed in version 0.2.40. Users are advised to upgrade. Users unable to upgrade may, during implementation of Open and OpenAtEnd for FS, ensure to use ValidPath() to check against path traversal or clean the user-provided paths manually.

- [https://github.com/ProxyPog/POC-CVE-2023-22726](https://github.com/ProxyPog/POC-CVE-2023-22726) :  ![starts](https://img.shields.io/github/stars/ProxyPog/POC-CVE-2023-22726.svg) ![forks](https://img.shields.io/github/forks/ProxyPog/POC-CVE-2023-22726.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/c3rrberu5/CVE-2022-46169](https://github.com/c3rrberu5/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/c3rrberu5/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/c3rrberu5/CVE-2022-46169.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/0romos/CVE-2022-35914](https://github.com/0romos/CVE-2022-35914) :  ![starts](https://img.shields.io/github/stars/0romos/CVE-2022-35914.svg) ![forks](https://img.shields.io/github/forks/0romos/CVE-2022-35914.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/name/log4j-scanner](https://github.com/name/log4j-scanner) :  ![starts](https://img.shields.io/github/stars/name/log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/name/log4j-scanner.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/marcellomaugeri/Hardening-7-Fuzzing](https://github.com/marcellomaugeri/Hardening-7-Fuzzing) :  ![starts](https://img.shields.io/github/stars/marcellomaugeri/Hardening-7-Fuzzing.svg) ![forks](https://img.shields.io/github/forks/marcellomaugeri/Hardening-7-Fuzzing.svg)


## CVE-2020-5377
 Dell EMC OpenManage Server Administrator (OMSA) versions 9.4 and prior contain multiple path traversal vulnerabilities. An unauthenticated remote attacker could potentially exploit these vulnerabilities by sending a crafted Web API request containing directory traversal character sequences to gain file system access on the compromised management station.

- [https://github.com/c0d3cr4f73r/CVE-2020-5377](https://github.com/c0d3cr4f73r/CVE-2020-5377) :  ![starts](https://img.shields.io/github/stars/c0d3cr4f73r/CVE-2020-5377.svg) ![forks](https://img.shields.io/github/forks/c0d3cr4f73r/CVE-2020-5377.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/c3rrberu5/ZeroLogon-to-Shell](https://github.com/c3rrberu5/ZeroLogon-to-Shell) :  ![starts](https://img.shields.io/github/stars/c3rrberu5/ZeroLogon-to-Shell.svg) ![forks](https://img.shields.io/github/forks/c3rrberu5/ZeroLogon-to-Shell.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/B1ackCat/cve-2016-5195-DirtyCOW](https://github.com/B1ackCat/cve-2016-5195-DirtyCOW) :  ![starts](https://img.shields.io/github/stars/B1ackCat/cve-2016-5195-DirtyCOW.svg) ![forks](https://img.shields.io/github/forks/B1ackCat/cve-2016-5195-DirtyCOW.svg)


## CVE-2000-0114
 Frontpage Server Extensions allows remote attackers to determine the name of the anonymous account via an RPC POST request to shtml.dll in the /_vti_bin/ virtual directory.

- [https://github.com/Cappricio-Securities/CVE-2000-0114](https://github.com/Cappricio-Securities/CVE-2000-0114) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2000-0114.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2000-0114.svg)

