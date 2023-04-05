# Update 2023-04-05
## CVE-2023-24780
 Funadmin v3.2.0 was discovered to contain a SQL injection vulnerability via the id parameter at /databases/table/columns.

- [https://github.com/csffs/CVE-2023-24775-and-CVE-2023-24780](https://github.com/csffs/CVE-2023-24775-and-CVE-2023-24780) :  ![starts](https://img.shields.io/github/stars/csffs/CVE-2023-24775-and-CVE-2023-24780.svg) ![forks](https://img.shields.io/github/forks/csffs/CVE-2023-24775-and-CVE-2023-24780.svg)


## CVE-2023-24775
 Funadmin v3.2.0 was discovered to contain a SQL injection vulnerability via the selectFields parameter at \member\Member.php.

- [https://github.com/csffs/CVE-2023-24775-and-CVE-2023-24780](https://github.com/csffs/CVE-2023-24775-and-CVE-2023-24780) :  ![starts](https://img.shields.io/github/stars/csffs/CVE-2023-24775-and-CVE-2023-24780.svg) ![forks](https://img.shields.io/github/forks/csffs/CVE-2023-24775-and-CVE-2023-24780.svg)


## CVE-2023-24774
 Funadmin v3.2.0 was discovered to contain a SQL injection vulnerability via the selectFields parameter at \controller\auth\Auth.php.

- [https://github.com/csffs/CVE-2023-24775-and-CVE-2023-24780](https://github.com/csffs/CVE-2023-24775-and-CVE-2023-24780) :  ![starts](https://img.shields.io/github/stars/csffs/CVE-2023-24775-and-CVE-2023-24780.svg) ![forks](https://img.shields.io/github/forks/csffs/CVE-2023-24775-and-CVE-2023-24780.svg)


## CVE-2023-20944
 In run of ChooseTypeAndAccountActivity.java, there is a possible escalation of privilege due to unsafe deserialization. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-244154558

- [https://github.com/Trinadh465/frameworks_base_CVE-2023-20944](https://github.com/Trinadh465/frameworks_base_CVE-2023-20944) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_CVE-2023-20944.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_CVE-2023-20944.svg)


## CVE-2023-20943
 In clearApplicationUserData of ActivityManagerService.java, there is a possible way to remove system files due to a path traversal error. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-240267890

- [https://github.com/Trinadh465/frameworks_base_CVE-2023-20943](https://github.com/Trinadh465/frameworks_base_CVE-2023-20943) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_CVE-2023-20943.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_CVE-2023-20943.svg)


## CVE-2023-20933
 In several functions of MediaCodec.cpp, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-245860753

- [https://github.com/Trinadh465/frameworks_av_CVE-2023-20933](https://github.com/Trinadh465/frameworks_av_CVE-2023-20933) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_av_CVE-2023-20933.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_av_CVE-2023-20933.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application](https://github.com/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application) :  ![starts](https://img.shields.io/github/stars/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application.svg)


## CVE-2022-42896
 There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively) remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within proximity of the victim. We recommend upgrading past commit https://www.google.com/url https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4 https://www.google.com/url

- [https://github.com/nidhi7598/linux-4.1.15_CVE-2022-42896](https://github.com/nidhi7598/linux-4.1.15_CVE-2022-42896) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.1.15_CVE-2022-42896.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.1.15_CVE-2022-42896.svg)


## CVE-2022-29455
 DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.

- [https://github.com/VarelSecurity/CVE-2022-29455](https://github.com/VarelSecurity/CVE-2022-29455) :  ![starts](https://img.shields.io/github/stars/VarelSecurity/CVE-2022-29455.svg) ![forks](https://img.shields.io/github/forks/VarelSecurity/CVE-2022-29455.svg)


## CVE-2022-27665
 Reflected XSS (via AngularJS sandbox escape expressions) exists in Progress Ipswitch WS_FTP Server 8.6.0. This can lead to execution of malicious code and commands on the client due to improper handling of user-provided input. By inputting malicious payloads in the subdirectory searchbar or Add folder filename boxes, it is possible to execute client-side commands. For example, there is Client-Side Template Injection via subFolderPath to the ThinClient/WtmApiService.asmx/GetFileSubTree URI.

- [https://github.com/dievus/CVE-2022-27665](https://github.com/dievus/CVE-2022-27665) :  ![starts](https://img.shields.io/github/stars/dievus/CVE-2022-27665.svg) ![forks](https://img.shields.io/github/forks/dievus/CVE-2022-27665.svg)


## CVE-2021-45919
 Studio 42 elFinder through 2.1.31 allows XSS via an SVG document.

- [https://github.com/SpiderLabs/Jorogumo](https://github.com/SpiderLabs/Jorogumo) :  ![starts](https://img.shields.io/github/stars/SpiderLabs/Jorogumo.svg) ![forks](https://img.shields.io/github/forks/SpiderLabs/Jorogumo.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/demonrvm/Log4ShellRemediation](https://github.com/demonrvm/Log4ShellRemediation) :  ![starts](https://img.shields.io/github/stars/demonrvm/Log4ShellRemediation.svg) ![forks](https://img.shields.io/github/forks/demonrvm/Log4ShellRemediation.svg)


## CVE-2017-1000006
 Plotly, Inc. plotly.js versions prior to 1.16.0 are vulnerable to an XSS issue.

- [https://github.com/ossf-cve-benchmark/CVE-2017-1000006](https://github.com/ossf-cve-benchmark/CVE-2017-1000006) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000006.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000006.svg)


## CVE-2016-2334
 Heap-based buffer overflow in the NArchive::NHfs::CHandler::ExtractZlibFile method in 7zip before 16.00 and p7zip allows remote attackers to execute arbitrary code via a crafted HFS+ image.

- [https://github.com/icewall/CVE-2016-2334](https://github.com/icewall/CVE-2016-2334) :  ![starts](https://img.shields.io/github/stars/icewall/CVE-2016-2334.svg) ![forks](https://img.shields.io/github/forks/icewall/CVE-2016-2334.svg)


## CVE-2012-2012
 HP System Management Homepage (SMH) before 7.1.1 does not have an off autocomplete attribute for unspecified form fields, which makes it easier for remote attackers to obtain access by leveraging an unattended workstation.

- [https://github.com/hello123body/CVE-2012-2012](https://github.com/hello123body/CVE-2012-2012) :  ![starts](https://img.shields.io/github/stars/hello123body/CVE-2012-2012.svg) ![forks](https://img.shields.io/github/forks/hello123body/CVE-2012-2012.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/MrEmpy/CVE-2006-3392](https://github.com/MrEmpy/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/MrEmpy/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/MrEmpy/CVE-2006-3392.svg)

