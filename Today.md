# Update 2023-10-21
## CVE-2023-46003
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/leekenghwa/CVE-2023-46003](https://github.com/leekenghwa/CVE-2023-46003) :  ![starts](https://img.shields.io/github/stars/leekenghwa/CVE-2023-46003.svg) ![forks](https://img.shields.io/github/forks/leekenghwa/CVE-2023-46003.svg)


## CVE-2023-45992
 Cross Site Scripting vulnerability in Ruckus Wireless (CommScope) Ruckus CloudPath v.5.12.54414 allows a remote attacker to escalate privileges via a crafted script to the macaddress parameter in the onboarding portal.

- [https://github.com/harry935/CVE-2023-45992](https://github.com/harry935/CVE-2023-45992) :  ![starts](https://img.shields.io/github/stars/harry935/CVE-2023-45992.svg) ![forks](https://img.shields.io/github/forks/harry935/CVE-2023-45992.svg)


## CVE-2023-36802
 Microsoft Streaming Service Proxy Elevation of Privilege Vulnerability

- [https://github.com/4zur-0312/CVE-2023-36802](https://github.com/4zur-0312/CVE-2023-36802) :  ![starts](https://img.shields.io/github/stars/4zur-0312/CVE-2023-36802.svg) ![forks](https://img.shields.io/github/forks/4zur-0312/CVE-2023-36802.svg)
- [https://github.com/x0rb3l/CVE-2023-36802-MSKSSRV-LPE](https://github.com/x0rb3l/CVE-2023-36802-MSKSSRV-LPE) :  ![starts](https://img.shields.io/github/stars/x0rb3l/CVE-2023-36802-MSKSSRV-LPE.svg) ![forks](https://img.shields.io/github/forks/x0rb3l/CVE-2023-36802-MSKSSRV-LPE.svg)


## CVE-2023-29360
 Microsoft Streaming Service Elevation of Privilege Vulnerability

- [https://github.com/exotikcheat/cve-2023-29360](https://github.com/exotikcheat/cve-2023-29360) :  ![starts](https://img.shields.io/github/stars/exotikcheat/cve-2023-29360.svg) ![forks](https://img.shields.io/github/forks/exotikcheat/cve-2023-29360.svg)


## CVE-2023-21118
 In unflattenString8 of Sensor.cpp, there is a possible out of bounds read due to a heap buffer overflow. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-269014004

- [https://github.com/nidhi7598/Frameworks_native_AOSP_10_r33_CVE-2023-21118](https://github.com/nidhi7598/Frameworks_native_AOSP_10_r33_CVE-2023-21118) :  ![starts](https://img.shields.io/github/stars/nidhi7598/Frameworks_native_AOSP_10_r33_CVE-2023-21118.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/Frameworks_native_AOSP_10_r33_CVE-2023-21118.svg)


## CVE-2023-21109
 In multiple places of AccessibilityService, there is a possible way to hide the app from the user due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-261589597

- [https://github.com/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-21109](https://github.com/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-21109) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-21109.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-21109.svg)


## CVE-2023-2114
 The NEX-Forms WordPress plugin before 8.4 does not properly escape the `table` parameter, which is populated with user input, before concatenating it to an SQL query.

- [https://github.com/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114](https://github.com/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114) :  ![starts](https://img.shields.io/github/stars/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114.svg) ![forks](https://img.shields.io/github/forks/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/botfather0x0/CVE-2022-46169](https://github.com/botfather0x0/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/botfather0x0/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/botfather0x0/CVE-2022-46169.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/qwutony/CVE-2021-41773](https://github.com/qwutony/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/qwutony/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/qwutony/CVE-2021-41773.svg)


## CVE-2021-40154
 NXP LPC55S69 devices before A3 have a buffer over-read via a crafted wlength value in a GET Descriptor Configuration request during use of USB In-System Programming (ISP) mode. This discloses protected flash memory.

- [https://github.com/Jeromeyoung/CVE-2021-40154](https://github.com/Jeromeyoung/CVE-2021-40154) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-40154.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-40154.svg)


## CVE-2021-28797
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/sule01u/SBSCAN](https://github.com/sule01u/SBSCAN) :  ![starts](https://img.shields.io/github/stars/sule01u/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/sule01u/SBSCAN.svg)


## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449](https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3449.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/botfather0x0/ZeroLogon-to-Shell](https://github.com/botfather0x0/ZeroLogon-to-Shell) :  ![starts](https://img.shields.io/github/stars/botfather0x0/ZeroLogon-to-Shell.svg) ![forks](https://img.shields.io/github/forks/botfather0x0/ZeroLogon-to-Shell.svg)


## CVE-2018-16156
 In PaperStream IP (TWAIN) 1.42.0.5685 (Service Update 7), the FJTWSVIC service running with SYSTEM privilege processes unauthenticated messages received over the FjtwMkic_Fjicube_32 named pipe. One of these message processing functions attempts to dynamically load the UninOldIS.dll library and executes an exported function named ChangeUninstallString. The default install does not contain this library and therefore if any DLL with that name exists in any directory listed in the PATH variable, it can be used to escalate to SYSTEM level privilege.

- [https://github.com/securifera/CVE-2018-16156-Exploit](https://github.com/securifera/CVE-2018-16156-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2018-16156-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2018-16156-Exploit.svg)


## CVE-2018-7844
 A CWE-200: Information Exposure vulnerability exists in all versions of the Modicon M580, Modicon M340, Modicon Quantum, and Modicon Premium which could cause the disclosure of SNMP information when reading memory blocks from the controller over Modbus.

- [https://github.com/yanissec/CVE-2018-7844](https://github.com/yanissec/CVE-2018-7844) :  ![starts](https://img.shields.io/github/stars/yanissec/CVE-2018-7844.svg) ![forks](https://img.shields.io/github/forks/yanissec/CVE-2018-7844.svg)


## CVE-2018-1111
 DHCP packages in Red Hat Enterprise Linux 6 and 7, Fedora 28, and earlier are vulnerable to a command injection flaw in the NetworkManager integration script included in the DHCP client. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.

- [https://github.com/knqyf263/CVE-2018-1111](https://github.com/knqyf263/CVE-2018-1111) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2018-1111.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2018-1111.svg)

