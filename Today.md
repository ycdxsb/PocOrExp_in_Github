# Update 2023-04-15
## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/CHINA-china/MinIO_CVE-2023-28432_EXP](https://github.com/CHINA-china/MinIO_CVE-2023-28432_EXP) :  ![starts](https://img.shields.io/github/stars/CHINA-china/MinIO_CVE-2023-28432_EXP.svg) ![forks](https://img.shields.io/github/forks/CHINA-china/MinIO_CVE-2023-28432_EXP.svg)


## CVE-2023-25610
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/FortiSecurity/CVE-2023-25610](https://github.com/FortiSecurity/CVE-2023-25610) :  ![starts](https://img.shields.io/github/stars/FortiSecurity/CVE-2023-25610.svg) ![forks](https://img.shields.io/github/forks/FortiSecurity/CVE-2023-25610.svg)


## CVE-2023-21554
 Microsoft Message Queuing Remote Code Execution Vulnerability

- [https://github.com/HshMkr/CVE-2023-21554](https://github.com/HshMkr/CVE-2023-21554) :  ![starts](https://img.shields.io/github/stars/HshMkr/CVE-2023-21554.svg) ![forks](https://img.shields.io/github/forks/HshMkr/CVE-2023-21554.svg)
- [https://github.com/select275/CVE-2023-21554-PoC](https://github.com/select275/CVE-2023-21554-PoC) :  ![starts](https://img.shields.io/github/stars/select275/CVE-2023-21554-PoC.svg) ![forks](https://img.shields.io/github/forks/select275/CVE-2023-21554-PoC.svg)


## CVE-2023-1454
 A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-223299.

- [https://github.com/BugFor-Pings/CVE-2023-1454](https://github.com/BugFor-Pings/CVE-2023-1454) :  ![starts](https://img.shields.io/github/stars/BugFor-Pings/CVE-2023-1454.svg) ![forks](https://img.shields.io/github/forks/BugFor-Pings/CVE-2023-1454.svg)
- [https://github.com/CKevens/CVE-2023-1454-EXP](https://github.com/CKevens/CVE-2023-1454-EXP) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-1454-EXP.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-1454-EXP.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/icebreack/CVE-2022-46169](https://github.com/icebreack/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/icebreack/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/icebreack/CVE-2022-46169.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Sonicwall-PSIRT-REPO/CVE-2022-42889](https://github.com/Sonicwall-PSIRT-REPO/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/Sonicwall-PSIRT-REPO/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/Sonicwall-PSIRT-REPO/CVE-2022-42889.svg)


## CVE-2022-41800
 In all versions of BIG-IP, when running in Appliance mode, an authenticated user assigned the Administrator role may be able to bypass Appliance mode restrictions, utilizing an undisclosed iControl REST endpoint. A successful exploit can allow the attacker to cross a security boundary. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/j-baines/tippa-my-tongue](https://github.com/j-baines/tippa-my-tongue) :  ![starts](https://img.shields.io/github/stars/j-baines/tippa-my-tongue.svg) ![forks](https://img.shields.io/github/forks/j-baines/tippa-my-tongue.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/Pro-me3us/CVE_2022_38181_Gazelle](https://github.com/Pro-me3us/CVE_2022_38181_Gazelle) :  ![starts](https://img.shields.io/github/stars/Pro-me3us/CVE_2022_38181_Gazelle.svg) ![forks](https://img.shields.io/github/forks/Pro-me3us/CVE_2022_38181_Gazelle.svg)
- [https://github.com/Pro-me3us/CVE_2022_38181_Raven](https://github.com/Pro-me3us/CVE_2022_38181_Raven) :  ![starts](https://img.shields.io/github/stars/Pro-me3us/CVE_2022_38181_Raven.svg) ![forks](https://img.shields.io/github/forks/Pro-me3us/CVE_2022_38181_Raven.svg)


## CVE-2022-32429
 An authentication-bypass issue in the component http://MYDEVICEIP/cgi-bin-sdb/ExportSettings.sh of Mega System Technologies Inc MSNSwitch MNT.2408 allows unauthenticated attackers to arbitrarily configure settings within the application, leading to remote code execution.

- [https://github.com/gudetem/CVE-2022-32429](https://github.com/gudetem/CVE-2022-32429) :  ![starts](https://img.shields.io/github/stars/gudetem/CVE-2022-32429.svg) ![forks](https://img.shields.io/github/forks/gudetem/CVE-2022-32429.svg)


## CVE-2022-31789
 An integer overflow in WatchGuard Firebox and XTM appliances allows an unauthenticated remote attacker to trigger a buffer overflow and potentially execute arbitrary code by sending a malicious request to exposed management ports. This is fixed in Fireware OS 12.8.1, 12.5.10, and 12.1.4.

- [https://github.com/Watchguard-PSIRT-REPO/CVE-2022-31789](https://github.com/Watchguard-PSIRT-REPO/CVE-2022-31789) :  ![starts](https://img.shields.io/github/stars/Watchguard-PSIRT-REPO/CVE-2022-31789.svg) ![forks](https://img.shields.io/github/forks/Watchguard-PSIRT-REPO/CVE-2022-31789.svg)


## CVE-2022-20928
 A vulnerability in the authentication and authorization flows for VPN connections in Cisco Adaptive Security Appliance (ASA) Software and Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to establish a connection as a different user. This vulnerability is due to a flaw in the authorization verifications during the VPN authentication flow. An attacker could exploit this vulnerability by sending a crafted packet during a VPN authentication. The attacker must have valid credentials to establish a VPN connection. A successful exploit could allow the attacker to establish a VPN connection with access privileges from a different user.

- [https://github.com/Cisco-PSIRT-Repo/CVE-2022-20928](https://github.com/Cisco-PSIRT-Repo/CVE-2022-20928) :  ![starts](https://img.shields.io/github/stars/Cisco-PSIRT-Repo/CVE-2022-20928.svg) ![forks](https://img.shields.io/github/forks/Cisco-PSIRT-Repo/CVE-2022-20928.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/attilaszia/cve-2022-3602](https://github.com/attilaszia/cve-2022-3602) :  ![starts](https://img.shields.io/github/stars/attilaszia/cve-2022-3602.svg) ![forks](https://img.shields.io/github/forks/attilaszia/cve-2022-3602.svg)


## CVE-2022-3236
 A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

- [https://github.com/Sophos-PSIRT-REPO/CVE-2022-3236](https://github.com/Sophos-PSIRT-REPO/CVE-2022-3236) :  ![starts](https://img.shields.io/github/stars/Sophos-PSIRT-REPO/CVE-2022-3236.svg) ![forks](https://img.shields.io/github/forks/Sophos-PSIRT-REPO/CVE-2022-3236.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/j-baines/tippa-my-tongue](https://github.com/j-baines/tippa-my-tongue) :  ![starts](https://img.shields.io/github/stars/j-baines/tippa-my-tongue.svg) ![forks](https://img.shields.io/github/forks/j-baines/tippa-my-tongue.svg)


## CVE-2022-0030
 An authentication bypass vulnerability in the Palo Alto Networks PAN-OS 8.1 web interface allows a network-based attacker with specific knowledge of the target firewall or Panorama appliance to impersonate an existing PAN-OS administrator and perform privileged actions.

- [https://github.com/PaloAlto-PSIRT-REPO/CVE-2022-0030](https://github.com/PaloAlto-PSIRT-REPO/CVE-2022-0030) :  ![starts](https://img.shields.io/github/stars/PaloAlto-PSIRT-REPO/CVE-2022-0030.svg) ![forks](https://img.shields.io/github/forks/PaloAlto-PSIRT-REPO/CVE-2022-0030.svg)


## CVE-2021-44142
 The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide &quot;...enhanced compatibility with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver.&quot; Samba versions prior to 4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via specially crafted extended file attributes. A remote attacker with write access to extended file attributes can execute arbitrary code with the privileges of smbd, typically root.

- [https://github.com/gudyrmik/CVE-2021-44142](https://github.com/gudyrmik/CVE-2021-44142) :  ![starts](https://img.shields.io/github/stars/gudyrmik/CVE-2021-44142.svg) ![forks](https://img.shields.io/github/forks/gudyrmik/CVE-2021-44142.svg)


## CVE-2021-35250
 A researcher reported a Directory Transversal Vulnerability in Serv-U 15.3. This may allow access to files relating to the Serv-U installation and server files. This issue has been resolved in Serv-U 15.3 Hotfix 1.

- [https://github.com/rissor41/SolarWinds-CVE-2021-35250](https://github.com/rissor41/SolarWinds-CVE-2021-35250) :  ![starts](https://img.shields.io/github/stars/rissor41/SolarWinds-CVE-2021-35250.svg) ![forks](https://img.shields.io/github/forks/rissor41/SolarWinds-CVE-2021-35250.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/adarshvs/CVE-2020-3580](https://github.com/adarshvs/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/adarshvs/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/adarshvs/CVE-2020-3580.svg)

