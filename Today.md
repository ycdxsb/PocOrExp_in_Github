# Update 2023-03-29
## CVE-2023-28434
 Minio is a Multi-Cloud Object Storage framework. Prior to RELEASE.2023-03-20T20-16-18Z, an attacker can use crafted requests to bypass metadata bucket name checking and put an object into any bucket while processing `PostPolicyBucket`. To carry out this attack, the attacker requires credentials with `arn:aws:s3:::*` permission, as well as enabled Console API access. This issue has been patched in RELEASE.2023-03-20T20-16-18Z. As a workaround, enable browser API access and turn off `MINIO_BROWSER=off`.

- [https://github.com/AbelChe/evil_minio](https://github.com/AbelChe/evil_minio) :  ![starts](https://img.shields.io/github/stars/AbelChe/evil_minio.svg) ![forks](https://img.shields.io/github/forks/AbelChe/evil_minio.svg)


## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/steponeerror/Cve-2023-28432-](https://github.com/steponeerror/Cve-2023-28432-) :  ![starts](https://img.shields.io/github/stars/steponeerror/Cve-2023-28432-.svg) ![forks](https://img.shields.io/github/forks/steponeerror/Cve-2023-28432-.svg)
- [https://github.com/yuyongxr/minio_cve-2023-28432](https://github.com/yuyongxr/minio_cve-2023-28432) :  ![starts](https://img.shields.io/github/stars/yuyongxr/minio_cve-2023-28432.svg) ![forks](https://img.shields.io/github/forks/yuyongxr/minio_cve-2023-28432.svg)


## CVE-2023-25263
 In Stimulsoft Designer (Desktop) 2023.1.5, and 2023.1.4, once an attacker decompiles the Stimulsoft.report.dll the attacker is able to decrypt any connectionstring stored in .mrt files since a static secret is used. The secret does not differ between the tested versions and different operating systems.

- [https://github.com/trustcves/CVE-2023-25263](https://github.com/trustcves/CVE-2023-25263) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2023-25263.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2023-25263.svg)


## CVE-2023-25262
 Stimulsoft GmbH Stimulsoft Designer (Web) 2023.1.3 is vulnerable to Server Side Request Forgery (SSRF). TThe Reporting Designer (Web) offers the possibility to embed sources from external locations. If the user chooses an external location, the request to that resource is performed by the server rather than the client. Therefore, the server causes outbound traffic and potentially imports data. An attacker may also leverage this behaviour to exfiltrate data of machines on the internal network of the server hosting the Stimulsoft Reporting Designer (Web).

- [https://github.com/trustcves/CVE-2023-25262](https://github.com/trustcves/CVE-2023-25262) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2023-25262.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2023-25262.svg)


## CVE-2023-25261
 Certain Stimulsoft GmbH products are affected by: Remote Code Execution. This affects Stimulsoft Designer (Desktop) 2023.1.4 and Stimulsoft Designer (Web) 2023.1.3 and Stimulsoft Viewer (Web) 2023.1.3. Access to the local file system is not prohibited in any way. Therefore, an attacker may include source code which reads or writes local directories and files. It is also possible for the attacker to prepare a report which has a variable that holds the gathered data and render it in the report.

- [https://github.com/trustcves/CVE-2023-25261](https://github.com/trustcves/CVE-2023-25261) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2023-25261.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2023-25261.svg)


## CVE-2023-25260
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/trustcves/CVE-2023-25260](https://github.com/trustcves/CVE-2023-25260) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2023-25260.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2023-25260.svg)


## CVE-2022-46836
 PHP code injection in watolib auth.php and hosttags.php in Tribe29's Checkmk &lt;= 2.1.0p10, Checkmk &lt;= 2.0.0p27, and Checkmk &lt;= 1.6.0p29 allows an attacker to inject and execute PHP code which will be executed upon request of the vulnerable component.

- [https://github.com/JacobEbben/CVE-2022-46836_remote_code_execution](https://github.com/JacobEbben/CVE-2022-46836_remote_code_execution) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2022-46836_remote_code_execution.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2022-46836_remote_code_execution.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/imjdl/CVE-2022-46169](https://github.com/imjdl/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/imjdl/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/imjdl/CVE-2022-46169.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/artemis-mike/cve-2021-4034](https://github.com/artemis-mike/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/artemis-mike/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/artemis-mike/cve-2021-4034.svg)
- [https://github.com/jehovah2002/CVE-2021-4034-pwnkit](https://github.com/jehovah2002/CVE-2021-4034-pwnkit) :  ![starts](https://img.shields.io/github/stars/jehovah2002/CVE-2021-4034-pwnkit.svg) ![forks](https://img.shields.io/github/forks/jehovah2002/CVE-2021-4034-pwnkit.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/briskets/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/briskets/CVE-2021-3493.svg)
- [https://github.com/pmihsan/OverlayFS-CVE-2021-3493](https://github.com/pmihsan/OverlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/pmihsan/OverlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/pmihsan/OverlayFS-CVE-2021-3493.svg)


## CVE-2020-28653
 Zoho ManageEngine OpManager Stable build before 125203 (and Released build before 125233) allows Remote Code Execution via the Smart Update Manager (SUM) servlet.

- [https://github.com/intrigueio/cve-2020-28653-poc](https://github.com/intrigueio/cve-2020-28653-poc) :  ![starts](https://img.shields.io/github/stars/intrigueio/cve-2020-28653-poc.svg) ![forks](https://img.shields.io/github/forks/intrigueio/cve-2020-28653-poc.svg)


## CVE-2018-19320
 The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes ring0 memcpy-like functionality that could allow a local attacker to take complete control of the affected system.

- [https://github.com/zer0condition/GDRVLoader](https://github.com/zer0condition/GDRVLoader) :  ![starts](https://img.shields.io/github/stars/zer0condition/GDRVLoader.svg) ![forks](https://img.shields.io/github/forks/zer0condition/GDRVLoader.svg)


## CVE-2015-3145
 The sanitize_cookie_path function in cURL and libcurl 7.31.0 through 7.41.0 does not properly calculate an index, which allows remote attackers to cause a denial of service (out-of-bounds write and crash) or possibly have other unspecified impact via a cookie path containing only a double-quote character.

- [https://github.com/Serz999/CVE-2015-3145](https://github.com/Serz999/CVE-2015-3145) :  ![starts](https://img.shields.io/github/stars/Serz999/CVE-2015-3145.svg) ![forks](https://img.shields.io/github/forks/Serz999/CVE-2015-3145.svg)


## CVE-2003-0172
 Buffer overflow in openlog function for PHP 4.3.1 on Windows operating system, and possibly other OSes, allows remote attackers to cause a crash and possibly execute arbitrary code via a long filename argument.

- [https://github.com/cyberdesu/Remote-Buffer-overflow-CVE-2003-0172](https://github.com/cyberdesu/Remote-Buffer-overflow-CVE-2003-0172) :  ![starts](https://img.shields.io/github/stars/cyberdesu/Remote-Buffer-overflow-CVE-2003-0172.svg) ![forks](https://img.shields.io/github/forks/cyberdesu/Remote-Buffer-overflow-CVE-2003-0172.svg)

