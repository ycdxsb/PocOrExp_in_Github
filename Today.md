# Update 2023-04-02
## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/Majus527/MinIO_CVE-2023-28432](https://github.com/Majus527/MinIO_CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/Majus527/MinIO_CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/Majus527/MinIO_CVE-2023-28432.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/H454NSec/CVE-2023-23752](https://github.com/H454NSec/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/H454NSec/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/H454NSec/CVE-2023-23752.svg)


## CVE-2023-21036
 In BitmapExport.java, there is a possible failure to truncate images due to a logic error in the code.Product: AndroidVersions: Android kernelAndroid ID: A-264261868References: N/A

- [https://github.com/lordofpipes/acropadetect](https://github.com/lordofpipes/acropadetect) :  ![starts](https://img.shields.io/github/stars/lordofpipes/acropadetect.svg) ![forks](https://img.shields.io/github/forks/lordofpipes/acropadetect.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/devAL3X/CVE-2022-46169_poc](https://github.com/devAL3X/CVE-2022-46169_poc) :  ![starts](https://img.shields.io/github/stars/devAL3X/CVE-2022-46169_poc.svg) ![forks](https://img.shields.io/github/forks/devAL3X/CVE-2022-46169_poc.svg)


## CVE-2022-45699
 Command injection in the administration interface in APSystems ECU-R version 5203 allows a remote unauthenticated attacker to execute arbitrary commands as root using the timezone parameter.

- [https://github.com/0xst4n/APSystems-ECU-R-RCE-Timezone](https://github.com/0xst4n/APSystems-ECU-R-RCE-Timezone) :  ![starts](https://img.shields.io/github/stars/0xst4n/APSystems-ECU-R-RCE-Timezone.svg) ![forks](https://img.shields.io/github/forks/0xst4n/APSystems-ECU-R-RCE-Timezone.svg)


## CVE-2022-42896
 There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively) remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within proximity of the victim. We recommend upgrading past commit https://www.google.com/url https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4 https://www.google.com/url

- [https://github.com/Trinadh465/linux-4.19.72_CVE-2022-42896](https://github.com/Trinadh465/linux-4.19.72_CVE-2022-42896) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.19.72_CVE-2022-42896.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.19.72_CVE-2022-42896.svg)


## CVE-2022-25012
 Argus Surveillance DVR v4.0 employs weak password encryption.

- [https://github.com/s3l33/CVE-2022-25012](https://github.com/s3l33/CVE-2022-25012) :  ![starts](https://img.shields.io/github/stars/s3l33/CVE-2022-25012.svg) ![forks](https://img.shields.io/github/forks/s3l33/CVE-2022-25012.svg)


## CVE-2022-2097
 AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn't written. In the special case of &quot;in place&quot; encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p).

- [https://github.com/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu](https://github.com/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu) :  ![starts](https://img.shields.io/github/stars/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu.svg) ![forks](https://img.shields.io/github/forks/PeterThomasAwen/OpenSSLUpgrade1.1.1q-Ubuntu.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/ChrisPritchard/CVE-2021-22911-rust](https://github.com/ChrisPritchard/CVE-2021-22911-rust) :  ![starts](https://img.shields.io/github/stars/ChrisPritchard/CVE-2021-22911-rust.svg) ![forks](https://img.shields.io/github/forks/ChrisPritchard/CVE-2021-22911-rust.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape](https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape) :  ![starts](https://img.shields.io/github/stars/Sauercloud/RWCTF21-VirtualBox-61-escape.svg) ![forks](https://img.shields.io/github/forks/Sauercloud/RWCTF21-VirtualBox-61-escape.svg)


## CVE-2019-1003000
 A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.

- [https://github.com/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins](https://github.com/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins) :  ![starts](https://img.shields.io/github/stars/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins.svg) ![forks](https://img.shields.io/github/forks/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/HACHp1/webmin_docker_and_exp](https://github.com/HACHp1/webmin_docker_and_exp) :  ![starts](https://img.shields.io/github/stars/HACHp1/webmin_docker_and_exp.svg) ![forks](https://img.shields.io/github/forks/HACHp1/webmin_docker_and_exp.svg)
- [https://github.com/wenruoya/CVE-2019-15107](https://github.com/wenruoya/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/wenruoya/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/wenruoya/CVE-2019-15107.svg)
- [https://github.com/g1vi/CVE-2019-15107](https://github.com/g1vi/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/g1vi/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/g1vi/CVE-2019-15107.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/jas502n/CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-1388.svg)


## CVE-2018-1999002
 A arbitrary file read vulnerability exists in Jenkins 2.132 and earlier, 2.121.1 and earlier in the Stapler web framework's org/kohsuke/stapler/Stapler.java that allows attackers to send crafted HTTP requests returning the contents of any file on the Jenkins master file system that the Jenkins master has access to.

- [https://github.com/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins](https://github.com/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins) :  ![starts](https://img.shields.io/github/stars/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins.svg) ![forks](https://img.shields.io/github/forks/slowmistio/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1324.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1324.svg)


## CVE-2018-1088
 A privilege escalation flaw was found in gluster 3.x snapshot scheduler. Any gluster client allowed to mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling malicious cronjob via symlink.

- [https://github.com/MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN) :  ![starts](https://img.shields.io/github/stars/MauroEldritch/GEVAUDAN.svg) ![forks](https://img.shields.io/github/forks/MauroEldritch/GEVAUDAN.svg)


## CVE-2017-3000
 Adobe Flash Player versions 24.0.0.221 and earlier have a vulnerability in the random number generator used for constant blinding. Successful exploitation could lead to information disclosure.

- [https://github.com/dangokyo/CVE-2017-3000](https://github.com/dangokyo/CVE-2017-3000) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE-2017-3000.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE-2017-3000.svg)


## CVE-2015-6620
 libstagefright in Android before 5.1.1 LMY48Z and 6.0 before 2015-12-01 allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bugs 24123723 and 24445127.

- [https://github.com/flankerhqd/mediacodecoob](https://github.com/flankerhqd/mediacodecoob) :  ![starts](https://img.shields.io/github/stars/flankerhqd/mediacodecoob.svg) ![forks](https://img.shields.io/github/forks/flankerhqd/mediacodecoob.svg)


## CVE-2010-4180
 OpenSSL before 0.9.8q, and 1.0.x before 1.0.0c, when SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG is enabled, does not properly prevent modification of the ciphersuite in the session cache, which allows remote attackers to force the downgrade to an unintended cipher via vectors involving sniffing network traffic to discover a session identifier.

- [https://github.com/protonnegativo/CVE-2010-4180-by-ChatGPT](https://github.com/protonnegativo/CVE-2010-4180-by-ChatGPT) :  ![starts](https://img.shields.io/github/stars/protonnegativo/CVE-2010-4180-by-ChatGPT.svg) ![forks](https://img.shields.io/github/forks/protonnegativo/CVE-2010-4180-by-ChatGPT.svg)

