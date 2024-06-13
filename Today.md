# Update 2024-06-13
## CVE-2024-30212
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Fehr-GmbH/blackleak](https://github.com/Fehr-GmbH/blackleak) :  ![starts](https://img.shields.io/github/stars/Fehr-GmbH/blackleak.svg) ![forks](https://img.shields.io/github/forks/Fehr-GmbH/blackleak.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/RalfHacker/CVE-2024-26229-exploit](https://github.com/RalfHacker/CVE-2024-26229-exploit) :  ![starts](https://img.shields.io/github/stars/RalfHacker/CVE-2024-26229-exploit.svg) ![forks](https://img.shields.io/github/forks/RalfHacker/CVE-2024-26229-exploit.svg)
- [https://github.com/otterpwn/CVE-2024-26229](https://github.com/otterpwn/CVE-2024-26229) :  ![starts](https://img.shields.io/github/stars/otterpwn/CVE-2024-26229.svg) ![forks](https://img.shields.io/github/forks/otterpwn/CVE-2024-26229.svg)


## CVE-2024-24590
 Deserialization of untrusted data can occur in versions 0.17.0 to 1.14.2 of the client SDK of Allegro AI&#8217;s ClearML platform, enabling a maliciously uploaded artifact to run arbitrary code on an end user&#8217;s system when interacted with.

- [https://github.com/OxyDeV2/PoC-CVE-2024-24590](https://github.com/OxyDeV2/PoC-CVE-2024-24590) :  ![starts](https://img.shields.io/github/stars/OxyDeV2/PoC-CVE-2024-24590.svg) ![forks](https://img.shields.io/github/forks/OxyDeV2/PoC-CVE-2024-24590.svg)
- [https://github.com/LordVileOnX/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-](https://github.com/LordVileOnX/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-) :  ![starts](https://img.shields.io/github/stars/LordVileOnX/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-.svg) ![forks](https://img.shields.io/github/forks/LordVileOnX/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-.svg)


## CVE-2024-23692
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/k3lpi3b4nsh33/CVE-2024-23692](https://github.com/k3lpi3b4nsh33/CVE-2024-23692) :  ![starts](https://img.shields.io/github/stars/k3lpi3b4nsh33/CVE-2024-23692.svg) ![forks](https://img.shields.io/github/forks/k3lpi3b4nsh33/CVE-2024-23692.svg)


## CVE-2024-4577
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nemu1k5ma/CVE-2024-4577](https://github.com/nemu1k5ma/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/nemu1k5ma/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/nemu1k5ma/CVE-2024-4577.svg)
- [https://github.com/aaddmin1122345/CVE-2024-4577-POC](https://github.com/aaddmin1122345/CVE-2024-4577-POC) :  ![starts](https://img.shields.io/github/stars/aaddmin1122345/CVE-2024-4577-POC.svg) ![forks](https://img.shields.io/github/forks/aaddmin1122345/CVE-2024-4577-POC.svg)
- [https://github.com/bl4cksku11/CVE-2024-4577](https://github.com/bl4cksku11/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/bl4cksku11/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/bl4cksku11/CVE-2024-4577.svg)


## CVE-2024-3705
 Unrestricted file upload vulnerability in OpenGnsys affecting version 1.1.1d (Espeto). This vulnerability allows an attacker to send a POST request to the endpoint '/opengnsys/images/M_Icons.php' modifying the file extension, due to lack of file extension verification, resulting in a webshell injection.

- [https://github.com/LeadroyaL/CVE-2024-37051-EXP](https://github.com/LeadroyaL/CVE-2024-37051-EXP) :  ![starts](https://img.shields.io/github/stars/LeadroyaL/CVE-2024-37051-EXP.svg) ![forks](https://img.shields.io/github/forks/LeadroyaL/CVE-2024-37051-EXP.svg)


## CVE-2024-3094
 Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/shefirot/CVE-2024-3094](https://github.com/shefirot/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/shefirot/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/shefirot/CVE-2024-3094.svg)


## CVE-2023-34040
 In Spring for Apache Kafka 3.0.9 and earlier and versions 2.9.10 and earlier, a possible deserialization attack vector existed, but only if unusual configuration was applied. An attacker would have to construct a malicious serialized object in one of the deserialization exception record headers. Specifically, an application is vulnerable when all of the following are true: * The user does not configure an ErrorHandlingDeserializer for the key and/or value of the record * The user explicitly sets container properties checkDeserExWhenKeyNull and/or checkDeserExWhenValueNull container properties to true. * The user allows untrusted sources to publish to a Kafka topic By default, these properties are false, and the container only attempts to deserialize the headers if an ErrorHandlingDeserializer is configured. The ErrorHandlingDeserializer prevents the vulnerability by removing any such malicious headers before processing the record.

- [https://github.com/buiduchoang24/CVE-2023-34040](https://github.com/buiduchoang24/CVE-2023-34040) :  ![starts](https://img.shields.io/github/stars/buiduchoang24/CVE-2023-34040.svg) ![forks](https://img.shields.io/github/forks/buiduchoang24/CVE-2023-34040.svg)


## CVE-2023-33733
 Reportlab up to v3.6.12 allows attackers to execute arbitrary code via supplying a crafted PDF file.

- [https://github.com/buiduchoang24/CVE-2023-33733](https://github.com/buiduchoang24/CVE-2023-33733) :  ![starts](https://img.shields.io/github/stars/buiduchoang24/CVE-2023-33733.svg) ![forks](https://img.shields.io/github/forks/buiduchoang24/CVE-2023-33733.svg)


## CVE-2023-29360
 Microsoft Streaming Service Elevation of Privilege Vulnerability

- [https://github.com/ISH2YU/CVE-2023-11518](https://github.com/ISH2YU/CVE-2023-11518) :  ![starts](https://img.shields.io/github/stars/ISH2YU/CVE-2023-11518.svg) ![forks](https://img.shields.io/github/forks/ISH2YU/CVE-2023-11518.svg)


## CVE-2023-20598
 An improper privilege management in the AMD Radeon&#8482; Graphics driver may allow an authenticated attacker to craft an IOCTL request to gain I/O control over arbitrary hardware ports or physical addresses resulting in a potential arbitrary code execution.

- [https://github.com/H4rk3nz0/CVE-2023-20598-PDFWKRNL](https://github.com/H4rk3nz0/CVE-2023-20598-PDFWKRNL) :  ![starts](https://img.shields.io/github/stars/H4rk3nz0/CVE-2023-20598-PDFWKRNL.svg) ![forks](https://img.shields.io/github/forks/H4rk3nz0/CVE-2023-20598-PDFWKRNL.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/HPT-Intern-Task-Submission/CVE-2022-46169](https://github.com/HPT-Intern-Task-Submission/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/HPT-Intern-Task-Submission/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/HPT-Intern-Task-Submission/CVE-2022-46169.svg)


## CVE-2019-19030
 Cloud Native Computing Foundation Harbor before 1.10.3 and 2.x before 2.0.1 allows resource enumeration because unauthenticated API calls reveal (via the HTTP status code) whether a resource exists.

- [https://github.com/shodanwashere/boatcrash](https://github.com/shodanwashere/boatcrash) :  ![starts](https://img.shields.io/github/stars/shodanwashere/boatcrash.svg) ![forks](https://img.shields.io/github/forks/shodanwashere/boatcrash.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/raytran54/CVE-2018-7600](https://github.com/raytran54/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/raytran54/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/raytran54/CVE-2018-7600.svg)

