# Update 2023-09-12
## CVE-2023-37756
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below) :  ![starts](https://img.shields.io/github/stars/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below.svg) ![forks](https://img.shields.io/github/forks/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below.svg)


## CVE-2023-37755
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/leekenghwa/CVE-2023-37755---Hardcoded-Admin-Credential-in-i-doit-Pro-25-and-below](https://github.com/leekenghwa/CVE-2023-37755---Hardcoded-Admin-Credential-in-i-doit-Pro-25-and-below) :  ![starts](https://img.shields.io/github/stars/leekenghwa/CVE-2023-37755---Hardcoded-Admin-Credential-in-i-doit-Pro-25-and-below.svg) ![forks](https://img.shields.io/github/forks/leekenghwa/CVE-2023-37755---Hardcoded-Admin-Credential-in-i-doit-Pro-25-and-below.svg)


## CVE-2023-37739
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below](https://github.com/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below) :  ![starts](https://img.shields.io/github/stars/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below.svg) ![forks](https://img.shields.io/github/forks/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below.svg)


## CVE-2023-27997
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/Cyb3rEnthusiast/CVE-2023-27997](https://github.com/Cyb3rEnthusiast/CVE-2023-27997) :  ![starts](https://img.shields.io/github/stars/Cyb3rEnthusiast/CVE-2023-27997.svg) ![forks](https://img.shields.io/github/forks/Cyb3rEnthusiast/CVE-2023-27997.svg)


## CVE-2023-20052
 On Feb 15, 2023, the following vulnerability in the ClamAV scanning library was disclosed: A vulnerability in the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and earlier could allow an unauthenticated, remote attacker to access sensitive information on an affected device. This vulnerability is due to enabling XML entity substitution that may result in XML external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file that may be read by the ClamAV scanning process.

- [https://github.com/cY83rR0H1t/CVE-2023-20052](https://github.com/cY83rR0H1t/CVE-2023-20052) :  ![starts](https://img.shields.io/github/stars/cY83rR0H1t/CVE-2023-20052.svg) ![forks](https://img.shields.io/github/forks/cY83rR0H1t/CVE-2023-20052.svg)


## CVE-2023-3450
 A vulnerability was found in Ruijie RG-BCR860 2.5.13 and classified as critical. This issue affects some unknown processing of the component Network Diagnostic Page. The manipulation leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-232547. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/caopengyan/CVE-2023-3450](https://github.com/caopengyan/CVE-2023-3450) :  ![starts](https://img.shields.io/github/stars/caopengyan/CVE-2023-3450.svg) ![forks](https://img.shields.io/github/forks/caopengyan/CVE-2023-3450.svg)


## CVE-2023-2825
 An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.

- [https://github.com/caopengyan/CVE-2023-2825](https://github.com/caopengyan/CVE-2023-2825) :  ![starts](https://img.shields.io/github/stars/caopengyan/CVE-2023-2825.svg) ![forks](https://img.shields.io/github/forks/caopengyan/CVE-2023-2825.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/copyleftdev/PricklyPwn](https://github.com/copyleftdev/PricklyPwn) :  ![starts](https://img.shields.io/github/stars/copyleftdev/PricklyPwn.svg) ![forks](https://img.shields.io/github/forks/copyleftdev/PricklyPwn.svg)


## CVE-2022-27997
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Cyb3rEnthusiast/CVE-2023-27997](https://github.com/Cyb3rEnthusiast/CVE-2023-27997) :  ![starts](https://img.shields.io/github/stars/Cyb3rEnthusiast/CVE-2023-27997.svg) ![forks](https://img.shields.io/github/forks/Cyb3rEnthusiast/CVE-2023-27997.svg)


## CVE-2021-46398
 A Cross-Site Request Forgery vulnerability exists in Filebrowser &lt; 2.18.0 that allows attackers to create a backdoor user with admin privilege and get access to the filesystem via a malicious HTML webpage that is sent to the victim. An admin can run commands using the FileBrowser and hence it leads to RCE.

- [https://github.com/LalieA/CVE-2021-46398](https://github.com/LalieA/CVE-2021-46398) :  ![starts](https://img.shields.io/github/stars/LalieA/CVE-2021-46398.svg) ![forks](https://img.shields.io/github/forks/LalieA/CVE-2021-46398.svg)


## CVE-2021-3712
 ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not a strict requirement, ASN.1 strings that are parsed using OpenSSL's own &quot;d2i&quot; functions (and other similar parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array by directly setting the &quot;data&quot; and &quot;length&quot; fields in the ASN1_STRING array. This can also happen by using the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for strings that have been directly constructed. Where an application requests an ASN.1 structure to be printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the application without NUL terminating the &quot;data&quot; field, then a read buffer overrun can occur. The same thing can also occur during name constraints processing of certificates (for example if a certificate has been directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack). It could also result in the disclosure of private memory contents (such as private keys, or sensitive plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3712](https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3712) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3712.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_CVE-2021-3712.svg)


## CVE-2010-0232
 The kernel in Microsoft Windows NT 3.1 through Windows 7, including Windows 2000 SP4, Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista Gold, SP1, and SP2, and Windows Server 2008 Gold and SP2, when access to 16-bit applications is enabled on a 32-bit x86 platform, does not properly validate certain BIOS calls, which allows local users to gain privileges by crafting a VDM_TIB data structure in the Thread Environment Block (TEB), and then calling the NtVdmControl function to start the Windows Virtual DOS Machine (aka NTVDM) subsystem, leading to improperly handled exceptions involving the #GP trap handler (nt!KiTrap0D), aka &quot;Windows Kernel Exception Handler Vulnerability.&quot;

- [https://github.com/azorfus/CVE-2010-0232](https://github.com/azorfus/CVE-2010-0232) :  ![starts](https://img.shields.io/github/stars/azorfus/CVE-2010-0232.svg) ![forks](https://img.shields.io/github/forks/azorfus/CVE-2010-0232.svg)

