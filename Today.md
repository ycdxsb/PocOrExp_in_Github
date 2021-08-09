# Update 2021-08-09
## CVE-2021-38185
 GNU cpio through 2.13 allows attackers to execute arbitrary code via a crafted pattern file, because of a dstring.c ds_fgetstr integer overflow that triggers an out-of-bounds heap write. NOTE: it is unclear whether there are common cases where the pattern file, associated with the -E option, is untrusted data.

- [https://github.com/fangqyi/cpiopwn](https://github.com/fangqyi/cpiopwn) :  ![starts](https://img.shields.io/github/stars/fangqyi/cpiopwn.svg) ![forks](https://img.shields.io/github/forks/fangqyi/cpiopwn.svg)


## CVE-2021-36983
 replay-sorcery-kms in Replay Sorcery 0.6.0 allows a local attacker to gain root privileges via a symlink attack on /tmp/replay-sorcery or /tmp/replay-sorcery/device.sock.

- [https://github.com/AlAIAL90/CVE-2021-36983](https://github.com/AlAIAL90/CVE-2021-36983) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36983.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36983.svg)


## CVE-2021-36754
 PowerDNS Authoritative Server 4.5.0 before 4.5.1 allows anybody to crash the process by sending a specific query (QTYPE 65535) that causes an out-of-bounds exception.

- [https://github.com/AlAIAL90/CVE-2021-36754](https://github.com/AlAIAL90/CVE-2021-36754) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36754.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36754.svg)


## CVE-2021-36217
 Avahi 0.8 allows a local denial of service (NULL pointer dereference and daemon crash) against avahi-daemon via the D-Bus interface or a &quot;ping .local&quot; command.

- [https://github.com/AlAIAL90/CVE-2021-36217](https://github.com/AlAIAL90/CVE-2021-36217) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36217.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36217.svg)


## CVE-2021-36004
 Adobe InDesign version 16.0 (and earlier) is affected by an Out-of-bounds Write vulnerability in the CoolType library. An unauthenticated attacker could leverage this vulnerability to achieve remote code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AlAIAL90/CVE-2021-36004](https://github.com/AlAIAL90/CVE-2021-36004) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36004.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36004.svg)


## CVE-2021-35479
 Nagios Log Server before 2.1.9 contains Stored XSS in the custom column view for the alert history and audit log function through the affected pp parameter. This affects users who open a crafted link or third-party web page.

- [https://github.com/AlAIAL90/CVE-2021-35479](https://github.com/AlAIAL90/CVE-2021-35479) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-35479.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-35479.svg)


## CVE-2021-35478
 Nagios Log Server before 2.1.9 contains Reflected XSS in the dropdown box for the alert history and audit log function. All parameters used for filtering are affected. This affects users who open a crafted link or third-party web page.

- [https://github.com/AlAIAL90/CVE-2021-35478](https://github.com/AlAIAL90/CVE-2021-35478) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-35478.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-35478.svg)


## CVE-2021-32610
 In Archive_Tar before 1.4.14, symlinks can refer to targets outside of the extracted archive, a different vulnerability than CVE-2020-36193.

- [https://github.com/AlAIAL90/CVE-2021-32610](https://github.com/AlAIAL90/CVE-2021-32610) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-32610.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-32610.svg)


## CVE-2021-32558
 An issue was discovered in Sangoma Asterisk 13.x before 13.38.3, 16.x before 16.19.1, 17.x before 17.9.4, and 18.x before 18.5.1, and Certified Asterisk before 16.8-cert10. If the IAX2 channel driver receives a packet that contains an unsupported media format, a crash can occur.

- [https://github.com/AlAIAL90/CVE-2021-32558](https://github.com/AlAIAL90/CVE-2021-32558) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-32558.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-32558.svg)


## CVE-2021-31878
 An issue was discovered in PJSIP in Asterisk before 16.19.1 and before 18.5.1. To exploit, a re-INVITE without SDP must be received after Asterisk has sent a BYE request.

- [https://github.com/AlAIAL90/CVE-2021-31878](https://github.com/AlAIAL90/CVE-2021-31878) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-31878.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-31878.svg)


## CVE-2021-31799
 In RDoc 3.11 through 6.x before 6.3.1, as distributed with Ruby through 3.0.1, it is possible to execute arbitrary code via | and tags in a filename.

- [https://github.com/AlAIAL90/CVE-2021-31799](https://github.com/AlAIAL90/CVE-2021-31799) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-31799.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-31799.svg)


## CVE-2021-29425
 In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input string, like &quot;//../foo&quot;, or &quot;\\..\foo&quot;, the result would be the same value, thus possibly providing access to files in the parent directory, but not further above (thus &quot;limited&quot; path traversal), if the calling code would use the result to construct a path value.

- [https://github.com/AlAIAL90/CVE-2021-29425](https://github.com/AlAIAL90/CVE-2021-29425) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-29425.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-29425.svg)


## CVE-2021-28966
 In Ruby through 3.0 on Windows, a remote attacker can submit a crafted path when a Web application handles a parameter with TmpDir.

- [https://github.com/AlAIAL90/CVE-2021-28966](https://github.com/AlAIAL90/CVE-2021-28966) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28966.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28966.svg)


## CVE-2021-28674
 The node management page in SolarWinds Orion Platform before 2020.2.5 HF1 allows an attacker to create or delete a node (outside of the attacker's perimeter) via an account with write permissions. This occurs because node IDs are predictable (with incrementing numbers) and the access control on Services/NodeManagement.asmx/DeleteObjNow is incorrect. To exploit this, an attacker must be authenticated and must have node management rights associated with at least one valid group on the platform.

- [https://github.com/AlAIAL90/CVE-2021-28674](https://github.com/AlAIAL90/CVE-2021-28674) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28674.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28674.svg)


## CVE-2021-28169
 For Eclipse Jetty versions &lt;= 9.4.40, &lt;= 10.0.2, &lt;= 11.0.2, it is possible for requests to the ConcatServlet with a doubly encoded path to access protected resources within the WEB-INF directory. For example a request to `/concat?/%2557EB-INF/web.xml` can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/AlAIAL90/CVE-2021-28169](https://github.com/AlAIAL90/CVE-2021-28169) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28169.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28169.svg)


## CVE-2021-28165
 In Eclipse Jetty 7.2.2 to 9.4.38, 10.0.0.alpha0 to 10.0.1, and 11.0.0.alpha0 to 11.0.1, CPU usage can reach 100% upon receiving a large invalid TLS frame.

- [https://github.com/AlAIAL90/CVE-2021-28165](https://github.com/AlAIAL90/CVE-2021-28165) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28165.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28165.svg)


## CVE-2021-22898
 curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized data from a stack based buffer to the server, resulting in potentially revealing sensitive internal information to the server using a clear-text network protocol.

- [https://github.com/AlAIAL90/CVE-2021-22898](https://github.com/AlAIAL90/CVE-2021-22898) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-22898.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-22898.svg)


## CVE-2021-21295
 Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers &amp; clients. In Netty (io.netty:netty-codec-http2) before version 4.1.60.Final there is a vulnerability that enables request smuggling. If a Content-Length header is present in the original HTTP/2 request, the field is not validated by `Http2MultiplexHandler` as it is propagated up. This is fine as long as the request is not proxied through as HTTP/1.1. If the request comes in as an HTTP/2 stream, gets converted into the HTTP/1.1 domain objects (`HttpRequest`, `HttpContent`, etc.) via `Http2StreamFrameToHttpObjectCodec `and then sent up to the child channel's pipeline and proxied through a remote peer as HTTP/1.1 this may result in request smuggling. In a proxy case, users may assume the content-length is validated somehow, which is not the case. If the request is forwarded to a backend channel that is a HTTP/1.1 connection, the Content-Length now has meaning and needs to be checked. An attacker can smuggle requests inside the body as it gets downgraded from HTTP/2 to HTTP/1.1. For an example attack refer to the linked GitHub Advisory. Users are only affected if all of this is true: `HTTP2MultiplexCodec` or `Http2FrameCodec` is used, `Http2StreamFrameToHttpObjectCodec` is used to convert to HTTP/1.1 objects, and these HTTP/1.1 objects are forwarded to another remote peer. This has been patched in 4.1.60.Final As a workaround, the user can do the validation by themselves by implementing a custom `ChannelInboundHandler` that is put in the `ChannelPipeline` behind `Http2StreamFrameToHttpObjectCodec`.

- [https://github.com/AlAIAL90/CVE-2021-21295](https://github.com/AlAIAL90/CVE-2021-21295) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21295.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21295.svg)


## CVE-2021-20786
 Cross-site request forgery (CSRF) vulnerability in GroupSession (GroupSession Free edition from ver2.2.0 to the version prior to ver5.1.0, GroupSession byCloud from ver3.0.3 to the version prior to ver5.1.0, and GroupSession ZION from ver3.0.3 to the version prior to ver5.1.0) allows a remote attacker to hijack the authentication of administrators via a specially crafted URL.

- [https://github.com/AlAIAL90/CVE-2021-20786](https://github.com/AlAIAL90/CVE-2021-20786) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20786.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20786.svg)


## CVE-2021-20228
 A flaw was found in the Ansible Engine 2.9.18, where sensitive info is not masked by default and is not protected by the no_log feature when using the sub-option feature of the basic.py module. This flaw allows an attacker to obtain sensitive information. The highest threat from this vulnerability is to confidentiality.

- [https://github.com/AlAIAL90/CVE-2021-20228](https://github.com/AlAIAL90/CVE-2021-20228) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20228.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20228.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/CyberCommands/CVE-2021-3156](https://github.com/CyberCommands/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/CyberCommands/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/CyberCommands/CVE-2021-3156.svg)


## CVE-2021-0129
 Improper access control in BlueZ may allow an authenticated user to potentially enable information disclosure via adjacent access.

- [https://github.com/AlAIAL90/CVE-2021-0129](https://github.com/AlAIAL90/CVE-2021-0129) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-0129.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-0129.svg)


## CVE-2020-36193
 Tar.php in Archive_Tar through 1.4.11 allows write operations with Directory Traversal due to inadequate checking of symbolic links, a related issue to CVE-2020-28948.

- [https://github.com/AlAIAL90/CVE-2021-32610](https://github.com/AlAIAL90/CVE-2021-32610) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-32610.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-32610.svg)


## CVE-2020-27153
 In BlueZ before 5.55, a double free was found in the gatttool disconnect_cb() routine from shared/att.c. A remote attacker could potentially cause a denial of service or code execution, during service discovery, due to a redundant disconnect MGMT event.

- [https://github.com/AlAIAL90/CVE-2020-27153](https://github.com/AlAIAL90/CVE-2020-27153) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-27153.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-27153.svg)


## CVE-2020-26558
 Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication procedure) by reflection of the public key and the authentication evidence of the initiating device, potentially permitting this attacker to complete authenticated pairing with the responding device using the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit at a time.

- [https://github.com/AlAIAL90/CVE-2020-26558](https://github.com/AlAIAL90/CVE-2020-26558) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-26558.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-26558.svg)


## CVE-2020-14365
 A flaw was found in the Ansible Engine, in ansible-engine 2.8.x before 2.8.15 and ansible-engine 2.9.x before 2.9.13, when installing packages using the dnf module. GPG signatures are ignored during installation even when disable_gpg_check is set to False, which is the default behavior. This flaw leads to malicious packages being installed on the system and arbitrary code executed via package installation scripts. The highest threat from this vulnerability is to integrity and system availability.

- [https://github.com/AlAIAL90/CVE-2020-14365](https://github.com/AlAIAL90/CVE-2020-14365) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-14365.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-14365.svg)


## CVE-2020-14332
 A flaw was found in the Ansible Engine when using module_args. Tasks executed with check mode (--check-mode) do not properly neutralize sensitive data exposed in the event data. This flaw allows unauthorized users to read this data. The highest threat from this vulnerability is to confidentiality.

- [https://github.com/AlAIAL90/CVE-2020-14332](https://github.com/AlAIAL90/CVE-2020-14332) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-14332.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-14332.svg)


## CVE-2020-14330
 An Improper Output Neutralization for Logs flaw was found in Ansible when using the uri module, where sensitive data is exposed to content and json output. This flaw allows an attacker to access the logs or outputs of performed tasks to read keys used in playbooks from other users within the uri module. The highest threat from this vulnerability is to data confidentiality.

- [https://github.com/AlAIAL90/CVE-2020-14330](https://github.com/AlAIAL90/CVE-2020-14330) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-14330.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-14330.svg)


## CVE-2020-10729
 A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the same length generate the equal value as the template caching action for the same file since no re-evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at once for the file. This flaw affects Ansible Engine versions before 2.9.6.

- [https://github.com/AlAIAL90/CVE-2020-10729](https://github.com/AlAIAL90/CVE-2020-10729) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-10729.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-10729.svg)


## CVE-2020-10685
 A flaw was found in Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x before 2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and 3.5.5 and 3.6.3 when using modules which decrypts vault files such as assemble, script, unarchive, win_copy, aws_s3 or copy modules. The temporary directory is created in /tmp leaves the s ts unencrypted. On Operating Systems which /tmp is not a tmpfs but part of the root partition, the directory is only cleared on boot and the decryp emains when the host is switched off. The system will be vulnerable when the system is not running. So decrypted data must be cleared as soon as possible and the data which normally is encrypted ble.

- [https://github.com/AlAIAL90/CVE-2020-10685](https://github.com/AlAIAL90/CVE-2020-10685) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-10685.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-10685.svg)


## CVE-2020-10684
 A flaw was found in Ansible Engine, all versions 2.7.x, 2.8.x and 2.9.x prior to 2.7.17, 2.8.9 and 2.9.6 respectively, when using ansible_facts as a subkey of itself and promoting it to a variable when inject is enabled, overwriting the ansible_facts after the clean. An attacker could take advantage of this by altering the ansible_facts, such as ansible_hosts, users and any other key data which would lead into privilege escalation or code injection.

- [https://github.com/AlAIAL90/CVE-2020-10684](https://github.com/AlAIAL90/CVE-2020-10684) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-10684.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-10684.svg)


## CVE-2020-3477
 A vulnerability in the CLI parser of Cisco IOS Software and Cisco IOS XE Software could allow an authenticated, local attacker to access files from the flash: filesystem. The vulnerability is due to insufficient application of restrictions during the execution of a specific command. An attacker could exploit this vulnerability by using a specific command at the command line. A successful exploit could allow the attacker to obtain read-only access to files that are located on the flash: filesystem that otherwise might not have been accessible.

- [https://github.com/AlAIAL90/CVE-2020-3477](https://github.com/AlAIAL90/CVE-2020-3477) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3477.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3477.svg)


## CVE-2020-3475
 Multiple vulnerabilities in the web management framework of Cisco IOS XE Software could allow an authenticated, remote attacker with read-only privileges to gain unauthorized read access to sensitive data or cause the web management software to hang or crash, resulting in a denial of service (DoS) condition. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/AlAIAL90/CVE-2020-3475](https://github.com/AlAIAL90/CVE-2020-3475) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3475.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3475.svg)


## CVE-2020-3472
 A vulnerability in the contacts feature of Cisco Webex Meetings could allow an authenticated, remote attacker with a legitimate user account to access sensitive information. The vulnerability is due to improper access restrictions on users who are added within user contacts. An attacker on one Webex Meetings site could exploit this vulnerability by sending specially crafted requests to the Webex Meetings site. A successful exploit could allow the attacker to view the details of users on another Webex site, including user names and email addresses.

- [https://github.com/AlAIAL90/CVE-2020-3472](https://github.com/AlAIAL90/CVE-2020-3472) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3472.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3472.svg)


## CVE-2020-3471
 A vulnerability in Cisco Webex Meetings and Cisco Webex Meetings Server could allow an unauthenticated, remote attacker to maintain bidirectional audio despite being expelled from an active Webex session. The vulnerability is due to a synchronization issue between meeting and media services on a vulnerable Webex site. An attacker could exploit this vulnerability by sending crafted requests to a vulnerable Cisco Webex Meetings or Cisco Webex Meetings Server site. A successful exploit could allow the attacker to maintain the audio connection of a Webex session despite being expelled.

- [https://github.com/AlAIAL90/CVE-2020-3471](https://github.com/AlAIAL90/CVE-2020-3471) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3471.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3471.svg)


## CVE-2020-3470
 Multiple vulnerabilities in the API subsystem of Cisco Integrated Management Controller (IMC) could allow an unauthenticated, remote attacker to execute arbitrary code with root privileges. The vulnerabilities are due to improper boundary checks for certain user-supplied input. An attacker could exploit these vulnerabilities by sending a crafted HTTP request to the API subsystem of an affected system. When this request is processed, an exploitable buffer overflow condition may occur. A successful exploit could allow the attacker to execute arbitrary code with root privileges on the underlying operating system (OS).

- [https://github.com/AlAIAL90/CVE-2020-3470](https://github.com/AlAIAL90/CVE-2020-3470) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3470.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3470.svg)


## CVE-2020-3465
 A vulnerability in Cisco IOS XE Software could allow an unauthenticated, adjacent attacker to cause a device to reload. The vulnerability is due to incorrect handling of certain valid, but not typical, Ethernet frames. An attacker could exploit this vulnerability by sending the Ethernet frames onto the Ethernet segment. A successful exploit could allow the attacker to cause the device to reload, resulting in a denial of service (DoS) condition.

- [https://github.com/AlAIAL90/CVE-2020-3465](https://github.com/AlAIAL90/CVE-2020-3465) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3465.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3465.svg)


## CVE-2020-3453
 Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 Series Routers could allow an authenticated, remote attacker with administrative credentials to execute arbitrary commands on the underlying operating system (OS) as a restricted user. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/AlAIAL90/CVE-2020-3453](https://github.com/AlAIAL90/CVE-2020-3453) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3453.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3453.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/AlAIAL90/CVE-2020-3452](https://github.com/AlAIAL90/CVE-2020-3452) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3452.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3452.svg)


## CVE-2020-3451
 Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 Series Routers could allow an authenticated, remote attacker with administrative credentials to execute arbitrary commands on the underlying operating system (OS) as a restricted user. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/AlAIAL90/CVE-2020-3451](https://github.com/AlAIAL90/CVE-2020-3451) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3451.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3451.svg)


## CVE-2020-3444
 A vulnerability in the packet filtering features of Cisco SD-WAN Software could allow an unauthenticated, remote attacker to bypass L3 and L4 traffic filters. The vulnerability is due to improper traffic filtering conditions on an affected device. An attacker could exploit this vulnerability by crafting a malicious TCP packet with specific characteristics and sending it to a targeted device. A successful exploit could allow the attacker to bypass the L3 and L4 traffic filters and inject an arbitrary packet into the network.

- [https://github.com/AlAIAL90/CVE-2020-3444](https://github.com/AlAIAL90/CVE-2020-3444) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3444.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3444.svg)


## CVE-2020-3441
 A vulnerability in Cisco Webex Meetings and Cisco Webex Meetings Server could allow an unauthenticated, remote attacker to view sensitive information from the meeting room lobby. This vulnerability is due to insufficient protection of sensitive participant information. An attacker could exploit this vulnerability by browsing the Webex roster. A successful exploit could allow the attacker to gather information about other Webex participants, such as email address and IP address, while waiting in the lobby.

- [https://github.com/AlAIAL90/CVE-2020-3441](https://github.com/AlAIAL90/CVE-2020-3441) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3441.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3441.svg)


## CVE-2020-3435
 A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to overwrite VPN profiles on an affected device. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system. The vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process on an affected device. A successful exploit could allow the attacker to modify VPN profile files. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system.

- [https://github.com/AlAIAL90/CVE-2020-3435](https://github.com/AlAIAL90/CVE-2020-3435) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3435.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3435.svg)


## CVE-2020-3434
 A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to cause a denial of service (DoS) condition on an affected device. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system. The vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process on an affected device. A successful exploit could allow the attacker to stop the AnyConnect process, causing a DoS condition on the device. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system.

- [https://github.com/AlAIAL90/CVE-2020-3434](https://github.com/AlAIAL90/CVE-2020-3434) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3434.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3434.svg)


## CVE-2020-3429
 A vulnerability in the WPA2 and WPA3 security implementation of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family could allow an unauthenticated, adjacent attacker to cause denial of service (DoS) condition on an affected device. The vulnerability is due to incorrect packet processing during the WPA2 and WPA3 authentication handshake when configured for dot1x or pre-shared key (PSK) authentication key management (AKM) with 802.11r BSS Fast Transition (FT) enabled. An attacker could exploit this vulnerability by sending a crafted authentication packet to an affected device. A successful exploit could cause an affected device to reload, resulting in a DoS condition.

- [https://github.com/AlAIAL90/CVE-2020-3429](https://github.com/AlAIAL90/CVE-2020-3429) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3429.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3429.svg)


## CVE-2020-3426
 A vulnerability in the implementation of the Low Power, Wide Area (LPWA) subsystem of Cisco IOS Software for Cisco 800 Series Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) could allow an unauthenticated, remote attacker to gain unauthorized read access to sensitive data or cause a denial of service (DoS) condition. The vulnerability is due to a lack of input and validation checking mechanisms for virtual-LPWA (VLPWA) protocol modem messages. An attacker could exploit this vulnerability by supplying crafted packets to an affected device. A successful exploit could allow the attacker to gain unauthorized read access to sensitive data or cause the VLPWA interface of the affected device to shut down, resulting in DoS condition.

- [https://github.com/AlAIAL90/CVE-2020-3426](https://github.com/AlAIAL90/CVE-2020-3426) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3426.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3426.svg)


## CVE-2020-3398
 A vulnerability in the Border Gateway Protocol (BGP) Multicast VPN (MVPN) implementation of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a BGP session to repeatedly reset, causing a partial denial of service (DoS) condition due to the BGP session being down. The vulnerability is due to incorrect parsing of a specific type of BGP MVPN update message. An attacker could exploit this vulnerability by sending this BGP MVPN update message to a targeted device. A successful exploit could allow the attacker to cause the BGP peer connections to reset, which could lead to BGP route instability and impact traffic. The incoming BGP MVPN update message is valid but is parsed incorrectly by the NX-OS device, which could send a corrupted BGP update to the configured BGP peer. Note: The Cisco implementation of BGP accepts incoming BGP traffic from only explicitly configured peers. To exploit this vulnerability, an attacker must send a specific BGP MVPN update message over an established TCP connection that appears to come from a trusted BGP peer. To do so, the attacker must obtain information about the BGP peers in the trusted network of the affected system.

- [https://github.com/AlAIAL90/CVE-2020-3398](https://github.com/AlAIAL90/CVE-2020-3398) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3398.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3398.svg)


## CVE-2020-3391
 A vulnerability in Cisco Digital Network Architecture (DNA) Center could allow an authenticated, remote attacker to view sensitive information in clear text. The vulnerability is due to insecure storage of certain unencrypted credentials on an affected device. An attacker could exploit this vulnerability by viewing the network device configuration and obtaining credentials that they may not normally have access to. A successful exploit could allow the attacker to use those credentials to discover and manage network devices.

- [https://github.com/AlAIAL90/CVE-2020-3391](https://github.com/AlAIAL90/CVE-2020-3391) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3391.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3391.svg)


## CVE-2020-3387
 A vulnerability in Cisco SD-WAN vManage Software could allow an authenticated, remote attacker to execute code with root privileges on an affected system. The vulnerability is due to insufficient input sanitization during user authentication processing. An attacker could exploit this vulnerability by sending a crafted response to the Cisco SD-WAN vManage Software. A successful exploit could allow the attacker to access the software and execute commands they should not be authorized to execute.

- [https://github.com/AlAIAL90/CVE-2020-3387](https://github.com/AlAIAL90/CVE-2020-3387) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3387.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3387.svg)


## CVE-2020-3383
 A vulnerability in the archive utility of Cisco Data Center Network Manager (DCNM) could allow an authenticated, remote attacker to conduct directory traversal attacks on an affected device. The vulnerability is due to a lack of proper input validation of paths that are embedded within archive files. An attacker could exploit this vulnerability by sending a crafted request to an affected device. A successful exploit could allow the attacker to write arbitrary files in the system with the privileges of the logged-in user.

- [https://github.com/AlAIAL90/CVE-2020-3383](https://github.com/AlAIAL90/CVE-2020-3383) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3383.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3383.svg)


## CVE-2020-3379
 A vulnerability in Cisco SD-WAN Solution Software could allow an authenticated, local attacker to elevate privileges to Administrator on the underlying operating system. The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a crafted request to an affected system. A successful exploit could allow the attacker to gain administrative privileges.

- [https://github.com/AlAIAL90/CVE-2020-3379](https://github.com/AlAIAL90/CVE-2020-3379) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-3379.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-3379.svg)


## CVE-2020-1753
 A security flaw was found in Ansible Engine, all Ansible 2.7.x versions prior to 2.7.17, all Ansible 2.8.x versions prior to 2.8.11 and all Ansible 2.9.x versions prior to 2.9.7, when managing kubernetes using the k8s module. Sensitive parameters such as passwords and tokens are passed to kubectl from the command line, not using an environment variable or an input configuration file. This will disclose passwords and tokens from process list and no_log directive from debug module would not have any effect making these secrets being disclosed on stdout and log files.

- [https://github.com/AlAIAL90/CVE-2020-1753](https://github.com/AlAIAL90/CVE-2020-1753) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-1753.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-1753.svg)


## CVE-2020-1746
 A flaw was found in the Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x before 2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and 3.5.5 and 3.6.3 when the ldap_attr and ldap_entry community modules are used. The issue discloses the LDAP bind password to stdout or a log file if a playbook task is written using the bind_pw in the parameters field. The highest threat from this vulnerability is data confidentiality.

- [https://github.com/AlAIAL90/CVE-2020-1746](https://github.com/AlAIAL90/CVE-2020-1746) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-1746.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-1746.svg)


## CVE-2020-1740
 A flaw was found in Ansible Engine when using Ansible Vault for editing encrypted files. When a user executes &quot;ansible-vault edit&quot;, another user on the same computer can read the old and new secret, as it is created in a temporary file with mkstemp and the returned file descriptor is closed and the method write_data is called to write the existing secret in the file. This method will delete the file before recreating it insecurely. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable.

- [https://github.com/AlAIAL90/CVE-2020-1740](https://github.com/AlAIAL90/CVE-2020-1740) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-1740.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-1740.svg)


## CVE-2020-1739
 A flaw was found in Ansible 2.7.16 and prior, 2.8.8 and prior, and 2.9.5 and prior when a password is set with the argument &quot;password&quot; of svn module, it is used on svn command line, disclosing to other users within the same node. An attacker could take advantage by reading the cmdline file from that particular PID on the procfs.

- [https://github.com/AlAIAL90/CVE-2020-1739](https://github.com/AlAIAL90/CVE-2020-1739) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-1739.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-1739.svg)


## CVE-2020-1735
 A flaw was found in the Ansible Engine when the fetch module is used. An attacker could intercept the module, inject a new path, and then choose a new destination path on the controller node. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable.

- [https://github.com/AlAIAL90/CVE-2020-1735](https://github.com/AlAIAL90/CVE-2020-1735) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-1735.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-1735.svg)


## CVE-2020-1733
 A race condition flaw was found in Ansible Engine 2.7.17 and prior, 2.8.9 and prior, 2.9.6 and prior when running a playbook with an unprivileged become user. When Ansible needs to run a module with become user, the temporary directory is created in /var/tmp. This directory is created with &quot;umask 77 &amp;&amp; mkdir -p &lt;dir&gt;&quot;; this operation does not fail if the directory already exists and is owned by another user. An attacker could take advantage to gain control of the become user as the target directory can be retrieved by iterating '/proc/&lt;pid&gt;/cmdline'.

- [https://github.com/AlAIAL90/CVE-2020-1733](https://github.com/AlAIAL90/CVE-2020-1733) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-1733.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-1733.svg)


## CVE-2019-14904
 A flaw was found in the solaris_zone module from the Ansible Community modules. When setting the name for the zone on the Solaris host, the zone name is checked by listing the process with the 'ps' bare command on the remote machine. An attacker could take advantage of this flaw by crafting the name of the zone and executing arbitrary commands in the remote host. Ansible Engine 2.7.15, 2.8.7, and 2.9.2 as well as previous versions are affected.

- [https://github.com/AlAIAL90/CVE-2019-14904](https://github.com/AlAIAL90/CVE-2019-14904) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-14904.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-14904.svg)


## CVE-2019-14864
 Ansible, versions 2.9.x before 2.9.1, 2.8.x before 2.8.7 and Ansible versions 2.7.x before 2.7.15, is not respecting the flag no_log set it to True when Sumologic and Splunk callback plugins are used send tasks results events to collectors. This would discloses and collects any sensitive data.

- [https://github.com/AlAIAL90/CVE-2019-14864](https://github.com/AlAIAL90/CVE-2019-14864) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-14864.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-14864.svg)


## CVE-2019-14846
 In Ansible, all Ansible Engine versions up to ansible-engine 2.8.5, ansible-engine 2.7.13, ansible-engine 2.6.19, were logging at the DEBUG level which lead to a disclosure of credentials if a plugin used a library that logged credentials at the DEBUG level. This flaw does not affect Ansible modules, as those are executed in a separate process.

- [https://github.com/AlAIAL90/CVE-2019-14846](https://github.com/AlAIAL90/CVE-2019-14846) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-14846.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-14846.svg)


## CVE-2019-10206
 ansible-playbook -k and ansible cli tools, all versions 2.8.x before 2.8.4, all 2.7.x before 2.7.13 and all 2.6.x before 2.6.19, prompt passwords by expanding them from templates as they could contain special characters. Passwords should be wrapped to prevent templates trigger and exposing them.

- [https://github.com/AlAIAL90/CVE-2019-10206](https://github.com/AlAIAL90/CVE-2019-10206) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-10206.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-10206.svg)


## CVE-2019-10156
 A flaw was discovered in the way Ansible templating was implemented in versions before 2.6.18, 2.7.12 and 2.8.2, causing the possibility of information disclosure through unexpected variable substitution. By taking advantage of unintended variable substitution the content of any variable may be disclosed.

- [https://github.com/AlAIAL90/CVE-2019-10156](https://github.com/AlAIAL90/CVE-2019-10156) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-10156.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-10156.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447](https://github.com/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/julio-cfa/POC-ES-File-Explorer-CVE-2019-6447.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/fahmifj/Docker-breakout-runc](https://github.com/fahmifj/Docker-breakout-runc) :  ![starts](https://img.shields.io/github/stars/fahmifj/Docker-breakout-runc.svg) ![forks](https://img.shields.io/github/forks/fahmifj/Docker-breakout-runc.svg)


## CVE-2016-8776
 Huawei P9 phones with software EVA-AL10C00,EVA-CL10C00,EVA-DL10C00,EVA-TL10C00 and P9 Lite phones with software VNS-L21C185 allow attackers to bypass the factory reset protection (FRP) to enter some functional modules without authorization and perform operations to update the Google account.

- [https://github.com/rerugan/CVE-2016-8776](https://github.com/rerugan/CVE-2016-8776) :  ![starts](https://img.shields.io/github/stars/rerugan/CVE-2016-8776.svg) ![forks](https://img.shields.io/github/forks/rerugan/CVE-2016-8776.svg)

