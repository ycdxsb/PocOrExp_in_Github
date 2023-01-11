# Update 2023-01-11
## CVE-2023-22472
 Deck is a kanban style organization tool aimed at personal planning and project organization for teams integrated with Nextcloud. It is possible to make a user send any POST request with an arbitrary body given they click on a malicious deep link on a Windows computer. (e.g. in an email, chat link, etc). There are currently no known workarounds. It is recommended that the Nextcloud Desktop client is upgraded to 3.6.2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22472](https://github.com/Live-Hack-CVE/CVE-2023-22472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22472.svg)


## CVE-2023-0125
 A vulnerability was found in Control iD Panel. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the component Web Interface. The manipulation of the argument Nome leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-217717 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0125](https://github.com/Live-Hack-CVE/CVE-2023-0125) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0125.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0125.svg)


## CVE-2023-0036
 platform_callback_stub in misc subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an &quot;SA relay attack&quot;.Local attackers can bypass authentication and attack other SAs with high privilege.

- [https://github.com/Live-Hack-CVE/CVE-2023-0036](https://github.com/Live-Hack-CVE/CVE-2023-0036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0036.svg)


## CVE-2023-0035
 softbus_client_stub in communication subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an &quot;SA relay attack&quot;.Local attackers can bypass authentication and attack other SAs with high privilege.

- [https://github.com/Live-Hack-CVE/CVE-2023-0035](https://github.com/Live-Hack-CVE/CVE-2023-0035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0035.svg)


## CVE-2022-48194
 TP-Link TL-WR902AC devices through V3 0.9.1 allow remote authenticated attackers to execute arbitrary code or cause a Denial of Service (DoS) by uploading a crafted firmware update because the signature check is inadequate.

- [https://github.com/Live-Hack-CVE/CVE-2022-48194](https://github.com/Live-Hack-CVE/CVE-2022-48194) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48194.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48194.svg)


## CVE-2022-46769
 An improper neutralization of input during web page generation ('Cross-site Scripting') [CWE-79] vulnerability in Sling App CMS version 1.1.2 and prior may allow an authenticated remote attacker to perform a reflected cross-site scripting (XSS) attack in the site group feature. Upgrade to Apache Sling App CMS &gt;= 1.1.4

- [https://github.com/Live-Hack-CVE/CVE-2022-46769](https://github.com/Live-Hack-CVE/CVE-2022-46769) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46769.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46769.svg)


## CVE-2022-46603
 An issue in Inkdrop v5.4.1 allows attackers to execute arbitrary commands via uploading a crafted markdown file.

- [https://github.com/Live-Hack-CVE/CVE-2022-46603](https://github.com/Live-Hack-CVE/CVE-2022-46603) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46603.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46603.svg)


## CVE-2022-46181
 Gotify server is a simple server for sending and receiving messages in real-time per WebSocket. Versions prior to 2.2.2 contain an XSS vulnerability that allows authenticated users to upload .html files. An attacker could execute client side scripts **if** another user opened a link. The attacker could potentially take over the account of the user that clicked the link. The Gotify UI won't natively expose such a malicious link, so an attacker has to get the user to open the malicious link in a context outside of Gotify. The vulnerability has been fixed in version 2.2.2. As a workaround, you can block access to non image files via a reverse proxy in the `./image` directory.

- [https://github.com/Live-Hack-CVE/CVE-2022-46181](https://github.com/Live-Hack-CVE/CVE-2022-46181) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46181.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46181.svg)


## CVE-2022-46173
 Elrond-GO is a go implementation for the Elrond Network protocol. Versions prior to 1.3.50 are subject to a processing issue where nodes are affected when trying to process a cross-shard relayed transaction with a smart contract deploy transaction data. The problem was a bad correlation between the transaction caches and the processing component. If the above-mentioned transaction was sent with more gas than required, the smart contract result (SCR transaction) that should have returned the leftover gas, would have been wrongly added to a cache that the processing unit did not consider. The node stopped notarizing metachain blocks. The fix was actually to extend the SCR transaction search in all other caches if it wasn't found in the correct (expected) sharded-cache. There are no known workarounds at this time. This issue has been patched in version 1.3.50.

- [https://github.com/Live-Hack-CVE/CVE-2022-46173](https://github.com/Live-Hack-CVE/CVE-2022-46173) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46173.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46173.svg)


## CVE-2022-45883
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-45883](https://github.com/Live-Hack-CVE/CVE-2022-45883) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45883.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45883.svg)


## CVE-2022-43974
 MatrixSSL 4.0.4 through 4.5.1 has an integer overflow in matrixSslDecodeTls13. A remote attacker might be able to send a crafted TLS Message to cause a buffer overflow and achieve remote code execution. This is fixed in 4.6.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-43974](https://github.com/Live-Hack-CVE/CVE-2022-43974) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43974.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43974.svg)


## CVE-2022-43973
 An arbitrary code execution vulnerability exisits in Linksys WRT54GL Wireless-G Broadband Router with firmware &lt;= 4.30.18.006. The Check_TSSI function within the httpd binary uses unvalidated user input in the construction of a system command. An authenticated attacker with administrator privileges can leverage this vulnerability over the network via a malicious POST request to /apply.cgi to execute arbitrary commands on the underlying Linux operating system as root.

- [https://github.com/Live-Hack-CVE/CVE-2022-43973](https://github.com/Live-Hack-CVE/CVE-2022-43973) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43973.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43973.svg)


## CVE-2022-43972
 A null pointer dereference vulnerability exists in Linksys WRT54GL Wireless-G Broadband Router with firmware &lt;= 4.30.18.006. A null pointer dereference in the soap_action function within the upnp binary can be triggered by an unauthenticated attacker via a malicious POST request invoking the AddPortMapping action.

- [https://github.com/Live-Hack-CVE/CVE-2022-43972](https://github.com/Live-Hack-CVE/CVE-2022-43972) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43972.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43972.svg)


## CVE-2022-43971
 An arbitrary code exection vulnerability exists in Linksys WUMC710 Wireless-AC Universal Media Connector with firmware &lt;= 1.0.02 (build3). The do_setNTP function within the httpd binary uses unvalidated user input in the construction of a system command. An authenticated attacker with administrator privileges can leverage this vulnerability over the network via a malicious GET or POST request to /setNTP.cgi to execute arbitrary commands on the underlying Linux operating system as root.

- [https://github.com/Live-Hack-CVE/CVE-2022-43971](https://github.com/Live-Hack-CVE/CVE-2022-43971) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43971.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43971.svg)


## CVE-2022-43970
 A buffer overflow vulnerability exists in Linksys WRT54GL Wireless-G Broadband Router with firmware &lt;= 4.30.18.006. A stack-based buffer overflow in the Start_EPI function within the httpd binary allows an authenticated attacker with administrator privileges to execute arbitrary commands on the underlying Linux operating system as root. This vulnerablity can be triggered over the network via a malicious POST request to /apply.cgi.

- [https://github.com/Live-Hack-CVE/CVE-2022-43970](https://github.com/Live-Hack-CVE/CVE-2022-43970) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43970.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43970.svg)


## CVE-2022-42270
 NVIDIA distributions of Linux contain a vulnerability in nvdla_emu_task_submit, where unvalidated input may allow a local attacker to cause stack-based buffer overflow in kernel code, which may lead to escalation of privileges, compromised integrity and confidentiality, and denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42270](https://github.com/Live-Hack-CVE/CVE-2022-42270) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42270.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42270.svg)


## CVE-2022-42269
 NVIDIA Trusted OS contains a vulnerability in an SMC call handler, where failure to validate untrusted input may allow a highly privileged local attacker to cause information disclosure and compromise integrity. The scope of the impact can extend to other components.

- [https://github.com/Live-Hack-CVE/CVE-2022-42269](https://github.com/Live-Hack-CVE/CVE-2022-42269) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42269.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42269.svg)


## CVE-2022-42266
 NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape, where an unprivileged regular user can cause exposure of sensitive information to an actor that is not explicitly authorized to have access to that information, which may lead to limited information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-42266](https://github.com/Live-Hack-CVE/CVE-2022-42266) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42266.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42266.svg)


## CVE-2022-40520
 Memory corruption due to stack-based buffer overflow in Core

- [https://github.com/Live-Hack-CVE/CVE-2022-40520](https://github.com/Live-Hack-CVE/CVE-2022-40520) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40520.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40520.svg)


## CVE-2022-39958
 The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body bypass to sequentially exfiltrate small and undetectable sections of data by repeatedly submitting an HTTP Range header field with a small byte range. A restricted resource, access to which would ordinarily be detected, may be exfiltrated from the backend, despite being protected by a web application firewall that uses CRS. Short subsections of a restricted resource may bypass pattern matching techniques and allow undetected access. The legacy CRS versions 3.0.x and 3.1.x are affected, as well as the currently supported versions 3.2.1 and 3.3.2. Integrators and users are advised to upgrade to 3.2.2 and 3.3.3 respectively and to configure a CRS paranoia level of 3 or higher.

- [https://github.com/Live-Hack-CVE/CVE-2022-39958](https://github.com/Live-Hack-CVE/CVE-2022-39958) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39958.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39958.svg)


## CVE-2022-37258
 Prototype pollution vulnerability in function convertLater in npm-convert.js in stealjs steal 2.2.4 via the packageName variable in npm-convert.js.

- [https://github.com/Live-Hack-CVE/CVE-2022-37258](https://github.com/Live-Hack-CVE/CVE-2022-37258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37258.svg)


## CVE-2022-36437
 The Connection handler in Hazelcast and Hazelcast Jet allows a remote unauthenticated attacker to access and manipulate data in the cluster with the identity of another already authenticated connection. The affected Hazelcast versions are through 4.0.6, 4.1.9, 4.2.5, 5.0.3, and 5.1.2. The affected Hazelcast Jet versions are through 4.5.3.

- [https://github.com/Live-Hack-CVE/CVE-2022-36437](https://github.com/Live-Hack-CVE/CVE-2022-36437) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36437.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36437.svg)


## CVE-2022-33285
 Transient DOS due to buffer over-read in WLAN while parsing WLAN CSA action frames.

- [https://github.com/Live-Hack-CVE/CVE-2022-33285](https://github.com/Live-Hack-CVE/CVE-2022-33285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33285.svg)


## CVE-2022-33276
 Memory corruption due to buffer copy without checking size of input in modem while receiving WMI_REQUEST_STATS_CMDID command.

- [https://github.com/Live-Hack-CVE/CVE-2022-33276](https://github.com/Live-Hack-CVE/CVE-2022-33276) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33276.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33276.svg)


## CVE-2022-33274
 Memory corruption in android core due to improper validation of array index while returning feature ids after license authentication.

- [https://github.com/Live-Hack-CVE/CVE-2022-33274](https://github.com/Live-Hack-CVE/CVE-2022-33274) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33274.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33274.svg)


## CVE-2022-33266
 Memory corruption in Audio due to integer overflow to buffer overflow while music playback of clips like amr,evrc,qcelp with modified content.

- [https://github.com/Live-Hack-CVE/CVE-2022-33266](https://github.com/Live-Hack-CVE/CVE-2022-33266) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33266.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33266.svg)


## CVE-2022-33265
 Memory corruption due to information exposure in Powerline Communication Firmware while sending different MMEs from a single, unassociated device.

- [https://github.com/Live-Hack-CVE/CVE-2022-33265](https://github.com/Live-Hack-CVE/CVE-2022-33265) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33265.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33265.svg)


## CVE-2022-33255
 Information disclosure due to buffer over-read in Bluetooth HOST while processing GetFolderItems and GetItemAttribute Cmds from peer device.

- [https://github.com/Live-Hack-CVE/CVE-2022-33255](https://github.com/Live-Hack-CVE/CVE-2022-33255) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33255.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33255.svg)


## CVE-2022-33253
 Transient DOS due to buffer over-read in WLAN while parsing corrupted NAN frames.

- [https://github.com/Live-Hack-CVE/CVE-2022-33253](https://github.com/Live-Hack-CVE/CVE-2022-33253) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33253.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33253.svg)


## CVE-2022-33252
 Information disclosure due to buffer over-read in WLAN while handling IBSS beacons frame.

- [https://github.com/Live-Hack-CVE/CVE-2022-33252](https://github.com/Live-Hack-CVE/CVE-2022-33252) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33252.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33252.svg)


## CVE-2022-33219
 Memory corruption in Automotive due to integer overflow to buffer overflow while registering a new listener with shared buffer.

- [https://github.com/Live-Hack-CVE/CVE-2022-33219](https://github.com/Live-Hack-CVE/CVE-2022-33219) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33219.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33219.svg)


## CVE-2022-33218
 Memory corruption in Automotive due to improper input validation.

- [https://github.com/Live-Hack-CVE/CVE-2022-33218](https://github.com/Live-Hack-CVE/CVE-2022-33218) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33218.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33218.svg)


## CVE-2022-25890
 All versions of the package wifey are vulnerable to Command Injection via the connect() function due to improper input sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-25890](https://github.com/Live-Hack-CVE/CVE-2022-25890) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25890.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25890.svg)


## CVE-2022-25725
 Denial of service in MODEM due to improper pointer handling

- [https://github.com/Live-Hack-CVE/CVE-2022-25725](https://github.com/Live-Hack-CVE/CVE-2022-25725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25725.svg)


## CVE-2022-25722
 Information exposure in DSP services due to improper handling of freeing memory

- [https://github.com/Live-Hack-CVE/CVE-2022-25722](https://github.com/Live-Hack-CVE/CVE-2022-25722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25722.svg)


## CVE-2022-25721
 Memory corruption in video driver due to type confusion error during video playback

- [https://github.com/Live-Hack-CVE/CVE-2022-25721](https://github.com/Live-Hack-CVE/CVE-2022-25721) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25721.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25721.svg)


## CVE-2022-25717
 Memory corruption in display due to double free while allocating frame buffer memory

- [https://github.com/Live-Hack-CVE/CVE-2022-25717](https://github.com/Live-Hack-CVE/CVE-2022-25717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25717.svg)


## CVE-2022-25716
 Memory corruption in Multimedia Framework due to unsafe access to the data members

- [https://github.com/Live-Hack-CVE/CVE-2022-25716](https://github.com/Live-Hack-CVE/CVE-2022-25716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25716.svg)


## CVE-2022-23509
 Weave GitOps is a simple open source developer platform for people who want cloud native applications, without needing Kubernetes expertise. GitOps run has a local S3 bucket which it uses for synchronizing files that are later applied against a Kubernetes cluster. The communication between GitOps Run and the local S3 bucket is not encrypted. This allows privileged users or process to tap the local traffic to gain information permitting access to the s3 bucket. From that point, it would be possible to alter the bucket content, resulting in changes in the Kubernetes cluster's resources. There are no known workaround(s) for this vulnerability. This vulnerability has been fixed by commits ce2bbff and babd915. Users should upgrade to Weave GitOps version &gt;= v0.12.0 released on 08/12/2022.

- [https://github.com/Live-Hack-CVE/CVE-2022-23509](https://github.com/Live-Hack-CVE/CVE-2022-23509) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23509.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23509.svg)


## CVE-2022-23508
 Weave GitOps is a simple open source developer platform for people who want cloud native applications, without needing Kubernetes expertise. A vulnerability in GitOps run could allow a local user or process to alter a Kubernetes cluster's resources. GitOps run has a local S3 bucket which it uses for synchronizing files that are later applied against a Kubernetes cluster. Its endpoint had no security controls to block unauthorized access, therefore allowing local users (and processes) on the same machine to see and alter the bucket content. By leveraging this vulnerability, an attacker could pick a workload of their choosing and inject it into the S3 bucket, which resulted in the successful deployment in the target cluster, without the need to provide any credentials to either the S3 bucket nor the target Kubernetes cluster. There are no known workarounds for this issue, please upgrade. This vulnerability has been fixed by commits 75268c4 and 966823b. Users should upgrade to Weave GitOps version &gt;= v0.12.0 released on 08/12/2022. ### Workarounds There is no workaround for this vulnerability. ### References Disclosed by Paulo Gomes, Senior Software Engineer, Weaveworks. ### For more information If you have any questions or comments about this advisory: - Open an issue in [Weave GitOps repository](https://github.com/weaveworks/weave-gitops) - Email us at [support@weave.works](mailto:support@weave.works)

- [https://github.com/Live-Hack-CVE/CVE-2022-23508](https://github.com/Live-Hack-CVE/CVE-2022-23508) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23508.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23508.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Arrnitage/CVE-2022-22947_exp](https://github.com/Arrnitage/CVE-2022-22947_exp) :  ![starts](https://img.shields.io/github/stars/Arrnitage/CVE-2022-22947_exp.svg) ![forks](https://img.shields.io/github/forks/Arrnitage/CVE-2022-22947_exp.svg)


## CVE-2022-22470
 IBM Security Verify Governance 10.0 stores user credentials in plain clear text which can be read by a local user. IBM X-Force ID: 225232.

- [https://github.com/Live-Hack-CVE/CVE-2022-22470](https://github.com/Live-Hack-CVE/CVE-2022-22470) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22470.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22470.svg)


## CVE-2022-22088
 Memory corruption in Bluetooth HOST due to buffer overflow while parsing the command response received from remote

- [https://github.com/Live-Hack-CVE/CVE-2022-22088](https://github.com/Live-Hack-CVE/CVE-2022-22088) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22088.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22088.svg)


## CVE-2022-22079
 Denial of service while processing fastboot flash command on mmc due to buffer over read

- [https://github.com/Live-Hack-CVE/CVE-2022-22079](https://github.com/Live-Hack-CVE/CVE-2022-22079) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22079.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22079.svg)


## CVE-2022-4882
 A vulnerability was found in kaltura mwEmbed up to 2.91. It has been rated as problematic. Affected by this issue is some unknown functionality of the file modules/KalturaSupport/components/share/share.js of the component Share Plugin. The manipulation of the argument res leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 2.92.rc1 is able to address this issue. The name of the patch is 4f11b6f6610acd6d89de5f8be47cf7c610643845. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217664.

- [https://github.com/Live-Hack-CVE/CVE-2022-4882](https://github.com/Live-Hack-CVE/CVE-2022-4882) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4882.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4882.svg)


## CVE-2022-4857
 A vulnerability was found in Modbus Tools Modbus Poll up to 9.10.0 and classified as critical. Affected by this issue is some unknown functionality of the file mbpoll.exe of the component mbp File Handler. The manipulation leads to buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-217022 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4857](https://github.com/Live-Hack-CVE/CVE-2022-4857) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4857.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4857.svg)


## CVE-2022-4856
 A vulnerability has been found in Modbus Tools Modbus Slave up to 7.5.1 and classified as critical. Affected by this vulnerability is an unknown functionality of the file mbslave.exe of the component mbs File Handler. The manipulation leads to buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-217021 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4856](https://github.com/Live-Hack-CVE/CVE-2022-4856) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4856.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4856.svg)


## CVE-2022-4855
 A vulnerability, which was classified as critical, was found in SourceCodester Lead Management System 1.0. Affected is an unknown function of the file login.php. The manipulation of the argument username leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-217020.

- [https://github.com/Live-Hack-CVE/CVE-2022-4855](https://github.com/Live-Hack-CVE/CVE-2022-4855) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4855.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4855.svg)


## CVE-2022-4643
 A vulnerability was found in docconv up to 1.2.0. It has been declared as critical. This vulnerability affects the function ConvertPDFImages of the file pdf_ocr.go. The manipulation of the argument path leads to os command injection. The attack can be initiated remotely. Upgrading to version 1.2.1 is able to address this issue. The name of the patch is b19021ade3d0b71c89d35cb00eb9e589a121faa5. It is recommended to upgrade the affected component. VDB-216502 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4643](https://github.com/Live-Hack-CVE/CVE-2022-4643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4643.svg)


## CVE-2022-4497
 The Jetpack CRM WordPress plugin before 5.5 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins

- [https://github.com/Live-Hack-CVE/CVE-2022-4497](https://github.com/Live-Hack-CVE/CVE-2022-4497) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4497.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4497.svg)


## CVE-2022-4491
 The WP-Table Reloaded WordPress plugin through 1.9.4 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks, which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4491](https://github.com/Live-Hack-CVE/CVE-2022-4491) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4491.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4491.svg)


## CVE-2022-4479
 The Table of Contents Plus WordPress plugin before 2212 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4479](https://github.com/Live-Hack-CVE/CVE-2022-4479) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4479.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4479.svg)


## CVE-2022-4468
 The WP Recipe Maker WordPress plugin before 8.6.1 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4468](https://github.com/Live-Hack-CVE/CVE-2022-4468) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4468.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4468.svg)


## CVE-2022-4426
 The Mautic Integration for WooCommerce WordPress plugin before 1.0.3 does not have proper CSRF check when updating settings, and does not ensure that the options to be updated belong to the plugin, allowing attackers to make a logged in admin change arbitrary blog options via a CSRF attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-4426](https://github.com/Live-Hack-CVE/CVE-2022-4426) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4426.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4426.svg)


## CVE-2022-4394
 The iPages Flipbook For WordPress plugin through 1.4.6 does not sanitise and escape some of its settings, which could allow users such as contributor+ to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-4394](https://github.com/Live-Hack-CVE/CVE-2022-4394) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4394.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4394.svg)


## CVE-2022-4393
 The ImageLinks Interactive Image Builder for WordPress plugin through 1.5.3 does not sanitise and escape some of its settings, which could allow users such as contributor+ to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-4393](https://github.com/Live-Hack-CVE/CVE-2022-4393) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4393.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4393.svg)


## CVE-2022-4392
 The iPanorama 360 WordPress Virtual Tour Builder plugin through 1.6.29 does not sanitise and escape some of its settings, which could allow users such as contributor+ to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-4392](https://github.com/Live-Hack-CVE/CVE-2022-4392) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4392.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4392.svg)


## CVE-2022-4391
 The Vision Interactive For WordPress plugin through 1.5.3 does not sanitise and escape some of its settings, which could allow users such as contributor+ to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-4391](https://github.com/Live-Hack-CVE/CVE-2022-4391) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4391.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4391.svg)


## CVE-2022-4374
 The Bg Bible References WordPress plugin through 3.8.14 does not sanitize and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting.

- [https://github.com/Live-Hack-CVE/CVE-2022-4374](https://github.com/Live-Hack-CVE/CVE-2022-4374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4374.svg)


## CVE-2022-4369
 The WP-Lister Lite for Amazon WordPress plugin before 2.4.4 does not sanitize and escapes a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which can be used against high-privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4369](https://github.com/Live-Hack-CVE/CVE-2022-4369) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4369.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4369.svg)


## CVE-2022-4368
 The WP CSV WordPress plugin through 1.8.0.0 does not sanitize and escape a parameter before outputting it back in the page when importing a CSV, and doe snot have CSRF checks in place as well, leading to a Reflected Cross-Site Scripting.

- [https://github.com/Live-Hack-CVE/CVE-2022-4368](https://github.com/Live-Hack-CVE/CVE-2022-4368) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4368.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4368.svg)


## CVE-2022-4362
 The Popup Maker WordPress plugin before 1.16.9 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4362](https://github.com/Live-Hack-CVE/CVE-2022-4362) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4362.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4362.svg)


## CVE-2022-4352
 The Qe SEO Handyman WordPress plugin through 1.0 does not properly sanitize and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by high privilege users such as admin

- [https://github.com/Live-Hack-CVE/CVE-2022-4352](https://github.com/Live-Hack-CVE/CVE-2022-4352) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4352.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4352.svg)


## CVE-2022-4351
 The Qe SEO Handyman WordPress plugin through 1.0 does not properly sanitize and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by high privilege users such as admin

- [https://github.com/Live-Hack-CVE/CVE-2022-4351](https://github.com/Live-Hack-CVE/CVE-2022-4351) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4351.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4351.svg)


## CVE-2022-4340
 The BookingPress WordPress plugin before 1.0.31 suffers from an Insecure Direct Object Reference (IDOR) vulnerability in it's thank you page, allowing any visitor to display information about any booking, including full name, date, time and service booked, by manipulating the appointment_id query parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-4340](https://github.com/Live-Hack-CVE/CVE-2022-4340) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4340.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4340.svg)


## CVE-2022-4329
 The Product list Widget for Woocommerce WordPress plugin through 1.0 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against both unauthenticated and authenticated users (such as high privilege one like admin).

- [https://github.com/Live-Hack-CVE/CVE-2022-4329](https://github.com/Live-Hack-CVE/CVE-2022-4329) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4329.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4329.svg)


## CVE-2022-4325
 The Post Status Notifier Lite WordPress plugin before 1.10.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which can be used against high privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4325](https://github.com/Live-Hack-CVE/CVE-2022-4325) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4325.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4325.svg)


## CVE-2022-4310
 The Slimstat Analytics WordPress plugin before 4.9.3 does not sanitise and escape the URI when logging requests, which could allow unauthenticated attackers to perform Stored Cross-Site Scripting attacks against logged in admin viewing the logs

- [https://github.com/Live-Hack-CVE/CVE-2022-4310](https://github.com/Live-Hack-CVE/CVE-2022-4310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4310.svg)


## CVE-2022-4301
 The Sunshine Photo Cart WordPress plugin before 2.9.15 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting.

- [https://github.com/Live-Hack-CVE/CVE-2022-4301](https://github.com/Live-Hack-CVE/CVE-2022-4301) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4301.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4301.svg)


## CVE-2022-4196
 The Multi Step Form WordPress plugin before 1.7.8 does not sanitise and escape some of its form fields, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-4196](https://github.com/Live-Hack-CVE/CVE-2022-4196) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4196.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4196.svg)


## CVE-2022-4103
 The Royal Elementor Addons WordPress plugin before 1.3.56 does not have authorisation and CSRF checks when creating a template, and does not ensure that the post created is a template. This could allow any authenticated users, such as subscriber to create a post (as well as any post type) with an arbitrary title

- [https://github.com/Live-Hack-CVE/CVE-2022-4103](https://github.com/Live-Hack-CVE/CVE-2022-4103) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4103.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4103.svg)


## CVE-2022-4102
 The Royal Elementor Addons WordPress plugin before 1.3.56 does not have authorization and CSRF checks when deleting a template and does not ensure that the post to be deleted is a template. This could allow any authenticated users, such as subscribers, to delete arbitrary posts assuming they know the related slug.

- [https://github.com/Live-Hack-CVE/CVE-2022-4102](https://github.com/Live-Hack-CVE/CVE-2022-4102) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4102.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4102.svg)


## CVE-2022-4043
 The WP Custom Admin Interface WordPress plugin before 7.29 unserialize user input provided via the settings, which could allow high privilege users such as admin to perform PHP Object Injection when a suitable gadget is present.

- [https://github.com/Live-Hack-CVE/CVE-2022-4043](https://github.com/Live-Hack-CVE/CVE-2022-4043) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4043.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4043.svg)


## CVE-2022-3923
 The ActiveCampaign for WooCommerce WordPress plugin through 1.9.6 does not have authorisation check when cleaning up its error logs via an AJAX action, which could allow any authenticated users, such as subscriber to call it and remove error logs.

- [https://github.com/Live-Hack-CVE/CVE-2022-3923](https://github.com/Live-Hack-CVE/CVE-2022-3923) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3923.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3923.svg)


## CVE-2022-3855
 The 404 to Start WordPress plugin through 1.6.1 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-3855](https://github.com/Live-Hack-CVE/CVE-2022-3855) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3855.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3855.svg)


## CVE-2022-3679
 The Starter Templates by Kadence WP WordPress plugin before 1.2.17 unserialises the content of an imported file, which could lead to PHP object injection issues when an admin import (intentionally or not) a malicious file and a suitable gadget chain is present on the blog.

- [https://github.com/Live-Hack-CVE/CVE-2022-3679](https://github.com/Live-Hack-CVE/CVE-2022-3679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3679.svg)


## CVE-2022-3649
 A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211992.

- [https://github.com/Live-Hack-CVE/CVE-2022-3649](https://github.com/Live-Hack-CVE/CVE-2022-3649) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3649.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3649.svg)


## CVE-2022-3417
 The WPtouch WordPress plugin before 4.3.45 unserialises the content of an imported settings file, which could lead to PHP object injections issues when an user import (intentionally or not) a malicious settings file and a suitable gadget chain is present on the blog.

- [https://github.com/Live-Hack-CVE/CVE-2022-3417](https://github.com/Live-Hack-CVE/CVE-2022-3417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3417.svg)


## CVE-2022-3416
 The WPtouch WordPress plugin before 4.3.45 does not properly validate images to be uploaded, allowing high privilege users such as admin to upload arbitrary files on the server even when they should not be allowed to (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-3416](https://github.com/Live-Hack-CVE/CVE-2022-3416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3416.svg)


## CVE-2022-3343
 The WPQA Builder WordPress plugin before 5.9.3 (which is a companion plugin used with Discy and Himer WordPress themes) incorrectly tries to validate that a user already follows another in the wpqa_following_you_ajax action, allowing a user to inflate their score on the site by having another user send repeated follow actions to them.

- [https://github.com/Live-Hack-CVE/CVE-2022-3343](https://github.com/Live-Hack-CVE/CVE-2022-3343) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3343.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3343.svg)


## CVE-2022-2602
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/th3-5had0w/CVE-2022-2602-Study](https://github.com/th3-5had0w/CVE-2022-2602-Study) :  ![starts](https://img.shields.io/github/stars/th3-5had0w/CVE-2022-2602-Study.svg) ![forks](https://img.shields.io/github/forks/th3-5had0w/CVE-2022-2602-Study.svg)


## CVE-2022-2196
 A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks. L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past commit 2e7eab81425a

- [https://github.com/Live-Hack-CVE/CVE-2022-2196](https://github.com/Live-Hack-CVE/CVE-2022-2196) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2196.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2196.svg)


## CVE-2022-1444
 heap-use-after-free in GitHub repository radareorg/radare2 prior to 5.7.0. This vulnerability is capable of inducing denial of service.

- [https://github.com/KrungSalad/POC-CVE-2022-1444](https://github.com/KrungSalad/POC-CVE-2022-1444) :  ![starts](https://img.shields.io/github/stars/KrungSalad/POC-CVE-2022-1444.svg) ![forks](https://img.shields.io/github/forks/KrungSalad/POC-CVE-2022-1444.svg)


## CVE-2022-1068
 Modbus Tools Modbus Slave (versions 7.4.2 and prior) is vulnerable to a stack-based buffer overflow in the registration field. This may cause the program to crash when a long character string is used.

- [https://github.com/webraybtl/CVE-2022-1068](https://github.com/webraybtl/CVE-2022-1068) :  ![starts](https://img.shields.io/github/stars/webraybtl/CVE-2022-1068.svg) ![forks](https://img.shields.io/github/forks/webraybtl/CVE-2022-1068.svg)


## CVE-2021-36603
 Cross Site Scripting (XSS) in Tasmota firmware 6.5.0 allows remote attackers to inject JavaScript code via a crafted string in the field &quot;Friendly Name 1&quot;.

- [https://github.com/Live-Hack-CVE/CVE-2021-36603](https://github.com/Live-Hack-CVE/CVE-2021-36603) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-36603.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-36603.svg)


## CVE-2021-29472
 Composer is a dependency manager for PHP. URLs for Mercurial repositories in the root composer.json and package source download URLs are not sanitized correctly. Specifically crafted URL values allow code to be executed in the HgDriver if hg/Mercurial is installed on the system. The impact to Composer users directly is limited as the composer.json file is typically under their own control and source download URLs can only be supplied by third party Composer repositories they explicitly trust to download and execute source code from, e.g. Composer plugins. The main impact is to services passing user input to Composer, including Packagist.org and Private Packagist. This allowed users to trigger remote code execution. The vulnerability has been patched on Packagist.org and Private Packagist within 12h of receiving the initial vulnerability report and based on a review of logs, to the best of our knowledge, was not abused by anyone. Other services/tools using VcsRepository/VcsDriver or derivatives may also be vulnerable and should upgrade their composer/composer dependency immediately. Versions 1.10.22 and 2.0.13 include patches for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-29472](https://github.com/Live-Hack-CVE/CVE-2021-29472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-29472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-29472.svg)


## CVE-2021-20784
 HTTP header injection vulnerability in Everything all versions except the Lite version may allow a remote attacker to inject an arbitrary script or alter the website that uses the product via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2021-20784](https://github.com/Live-Hack-CVE/CVE-2021-20784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-20784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-20784.svg)


## CVE-2021-4311
 A vulnerability classified as problematic was found in Talend Open Studio for MDM. This vulnerability affects unknown code of the component XML Handler. The manipulation leads to xml external entity reference. The name of the patch is 31d442b9fb1d518128fd18f6e4d54e06c3d67793. It is recommended to apply a patch to fix this issue. VDB-217666 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4311](https://github.com/Live-Hack-CVE/CVE-2021-4311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4311.svg)


## CVE-2021-4310
 A vulnerability was found in 01-Scripts 01-Artikelsystem. It has been classified as problematic. Affected is an unknown function of the file 01article.php. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is ae849b347a58c2cb1be38d04bbe56fc883d5d84a. It is recommended to apply a patch to fix this issue. VDB-217662 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4310](https://github.com/Live-Hack-CVE/CVE-2021-4310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4310.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/HellGateCorp/pwnkit](https://github.com/HellGateCorp/pwnkit) :  ![starts](https://img.shields.io/github/stars/HellGateCorp/pwnkit.svg) ![forks](https://img.shields.io/github/forks/HellGateCorp/pwnkit.svg)


## CVE-2021-3928
 vim is vulnerable to Use of Uninitialized Variable

- [https://github.com/Live-Hack-CVE/CVE-2021-3928](https://github.com/Live-Hack-CVE/CVE-2021-3928) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3928.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3928.svg)


## CVE-2021-3859
 A flaw was found in Undertow that tripped the client-side invocation timeout with certain calls made over HTTP2. This flaw allows an attacker to carry out denial of service attacks.

- [https://github.com/Live-Hack-CVE/CVE-2021-3859](https://github.com/Live-Hack-CVE/CVE-2021-3859) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3859.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3859.svg)


## CVE-2019-10779
 All versions of stroom:stroom-app before 5.5.12 and all versions of the 6.0.0 branch before 6.0.25 are affected by Cross-site Scripting. An attacker website is able to load the Stroom UI into a hidden iframe. Using that iframe, the attacker site can issue commands to the Stroom UI via an XSS vulnerability to take full control of the Stroom UI on behalf of the logged-in user.

- [https://github.com/RepublicR0K/CVE-2019-10779](https://github.com/RepublicR0K/CVE-2019-10779) :  ![starts](https://img.shields.io/github/stars/RepublicR0K/CVE-2019-10779.svg) ![forks](https://img.shields.io/github/forks/RepublicR0K/CVE-2019-10779.svg)


## CVE-2018-25059
 A vulnerability was found in pastebinit up to 0.2.2 and classified as problematic. Affected by this issue is the function pasteHandler of the file server.go. The manipulation of the argument r.URL.Path leads to path traversal. Upgrading to version 0.2.3 is able to address this issue. The name of the patch is 1af2facb6d95976c532b7f8f82747d454a092272. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217040.

- [https://github.com/Live-Hack-CVE/CVE-2018-25059](https://github.com/Live-Hack-CVE/CVE-2018-25059) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25059.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25059.svg)


## CVE-2017-20166
 Ecto 2.2.0 lacks a certain protection mechanism associated with the interaction between is_nil and raise.

- [https://github.com/Live-Hack-CVE/CVE-2017-20166](https://github.com/Live-Hack-CVE/CVE-2017-20166) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20166.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20166.svg)


## CVE-2015-10035
 A vulnerability was found in gperson angular-test-reporter and classified as critical. This issue affects the function getProjectTables/addTest of the file rest-server/data-server.js. The manipulation leads to sql injection. The name of the patch is a29d8ae121b46ebfa96a55a9106466ab2ef166ae. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217715.

- [https://github.com/Live-Hack-CVE/CVE-2015-10035](https://github.com/Live-Hack-CVE/CVE-2015-10035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10035.svg)


## CVE-2015-10034
 A vulnerability has been found in j-nowak workout-organizer and classified as critical. This vulnerability affects unknown code. The manipulation leads to sql injection. The name of the patch is 13cd6c3d1210640bfdb39872b2bb3597aa991279. It is recommended to apply a patch to fix this issue. VDB-217714 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10034](https://github.com/Live-Hack-CVE/CVE-2015-10034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10034.svg)


## CVE-2015-10033
 A vulnerability, which was classified as problematic, was found in jvvlee MerlinsBoard. This affects an unknown part of the component Grade Handler. The manipulation leads to improper authorization. The name of the patch is 134f5481e2914b7f096cd92a22b1e6bcb8e6dfe5. It is recommended to apply a patch to fix this issue. The identifier VDB-217713 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10033](https://github.com/Live-Hack-CVE/CVE-2015-10033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10033.svg)


## CVE-2014-125073
 A vulnerability was found in mapoor voteapp. It has been rated as critical. Affected by this issue is the function create_poll/do_poll/show_poll/show_refresh of the file app.py. The manipulation leads to sql injection. The name of the patch is b290c21a0d8bcdbd55db860afd3cadec97388e72. It is recommended to apply a patch to fix this issue. VDB-217790 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125073](https://github.com/Live-Hack-CVE/CVE-2014-125073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125073.svg)


## CVE-2014-125072
 A vulnerability classified as critical has been found in CherishSin klattr. This affects an unknown part. The manipulation leads to sql injection. The name of the patch is f8e4ecfbb83aef577011b0b4aebe96fb6ec557f1. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217719.

- [https://github.com/Live-Hack-CVE/CVE-2014-125072](https://github.com/Live-Hack-CVE/CVE-2014-125072) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125072.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125072.svg)


## CVE-2014-125071
 A vulnerability was found in lukehutch Gribbit. It has been classified as problematic. Affected is the function messageReceived of the file src/gribbit/request/HttpRequestHandler.java. The manipulation leads to missing origin validation in websockets. The name of the patch is 620418df247aebda3dd4be1dda10fe229ea505dd. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217716.

- [https://github.com/Live-Hack-CVE/CVE-2014-125071](https://github.com/Live-Hack-CVE/CVE-2014-125071) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125071.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125071.svg)

