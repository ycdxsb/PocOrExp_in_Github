# Update 2022-03-02
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


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/kh4sh3i/CVE-2022-23131](https://github.com/kh4sh3i/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2022-23131.svg)


## CVE-2022-0725
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ByteHackr/keepass_poc](https://github.com/ByteHackr/keepass_poc) :  ![starts](https://img.shields.io/github/stars/ByteHackr/keepass_poc.svg) ![forks](https://img.shields.io/github/forks/ByteHackr/keepass_poc.svg)


## CVE-2022-0530
 A flaw was found in Unzip. The vulnerability occurs during the conversion of a wide string to a local string that leads to a heap of out-of-bound write. This flaw allows an attacker to input a specially crafted zip file, leading to a crash or code execution.

- [https://github.com/nanaao/unzip_poc](https://github.com/nanaao/unzip_poc) :  ![starts](https://img.shields.io/github/stars/nanaao/unzip_poc.svg) ![forks](https://img.shields.io/github/forks/nanaao/unzip_poc.svg)


## CVE-2022-0529
 A flaw was found in Unzip. The vulnerability occurs during the conversion of a wide string to a local string that leads to a heap of out-of-bound write. This flaw allows an attacker to input a specially crafted zip file, leading to a crash or code execution.

- [https://github.com/nanaao/unzip_poc](https://github.com/nanaao/unzip_poc) :  ![starts](https://img.shields.io/github/stars/nanaao/unzip_poc.svg) ![forks](https://img.shields.io/github/forks/nanaao/unzip_poc.svg)


## CVE-2021-30955
 A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. A malicious application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/timb-machine-mirrors/CVE-2021-30955](https://github.com/timb-machine-mirrors/CVE-2021-30955) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/CVE-2021-30955.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/CVE-2021-30955.svg)
- [https://github.com/nickorlow/CVE-2021-30955-POC](https://github.com/nickorlow/CVE-2021-30955-POC) :  ![starts](https://img.shields.io/github/stars/nickorlow/CVE-2021-30955-POC.svg) ![forks](https://img.shields.io/github/forks/nickorlow/CVE-2021-30955-POC.svg)
- [https://github.com/verygenericname/CVE-2021-30955-POC-IPA](https://github.com/verygenericname/CVE-2021-30955-POC-IPA) :  ![starts](https://img.shields.io/github/stars/verygenericname/CVE-2021-30955-POC-IPA.svg) ![forks](https://img.shields.io/github/forks/verygenericname/CVE-2021-30955-POC-IPA.svg)


## CVE-2019-15126
 An issue was discovered on Broadcom Wi-Fi client devices. Specifically timed and handcrafted traffic can cause internal errors (related to state transitions) in a WLAN device that lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for a discrete set of traffic, a different vulnerability than CVE-2019-9500, CVE-2019-9501, CVE-2019-9502, and CVE-2019-9503.

- [https://github.com/hexway/r00kie-kr00kie](https://github.com/hexway/r00kie-kr00kie) :  ![starts](https://img.shields.io/github/stars/hexway/r00kie-kr00kie.svg) ![forks](https://img.shields.io/github/forks/hexway/r00kie-kr00kie.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/twseptian/cve-2018-6574](https://github.com/twseptian/cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2018-6574.svg)


## CVE-2018-1235
 Dell EMC RecoverPoint versions prior to 5.1.2 and RecoverPoint for VMs versions prior to 5.1.1.3, contain a command injection vulnerability. An unauthenticated remote attacker may potentially exploit this vulnerability to execute arbitrary commands on the affected system with root privilege.

- [https://github.com/AbsoZed/CVE-2018-1235](https://github.com/AbsoZed/CVE-2018-1235) :  ![starts](https://img.shields.io/github/stars/AbsoZed/CVE-2018-1235.svg) ![forks](https://img.shields.io/github/forks/AbsoZed/CVE-2018-1235.svg)

