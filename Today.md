# Update 2021-09-11
## CVE-2021-40444
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/vysecurity/CVE-2021-40444](https://github.com/vysecurity/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/vysecurity/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/vysecurity/CVE-2021-40444.svg)


## CVE-2021-40223
 Rittal CMC PU III Web management (version V3.11.00_2) fails to sanitize user input on several parameters of the configuration (User Configuration dialog, Task Configuration dialog and set logging filter dialog). This allows an attacker to backdoor the device with HTML and browser-interpreted content (such as JavaScript or other client-side scripts). The XSS payload will be triggered when the user accesses some specific sections of the application.

- [https://github.com/asang17/CVE-2021-40223](https://github.com/asang17/CVE-2021-40223) :  ![starts](https://img.shields.io/github/stars/asang17/CVE-2021-40223.svg) ![forks](https://img.shields.io/github/forks/asang17/CVE-2021-40223.svg)


## CVE-2021-40222
 Rittal CMC PU III Web management Version affected: V3.11.00_2. Version fixed: V3.17.10 is affected by a remote code execution vulnerablity. It is possible to introduce shell code to create a reverse shell in the PU-Hostname field of the TCP/IP Configuration dialog. Web application fails to sanitize user input on Network TCP/IP configuration page. This allows the attacker to inject commands as root on the device which will be executed once the data is received.

- [https://github.com/asang17/CVE-2021-40222](https://github.com/asang17/CVE-2021-40222) :  ![starts](https://img.shields.io/github/stars/asang17/CVE-2021-40222.svg) ![forks](https://img.shields.io/github/forks/asang17/CVE-2021-40222.svg)


## CVE-2021-37678
 TensorFlow is an end-to-end open source platform for machine learning. In affected versions TensorFlow and Keras can be tricked to perform arbitrary code execution when deserializing a Keras model from YAML format. The [implementation](https://github.com/tensorflow/tensorflow/blob/460e000de3a83278fb00b61a16d161b1964f15f4/tensorflow/python/keras/saving/model_config.py#L66-L104) uses `yaml.unsafe_load` which can perform arbitrary code execution on the input. Given that YAML format support requires a significant amount of work, we have removed it for now. We have patched the issue in GitHub commit 23d6383eb6c14084a8fc3bdf164043b974818012. The fix will be included in TensorFlow 2.6.0. We will also cherrypick this commit on TensorFlow 2.5.1, TensorFlow 2.4.3, and TensorFlow 2.3.4, as these are also affected and still in supported range.

- [https://github.com/fran-CICS/ExploitTensorflowCVE-2021-37678](https://github.com/fran-CICS/ExploitTensorflowCVE-2021-37678) :  ![starts](https://img.shields.io/github/stars/fran-CICS/ExploitTensorflowCVE-2021-37678.svg) ![forks](https://img.shields.io/github/forks/fran-CICS/ExploitTensorflowCVE-2021-37678.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/dorkerdevil/CVE-2021-26084](https://github.com/dorkerdevil/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-26084.svg)


## CVE-2020-25233
 A vulnerability has been identified in LOGO! 8 BM (incl. SIPLUS variants) (All versions &lt; V8.3). The firmware update of affected devices contains the private RSA key that is used as a basis for encryption of communication with the device.

- [https://github.com/twentybel0w/CVE-2020-25233](https://github.com/twentybel0w/CVE-2020-25233) :  ![starts](https://img.shields.io/github/stars/twentybel0w/CVE-2020-25233.svg) ![forks](https://img.shields.io/github/forks/twentybel0w/CVE-2020-25233.svg)


## CVE-2020-17533
 Apache Accumulo versions 1.5.0 through 1.10.0 and version 2.0.0 do not properly check the return value of some policy enforcement functions before permitting an authenticated user to perform certain administrative operations. Specifically, the return values of the 'canFlush' and 'canPerformSystemActions' security functions are not checked in some instances, therefore allowing an authenticated user with insufficient permissions to perform the following actions: flushing a table, shutting down Accumulo or an individual tablet server, and setting or removing system-wide Accumulo configuration properties.

- [https://github.com/pazeray/CVE-2020-17533](https://github.com/pazeray/CVE-2020-17533) :  ![starts](https://img.shields.io/github/stars/pazeray/CVE-2020-17533.svg) ![forks](https://img.shields.io/github/forks/pazeray/CVE-2020-17533.svg)


## CVE-2020-9054
 Multiple ZyXEL network-attached storage (NAS) devices running firmware version 5.21 contain a pre-authentication command injection vulnerability, which may allow a remote, unauthenticated attacker to execute arbitrary code on a vulnerable device. ZyXEL NAS devices achieve authentication by using the weblogin.cgi CGI executable. This program fails to properly sanitize the username parameter that is passed to it. If the username parameter contains certain characters, it can allow command injection with the privileges of the web server that runs on the ZyXEL device. Although the web server does not run as the root user, ZyXEL devices include a setuid utility that can be leveraged to run any command with root privileges. As such, it should be assumed that exploitation of this vulnerability can lead to remote code execution with root privileges. By sending a specially-crafted HTTP POST or GET request to a vulnerable ZyXEL device, a remote, unauthenticated attacker may be able to execute arbitrary code on the device. This may happen by directly connecting to a device if it is directly exposed to an attacker. However, there are ways to trigger such crafted requests even if an attacker does not have direct connectivity to a vulnerable devices. For example, simply visiting a website can result in the compromise of any ZyXEL device that is reachable from the client system. Affected products include: NAS326 before firmware V5.21(AAZF.7)C0 NAS520 before firmware V5.21(AASZ.3)C0 NAS540 before firmware V5.21(AATB.4)C0 NAS542 before firmware V5.21(ABAG.4)C0 ZyXEL has made firmware updates available for NAS326, NAS520, NAS540, and NAS542 devices. Affected models that are end-of-support: NSA210, NSA220, NSA220+, NSA221, NSA310, NSA310S, NSA320, NSA320S, NSA325 and NSA325v2

- [https://github.com/darrenmartyn/CVE-2020-9054](https://github.com/darrenmartyn/CVE-2020-9054) :  ![starts](https://img.shields.io/github/stars/darrenmartyn/CVE-2020-9054.svg) ![forks](https://img.shields.io/github/forks/darrenmartyn/CVE-2020-9054.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/darrenmartyn/CVE-2019-15107](https://github.com/darrenmartyn/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/darrenmartyn/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/darrenmartyn/CVE-2019-15107.svg)

