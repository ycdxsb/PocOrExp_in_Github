# Update 2021-05-19
## CVE-2021-31916
 An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or a leak of internal kernel information. The highest threat from this vulnerability is to system availability.

- [https://github.com/JamesGeee/CVE-2021-31916](https://github.com/JamesGeee/CVE-2021-31916) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-31916.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-31916.svg)


## CVE-2021-31899
 In JetBrains Code With Me bundled to the compatible IDEs before version 2021.1, the client could execute code in read-only mode.

- [https://github.com/JamesGeee/CVE-2021-31899](https://github.com/JamesGeee/CVE-2021-31899) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-31899.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-31899.svg)


## CVE-2021-31793
 An issue exists on NightOwl WDB-20-V2 WDB-20-V2_20190314 devices that allows an unauthenticated user to gain access to snapshots and video streams from the doorbell. The binary app offers a web server on port 80 that allows an unauthenticated user to take a snapshot from the doorbell camera via the /snapshot URI.

- [https://github.com/JamesGeee/CVE-2021-31793](https://github.com/JamesGeee/CVE-2021-31793) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-31793.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-31793.svg)


## CVE-2021-31180
 Microsoft Office Graphics Remote Code Execution Vulnerability

- [https://github.com/JamesGeee/CVE-2021-31180](https://github.com/JamesGeee/CVE-2021-31180) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-31180.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-31180.svg)


## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/An0ny-m0us/CVE-2021-31166](https://github.com/An0ny-m0us/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/An0ny-m0us/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/An0ny-m0us/CVE-2021-31166.svg)
- [https://github.com/Frankmock/CVE-2021-31166-detection-rules](https://github.com/Frankmock/CVE-2021-31166-detection-rules) :  ![starts](https://img.shields.io/github/stars/Frankmock/CVE-2021-31166-detection-rules.svg) ![forks](https://img.shields.io/github/forks/Frankmock/CVE-2021-31166-detection-rules.svg)


## CVE-2021-30128
 Apache OFBiz has unsafe deserialization prior to 17.12.07 version

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2021-29603
 TensorFlow is an end-to-end open source platform for machine learning. A specially crafted TFLite model could trigger an OOB write on heap in the TFLite implementation of `ArgMin`/`ArgMax`(https://github.com/tensorflow/tensorflow/blob/102b211d892f3abc14f845a72047809b39cc65ab/tensorflow/lite/kernels/arg_min_max.cc#L52-L59). If `axis_value` is not a value between 0 and `NumDimensions(input)`, then the condition in the `if` is never true, so code writes past the last valid element of `output_dims-&gt;data`. The fix will be included in TensorFlow 2.5.0. We will also cherrypick this commit on TensorFlow 2.4.2, TensorFlow 2.3.3, TensorFlow 2.2.3 and TensorFlow 2.1.4, as these are also affected and still in supported range.

- [https://github.com/JamesGeee/CVE-2021-29603](https://github.com/JamesGeee/CVE-2021-29603) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29603.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29603.svg)


## CVE-2021-29602
 TensorFlow is an end-to-end open source platform for machine learning. The implementation of the `DepthwiseConv` TFLite operator is vulnerable to a division by zero error(https://github.com/tensorflow/tensorflow/blob/1a8e885b864c818198a5b2c0cbbeca5a1e833bc8/tensorflow/lite/kernels/depthwise_conv.cc#L287-L288). An attacker can craft a model such that `input`'s fourth dimension would be 0. The fix will be included in TensorFlow 2.5.0. We will also cherrypick this commit on TensorFlow 2.4.2, TensorFlow 2.3.3, TensorFlow 2.2.3 and TensorFlow 2.1.4, as these are also affected and still in supported range.

- [https://github.com/JamesGeee/CVE-2021-29602](https://github.com/JamesGeee/CVE-2021-29602) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29602.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29602.svg)


## CVE-2021-29478
 Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker. An integer overflow bug in Redis 6.2 before 6.2.3 could be exploited to corrupt the heap and potentially result with remote code execution. Redis 6.0 and earlier are not directly affected by this issue. The problem is fixed in version 6.2.3. An additional workaround to mitigate the problem without patching the `redis-server` executable is to prevent users from modifying the `set-max-intset-entries` configuration parameter. This can be done using ACL to restrict unprivileged users from using the `CONFIG SET` command.

- [https://github.com/JamesGeee/CVE-2021-29478](https://github.com/JamesGeee/CVE-2021-29478) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29478.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29478.svg)


## CVE-2021-29425
 In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input string, like &quot;//../foo&quot;, or &quot;\\..\foo&quot;, the result would be the same value, thus possibly providing access to files in the parent directory, but not further above (thus &quot;limited&quot; path traversal), if the calling code would use the result to construct a path value.

- [https://github.com/JamesGeee/CVE-2021-29425](https://github.com/JamesGeee/CVE-2021-29425) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29425.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29425.svg)


## CVE-2021-28465
 Web Media Extensions Remote Code Execution Vulnerability

- [https://github.com/JamesGeee/CVE-2021-28465](https://github.com/JamesGeee/CVE-2021-28465) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-28465.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-28465.svg)


## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27078.

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2021-26814
 Wazuh API in Wazuh from 4.0.0 to 4.0.3 allows authenticated users to execute arbitrary code with administrative privileges via /manager/files URI. An authenticated user to the service may exploit incomplete input validation on the /manager/files API to inject arbitrary code within the API service script.

- [https://github.com/CYS4srl/CVE-2021-26814](https://github.com/CYS4srl/CVE-2021-26814) :  ![starts](https://img.shields.io/github/stars/CYS4srl/CVE-2021-26814.svg) ![forks](https://img.shields.io/github/forks/CYS4srl/CVE-2021-26814.svg)
- [https://github.com/WickdDavid/CVE-2021-26814](https://github.com/WickdDavid/CVE-2021-26814) :  ![starts](https://img.shields.io/github/stars/WickdDavid/CVE-2021-26814.svg) ![forks](https://img.shields.io/github/forks/WickdDavid/CVE-2021-26814.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/convisoappsec/CVE-2021-22204-exiftool](https://github.com/convisoappsec/CVE-2021-22204-exiftool) :  ![starts](https://img.shields.io/github/stars/convisoappsec/CVE-2021-22204-exiftool.svg) ![forks](https://img.shields.io/github/forks/convisoappsec/CVE-2021-22204-exiftool.svg)


## CVE-2021-3007
 ** DISPUTED ** Laminas Project laminas-http before 2.14.2, and Zend Framework 3.0.0, has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the Zend\Http\Response\Stream class in Stream.php. NOTE: Zend Framework is no longer supported by the maintainer. NOTE: the laminas-http vendor considers this a &quot;vulnerability in the PHP language itself&quot; but has added certain type checking as a way to prevent exploitation in (unrecommended) use cases where attacker-supplied data can be deserialized.

- [https://github.com/Vulnmachines/ZF3_CVE-2021-3007](https://github.com/Vulnmachines/ZF3_CVE-2021-3007) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/ZF3_CVE-2021-3007.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/ZF3_CVE-2021-3007.svg)


## CVE-2020-24421
 Adobe InDesign version 15.1.2 (and earlier) is affected by a NULL pointer dereference bug that occurs when handling a malformed .indd file. The impact is limited to causing a denial-of-service of the client application. User interaction is required to exploit this issue.

- [https://github.com/JamesGeee/CVE-2020-24421](https://github.com/JamesGeee/CVE-2020-24421) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-24421.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-24421.svg)


## CVE-2020-23852
 A heap based buffer overflow vulnerability exists in ffjpeg through 2020-07-02 in the jfif_decode(void *ctxt, BMP *pb) function at ffjpeg/src/jfif.c (line 544 &amp; line 545), which could cause a denial of service by submitting a malicious jpeg image.

- [https://github.com/JamesGeee/CVE-2020-23852](https://github.com/JamesGeee/CVE-2020-23852) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-23852.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-23852.svg)


## CVE-2020-23851
 A stack-based buffer overflow vulnerability exists in ffjpeg through 2020-07-02 in the jfif_decode(void *ctxt, BMP *pb) function at ffjpeg/src/jfif.c:513:28, which could cause a denial of service by submitting a malicious jpeg image.

- [https://github.com/JamesGeee/CVE-2020-23851](https://github.com/JamesGeee/CVE-2020-23851) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-23851.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-23851.svg)


## CVE-2020-18102
 Cross Site Scripting (XSS) in Hotels_Server v1.0 allows remote attackers to execute arbitrary code by injecting crafted commands the data fields in the component &quot;/controller/publishHotel.php&quot;.

- [https://github.com/JamesGeee/CVE-2020-18102](https://github.com/JamesGeee/CVE-2020-18102) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-18102.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-18102.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/RepublicR0K/CVE-2020-9484](https://github.com/RepublicR0K/CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/RepublicR0K/CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/RepublicR0K/CVE-2020-9484.svg)


## CVE-2020-9390
 SquaredUp allowed Stored XSS before version 4.6.0. A user was able to create a dashboard that executed malicious content in iframe or by uploading an SVG that contained a script.

- [https://github.com/JamesGeee/CVE-2020-9390](https://github.com/JamesGeee/CVE-2020-9390) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-9390.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-9390.svg)


## CVE-2020-9389
 A username enumeration issue was discovered in SquaredUp before version 4.6.0. The login functionality was implemented in a way that would enable a malicious user to guess valid username due to a different response time from invalid usernames.

- [https://github.com/JamesGeee/CVE-2020-9389](https://github.com/JamesGeee/CVE-2020-9389) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-9389.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-9389.svg)


## CVE-2020-9388
 CSRF protection was not present in SquaredUp before version 4.6.0. A CSRF attack could have been possible by an administrator executing arbitrary code in a HTML dashboard tile via a crafted HTML page, or by uploading a malicious SVG payload into a dashboard.

- [https://github.com/JamesGeee/CVE-2020-9388](https://github.com/JamesGeee/CVE-2020-9388) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-9388.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-9388.svg)


## CVE-2020-3864
 A logic issue was addressed with improved validation. This issue is fixed in iCloud for Windows 7.17, iTunes 12.10.4 for Windows, iCloud for Windows 10.9.2, tvOS 13.3.1, Safari 13.0.5, iOS 13.3.1 and iPadOS 13.3.1. A DOM object context may not have had a unique security origin.

- [https://github.com/JamesGeee/CVE-2020-3864](https://github.com/JamesGeee/CVE-2020-3864) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-3864.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-3864.svg)


## CVE-2020-1020
 A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format.For all systems except Windows 10, an attacker who successfully exploited the vulnerability could execute code remotely, aka 'Adobe Font Manager Library Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0938.

- [https://github.com/mavillon1/CVE-2020-1020-Exploit](https://github.com/mavillon1/CVE-2020-1020-Exploit) :  ![starts](https://img.shields.io/github/stars/mavillon1/CVE-2020-1020-Exploit.svg) ![forks](https://img.shields.io/github/forks/mavillon1/CVE-2020-1020-Exploit.svg)


## CVE-2020-0610
 A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0609.

- [https://github.com/ruppde/rdg_scanner_cve-2020-0609](https://github.com/ruppde/rdg_scanner_cve-2020-0609) :  ![starts](https://img.shields.io/github/stars/ruppde/rdg_scanner_cve-2020-0609.svg) ![forks](https://img.shields.io/github/forks/ruppde/rdg_scanner_cve-2020-0609.svg)


## CVE-2020-0609
 A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0610.

- [https://github.com/ruppde/rdg_scanner_cve-2020-0609](https://github.com/ruppde/rdg_scanner_cve-2020-0609) :  ![starts](https://img.shields.io/github/stars/ruppde/rdg_scanner_cve-2020-0609.svg) ![forks](https://img.shields.io/github/forks/ruppde/rdg_scanner_cve-2020-0609.svg)


## CVE-2019-14322
 In Pallets Werkzeug before 0.15.5, SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames.

- [https://github.com/faisalfs10x/http-vuln-cve2019-14322.nse](https://github.com/faisalfs10x/http-vuln-cve2019-14322.nse) :  ![starts](https://img.shields.io/github/stars/faisalfs10x/http-vuln-cve2019-14322.nse.svg) ![forks](https://img.shields.io/github/forks/faisalfs10x/http-vuln-cve2019-14322.nse.svg)


## CVE-2019-8846
 A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 13.3, iCloud for Windows 10.9, iOS 13.3 and iPadOS 13.3, Safari 13.0.4, iTunes 12.10.3 for Windows, iCloud for Windows 7.16. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8846](https://github.com/JamesGeee/CVE-2019-8846) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8846.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8846.svg)


## CVE-2019-8844
 Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in tvOS 13.3, watchOS 6.1.1, iCloud for Windows 10.9, iOS 13.3 and iPadOS 13.3, Safari 13.0.4, iTunes 12.10.3 for Windows, iCloud for Windows 7.16. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8844](https://github.com/JamesGeee/CVE-2019-8844) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8844.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8844.svg)


## CVE-2019-8835
 Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in tvOS 13.3, iCloud for Windows 10.9, iOS 13.3 and iPadOS 13.3, Safari 13.0.4, iTunes 12.10.3 for Windows, iCloud for Windows 7.16. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8835](https://github.com/JamesGeee/CVE-2019-8835) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8835.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8835.svg)


## CVE-2019-8816
 Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS 13.2 and iPadOS 13.2, tvOS 13.2, watchOS 6.1, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0, iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8816](https://github.com/JamesGeee/CVE-2019-8816) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8816.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8816.svg)


## CVE-2019-8815
 Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS 13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0, iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8815](https://github.com/JamesGeee/CVE-2019-8815) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8815.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8815.svg)


## CVE-2019-8814
 Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS 13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0, iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8814](https://github.com/JamesGeee/CVE-2019-8814) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8814.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8814.svg)


## CVE-2019-8689
 Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS 12.4, macOS Mojave 10.14.6, tvOS 12.4, watchOS 5.3, Safari 12.1.2, iTunes for Windows 12.9.6, iCloud for Windows 7.13, iCloud for Windows 10.6. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2019-8689](https://github.com/JamesGeee/CVE-2019-8689) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-8689.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-8689.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/kienquoc102/CVE-2018-9995-Exploit](https://github.com/kienquoc102/CVE-2018-9995-Exploit) :  ![starts](https://img.shields.io/github/stars/kienquoc102/CVE-2018-9995-Exploit.svg) ![forks](https://img.shields.io/github/forks/kienquoc102/CVE-2018-9995-Exploit.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux](https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux) :  ![starts](https://img.shields.io/github/stars/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg) ![forks](https://img.shields.io/github/forks/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg)

