# Update 2021-06-08
## CVE-2021-33879
 Tencent GameLoop before 4.1.21.90 downloaded updates over an insecure HTTP connection. A malicious attacker in an MITM position could spoof the contents of an XML document describing an update package, replacing a download URL with one pointing to an arbitrary Windows executable. Because the only integrity check would be a comparison of the downloaded file's MD5 checksum to the one contained within the XML document, the downloaded executable would then be executed on the victim's machine.

- [https://github.com/mmiszczyk/cve-2021-33879](https://github.com/mmiszczyk/cve-2021-33879) :  ![starts](https://img.shields.io/github/stars/mmiszczyk/cve-2021-33879.svg) ![forks](https://img.shields.io/github/forks/mmiszczyk/cve-2021-33879.svg)


## CVE-2021-25641
 Each Apache Dubbo server will set a serialization id to tell the clients which serialization protocol it is working on. But for Dubbo versions before 2.7.8 or 2.6.9, an attacker can choose which serialization id the Provider will use by tampering with the byte preamble flags, aka, not following the server's instruction. This means that if a weak deserializer such as the Kryo and FST are somehow in code scope (e.g. if Kryo is somehow a part of a dependency), a remote unauthenticated attacker can tell the Provider to use the weak deserializer, and then proceed to exploit it.

- [https://github.com/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept](https://github.com/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept.svg)


## CVE-2020-9496
 XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03

- [https://github.com/ambalabanov/CVE-2020-9496](https://github.com/ambalabanov/CVE-2020-9496) :  ![starts](https://img.shields.io/github/stars/ambalabanov/CVE-2020-9496.svg) ![forks](https://img.shields.io/github/forks/ambalabanov/CVE-2020-9496.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/MrTiz/CVE-2020-0688](https://github.com/MrTiz/CVE-2020-0688) :  ![starts](https://img.shields.io/github/stars/MrTiz/CVE-2020-0688.svg) ![forks](https://img.shields.io/github/forks/MrTiz/CVE-2020-0688.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/kienquoc102/CVE-2018-9995-P2](https://github.com/kienquoc102/CVE-2018-9995-P2) :  ![starts](https://img.shields.io/github/stars/kienquoc102/CVE-2018-9995-P2.svg) ![forks](https://img.shields.io/github/forks/kienquoc102/CVE-2018-9995-P2.svg)

