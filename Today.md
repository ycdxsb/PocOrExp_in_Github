# Update 2021-09-15
## CVE-2021-41074
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/dillonkirsch/CVE-2021-41074](https://github.com/dillonkirsch/CVE-2021-41074) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2021-41074.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2021-41074.svg)


## CVE-2021-40444
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/aydianosec/CVE2021-40444](https://github.com/aydianosec/CVE2021-40444) :  ![starts](https://img.shields.io/github/stars/aydianosec/CVE2021-40444.svg) ![forks](https://img.shields.io/github/forks/aydianosec/CVE2021-40444.svg)
- [https://github.com/khoaduynu/CVE-2021-40444](https://github.com/khoaduynu/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/khoaduynu/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/khoaduynu/CVE-2021-40444.svg)
- [https://github.com/Immersive-Labs-Sec/cve-2021-40444-analysis](https://github.com/Immersive-Labs-Sec/cve-2021-40444-analysis) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/cve-2021-40444-analysis.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/cve-2021-40444-analysis.svg)


## CVE-2021-36582
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/l00neyhacker/CVE-2021-36582](https://github.com/l00neyhacker/CVE-2021-36582) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-36582.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-36582.svg)


## CVE-2021-36581
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/l00neyhacker/CVE-2021-36581](https://github.com/l00neyhacker/CVE-2021-36581) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-36581.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-36581.svg)


## CVE-2021-32202
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/l00neyhacker/CVE-2021-32202](https://github.com/l00neyhacker/CVE-2021-32202) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-32202.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-32202.svg)


## CVE-2021-27850
 A critical unauthenticated remote code execution vulnerability was found all recent versions of Apache Tapestry. The affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. The vulnerability I have found is a bypass of the fix for CVE-2019-0195. Recap: Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL. An attacker was able to download the file `AppModule.class` by requesting the URL `http://localhost:8080/assets/something/services/AppModule.class` which contains a HMAC secret key. The fix for that bug was a blacklist filter that checks if the URL ends with `.class`, `.properties` or `.xml`. Bypass: Unfortunately, the blacklist solution can simply be bypassed by appending a `/` at the end of the URL: `http://localhost:8080/assets/something/services/AppModule.class/` The slash is stripped after the blacklist check and the file `AppModule.class` is loaded into the response. This class usually contains the HMAC secret key which is used to sign serialized Java objects. With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE (e.g. CommonsBeanUtils1 from ysoserial). Solution for this vulnerability: * For Apache Tapestry 5.4.0 to 5.6.1, upgrade to 5.6.2 or later. * For Apache Tapestry 5.7.0, upgrade to 5.7.1 or later.

- [https://github.com/dorkerdevil/CVE-2021-27850_POC](https://github.com/dorkerdevil/CVE-2021-27850_POC) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-27850_POC.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-27850_POC.svg)


## CVE-2021-2075
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2020-28647
 In Progress MOVEit Transfer before 2020.1, a malicious user could craft and store a payload within the application. If a victim within the MOVEit Transfer instance interacts with the stored payload, it could invoke and execute arbitrary code within the context of the victim's browser (XSS).

- [https://github.com/SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647](https://github.com/SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647) :  ![starts](https://img.shields.io/github/stars/SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647.svg) ![forks](https://img.shields.io/github/forks/SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647.svg)


## CVE-2019-15782
 WebTorrent before 0.107.6 allows XSS in the HTTP server via a title or file name.

- [https://github.com/ossf-cve-benchmark/CVE-2019-15782](https://github.com/ossf-cve-benchmark/CVE-2019-15782) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-15782.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-15782.svg)


## CVE-2018-19592
 The &quot;CLink4Service&quot; service is installed with Corsair Link 4.9.7.35 with insecure permissions by default. This allows unprivileged users to take control of the service and execute commands in the context of NT AUTHORITY\SYSTEM, leading to total system takeover, a similar issue to CVE-2018-12441.

- [https://github.com/BradyDonovan/CVE-2018-19592](https://github.com/BradyDonovan/CVE-2018-19592) :  ![starts](https://img.shields.io/github/stars/BradyDonovan/CVE-2018-19592.svg) ![forks](https://img.shields.io/github/forks/BradyDonovan/CVE-2018-19592.svg)

