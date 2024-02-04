# Update 2024-02-04
## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/iota4/PoC-Fix-jenkins-rce_CVE-2024-23897](https://github.com/iota4/PoC-Fix-jenkins-rce_CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/iota4/PoC-Fix-jenkins-rce_CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/iota4/PoC-Fix-jenkins-rce_CVE-2024-23897.svg)
- [https://github.com/brijne/CVE-2024-23897-RCE](https://github.com/brijne/CVE-2024-23897-RCE) :  ![starts](https://img.shields.io/github/stars/brijne/CVE-2024-23897-RCE.svg) ![forks](https://img.shields.io/github/forks/brijne/CVE-2024-23897-RCE.svg)


## CVE-2024-21893
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/h4x0r-dz/CVE-2024-21893.py](https://github.com/h4x0r-dz/CVE-2024-21893.py) :  ![starts](https://img.shields.io/github/stars/h4x0r-dz/CVE-2024-21893.py.svg) ![forks](https://img.shields.io/github/forks/h4x0r-dz/CVE-2024-21893.py.svg)


## CVE-2024-21626
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/zhangguanzhang/CVE-2024-21626](https://github.com/zhangguanzhang/CVE-2024-21626) :  ![starts](https://img.shields.io/github/stars/zhangguanzhang/CVE-2024-21626.svg) ![forks](https://img.shields.io/github/forks/zhangguanzhang/CVE-2024-21626.svg)
- [https://github.com/laysakura/CVE-2024-21626-demo](https://github.com/laysakura/CVE-2024-21626-demo) :  ![starts](https://img.shields.io/github/stars/laysakura/CVE-2024-21626-demo.svg) ![forks](https://img.shields.io/github/forks/laysakura/CVE-2024-21626-demo.svg)


## CVE-2024-0652
 A vulnerability was found in PHPGurukul Company Visitor Management System 1.0. It has been rated as problematic. Affected by this issue is some unknown functionality of the file search-visitor.php. The manipulation leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-251378 is the identifier assigned to this vulnerability.

- [https://github.com/Agampreet-Singh/CVE-2024-0652](https://github.com/Agampreet-Singh/CVE-2024-0652) :  ![starts](https://img.shields.io/github/stars/Agampreet-Singh/CVE-2024-0652.svg) ![forks](https://img.shields.io/github/forks/Agampreet-Singh/CVE-2024-0652.svg)


## CVE-2022-37434
 zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).

- [https://github.com/Trinadh465/external_zlib_CVE-2022-37434](https://github.com/Trinadh465/external_zlib_CVE-2022-37434) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_zlib_CVE-2022-37434.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_zlib_CVE-2022-37434.svg)


## CVE-2020-12717
 The COVIDSafe (Australia) app 1.0 and 1.1 for iOS allows a remote attacker to crash the app, and consequently interfere with COVID-19 contact tracing, via a Bluetooth advertisement containing manufacturer data that is too short. This occurs because of an erroneous OpenTrace manuData.subdata call. The ABTraceTogether (Alberta), ProteGO (Poland), and TraceTogether (Singapore) apps were also affected.

- [https://github.com/wabzqem/covidsafe-CVE-2020-12717-exploit](https://github.com/wabzqem/covidsafe-CVE-2020-12717-exploit) :  ![starts](https://img.shields.io/github/stars/wabzqem/covidsafe-CVE-2020-12717-exploit.svg) ![forks](https://img.shields.io/github/forks/wabzqem/covidsafe-CVE-2020-12717-exploit.svg)


## CVE-2013-3664
 Trimble SketchUp (formerly Google SketchUp) before 2013 (13.0.3689) allows remote attackers to execute arbitrary code via a crafted color palette table in a MAC Pict texture, which triggers an out-of-bounds stack write.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-3662.  NOTE: this issue was SPLIT due to different affected products and codebases (ADT1); CVE-2013-7388 has been assigned to the paintlib issue.

- [https://github.com/defrancescojp/CVE-2013-3664_MAC](https://github.com/defrancescojp/CVE-2013-3664_MAC) :  ![starts](https://img.shields.io/github/stars/defrancescojp/CVE-2013-3664_MAC.svg) ![forks](https://img.shields.io/github/forks/defrancescojp/CVE-2013-3664_MAC.svg)
- [https://github.com/defrancescojp/CVE-2013-3664_BMP](https://github.com/defrancescojp/CVE-2013-3664_BMP) :  ![starts](https://img.shields.io/github/stars/defrancescojp/CVE-2013-3664_BMP.svg) ![forks](https://img.shields.io/github/forks/defrancescojp/CVE-2013-3664_BMP.svg)


## CVE-2013-2977
 Integer overflow in IBM Notes 8.5.x before 8.5.3 FP4 Interim Fix 1 and 9.x before 9.0 Interim Fix 1 on Windows, and 8.5.x before 8.5.3 FP5 and 9.x before 9.0.1 on Linux, allows remote attackers to execute arbitrary code via a malformed PNG image in a previewed e-mail message, aka SPR NPEI96K82Q.

- [https://github.com/defrancescojp/CVE-2013-2977](https://github.com/defrancescojp/CVE-2013-2977) :  ![starts](https://img.shields.io/github/stars/defrancescojp/CVE-2013-2977.svg) ![forks](https://img.shields.io/github/forks/defrancescojp/CVE-2013-2977.svg)

