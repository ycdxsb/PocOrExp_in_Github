# Update 2021-06-27
## CVE-2021-35448
 Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe. It binds to local ports to listen for incoming connections.

- [https://github.com/deathflash1411/CVE-2021-35448](https://github.com/deathflash1411/CVE-2021-35448) :  ![starts](https://img.shields.io/github/stars/deathflash1411/CVE-2021-35448.svg) ![forks](https://img.shields.io/github/forks/deathflash1411/CVE-2021-35448.svg)


## CVE-2021-33624
 In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a side-channel attack, aka CID-9183671af6db.

- [https://github.com/Kakashiiiiy/CVE-2021-33624](https://github.com/Kakashiiiiy/CVE-2021-33624) :  ![starts](https://img.shields.io/github/stars/Kakashiiiiy/CVE-2021-33624.svg) ![forks](https://img.shields.io/github/forks/Kakashiiiiy/CVE-2021-33624.svg)


## CVE-2021-31955
 Windows Kernel Information Disclosure Vulnerability

- [https://github.com/mavillon1/CVE-2021-31955-POC](https://github.com/mavillon1/CVE-2021-31955-POC) :  ![starts](https://img.shields.io/github/stars/mavillon1/CVE-2021-31955-POC.svg) ![forks](https://img.shields.io/github/forks/mavillon1/CVE-2021-31955-POC.svg)


## CVE-2021-27850
 A critical unauthenticated remote code execution vulnerability was found all recent versions of Apache Tapestry. The affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. The vulnerability I have found is a bypass of the fix for CVE-2019-0195. Recap: Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL. An attacker was able to download the file `AppModule.class` by requesting the URL `http://localhost:8080/assets/something/services/AppModule.class` which contains a HMAC secret key. The fix for that bug was a blacklist filter that checks if the URL ends with `.class`, `.properties` or `.xml`. Bypass: Unfortunately, the blacklist solution can simply be bypassed by appending a `/` at the end of the URL: `http://localhost:8080/assets/something/services/AppModule.class/` The slash is stripped after the blacklist check and the file `AppModule.class` is loaded into the response. This class usually contains the HMAC secret key which is used to sign serialized Java objects. With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE (e.g. CommonsBeanUtils1 from ysoserial). Solution for this vulnerability: * For Apache Tapestry 5.4.0 to 5.6.1, upgrade to 5.6.2 or later. * For Apache Tapestry 5.7.0, upgrade to 5.7.1 or later.

- [https://github.com/kahla-sec/CVE-2021-27850_POC](https://github.com/kahla-sec/CVE-2021-27850_POC) :  ![starts](https://img.shields.io/github/stars/kahla-sec/CVE-2021-27850_POC.svg) ![forks](https://img.shields.io/github/forks/kahla-sec/CVE-2021-27850_POC.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/donghyunlee00/CVE-2021-3156](https://github.com/donghyunlee00/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/donghyunlee00/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/donghyunlee00/CVE-2021-3156.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/amil-ptl-test/ptl_cve_2018_6574](https://github.com/amil-ptl-test/ptl_cve_2018_6574) :  ![starts](https://img.shields.io/github/stars/amil-ptl-test/ptl_cve_2018_6574.svg) ![forks](https://img.shields.io/github/forks/amil-ptl-test/ptl_cve_2018_6574.svg)


## CVE-2011-0228
 The Data Security component in Apple iOS before 4.2.10 and 4.3.x before 4.3.5 does not check the basicConstraints parameter during validation of X.509 certificate chains, which allows man-in-the-middle attackers to spoof an SSL server by using a non-CA certificate to sign a certificate for an arbitrary domain.

- [https://github.com/amil-ptl-test/ptl_cve_2011_0228](https://github.com/amil-ptl-test/ptl_cve_2011_0228) :  ![starts](https://img.shields.io/github/stars/amil-ptl-test/ptl_cve_2011_0228.svg) ![forks](https://img.shields.io/github/forks/amil-ptl-test/ptl_cve_2011_0228.svg)

