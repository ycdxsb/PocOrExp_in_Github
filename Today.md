# Update 2021-11-04
## CVE-2021-42694
 An issue was discovered in the character definitions of the Unicode Specification through 14.0. The specification allows an adversary to produce source code identifiers such as function names using homoglyphs that render visually identical to a target identifier. Adversaries can leverage this to inject code via adversarial identifier definitions in upstream software dependencies invoked deceptively in downstream software.

- [https://github.com/js-on/CVE-2021-42694](https://github.com/js-on/CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/js-on/CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/js-on/CVE-2021-42694.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers.

- [https://github.com/js-on/CVE-2021-42574](https://github.com/js-on/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/js-on/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/js-on/CVE-2021-42574.svg)


## CVE-2021-41822
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/badboycxcc/CVE-2021-41822](https://github.com/badboycxcc/CVE-2021-41822) :  ![starts](https://img.shields.io/github/stars/badboycxcc/CVE-2021-41822.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/CVE-2021-41822.svg)


## CVE-2021-22119
 Spring Security versions 5.5.x prior to 5.5.1, 5.4.x prior to 5.4.7, 5.3.x prior to 5.3.10 and 5.2.x prior to 5.2.11 are susceptible to a Denial-of-Service (DoS) attack via the initiation of the Authorization Request in an OAuth 2.0 Client Web and WebFlux application. A malicious user or attacker can send multiple requests initiating the Authorization Request for the Authorization Code Grant, which has the potential of exhausting system resources using a single session or multiple sessions.

- [https://github.com/mari6274/oauth-client-exploit](https://github.com/mari6274/oauth-client-exploit) :  ![starts](https://img.shields.io/github/stars/mari6274/oauth-client-exploit.svg) ![forks](https://img.shields.io/github/forks/mari6274/oauth-client-exploit.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/Aviksaikat/CVE-2020-3452](https://github.com/Aviksaikat/CVE-2020-3452) :  ![starts](https://img.shields.io/github/stars/Aviksaikat/CVE-2020-3452.svg) ![forks](https://img.shields.io/github/forks/Aviksaikat/CVE-2020-3452.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/Trushal2004/CVE-2018-16763](https://github.com/Trushal2004/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/Trushal2004/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/Trushal2004/CVE-2018-16763.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/imojne/CVE-2018-6574-POC](https://github.com/imojne/CVE-2018-6574-POC) :  ![starts](https://img.shields.io/github/stars/imojne/CVE-2018-6574-POC.svg) ![forks](https://img.shields.io/github/forks/imojne/CVE-2018-6574-POC.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/nksf7/CVE-2015-1635](https://github.com/nksf7/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/nksf7/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/nksf7/CVE-2015-1635.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/Adel-kaka-dz/CVE-2006-3392](https://github.com/Adel-kaka-dz/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/Adel-kaka-dz/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/Adel-kaka-dz/CVE-2006-3392.svg)

