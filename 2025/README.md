## CVE-2025-24659
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WordPress Download Manager Premium Packages allows Blind SQL Injection. This issue affects Premium Packages: from n/a through 5.9.6.



- [https://github.com/DoTTak/CVE-2025-24659](https://github.com/DoTTak/CVE-2025-24659) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24659.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24659.svg)

## CVE-2025-24587
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in I Thirteen Web Solution Email Subscription Popup allows Blind SQL Injection. This issue affects Email Subscription Popup: from n/a through 1.2.23.



- [https://github.com/DoTTak/CVE-2025-24587](https://github.com/DoTTak/CVE-2025-24587) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24587.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24587.svg)

## CVE-2025-24118
 The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.4, macOS Sequoia 15.3, macOS Sonoma 14.7.3. An app may be able to cause unexpected system termination or write kernel memory.



- [https://github.com/jprx/CVE-2025-24118](https://github.com/jprx/CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2025-24118.svg)

## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.



- [https://github.com/bronsoneaver/CVE-2025-24085](https://github.com/bronsoneaver/CVE-2025-24085) :  ![starts](https://img.shields.io/github/stars/bronsoneaver/CVE-2025-24085.svg) ![forks](https://img.shields.io/github/forks/bronsoneaver/CVE-2025-24085.svg)

## CVE-2025-23040
 GitHub Desktop is an open-source Electron-based GitHub app designed for git development. An attacker convincing a user to clone a repository directly or through a submodule can allow the attacker access to the user's credentials through the use of maliciously crafted remote URL. GitHub Desktop relies on Git to perform all network related operations (such as cloning, fetching, and pushing). When a user attempts to clone a repository GitHub Desktop will invoke `git clone` and when Git encounters a remote which requires authentication it will request the credentials for that remote host from GitHub Desktop using the git-credential protocol. Using a maliciously crafted URL it's possible to cause the credential request coming from Git to be misinterpreted by Github Desktop such that it will send credentials for a different host than the host that Git is currently communicating with thereby allowing for secret exfiltration. GitHub username and OAuth token, or credentials for other Git remote hosts stored in GitHub Desktop could be improperly transmitted to an unrelated host. Users should update to GitHub Desktop 3.4.12 or greater which fixes this vulnerability. Users who suspect they may be affected should revoke any relevant credentials.



- [https://github.com/GabrieleDattile/CVE-2025-23040](https://github.com/GabrieleDattile/CVE-2025-23040) :  ![starts](https://img.shields.io/github/stars/GabrieleDattile/CVE-2025-23040.svg) ![forks](https://img.shields.io/github/forks/GabrieleDattile/CVE-2025-23040.svg)

## CVE-2025-22968
 An issue in D-Link DWR-M972V 1.05SSG allows a remote attacker to execute arbitrary code via SSH using root account without restrictions



- [https://github.com/CRUNZEX/CVE-2025-22968](https://github.com/CRUNZEX/CVE-2025-22968) :  ![starts](https://img.shields.io/github/stars/CRUNZEX/CVE-2025-22968.svg) ![forks](https://img.shields.io/github/forks/CRUNZEX/CVE-2025-22968.svg)

## CVE-2025-22964
 DDSN Interactive cm3 Acora CMS version 10.1.1 has an unauthenticated time-based blind SQL Injection vulnerability caused by insufficient input sanitization and validation in the "table" parameter. This flaw allows attackers to inject malicious SQL queries by directly incorporating user-supplied input into database queries without proper escaping or validation. Exploiting this issue enables unauthorized access, manipulation of data, or exposure of sensitive information, posing significant risks to the integrity and confidentiality of the application.



- [https://github.com/padayali-JD/CVE-2025-22964](https://github.com/padayali-JD/CVE-2025-22964) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-22964.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-22964.svg)

## CVE-2025-22828
 CloudStack users can add and read comments (annotations) on resources they are authorised to access. 

Due to an access validation issue that affects Apache CloudStack versions from 4.16.0, users who have access, prior access or knowledge of resource UUIDs can list and add comments (annotations) to such resources. 

An attacker with a user-account and access or prior knowledge of resource UUIDs may exploit this issue to read contents of the comments (annotations) or add malicious comments (annotations) to such resources. 

This may cause potential loss of confidentiality of CloudStack environments and resources if the comments (annotations) contain any privileged information. However, guessing or brute-forcing resource UUIDs are generally hard to impossible and access to listing or adding comments isn't same as access to CloudStack resources, making this issue of very low severity and general low impact.


CloudStack admins may also disallow listAnnotations and addAnnotation API access to non-admin roles in their environment as an interim measure.



- [https://github.com/Stolichnayer/CVE-2025-22828](https://github.com/Stolichnayer/CVE-2025-22828) :  ![starts](https://img.shields.io/github/stars/Stolichnayer/CVE-2025-22828.svg) ![forks](https://img.shields.io/github/forks/Stolichnayer/CVE-2025-22828.svg)

## CVE-2025-22710
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in StoreApps Smart Manager allows Blind SQL Injection. This issue affects Smart Manager: from n/a through 8.52.0.



- [https://github.com/DoTTak/CVE-2025-22710](https://github.com/DoTTak/CVE-2025-22710) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22710.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22710.svg)

## CVE-2025-22620
 gitoxide is an implementation of git written in Rust. Prior to 0.17.0, gix-worktree-state specifies 0777 permissions when checking out executable files, intending that the umask will restrict them appropriately. But one of the strategies it uses to set permissions is not subject to the umask. This causes files in a repository to be world-writable in some situations. This vulnerability is fixed in 0.17.0.



- [https://github.com/EliahKagan/checkout-index](https://github.com/EliahKagan/checkout-index) :  ![starts](https://img.shields.io/github/stars/EliahKagan/checkout-index.svg) ![forks](https://img.shields.io/github/forks/EliahKagan/checkout-index.svg)

## CVE-2025-22510
 Deserialization of Untrusted Data vulnerability in Konrad Karpieszuk WC Price History for Omnibus allows Object Injection.This issue affects WC Price History for Omnibus: from n/a through 2.1.4.



- [https://github.com/DoTTak/CVE-2025-22510](https://github.com/DoTTak/CVE-2025-22510) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22510.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22510.svg)

## CVE-2025-22352
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ELEXtensions ELEX WooCommerce Advanced Bulk Edit Products, Prices & Attributes allows Blind SQL Injection.This issue affects ELEX WooCommerce Advanced Bulk Edit Products, Prices & Attributes: from n/a through 1.4.8.



- [https://github.com/DoTTak/CVE-2025-22352](https://github.com/DoTTak/CVE-2025-22352) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22352.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22352.svg)

## CVE-2025-21385
 A Server-Side Request Forgery (SSRF) vulnerability in Microsoft Purview allows an authorized attacker to disclose information over a network.



- [https://github.com/Pauloxc6/CVE-2025-21385](https://github.com/Pauloxc6/CVE-2025-21385) :  ![starts](https://img.shields.io/github/stars/Pauloxc6/CVE-2025-21385.svg) ![forks](https://img.shields.io/github/forks/Pauloxc6/CVE-2025-21385.svg)

## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability



- [https://github.com/ynwarcs/CVE-2025-21298](https://github.com/ynwarcs/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/ynwarcs/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/ynwarcs/CVE-2025-21298.svg)

## CVE-2025-0411
 7-Zip Mark-of-the-Web Bypass Vulnerability. This vulnerability allows remote attackers to bypass the Mark-of-the-Web protection mechanism on affected installations of 7-Zip. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.



- [https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC](https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/iSee857/CVE-2025-0411-PoC](https://github.com/iSee857/CVE-2025-0411-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0411-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0411-PoC.svg)

- [https://github.com/CastroJared/7-Zip-CVE-2025-0411-POC](https://github.com/CastroJared/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/CastroJared/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/CastroJared/7-Zip-CVE-2025-0411-POC.svg)

## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.



- [https://github.com/absholi7ly/CVE-2025-0282-Ivanti-exploit](https://github.com/absholi7ly/CVE-2025-0282-Ivanti-exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-0282-Ivanti-exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-0282-Ivanti-exploit.svg)

- [https://github.com/sfewer-r7/CVE-2025-0282](https://github.com/sfewer-r7/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2025-0282.svg)

- [https://github.com/watchtowrlabs/CVE-2025-0282](https://github.com/watchtowrlabs/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2025-0282.svg)

- [https://github.com/securexploit1/CVE-2025-0282](https://github.com/securexploit1/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/securexploit1/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/securexploit1/CVE-2025-0282.svg)

- [https://github.com/AnonStorks/CVE-2025-0282-Full-version](https://github.com/AnonStorks/CVE-2025-0282-Full-version) :  ![starts](https://img.shields.io/github/stars/AnonStorks/CVE-2025-0282-Full-version.svg) ![forks](https://img.shields.io/github/forks/AnonStorks/CVE-2025-0282-Full-version.svg)

- [https://github.com/AdaniKamal/CVE-2025-0282](https://github.com/AdaniKamal/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/AdaniKamal/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/AdaniKamal/CVE-2025-0282.svg)

- [https://github.com/chiefchainer/CVE-2025-0282](https://github.com/chiefchainer/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/chiefchainer/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/chiefchainer/CVE-2025-0282.svg)

- [https://github.com/NyxanGoat/CVE-2025-0282-PoC](https://github.com/NyxanGoat/CVE-2025-0282-PoC) :  ![starts](https://img.shields.io/github/stars/NyxanGoat/CVE-2025-0282-PoC.svg) ![forks](https://img.shields.io/github/forks/NyxanGoat/CVE-2025-0282-PoC.svg)

- [https://github.com/rxwx/pulse-meter](https://github.com/rxwx/pulse-meter) :  ![starts](https://img.shields.io/github/stars/rxwx/pulse-meter.svg) ![forks](https://img.shields.io/github/forks/rxwx/pulse-meter.svg)

- [https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser) :  ![starts](https://img.shields.io/github/stars/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg) ![forks](https://img.shields.io/github/forks/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg)
