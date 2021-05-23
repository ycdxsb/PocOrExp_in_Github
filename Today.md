# Update 2021-05-23
## CVE-2020-14372
 A flaw was found in grub2 in versions prior to 2.06, where it incorrectly enables the usage of the ACPI command when Secure Boot is enabled. This flaw allows an attacker with privileged access to craft a Secondary System Description Table (SSDT) containing code to overwrite the Linux kernel lockdown variable content directly into memory. The table is further loaded and executed by the kernel, defeating its Secure Boot lockdown and allowing the attacker to load unsigned code. The highest threat from this vulnerability is to data confidentiality and integrity, as well as system availability.

- [https://github.com/kukrimate/CVE-2020-14372](https://github.com/kukrimate/CVE-2020-14372) :  ![starts](https://img.shields.io/github/stars/kukrimate/CVE-2020-14372.svg) ![forks](https://img.shields.io/github/forks/kukrimate/CVE-2020-14372.svg)


## CVE-2019-8389
 A file-read vulnerability was identified in the Wi-Fi transfer feature of Musicloud 1.6. By default, the application runs a transfer service on port 8080, accessible by everyone on the same Wi-Fi network. An attacker can send the POST parameters downfiles and cur-folder (with a crafted ../ payload) to the download.script endpoint. This will create a MusicPlayerArchive.zip archive that is publicly accessible and includes the content of any requested file (such as the /etc/passwd file).

- [https://github.com/shawarkhanethicalhacker/CVE-2019-8389](https://github.com/shawarkhanethicalhacker/CVE-2019-8389) :  ![starts](https://img.shields.io/github/stars/shawarkhanethicalhacker/CVE-2019-8389.svg) ![forks](https://img.shields.io/github/forks/shawarkhanethicalhacker/CVE-2019-8389.svg)


## CVE-2019-0604
 A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0594.

- [https://github.com/MayankPandey01/Sparty-2.0](https://github.com/MayankPandey01/Sparty-2.0) :  ![starts](https://img.shields.io/github/stars/MayankPandey01/Sparty-2.0.svg) ![forks](https://img.shields.io/github/forks/MayankPandey01/Sparty-2.0.svg)


## CVE-2019-0504
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/MayankPandey01/Sparty-2.0](https://github.com/MayankPandey01/Sparty-2.0) :  ![starts](https://img.shields.io/github/stars/MayankPandey01/Sparty-2.0.svg) ![forks](https://img.shields.io/github/forks/MayankPandey01/Sparty-2.0.svg)

