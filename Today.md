# Update 2024-08-16
## CVE-2024-23705
 In multiple locations, there is a possible failure to persist or enforce user restrictions due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.

- [https://github.com/uthrasri/frameworks_base_CVE-2024-23705](https://github.com/uthrasri/frameworks_base_CVE-2024-23705) :  ![starts](https://img.shields.io/github/stars/uthrasri/frameworks_base_CVE-2024-23705.svg) ![forks](https://img.shields.io/github/forks/uthrasri/frameworks_base_CVE-2024-23705.svg)


## CVE-2024-22120
 Zabbix server can perform command execution for configured scripts. After command is executed, audit entry is added to &quot;Audit Log&quot;. Due to &quot;clientip&quot; field is not sanitized, it is possible to injection SQL into &quot;clientip&quot; and exploit time based blind SQL injection.

- [https://github.com/isPique/CVE-2024-22120-RCE-with-gopher](https://github.com/isPique/CVE-2024-22120-RCE-with-gopher) :  ![starts](https://img.shields.io/github/stars/isPique/CVE-2024-22120-RCE-with-gopher.svg) ![forks](https://img.shields.io/github/forks/isPique/CVE-2024-22120-RCE-with-gopher.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/JolyIrsb/CVE-2024-4956](https://github.com/JolyIrsb/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/JolyIrsb/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/JolyIrsb/CVE-2024-4956.svg)


## CVE-2024-4879
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jdusane/CVE-2024-4879](https://github.com/jdusane/CVE-2024-4879) :  ![starts](https://img.shields.io/github/stars/jdusane/CVE-2024-4879.svg) ![forks](https://img.shields.io/github/forks/jdusane/CVE-2024-4879.svg)


## CVE-2024-3183
 A vulnerability was found in FreeIPA in a way when a Kerberos TGS-REQ is encrypted using the client&#8217;s session key. This key is different for each new session, which protects it from brute force attacks. However, the ticket it contains is encrypted using the target principal key directly. For user principals, this key is a hash of a public per-principal randomly-generated salt and the user&#8217;s password. If a principal is compromised it means the attacker would be able to retrieve tickets encrypted to any principal, all of them being encrypted by their own key directly. By taking these tickets and salts offline, the attacker could run brute force attacks to find character strings able to decrypt tickets when combined to a principal salt (i.e. find the principal&#8217;s password).

- [https://github.com/Cyxow/CVE-2024-3183-POC](https://github.com/Cyxow/CVE-2024-3183-POC) :  ![starts](https://img.shields.io/github/stars/Cyxow/CVE-2024-3183-POC.svg) ![forks](https://img.shields.io/github/forks/Cyxow/CVE-2024-3183-POC.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/AntiVlad/CVE-2023-22809](https://github.com/AntiVlad/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/AntiVlad/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/AntiVlad/CVE-2023-22809.svg)


## CVE-2021-46702
 Tor Browser 9.0.7 on Windows 10 build 10586 is vulnerable to information disclosure. This could allow local attackers to bypass the intended anonymity feature and obtain information regarding the onion services visited by a local user. This can be accomplished by analyzing RAM memory even several hours after the local user used the product. This occurs because the product doesn't properly free memory.

- [https://github.com/Exmak-s/CVE-2021-46702](https://github.com/Exmak-s/CVE-2021-46702) :  ![starts](https://img.shields.io/github/stars/Exmak-s/CVE-2021-46702.svg) ![forks](https://img.shields.io/github/forks/Exmak-s/CVE-2021-46702.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/MahdiOsman/CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing](https://github.com/MahdiOsman/CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing) :  ![starts](https://img.shields.io/github/stars/MahdiOsman/CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing.svg) ![forks](https://img.shields.io/github/forks/MahdiOsman/CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing.svg)

