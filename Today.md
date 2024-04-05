# Update 2024-04-05
## CVE-2024-29375
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ismailcemunver/CVE-2024-29375](https://github.com/ismailcemunver/CVE-2024-29375) :  ![starts](https://img.shields.io/github/stars/ismailcemunver/CVE-2024-29375.svg) ![forks](https://img.shields.io/github/forks/ismailcemunver/CVE-2024-29375.svg)


## CVE-2024-28589
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Alaatk/CVE-2024-28589](https://github.com/Alaatk/CVE-2024-28589) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-28589.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-28589.svg)


## CVE-2024-27674
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Alaatk/CVE-2024-27674](https://github.com/Alaatk/CVE-2024-27674) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-27674.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-27674.svg)


## CVE-2024-27673
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Alaatk/CVE-2024-27673](https://github.com/Alaatk/CVE-2024-27673) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-27673.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-27673.svg)


## CVE-2024-27518
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/secunnix/CVE-2024-27518](https://github.com/secunnix/CVE-2024-27518) :  ![starts](https://img.shields.io/github/stars/secunnix/CVE-2024-27518.svg) ![forks](https://img.shields.io/github/forks/secunnix/CVE-2024-27518.svg)


## CVE-2024-26198
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/babywalkerenc/CVE-2024-26198-POC](https://github.com/babywalkerenc/CVE-2024-26198-POC) :  ![starts](https://img.shields.io/github/stars/babywalkerenc/CVE-2024-26198-POC.svg) ![forks](https://img.shields.io/github/forks/babywalkerenc/CVE-2024-26198-POC.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/lore-is-already-taken/multicheck_CVE-2024-21762](https://github.com/lore-is-already-taken/multicheck_CVE-2024-21762) :  ![starts](https://img.shields.io/github/stars/lore-is-already-taken/multicheck_CVE-2024-21762.svg) ![forks](https://img.shields.io/github/forks/lore-is-already-taken/multicheck_CVE-2024-21762.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem (&quot;attack 2&quot;). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run (&quot;attack 1&quot;). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes (&quot;attack 3a&quot; and &quot;attack 3b&quot;). runc 1.1.12 includes patches for this issue.

- [https://github.com/KubernetesBachelor/CVE-2024-21626](https://github.com/KubernetesBachelor/CVE-2024-21626) :  ![starts](https://img.shields.io/github/stars/KubernetesBachelor/CVE-2024-21626.svg) ![forks](https://img.shields.io/github/forks/KubernetesBachelor/CVE-2024-21626.svg)


## CVE-2024-1086
 A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/Alicey0719/docker-POC_CVE-2024-1086](https://github.com/Alicey0719/docker-POC_CVE-2024-1086) :  ![starts](https://img.shields.io/github/stars/Alicey0719/docker-POC_CVE-2024-1086.svg) ![forks](https://img.shields.io/github/forks/Alicey0719/docker-POC_CVE-2024-1086.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/RUB-NDS/Terrapin-Artifacts](https://github.com/RUB-NDS/Terrapin-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/Terrapin-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/Terrapin-Artifacts.svg)


## CVE-2023-46446
 An issue in AsyncSSH before 2.14.1 allows attackers to control the remote end of an SSH client session via packet injection/removal and shell emulation, aka a &quot;Rogue Session Attack.&quot;

- [https://github.com/RUB-NDS/Terrapin-Artifacts](https://github.com/RUB-NDS/Terrapin-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/Terrapin-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/Terrapin-Artifacts.svg)


## CVE-2023-46445
 An issue in AsyncSSH before 2.14.1 allows attackers to control the extension info message (RFC 8308) via a man-in-the-middle attack, aka a &quot;Rogue Extension Negotiation.&quot;

- [https://github.com/RUB-NDS/Terrapin-Artifacts](https://github.com/RUB-NDS/Terrapin-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/Terrapin-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/Terrapin-Artifacts.svg)


## CVE-2023-46304
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jselliott/CVE-2023-46304](https://github.com/jselliott/CVE-2023-46304) :  ![starts](https://img.shields.io/github/stars/jselliott/CVE-2023-46304.svg) ![forks](https://img.shields.io/github/forks/jselliott/CVE-2023-46304.svg)


## CVE-2023-33466
 Orthanc before 1.12.0 allows authenticated users with access to the Orthanc API to overwrite arbitrary files on the file system, and in specific deployment scenarios allows the attacker to overwrite the configuration, which can be exploited to trigger Remote Code Execution (RCE).

- [https://github.com/v3gahax/CVE-2023-33466](https://github.com/v3gahax/CVE-2023-33466) :  ![starts](https://img.shields.io/github/stars/v3gahax/CVE-2023-33466.svg) ![forks](https://img.shields.io/github/forks/v3gahax/CVE-2023-33466.svg)


## CVE-2021-38297
 Go before 1.16.9 and 1.17.x before 1.17.2 has a Buffer Overflow via large arguments in a function invocation from a WASM module, when GOARCH=wasm GOOS=js is used.

- [https://github.com/paras98/CVE-2021-38297-Go-wasm-Replication](https://github.com/paras98/CVE-2021-38297-Go-wasm-Replication) :  ![starts](https://img.shields.io/github/stars/paras98/CVE-2021-38297-Go-wasm-Replication.svg) ![forks](https://img.shields.io/github/forks/paras98/CVE-2021-38297-Go-wasm-Replication.svg)


## CVE-2018-16890
 libcurl versions from 7.36.0 to before 7.64.0 is vulnerable to a heap buffer out-of-bounds read. The function handling incoming NTLM type-2 messages (`lib/vauth/ntlm.c:ntlm_decode_type2_target`) does not validate incoming data correctly and is subject to an integer overflow vulnerability. Using that overflow, a malicious or broken NTLM server could trick libcurl to accept a bad length + offset combination that would lead to a buffer read out-of-bounds.

- [https://github.com/michelleamesquita/CVE-2018-16890](https://github.com/michelleamesquita/CVE-2018-16890) :  ![starts](https://img.shields.io/github/stars/michelleamesquita/CVE-2018-16890.svg) ![forks](https://img.shields.io/github/forks/michelleamesquita/CVE-2018-16890.svg)

