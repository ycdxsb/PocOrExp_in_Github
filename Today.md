# Update 2024-12-13
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/jolibb55/donald](https://github.com/jolibb55/donald) :  ![starts](https://img.shields.io/github/stars/jolibb55/donald.svg) ![forks](https://img.shields.io/github/forks/jolibb55/donald.svg)


## CVE-2024-5558
 CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability exists that could cause escalation of privileges when an attacker abuses a limited admin account.

- [https://github.com/CSIRTTrizna/CVE-2024-55587](https://github.com/CSIRTTrizna/CVE-2024-55587) :  ![starts](https://img.shields.io/github/stars/CSIRTTrizna/CVE-2024-55587.svg) ![forks](https://img.shields.io/github/forks/CSIRTTrizna/CVE-2024-55587.svg)


## CVE-2024-5062
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/watchtowrlabs/CVE-2024-50623](https://github.com/watchtowrlabs/CVE-2024-50623) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2024-50623.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2024-50623.svg)


## CVE-2024-4232
 This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to lack of encryption or hashing in storing of passwords within the router's firmware/ database. An attacker with physical access could exploit this by extracting the firmware and reverse engineer the binary data to access the plaintext passwords on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to gain unauthorized access to the targeted system.

- [https://github.com/igorbf495/CVE-2024-42327](https://github.com/igorbf495/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/igorbf495/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/igorbf495/CVE-2024-42327.svg)


## CVE-2024-1172
 The Essential Addons for Elementor &#8211; Best Elementor Templates, Widgets, Kits &amp; WooCommerce Builders plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's Accordion widget in all versions up to, and including, 5.9.8 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers with contributor-level and above permissions to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/samogod/CVE-2024-11728](https://github.com/samogod/CVE-2024-11728) :  ![starts](https://img.shields.io/github/stars/samogod/CVE-2024-11728.svg) ![forks](https://img.shields.io/github/forks/samogod/CVE-2024-11728.svg)


## CVE-2024-0012
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC](https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC) :  ![starts](https://img.shields.io/github/stars/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC.svg) ![forks](https://img.shields.io/github/forks/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/tomasmussi-mulesoft/activemq-cve-2023-46604-duplicate](https://github.com/tomasmussi-mulesoft/activemq-cve-2023-46604-duplicate) :  ![starts](https://img.shields.io/github/stars/tomasmussi-mulesoft/activemq-cve-2023-46604-duplicate.svg) ![forks](https://img.shields.io/github/forks/tomasmussi-mulesoft/activemq-cve-2023-46604-duplicate.svg)


## CVE-2023-3460
 The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.

- [https://github.com/TranKuBao/CVE-2023-3460_FIX](https://github.com/TranKuBao/CVE-2023-3460_FIX) :  ![starts](https://img.shields.io/github/stars/TranKuBao/CVE-2023-3460_FIX.svg) ![forks](https://img.shields.io/github/forks/TranKuBao/CVE-2023-3460_FIX.svg)


## CVE-2022-23303
 The implementations of SAE in hostapd before 2.10 and wpa_supplicant before 2.10 are vulnerable to side channel attacks as a result of cache access patterns. NOTE: this issue exists because of an incomplete fix for CVE-2019-9494.

- [https://github.com/web-logs2/hostapd_mirror](https://github.com/web-logs2/hostapd_mirror) :  ![starts](https://img.shields.io/github/stars/web-logs2/hostapd_mirror.svg) ![forks](https://img.shields.io/github/forks/web-logs2/hostapd_mirror.svg)


## CVE-2022-2588
 It was discovered that the cls_route filter implementation in the Linux kernel would not remove an old filter from the hashtable before freeing it if its handle had the value 0.

- [https://github.com/PolymorphicOpcode/CVE-2022-2588](https://github.com/PolymorphicOpcode/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/PolymorphicOpcode/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/PolymorphicOpcode/CVE-2022-2588.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/l0w3/CVE-2019-18634](https://github.com/l0w3/CVE-2019-18634) :  ![starts](https://img.shields.io/github/stars/l0w3/CVE-2019-18634.svg) ![forks](https://img.shields.io/github/forks/l0w3/CVE-2019-18634.svg)

