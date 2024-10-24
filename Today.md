# Update 2024-10-24
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/grecosamuel/CVE-2024-32002](https://github.com/grecosamuel/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/grecosamuel/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/grecosamuel/CVE-2024-32002.svg)


## CVE-2023-46747
 Undisclosed requests may bypass configuration utility authentication, allowing an attacker with network access to the BIG-IP system through the management port and/or self IP addresses to execute arbitrary system commands. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/Rizzler4562/CVE-2023-46747-Mass-RCE](https://github.com/Rizzler4562/CVE-2023-46747-Mass-RCE) :  ![starts](https://img.shields.io/github/stars/Rizzler4562/CVE-2023-46747-Mass-RCE.svg) ![forks](https://img.shields.io/github/forks/Rizzler4562/CVE-2023-46747-Mass-RCE.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/cuanh2333/CVE-2023-46604](https://github.com/cuanh2333/CVE-2023-46604) :  ![starts](https://img.shields.io/github/stars/cuanh2333/CVE-2023-46604.svg) ![forks](https://img.shields.io/github/forks/cuanh2333/CVE-2023-46604.svg)

