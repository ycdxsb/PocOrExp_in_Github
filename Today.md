# Update 2021-08-02
## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/ErnestZiemkowski/cve-2018-6574](https://github.com/ErnestZiemkowski/cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/ErnestZiemkowski/cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/ErnestZiemkowski/cve-2018-6574.svg)

