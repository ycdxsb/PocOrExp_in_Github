# Update 2021-07-18
## CVE-2021-33560
 Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. (There is also an interoperability problem because the selection of the k integer value does not properly consider the differences between basic ElGamal encryption and generalized ElGamal encryption.) This, for example, affects use of ElGamal in OpenPGP.

- [https://github.com/IBM/PGP-client-checker-CVE-2021-33560](https://github.com/IBM/PGP-client-checker-CVE-2021-33560) :  ![starts](https://img.shields.io/github/stars/IBM/PGP-client-checker-CVE-2021-33560.svg) ![forks](https://img.shields.io/github/forks/IBM/PGP-client-checker-CVE-2021-33560.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/cgwalters/container-cve-2021-22555](https://github.com/cgwalters/container-cve-2021-22555) :  ![starts](https://img.shields.io/github/stars/cgwalters/container-cve-2021-22555.svg) ![forks](https://img.shields.io/github/forks/cgwalters/container-cve-2021-22555.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/thalpius/Microsoft-CVE-2021-1675](https://github.com/thalpius/Microsoft-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/thalpius/Microsoft-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thalpius/Microsoft-CVE-2021-1675.svg)


## CVE-2014-8609
 The addAccount method in src/com/android/settings/accounts/AddAccountSettings.java in the Settings application in Android before 5.0.0 does not properly create a PendingIntent, which allows attackers to use the SYSTEM uid for broadcasting an intent with arbitrary component, action, or category information via a third-party authenticator in a crafted application, aka Bug 17356824.

- [https://github.com/MazX0p/CVE-2014-8609-POC](https://github.com/MazX0p/CVE-2014-8609-POC) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2014-8609-POC.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2014-8609-POC.svg)

