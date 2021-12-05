# Update 2021-12-05
## CVE-2021-42008
 The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.

- [https://github.com/0xdevil/CVE-2021-42008](https://github.com/0xdevil/CVE-2021-42008) :  ![starts](https://img.shields.io/github/stars/0xdevil/CVE-2021-42008.svg) ![forks](https://img.shields.io/github/forks/0xdevil/CVE-2021-42008.svg)
- [https://github.com/numanturle/CVE-2021-42008](https://github.com/numanturle/CVE-2021-42008) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-42008.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-42008.svg)


## CVE-2021-41379
 Windows Installer Elevation of Privilege Vulnerability

- [https://github.com/jbaines-r7/shakeitoff](https://github.com/jbaines-r7/shakeitoff) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/shakeitoff.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/shakeitoff.svg)


## CVE-2021-37832
 A SQL injection vulnerability exists in version 3.0.2 of Hotel Druid when SQLite is being used as the application database. A malicious attacker can issue SQL commands to the SQLite database through the vulnerable idappartamenti parameter.

- [https://github.com/AK-blank/CVE-2021-37832](https://github.com/AK-blank/CVE-2021-37832) :  ![starts](https://img.shields.io/github/stars/AK-blank/CVE-2021-37832.svg) ![forks](https://img.shields.io/github/forks/AK-blank/CVE-2021-37832.svg)


## CVE-2021-35616
 Vulnerability in the Oracle Transportation Management product of Oracle Supply Chain (component: UI Infrastructure). The supported version that is affected is 6.4.3. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Transportation Management. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Transportation Management accessible data as well as unauthorized read access to a subset of Oracle Transportation Management accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/Ofirhamam/OracleOTM](https://github.com/Ofirhamam/OracleOTM) :  ![starts](https://img.shields.io/github/stars/Ofirhamam/OracleOTM.svg) ![forks](https://img.shields.io/github/forks/Ofirhamam/OracleOTM.svg)


## CVE-2021-32724
 check-spelling is a github action which provides CI spell checking. In affected versions and for a repository with the [check-spelling action](https://github.com/marketplace/actions/check-spelling) enabled that triggers on `pull_request_target` (or `schedule`), an attacker can send a crafted Pull Request that causes a `GITHUB_TOKEN` to be exposed. With the `GITHUB_TOKEN`, it's possible to push commits to the repository bypassing standard approval processes. Commits to the repository could then steal any/all secrets available to the repository. As a workaround users may can either: [Disable the workflow](https://docs.github.com/en/actions/managing-workflow-runs/disabling-and-enabling-a-workflow) until you've fixed all branches or Set repository to [Allow specific actions](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/disabling-or-limiting-github-actions-for-a-repository#allowing-specific-actions-to-run). check-spelling isn't a verified creator and it certainly won't be anytime soon. You could then explicitly add other actions that your repository uses. Set repository [Workflow permissions](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/disabling-or-limiting-github-actions-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository) to `Read repository contents permission`. Workflows using `check-spelling/check-spelling@main` will get the fix automatically. Workflows using a pinned sha or tagged version will need to change the affected workflows for all repository branches to the latest version. Users can verify who and which Pull Requests have been running the action by looking up the spelling.yml action in the Actions tab of their repositories, e.g., https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml - you can filter PRs by adding ?query=event%3Apull_request_target, e.g., https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml?query=event%3Apull_request_target.

- [https://github.com/MaximeSchlegel/CVE-2021-32724-Target](https://github.com/MaximeSchlegel/CVE-2021-32724-Target) :  ![starts](https://img.shields.io/github/stars/MaximeSchlegel/CVE-2021-32724-Target.svg) ![forks](https://img.shields.io/github/forks/MaximeSchlegel/CVE-2021-32724-Target.svg)
- [https://github.com/JeSuisUnAttaquant/AMUM2-CVE-2021-32724-Target](https://github.com/JeSuisUnAttaquant/AMUM2-CVE-2021-32724-Target) :  ![starts](https://img.shields.io/github/stars/JeSuisUnAttaquant/AMUM2-CVE-2021-32724-Target.svg) ![forks](https://img.shields.io/github/forks/JeSuisUnAttaquant/AMUM2-CVE-2021-32724-Target.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/AmIAHuman/OverlayFS-CVE-2021-3493](https://github.com/AmIAHuman/OverlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/AmIAHuman/OverlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/AmIAHuman/OverlayFS-CVE-2021-3493.svg)
- [https://github.com/Abdennour-py/CVE-2021-3493](https://github.com/Abdennour-py/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Abdennour-py/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Abdennour-py/CVE-2021-3493.svg)

