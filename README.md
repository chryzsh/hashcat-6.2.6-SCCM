## hashcat 6.2.6 fork with support for SCCM hashes (Mode 19850 / 19851)

Fork of [The-Viper-One/hashcat-6.2.6-SCCM](https://github.com/The-Viper-One/hashcat-6.2.6-SCCM) with added support for AES-256 encrypted SCCM task sequence media variables.

### Background

SCCM task sequence media can contain encrypted credentials. See [CRED-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md) for the full attack description.

### Hash modes

| Mode | Description |
|------|-------------|
| 19850 | SCCM CryptDeriveKey AES-128 |
| 19851 | SCCM CryptDeriveKey AES-256 |

### Extracting hashes

Use [cred1py](https://github.com/chryzsh/cred1py) to extract hashes from SCCM task sequence media variable files.

### Usage

Compile from source:

```
make -j$(nproc)
```

Crack AES-128:
```
./hashcat -m 19850 -a 0 hash.txt wordlist.txt
```

Crack AES-256:
```
./hashcat -m 19851 -a 0 hash.txt wordlist.txt
```

### Credits

- [MWR CyberSec](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module) - Original AES-128 hashcat module
- [blurbdust](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module/pull/5) - AES-256 module and kernel updates
- [The-Viper-One](https://github.com/The-Viper-One/hashcat-6.2.6-SCCM) - Original hashcat fork with pre-integrated SCCM support
