TRINCI Blockchain Core
======================

A lightweight and flexible framework to build your tailored blockchain applications.

## Requirements

The required dependencies to build correctly the project are the following:

- clang
- libclang-dev (ver. 11 suggested)

follow the installations for the most common Unix/Linux systems 

### Ubuntu/Debian installation

update the package list:

```
sudo apt-get update
```

install the dependencies:

```
sudo apt-get install clang libclang-dev
```

### Fedora/RHEL installation

update the package list:

```
sudo dnf check-update
```

install the dependencies:
```
sudo dnf install clang rust-clang-sys+clang_11_0-devel
```

### TPM2 module requirements

in case of the optional feature for the TPM2 module is enabled, the following dependencies are needed:

- libtss2-dev

#### Ubintu/Debian installation


install the dependencies:
```
sudo apt-get install libtss2-dev
```

### Fedora/RHEL installation

install the dependencies:
```
sudo dnf install tpm2-tss
```

## Build

to build the cargo package:

```
cd ./trinci-core
cargo build
```

References
----------

[Link to lightpaper](https://github.com/affidaty-blockchain/whitepaper) 
