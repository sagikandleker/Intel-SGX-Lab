# Intel® Software Guard Extensions (SGX)

## Introduction
Intel Software Security Extensions (SGX) is a set of security-related instruction codes that are built into some modern Intel central processing units (CPUs). They allow user-level as well as operating system code to define private regions of memory, called enclaves, whose contents are protected and unable to be either read or saved by any process outside the enclave itself, including processes running at higher privilege levels. SGX is disabled by default and must be opted in to by the user through their BIOS settings on a supported system.

SGX involves encryption by the CPU of a portion of memory. The enclave is decrypted on the fly only within the CPU itself, and even then, only for code and data running from within the enclave itself.
The processor thus protects the code from being "spied on" or examined by other code. The code and data in the enclave utilise a threat model in which the enclave is trusted but no process outside it (including the operating system itself and any hypervisor), can be trusted and these are all treated as potentially hostile. The enclave contents are unable to be read by any code outside the enclave, other than in its encrypted form.

## 2. Install


# Lab
## 1. Lab Overview


## 2. Lab Environment
In this lab we will use [Intel(R) Software Guard Extensions for Linux](https://github.com/intel/linux-sgx).

## 3. Lab Tasks

### Task 1: Functionality

### Task 2: Enclave

```c
CODE
```
