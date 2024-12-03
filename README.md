# Project Name

Assignment 3.2 for Computer Securtiy taught by Justin Cappos

## Table of Contents

- [About](#about)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Steps](#steps)

---

## About

Exploring quantum-resistant digital signatures using SPHINCS+ from the
Open Quantum Safe (OQS) for securing Retail and E-Commerce.

---

## Features

- Quantum Resistent Signatures using SPHINCS+
  - Ensures integrity of order details
  - Ensures anti-tampering of order details
  - Ensuring authenticity of transactions, ensuring they originate from legitimate sources 
- Encrypted Order Details to ensure
  - Ensures confindentialty of order details espically pesonally identifable information so only authorized users can see the details

---

## Prerequisites

- Copied form [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) repo of Open Quantum Safe
  - [liboqs](https://github.com/open-quantum-safe/liboqs)
  - [git](https://git-scm.com/)
  - [CMake](https://cmake.org/)
  - C compiler,
    e.g., [gcc](https://gcc.gnu.org/), [clang](https://clang.llvm.org),
    [MSVC](https://visualstudio.microsoft.com/vs/) etc.
  - [Python 3](https://www.python.org/)

### Steps

1. Install Prerequisites and follow steps form [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)

2. Within the same python virtual envorinment, run:
   ```bash
   pip3 install cryptography
3. Ensure virtual enviornment where liboqs and cryptography are installed is active
4. To execute program, run
   ```bash
   python3 crackpit.py

