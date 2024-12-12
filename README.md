# Rootkit LKM

## Description
This project is a **Loadable Kernel Module (LKM)** that functions as a rootkit. It implements the following features:
- **Privilege Escalation**: Grants `root` privileges to a specific process.
- **Hiding**:
  - Makes the module itself invisible in the list of loaded modules.
  - Hides specific files from the filesystem.
- **Protection**: Prevents accidental or intentional removal of the module while it is running.

### Disclaimer ⚠️
This project is for educational purposes only. Any malicious or illegal use of this code is strictly prohibited. Always respect the law.

---

## Features
Detailed information about the features can be found in the `features` folder of the repository. Here is a brief overview of the functional features:

### 1. Privilege Escalation
- Grants `root` privileges to processes named `trigger`.
- To activate this functionality:
  1. Create a bash script named `trigger`:
     ```bash
     echo "#!/bin/bash" > /usr/bin/trigger
     echo "id" >> /usr/bin/trigger
     chmod +x /usr/bin/trigger
     ```
  2. Execute the `trigger` script to escalate privileges:
     ```bash
     /usr/bin/trigger
     ```

### 2. File and Module Hiding
- Hides files with specific names from directory listings.
- Makes the LKM itself invisible in the kernel module list.

### 3. Module Protection
- Protects the module from being unloaded while it is active, ensuring uninterrupted functionality.

### 4. Module Persistence
- Ensures the module remains persistent across reboots, maintaining continuous functionality without manual intervention.

---

## Compilation and Usage

### Prerequisites
- A compatible Linux kernel source tree.
- Kernel development tools and headers installed.

### Build Instructions
1. Modify the `Makefile` to point to your kernel source directory (`KDIR`).
2. Compile the LKM:
   ```bash
   make
   ```
3. Load the module into the kernel:
    ```bash
    sudo insmod rootkit.ko
    ```
4. Unload the module:
    ```bash
    sudo rmmod rootkit.ko
    ```

### Cleaning Up

To clean up build artifacts:
    ```
    make clean
    ```

### Users

User:   Password:
-> root -> password
-> feur -> apagnan


### Authors

    - Victor
    - Mina
    - Marouane
    - Axel

### License

This project is licensed under the GPL. See the LICENSE file for details.
