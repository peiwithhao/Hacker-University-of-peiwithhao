<p align="center">
    <img src="./img/README_logo.png" width="360">
</p>

# Hacker-University-of-peiwithhao

Welcome hackers!
Here is the Hacker University of Peiwithhao(HUP)! :)

## 📚 Table of Contents
- [Background](#background)
- [Project Overview](#project-overview)
- [Repository Structure](#repository-structure)
- [Features](#features)
- [Getting Started](#getting-started)
- [Author](#author)
- [Disclaimer](#disclaimer)

## Background
In the rapidly evolving landscape of technology, the realm of hacking has emerged as a multifaceted discipline that transcends mere illicit activities. It embodies a profound understanding of systems, networks, and the intricate interplay of software and hardware. As we delve into the world of hacking techniques, we uncover a rich tapestry of skills that not only empower individuals to navigate and manipulate digital environments but also foster innovation and security in an increasingly interconnected world.

At its core, hacking is an art form that requires a blend of creativity, analytical thinking, and technical prowess. Ethical hackers, often referred to as "white hat" hackers, leverage their expertise to identify vulnerabilities within systems, thereby fortifying defenses against malicious attacks. This proactive approach is essential in safeguarding sensitive information and maintaining the integrity of digital infrastructures.

The study of hacking techniques encompasses a wide array of methodologies, including penetration testing, social engineering, and cryptography. Each technique serves as a critical tool in the hacker's arsenal, enabling them to assess security measures, exploit weaknesses, and ultimately contribute to the development of robust cybersecurity protocols. Furthermore, the ethical implications of hacking underscore the importance of responsible practices, as the line between ethical and unethical hacking can often blur in the face of technological advancement.

As we embark on this exploration of hacking techniques, we aim to cultivate a comprehensive understanding of the skills and knowledge required to navigate this dynamic field. By fostering a culture of innovation and ethical responsibility, we can empower the next generation of cybersecurity professionals to not only defend against threats but also to drive the evolution of technology in a secure and sustainable manner.

## 🎯 Project Overview
This repository serves as a comprehensive knowledge base and practical demonstration platform for:
- **Linux Kernel Security Research**: Deep dive into kernel-level vulnerabilities and exploitation techniques
- **Rootkit Development**: Educational implementations of kernel rootkits for defensive purposes
- **System Tracing & Analysis**: Various tools and techniques for system behavior monitoring
- **Exploit Development**: Analysis and reproduction of real-world CVEs
- **Security Research**: Papers, notes, and findings from ongoing security research

## 📁 Repository Structure

### 🔴 **exploit/**
Exploitation techniques and CVE analysis
- **CVEs/**: In-depth analysis and exploits for various Linux kernel vulnerabilities
  - CVE-2017-7308: Packet socket use-after-free
  - CVE-2021-22555: Netfilter heap out-of-bounds write
  - CVE-2021-41073: io_uring vulnerability
  - CVE-2022-23222: eBPF verifier vulnerability
  - CVE-2022-2588: Route4 classifier use-after-free
  - CVE-2024-1086: Netfilter nft_fwd_dup vulnerability
- **angr/**: Binary analysis framework usage and examples
- **ctf/**: CTF challenge writeups and solutions
- **fuzz/**: Fuzzing techniques and syzkaller usage

### 🔵 **rootkit/**
Linux kernel rootkit implementations (for educational purposes only)
- Privilege escalation techniques
- System call hooking (syscall table and inline hooks)
- File/directory hiding mechanisms
- Module hiding techniques
- Arbitrary memory read/write capabilities

### 🟢 **trace/**
System tracing and monitoring tools
- **eBPF/**: Extended Berkeley Packet Filter programs and applications
- **LLVM_TRACE/**: LLVM-based tracing techniques
- **LSM/**: Linux Security Modules exploration
- **audit/**: Linux audit subsystem usage
- **perf/**: Performance analysis tools

### 🟡 **system/**
System-level topics and implementations
- Container technologies (Docker, Kubernetes, OpenStack)
- Virtualization (QEMU, KVM)
- Network subsystem
- I/O systems (io_uring, FUSE)
- Memory management

### 📄 **paper/**
Research papers and reading notes
- Rootkit analysis papers
- Honeypot concealment techniques
- Regular paper reading notes

### 🔧 **build/**
Kernel and filesystem build environments
- buildroot configurations
- busybox filesystem setups

## ✨ Features

### 🎓 **Learning Resources**
- Detailed READMEs for each topic with code examples
- Step-by-step vulnerability analysis
- Practical implementations with explanations
- Research paper summaries and insights

### 🛠️ **Practical Tools**
- Working exploit code for educational analysis
- Rootkit implementations demonstrating various techniques
- eBPF monitoring applications
- Build environments for kernel development

### 📖 **Documentation**
- Comprehensive guides on kernel exploitation
- System architecture deep dives
- Security mechanism analysis
- Best practices for defensive security

## 🚀 Getting Started

### Prerequisites
- Linux environment (preferably Arch Linux based on the guide)
- Basic understanding of C programming
- Familiarity with Linux kernel concepts
- GDB and debugging tools

### Exploring the Repository
1. **For CVE Analysis**: Navigate to `exploit/CVEs/` and choose a CVE to study
2. **For Rootkit Learning**: Check `rootkit/README.md` for detailed explanations
3. **For Tracing**: Explore `trace/eBPF/` for practical eBPF examples
4. **For System Topics**: Visit `system/` for various subsystem studies

### Building and Testing
Each subdirectory contains specific build instructions. Generally:
```bash
# For exploit examples
cd exploit/CVEs/<cve-name>
make

# For rootkit modules (Linux 6.3.4)
cd rootkit/<module-name>
make

# For eBPF programs
cd trace/eBPF/<program-name>
make
```

## 👤 Author
+ [Peiwithhao](https://github.com/peiwithhao)

## ⚠️ Disclaimer
**IMPORTANT**: All content in this repository is provided **for educational and research purposes only**. The techniques and tools demonstrated here are intended to:
- Help security professionals understand attack vectors
- Improve defensive security measures
- Advance cybersecurity research and education

**Do NOT**:
- Use these techniques on systems you don't own or have explicit permission to test
- Deploy rootkits or exploits in production environments
- Engage in any illegal activities

The author assumes no liability for any misuse of the information provided. Always ensure you have proper authorization before conducting security testing.

---

<p align="center">
    <i>🔒 Security through education • 🛡️ Defense through understanding</i>
</p>
