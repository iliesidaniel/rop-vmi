# Detection and mitigation of Return-oriented Programming attacks using Virtual Machine Introspection _(Dissertation thesis)_


## Table of contents

- [Thesis table of contents](#Table)
- [Platform specifications](#Platform)
- [Objectives](#Objectives)
- [Contributions](#Contributions)
- [Required technical knowledge](#Required)
    - [Calling convention](#RequiredCalling)
    - [Windows memory protection constants](#RequiredWindows)
- [Prototype](#Prototype)
    - [Objectives](#PrototypeObjectives)
    - [Hypervisor](#PrototypeHypervisor)
    - [Virtual machine introspection](#PrototypeVirtual)
        - [Windows API hooking](#PrototypeVirtualWindows)
        - [Modification done to VirtualBox](#PrototypeVirtualModification)
        - [Detection mechanism](#PrototypeVirtualDetection)
        - [Mitigation mechanism](#PrototypeVirtualMitigation)
- [Bibliography](#Bibliography)

<a name="Table"></a>
## Thesis table of contents

    Thesis contents

        Chapter 1 Introduction                                                                  1
            1.1 Thesis context . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  1
            1.2 Objectives of the research thesis  . . . . . . . . . . . . . . . . . . . . . .  3
                1.2.1 Objectives . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  3
                1.2.2 Motivation for the chosen objectives . . . . . . . . . . . . . . . . . .  4
                1.2.3 Achieving the objectives . . . . . . . . . . . . . . . . . . . . . . . .  5
            1.3 Proposed defense solution - Short presentation . . . . . . . . . . . . . . . .  5
            1.4 Contributions of the research thesis . . . . . . . . . . . . . . . . . . . . .  7
            1.5 Thesis structure . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  7

        Chapter 2 Bibliographic study                                                           9
            2.1 Thesis domains . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  9
                2.1.1 Return-oriented Programming  . . . . . . . . . . . . . . . . . . . . . .  9
                2.1.2 Virtual machine introspection  . . . . . . . . . . . . . . . . . . . . .  10
            2.2 Relevant papers  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  11
                2.2.1 Relevant papers - Return-oriented Programming  . . . . . . . . . . . . .  12
                2.2.2 Relevant papers - Virtual machine introspection  . . . . . . . . . . . .  14
            2.3 Comparing thesis with literature . . . . . . . . . . . . . . . . . . . . . . .  16

        Chapter 3 Tools used                                                                    17
            3.1 Metasploit Framework . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  17
            3.2 Gadget identification - ROPgadget  . . . . . . . . . . . . . . . . . . . . . .  19
            3.3 Sysinternals Suite . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  19
            3.4 IDA Freeware . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  19
            3.5 Cinebench R20  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  21
            3.6 Geekbench 5  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  21
            3.7 x64dbg . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  22
            3.8 CFF Explorer . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  23

        Chapter 4 Return-oriented Programming attacks                                           24
            4.1 64-bit Windows 10 from the attacker's perspective  . . . . . . . . . . . . . .  24
                4.1.1 x86-64 architecture  . . . . . . . . . . . . . . . . . . . . . . . . . .  24
                4.1.2 Kernel-mode - User-mode  . . . . . . . . . . . . . . . . . . . . . . . .  25
                4.1.3 Interpretation of data from memory . . . . . . . . . . . . . . . . . . .  25
                4.1.4 The stack  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  26
                4.1.5 Return address . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  27
                4.1.6 Calling convention . . . . . . . . . . . . . . . . . . . . . . . . . . .  28
                4.1.7 Windows API  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  29
            4.2 Implement an attack using Return-oriented Programming  . . . . . . . . . . . .  30
                4.2.1 Creating a vulnerable application  . . . . . . . . . . . . . . . . . . .  30
                4.2.2 Gadget identification or . . . . . . . . . . . . . . . . . . . . . . . .  31
                4.2.3 Exploit creation . . . . . . . . . . . . . . . . . . . . . . . . . . . .  33
                4.2.4 Carrying out the attack  . . . . . . . . . . . . . . . . . . . . . . . .  38

        Chapter 5 Creating a set of real world Return-oriented Programming exploits             40
            5.1 General aspects . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 40
            5.2 Identifying exploits - Automated selection  . . . . . . . . . . . . . . . . . . 40
            5.2 Identifying exploits - Manual selection . . . . . . . . . . . . . . . . . . . . 40
            5.4 Exploit set . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42

        Chapter 6 Detection and mitigation of Return-oriented Programming attacks               44
            6.1 Windows 10 from the defender's perspective . . . . . . . . . . . . . . . . . .  44
                6.1.1 No-execute . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  45
                6.1.2 Data Execution Prevention - DEP  . . . . . . . . . . . . . . . . . . . .  45
                6.1.3 Address Space Layout Randomization - ASLR  . . . . . . . . . . . . . . .  45
                6.1.4 Control-flow integrity . . . . . . . . . . . . . . . . . . . . . . . . .  46
                6.1.5 Control Flow Guard - CFG . . . . . . . . . . . . . . . . . . . . . . . .  46
            6.2 Analysis in order to design the defense solution . . . . . . . . . . . . . . .  46
                6.2.1 Execution interception . . . . . . . . . . . . . . . . . . . . . . . . .  47
                6.2.2 Identification of functions of interest  . . . . . . . . . . . . . . . .  48
                6.2.3 Virtual machine introspection  . . . . . . . . . . . . . . . . . . . . .  48
            6.3 Proposed defense solution  . . . . . . . . . . . . . . . . . . . . . . . . . .  50
                6.3.1 Presentation of the proposed defense solution  . . . . . . . . . . . . .  50
                6.3.2 Windows API hooking  . . . . . . . . . . . . . . . . . . . . . . . . . .  53
                6.3.3 Handling of the exits caused by the injected hooks . . . . . . . . . . .  54
                6.3.4 Detection of the Return-oriented Programming attacks . . . . . . . . . .  56
                6.3.5 Mitigation of the Return-oriented Programming attacks  . . . . . . . . .  57
            6.4 Prototype implementation . . . . . . . . . . . . . . . . . . . . . . . . . . .  61
                6.4.1 Choosing a hypervisor  . . . . . . . . . . . . . . . . . . . . . . . . .  61
                6.4.2 Installing and configuring the development and test environment  . . . .  62
                6.4.3 Windows API hooking  . . . . . . . . . . . . . . . . . . . . . . . . . .  64
                6.4.4 Detection of the Return-oriented Programming attacks . . . . . . . . . .  69
                6.4.5 Mitigation of the Return-oriented Programming attacks  . . . . . . . . .  70
                6.4.6 Bridging the semantic gap  . . . . . . . . . . . . . . . . . . . . . . .  70

        Chapter 7 Theoretical and experimental results                                          71
            7.1 Theoretical evaluation of the  proposed defense solution  . . . .  . . . . . .  71
                7.1.1 Effectiveness of attack detection  . . . . . . . . . . . . . . . . . . .  71
                7.1.2 Effectiveness of attack mitigation . . . . . . . . . . . . . . . . . . .  72
            7.2 Prototype's effectiveness in attack detection  . . . . . . . . . . . . . . . .  73
            7.3 Prototype's impact on the monitored virtual machine's performance  . . . . . .  75
                7.3.1 Designing the evaluation process . . . . . . . . . . . . . . . . . . . .  76
                7.3.2 Designing the selection process of the evaluation applications . . . . .  79
                7.3.3 Selection of the benchmark applications  . . . . . . . . . . . . . . . .  83
                7.3.4 Prototype's performance impact . . . . . . . . . . . . . . . . . . . . .  86

        Chapter 8 Conclusions                                                                   90
            8.1 Contributions  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  90
                8.1.1 Analysis . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  90
                8.1.2 Original contributions . . . . . . . . . . . . . . . . . . . . . . . . .  91
            8.2 Analysis of the proposed solution  . . . . . . . . . . . . . . . . . . . . . .  91
                8.2.1 Advantages . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  92
                8.2.2 Disadvantages  . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  92
                8.2.3 Limitations  . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .  93
            8.3 Analysis of the implemented prototype  . . . . . . . . . . . . . . . . . . . .  93
            8.4 Improvements and future work . . . . . . . . . . . . . . . . . . . . . . . . .  94

        Bibliography


<a name="Platform"></a>
## Platform specifications

- **Device type**: PC
- **CPU**: x86-64 that supports VT-x
- **OS**: Windows 10, but can be extended to older versions from the Windows NT family.


<a name="Objectives"></a>
## Objectives

**Main objective**:
- Propose a defense mechanism which has the mission to detect and mitigate cyberattacks which use the Return-oriented Programming technique to exploit stack buffer overflow vulnerabilities.

**Secondary objectives** _- self imposed quality requirements which the proposed defense solution must fulfill_:
- If not impossible, at least a very high degree of difficulty associated with the implementation of a cyberattack that could bypass/disable the security solution.
- Minimal impact on the monitored operating system's performance.
- Minimal changes made to the monitored operating system.
- Compatibility with the software already installed without the need to modify or have prior knowledge about it.


<a name="Contributions"></a>
## Contributions

**Analyses**
- Identified and analyzed the hardware _- x86-64 CPUs -_ and software _- Windows NT operating system family -_ mechanisms that make the existence of stack buffer overflow vulnerability and Return-oriented Programming technique possible.
- Identified and analyzed the hardware _- x86-64 CPUs -_ and software _- Windows NT operating system family -_ mechanisms as well as the ones proposed in the literature that are relevant in designing a defense solution against attacks that use the Return-oriented Programming technique.
- Evaluated the conclusions resulted from the previous analyses to determine which are the best implementation approaches for a defense solution against the Return-oriented Programming exploitation technique.

**Original contributions**
- Created a server application with an intentional stack buffer overflow vulnerability and a benign exploit for it that uses the Return-oriented Programming technique.
- Identified a set of real world exploits which use Return-oriented Programming and target the platform of interest.
- Based on the analyses previously realized, proposed a defense mechanism which can detect and mitigate attacks that use the Return-oriented Programming technique.
- As proof of concept to determine if the proposed solution is feasible or not, a prototype was implemented based on the simplified version of the mechanisms that make up the proposed defense solution.


<a name="Required"></a>
## Required technical knowledge


<a name="RequiredCalling"></a>
### Calling convention

Calling conventions are schemes that specify what are the duties of the caller and the called subroutines.

Under the Windows operating systems the x64 calling convention requires that the first four parameters are passed in order using the `RCX`, `RDX`, `R8` and `R9` registers [48]. Bellow is an example that illustrates a situation that is relevant to our work, for more details regarding this particular calling convention please visit https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention

```C++
BOOL    VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);
```

```NASM
lpAddress => RCX
dwSize => RDX
flNewProtect => R8
lpflOldProtect => R9
```

<a name="RequiredWindows"></a>
### Windows memory protection constants

Under the Windows operating systems each memory page has associated a protection constant [50] which dictates what are the allowed actions for that particular memory page: `PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_EXECUTE` etc.


<a name="Prototype"></a>
## Prototype

<a name="PrototypeObjectives"></a>
### Objectives

Our main goal for implementing the prototype is to demonstrate the feasibility of our proposed defense solution against attacks that use the Return-oriented Programing technique. As a consequence the implementation is just a simplified proof of concept that should not be used in real world.

<a name="PrototypeHypervisor"></a>
### Hypervisor

In order to implement the virtual memory introspection solution we needed a hypervisor and since our goal is to create an academic proof of concept, we decided that the criteria for choosing the hypervisor should focus on the difficulty associated with the development of the virtual machine introspection solution. Bellow is the table in which we scored the evaluated hypervisors:

| Hypervisor | Open source | Hypervisor type | Requires modifications to the host OS's kernel | Final score |
| ------ | ------ | ------ | ------ | ------ |
| Hyper-V | No | 1 | No | 1 |
| KVM | Yes | Hybrid | Yes | 1.5 |
| **VirtualBox** | **Yes** | **2** | **No** | **3** |
| VMware | No | 1 or 2 | No | 2 |
| Xen | Yes | 1 | No | 2 |

As a result we decided to base our prototype on the VirtualBox hypervisor.

<a name="PrototypeVirtual"></a>
### Virtual machine introspection

To better understand how our virtual machine introspection works and what are the modifications done to the VirtualBox hypervisor we will follow the execute path generated by a call to one of the Windows API functions of interest.

| Level at which is executed | What happens | What we did to implement it |
| ------ | ------ | ------ |
| Monitored operating system | A call is made to either `VirtualAlloc` or `VirtualProtect` which triggers the corresponding hook. | Windows API hooking |
| Hypervisor | The hypervisor determines that the `VMExist` was caused because of a call to one of the two functions and calls the virtual machine introspection solution, passing this information. | Modified VirtualBox |
| Virtual machine introspection | The function corresponding to the called Windows API function is called. | Detection mechanism |
| Virtual machine introspection | This part is called only if the previous VMI module determined that an attack is underway and is responsible with terminating it. | Mitigation mechanism |
| Hypervisor | The `VMExit` is resolved and the execution is transfered back to the monitored operating system. | - |
| Monitored operating system | If the call was deemed to be part of an attack the compromised process is terminated, otherwise the execution follows its course as if nothing happened. | - |

<a name="PrototypeVirtualWindows"></a>
#### Windows API hooking

We decided to monitor only two functions of interest from the Windows API, namely **VirtualAlloc** and **VirtualProtect**.

For simplicity the two hooks were manually injected in `kernel32.dll` using a Linux live session and each one of them consists of a custom `VMCALL` that is placed before the corresponding function's `JMP`.

```NASM
; Hook we used for VirtualAlloc.
b898 efbe 890f 01c1

; Instructions disassembled
0:  b8 98 ef be 89          MOV     EAX, 0x89beef98
5:  0f 01 c1                VMCALL
```

***Note** Just inserting the hook will break the operating system, the offset of the `JMP` needs to be updated to account for the 8 byte shift.*

```NASM
; VirtualAlloc function in original kernel32.dll.
...
0x000196a0:     48ff 25f9 ee05 00cc  cccc cccc cccc cccc     H.%.............
...

; VirtualAlloc after the hook is injected.
...
0x000196a0:     b898 efbe 890f 01c1  48ff 25f1 ee05 00cc     ........H.%.....
...
```

<a name="PrototypeVirtualModification"></a>
#### Modification done to VirtualBox

In order of execution the first modification we have done to the VirtualBox source code consists of adding checks to see what is the reason that caused a `VMExit`. This was done to the `hmR0VmxExitVmcall` function located in the `HMVMXR0.cpp` file, which is in the `src/VBox/VMM/VMMR0` directory. Bellow is the simplified code of this function after we modified it.

```C++
HMVMX_EXIT_DECL hmR0VmxExitVmcall(PVMCPUCC pVCpu, PVMXTRANSIENT pVmxTransient)
{
    // ...

    if (EMAreHypercallInstructionsEnabled(pVCpu))
    {
        // ...

        if (pVCpu->cpum.GstCtx.eax == 0x89beef98)           // VMExist caused by a call to VirtualAlloc.
        {
            attack_detection_va(pVCpu, pVmxTransient);

            // ...
        }
        else if (pVCpu->cpum.GstCtx.eax == 0x90beef09)      // VMExist caused by a call to VirtualProtect.
        {
            attack_detection_vp(pVCpu, pVmxTransient);

            // ...
        }
        else
        {
            // ...
        }
    }
    else
        // ...

    // ...
}
```

Given the simplicity and overall small size of the source code required for the virtual machine introspection solution, we decided to implement it inside the same file in order to keep everything as straightforward as possible.

<a name="PrototypeVirtualDetection"></a>
#### Detection mechanism

In our simplified mechanism we consider that an attack is underway if for a memory page that was previously allocated using `VirtualAlloc` with write attributes a request is made by calling `VirtualProtect` to gain execution attributes. If such situation is detected the execution is transfered to the mitigation algorithm. The code bellow handles part of the attack detection mechanism, namely the one that is triggered by any `VirtualProtect` call.

```C++
void attack_detection_vp (
    PVMCPUCC                pVCpu,
    PVMXTRANSIENT           pVmxTransient
)
{
    if (
        PAGE_EXECUTE & pVCpu->cpum.GstCtx.r8
        || PAGE_EXECUTE_READ & pVCpu->cpum.GstCtx.r8
        || PAGE_EXECUTE_READWRITE & pVCpu->cpum.GstCtx.r8
    )
    {
        LogRel(("Requires execution rights!\n"));

        for (uint64_t index = 0; index < virtual_alloc_calls.count; index++)
        {
            if (
                pVCpu->cpum.GstCtx.rcx == virtual_alloc_calls.calls[index].RCX
                && (
                    PAGE_READONLY & virtual_alloc_calls.calls[index].R9
                    || PAGE_READWRITE & virtual_alloc_calls.calls[index].R9
                )
            )
            {
                LogRel(("Attack detected!\n"));

                attack_mitigation (pVCpu);
            }
        }
    }
}
```

<a name="PrototypeVirtualMitigation"></a>
#### Mitigation mechanism

One of the memory protection attributes is `PAGE_NOACCESS`. If a memory page has this attribute then all access to it is disabled and any attempt to *read from*, *write to* or more importantly to us *execute from* will result in an access violation. Using this mechanism in a real world defense application might not be the best option since it relies on the integrity of the monitored operating system.

Given our goals with regards to the prototype we decided to use it as out of the proposed options it's the easiest to implement and it doesn't affect the evaluation of the effectiveness of the proposed solution. Bellow is the prototype's function responsible with the attack mitigation:

```C++
void attack_mitigation (
    PVMCPUCC                pVCpu
)
{
    LogRel(("The new permissions for the compromised region are: PAGE_NOACCESS.\n"));

    pVCpu->cpum.GstCtx.r8 = PAGE_NOACCESS;
}
```

<a name="Bibliography"></a>
## Bibliography

- [1] Central Intelligence Agency. (2020) The World Factbook - Internet users. [Online]. Available: https://www.cia.gov/library/publications/the-world-factbook/fields/204.html
- [2] Europol. (2019) INTERNET ORGANISED CRIME THREAT ASSESSMENT (IOCTA) 2019. [Online]. Available: https://www.europol.europa.eu/activities-services/main-reports/internet-organised-crime-threat-assessment-iocta-2019
- [3] Federal Bureau of Investigation - Internet Crime Complaint Center. (2018) 2018 Internet Crime Report. [Online]. Available: https://pdf.ic3.gov/2018_IC3Report.pdf
- [4] U.S. Department of Homeland Security - National Cybersecurity and Communications Integration Center. (2016) Malware Trends. [Online]. Available: https://www.us-cert.gov/sites/default/files/documents/NCCIC_ICS-CERT_AAL_Malware_Trends_Paper_S508C.pdf
- [5] Serviciul Român de Informații. (2020) Buletin Cyberint, Semestrul 1 - 2020. [Online]. Available: https://www.sri.ro/assets/files/publicatii/buletin-cyber-sem-1-2020.pdf
- [6] European Union Agency for Cybersecurity. (2019) Industry 4.0 - Cybersecurity Challenges and Recommendations. [Online]. Available: https://www.enisa.europa.eu/publications/industry-4-0-cybersecurity-challenges-and-recommendations
- [7] I.-C. Mihai, C. Ciuchi, and G.-M. Petrică, “Provocări actuale în domeniul securității cibernetice-impact și contribuția României în domeniu” Sector 3, București: Institutul European din România, 2018. [Online]. Available: http://ier.gov.ro/wp-content/uploads/2018/10/SPOS-2017_Studiul_4_FINAL.pdf
- [8] W. S., Spitle., Hylender., and B. G., “2018 Verizon Data Breach Investigations Report” 04 2018.
- [9] W3Schools. OS Platform Statistics. [Online]. Available: https://www.w3schools.com/browsers/browsers_os.asp
- [10] StatCounter. Desktop Operating System Market Share Worldwide. [Online]. Available: http://gs.statcounter.com/os-market-share/desktop/worldwide/#monthly-200901-201905
- [11] Stack Overflow. Developers' Primary Operating Systems. [Online]. Available: https://insights.stackoverflow.com/survey/2019#technology-_-developers-primary-operating-systems
- [12] M. Tran, M. Etheridge, T. Bletsch, X. Jiang, V. Freeh, and P. Ning, “On the Expressiveness of Return-into-libc Attacks” in Recent Advances in Intrusion Detection. Berlin, Heidelberg: Springer Berlin Heidelberg, 2011, pp. 121–141.
- [13] H. Shacham, “The Geometry of Innocent Flash on the Bone: Return-into-libc without Function Calls (on the x86)” pp. 552–561, May 2007.
- [14] E. Buchanan, R. Roemer, H. Shacham, and S. Savage, “When Good Instructions Go Bad: Generalizing Return-Oriented Programming to RISC,” January 2008, pp. 27–38.
- [15] T. Kornau, “Return Oriented Programming for the ARM Architecture,” December 2009. [Online]. Available: https://static.googleusercontent.com/media/www.zynamics.com/en//downloads/kornau-tim--diplomarbeit--rop.pdf
- [16] S. Checkoway, L. Davi, A. Dmitrienko, A.-R. Sadeghi, H. Shacham, and M. Winandy, “Return-Oriented Programming without Returns,” January 2010, pp. 559–572.
- [17] R. Roemer, E. Buchanan, H. Shacham, and S. Savage, “Return-Oriented Programming: Systems, Languages, and Applications,”ACM Transactions on Information and System Security - TISSEC, vol. 15, pp. 1–34, March 2012.
- [18] Intel, Control-flow Enforcement Technology Specification. Intel, 2019.
- [19] Symantec. (2012) Rootkits. [Online]. Available: https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/security-response-w32-stuxnet-dossier-11-en.pdf
- [20] N. Falliere, L. O. Murchu, and E. Chien, W32.Stuxnet Dossier,” February 2011. [Online]. Available: https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/rootkits-12-en.pdf
- [21] G. Tal and R. Mendel, “A Virtual Machine Introspection Based Architecture for Intrusion Detection,” NDSS, vol. 3, May 2003.
- [22] L. Litty, H. A. Lagar-Cavilla, and D. Lie, “Hypervisor Support for Identifying Covertly Executing Binaries,” January 2008, pp. 243–258.
- [23] Intel, Intel® 64 and IA-32 Architectures Software Developer’s Manual. Intel, 2019, vol. Combined Volumes 3A, 3B, 3C, and 3D: System Programming Guide.  
- [24] Inc. Advanced Micro Devices, AMD, “AMD Virtualization Codenamed "Pacifica" Technology, Secure Virtual Machine Architecture Reference Manual,” January 2005.
- [25] B. Jain, M. Basim B., D. Zhang, D. Porter, and R. Sion, “SoK: Introspections on Trust and the Semantic Gap,” Proceedings - IEEE Symposium on Security and Privacy, pp. 605–620, November 2014.
- [26] A. More and S. Tapaswi, “Virtual machine introspection: towards bridging the semantic gap,” Journal of Cloud Computing, vol. 3, pp. 1–14, January 2014.
- [27] B. Jain, M. Basim B., D. Zhang, D. Porter, and R. Sion, “Introspections on the Semantic Gap,” Security and Privacy, IEEE, vol. 13, pp. 48–55, March 2015.
- [28] J. Pfoh, C. Schneider, and C. Eckert, “Exploiting the x86 Architecture to Derive Virtual Machine State Information,” August 2010, pp. 166 – 175.
- [29] T. Lengyel, T. Kittel, G. Webster, J. Torrey, and C. Eckert, “Pitfalls of virtual machine introspection on modern hardware,” December 2014.
- [30] A. Lutaș , D. Ticle, and O. Cret, , “Hypervisor based Memory Introspection: Challenges, Problems and Limitations,” January 2017, pp. 285–294.
- [31] K. Onarlioglu, L. Bilge, A. Lanzi, D. Balzarotti, and E. Kirda, “G-Free: defeating return-oriented programming through gadget-less binaries” January 2010, pp. 49–58.
- [32] L. Davi, A.-R. Sadeghi, and M. Winandy, “ROPdefender: A detection tool to defend against return-oriented programming attacks,” January 2011, pp. 40–51.
- [33] M. Polychronakis and A. D. Keromytis, “ROP Payload Detection Using Speculative Code Execution,” October 2011.
- [34] V. Pappas, M. Polychronakis, and D. A. Keromytis, “Transparent ROP exploit mitigation using indirect branch tracing,” August 2013, pp. 447–462.
- [35] B. Stancill, K. Z. Snow, N. Otterness, F. Monrose, L. Davi, and A.-R. Sadeghi, “Check My Profile: Leveraging Static Analysis for Fast and Accurate Detection of ROP Gadgets,” October 2013, pp. 62–81.
- [36] C. Y., Z. Zhou, M. Yu, X. Ding, and H. Deng, R., “ROPecker: A Generic and Practical Approach for Defending Against ROP Attacks,” 2014.
- [37] C. N. and W. D., “ROP is Still Dangerous: Breaking Modern Defensess,” in 23rd USENIX Security Symposium (USENIX Security 14). San Diego, CA: USENIX Association, August 2014, pp. 385–399. [Online]. Available: https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/carlini
- [38] L. Davi, C. Liebchen, A.-R. Sadeghi, K. Z. Snow, and F. Monrose, “Isomeron: Code Randomization Resilient to (Just-In-Time) Return-Oriented Programming,” January 2015.
- [39] X. Li, Z. hu, Y. Fu, P. Chen, M. Zhu, and P. Liu, “ROPNN: Detection of ROP Payloads Using Deep Neural Networks,” July 2018.
- [40] P. Borrello, E. Coppa, D. C. D’Elia, and C. Demetrescu, “The ROP Needle: Hiding Trigger-based Injection Vectors via Code Reuse,” April 2019.
- [41] N. Burow, X. Zhang, and M. Payer, “SoK: Shining Light on Shadow Stacks,” 05 2019, pp. 985–999.
- [42] A. Luțaș , A. Coleșa, S. Lukacs, and D. Luțaș , “U-HIPE: hypervisor-based protection of user-mode processes in Windows,” Journal of Computer Virology and Hacking Techniques, February 2015.
- [43] I. Korkin, “Hypervisor-Based Active Data Protection for Integrity and Confidentiality of Dynamically Allocated Memory in Windows Kernel,” May 2018.
- [44] A. Follner, A. Bartel, H. Peng, Y.-C. Chang, K. Ispoglou, M. Payer, and E. Bodden, “PSHAPE: Automatically Combining Gadgets for Arbitrary Method Execution,” vol. 9871, September 2016, pp. 212–228.
- [45] J. Salwan. Ropgadget. [Online]. Available: https://github.com/JonathanSalwan/ROPgadget
- [46] Hex-Rays. About ida. [Online]. Available: https://www.hex-rays.com/products/ida/
- [47] Intel, Intel® 64 and IA-32 Architectures Software Developer’s Manual. Intel, 2019, vol. 1: Basic Architecture.
- [48] Microsoft. x64 calling convention. [Online]. Available: https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
- [49] ——. x64: Starting out in 64-bit windows systems with visual c++. [Online]. Available: https://docs.microsoft.com/en-us/archive/msdn-magazine/2006/may/x64-starting-out-in-64-bit-windows-systems-with-visual-c
- [50] ——. (2020) Memory protection constants. [Online]. Available: https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants

