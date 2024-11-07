---
title: "The GREM Reaper - Review of the SANS FOR610 Course"
permalink: "The GREM Reaper"
date: 2024-11-07
---

![image](https://github.com/user-attachments/assets/5bd550c8-9167-4dc0-8bf5-d344b9e8b8a5)

# **Recap**
Recently, I passed the GIAC GREM exam with 96%. I wanted to take the opportunity to review the course content and also compare it with some of the previous courses that I had undertaken. I will also share open-source materials that will support the training content. The objective is to help viewers better navigate the course selection process and also structure their learning path to ensure that prerequisites are met.

![image](https://github.com/user-attachments/assets/64eae213-a5fb-4509-8d9f-fbc6d2bfd609)


This was my first SANS course which I had taken in-person in London which was delivered by [Xavier Mertens](https://x.com/xme) . My malware analysis journey began almost a year and half ago when I first started reading about it and went through some other training in the process. The sequence of my training courses is as follows:

=> Kaspersky Reverse Engineering 101
=> Kaspersky Targeted Malware Reverse Engineering 
=> TCM Practical Malware Analysis & Triage (PMAT)
=> SANS GREM  

Another important distinction that I would like to highlight is the difference between Malware Analysis and Reverse Engineering as this would mean different things to different individuals:

Here is what I think and will use for this blog to be consistent. Malware analysis would be limited to static and dynamic analysis of the malware specimen which includes manual inspection of the properties of the malware using tools such as PE Studio and also detonating the malware sample in your lab environment to observe its behavior. I would also place any usage of external sandbox services and emulation under malware analysis. 

On the other hand, reverse engineering is the deeper examination of the malware using static code analysis (disassembly including observation of decompiled outputs) and dynamic code analysis (debugging) which typically involves understanding assembly language.

The above is important as the SANS course does not distinguish between the two terms, but I feel that a separation is required to better assess the course content.

![image](https://github.com/user-attachments/assets/21f4bcf8-4753-48b4-b40c-b71cc1bbee79)


# **My Background**
I have been working in the Cyber Threat Intelligence field for almost two years and have been dealing with malware to some extend directly or indirectly but not at the low assembly level. Hence, I am pretty much a noob when it comes to malware analysis. With respect to my field, my objective of learning malware analysis is to uncover additional indicators to enable wider pivoting and trace infection chains to later stages. 

This was important to mention prior to reviewing and comparing the course content as based on your working field, you may have different objectives.

**Note:** The below is review is unbiased and is based my opinion. The only bias that I would like to point out is my selection of courses, these are only the ones that I have taken and nothing outside of those are considered in this review. I have no affiliations with SANS or any other training orgs mentioned below. Also, I will not be disclosing any exam related information, so please do not ask me anything related to that. 


The scoring criteria is based on the following:
+ Course Cost
+ Couse Content Coverage 
+ Content Delivery and Clarity 
+ Course Relevance 

# **About GREM** 
I will not mention everything that the course covers as that is covered in more detail on the official website and reviews by other people. But for those who do not know the GIAC exam, this is the credential that you receive once you pass the exam. The SANS training related to GREM is the FOR610:Reverse-Engineering Malware: Malware Analysis Tools and Techniques. 

The exam can also be taken independently without the training (although, it is not recommended as the real value lies in the training content and delivery). The training is available in many formats (Self-Paced, Live Online and Live-In Person). The below was taken from the GIAC GREM course intro section. 

The GIAC Reverse Engineering Malware (GREM) certification is designed for technologists who protect the organization from malicious code. GREM-certified technologists possess the knowledge and skills to reverse-engineer malicious software (malware) that targets common platforms, such as Microsoft Windows and web browsers. These individuals know how to examine inner-workings of malware in the context of forensic investigations, incident response, and Windows system administration. Become more valuable to your employer and/or customers by highlighting your cutting-edge malware analysis skills through the GREM certification.

## **Key Features:**
*   Build an isolated, controlled laboratory environment for analyzing the code and behavior of malicious programs
*   Employ network and system-monitoring tools to examine how malware interacts with the file system, registry, network, and other processes in a Windows environment
*   Analyze malicious, often obfuscated JavaScript and PowerShell scripts that are often used as part of attack chains
*   Control relevant aspects of the malicious program's behavior through network traffic interception and code patching to perform effective malware analysis
*   Use a disassembler and a debugger to examine the inner workings of malicious Windows executables
*   Bypass a variety of packers and other defensive mechanisms designed by malware authors to misdirect, confuse, and otherwise slow down the analyst
*   Recognize and understand common assembly-level patterns in malicious code, such as code injection, C2 interactions, dropper and downloader techniques, and anti-analysis measures
*   Assess the threat associated with malicious documents, such as PDF and Microsoft Office files
*   Derive Indicators of Compromise (IOCs) from malicious executables to strengthen incident response and threat intelligence efforts.
*   Analyze .NET malware, which is often obfuscated and attempts to evade detection by using reflective code loading.

To read more about GREM and the underlying training please visit:

=> GREM: https://exams.giac.org/CertOverview/13309840/GREM
=> FOR610 Training: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## **My feedback:**
Since this was my first SANS course, I wanted to pick something impactful, relevant to my field and something that can justify the price point and after hearing many positive things from my collogues and other people who had done a bunch of SANS courses, a majority of them said that this was the best SANS course that they had taken so far with the second closest competitor being the GCFA (Digital Forensics & Threat Hunting).

The GAIC GREM sits under the DFIR category and the primary goal of the course is leveraging malware analysis for incident response and other intrusions to quickly understand what the malware capabilities are. Now, for some people (including myself initially), this may seem insufficient but realistically this makes a lot more sense at least in my field. 

Within CTI, we are constantly under tight time constraints and we need to assess ambiguous situations in that time frame. As briefly mentioned before, for me it is about identifying IoCs from samples so that we can push for wider threat hunting and external pivoting. 

## **Pros:**
+ The course focuses on the core concepts and how to apply them regardless of the diversity of the malware samples that you will encounter. This is super critical, as I have always been a firm believer that the conceptual understanding is more important and not just the tools used. This is something that the course excels at. 

+ People push for trainings so that they can get a head start at the concepts they want digest, beyond that it comes down to how you maintain those concepts in your head by applying them in real life scenarios, reading content associated to it or discussing them with people specialising in this field. 

+ The GREM training does exactly that, it brings you up to speed with everything you need to know in order to start exploring malware on your own. This is huge in my opinion as reverse engineering can be quite challenging to you if you are a beginner and it can be overwhelming if you do not have a game plan as there are ample amount of resources to choose from.

T+ he course is very practically hands-on which is exactly how it should be. You can watch all the walkthroughs available online but if you do not practice them on your end, it is pretty much pointless. I do think that the course was very interesting and I genuinely enjoyed the in-person course delivery as well as the self-paced format which was delivered by [Lenny Zeltser](https://x.com/lennyzeltser).

My favorite section was the malware analysis of initial access documents as this is something that a lot of courses out there do not offer in depth.

## **Cons:**
- The price point, while all SANS courses more or less cost the same, they can create a serious hole in your pocket if you pay for it on your own. In my case, my employer had provided my this valuable opportunity. You can watch out for their work study programs or take a look at SANS Edu which offer courses at a reduced cost. Considering the course price point, you can easily hand pick multiple custom courses and create a different learning path to suit your requirements. However, do bear in mind that you are essentially paying for the credibility of the GIAC certifications. 

- With respect to the course content, you can use a combination of books and other cheaper training to closely reconstruct what the GREM has to offer. I will reference the 5 days of the training to cover supporting content in those areas in the last section of this blog.

- Expanding on the above, while this SANS course is a level 6 (level 7 being the highest), it is clearly stated in the course description that the course covers everything within it that that there are no actual formal prerequisites. There is a likely misconception considering the Level 6 rating that this course is not for beginners which is not the case, with extra reading and practice, you can ace the exam and navigate through the challenges. This is not really a con but more around the clarity behind the course rating.

- The course does not touch on malware written in Rust or Go. I can see an increase in malware written in these languages which may require different approaches to tackle it. I fully understand that the course cannot cover malware written in all languages, as it is practically impossible to do so. 

## **Tips & Tricks to Score High:**

Wanna score like me in the GREM exam, here is the secret, there is none. I would probably say that understanding the core concepts and the _"why"_ behind the analysis and the methodology covered is key to success, there is no cheat code otherwise. If you can grasp the core concepts and know when to apply them, that will be a huge W. 

Do not study for passing the exam, go beyond that, try to embrace the journey, the result is only a bi-product. There are several involved topics in the course when may require you to revisit, this is particularly true during the day 4 and 5. You will find ample amount of open-source material both within and outside of the course, make sure to leverage it should time allow it.

# **Other Training Courses**
![image](https://github.com/user-attachments/assets/2628858a-fdad-45f7-9e53-3a56cccc1093)


## **Kaspersky Reversing Engineering 101:**

Link to [Course](https://xtraining.kaspersky.com/courses/reverse-engineering-101/)
Cost: $920

### **Key Features:**
*   Gain the initial knowledge needed for malware analysis
*   Understand the main Intel assembly instructions
*   Understand different calling conventions (stdcall, fastcall) and memory types (automatic, dynamic, static)
*   Analyze executables generated by different compilers to become unafraid of more “esoteric” ones
*   Prepare yourself for the next level RE course

Created by [Ivan Kwiatkowski](https://x.com/JusticeRage) and [Dennis Legezo](https://x.com/legezo) This is a pretty good course and is dedicated to reverse engineering and learning to interpret assembly in greater depth. Something worth noting that in this course, during most of the course, you do not directly deal with malware but rather basic programs. This is also a reminder that reverse engineering extends beyond malware.

In my opinion this is the best way of learning reverse engineering and it is because if you start directly looking at malware at the assembly level, you will quickly get hammered and feel lost. Start with simple programs, try compiling them with different optimization options and see how their respective assembly differs. 

### **Cons:**
Because the course is dedicated to looking at assembly, you can feel exhausted time to time. My advice would be to take your own time and not rush the content.

## **Kaspersky Targeted Malware Reverse Engineering:**

Link to [Course](https://xtraining.kaspersky.com/courses/targeted-malware-reverse-engineering/)
Cost: $1400

### **Key Features:**
*   Analyze real-life malware
*   Reverse-engineer malicious documents and exploits
*   Approach reverse engineering programs written in a number of languages and compiled for different architectures
*   Become more familiar with assembly
*   Master advanced features of reverse-engineering tools, understand steganography
*   Handle obfuscated or encrypted content
*   Understand the roundabout ways attackers launch their programs
*   Analyze shellcodes

This is a more serious course and deals with dissecting malware samples used in APT cyber attacks. One thing the course does really well is the coverage of a spectrum of malware samples written in different languages including Rust and Go. The course also succeeds in detailing the different approaches taken towards such malware.

### **Cons:**
The course is not credible and very few people know about it. I would place this course harder when compared to GREM as it purely focuses on code analysis using disassemblers and debuggers. Hence, you will have a hard time if you did not complete their foundational reverse engineering 101 training. 

In terms of relevance and the time taken to really go in the weeds of the internal functioning of such malware samples, it can be determined to be impractical if you work at small to medium sized organisations that do not directly have a dedicated reverse engineer role. 

## **PMAT:** 
Link to [course](https://academy.tcm-sec.com/p/practical-malware-analysis-triage)
Cost: Subscription Based Model

**Key Features:**
1.  **Safety Always!** Build good habits for handling malware safely and create an analysis lab.
2.   **Safe Malware Sourcing**. Learn where to source malware samples safely (no need for the dark web!).
3.   **Basic Analysis.** Learn basic analysis methodology, including interpreting strings, inspecting Windows API calls, identifying packed malware, and discovering host-based signatures. Then, detonate malware to collect network signatures and identify malicious domains and second-stage payloads!
4.   **Intro to the x86 Assembly Language.** Dip your toes into the low-level world of Assembly Language! Learn the foundations of x86 Assembly and use it to perform advanced analysis.
5.   **Advanced Analysis.** Use sophisticated tools like Cutter and x32dbg to discover key insights about malware samples at the lowest possible level. Control the execution flow of a program and manipulate its low-level instructions in a debugger.
6.   **Patch It Out: Binary Patching & Anti-analysis**. Learn the crafty practice of patching binaries at the ASM level to alter the flow of their programs. Then, learn to identify and defeat anti-analysis techniques.
7.   **Gone Phishing.** Learn to analyze malicious documents and document-delivered malware, including malicious macros and remote template injections.
8.   **What the Shell?** Learn to identify and carve out embedded shellcode.
9.   **Off Script.** Identify scripted, obfuscated malware delivery techniques that use PowerShell and Visual Basic Script.
10.   **Stay Sharp.** Decompile and reverse engineer C# assemblies and learn about reverse engineering the .NET Framework! Then, reverse engineer an encrypted malware C2 dropper back to near-perfect original source code with DNSpy!
11.   **Go Time.** Learn the analysis considerations of malware written in Go.
12.   **Get Mobile!** Use MobSF to reverse engineer malicious Android applications.
13.   **The Bossfight!** Use everything you have learned to do a full analysis of one of the most infamous malware samples in history.
14.   **Automating the Process.** Use Jupyter Notebooks and malware sandboxes to automate the analysis process.
15.   **Tell the World!** Write YARA rules to aid in the detection of malware samples and learn how to write effective analysis reports to publish findings.

The course is developed by [Matt Kiely aka Husky Hacks](https://x.com/HuskyHacksMK). This is a good option for malware analysis and reverse engineering especially considering its price point. 

This is the cheapest course in the bunch and is totally worth its price point. It over takes GREM is certain areas such as automation via Jupyter Notebooks (something missing in the FOR610 but covered deeply in FOR710) and YARA (which some of you may know that I am a huge fan of). It even touches on mobile malware!

### **Cons:**
I had a hard time understanding the reverse engineering aspect of it but it is still a solid course if your main goal is rapid triage of malware samples. my struggle was mainly due to the wrong sequence of training. I would suggest to understand assembly first separately and then view the reversing sections of this course.

# **Learning Path**
This might be hard to digest but in my eyes, the GREM can be distributed between the Learning Malware Analysis book and a combination of training courses which can effectively reduce the cost to under a grand or two. But do bear in mind that GREM still has more credibility if that matters to you. I have split the learning path across the five days of GREM training.

**Note:** I have placed the books mentioned under the open-source section, you will need to purchase the books if you plan to use them.

## **Day 1** 

*   Assembling a toolkit for effective malware analysis
*   Examining static properties of suspicious programs
*   Performing behavioral analysis of malicious Windows executables; Performing dynamic code analysis of malicious Windows executables
*   Exploring network interactions of malware in a lab for additional characteristics

### **Course Mapping:** 
PMAT: 1,2 and 3 from the Key Features 

### **Open-Source:**
Learning Malware Analysis Book: Chapters 1,2 and 3.

This YouTube Playlist by [Dr. Josh Stroschein aka The Cyber Yeti](https://x.com/jstrosch) is perfect to cover PE format and properties which is indispensable for static malware analysis.

Link to Playlist: https://www.youtube.com/playlist?list=PLHJns8WZXCdstHnLaxcz-CO74fO4Q88_8

PE 101 Visual: https://github.com/corkami/pics/blob/master/binary/pe101/pe101.pdf

## **Day2** 
*   Understanding core x86 assembly concepts for malicious code analysis
*   Identifying key assembly constructs with a disassembler
*   Following program control flow to understand decision points
*   Recognizing common malware characteristics at the Windows API level
*   Extending assembly knowledge to include x64 code analysis

### **Course Mapping:**
PMAT: 4 and 5 from Key Features

REV-101: Comprehensive Coverage of Assembly

### **Open-Source:**

Learning Malware Analysis Book: Chapter 5.

YouTube Playlist: Intro to Reverse Engineering https://www.youtube.com/playlist?list=PLHJns8WZXCdvaD7-xR7e5FJNW_6H9w-wC

YouTube Playlist: Ghidra https://www.youtube.com/playlist?list=PLHJns8WZXCdu6kPwPpBhA0mfdB4ZuWy6M

## **Day3** 
*   Malicious PDF file analysis
*   The analysis of suspicious websites
*   VBA macros in Microsoft Office documents
*   Examining malicious RTF files
*   Understanding shellcode
*   Deobfuscating malicious JavaScript scripts

### **Course Mapping:**
PMAT: 7,8 and 9 from Key Features (limited)

## **Day4**
*   Recognizing packed Windows malware
*   Getting started with unpacking
*   Using debuggers for dumping packed malware from memory
*   Analyzing multi-technology and "fileless" malware
*   Analyzing .NET malware
*   Code injection techniques

### **Course Mapping:** 
PMAT: 6 and 10 from Key Features

### **Open-Source:**

Learning Malware Analysis Book: Chapters 7,8 and 9.

## **Day5**
*   How malware detects debuggers and protects embedded data
*   Unpacking malicious software that employs process hollowing
*   Bypassing the attempts by malware to detect and evade analysis tools
*   Handling code misdirection techniques, including SEH and TLS callbacks
*   Unpacking malicious executables by anticipating the packer's actions

### **Course Mapping:** 
PMAT: 13 from Key Features (Limited)

### **Open-Source:**

Learning Malware Analysis Book: Chapters 10 and 11.

**Special Mention:** Evasive Malware Book by [Kyle Cucci](https://x.com/d4rksystem), which has super positive reviews from the authors of GREM and Kaspersky courses mentioned above. 

# **End of Line**

All I would like to say to conclude this review is that, do not let the training end our journey, this is the mere beginning and we all are just scratching the surface, continue to maintain and develop your understanding of malware by reading blogs, articles and research papers published by others, try to replicate it on your end or maybe even write a blog of your own to share it with others. 

If you have any suggestions, courses that you have done that could potentially map to the GREM training content or maybe think I missed something, please feel free to let me know [My Twitter Handle](https://x.com/RustyNoob619) :penguin:
