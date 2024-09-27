---
layout: post
permalink: "From-Sushi-To-Kimsuky"
title: "From Sushi To Kimsuky"
date: 2024-09-27
---

As part of routine research, I was going through Twitter to bookmark some interesting tweets that can potentially be operationalised to build detection content. While doing so, I happened to have come across a [tweet](https://x.com/fmc_nan/status/1819312957651865623) by [fmc_nan](https://x.com/fmc_nan) with a malware sample hash attributed to Kimsuky which is a North Korean APT. 

![image](https://github.com/user-attachments/assets/c9d3384f-9a68-4e4a-8bb6-656160b4b843)


At a first glance neither the tweet nor the underlying file content looked interesting since it did not reveal anything that can be used to create a YARA rule for this malware sample.

As part of the standard research workflow, the file hash _d1f1019fb0f0810a8633bd0ef5a0d7b68ec94c5f09251eccd3e5076c97984377_ was dropped into VirusTotal for further analysis. I decided to log into VirusTotal to use some of the premium features which will be more obvious at a later point. 

The primary goal was to see if there were any crowd sourced YARA rules which were detecting this malware as Kimsuky, but this was not the case. The secondary use case was to simply use the content tab to view the strings of the sample which we will get to later.

Primary analysis shows that this file is an LNK (shortcut file). Typically LNK files are used as first stage to drop/download additional malware.

![image](https://github.com/user-attachments/assets/f23e343b-219b-4e7d-b73d-74d18e99edf0)


From the above, it can be seen that none of the YARA rules are able to identify the file linked to Kimsuky. Also the Community comments failed to do the same.

However, scrolling down the Detection tab on VT, it can be observed that out of 32 AV vendors who flagged this file as malicious, four of them were able to successfully identify the file as Kimsuky which is intriguing since AV vendors tend to attribute files to malware rather than threat actors.

![image](https://github.com/user-attachments/assets/277561bf-7c6d-40c4-9960-9578845251b2)


From there, lets pivot to OSINT sources and the next natural step was to visit Malware Bazaar by Abuse Ch. Our objective is to identify useful samples that have been referenced in threat intel reports to gain external context and gain some meaningful insights that can support hunting. On Malware Bazaar, we can use the search syntax to look for malware samples tagged as Kimsuky. 

By using the search _tag:Kimsuky_, it outputs 220 entries. Do recollect that the original sample was of the file type LNK. By performing a simple CTRL + F search on the results and searching by the term LNK will only give one matched sample _fe156159a26f8b7c140db61dd8b136e1c8103a800748fe9b70a3a3fdf179d3c3_ submitted by [smica83](https://x.com/smica83).  

![image](https://github.com/user-attachments/assets/6ea0a6c8-e15d-4217-8fe9-91d071821140)


Alternatively, we can try to browse for Kimsuky by checking other aliases such as APT43, this _tag:APT43_ search query provided only one result. This sample  _e936445935c4a636614f7113e4121695a5f3e4a6c137b7cdcceb6f629aa957c4_ was submitted by [JAMESWT](https://x.com/JAMESWT_MHT). 

![image](https://github.com/user-attachments/assets/83d3abb9-1da8-41bd-bedb-6afc8e79f61d)

By selecting either of the file samples in Malware Bazaar, again it was reinforced that no YARA signatures are identifying this sample as Kimsuky (at least on Malware Bazaar) with one exception. 

![image](https://github.com/user-attachments/assets/4cbdbe78-260f-4ace-9571-afd305de8add)


Taking either of the file hashes and dropping them on Virus Total and navigating to the Community section shows one interesting reference which is an absolute gold mine. The reference was provided by [Patrickvgr](https://x.com/patricksvgr) and mentions the original source as a [Rapid7 blog](https://www.rapid7.com/blog/post/2024/07/16/defending-against-apts-a-learning-exercise-with-kimsuky/), there is also a link to their detailed [research paper](https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-Kimsukys-Phishing-and-Payload-Tactics_wp.pdf). 

![image](https://github.com/user-attachments/assets/2ce94694-e55a-4b9c-b4b4-bfefe716bc10)

The section of interest in the Rapid7 research paper is the Payloads section with the sub-heading _LNKs everywhere_ (pages 7-10). In the beginning of this section, we immediately see some key attributes which could be used to build a YARA rule. From a technical detail, these attributes are due to the variant of a LNK builder being used to construct the LNK file.

![image](https://github.com/user-attachments/assets/a78b8856-ad65-45f2-8182-df5c322194db)

The second interesting attribute that the research paper mentions is the large blob of space before the PowerShell command as seen in the screenshot below in blue color. 

![image](https://github.com/user-attachments/assets/c450439a-0cb3-405d-a465-4e6a5443765f)


The rest of the LNK section of this research paper shares the different implementations of the PowerShell command being executed in terms of Base64 encoding, embedded payloads and other forms of obfuscation which is irrelevant to the construction of our YARA rule. This is because, all of those variations have the two attributes in common which should not impact the detection.

Going back to VT to view the file content (we can easily download the malware samples and use any strings utility on Windows or Linux) of the original sample, we can indeed find the first attribute in the strings (these are wide/unicode). We can also see the PowerShell command which was the second attribute.

![image](https://github.com/user-attachments/assets/9449de06-6799-440a-aa8a-078a240f232a)

An initial YARA rule could be something like this:

![image](https://github.com/user-attachments/assets/b74b9c23-8cd8-401a-a3a7-19f9f7b7a156)

Breakdown of the YARA:

=> The string identifier lnk is the file header for LNK file types which was identified from [here](https://www.garykessler.net/library/file_sigs.html) (simply CTRL + F and search for the term lnk).

=> Strings str1,2 and 3 together constitute the first attribute that was mentioned in the research paper. 

=> Finally, the string identifier pwrshll is the PowerShell command which is the second attribute.

The above YARA rule is decent and should be able to pick up LNK files used by Kimsuky. However, there is a problem, we are not able to fully satisfy the condition for the second attribute which is to account for the large space right before the PowerShell command.

In order to fix the issue, lets move to the Hex view under the same Content section on VT. I have broken down the Hex view into two parts for easier viewing. 

**Part1:**
![image](https://github.com/user-attachments/assets/65fe1faa-59ee-4523-ac42-66636952e913)

We can clearly see the LNK file header that we had used in the YARA rule, the strings related to the first attribute and their respective offsets. Upon scrolling further down, it is evident that there is indeed a large empty blob before the PowerShell command. Part2 depicts the empty blob of space in the upper half and the identified PowerShell command in the lower half.

**Part2:** 
![image](https://github.com/user-attachments/assets/56926259-a4bc-4bb9-a29b-18cfa1b2502a)

This is where things get both interesting and complex. In order to identify exactly how big this empty blob is between the strings str1,2,3 and the pwrshll string identifiers, we will need to measure the starting addresses of those strings str1 and pwrshell and then subtract them to identify how far are they apart.

To do so, we will require a hex calculator. But before that, we need to convert strings str1,2 and 3 into a combined hex string as seen in part1. We can use [Cyber Chef](https://cyberchef.org/) to do the conversion and verification. 

By pasting the related hex content (see part1) into Cyber Chef, we can validate that the hex content translates to the strings str1, 2 and 3 that were used in the initial YARA rule.

![image](https://github.com/user-attachments/assets/e51f9f0a-d234-4b12-b81f-126e39d728e7)


Heading back to VT to calculate the required starting addresses for the respective strings. In order to achieve this, we need the exact addresses. There are two parts to this, the hexadecimal addresses shown vertically and the horizontal rows at the top. We will require a combination of these to determine the exact address. 

For instance, _str1_ starts with the letter _T_ (which is 54 in hex, if you want to double tap, simply use Cyber Chef and enter the letter _T_ in the input section and use the recipe _To Hex_ to find the corresponding Hex value of _T_).

![image](https://github.com/user-attachments/assets/12fb5763-4e92-4f75-9ff4-32117c7f23cd)


To calculate the address of _T_, first check the vertical addresses on the left and then intersect the address on the top. This provides us with the hexadecimal address for _T_ as **40** + **0E** which is **4E**.

Performing the same process for the string _pwrshll_, we get the hexadecimal address for the character _/_ (which is 2F in hex) as **4D0** + **02** which is **4D2**.    

![image](https://github.com/user-attachments/assets/d316a6e8-3cca-4d29-94d1-b2e79bc120ee)

We can now use a hex calculator to perform subtraction of **4D2** and **04E** which results in **484** in hexadecimal and **1156** in decimal.

![image](https://github.com/user-attachments/assets/d4d3aeaf-958a-42e6-b119-fc234f24ce79)

**Note:** It is critical to keep track of the data types and not confuse hexadecimal with decimal, otherwise the calculations will be inaccurate.

In YARA, the **@** symbol is used to define an address rather than the value of the string. For example, in the YARA rule conditions: @str1 > @str2 means that if _str1_ appears after _str2_, then the condition will be satisfied. This function becomes even more interesting when we combine the support of relative offsets. 

For instance: @str1 > @str2 + 100 

**Note:** In YARA, by default, 100 implies a decimal value. This can be changed to hexadecimal of required by prefixing _0x_ to the value. The equivalent of above would be @str1 > @str2 + 0x64

This means that not only _str1_ should appear after _str2_ but there should be a gap of at least 100 between them. The relational mathematical operator can be switched to _==_ which would imply that we are looking for strings at the exact position as stated in the conditions of the YARA rule. 

Taking the above concepts into consideration, the new and improved YARA rule would be:

![image](https://github.com/user-attachments/assets/97886325-22c1-45e2-a67d-94ac152c0b79)

**IOCs**
d1f1019fb0f0810a8633bd0ef5a0d7b68ec94c5f09251eccd3e5076c97984377
fe156159a26f8b7c140db61dd8b136e1c8103a800748fe9b70a3a3fdf179d3c3
e936445935c4a636614f7113e4121695a5f3e4a6c137b7cdcceb6f629aa957c4

**YARA Rule**
'''
rule LNK_Kimsuky_Aug2024
{
  meta:
    description = "Detects LNK files used by North Korean APT Kimsuky"
    Reference = "https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-Kimsukys-Phishing-and-Payload-Tactics_wp.pdf"
    Filehash1 = "d1f1019fb0f0810a8633bd0ef5a0d7b68ec94c5f09251eccd3e5076c97984377"
    Filehash2 = "e936445935c4a636614f7113e4121695a5f3e4a6c137b7cdcceb6f629aa957c4"
    Filehash3 = "3065b8e4bb91b4229d1cea671e8959da8be2e7482067e1dd03519c882738045e"
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    date = "2024-08-03"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "886535bbe925890a01f49f49f49fee40"
    yarahub_uuid = "b5c30e45-849c-42c2-9e8f-10c8e75e2019"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:RED"

  strings:
    $lnk = {4c	00	00	00	01	14	02	00}

    $hex = {54 00 79	00	70	00	65	00	3a	00	20	00	54	00	65	00	78	00 
          74 00	20	00	44	00	6f	00	63	00	75	00	6d	00	65	00   //Type: Text Document
          6e 00	74	00	0a	00	53	00	69	00	7a	00	65	00	3a	00  // Size: 5.23 KB
          20 00	35	00	2e	00	32	00	33	00	20	00	4b	00	42	00 //  Date modified: 01/02/2020 11:23
          0a 00	44	00	61	00	74	00	65	00	20	00	6d	00	6f	00
          64 00	69	00	66	00	69	00	65	00	64	00	3a	00	20	00
          30 00	31	00	2f	00	30	00	32	00	2f	00	32	00	30	00
          32 00	30	00	20	00	31	00	31	00	3a	00	32	00	33	00}
    
    $pwrshll = "/c powershell" wide

  condition:
    $lnk at 0
    and $hex
    and @pwrshll == @hex + 1156 // Large amount of space added before the actual command 
}  
'''




 



 
 






  







