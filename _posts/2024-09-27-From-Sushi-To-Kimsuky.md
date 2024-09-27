As part of routine research, I was going through Twitter to bookmark some interesting tweets that can potentially be operationalised to build detection content. While doing so, I happened to have come across a [tweet](https://x.com/fmc_nan/status/1819312957651865623) with a malware sample hash attributed to Kimsuky which is a North Korean APT. 

![image.png](/.attachments/image-97e31679-8edd-4fe0-94ad-efc888ccfb11.png)

At a first glance neither the tweet nor the underlying file content looked interesting since it did not reveal anything that can be used to create a YARA rule for this malware sample.

As part of the standard research workflow, the file hash _d1f1019fb0f0810a8633bd0ef5a0d7b68ec94c5f09251eccd3e5076c97984377_ was dropped into VirusTotal for further analysis. I decided to log into VirusTotal to use some of the premium features which will be more obvious at a later point. 

The primary goal was to see if there were any crowd sourced YARA rules which were detecting this malware as Kimsuky, but this was not the case. The secondary use case was to simply use the content tab to view the strings of the sample which we will get to later.

Primary analysis shows that this file is an LNK (shortcut file). Typically LNK files are used as first stage to drop/download additional malware.

![image.png](/.attachments/image-23c2d435-6a97-4a64-9748-047d83acccc0.png)

From the above, it can be seen that none of the YARA rules are able to identify the file linked to Kimsuky. Also the Community comments failed to do the same.

However, scrolling down the Detection tab on VT, it can be observed that out of 32 AV vendors who flagged this file as malicious, four of them were able to successfully identify the file as Kimsuky which is intriguing since AV vendors tend to attribute files to malware rather than threat actors.

![image.png](/.attachments/image-e4b45e87-0950-49f3-ae8f-5ab35403f4fc.png)

From there, lets pivot to OSINT sources and the next natural step was to visit Malware Bazaar by Abuse Ch. Our objective is to identify useful samples that have been referenced in threat intel reports to gain external context and gain some meaningful insights that can support hunting. On Malware Bazaar, we can use the search syntax to look for malware samples tagged as Kimsuky. 

By using the search _tag:Kimsuky_, it outputs 220 entries. Do recollect that the original sample was of the file type LNK. By performing a simple CTRL + F search on the results and searching by the term LNK will only give one matched sample _fe156159a26f8b7c140db61dd8b136e1c8103a800748fe9b70a3a3fdf179d3c3_ submitted by [smica83](https://x.com/smica83).  

![image.png](/.attachments/image-eecbce68-d54c-4a87-9ece-2d9b97a4699c.png)

Alternatively, we can try to browse for Kimsuky by checking other aliases such as APT43, this _tag:APT43_ search query provided only one result. This sample  _e936445935c4a636614f7113e4121695a5f3e4a6c137b7cdcceb6f629aa957c4_ was submitted by [JAMESWT](https://x.com/JAMESWT_MHT). 

![image.png](/.attachments/image-37ba582f-3bf8-4cf0-8c6c-cc675ae31aad.png)

By selecting either of the file samples in Malware Bazaar, again it was reinforced that no YARA signatures are identifying this sample as Kimsuky (at least on Malware Bazaar) with one exception. 

![image.png](/.attachments/image-81b6f1ef-9424-4475-be5a-fc5aa47e3b2c.png)

Taking either of the file hashes and dropping them on Virus Total and navigating to the Community section shows one interesting reference which is an absolute gold mine. The reference was provided by [Patrickvgr](https://x.com/patricksvgr) and mentions the original source as a [Rapid7 blog](https://www.rapid7.com/blog/post/2024/07/16/defending-against-apts-a-learning-exercise-with-kimsuky/), there is also a link to their detailed [research paper](https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-Kimsukys-Phishing-and-Payload-Tactics_wp.pdf). 

![image.png](/.attachments/image-f6a7fefe-8641-42df-b65a-f82f8cde64d5.png) 

The section of interest in the Rapid7 research paper is the Payloads section with the sub-heading _LNKs everywhere_ (pages 7-10). In the beginning of this section, we immediately see some key attributes which could be used to build a YARA rule. From a technical detail, these attributes are due to the variant of a LNK builder being used to construct the LNK file.

![image.png](/.attachments/image-b6e734b5-ce02-42bb-a704-8356554b21ae.png)

The second interesting attribute that the research paper mentions is the large blob of space before the PowerShell command as seen in the screenshot below in blue color. 

![image.png](/.attachments/image-8e2a6952-13e1-4a66-b162-affe75403d9a.png)

The rest of the LNK section of this research paper shares the different implementations of the PowerShell command being executed in terms of Base64 encoding, embedded payloads and other forms of obfuscation which is irrelevant to the construction of our YARA rule. This is because, all of those variations have the two attributes in common which should not impact the detection.

Going back to VT to view the file content (we can easily download the malware samples and use any strings utility on Windows or Linux) of the original sample, we can indeed find the first attribute in the strings (these are wide/unicode). We can also see the PowerShell command which was the second attribute.

![image.png](/.attachments/image-80a99b5b-be56-4f3e-ac0a-d3fafdf0ff84.png)

An initial YARA rule could be something like this:

![image.png](/.attachments/image-3b722a87-af8b-40cc-a93d-2c69da730cd2.png)

Breakdown of the YARA:

=> The string identifier lnk is the file header for LNK file types which was identified from [here](https://www.garykessler.net/library/file_sigs.html) (simply CTRL + F and search for the term lnk).

=> Strings str1,2 and 3 together constitute the first attribute that was mentioned in the research paper. 

=> Finally, the string identifier pwrshll is the PowerShell command which is the second attribute.

The above YARA rule is decent and should be able to pick up LNK files used by Kimsuky. However, there is a problem, we are not able to fully satisfy the condition for the second attribute which is to account for the large space right before the PowerShell command.

In order to fix the issue, lets move to the Hex view under the same Content section on VT. I have broken down the Hex view into two parts for easier viewing. 

**Part1:**
![image.png](/.attachments/image-76f11336-ece9-4413-8996-69adc1ac4246.png)

We can clearly see the LNK file header that we had used in the YARA rule, the strings related to the first attribute and their respective offsets. Upon scrolling further down, it is evident that there is indeed a large empty blob before the PowerShell command. Part2 depicts the empty blob of space in the upper half and the identified PowerShell command in the lower half.

**Part2:** 
![image.png](/.attachments/image-a603b1e2-817e-470b-a97f-9ef6f9e89de9.png)



This is where things get both interesting and complex. In order to identify exactly how big this empty blob is between the strings str1,2,3 and the pwrshll string identifiers, we will need to measure the starting addresses of those strings str1 and pwrshell and then subtract them to identify how far are they apart.

To do so, we will require a hex calculator. But before that, we need to convert strings str1,2 and 3 into a combined hex string as seen in part1. We can use [Cyber Chef](https://cyberchef.org/) to do the conversion and verification. 

By pasting the related hex content (see part1) into Cyber Chef, we can validate that the hex content translates to the strings str1, 2 and 3 that were used in the initial YARA rule.

![image.png](/.attachments/image-e8d503e0-ee96-4eb8-91ae-9794bbcebeab.png)

Heading back to VT to calculate the required starting addresses for the respective strings. In order to achieve this, we need the exact addresses. There are two parts to this, the hexadecimal addresses shown vertically and the horizontal rows at the top. We will require a combination of these to determine the exact address. 

For instance, _str1_ starts with the letter _T_ (which is 54 in hex, if you want to double tap, simply use Cyber Chef and enter the letter _T_ in the input section and use the recipe _To Hex_ to find the corresponding Hex value of _T_).

![image.png](/.attachments/image-f753f686-203e-49fb-8d10-597e00e52e55.png)

To calculate the address of _T_, first check the vertical addresses on the left and then intersect the address on the top. This provides us with the hexadecimal address for _T_ as **40** + **0E** which is **4E**.

Performing the same process for the string _pwrshll_, we get the hexadecimal address for the character _/_ (which is 2F in hex) as **4D0** + **02** which is **4D2**.    

![image.png](/.attachments/image-3b9a90ac-3f29-4184-9898-937d643cab80.png)

We can now use a hex calculator to perform subtraction of **4D2** and **04E** which results in **484** in hexadecimal and **1156** in decimal.

![image.png](/.attachments/image-744cb490-fc6e-40b0-8d43-7c184a203078.png)

**Note:** It is critical to keep track of the data types and not confuse hexadecimal with decimal, otherwise the calculations will be inaccurate.

In YARA, the **@** symbol is used to define an address rather than the value of the string. For example, in the YARA rule conditions: @str1 > @str2 means that if _str1_ appears after _str2_, then the condition will be satisfied. This function becomes even more interesting when we combine the support of relative offsets. 

For instance: @str1 > @str2 + 100 

**Note:** In YARA, by default, 100 implies a decimal value. This can be changed to hexadecimal of required by prefixing _0x_ to the value. The equivalent of above would be @str1 > @str2 + 0x64

This means that not only _str1_ should appear after _str2_ but there should be a gap of at least 100 between them. The relational mathematical operator can be switched to _==_ which would imply that we are looking for strings at the exact position as stated in the conditions of the YARA rule. 

Taking the above concepts into consideration, the new and improved YARA rule would be:

![image.png](/.attachments/image-306809d3-eb2f-4175-aa58-68c8370e5fcd.png)






 



 
 






  







