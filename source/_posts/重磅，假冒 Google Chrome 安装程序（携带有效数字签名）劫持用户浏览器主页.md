---
title: 重磅，假冒 Google Chrome 安装程序（携带有效数字签名）劫持用户浏览器主页
date: 2023-05-27 12:00:00
tags:
---

# 重磅，假冒 Google Chrome 安装程序（携带有效数字签名）劫持用户浏览器主页

## 一、背景

近日，在进行日常样本捕获过程当中发现一假冒的 Google Chrome 安装程序，携带“上海都点网络科技有限公司”有效数字签名，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120731kxm3ugslwdad3fuu.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120743d10j004mya027av5.png)

该样本来源于某假冒 Google Chrome 下载的恶意网站（chrome[.]jshkck[.]cn），该网站为了躲避安全分析研究人员的分析，其加载的加密 js r.js 会使得浏览器的 F12 审查元素无法正常工作，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120758sb36mm3sxmk43w3z.png)

并且发现，如果将 r.js 进行阻断，或使用查看网页源代码的方式查看下载 URL，得到的下载 URL 与直接下载得到的URL与文件名称并不相符，如下图所示（左图正常访问下载，中图阻断干扰调试的 r.js 进行下载，右图为网页源代码）：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120835hb4zss2wp6pzkzs3.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120840ceoz3tleod0sm8cu.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120844s7sbg277707s72v7.png)

可以显而易见地看到，只有正常下载时才会下载得到带有数字文件名称的恶意安装程序

并且在无 cookies 的情况下，该链接无法被访问，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120859dopbmu1a8mgj44eo.jpg)

同时还发现每次下载时该链接与下载文件名称当中的数字不一定会相同，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120915o9pilgkn5kylk9l9.png)

测试时环境下三次下载得到的文件 Hash 值，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120926i55ooeni5blv7d5n.png)

我们发现该网站被收录于 Bing 必应搜索当中，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/120940g4d548hqspn85o8s.png)


## 二、样本行为

运行样本后，程序会使用恶意拓展锁定 Microsoft edge 与 Google Chrome 的浏览器主页、新标签页和搜索跳转页面，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121010re1eixynlpe01nng.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121015abyj6jjk3zko6jdw.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121019likrrybjbo9busuj.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121041bx8q5rzqg5q8rqz6.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121046avc6m6mwhvfc66ue.png)

恶意拓展相关信息，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121113r85v8dgdfd0x0knd.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121119zku2442kzbv6s6b2.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121129ft8dss7t2yg7982a.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121134blk3ljby3ntl3t87.png)

恶意拓展相关代码，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121156tdvff7ftiqhlxv73.png)

恶意程序释放恶意拓展与恶意模块部分过程，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121222bqomdesja0r6mmua.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121228yb4wy9dhdm3m3lyp.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121233kllxvxkavyynn7yx.png)

该样本还存在复制cmd.exe执行行为的行为，尚不清楚作用是什么，存在较高的安全风险与安全隐患，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121250kuhkbdb7bz9ernwu.jpg)

样本检出率仅 1 家，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121307st7t6aecrvqrywzv.png)

我们发现了多个同源样本，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121321cerp9rb2br1i9ttx.jpeg)

** 该家族样本使用多个恶意拓展与恶意模块，其网站对调试器进行干扰与欺骗，强制锁定用户浏览器主页、标签页、搜索结果页，用户很难手动改回，且对用户的其他浏览器进行同样的操作，已严重越界，手法与木马病毒无异。 **

## 三、搜索引擎随机取样
既然该网站收录于 Bing 必应搜索引擎，我们在该搜索引擎当中随机取样。当搜索“谷歌浏览器”为关键词时，页面顶端出现了许多广告，我们取其中某个广告（bb[.]yiliwl[.]top）与在广告下面的第一个搜索结果对象（chrome[.]xahuapu[.]net）进行下载，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121345nkay3z3llin3ubu9.png)

这两个网站域名下载得到的文件 Hash 完全一致

样本文件数字签名，厦门腾瑞科技有限公司，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121403mr21wj222v0orrj9.png)

其安装完成后的 Chromium 内核浏览器（非 Google Chrome）同样被捆绑了主页、书签和广告图标，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121429qjh5ukkunuww1gwk.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121434dataz9ccudosauus.png)
![](https://bbs.huorong.cn/data/attachment/forum/202305/27/121439cp6obk2v6mo26xz7.png)

不过可以肯定的是，该样本首页和标签用户可以手动修改回来，且并未使用恶意拓展的方式，不会涉及用户的其他浏览器。

## 四、总结
浏览器已离不开我们的生活，许多用户喜欢去各大搜索引擎下载浏览器，下载时用户务必要擦亮眼睛，避免造成不必要的麻烦，给他人暗刷广告流量。
