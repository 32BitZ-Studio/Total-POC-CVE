# CVE-2019-16784 POC

This is my POC for the Windows PyInstaller version < 3.6 vulnerability that exists for the `--onefile` option. An attacker could achieve command execution and possible LPE by hijacking a DLL imported by the python interpreter DLL used by the pyinstaller binary. A short explanation of the vulnerability and the exploitation process will follow. My thanks to [Alter Solutions](https://github.com/AlterSolutions) for finding the vulnerability and writing about their finding on [PagedOut #3](https://pagedout.institute/download/PagedOut_003_beta1.pdf) (page 55 on pdf). 

## The Vulnerability

The vulnerability was caused because of a weak creation of a directory used by PyInstaller in the runtime of the executed binary. PyInstaller constructs a _MEI*PIDX* directory in the users temp directory, and puts diferent stuff in it, like the python interpreter dll used to run the python code packed into a PE executable.

The problem with this process was that the directory costructed for NT AUTHORITY\SYSTEM was `C:\Windows\Temp`, which allowed someone to both guess it, and to write inside it. So a DLL hijacking would be possible e.g. when the python interpreter was executed. [Here](https://github.com/pyinstaller/pyinstaller/commit/42a67148b3bdf9211fda8499fdc5b63acdd7e6cc?diff=split&w=0) is the commit fixing the vulnerability. Instead of relying on just some standard API functions for creating the directory, the developers implemented their own function to have more control over the directory creation.

## The Exploitation Process

Since this was my first POC, I'll discuss a couple of problems I encountered along the way.

### Setting Up The Testing Environment

First off, settting up an environment for this POC wasn't particularly difficult, since all you needed was the correct package version. However when I installed it, it would crash

```py
Traceback (most recent call last):
  File "c:\users\ckrielle\appdata\local\programs\python\python38\lib\runpy.py", line 194, in _run_module_as_main
    return _run_code(code, main_globals, None,
...
  File "c:\users\ckrielle\appdata\local\programs\python\python38\lib\site-packages\PyInstaller\building\utils.py", line 653, in <genexpr>
    strip_paths_in_code(const_co, new_filename)
  File "c:\users\ckrielle\appdata\local\programs\python\python38\lib\site-packages\PyInstaller\building\utils.py", line 660, in strip_paths_in_code
    return code_func(co.co_argcount, co.co_kwonlyargcount, co.co_nlocals, co.co_stacksize,
TypeError: an integer is required (got type bytes)
```

After searching for a bit, I saw that my Python version was at fault (I am using 3.8.10). My Python version made it difficult to install any other 3.8.x version, since on install the installer would find my Python38 version and return an error. I also tried builting another 3.8 version, however I couldn't because it needed Visual Studio 2015, while I have 2022. At last, I chose to download Python 3.7.5, which worked perfectly. So I created a virtual environment for the 3.7 version.

I understood that setting up the environment can range from already having it setup, to potentially taking a lot of time to setup right. Even though it's important, it could potentially take from the fun of actually exploiting our target.

### Writing The Exploit

There are two steps to our exploitation process, finding the directory of the PyInstaller packaged process, and writing our exploit DLL there. For the first part, we can find the PID through the standard WINAPI functions (`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`). This worked smoothly. After, we need to find the last number of the _MEI directory. The original exploit suggets using just the `GetFileAttributesA` function, and checking if the status code returned is `FILE_ATTRIBUTE_DIRECTORY`. However this didn't work for me. My solution was to create a file in every directory candidate, and if the file was created succesfully, then the directory existed. For some reason the status returned for the file from `GetFileAttributesA` was `FILE_ATTRIBUTE_ARCHIVE`, so I check for that. Before moving on, the loop while searching the PID is because we want to inject our DLLs when the target process is executed, to have them ready before the loading occurs.

For the DLL, we need to hijack a DLL that the python interpreter (`python37.dll`) imports. To get the DLLs the interpreter imports, we could open the DLL with PE-Bear. One of the imported system DLLs is `version.dll`. So we can create our own DLL, and abuse the search order of the Windows loader by placing it in the temp directory of the PyInstaller packaged process. That way, when it wants to import the DLL, it will import our malicious DLL, rather than the correct one.

![python37.dll Imports](./images/python37_imports.png)

However doing this won't work. The reason is that the import of the function the python interpreter calls from `version.dll` (specifically `VerQueryValueW` from the image) is not resolved. So the program crashes. To solve this issue, we need to do DLL proxying. In short, we configure our malicious DLL to export the functions of the original DLL, and we bring the original DLL renamed, so it can load it and call the function from there. So for our exploit, we will compile a malicious DLL with a `DllMain` which will let us achieve our code execution. We will export all the `version.dll` functions, and copy the original system `version2.dll` and place it in the same directory. That way, `version.dll` can forward the function calls to `version2.dll`. And once we have these DLLs, all we need to do is copy them in the process's directory, and wait to get code execution. For a better [DLL Proxying/Hijacking](https://cihansol.com/blog/index.php/2021/09/14/windows-dll-proxying-hijacking/) explanation, read the linked article.

![Malicious version.dll Exported Functions](./images/python37_imports.png)

Even though in retrospect these steps are all easy and straightforward, it wasn't while developing the POC. Before a while, it took a bit to understand the process of the exploit, and once I started coding I started understanding it more. As for the DLL, I tried to compile it myself the way that it was implied in the Alter Solutions POC repo. They have a separate DLL for code execution, and a different for proxying, which loaded the `payload.dll` at runtime (`DllMain` is called upon loading). ΗHowever I couldn't compile it properly. At the end after reading the above article, I decided to go with the [DLLProxyProject](https://github.com/cihansol/DLLProxyProject) repository, which compiled the DLL I wanted, and can be used generally to produce a DLL for proxying purposes. I tried copying it's `DLLMain.cpp` file and to compile it with the `exports.h` header file. And even though it did run, it produced an error:

```
Fatal Python error: init_sys_streams: can't initialize sys standard streams
OSError: [WinError 6] The handle is invalid

Current thread 0x00002ea8 (most recent call first):
```

This error might be avoided with the `Utils.cpp` file, so I decided to keep that project for my DLL compilation (though it would have been nicer if I did it completely myself).

### Exploiting Our Target

After setting up the environment (used `psexec` to get NT AUTHORITY\SYSTEM shell), I ran the exploit, ran the target binary, and got code execution as admin.

![POC Success](./images/poc_success.png)

## Closing Remarks

This was a very nice experience, and one I'm happy I went through. I really want to produce more POCs for other CVEs, and this was a perfect first target. Reading the description of the vulnerability was interesting, as I understood that the main difficulty of implementing a POC yourself is filling in the blanks for things that the author didn't explain (whether in purpose or not), and just understanding what it is you're reading. It was a simple vulnerability, so I didn't put in a lot of effort into understanding it. In the near future after I do a couple of more,  I'll try and do a POC for a memory corruption vulnerability.