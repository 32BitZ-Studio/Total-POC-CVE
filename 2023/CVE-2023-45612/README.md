# CVE-2023-45612 Reproduction Steps

### My Versions
- **Java 17**
- **Gradle 8.14.3**
- **Python 3.13.7** (for POC script)

### Steps

```
git clone git@github.com:bbugdigger/ktor-xxe-poc.git
cd ktor-xxe-poc
.\gradlew build
.\gradlew run
```

In new tab with same folder destination run PoC script
```
python .\xxe_poc.py
```
