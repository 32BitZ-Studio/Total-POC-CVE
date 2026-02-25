# CVE-2023-36281
PoC of CVE-2023-36281

I referred to [this PoC](https://aisec.today/LangChain-2e6244a313dd46139c5ef28cbcab9e55). Unfortunately, it doesn’t work because the indexes of `subprocess.Popen` are different in each Python environment. However, my PoC code addresses this problem.

## Installation
`$ pip install -r requirements.txt`

## Execution
### 1. Get index of subprocss on your own environment since it could be different for each environment.
#### In
`$ python get_index_of_subprocess.py`

#### Out
```
subprcess.Popen index: 309.
Replace target_index in attack_prompt.json with this value.
```

### 2. Replace target_index in attack_prompt.json with the value you get.

### 3. Exploit
#### In
`$ python exploit.py`

#### Out
```
README.md  attack_prompt.json  get_index_of_subprocess.py  exploit.py  requirements.txt
```
