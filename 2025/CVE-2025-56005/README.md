# Undocumented RCE in PLY yacc – CVE-2025-56005

## Clarification Regarding the Rejection Arguments

This document provides a clarification and technical response to the rejection arguments raised against **CVE-2025-56005**.
Each argument from the rejection repository is addressed individually and supported with technical evidence.

---

## References

**Rejection Repository:**
[https://github.com/tom025/ply_exploit_rejection](https://github.com/tom025/ply_exploit_rejection)

**NVD Entry:**
[https://nvd.nist.gov/vuln/detail/CVE-2025-56005](https://nvd.nist.gov/vuln/detail/CVE-2025-56005)

**Original Proof of Concept:**
[https://github.com/bohmiiidd/Undocumented-RCE-in-PLY](https://github.com/bohmiiidd/Undocumented-RCE-in-PLY)

**MITRE Entry:**
[https://www.cve.org/CVERecord?id=CVE-2025-56005](https://www.cve.org/CVERecord?id=CVE-2025-56005)

---

## Introduction

This document aims to clarify misunderstandings regarding the Proof of Concept (PoC) for **CVE-2025-56005**, which describes an **undocumented unsafe deserialization vulnerability** in PLY (Python Lex-Yacc).

The rejection repository claims that:

* The PoC does not execute successfully.
* The vulnerability does not demonstrate Arbitrary Code Execution (ACE) or CWE-502.

Both claims are addressed below.

---
[Argument 1 ](https://github.com/tom025/ply_exploit_rejection/blob/main/README.md#L5-L30)
```
Argument 1: The Proof of Concept does not complete successfully

In this project, the code from the proof of concept has been copied to main.py.

To run the exploit, ensure that you have installed uv.

Run:

uv sync

This will install ply==3.11 as a project dependency.

Run:

uv run main.py

This will run the proof of concept. This results in the program exiting early with an
AttributeError: 'function' object has no attribute 'input'.
The text VULNERABLE is not written to /tmp/pwned.
This is not a working example of the alleged vulnerability.
```

---

## Argument 1 – Response

First, let’s verify the installed PLY (yacc) version:

<img width="916" height="117" alt="fin" src="https://github.com/user-attachments/assets/cecd8de0-5b17-4513-8ce5-fb90f8b19b5e" />

This confirms that **PLY 3.11** is installed, which matches the affected version specified in both the PoC and the CVE.

### Running the PoC and Achieving Code Execution

The rejection argument incorrectly assumes that **successful parsing is required** to demonstrate exploitation.
This assumption is false.

The vulnerability is triggered during **pickle deserialization**, not during parsing.

Specifically, the vulnerable code exists in `ply/yacc.py` within the `LRTable.read_pickle()` method:

```python
def read_pickle(self, filename):
        try:
            import cPickle as pickle
        except ImportError:
            import pickle

        if not os.path.exists(filename):
            raise ImportError

        in_f = open(filename, 'rb')
        # Vulnerable code starts here
        tabversion = pickle.load(in_f)
        if tabversion != __tabversion__:
            raise VersionError('yacc table file version is out of date')

        
        self.lr_method = pickle.load(in_f)
        signature      = pickle.load(in_f)
        self.lr_action = pickle.load(in_f)
        self.lr_goto   = pickle.load(in_f)
        productions    = pickle.load(in_f)
        # Pickle file is deserialized without validation (code execution achieved)

        self.lr_productions = []
        for p in productions:
            self.lr_productions.append(MiniProduction(*p))

        in_f.close()
        return signature
```

The [PLY PoC](https://github.com/bohmiiidd/Undocumented-RCE-in-PLY) repository explains **how and why the vulnerability is triggered**.
It is well known that `pickle.load()` can execute arbitrary code during deserialization.

Below is the vulnerable method in `ply/yacc.py`:

<img width="699" height="485" alt="Screenshot from 2026-01-28 15-29-44" src="https://github.com/user-attachments/assets/563ca4cd-2a3f-456e-ac25-a1eab7ed720f" />

The PoC code in the [PLY PoC repository](https://github.com/bohmiiidd/Undocumented-RCE-in-PLY) is **valid and functional**, and the execution results confirm this behavior.

<img width="915" height="367" alt="Screenshot from 2026-01-28 15-33-16" src="https://github.com/user-attachments/assets/f102172f-9266-4565-9f78-e91457820f7b" />

Therefore, Code execution achieved and **Argument 1** from the [Rejection Request](https://github.com/tom025/ply_exploit_rejection/tree/main) is incorrect.

---

[Argument 2](https://github.com/tom025/ply_exploit_rejection/blob/main/README.md#L31-L35)

## Argument 2 – Response

```
Argument 2: The proof of concept does not demonstrate Arbitrary Code Execution as claimed.
Referring to the proof of concept code, this does not demonstrate Arbitrary Code Execution,
as there is a single program running and no untrusted data has been passed between processes.
This is not a demonstration of CWE-502 as claimed.
```

### Answer

A **pickle file** contains a serialized Python object.
In simple terms, it stores Python objects so they can be saved to disk and loaded later.

However, **pickle files are not just data — they are instructions**.

Using `pickle.load()` on **untrusted grammar tables**, which may be shared over a network or reused without validation, creates a **stealthy backdoor** that enables **remote code execution**.

To clarify further, when an untrusted pickle file is:

* shared in CI/CD pipelines,
* reused across environments,
* or loaded from a writable or shared location,

and then deserialized **without validation**, it effectively opens the door for attackers to execute arbitrary commands on the system.

This behavior directly matches the definition of
[CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

