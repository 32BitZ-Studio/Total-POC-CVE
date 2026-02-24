# Dual_EC_DRBG Backdoor: Educational Proof-of-Concept

**For Security Professionals | Educational Purposes Only**

---

## ⚠️ Disclaimer

This repository contains an educational demonstration of the **Dual_EC_DRBG** cryptographic backdoor (CVE-2014-8610), a well-documented vulnerability disclosed following the Snowden revelations.

**This is for EDUCATIONAL PURPOSES ONLY:**
- Demonstrates a 10+ year old, deprecated vulnerability
- Uses publicly known parameters and mathematical relationships
- Intended for security training and awareness
- Follows responsible disclosure practices

---

## 📚 What You'll Learn

1. **Historical Context**: How the NSA allegedly backdoored a NIST standard
2. **Mathematical Foundations**: Elliptic curves and the discrete log problem
3. **The Backdoor Mechanism**: Why Q = d·P creates a skeleton key
4. **Live Attack Demo**: State recovery from 32 bytes of observed output
5. **Mitigations**: How to avoid similar vulnerabilities

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ (we recommend using pyenv)
- pip

### Option 1: Using the Launcher Script (Recommended)

```bash
cd dual-ec-drbg

# One command to setup and run
./run.sh
```

This script will:
1. Detect/create pyenv local configuration
2. Create a virtual environment in `venv/`
3. Install all dependencies
4. Launch Jupyter with the notebook

### Option 2: Manual Setup with pyenv

```bash
cd dual-ec-drbg

# Set local Python version with pyenv
pyenv local 3.12.12

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Launch Jupyter
jupyter notebook dual_ec_drbg_backdoor_poc.ipynb
```

### Option 3: System Python (Not Recommended)

```bash
cd dual-ec-drbg
pip install --user -r requirements.txt
jupyter notebook dual_ec_drbg_backdoor_poc.ipynb
```

### Dependencies

- `ecdsa>=0.18.0` - NIST P-256 curve operations
- `jupyter>=1.0.0` - Notebook interface
- `ipython>=7.0.0` - Interactive Python

---

## 📖 Notebook Contents

| Section | Description |
|---------|-------------|
| **1. Historical Context** | Timeline from 1997-2024, key players, Snowden revelations |
| **2. Mathematical Foundations** | Elliptic curves, ECDLP, the backdoor math |
| **3. NIST P-256 Parameters** | Real FIPS 186-4 curve parameters |
| **4. Algorithm Specification** | NIST SP 800-90 DRBG specification |
| **5. Implementation** | Honest vs Backdoored DRBG classes |
| **6. Attack Implementation** | State recovery attack with secret d |
| **7. Live Demonstration** | Juniper-style attack simulation |
| **8. Mitigations** | Lessons learned and best practices |

---

## 🎯 The Attack in a Nutshell

```
Dual_EC_DRBG State Update:    s_{i+1} = φ(s_i · P)
Dual_EC_DRBG Output:          r_i = φ(s_i · Q)     [truncated]

Backdoor Relationship:        Q = d · P

Attack (knowing d):
1. Observe r_i (30+ bytes of output)
2. Reconstruct candidate R where x(R) ≈ r_i  
3. Compute: s_{i+1} = φ(d⁻¹ · R) = φ(s_i · P)
4. Predict ALL future output!

Time Complexity: O(1) - milliseconds on a laptop
Data Required: 32 bytes of observed output
```

---

## 🧪 Running the Demonstration

### Interactive Mode

1. Open the notebook:
   ```bash
   jupyter notebook dual_ec_drbg_backdoor_poc.ipynb
   ```

2. Run cells sequentially (Shift+Enter)

3. Observe:
   - Both honest and backdoored DRBGs produce statistically random output
   - Only the backdoored version is vulnerable to state recovery
   - The attack succeeds in milliseconds

### Command Line (Optional)

Extract and run the Python code:

```bash
# Extract code cells to a Python script
jupyter nbconvert --to script dual_ec_drbg_backdoor_poc.ipynb

# Run the script
python dual_ec_drbg_backdoor_poc.py
```

---

## 📊 Expected Output

```
[=== HONEST Dual_EC_DRBG ===]
[+] DRBG initialized
    Mode: HONEST
    P = (6b17d1f2e12c4247..., 4fe342e2fe1a7f9b...)
    Q = (a53a7f9b2e1c4247..., 7fe342e2fe1a7f9b...)

[=== BACKDOORED Dual_EC_DRBG ===]
[+] DRBG initialized
    Mode: BACKDOORED
    P = (6b17d1f2e12c4247..., 4fe342e2fe1a7f9b...)
    Q = (b23d7c9a3f8e5156..., 9ab456d3c7e2f1a8...)
    Secret d = 0x4f3e2d1c0b9a8f7e...

[=== ATTACK EXECUTION ===]
[+] Observed output: a1b2c3d4e5f6...
[+] Found 2 candidate points on curve
...
[OK] PERFECT MATCH - All future output predicted!
```

---

## 🔍 Key Findings

### Why This Backdoor is Insidious

1. **Statistically Undetectable**: Output passes all randomness tests
2. **Mathematical, Not Code**: No malicious code to detect
3. **Master Key Architecture**: One secret (d) breaks all instances
4. **Low Detection Probability**: Backdoor undetectable without d

### Historical Impact

| Event | Date | Impact |
|-------|------|--------|
| NIST Standardization | 2006 | Dual_EC becomes official |
| RSA BSAFE Default | 2004-2013 | $10M payment to use weak default |
| Snowden Revelations | 2013 | Public awareness |
| Juniper Backdoor | 2015 | Attackers exploited weak Dual_EC |
| NIST Withdrawal | 2014 | Official deprecation |

---

## 🛡️ Mitigations

### Never Use
- ❌ Dual_EC_DRBG (deprecated since 2014)

### Use Instead
- ✅ `/dev/urandom` or `getrandom()` (Linux)
- ✅ `BCryptGenRandom()` (Windows)
- ✅ `CryptoKit` (Apple)
- ✅ Hash_DRBG, HMAC_DRBG, CTR_DRBG (NIST SP 800-90A Rev 1)

### Security Auditing
- Audit dependencies for Dual_EC usage
- Verify RNG sources in critical systems
- Demand verifiable parameter generation

---

## 📚 References

1. [NIST SP 800-90A Rev 1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) - Current DRBG standard (Dual_EC removed)
2. [Shumow & Ferguson 2007](https://rump2007.cr.yp.to/15-shumow.pdf) - Original backdoor warning
3. [Bernstein et al. - Dual EC: A Standardized Back Door](https://projectbullrun.org/dual-ec/documents/dual-ec-20150626.pdf)
4. [Checkoway et al. - Juniper Analysis](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_checkoway.pdf)
5. [Reuters - NSA and RSA](https://www.reuters.com/article/us-usa-security-nsa-rsa-idUSBRE9BJ1C220131220/)

---

## 🤝 Contributing

This is an educational resource. Improvements welcome:
- Additional visualizations
- Extended historical context
- More attack variants

---

## 📜 License

MIT License - See LICENSE file for details.

**Use responsibly and ethically. This code is for educational purposes only.**

---

## 🎓 For Instructors

This notebook is suitable for:
- Cryptography courses
- Security awareness training
- Conference presentations
- CTF challenges

**Recommended presentation time**: 45-60 minutes

---

*Created for educational purposes to understand and prevent cryptographic vulnerabilities.*
