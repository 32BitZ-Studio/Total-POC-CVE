# 🚀 metasploit-bailiwicked_domain-fix
**Fix for `undefined method each` in Metasploit’s `bailiwicked_domain.rb` (CVE-2008-1447 DNS cache poisoning module)**  

---

## 🔎 Problem
While testing **CVE-2008-1447** using Metasploit, the original module crashed with:

```
undefined method `each` for an instance of IPAddr (NoMethodError)
```

This happens because the code calls **`.each` on an `IPAddr` object** instead of an array.

---

## 🛠️ Fix
The fix is to **wrap the IP object in an array before iterating**:
line 253

```ruby
Array(rr1.address).each do |ip|
res2 = Net::DNS::Resolver.new(nameservers: [ip.to_s],...
  # original code logic
end
```

✅ This prevents the **NoMethodError** and allows the module to run successfully.  

---

## 📌 Usage
1. **Replace** your original `bailiwicked_domain.rb` with the fixed one in this repo.  
   - Location: `/usr/share/metasploit-framework/modules/auxiliary/spoof/dns/bailiwicked_domain.rb`  
2. **Restart** Metasploit.  
3. **Load and run** the module as usual.  

---

## 📝 Notes
- Tested on Metasploit Framework version: [6.4.69-dev]
- This fix only addresses the IPAddr.each crash — functionality remains the same.

---

## ⚠️ Disclaimer
This module exploits a **known DNS vulnerability (CVE-2008-1447)**.  
👉 Use **only in a controlled lab environment** for **research and educational purposes**.  

---

✨ If this fix helped you, consider giving the repo a ⭐!
