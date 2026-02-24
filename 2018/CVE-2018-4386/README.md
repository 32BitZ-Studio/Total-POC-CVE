# Sleirsgoevy's version of Bad_Hoist (Write-up) | CVE-2018-4386

> [!Note]
> **Background information about the PS4:** <br>
> The PlayStation 4 Console features a custom AMD x86-64 CPU (8 cores), it's Orbis OS is based on FreeBSD (v9.0) with parts of NetBSD as well.
> It also includes a wide variety of additional open source software as well, such as Mono VM, and WebKit. 

## PS4 Internet Browser:
The Internet Browser used by the PS4 is actually built with the Open Sourced WebKit Project. 
This is the open source layout engine which renders web pages in the browsers for iOS, Wii U, 3DS, PS Vita, and the PS4. 

### WebProcess:
The PS4 Internet Browser actually consists of 2 separate processes. 
The one which we hijack for code execution is the WebKit Core Process (which handles parsing HTML and CSS, decoding images, and executing JavaScript for example). 
The other one handle's everything else: displaying graphics, receiving controller input, managing history and bookmarks, etc.

### Heap Allocators
The PS4 WebKit browser employs multiple heap allocators, each serving different components. These are the following:
- FastMalloc is the standard allocator. It is used by many WebKit components
- IsoHeap is used by the DOM engine. Its purpose is to sort each allocation using their types to mitigate UAF vulnerability.
- Garbage Collector is used by the JavaScript engine to allocate JavaScript objects.
- IsoSubspace is also used by the JavaScript engine. Its purpose is the same as IsoHeap but it is used for a few objects.
- Gigacage implements mitigations to prevent out-of-bound read/write on specific objects. As mentioned earlier, it is disabled on the PS4.


## Bad_Hoist

The core of **CVE-2018-4386** is a logic flaw in the **JavaScriptCore (JSC)** engine of WebKit (v605.1.15), which is the version used in PS4 firmware 6.XX. The flaw resides in the `BytecodeGenerator::hoistSloppyModeFunctionIfNecessary` function and involves improper handling of variable hoisting in sloppy mode JavaScript, specifically within `for-in` loops.

**Vulnerable Component (ForInContext)**:
The thing we target primarly, is **ForInContext**. This is an internal structure used by JavaScriptCore to manage the state of a `for-in` loop, tracking the current iteration variable and the set of properties being enumerated.

When a function declaration is hoisted inside a `for-in` loop, the engine should _invalidate_ the associated `ForInContext` object if the iteration variable is overwritten. However, due to the bug, this invalidation does not occur.  This allows the iteration variable to be replaced with an **arbitrary object**. Despite this, the engine continues to treat the variable as a string property name. 

When the `op_get_direct_pname` bytecode handler is later invoked, it uses the iteration variable directly as a string object, without type checking. 

By passing a crafted object instead of a string, leading to a type-confusion, we are able to exploit this in a way that achieves memory corruption, and even useful exploitation primitives such as `addrof`, `fakeobj`, and **Arbitrary Read/Write**.

## WebKit Internals: Structure IDs and Type Confusion
**Structure ID:**  Every object in JavaScriptCore, including internal representations like `WTF::StringImpl`, has a _structure ID_ (or type tag) that tells the engine what kind of object it is and how to interpret its fields.
    
**Type Confusion:** Our exploit abuses the CVE-2018-4386 bug to have a JavaScript object be interpreted as a `StringImpl`. This is the purpose of the `create_impl()` function, which returns a `WTF::StringImpl` Type-confused object, that can then be passed to the `trigger()` function, as the arbitrary object we spoke about earlier in **vulnerability mechanism** part of this writeup.

However, for this to work, the memory layout and the structure ID must be "close enough" to what the engine expects for a real string object.
    
## What does `JSString::toIdentifier()` do internally?
There is a method in the PS4 Internet Browser's WebKIT JavaScriptCore Engine whose name is `JSString::toIdentifier()`. This method **converts a JavaScript string object (`JSString`) into an internal Identifier representation**. 

This Identifier is used throughout the engine to efficiently compare, store, and look up property names, variable names, and other strings that must be quickly and frequently referenced by the JavaScript engine.

It checks that the object is a valid string and that its structure ID matches what the engine expects for a string object. If the string is a rope (a concatenation of strings), it may flatten it before converting. It then either retrieves an existing Identifier for the string or creates a new one if it does not exist. 

This Identifier is then used internally for fast property and variable lookups.

## Workaround for`JSString::toIdentifier()` Checks

When the exploit enters the for-loop that iterates 1024 times, each iteration creates a new type-confused `WTF::StringImpl` object with 32 new **Structure IDs** returned by the `create_impl()` function . When this type-confused object is used and passed to `trigger()` as the arbitrary object, JSC calls `JSString::toIdentifier()` on it.

`JSString::toIdentifier()` checks certain bits in the structure ID to confirm the object is a valid string or can be treated as one. By generating many objects with different layouts and structure IDs, the exploit increases the chances that at least one will have a structure ID that passes the internal checks in `JSString::toIdentifier()`


# Refrences
- [Project Zero: CVE-2018-4386](https://project-zero.issues.chromium.org/issues/42450731)
- [Synacktiv's Publication](https://www.synacktiv.com/en/publications/this-is-for-the-pwners-exploiting-a-webkit-0-day-in-playstation-4.html)
- [Hacking the PS4 (3 Part Series) by CTurt](https://cturt.github.io/ps4.html)
- [Fire30's Original Bad_Hoist](https://github.com/Fire30/Bad_Hoist)
- [Sleirsgoevy's Bad_Hoist version](https://github.com/Sleirsgoevy/Bad_Hoist)
