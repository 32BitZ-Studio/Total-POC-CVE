# CVE-2021-44906

Originally from: https://github.com/Marynk/JavaScript-vulnerability-detection/blob/main/minimist%20PoC.zip

## Run
```
npm run hack
```
And you will see the any function's done property is changed to true.
The explanation of command line `node index.js --_.concat.constructor.prototype.done true`:
- `--` is the hypen mark normally used in command line arguments.
- `_` is the built in key in minimist: https://github.com/minimistjs/minimist/blob/v1.2.5/index.js#L37
- `.concat.constructor.prototype.done true` will `set _.concat.constructor.prototype.done` to `true`.
Because `_.concat.constructor` is a `Function` type, all `Function`'s prototype will be added by a property called `done`.

The reason why the prototype chain is this long is that in the previous fixes, the developer banned `__proto__`, `Arrary.prototype`, `Object.prototype`, `Number.prototype` and `String.prototype`. So we have to use `constructor` who has prototype property and which is not blacklisted.

Another example is:
```
npm run hack2
```

However, in the above two example, we can only tamper values but not functions' definition.

## Cause
In the fix for CVE-2020-7598 (1.2.2), and in 1.2.3 the developer already fixed some vulnerability by checking `__proto__`, `Arrary.prototype`, `Object.prototype`, `Number.prototype`, `String.prototype`,
but they forgot to check `Function.prototye`. This is why this exploit can only affect the property of `Function`.
For the fix of this CVE, the developer checked the `Function.prototype` as well as `constructor`: https://github.com/minimistjs/minimist/blob/v1.2.6/index.js#L73
