# CVE-2022-36163
> [Suggested description]
> A format string vulnerability was found in pdftoroff hovacui 1.1.0 pdf
> reader. A user can control the second parameter to sprintf which can
> lead to DoS or Information Disclosure for more attacks.
> `sprintf(command, output->postsave, fileno, fileno);`
>
> ------------------------------------------
>
> [Additional Information]
> This is just a DoS PoC:
> *** %n in writable segment detected ***
> [1]    8518 IOT instruction (core dumped)  python3 exploit.py
>
> ------------------------------------------
>
> [VulnerabilityType Other]
> Format string vulnerability.
>
> ------------------------------------------
>
> [Vendor of Product]
> pdftoroff
>
> ------------------------------------------
>
> [Affected Product Code Base]
> hovacui - 1.1.0
>
> ------------------------------------------
>
> [Affected Component]
> hovacui.c, line: 1572
>
> ------------------------------------------
>
> [Attack Type]
> Local
>
> ------------------------------------------
>
> [Impact Denial of Service]
> true
>
> ------------------------------------------
>
> [Impact Information Disclosure]
> true
>
> ------------------------------------------
>
> [Attack Vectors]
> Create a bogus `postsave` and then open a pdf file, and save it.
>
> ------------------------------------------
>
> [Discoverer]
> Maher Azzouzi
>
> ------------------------------------------
>
> [Reference]
> http://hovacui.com
> http://pdftoroff.com

