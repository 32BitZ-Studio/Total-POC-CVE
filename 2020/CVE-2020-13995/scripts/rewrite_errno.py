#!/usr/bin/env python3
import lief

binary = lief.parse('extract75')

stdin = next(filter(lambda e:e.name == "stdin", binary.symbols))
errno = next(filter(lambda e:e.name == "errno", binary.symbols))

errno.name = stdin.name

binary.write("extract75-patched")
