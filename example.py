#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
Small example of how to use the Dex2Call class in python code.
"""

from __future__ import print_function
from dex2call import Dex2Call

class ExampleListener(object):
    def on_method(self, mthd):
        print(mthd)

d = Dex2Call("classes.dex", ExampleListener())

# Run the extraction
d.extract()

