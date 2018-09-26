#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
Small example of how to use the Dex2Call class in python code.
"""

from __future__ import print_function
from dex2call import Extractor

# Run the extraction
for mthd in Extractor("classes.dex").extract():
    print(mthd)
