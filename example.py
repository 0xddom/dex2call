#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

"""
Small example of how to use the Dex2Call class in python2 code.

For a python 3 version, change the import of StringIO to the correct one.
"""

from StringIO import StringIO
from dex2call import Dex2Call

# Store the result in an IO memory buffer
output = StringIO()
d = Dex2Call("classes.dex", output)

# Run the extraction
d.extract()

# Now the result is in StringIO's buffer
for api in output.getvalue().split('\n'):
    print api

output.close()
