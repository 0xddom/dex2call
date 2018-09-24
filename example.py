#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
Small example of how to use the Dex2Call class in python code.
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
