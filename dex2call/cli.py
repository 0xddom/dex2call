"""
Cli entrypoint for dex2call
"""

import sys
import click
from dex2call import Dex2Call


class CliOutput(object):
    """
    Class that implements the listener interface that Dex2Call requires.
    """

    def __init__(self, output):
         if output == '-':
             self.output = sys.stdout
         else:
             self.output = open(output, 'w')

    def on_method(self, mthd):
        """
        Called by Dex2Call each time it finds a method that 
        needs to be logged in.
        """
        self.output.write("%s\n" % mthd)
             

@click.command()
@click.argument('dexfile', default='classes.dex',
                type=click.Path(exists=True),
                metavar="<dex or apk>")
@click.option('-o', '--output', default='-',
              help="Location where to dump the results. Default stdout (-)",
              metavar="<file>")
@click.option('--android-only/--all-methods', default=True,
              help="Set to true to remove any method call " +
              "that doesn't point to an android method")
def cli(dexfile, output, android_only):
    """
    This script reads the bytecode of a dex file or an apk file and yields
    the API calls made by the developer code. By default only shows the API
    calls made to android.jar.

    The script by default looks for ./classes.dex.
    """
   
    Dex2Call(dexfile, CliOutput(output), android_only).extract()
        
