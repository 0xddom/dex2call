"""
Cli entrypoint for dex2call
"""

import sys
import click
from dex2call import Extractor


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

    methods = Extractor(dexfile, android_only=android_only).extract()
    if output == '-':
        output = sys.stdout
    else:
        output = open(output, 'w')

    for mthd in methods:
        output.write("%s\n" % mthd)
