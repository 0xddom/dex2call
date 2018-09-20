#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This script takes an APK file or a DEX file and extracts all the API 
calls made by methods that do not belong to classes in the android package.

By default it removes the calls made to methods that do not belong to the android.jar.
This means that the default behaviour is to get the calls made to android.jar made by
the developer's code.

(c) 2018 Daniel Domínguez <daniel.dominguez@idmea.org>
"""

from __future__ import print_function

import re
import sys
import r2pipe
from itertools import chain
import click
from androguard.core.bytecodes.apk import APK
from tempfile import NamedTemporaryFile

@click.command()
@click.option('-f', default='classes.dex', help="The file that is going to be parsed")
@click.option('-o', default='-', help="Location where to dump the results. Default stdout (-)")
@click.option('--android-only/--all-methods', default=True,
              help="Set to true to remove any method call that doesn't point to a method in android.jar")
class Dex2Call():
    """
    Entry point of the script
    """
    
    def __init__(self, f, o, android_only):
        """
        Inits all the attributes and starts the main routines.
        """
        if o == '-':
            self.out = sys.stdout
        elif type(o) == str:
            self.out = open(o, 'w')
        else:
            self.out = o

        self.is_android_method = re.compile('^.android\/')
        self.is_invocation_opcode = re.compile('^invoke-')
        self.invoke_disasm = re.compile('^invoke-.* \{.*\}, ([^ ]*)( ;.*)?$')

        self.android_only = android_only
        if f.endswith('.dex'):
            self.extract_calls_from_dex(f)
        else:
            self.extract_calls_from_apk(f)

    def extract_calls_from_apk(self, apkfile):
        """
        Extracts the APK using androguard and pass each dex file to the dex extracion routine.
        """
        apk = APK(apkfile)
        for dex in apk.get_all_dex():
            with NamedTemporaryFile(delete=True) as temp:
                temp.write(dex)
                self.extract_calls_from_dex(temp.name)

    def extract_calls_from_dex(self, dexfile):
        """
        Using radare2 as backend extracts the method calls from the Dalvik Bytecode.
        """
        self.r2 = r2pipe.open(dexfile)
        self.r2.cmd('aa')

        # Take the classes that are not from andriod.jar. The command 'icj' returns each class with their methods
        interesting_classes = (c for c in self.r2.cmdj('icj') if not self.is_android_method.match(c['classname']))
        # Extract the code of each method 
        methods = chain(*map(self.extract_methods, interesting_classes))
        # From the code of each method, extract the ones that invoke other methods
        opcodes = filter(self.is_invocation, chain(*methods)) 
        # From the disasm of each opcode, extract the called method
        called_methods = set(map(self.extract_called, opcodes))
        # Filter the methods that are not from android.jar
        if self.android_only:
            called_methods = filter(self.is_android_method.match, called_methods)

        for mthd in called_methods: self.out.write("%s\n" % mthd)
        self.r2.quit()

    def extract_methods(self, c):
        """
        Takes the JSON of a class and extracts the code of each method.
        """
        return (self.parse_method(m) for m in c['methods'])
        
    def parse_method(self, m):
        """
        From a method JSON takes the address and returns the disasembly of the method.
        """
        return self.r2.cmdj('pdfj @ 0x%08x' % m['addr'])['ops']

    def is_invocation(self, op):
        """
        Check if it's an invocation opcode.
        """
        return self.is_invocation_opcode.match(op['disasm'])

    def extract_called(self, op):
        """
        Takes the called method from the disassembly and returns it.
        """
        return re.search(self.invoke_disasm, op['disasm']).group(1)

if __name__ == "__main__":
    Dex2Call()
