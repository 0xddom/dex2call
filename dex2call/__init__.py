#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This script takes an APK file or a DEX file and extracts all the API
calls made by methods that do not belong to classes in the android package.

By default it removes the calls made to methods that do not belong to the android.jar.
This means that the default behaviour is to get the calls made to android.jar made by
the developer's code.

(c) 2018 Daniel Domínguez <daniel.dominguez@imdea.org>
"""

from __future__ import print_function

import re
import sys
from itertools import chain
from tempfile import NamedTemporaryFile

import r2pipe
from androguard.core.bytecodes.apk import APK


class Dex2Call(object):
    """
    This class implements the logic for extracting the API calls to android.jar from the bytecode.
    """

    def __init__(self, dexpath, out, android_only=True):
        """
        Inits all the attributes.
        """
        
        self.out = out

        self.is_android_method = re.compile(r'^.android\/')
        self.is_invocation_opcode = re.compile(r'^invoke-')
        self.invoke_disasm = re.compile(r'^invoke-.* \{.*\}, ([^ ]*)( ;.*)?$')

        self.android_only = android_only
        self.dexpath = dexpath

    def extract(self):
        """
        Launches the extraction logic.
        """

        if self.dexpath.endswith('.dex'):
            self.extract_calls_from_dex(self.dexpath)
        else:
            self.extract_calls_from_apk(self.dexpath)

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
        self.r2 = r2pipe.open(dexfile) # pylint: disable=invalid-name,attribute-defined-outside-init
        self.r2.cmd('aa')

        # Take the classes that are not from andriod.jar.
        # The command 'icj' returns each class with their methods
        interesting_classes = (c for c in self.r2.cmdj('icj')
                               if not self.is_android_method.match(c['classname']))
        # Extract the code of each method
        methods = chain(*map(self.extract_methods, interesting_classes))
        # From the code of each method, extract the ones that invoke other methods
        opcodes = filter(self.is_invocation, chain(*methods))
        # From the disasm of each opcode, extract the called method
        called_methods = set(map(self.extract_called, opcodes))
        # Filter the methods that are not from android.jar
        if self.android_only:
            called_methods = filter(self.is_android_method.match, called_methods)

        for mthd in called_methods:
            self.out.on_method(mthd)
        self.r2.quit()

    def extract_methods(self, klass):
        """
        Takes the JSON of a class and extracts the code of each method.
        """
        return (self.parse_method(m) for m in klass['methods'])

    def parse_method(self, method):
        """
        From a method JSON takes the address and returns the disasembly of the method.
        """
        return self.r2.cmdj('pdfj @ 0x%08x' % method['addr'])['ops']

    def is_invocation(self, opcode):
        """
        Check if it's an invocation opcode.
        """
        return self.is_invocation_opcode.match(opcode['disasm'])

    def extract_called(self, opcode):
        """
        Takes the called method from the disassembly and returns it.
        """
        return re.search(self.invoke_disasm, opcode['disasm']).group(1)

