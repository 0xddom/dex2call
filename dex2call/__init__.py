#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This script takes an APK file or a DEX file and extracts all the API
calls made by methods that do not belong to classes in the android package.

By default it removes the calls made to methods that do not belong to the android.jar.
This means that the default behaviour is to get the calls made to android.jar by
the developer's code.

(c) 2018 Daniel Domínguez <daniel.dominguez@imdea.org>
"""

from __future__ import print_function

import sys
import re
from itertools import chain

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat


def search_type(arg_expr):
    search = re.search('L([a-zA-Z\.]+)', arg_expr)

    if search:
        return search.group(1)


class ExtractedMethod(object):
    """
    Describes a method extracted by the tool.
    """

    def __init__(self, signature):
        self.signature = signature
        splited = signature.split("->")
        self.class_name = splited[0][1:-1].replace('/', '.')
        splited = splited[1].split('(')
        self.method_name = splited[0]
        splited = splited[1].split(')')
        if splited[0]:
            self.args = (search_type(s.strip().replace('/', '.')) for s in splited[0].split(';') if s)
        else:
            self.args = []
        self.args = [a for a in self.args if a]
        self.return_type = search_type(splited[1][:-1].replace('/', '.'))

    def __str__(self):
        return "(%s %s (%s) %s)" % (self.class_name, self.method_name, " ".join(self.args), self.return_type)


class Extractor(object):
    """
    This class implements the logic for extracting the API calls to android.jar from the bytecode.
    """

    def __init__(self, dexpath, android_only=True):
        """
        Inits all the attributes.
        """
        self.android_only = android_only
        self.dexpath = dexpath

    def extract(self):
        """
        Launches the extraction logic.
        """
        if self.dexpath.endswith('.dex'):
            return self.extract_calls_from_dexfile(self.dexpath)
        else:
            return self.extract_calls_from_apk(self.dexpath)

    def extract_calls_from_apk(self, apkfile):
        """
        Extracts the APK using androguard and pass each dex file to the dex extracion routine.
        """
        return chain(*(self.extract_calls_from_dex(dex) for dex in APK(apkfile).get_all_dex()))

    def extract_calls_from_dexfile(self, dexfile):
        with open(dexfile, 'rb') as dexfd:
            return self.extract_calls_from_dex(dexfd.read())

    def is_interesting_instruction(self, i):
        if not i.get_name().startswith("invoke-"):
            return False
        return str(i.get_translated_kind())[1:].startswith("android") if self.android_only else True

    def extract_calls_from_dex(self, dex):
        """
        Using androguard extracts the method calls from the Dalvik Bytecode.

        Returns a generator.
        """
        instructions = chain(*(m.get_instructions() for m in DalvikVMFormat(dex).get_methods() if not m.get_class_name()[1:].startswith("android")))
        return (self.parse_method_signature(i.get_translated_kind()) for i in instructions if self.is_interesting_instruction(i))

    def parse_method_signature(self, mthd_sig):
        return ExtractedMethod(mthd_sig)