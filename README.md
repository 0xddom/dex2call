# Dex2Call

[![PyPI version](https://badge.fury.io/py/dex2call.svg)](https://badge.fury.io/py/dex2call)

A simple script that takes an APK or a DEX files and returns the method calls made by the developer's code to the android.jar classes.

Tested on Python 2.7 and 3.7 but should be a polyglot script.

## Installation

    pip install dex2call

## Usage

    $ dex2call --help
    Usage: dex2call [OPTIONS] <dex or apk>
    
      This script reads the bytecode of a dex file or an apk file and yields the
      API calls made by the developer code. By default only shows the API calls
      made to android.jar.
    
      The script by default looks for ./classes.dex.
    
    Options:
      -o, --output <file>             Location where to dump the results. Default
                                      stdout (-)
      --android-only / --all-methods  Set to true to remove any method call that
                                      doesn't point to an android method
      --help                          Show this message and exit.

## Example:

As command line tool:

    $ dex2call classes.dex
    (android.location.Location getLatitude () None)
    (android.location.Location getLongitude () None)
    (android.app.Activity <init> () None)
    (android.app.Activity onCreate (android.os.Bundle) None)
    (android.location.LocationManager requestLocationUpdates (java.lang.String android.location.LocationListener) None)
    (android.app.Activity onResume () None)
    (android.util.Log d (java.lang.String java.lang.String) None)
    (android.util.Log d (java.lang.String java.lang.String) None)
    (android.widget.Toast makeText (android.content.Context java.lang.CharSequence) android.widget.Toast)
    (android.widget.Toast show () None)
    (android.widget.Toast makeText (android.content.Context java.lang.CharSequence) android.widget.Toast)
    (android.widget.Toast show () None)

If an APK is passed to the tool, it will extract each dex file and also will infer the package name.

An example can be found in `example.py` of how to use dex2call as a python module.
