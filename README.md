# Dex2Call

A simple script that takes an APK or a DEX files and returns the method calls made by the developer's code to the android.jar classes.

Tested on Python 2.7 but should be a polyglot script.

## Installation

Install [radare2](https://github.com/radare/radare2) and run:

    pip install dex2call

## Usage

    $ dex2call.py --help
    Usage: dex2call.py [OPTIONS] <dex or apk>
    
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

    $ dex2call.py classes.dex
	Landroid/util/Log.d(Ljava/lang/String;Ljava/lang/String;)I
    Landroid/location/Location.getLongitude()D
    Landroid/app/Activity.onResume()V
    Landroid/location/Location.getLatitude()D
    Landroid/widget/Toast.makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
    Landroid/location/LocationManager.requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;)V
    Landroid/app/Activity.onCreate(Landroid/os/Bundle;)V
    Landroid/app/Activity.<init>()V
    Landroid/widget/Toast.show()V

As library:

	>>> from dex2call import Dex2Call
	>>> d = Dex2Call("./classes.dex", "-")
	>>> d.extract()
	Landroid/util/Log.d(Ljava/lang/String;Ljava/lang/String;)I
	Landroid/location/Location.getLongitude()D
	Landroid/app/Activity.onResume()V
	Landroid/location/Location.getLatitude()D
	Landroid/widget/Toast.makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
	Landroid/location/LocationManager.requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;)V
	Landroid/app/Activity.onCreate(Landroid/os/Bundle;)V
	Landroid/app/Activity.<init>()V
	Landroid/widget/Toast.show()V
	>>>

A more elaborated example can be found in `example.py`.
