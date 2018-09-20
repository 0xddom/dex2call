# Dex2Call

A simple script that takes an APK or a DEX files and returns the method calls made by the developer's code to the android.jar classes.

Tested on Python 2.7 but should be a polyglot script.

## Installation

Install [radare2](https://github.com/radare/radare2) and the following python packages:

- r2pipe
- click
- androguard

## Usage

    ./dex2call.py --help
    Usage: dex2call.py [OPTIONS]

    Entry point of the script

    Options:
      -f TEXT                         The file that is going to be parsed
      -o TEXT                         Location where dump the results. Default stdout (-)
      --android-only / --all-methods  Set to true to remove any method call that doesn't point to a method in android.jar
      --help                          Show this message and exit.

## Example:

    ./dex2call.py -f classes.dex
	Landroid/util/Log.d(Ljava/lang/String;Ljava/lang/String;)I
    Landroid/location/Location.getLongitude()D
    Landroid/app/Activity.onResume()V
    Landroid/location/Location.getLatitude()D
    Landroid/widget/Toast.makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
    Landroid/location/LocationManager.requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;)V
    Landroid/app/Activity.onCreate(Landroid/os/Bundle;)V
    Landroid/app/Activity.<init>()V
    Landroid/widget/Toast.show()V
