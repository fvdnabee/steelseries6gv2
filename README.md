steelseries6gv2
===========

steelseries6gv2 is a program that translates USB HID events from the media keys of a Steelseries 6gv2 keyboard to media key strokes in linux.
The program barrows heavily from (usbhid-dump)[https://github.com/DIGImend/usbhid-dump/] for processing the USB HID communication.
Sending key strokes to the linux kernel is done via the (uinput module)[https://www.kernel.org/doc/html/v4.12/input/uinput.html].

Dependencies:
------------
* libusb (>=1.0)
* libevdev (>1.3)

Installation
------------

* Run `autoreconf -i -f`.
* Run `./configure && make` to build.
* The binary is available under src/steelseries6gv2.

Usage:
-----
You can run steelseries6gv2 for all users as root or run it as a single user.

Running steelseries6gv2 as an unprivileged user requires access to both the uinput and the usb device. The following udev rules might help you:
```
KERNEL=="uinput", MODE="0666"
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="04b4", ATTR{idProduct}=="0101", GROUP="input", MODE="0666"
```
See (Arch Wiki)[https://wiki.archlinux.org/index.php/Udev] for more details on udev rules.

Known issues:
------------
* You might notice that /dev/uinput does not exist or does not have the file permissions as per the udev rule above. One fix for this is to signal the kernel to load uinput module as follows:
`cat uinput > /etc/modules-load.d/uinput.conf`
* When you have pressed the media keys without the steelseries6gv2 program running, then the usb device won't generate any USB HID events. In this case you can reset the USB device by executing the reset-keyboard-usb-device.sh script.

TODO:
-----
* Extend udev rules to automatically start the program when the keyboard is detected.
* Add make install which installs the necessary udev rules and make the program available on the system path.
* Handle the case when pressing the media keys doesn't generate the USB HID events. Best solution seems to be to always reset the USB device at the beginning of the program and hope that this always fixes the issue...
* Hot swapping might be a problem, could be fixed by udev rules?
