steelseries6gv2
===========

steelseries6gv2 is a program that translates USB HID events from the media keys of a Steelseries 6gv2 keyboard to media key strokes in linux.
The program barrows heavily from [usbhid-dump](https://github.com/DIGImend/usbhid-dump/) for processing the USB HID communication.
Sending key strokes to the linux kernel is done via the [uinput module](https://www.kernel.org/doc/html/v4.12/input/uinput.html).

Dependencies:
------------
* libusb (>=1.0)
* libevdev (>1.3)

Installation
------------

* Run `autoreconf -i -f`
* Run `./configure && make` to build
* The binary is available under src/steelseries6gv2

Usage:
-----
You can run steelseries6gv2 for all users as root or run it as a single user.

Running steelseries6gv2 as an unprivileged user requires access to both the uinput and the usb device. The following udev rules might help you:
```
KERNEL=="uinput", MODE="0666"
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="04b4", ATTR{idProduct}=="0101", GROUP="input", MODE="0666"
```
See the [Arch Wiki](https://wiki.archlinux.org/index.php/Udev) for more details on udev rules.

### Loading steelseriesg6v2 when the keyboard is plugged in
You can use the systemd service file provided under var/steelseries6gv2.service. This service file depends on the udev rules in var/00-steelseries6gv2.rules.

Steps:
* Install the udev rules from var/00-steelseriesg6v2.rules in /etc/udev/rules.d: `cp var/00-steelseriesg6v2.rules /etc/udev/rules.d`
* Force reload of udev rules via `udevadm control --reload && udevadm trigger`
* Install systemd service file: `ln -s `pwd`/var/steelseries6gv2.service /etc/systemd/system/`
* Reload systemd: `systemctl daemon-reload`

The next time you plugin your keyboard (or when detected at first boot), the systemctl service should be active.
Note that when the keyboard is removed the service will have failed in an error state, e.g.: `Main PID: 481 (code=exited, status=1/FAILURE)`. This is normal and shouldn't affect the next time you plugin the keyboard.

Known issues:
------------
* You might notice that /dev/uinput does not exist or does not have the file permissions as per the udev rule above. One fix for this is to signal the kernel to load uinput module as follows: `cat uinput > /etc/modules-load.d/uinput.conf`. This file is available under var.
* When you have pressed the media keys without the steelseries6gv2 program running, then the usb device won't generate any USB HID events. In this case you can reset the USB device by executing the `reset-keyboard-usb-device.sh` script. This script is available under var.

HID events to media keys:
-------------------------
On a media key press the steelseries 6Gv2 keyboard generates a HID event with 2 bytes of data. The first byte is always equal to 2, the second byte states which key was pressed. The mapping is listed in the table below. When the media key is released the second byte is equal to zero.

| Media key pressed  | HID event data | Linux key            |
| ------------------ | -------------- | -------------------- |
| Fn+F1              | 0x02 0x04      | KEY_MUTE             |
| Fn+F2              | 0x02 0x02      | KEY_VOLUMEDOWN       |
| Fn+F3              | 0x02 0x01      | KEY_VOLUMEUP         |
| Fn+F4              | 0x02 0x08      | KEY_PLAYPAUSE        |
| Fn+F5              | 0x02 0x20      | KEY_NEXTSONG         |
| Fn+F6              | 0x02 0x10      | KEY_PREVIOUSSONG     |
| Keys released      | 0x02 0x00      | Release previous key |


TODO:
-----
* Add make install which installs the necessary udev rules, installs the systemctl service and makes the program available on the system path.
* Handle the case when pressing the media keys doesn't generate the USB HID events. Best solution seems to be to always reset the USB device at the beginning of the program and hope that this always fixes the issue...
