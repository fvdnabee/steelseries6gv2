#!/bin/bash
# This script will search for the usb device path for a steelseries6gv2 key
# board and reset the usb device.
# See https://askubuntu.com/a/61165/156921

# Find usb_dev_path for keyboard:
lsusb_output=`lsusb -d 04b4:0101`
#lsusb_output should contain:
#'Bus 002 Device 004: ID 04b4:0101 Cypress Semiconductor Corp. Keyboard/Hub'
keyboard_bus=`echo $lsusb_output | cut -f2 -d ' '`
keyboard_port=`echo $lsusb_output | cut -c16-18`
usb_dev_path=`udevadm info -q path -n /dev/bus/usb/$keyboard_bus/$keyboard_port`
# usb_dev_path should contain:
#'/devices/pci0000:00/0000:00:14.0/usb2/2-3/2-3.2'

# Actually reset device
if [[ -n "$usb_dev_path" ]]; then
	usb_dev_authorized_path="/sys$usb_dev_path/authorized"

	echo 0 > $usb_dev_authorized_path
	echo 1 > $usb_dev_authorized_path
fi
