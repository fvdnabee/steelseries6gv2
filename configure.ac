AC_INIT([steelseries6gv2], [0.1], [floris@vdna.be])
AM_INIT_AUTOMAKE([1.9 -Wall foreign])

AC_CONFIG_HEADER([config.h])

#
# Fix: libtoolize: putting auxiliary files in '.'.
# libtoolize: copying file './ltmain.sh'
# libtoolize: Consider adding 'AC_CONFIG_MACRO_DIRS([m4])' to configure.ac,
# libtoolize: and rerunning libtoolize and aclocal.
# libtoolize: Consider adding '-I m4' to ACLOCAL_AMFLAGS in Makefile.am.
#
AC_CONFIG_MACRO_DIR([m4])

#
# Checks for programs.
# Note: copied from usbhid-dump/configure.ac
#
AC_PROG_CC
AC_PROG_INSTALL
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL

#
# To have empty CFLAGS instead of undefined and '-g -O2' by default
# Note: copied from usbhid-dump/configure.ac
#
CFLAGS=$CFLAGS
#CFLAGS="-Os -Wall $CFLAGS"
CFLAGS="-Os -Wall"

#
# Add include folder to -I for uhd includes
# Note: copied from usbhid-dump/configure.ac
#
ABS_SRCDIR=`cd ${srcdir} ; pwd`
ABS_BUILDDIR=`pwd`
CPPFLAGS="-I${ABS_BUILDDIR} -I${ABS_BUILDDIR}/include -DNDEBUG $CPPFLAGS"
if test "$ABS_SRCDIR" != "$ABS_BUILDDIR"; then
    CPPFLAGS="-I${ABS_SRCDIR}/include $CPPFLAGS"
fi

#
# Checks for libraries.
#
PKG_CHECK_MODULES(LIBUSB, [libusb-1.0 >= 1.0.0])
CFLAGS="$CFLAGS $LIBUSB_CFLAGS"
LIBS="$LIBS $LIBUSB_LIBS"

PKG_CHECK_MODULES(LIBEVDEV, [libevdev >= 1.3])
CFLAGS="$CFLAGS $LIBEVDEV_CFLAGS"
LIBS="$LIBS $LIBEVDEV_LIBS"

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 include/uhd/Makefile
                 lib/Makefile
                 src/Makefile])

AC_OUTPUT
