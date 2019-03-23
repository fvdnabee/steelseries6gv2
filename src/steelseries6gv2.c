/** @file
 * @brief steelseries6gv2 entry point *
 * Copyright (C) 2019 Floris Van den Abeele
 *
 * Note this file barrows heavily from the usbhid-dump project.
 *
 * This file is part of steelseries6gv2.
 * steelseries6gv2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * steelseries6gv2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with steelseries6gv2; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @author Floris Van den Abeele <floris@vdna.be>
 *
 * @(#) $Id$
 */

#include "uhd/iface_list.h"
#include "uhd/libusb.h"
#include "uhd/misc.h"

#include <assert.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>

#include <libusb.h>

#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>


#define GENERIC_ERROR(_fmt, _args...) \
    fprintf(stderr, _fmt "\n", ##_args)

#define IFACE_ERROR(_iface, _fmt, _args...) \
    GENERIC_ERROR("%s:" _fmt, _iface->addr_str, ##_args)

#define GENERIC_FAILURE(_fmt, _args...) \
    GENERIC_ERROR("Failed to " _fmt, ##_args)

#define IFACE_FAILURE(_iface, _fmt, _args...) \
    IFACE_ERROR(_iface, "Failed to " _fmt, ##_args)

#define LIBUSB_FAILURE(_fmt, _args...) \
    GENERIC_FAILURE(_fmt ": %s", ##_args, libusb_strerror(err))

#define LIBUSB_IFACE_FAILURE(_iface, _fmt, _args...) \
    IFACE_FAILURE(_iface, _fmt ": %s", ##_args, libusb_strerror(err))

#define ERROR_CLEANUP(_fmt, _args...) \
    do {                                \
        GENERIC_ERROR(_fmt, ##_args);   \
        goto cleanup;                   \
    } while (0)

#define FAILURE_CLEANUP(_fmt, _args...) \
    do {                                \
        GENERIC_FAILURE(_fmt, ##_args); \
        goto cleanup;                   \
    } while (0)

#define LIBUSB_FAILURE_CLEANUP(_fmt, _args...) \
    do {                                        \
        LIBUSB_FAILURE(_fmt, ##_args);          \
        goto cleanup;                           \
    } while (0)

#define LIBUSB_IFACE_FAILURE_CLEANUP(_iface, _fmt, _args...) \
    do {                                                        \
        LIBUSB_IFACE_FAILURE(_iface, _fmt, ##_args);            \
        goto cleanup;                                           \
    } while (0)

#define LIBUSB_GUARD(_expr, _fmt, _args...) \
    do {                                            \
        err = _expr;                                \
        if (err != LIBUSB_SUCCESS)                  \
            LIBUSB_FAILURE_CLEANUP(_fmt, ##_args);  \
    } while (0)

#define LIBUSB_IFACE_GUARD(_expr, _iface, _fmt, _args...) \
    do {                                                            \
        err = _expr;                                                \
        if (err != LIBUSB_SUCCESS)                                  \
            LIBUSB_IFACE_FAILURE_CLEANUP(_iface, _fmt, ##_args);    \
    } while (0)


static struct libevdev *dev;
static struct libevdev_uinput *uidev;

static int
create_steelseries_uinput_device() {
  int result;

  dev = libevdev_new();
  libevdev_set_name(dev, "steelseries media keys uinput device");

  libevdev_enable_event_type(dev, EV_KEY);
  libevdev_enable_event_code(dev, EV_KEY, KEY_MUTE, NULL);
  libevdev_enable_event_code(dev, EV_KEY, KEY_VOLUMEDOWN, NULL);
  libevdev_enable_event_code(dev, EV_KEY, KEY_VOLUMEUP, NULL);
  libevdev_enable_event_code(dev, EV_KEY, KEY_PLAYPAUSE, NULL);
  libevdev_enable_event_code(dev, EV_KEY, KEY_PREVIOUSSONG, NULL);
  libevdev_enable_event_code(dev, EV_KEY, KEY_NEXTSONG, NULL);

  result = libevdev_uinput_create_from_device(dev,
      LIBEVDEV_UINPUT_OPEN_MANAGED, &uidev);

  if (result != 0) {
    GENERIC_FAILURE("create uinput device %d", result);
  }
  return result;
}

static void
free_steelseries_uinput_device() {
  libevdev_uinput_destroy(uidev);
  libevdev_free(dev);
}
/**< Number of the signal causing the exit */
static volatile sig_atomic_t exit_signum  = 0;

static void
exit_sighandler(int signum)
{
    if (exit_signum == 0)
        exit_signum = signum;
}

/**< "Stream paused" flag - non-zero if paused */
static volatile sig_atomic_t stream_paused = 0;


static void
stream_pause_sighandler(int signum)
{
    (void)signum;
    stream_paused = 1;
}

static void
stream_resume_sighandler(int signum)
{
    (void)signum;
    stream_paused = 0;
}

static void
parse_steelseries6gv2_transfer(const uint8_t     *ptr,
     size_t             len)
{
  static uint16_t last_key = 0;
  bool            key_release = false;
  int             result;

  /* I have only seen transfers with length two, so reject other transfers */
  if (len != 2) return;

  /* For all the transfers I have seen the first byte has always been two */
  if (ptr[0] != 2) return;

  /* Map transfser to key code */
  switch (ptr[1]) {
    case 1:
      last_key = KEY_VOLUMEUP;
      break;
    case 2:
      last_key = KEY_VOLUMEDOWN;
      break;
    case 4:
      last_key = KEY_MUTE;
      break;
    case 8:
      last_key = KEY_PLAYPAUSE;
      break;
    case 0x10:
      last_key = KEY_NEXTSONG;
      break;
    case 0x20:
      last_key = KEY_PREVIOUSSONG;
      break;
    case 0:
      key_release = true;
      break;
    default:
      GENERIC_ERROR("unknown key, ignoring");
      return;
  }

  /* Pass key code corresponding to transfer to kernel via uinput device */
  result = libevdev_uinput_write_event(uidev, EV_KEY, last_key, !key_release ? 1 : 0);
  if (result != 0) {
    GENERIC_ERROR("libevdev_uinput_write_event returned %d", result);
    return;
  }

  /* Report the event */
  result = libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0);
  if (result != 0) {
    GENERIC_ERROR("libevdev_uinput_write_event returned %d", result);
    return;
  }
}

static void LIBUSB_CALL
monitor_iface_list_stream_cb(struct libusb_transfer *transfer)
{
    enum libusb_error   err;
    uhd_iface          *iface;

    assert(transfer != NULL);

    iface = (uhd_iface *)transfer->user_data;
    assert(uhd_iface_valid(iface));

    /* Clear interface "has transfer submitted" flag */
    iface->submitted = false;

    switch (transfer->status)
    {
        case LIBUSB_TRANSFER_COMPLETED:
            /* Parse the result */
            if (!stream_paused)
            {
                parse_steelseries6gv2_transfer(transfer->buffer, transfer->actual_length);
            }
            /* Resubmit the transfer */
            err = libusb_submit_transfer(transfer);
            if (err != LIBUSB_SUCCESS)
                LIBUSB_IFACE_FAILURE(iface, "resubmit a transfer");
            else
            {
                /* Set interface "has transfer submitted" flag */
                iface->submitted = true;
            }
            break;

#define MAP(_name, _desc) \
    case LIBUSB_TRANSFER_##_name: \
        IFACE_ERROR(iface, _desc);  \
        break

        MAP(ERROR,      "Interrupt transfer failed");
        MAP(TIMED_OUT,  "Interrupt transfer timed out");
        MAP(STALL,      "Interrupt transfer halted (endpoint stalled)");
        MAP(NO_DEVICE,  "Device was disconnected");
        MAP(OVERFLOW,   "Interrupt transfer overflowed "
                        "(device sent more data than requested)");
#undef MAP

        case LIBUSB_TRANSFER_CANCELLED:
            break;
    }
}

static bool
monitor_iface_list_stream(libusb_context  *ctx,
                       uhd_iface       *list,
                       unsigned int     timeout)
{
    bool                        result              = false;
    enum libusb_error           err;
    size_t                      transfer_num        = 0;
    struct libusb_transfer    **transfer_list       = NULL;
    struct libusb_transfer    **ptransfer;
    uhd_iface                  *iface;
    bool                        submitted           = false;

    fprintf(stdout, "Starting monitoring interrupt transfer stream\n\n");

    UHD_IFACE_LIST_FOR_EACH(iface, list)
    {
        /* Set report protocol */
        LIBUSB_IFACE_GUARD(uhd_iface_set_protocol(iface, true,
                                                  UHD_IO_TIMEOUT),
                           iface, "set report protocol");
        /* Set infinite idle duration */
        LIBUSB_IFACE_GUARD(uhd_iface_set_idle(iface, 0, UHD_IO_TIMEOUT),
                           iface, "set infinite idle duration");
    }

    /* Calculate number of interfaces and thus transfers */
    transfer_num = uhd_iface_list_len(list);

    /* Allocate transfer list */
    transfer_list = malloc(sizeof(*transfer_list) * transfer_num);
    if (transfer_list == NULL)
        FAILURE_CLEANUP("allocate transfer list");

    /* Zero transfer list */
    for (ptransfer = transfer_list;
         (size_t)(ptransfer - transfer_list) < transfer_num;
         ptransfer++)
        *ptransfer = NULL;

    /* Allocate transfers */
    for (ptransfer = transfer_list;
         (size_t)(ptransfer - transfer_list) < transfer_num;
         ptransfer++)
    {
        *ptransfer = libusb_alloc_transfer(0);
        if (*ptransfer == NULL)
            FAILURE_CLEANUP("allocate a transfer");
        /*
         * Set user_data to NULL explicitly, since libusb_alloc_transfer
         * does memset to zero only and zero is not NULL, strictly speaking.
         */
        (*ptransfer)->user_data = NULL;
    }

    /* Initialize the transfers as interrupt transfers */
    for (ptransfer = transfer_list, iface = list;
         (size_t)(ptransfer - transfer_list) < transfer_num;
         ptransfer++, iface = iface->next)
    {
        void           *buf;
        const size_t    len = iface->int_in_ep_maxp;

        /* Allocate the transfer buffer */
        buf = malloc(len);
        if (len > 0 && buf == NULL)
            FAILURE_CLEANUP("allocate a transfer buffer");

        /* Initialize the transfer */
        libusb_fill_interrupt_transfer(*ptransfer,
                                       iface->dev->handle, iface->int_in_ep_addr,
                                       buf, len,
                                       monitor_iface_list_stream_cb,
                                       (void *)iface,
                                       timeout);

        /* Ask to free the buffer when the transfer is freed */
        (*ptransfer)->flags |= LIBUSB_TRANSFER_FREE_BUFFER;
    }

    /* Submit first transfer requests */
    for (ptransfer = transfer_list;
         (size_t)(ptransfer - transfer_list) < transfer_num;
         ptransfer++)
    {
        LIBUSB_GUARD(libusb_submit_transfer(*ptransfer),
                     "submit a transfer");
        /* Set interface "has transfer submitted" flag */
        ((uhd_iface *)(*ptransfer)->user_data)->submitted = true;
        /* Set "have any submitted transfers" flag */
        submitted = true;
    }

    /* Run the event machine */
    while (submitted && exit_signum == 0)
    {
        /* Handle the transfer events */
        err = libusb_handle_events(ctx);
        if (err != LIBUSB_SUCCESS && err != LIBUSB_ERROR_INTERRUPTED)
            LIBUSB_FAILURE_CLEANUP("handle transfer events");

        /* Check if there are any submitted transfers left */
        submitted = false;
        for (ptransfer = transfer_list;
             (size_t)(ptransfer - transfer_list) < transfer_num;
             ptransfer++)
        {
            iface = (uhd_iface *)(*ptransfer)->user_data;

            if (iface != NULL && iface->submitted)
                submitted = true;
        }
    }

    /* If all the transfers were terminated unexpectedly */
    if (transfer_num > 0 && !submitted)
        ERROR_CLEANUP("No more interfaces to monitor");

    result = true;

cleanup:

    /* Cancel the transfers */
    if (submitted)
    {
        submitted = false;
        for (ptransfer = transfer_list;
             (size_t)(ptransfer - transfer_list) < transfer_num;
             ptransfer++)
        {
            iface = (uhd_iface *)(*ptransfer)->user_data;

            if (iface != NULL && iface->submitted)
            {
                err = libusb_cancel_transfer(*ptransfer);
                if (err == LIBUSB_SUCCESS)
                    submitted = true;
                else
                {
                    LIBUSB_FAILURE("cancel a transfer, ignoring");
                    /*
                     * XXX are we really sure
                     * the transfer won't be finished?
                     */
                    iface->submitted = false;
                }
            }
        }
    }

    /* Wait for transfer cancellation */
    while (submitted)
    {
        /* Handle cancellation events */
        err = libusb_handle_events(ctx);
        if (err != LIBUSB_SUCCESS && err != LIBUSB_ERROR_INTERRUPTED)
        {
            LIBUSB_FAILURE("handle transfer cancellation events, "
                           "aborting transfer cancellation");
            break;
        }

        /* Check if there are any submitted transfers left */
        submitted = false;
        for (ptransfer = transfer_list;
             (size_t)(ptransfer - transfer_list) < transfer_num;
             ptransfer++)
        {
            iface = (uhd_iface *)(*ptransfer)->user_data;

            if (iface != NULL && iface->submitted)
                submitted = true;
        }
    }

    /*
     * Free transfer list along with non-submitted transfers and their
     * buffers.
     */
    if (transfer_list != NULL)
    {
        for (ptransfer = transfer_list;
             (size_t)(ptransfer - transfer_list) < transfer_num;
             ptransfer++)
        {
            iface = (uhd_iface *)(*ptransfer)->user_data;

            /*
             * Only free a transfer if it is not submitted. Better leak some
             * memory than have some important memory overwritten.
             */
            if (iface == NULL || !iface->submitted)
                libusb_free_transfer(*ptransfer);
        }

        free(transfer_list);
    }

    return result;
}

static int
run(unsigned int    stream_timeout,
    uint8_t         bus_num,
    uint8_t         dev_addr,
    uint16_t        vid,
    uint16_t        pid,
    int             iface_num)
{
    int                 result      = 1;
    enum libusb_error   err;
    libusb_context     *ctx         = NULL;
    uhd_dev            *dev_list    = NULL;
    uhd_iface          *iface_list  = NULL;
    uhd_iface          *iface;

    /* Create libusb context */
    LIBUSB_GUARD(libusb_init(&ctx), "create libusb context");

    /* Set libusb debug level to informational only */
#define HAVE_LIBUSB_SET_OPTION 1 // TODO
#if HAVE_LIBUSB_SET_OPTION
    libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO);
#else
    libusb_set_debug(ctx, LIBUSB_LOG_LEVEL_INFO);
#endif

    /* Open device list */
    LIBUSB_GUARD(uhd_dev_list_open(ctx, bus_num, dev_addr,
                                   vid, pid, &dev_list),
                 "find and open the devices");

    /* Retrieve the list of HID interfaces from the device list */
    LIBUSB_GUARD(uhd_iface_list_new(dev_list, &iface_list),
                 "find HID interfaces");

    /* Filter the interface list by specified interface number */
    if (iface_num != UHD_IFACE_NUM_ANY)
        iface_list = uhd_iface_list_fltr_by_num(iface_list, iface_num);

    /* Check if there are any interfaces left */
    if (uhd_iface_list_empty(iface_list))
        ERROR_CLEANUP("No matching HID interfaces");

    /* Detach and claim the interfaces */
    UHD_IFACE_LIST_FOR_EACH(iface, iface_list)
    {
        LIBUSB_IFACE_GUARD(uhd_iface_detach(iface),
                           iface, "detach from the kernel driver");
        LIBUSB_IFACE_GUARD(uhd_iface_claim(iface),
                           iface, "claim");

        fprintf(stdout,
            "Found steelseries6gv2 HID interface for media keys at %s\n",
            iface->addr_str);
    }

    /* Run with the prepared interface list */
    result = monitor_iface_list_stream(ctx, iface_list, stream_timeout) ? 0 : 1;

cleanup:

    /* Release and attach the interfaces back */
    UHD_IFACE_LIST_FOR_EACH(iface, iface_list)
    {
        err = uhd_iface_release(iface);
        if (err != LIBUSB_SUCCESS)
            LIBUSB_IFACE_FAILURE(iface, "release");

        err = uhd_iface_attach(iface);
        if (err != LIBUSB_SUCCESS)
            LIBUSB_IFACE_FAILURE(iface, "attach to the kernel driver");
    }

    /* Free the interface list */
    uhd_iface_list_free(iface_list);

    /* Close the device list */
    uhd_dev_list_close(dev_list);

    /* Destroy the libusb context */
    if (ctx != NULL)
        libusb_exit(ctx);

    return result;
}

int
main() {
    int                 result;

    uint8_t             bus_num         = UHD_BUS_NUM_ANY;
    uint8_t             dev_addr        = UHD_DEV_ADDR_ANY;

    /*
     * Check:
     * $ lsusb | grep 'Cypress Semiconductor Corp. Keyboard/Hub'
     * Bus 002 Device 006: ID 04b4:0101 Cypress Semiconductor Corp. Keyboard/Hub
     * */
    uint16_t            vid             = 0x04b4;
    uint16_t            pid             = 0x0101;

    /* interface 1 for the media keys, be careful not to choose the interface
     * number for the actual keyboard keys as this program detaches kernel
     * drivers from the interfaces and uses them exclusively, so no other
     * program receives the input in the meantime.
     * */
    uint8_t             iface_num       = 1;

    /* Note timeout is per transfer */
    unsigned int        stream_timeout  = UINT32_MAX;

    struct sigaction    sa;

    /* Setup virtual input device */
    result = create_steelseries_uinput_device();
    if (result != 0)
      return result;

    /*
     * Setup signal handlers
     */
    /* Setup SIGINT to terminate gracefully */
    sigaction(SIGINT, NULL, &sa);
    if (sa.sa_handler != SIG_IGN)
    {
        sa.sa_handler = exit_sighandler;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGTERM);
        sa.sa_flags = 0;    /* NOTE: no SA_RESTART on purpose */
        sigaction(SIGINT, &sa, NULL);
    }

    /* Setup SIGTERM to terminate gracefully */
    sigaction(SIGTERM, NULL, &sa);
    if (sa.sa_handler != SIG_IGN)
    {
        sa.sa_handler = exit_sighandler;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGINT);
        sa.sa_flags = 0;    /* NOTE: no SA_RESTART on purpose */
        sigaction(SIGTERM, &sa, NULL);
    }

    /* Setup SIGUSR1/SIGUSR2 to pause/resume the stream output */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = stream_pause_sighandler;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = stream_resume_sighandler;
    sigaction(SIGUSR2, &sa, NULL);

    /* Run! */
    result = run(stream_timeout, bus_num, dev_addr, vid, pid, iface_num);

    /*
     * Restore signal handlers
     */
    sigaction(SIGINT, NULL, &sa);
    if (sa.sa_handler != SIG_IGN)
        signal(SIGINT, SIG_DFL);

    sigaction(SIGTERM, NULL, &sa);
    if (sa.sa_handler != SIG_IGN)
        signal(SIGTERM, SIG_DFL);

    /*
     * Reproduce the signal used to stop the program to get proper exit
     * status.
     */
    if (exit_signum != 0)
        raise(exit_signum);

    /* Free uinput device */
    free_steelseries_uinput_device();

    return result;
}
