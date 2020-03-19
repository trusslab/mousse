/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  Copyright (C) 2020, TrussLab@University of California, Irvine.
 * 	Authors: Yingtong Liu <yingtong@uci.edu> 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
STRUCT_SPECIAL(termios)
STRUCT_SPECIAL(binder_write_read)

STRUCT(winsize,
       TYPE_SHORT, TYPE_SHORT, TYPE_SHORT, TYPE_SHORT)

STRUCT(serial_multiport_struct,
       TYPE_INT, TYPE_INT, TYPE_CHAR, TYPE_CHAR, TYPE_INT, TYPE_CHAR, TYPE_CHAR,
       TYPE_INT, TYPE_CHAR, TYPE_CHAR, TYPE_INT, TYPE_CHAR, TYPE_CHAR, TYPE_INT,
       MK_ARRAY(TYPE_INT, 32))

STRUCT(serial_icounter_struct,
       TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, MK_ARRAY(TYPE_INT, 16))

STRUCT(sockaddr,
       TYPE_SHORT, MK_ARRAY(TYPE_CHAR, 14))

STRUCT(rtentry,
       TYPE_ULONG, MK_STRUCT(STRUCT_sockaddr), MK_STRUCT(STRUCT_sockaddr), MK_STRUCT(STRUCT_sockaddr),
       TYPE_SHORT, TYPE_SHORT, TYPE_ULONG, TYPE_PTRVOID, TYPE_SHORT, TYPE_PTRVOID,
       TYPE_ULONG, TYPE_ULONG, TYPE_SHORT)

STRUCT(ifmap,
       TYPE_ULONG, TYPE_ULONG, TYPE_SHORT, TYPE_CHAR, TYPE_CHAR, TYPE_CHAR,
       /* Spare 3 bytes */
       TYPE_CHAR, TYPE_CHAR, TYPE_CHAR)

/* The *_ifreq_list arrays deal with the fact that struct ifreq has unions */

STRUCT(sockaddr_ifreq,
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ), MK_STRUCT(STRUCT_sockaddr))

STRUCT(short_ifreq,
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ), TYPE_SHORT)

STRUCT(int_ifreq,
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ), TYPE_INT)

STRUCT(ifmap_ifreq,
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ), MK_STRUCT(STRUCT_ifmap))

STRUCT(char_ifreq,
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ),
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ))

STRUCT(ptr_ifreq,
       MK_ARRAY(TYPE_CHAR, IFNAMSIZ), TYPE_PTRVOID)

STRUCT(ifconf,
       TYPE_INT, TYPE_PTRVOID)

STRUCT(arpreq,
       MK_STRUCT(STRUCT_sockaddr), MK_STRUCT(STRUCT_sockaddr), TYPE_INT, MK_STRUCT(STRUCT_sockaddr),
       MK_ARRAY(TYPE_CHAR, 16))

STRUCT(arpreq_old,
       MK_STRUCT(STRUCT_sockaddr), MK_STRUCT(STRUCT_sockaddr), TYPE_INT, MK_STRUCT(STRUCT_sockaddr))

STRUCT(cdrom_read_audio,
       TYPE_CHAR, TYPE_CHAR, TYPE_CHAR, TYPE_CHAR, TYPE_CHAR, TYPE_INT, TYPE_PTRVOID,
       TYPE_NULL)

STRUCT(hd_geometry,
       TYPE_CHAR, TYPE_CHAR, TYPE_SHORT, TYPE_ULONG)

STRUCT(dirent,
       TYPE_LONG, TYPE_LONG, TYPE_SHORT, MK_ARRAY(TYPE_CHAR, 256))

STRUCT(kbentry,
       TYPE_CHAR, TYPE_CHAR, TYPE_SHORT)

STRUCT(kbsentry,
       TYPE_CHAR, MK_ARRAY(TYPE_CHAR, 512))

STRUCT(audio_buf_info,
       TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT)

STRUCT(count_info,
       TYPE_INT, TYPE_INT, TYPE_INT)

STRUCT(buffmem_desc,
       TYPE_PTRVOID, TYPE_INT)

STRUCT(mixer_info,
       MK_ARRAY(TYPE_CHAR, 16), MK_ARRAY(TYPE_CHAR, 32), TYPE_INT, MK_ARRAY(TYPE_INT, 10))

/* loop device ioctls */
STRUCT(loop_info,
       TYPE_INT,                 /* lo_number */
       TYPE_OLDDEVT,             /* lo_device */
       TYPE_ULONG,               /* lo_inode */
       TYPE_OLDDEVT,             /* lo_rdevice */
       TYPE_INT,                 /* lo_offset */
       TYPE_INT,                 /* lo_encrypt_type */
       TYPE_INT,                 /* lo_encrypt_key_size */
       TYPE_INT,                 /* lo_flags */
       MK_ARRAY(TYPE_CHAR, 64),  /* lo_name */
       MK_ARRAY(TYPE_CHAR, 32),  /* lo_encrypt_key */
       MK_ARRAY(TYPE_ULONG, 2),  /* lo_init */
       MK_ARRAY(TYPE_CHAR, 4))   /* reserved */

STRUCT(loop_info64,
       TYPE_ULONGLONG,           /* lo_device */
       TYPE_ULONGLONG,           /* lo_inode */
       TYPE_ULONGLONG,           /* lo_rdevice */
       TYPE_ULONGLONG,           /* lo_offset */
       TYPE_ULONG,               /* lo_number */
       TYPE_ULONG,               /* lo_encrypt_type */
       TYPE_ULONG,               /* lo_encrypt_key_size */
       TYPE_ULONG,               /* lo_flags */
       MK_ARRAY(TYPE_CHAR, 64),  /* lo_name */
       MK_ARRAY(TYPE_CHAR, 64),  /* lo_crypt_name */
       MK_ARRAY(TYPE_CHAR, 32),  /* lo_encrypt_key */
       MK_ARRAY(TYPE_ULONGLONG, 2))  /* lo_init */

/* mag tape ioctls */
STRUCT(mtop, TYPE_SHORT, TYPE_INT)
STRUCT(mtget, TYPE_LONG, TYPE_LONG, TYPE_LONG, TYPE_LONG, TYPE_LONG,
       TYPE_INT, TYPE_INT)
STRUCT(mtpos, TYPE_LONG)

STRUCT(fb_fix_screeninfo,
       MK_ARRAY(TYPE_CHAR, 16), /* id */
       TYPE_ULONG, /* smem_start */
       TYPE_INT, /* smem_len */
       TYPE_INT, /* type */
       TYPE_INT, /* type_aux */
       TYPE_INT, /* visual */
       TYPE_SHORT, /* xpanstep */
       TYPE_SHORT, /* ypanstep */
       TYPE_SHORT, /* ywrapstep */
       TYPE_INT, /* line_length */
       TYPE_ULONG, /* mmio_start */
       TYPE_INT, /* mmio_len */
       TYPE_INT, /* accel */
       MK_ARRAY(TYPE_CHAR, 3)) /* reserved */

STRUCT(fb_var_screeninfo,
       TYPE_INT, /* xres */
       TYPE_INT, /* yres */
       TYPE_INT, /* xres_virtual */
       TYPE_INT, /* yres_virtual */
       TYPE_INT, /* xoffset */
       TYPE_INT, /* yoffset */
       TYPE_INT, /* bits_per_pixel */
       TYPE_INT, /* grayscale */
       MK_ARRAY(TYPE_INT, 3), /* red */
       MK_ARRAY(TYPE_INT, 3), /* green */
       MK_ARRAY(TYPE_INT, 3), /* blue */
       MK_ARRAY(TYPE_INT, 3), /* transp */
       TYPE_INT, /* nonstd */
       TYPE_INT, /* activate */
       TYPE_INT, /* height */
       TYPE_INT, /* width */
       TYPE_INT, /* accel_flags */
       TYPE_INT, /* pixclock */
       TYPE_INT, /* left_margin */
       TYPE_INT, /* right_margin */
       TYPE_INT, /* upper_margin */
       TYPE_INT, /* lower_margin */
       TYPE_INT, /* hsync_len */
       TYPE_INT, /* vsync_len */
       TYPE_INT, /* sync */
       TYPE_INT, /* vmode */
       TYPE_INT, /* rotate */
       MK_ARRAY(TYPE_INT, 5)) /* reserved */

STRUCT(fb_cmap,
       TYPE_INT, /* start  */
       TYPE_INT, /* len    */
       TYPE_PTRVOID, /* red    */
       TYPE_PTRVOID, /* green  */
       TYPE_PTRVOID, /* blue   */
       TYPE_PTRVOID) /* transp */

STRUCT(fb_con2fbmap,
       TYPE_INT, /* console     */
       TYPE_INT) /* framebuffer */


STRUCT(vt_stat,
       TYPE_SHORT, /* v_active */
       TYPE_SHORT, /* v_signal */
       TYPE_SHORT) /* v_state */

STRUCT(vt_mode,
       TYPE_CHAR,  /* mode   */
       TYPE_CHAR,  /* waitv  */
       TYPE_SHORT, /* relsig */
       TYPE_SHORT, /* acqsig */
       TYPE_SHORT) /* frsig  */

STRUCT(dm_ioctl,
       MK_ARRAY(TYPE_INT, 3), /* version */
       TYPE_INT, /* data_size */
       TYPE_INT, /* data_start */
       TYPE_INT, /* target_count*/
       TYPE_INT, /* open_count */
       TYPE_INT, /* flags */
       TYPE_INT, /* event_nr */
       TYPE_INT, /* padding */
       TYPE_ULONGLONG, /* dev */
       MK_ARRAY(TYPE_CHAR, 128), /* name */
       MK_ARRAY(TYPE_CHAR, 129), /* uuid */
       MK_ARRAY(TYPE_CHAR, 7)) /* data */

STRUCT(dm_target_spec,
       TYPE_ULONGLONG, /* sector_start */
       TYPE_ULONGLONG, /* length */
       TYPE_INT, /* status */
       TYPE_INT, /* next */
       MK_ARRAY(TYPE_CHAR, 16)) /* target_type */

STRUCT(dm_target_deps,
       TYPE_INT, /* count */
       TYPE_INT) /* padding */

STRUCT(dm_name_list,
       TYPE_ULONGLONG, /* dev */
       TYPE_INT) /* next */

STRUCT(dm_target_versions,
       TYPE_INT, /* next */
       MK_ARRAY(TYPE_INT, 3)) /* version*/

STRUCT(dm_target_msg,
       TYPE_ULONGLONG) /* sector */

STRUCT(fiemap_extent,
       TYPE_ULONGLONG, /* fe_logical */
       TYPE_ULONGLONG, /* fe_physical */
       TYPE_ULONGLONG, /* fe_length */
       MK_ARRAY(TYPE_ULONGLONG, 2), /* fe_reserved64[2] */
       TYPE_INT, /* fe_flags */
       MK_ARRAY(TYPE_INT, 3)) /* fe_reserved[3] */

STRUCT(fiemap,
       TYPE_ULONGLONG, /* fm_start */
       TYPE_ULONGLONG, /* fm_length */
       TYPE_INT, /* fm_flags */
       TYPE_INT, /* fm_mapped_extents */
       TYPE_INT, /* fm_extent_count */
       TYPE_INT) /* fm_reserved */
STRUCT(media_device_info,
	MK_ARRAY(TYPE_CHAR, 16), /* driver[16] */ 
	MK_ARRAY(TYPE_CHAR, 32), /* model[32] */ 
	MK_ARRAY(TYPE_CHAR, 40), /* serial[40] */ 
	MK_ARRAY(TYPE_CHAR, 32), /* bus_info[32] */ 
        TYPE_ULONG, /* media_version */
        TYPE_ULONG, /* hw_revision */
        TYPE_ULONG) /* driver_version */
STRUCT(dev,
	TYPE_ULONG, /* major */
	TYPE_ULONG) /* minor */ 

STRUCT(alsa,
	TYPE_ULONG, /* card */
	TYPE_ULONG, /* device */
	TYPE_ULONG) /* subdevice */

STRUCT(v4l,
	TYPE_ULONG, /* major */
	TYPE_ULONG) /* minor */

STRUCT(fb,
	TYPE_ULONG, /* major */
	TYPE_ULONG) /* minor */

STRUCT(media_entity_desc,
	TYPE_ULONG, /* id */
	MK_ARRAY(TYPE_CHAR, 32), /* name[32] */ 
	TYPE_ULONG, /* type */
	TYPE_ULONG, /* revision */
	TYPE_ULONG, /* flags */
	TYPE_ULONG, /* group_id */
	TYPE_SHORT, /* pads */
	TYPE_SHORT, /* links */

	MK_ARRAY(TYPE_ULONG, 4), /* reserved[4] */ 
	MK_STRUCT(STRUCT_dev),
	MK_STRUCT(STRUCT_alsa),
	MK_STRUCT(STRUCT_v4l),
	MK_STRUCT(STRUCT_fb),
	TYPE_INT, /* dvb */
	MK_ARRAY(TYPE_CHAR, 184)) /* raw[184] */ 
/* binder: copied from binder.h: https://github.com/spotify/linux/blob/master/drivers/staging/android/binder.h  */
STRUCT(binder_version,
	TYPE_LONG) /* protocol_version */
STRUCT(v4l2_event_subscription,
	TYPE_ULONG,	
	TYPE_ULONG,	
	TYPE_ULONG,	
	MK_ARRAY(TYPE_ULONG, 5)) 
STRUCT(v4l2_capability,
    MK_ARRAY(TYPE_CHAR, 16),	
	MK_ARRAY(TYPE_CHAR, 32),	
	MK_ARRAY(TYPE_CHAR, 32),	
	TYPE_ULONG,	
	TYPE_ULONG,	
	TYPE_ULONG,	
	MK_ARRAY(TYPE_ULONG, 3)) 

STRUCT(v4l2_event,
	TYPE_ULONG,	
    MK_ARRAY(TYPE_CHAR, 64),	
	TYPE_ULONG,	
	TYPE_ULONG,	
	TYPE_ULONG,	
	TYPE_LONG,	
	TYPE_ULONG,	
	MK_ARRAY(TYPE_ULONG, 8)) 

STRUCT(ion_allocation_data,
    TYPE_ULONG,
    TYPE_ULONG,
    TYPE_ULONG,
    TYPE_ULONG,
    TYPE_INT)
STRUCT(ion_fd_data,
    TYPE_INT,
    TYPE_INT)
STRUCT(ion_handle_data,
    TYPE_INT)
