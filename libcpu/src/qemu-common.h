/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2016  Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
/// 	Authors: Yingtong Liu <yingtong@uci.edu> 
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

/* Common header file that is included by all of qemu.  */
#ifndef QEMU_COMMON_H
#define QEMU_COMMON_H

#include <cpu/config-host.h>
#include <libcpu-compiler.h>

/* we put basic includes here to avoid repeating them in device drivers */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* FIXME: Remove NEED_CPU_H.  */
#ifndef NEED_CPU_H

#include "bswap.h"
#include "osdep.h"

#else

#include "cpu.h"

#endif /* !defined(NEED_CPU_H) */

bool tcg_enabled(void);

void qemu_init_vcpu(void *env);

#ifdef CONFIG_USER_KVM

#ifdef _WIN32
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, (void *)buf, len, flags)
#else
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, buf, len, flags)
#endif
typedef struct QEMUIOVector {
    struct iovec *iov;
    int niov;
    int nalloc;
    size_t size;
} QEMUIOVector;
/* mmap.c */
void read_in_mmap_min_addr();
/* cutils.c */
void pstrcpy(char *buf, int buf_size, const char *str);
void strpadcpy(char *buf, int buf_size, const char *str, char pad);
char *pstrcat(char *buf, int buf_size, const char *s);
int strstart(const char *str, const char *val, const char **ptr);
int stristart(const char *str, const char *val, const char **ptr);
int qemu_strnlen(const char *s, int max_len);
time_t mktimegm(struct tm *tm);
int qemu_fls(int i);
int qemu_fdatasync(int fd);
int fcntl_setfl(int fd, int flag);
int qemu_parse_fd(const char *param);
int qemu_parse_fdset(const char *param);
void qemu_iovec_reset(QEMUIOVector *qiov);
/*
 * strtosz() suffixes used to specify the default treatment of an
 * argument passed to strtosz() without an explicit suffix.
 * These should be defined using upper case characters in the range
 * A-Z, as strtosz() will use qemu_toupper() on the given argument
 * prior to comparison.
 */
#define STRTOSZ_DEFSUFFIX_TB	'T'
#define STRTOSZ_DEFSUFFIX_GB	'G'
#define STRTOSZ_DEFSUFFIX_MB	'M'
#define STRTOSZ_DEFSUFFIX_KB	'K'
#define STRTOSZ_DEFSUFFIX_B	'B'
int64_t strtosz(const char *nptr, char **end);
int64_t strtosz_suffix(const char *nptr, char **end, const char default_suffix);
int64_t strtosz_suffix_unit(const char *nptr, char **end,
                            const char default_suffix, int64_t unit);

/* path.c */
void init_paths(const char *prefix);
const char *path(const char *pathname);
#define qemu_isalnum(c)		isalnum((unsigned char)(c))
#define qemu_isalpha(c)		isalpha((unsigned char)(c))
#define qemu_iscntrl(c)		iscntrl((unsigned char)(c))
#define qemu_isdigit(c)		isdigit((unsigned char)(c))
#define qemu_isgraph(c)		isgraph((unsigned char)(c))
#define qemu_islower(c)		islower((unsigned char)(c))
#define qemu_isprint(c)		isprint((unsigned char)(c))
#define qemu_ispunct(c)		ispunct((unsigned char)(c))
#define qemu_isspace(c)		isspace((unsigned char)(c))
#define qemu_isupper(c)		isupper((unsigned char)(c))
#define qemu_isxdigit(c)	isxdigit((unsigned char)(c))
#define qemu_tolower(c)		tolower((unsigned char)(c))
#define qemu_toupper(c)		toupper((unsigned char)(c))
#define qemu_isascii(c)		isascii((unsigned char)(c))
#define qemu_toascii(c)		toascii((unsigned char)(c))

static inline bool is_power_of_2(uint64_t value)
{
    if (!value) {
        return 0;
    }

    return !(value & (value - 1));
}
#endif
#endif
