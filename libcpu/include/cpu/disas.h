/// Copyright (C) 2017  Cyberhaven
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

#ifndef _LIBCPU_DISAS_H
#define _LIBCPU_DISAS_H

#include <cpu/types.h>
#include <stdio.h>

void target_disas(FILE *out, target_ulong code, target_ulong size, int flags);

typedef int (*fprintf_function_t)(FILE *f, const char *fmt, ...);
void target_disas_ex(FILE *out, fprintf_function_t func, target_ulong code, target_ulong size, int flags);
const char *lookup_symbol(target_ulong orig_addr);
void disas(FILE *out, void *code, unsigned long size);
struct syminfo;
struct elf32_sym;
struct elf64_sym;
typedef const char *(*lookup_symbol_t)(struct syminfo *s, target_phys_addr_t orig_addr);

struct syminfo {
    lookup_symbol_t lookup_symbol;
    unsigned int disas_num_syms;
    union {
      struct elf32_sym *elf32;
      struct elf64_sym *elf64;
    } disas_symtab;
    const char *disas_strtab;
    struct syminfo *next;
};

/* Filled in by elfload.c.  Simplistic, but will do for now. */
extern struct syminfo *syminfos;
#endif /* _LIBCPU_DISAS_H */
