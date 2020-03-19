/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
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

#include <glib.h>

#include <cpu/config.h>
#include "exec-phystb.h"
#include "exec.h"
#include "osdep.h"
#include "qemu-common.h"
#ifdef CONFIG_USER_KVM
#include <sys/mman.h>
#endif
/* This is a multi-level map on the virtual address space.
   The bottom level has pointers to PageDesc.  */
void *l1_map[V_L1_SIZE];

PageDesc *page_find_alloc(tb_page_addr_t index, int alloc) {
    PageDesc *pd;
    void **lp;
    int i;
#if defined(CONFIG_USER_KVM)
    /* We can't use g_malloc because it may recurse into a locked mutex. */
# define ALLOC(P, SIZE)                                 \
    do {                                                \
        P = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,    \
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   \
    } while (0)
#else
#define ALLOC(P, SIZE)       \
    do {                     \
        P = g_malloc0(SIZE); \
    } while (0)
#endif
    /* Level 1.  Always allocated.  */
    lp = l1_map + ((index >> V_L1_SHIFT) & (V_L1_SIZE - 1));

    /* Level 2..N-1.  */
    for (i = V_L1_SHIFT / L2_BITS - 1; i > 0; i--) {
        void **p = *lp;

        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            ALLOC(p, sizeof(void *) * L2_SIZE);
            *lp = p;
        }

        lp = p + ((index >> (i * L2_BITS)) & (L2_SIZE - 1));
    }

    pd = *lp;
    if (pd == NULL) {
        if (!alloc) {
            return NULL;
        }
        ALLOC(pd, sizeof(PageDesc) * L2_SIZE);
        *lp = pd;
    }

#undef ALLOC

    return pd + (index & (L2_SIZE - 1));
}

PageDesc *page_find(tb_page_addr_t index) {
    return page_find_alloc(index, 0);
}
