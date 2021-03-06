/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017  Adrian Herrera
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

#ifndef __CPU_ARM_DEFS__
#define __CPU_ARM_DEFS__

// clang-format off

/*******************************************/

#define NB_MMU_MODES 2
#if defined(CONFIG_USER_ONLY)
#define TARGET_PAGE_BITS 10
#else
/* The ARM MMU allows 1k pages.  */
/* ??? Linux doesn't actually use these, and they're deprecated in recent
   architecture revisions.  Maybe a configure option to disable them.  */
#define TARGET_PAGE_BITS 10
#endif
////#define TARGET_HAS_ICE 1

#ifdef CONFIG_USER_KVM
#define NO_EXCP         19
#endif

#endif
