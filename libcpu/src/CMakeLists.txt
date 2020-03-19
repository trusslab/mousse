# Copyright 2016 - Cyberhaven
# Copyright (C) 2020, TrussLab@University of California, Irvine.
# Authors: Yingtong Liu <yingtong@uci.edu>
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
enable_language(ASM)

add_library(
    cpu exec.c cpus.c cpu-exec.c exec-bp.c exec-log.c exec-memdbg.c exec-phys.c exec-phystb.c exec-ram.c exec-tb.c exec-tlb.c host-utils.c ioport.c memory.c timer.c translate-all.c
    fpu/softfloat.c
    safe-syscall.S signal.c gdbstub.c mmap.c cpu-uname.c path.c cutils.c uaccess.c strace.c thunk.c syscall.c target-arm/helper.c target-arm/op_helper.c target-arm/translate.c target-arm/iwmmxt_helper.c target-arm/neon_helper.c target-arm/stubs.c target-arm/arm-dis.c disas.c cutils.c
)


target_include_directories (cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/target-arm
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/fpu
    ${CMAKE_BINARY_DIR}/include
)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__STDC_FORMAT_MACROS -D_GNU_SOURCE -DNEED_CPU_H  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DTARGET_PHYS_ADDR_BITS=64")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -Werror -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing -Wno-sign-compare -Wno-missing-field-initializers -Wno-mismatched-tags -Wno-deprecated-declarations -Wno-initializer-overrides -Wno-zero-length-array -Wno-unused-function -Wno-string-plus-int -Wno-empty-body -Wno-constant-conversion -Wno-shift-negative-value")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fexceptions")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -Wno-mismatched-tags -Werror -Wno-zero-length-array -Wno-unused-function -Wno-string-plus-int -Wno-empty-body")


if (WITH_SYMBEX)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_SYMBEX")

set(CARGS_LIST "${CMAKE_C_FLAGS}")
separate_arguments(CARGS_LIST)

get_property(dirs TARGET cpu PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
  set(BC_INC_DIRS "${BC_INC_DIRS} -I${dir}")
endforeach()
separate_arguments(BC_INC_DIRS)
add_custom_target(
    op_helper_bc ALL
    ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/target-arm/op_helper.c -c ${CARGS_LIST} -Wno-unused-function -O3 -DSYMBEX_LLVM_LIB -emit-llvm -o ${CMAKE_CURRENT_BINARY_DIR}/op_helper.bc
    ${BC_INC_DIRS}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/target-arm/op_helper.c
)
endif (WITH_SYMBEX)

MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )
MESSAGE( STATUS "WITH_SYMBEX: " ${WITH_SYMBEX} )
MESSAGE( STATUS "DIRS:" ${HOST_INCLUDE_DIR} ${TARGET_INCLUDE_DIR})
