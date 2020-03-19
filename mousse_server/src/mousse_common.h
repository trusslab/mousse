/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef MOUSSE_COMMON_H
#define MOUSSE_COMMON_H
#include <stdint.h>

#define INPUT_BUF_SIZE 20000
#define BIN_NAME_BUF_SIZE 124

#define THIS(s) (s & 0xffff)
#define FROM(s) (s >> 16)

#define FORK_COUNTERS_SIZE 128

typedef struct fork_counter_t {
    uint64_t hash;
    uint32_t count;
} fork_counter_t;

typedef struct fork_counters_t {
    fork_counter_t counter[FORK_COUNTERS_SIZE];
} fork_counters_t;

typedef struct syscall_symbolic_output_t {
    uint32_t syscall_num;
    uint32_t count;
    uint64_t hash;
} syscall_symbolic_output_t;

typedef struct state_t {
    uint32_t id; // [31:16] forked state id, [15:0] parent state id
    uint32_t ignore_depth;
    uint8_t input_buf[INPUT_BUF_SIZE];
    syscall_symbolic_output_t syscall_output[10];
} state_t;

#define BUG_C_R_NULLPTR           1
#define BUG_C_W_CODE              2
#define BUG_C_W_RETPTR            3
#define BUG_C_W_STACKANDHEAP      4
#define BUG_C_LIBC_DOUBLEFREE     5
#define BUG_C_LIBC_UNALLOCHEAP    6
#define BUG_S 0x80000000
#define BUG_S_MEMACCESS           0 | BUG_S
#define BUG_S_R_NULLPTR           1 | BUG_S
#define BUG_S_W_CODE              2 | BUG_S
#define BUG_S_W_RETPTR            3 | BUG_S
#define BUG_S_W_STACKANDHEAP      4 | BUG_S
#define BUG_S_LIBC_DOUBLEFREE     5 | BUG_S
#define BUG_S_LIBC_UNALLOCHEAP    6 | BUG_S

typedef struct bug_t {
    uint32_t state_id;
    uint32_t addr;
    uint32_t insn;
    uint32_t type;
    uint32_t cs_size;
    uint32_t cs2_size;
    uint8_t binary_name_buf[BIN_NAME_BUF_SIZE];
} bug_t;

typedef struct cs_entry_t {
    uint32_t addr;
    uint8_t binary_name_buf[124];
} cs_entry_t;

#define STATUS_MASK             0xffff0000
#define STATUS_REBOOT           0x10000000
#define STATUS_START            0x20000000
#define STATUS_TEST             0x40000000
#define STATUS_TERM             0x80000000
#define STATUS_TERM_UNKNOWN     0 | STATUS_TERM
#define STATUS_TERM_TIMEOUT     1 | STATUS_TERM
#define STATUS_TERM_SYSCALL     2 | STATUS_TERM
#define STATUS_TERM_TEST_FINISH 3 | STATUS_TERM
#define STATUS_TERM_EXIT        4 | STATUS_TERM
#define STATUS_TERM_REACH_FORK_LIMIT        5 | STATUS_TERM

typedef struct status_t {
    uint32_t state_id;
    uint32_t status;
    uint32_t duration;
} status_t;

#define SYM_SYSCALL_HAS_FD  0x10000000
#define SYM_SYSCALL_PTR_ARG 0x10000000

typedef struct sym_syscall_t {
    uint32_t state_id;
    uint32_t num;
    uint32_t symbolic; // [31] has fd, [30] is ptr, [2:0] reg num
    uint8_t fd_name_buf[BIN_NAME_BUF_SIZE];
} sym_syscall_t;

typedef struct tbs_header_t {
    uint32_t state_id;
    uint32_t size;
} tbs_header_t;

typedef struct tb_header_t {
    uint32_t size;
    uint8_t binary_name_buf[BIN_NAME_BUF_SIZE];
} tb_header_t;

typedef struct tb_t {
    uint32_t start_pc;
    uint32_t last_pc;
} tb_t;

typedef struct signal_t {
    uint32_t state_id;
    uint32_t signal;
} signal_t;

#define OPC_SIZE 4 //byte
#define OP_BUF_SIZE(op) (op & 0xffffff)
#define OPC_R 0x00000000
#define OPC_W 0x80000000
#define OPC_Q 0x40000000

// |31|30|29:23|23:0|
// |RW| Q|   OP|SIZE|

#define DEFINE_OPC_W(num, size, name) \
    const uint32_t OPC_W_##name = OPC_W | num << 24 | size;
#define DEFINE_OPC_R(num, size, name) \
    const uint32_t OPC_R_##name = OPC_R | num << 24 | size;
#define DEFINE_OPC_Q(num, size, name) \
    const uint32_t OPC_Q_##name = OPC_Q | num << 24 | size;

#define OPC_REPLY_SUCCESS 0
#define OPC_REPLY_FAILURE 1

DEFINE_OPC_R(1, sizeof(state_t),         GET_STATE)
DEFINE_OPC_R(2, 4,                       GET_STATE_ID)
DEFINE_OPC_R(3, sizeof(fork_counters_t), GET_FORK_COUNTERS)

DEFINE_OPC_Q(1, 4,                       INC_AND_GET_FORK_COUNTER)

DEFINE_OPC_W(1, sizeof(state_t),         OFFLOAD_STATE)
DEFINE_OPC_W(2, sizeof(state_t),         FORK_STATE)
DEFINE_OPC_W(3, sizeof(state_t),         TEMP_FORK_STATE)
DEFINE_OPC_W(4, sizeof(bug_t),           BUG)
DEFINE_OPC_W(5, sizeof(state_t),         BUG_INPUTS)
DEFINE_OPC_W(6, sizeof(sym_syscall_t),   SYSCALL)
DEFINE_OPC_W(7, sizeof(status_t),        STATUS)
DEFINE_OPC_W(8, 4,                       IS_SYMBOLIC)
DEFINE_OPC_W(9, sizeof(tbs_header_t),    TBS_HEADER)
DEFINE_OPC_W(10,sizeof(signal_t),        GOT_SIGNAL)
DEFINE_OPC_W(11,sizeof(fork_counters_t), UPDATE_FORK_COUNTERS)

#endif // MOUSSE_COMMON_H
