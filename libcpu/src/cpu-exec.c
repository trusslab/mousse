/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
/// 	Authors: Yingtong Liu <yingtong@uci.edu> Hsin-Wei Hung <hsinweih@uci.edu>
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
#include <cpu/config.h>
#include <tcg/tcg.h>
#include "cpu.h"

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif
#include "syscall_hdr.h"
#define barrier() asm volatile("" ::: "memory")
#if defined(CONFIG_SYMBEX)
#include "tcg/tcg-llvm.h"
const int has_llvm_engine = 1;
#endif
#ifdef CONFIG_USER_KVM
extern const char *qemu_uname_release;
extern char *exec_path;
#endif

int generate_llvm = 0;

int tb_invalidated_flag;

struct cpu_stats_t g_cpu_stats;

#ifdef CONFIG_SYMBEX
static int tb_invalidate_before_fetch = 0;

void se_tb_safe_flush(void) {
    tb_invalidate_before_fetch = 1;
}
#endif
#define CONFIG_DEBUG_EXEC
/* copied from qemu/linux-user/main.c */
/***********************************************************/
#ifndef DISABLE_THREAD_LOCK
static pthread_mutex_t guest_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifdef ENABLE_THREAD_COND_LOCK
static pthread_cond_t guest_thread_cond = PTHREAD_COND_INITIALIZER;
static bool guest_thread_predicate = 0;
#endif
#endif

void guest_thread_lock(void)
{
#ifndef DISABLE_THREAD_LOCK
    pthread_mutex_lock(&guest_thread_mutex);
    g_sqi.exec.update_klee_cpu(env);
#endif
}

void guest_thread_unlock(void)
{
#ifndef DISABLE_THREAD_LOCK
    pthread_mutex_unlock(&guest_thread_mutex);
#endif
}
static void guest_thread_cond_wait(void)
{
#if !defined(DISABLE_THREAD_LOCK) && defined(ENABLE_THREAD_COND_LOCK) 
    if(guest_thread_predicate) {
          pthread_cond_wait(&guest_thread_cond,&guest_thread_mutex);
    }
#endif
}
void guest_thread_cond_lock(void)
{
#ifndef DISABLE_THREAD_LOCK
     guest_thread_lock();
#ifdef ENABLE_THREAD_COND_LOCK
     guest_thread_cond_wait();
#endif
#endif
}

static void guest_thread_cond_signal(void)
{
#if !defined(DISABLE_THREAD_LOCK) && defined(ENABLE_THREAD_COND_LOCK) 
     pthread_cond_broadcast(&guest_thread_cond);
#endif
}
void set_guest_thread_predicate(void)
{
#if !defined(DISABLE_THREAD_LOCK) && defined(ENABLE_THREAD_COND_LOCK) 
    guest_thread_predicate = 1;
#endif
}
void unset_guest_thread_predicate_and_signal(void)
{
#if !defined(DISABLE_THREAD_LOCK) && defined(ENABLE_THREAD_COND_LOCK) 
    if(guest_thread_predicate) {
         guest_thread_predicate = 0;
         guest_thread_cond_signal();
    }
#endif
}
//#define DISABLE_EXCLUSIVE_LOCK
#if defined(CONFIG_USE_NPTL) && !defined(DISABLE_EXCLUSIVE_LOCK)
/* Helper routines for implementing atomic operations.  */

/* To implement exclusive operations we force all cpus to syncronise.
   We don't require a full sync, only that no cpus are executing guest code.
   The alternative is to map target atomic ops onto host equivalents,
   which requires quite a lot of per host/target work.  */
/* Make sure everything is in a consistent state for calling fork().  */
static pthread_mutex_t cpu_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t exclusive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exclusive_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t exclusive_resume = PTHREAD_COND_INITIALIZER;
static int pending_cpus;

void fork_start(void)
{
    pthread_mutex_lock((pthread_mutex_t *)&tb_lock);
    pthread_mutex_lock(&exclusive_lock);
    mmap_fork_start();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        first_cpu = env;
        env->next_cpu = NULL;
        pending_cpus = 0;
        pthread_mutex_init(&exclusive_lock, NULL);
        pthread_mutex_init(&cpu_list_mutex, NULL);
        pthread_cond_init(&exclusive_cond, NULL);
        pthread_cond_init(&exclusive_resume, NULL);
        pthread_mutex_init((pthread_mutex_t *)&tb_lock, NULL);
        gdbserver_fork(env);
    } else {
        pthread_mutex_unlock(&exclusive_lock);
        pthread_mutex_unlock((pthread_mutex_t *)&tb_lock);
    }
}

/* Wait for pending exclusive operations to complete.  The exclusive lock
   must be held.  */
static inline void exclusive_idle(void)
{
    while (pending_cpus) {
        pthread_cond_wait(&exclusive_resume, &exclusive_lock);
    }
}

/* Start an exclusive operation.
   Must only be called from outside cpu_arm_exec.   */
static inline void start_exclusive(void)
{
    CPUArchState *other;
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();

    pending_cpus = 1;
    /* Make all other cpus stop executing.  */
    for (other = first_cpu; other; other = other->next_cpu) {
        if (other->running) {
            pending_cpus++;
            cpu_exit(other);
        }
    }
    if (pending_cpus > 1) {
        pthread_cond_wait(&exclusive_cond, &exclusive_lock);
    }
}

/* Finish an exclusive operation.  */
static inline void end_exclusive(void)
{
    pending_cpus = 0;
    pthread_cond_broadcast(&exclusive_resume);
    pthread_mutex_unlock(&exclusive_lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution.  */
static inline void cpu_exec_start(CPUArchState *env)
{
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();
    env->running = 1;
    pthread_mutex_unlock(&exclusive_lock);
}

/* Mark cpu as not executing, and release pending exclusive ops.  */
static inline void cpu_exec_end(CPUArchState *env)
{
    pthread_mutex_lock(&exclusive_lock);
    env->running = 0;
    if (pending_cpus > 1) {
        pending_cpus--;
        if (pending_cpus == 1) {
            pthread_cond_signal(&exclusive_cond);
        }
    }
    exclusive_idle();
    pthread_mutex_unlock(&exclusive_lock);
}

void cpu_list_lock(void)
{
    pthread_mutex_lock(&cpu_list_mutex);
}

void cpu_list_unlock(void)
{
    pthread_mutex_unlock(&cpu_list_mutex);
}


#else /* if !CONFIG_USE_NPTL */
/* These are no-ops because we are not threadsafe.  */
void cpu_exec_start(CPUArchState *env)
{
}

void cpu_exec_end(CPUArchState *env)
{
}

void start_exclusive(void)
{
}

void end_exclusive(void)
{
}

void fork_start(void)
{
    assert(0 && "fixme for fork\n");
}

void fork_end(int child)
{
    if (child) {
        gdbserver_fork(env);
    }
}

void cpu_list_lock(void)
{
}

void cpu_list_unlock(void)
{
}
#endif
void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;
 
    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

void evaluate_values_for_regs(char *name, CPUArchState *env, uint32_t regs0, uint32_t regs1, uint32_t regs2, uint32_t regs3, uint32_t regs4, uint32_t regs5, uint32_t regs6, uint32_t regs7) {
	env->regs[0] = regs0;
	env->regs[1] = regs1;
	env->regs[2] = regs2;
	env->regs[3] = regs3;
	env->regs[4] = regs4;
	env->regs[5] = regs5;
	env->regs[6] = regs6;
	env->regs[7] = regs7;
}

void evaluate_values_for_regs_1(CPUArchState *env, uint32_t regs0, uint32_t regs1, uint32_t regs2, uint32_t regs3, uint32_t regs4, uint32_t regs5, uint32_t regs6, uint32_t regs7, uint32_t exclusive_info) {
	env->regs[0] = regs0;
	env->regs[1] = regs1;
	env->regs[2] = regs2;
	env->regs[3] = regs3;
	env->regs[4] = regs4;
	env->regs[5] = regs5;
	env->regs[6] = regs6;
	env->regs[7] = regs7;
	env->exclusive_info = exclusive_info;
}

void evaluate_value_for_reg(char *name, CPUArchState *env, int reg, uint32_t value) {
    env->regs[reg] = value;
}

void cpu_loop_exit(CPUArchState *env) {
    env->current_tb = NULL;
    longjmp(env->jmp_env, 1);
}

/* exit the current TB from a signal handler. The host registers are
   restored in a state compatible with the CPU emulator
 */
#if defined(CONFIG_SOFTMMU) || defined(CONFIG_USER_KVM)
void cpu_resume_from_signal(CPUArchState *env, void *puc) {
    /* XXX: restore cpu registers saved in host registers */

    env->exception_index = -1;
    longjmp(env->jmp_env, 1);
}
#endif

static TranslationBlock *tb_find_slow(CPUArchState *env, target_ulong pc, target_ulong cs_base, uint64_t flags) {
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    target_ulong virt_page2;

    tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
    phys_pc = get_page_addr_code(env, pc);
    phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = &tb_phys_hash[h];
    for (;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;
        if (tb->pc == pc && tb->page_addr[0] == phys_page1 && tb->cs_base == cs_base && tb->flags == flags) {
            /* check next page if needed */
            if (tb->page_addr[1] != -1) {
                tb_page_addr_t phys_page2;

                virt_page2 = (pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
                phys_page2 = get_page_addr_code(env, virt_page2);
                if (tb->page_addr[1] == phys_page2)
                    ++g_cpu_stats.tb_misses;
                goto found;
            } else {
                ++g_cpu_stats.tb_misses;
                goto found;
            }
        }
        ptb1 = &tb->phys_hash_next;
    }
not_found:
    /* if no translated code available, then translate it now */
    tb = tb_gen_code(env, pc, cs_base, flags, 0);
    ++g_cpu_stats.tb_regens;

found:
    /* Move the last found TB to the head of the list */
    if (likely(*ptb1)) {
        *ptb1 = tb->phys_hash_next;
        tb->phys_hash_next = tb_phys_hash[h];
        tb_phys_hash[h] = tb;
    }
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

static inline TranslationBlock *tb_find_fast(CPUArchState *env) {
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    int flags;

/**
 * Plugin code cannot usually invalidate the TB cache safely
 * because it would also detroy the currently running code.
 * Instead, flush the cache at the next TB fetch.
 */
#ifdef CONFIG_SYMBEX
    if (tb_invalidate_before_fetch) {
        tb_invalidate_before_fetch = 0;
        tb_flush(env);
    }
#endif

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base || tb->flags != flags)) {
        tb = tb_find_slow(env, pc, cs_base, flags);
    } else {
        ++g_cpu_stats.tb_hits;
    }
    return tb;
}

static CPUDebugExcpHandler *debug_excp_handler;

CPUDebugExcpHandler *cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler) {
    CPUDebugExcpHandler *old_handler = debug_excp_handler;

    debug_excp_handler = handler;
    return old_handler;
}

static void cpu_handle_debug_exception(CPUArchState *env) {
    CPUWatchpoint *wp;

    if (!env->watchpoint_hit) {
        QTAILQ_FOREACH (wp, &env->watchpoints, entry) { wp->flags &= ~BP_WATCHPOINT_HIT; }
    }
    if (debug_excp_handler) {
        debug_excp_handler(env);
    }
}

/*****************************************************************/

/* main execution loop */

volatile sig_atomic_t exit_request;
extern int g_s2e_fast_concrete_invocation;
extern uint8_t *g_code_gen_ptr;
static uintptr_t fetch_and_run_tb(uintptr_t prev_tb, CPUArchState *env) {
    uint8_t *tc_ptr;
    uintptr_t next_tb;
    TranslationBlock *tb = tb_find_fast(env);
    /* Note: we do it here to avoid a gcc bug on Mac OS X when
       doing it in tb_find_slow */
    if (tb_invalidated_flag) {
        /* as some TB could have been invalidated because
           of memory exceptions while generating the code, we
           must recompute the hash index here */
        prev_tb = 0;
        tb_invalidated_flag = 0;
    }

#ifdef CONFIG_DEBUG_EXEC
    libcpu_log_mask(CPU_LOG_EXEC, "Trace 0x%08lx [" TARGET_FMT_lx "] \n", (long) tb->tc_ptr, tb->pc);
#endif
    /*
     * see if we can patch the calling TB. When the TB
     * spans two pages, we cannot safely do a direct jump.
     */
    if (prev_tb != 0 && tb->page_addr[1] == -1) {
        tb_add_jump((TranslationBlock *) (prev_tb & ~3), prev_tb & 3, tb);
    }

    /* cpu_interrupt might be called while translating the
       TB, but before it is linked into a potentially
       infinite loop and becomes env->current_tb. Avoid
       starting execution if there is a pending interrupt. */
    env->current_tb = tb;
    barrier();
    if (unlikely(env->exit_request)) {
        env->current_tb = NULL;
        return 0;
    }

    tc_ptr = tb->tc_ptr;
#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
//    assert(env->eip == env->precise_eip);
#endif

/* execute the generated code */

#if defined(CONFIG_SYMBEX)
    env->se_current_tb = tb;
    if (likely(*g_sqi.mode.fast_concrete_invocation && **g_sqi.mode.running_concrete)) {
        **g_sqi.mode.running_exception_emulation_code = 0;
        next_tb = tcg_libcpu_tb_exec(env, tc_ptr);
    } else {
        next_tb = g_sqi.exec.tb_exec(env, tb);
    }
    env->se_current_tb = NULL;
#else

#ifdef TRACE_EXEC
    printf("eip=%lx eax=%lx ebx=%lx ecx=%lx edx=%lx esi=%lx edi=%lx ebp=%lx esp=%lx\n", (uint64_t) env->eip,
           (uint64_t) env->regs[R_EAX], (uint64_t) env->regs[R_EBX], (uint64_t) env->regs[R_ECX],
           (uint64_t) env->regs[R_EDX], (uint64_t) env->regs[R_ESI], (uint64_t) env->regs[R_EDI],
           (uint64_t) env->regs[R_EBP], (uint64_t) env->regs[R_ESP]);
    * /
#endif

        next_tb = tcg_libcpu_tb_exec(env, tc_ptr);
#endif

    env->current_tb = NULL;
    return next_tb;
}

static bool process_interrupt_request(CPUArchState *env) {
    int interrupt_request = env->interrupt_request;
    if (likely(!interrupt_request)) {
        return false;
    }

    bool has_interrupt = false;

    if (unlikely(env->singlestep_enabled & SSTEP_NOIRQ)) {
        /* Mask out external interrupts for this step. */
        interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
    }
    if (interrupt_request & CPU_INTERRUPT_DEBUG) {
        env->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
        env->exception_index = EXCP_DEBUG;
        cpu_loop_exit(env);
    }
#if defined(TARGET_ARM) || defined(TARGET_SPARC) || defined(TARGET_MIPS) || \
    defined(TARGET_PPC) || defined(TARGET_ALPHA) || defined(TARGET_CRIS) || \
    defined(TARGET_MICROBLAZE)
    if (interrupt_request & CPU_INTERRUPT_HALT) {
        env->interrupt_request &= ~CPU_INTERRUPT_HALT;
        env->halted = 1;
        env->exception_index = EXCP_HLT;
        cpu_loop_exit(env);
    }
#endif

#ifdef TARGET_I386
    if (interrupt_request & CPU_INTERRUPT_INIT) {
        svm_check_intercept(env, SVM_EXIT_INIT);
        do_cpu_init(env);
        env->exception_index = EXCP_HALTED;
        cpu_loop_exit(env);
    } else if (interrupt_request & CPU_INTERRUPT_SIPI) {
        do_cpu_sipi(env);
        perror("Not implemented");
    } else if (env->hflags2 & HF2_GIF_MASK) {
        if ((interrupt_request & CPU_INTERRUPT_SMI) && !(env->hflags & HF_SMM_MASK)) {
            svm_check_intercept(env, SVM_EXIT_SMI);
            env->interrupt_request &= ~CPU_INTERRUPT_SMI;
            do_smm_enter(env);
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_NMI) && !(env->hflags2 & HF2_NMI_MASK)) {
            env->interrupt_request &= ~CPU_INTERRUPT_NMI;
            env->hflags2 |= HF2_NMI_MASK;
            do_interrupt_x86_hardirq(env, EXCP02_NMI, 1);
            has_interrupt = true;
        } else if (interrupt_request & CPU_INTERRUPT_MCE) {
            env->interrupt_request &= ~CPU_INTERRUPT_MCE;
            do_interrupt_x86_hardirq(env, EXCP12_MCHK, 0);
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_HARD) &&
                   (((env->hflags2 & HF2_VINTR_MASK) && (env->hflags2 & HF2_HIF_MASK)) ||
                    (!(env->hflags2 & HF2_VINTR_MASK) &&
                     (env->mflags & IF_MASK && !(env->hflags & HF_INHIBIT_IRQ_MASK))))) {
            int intno;
            svm_check_intercept(env, SVM_EXIT_INTR);
            env->interrupt_request &= ~(CPU_INTERRUPT_HARD | CPU_INTERRUPT_VIRQ);
            intno = cpu_get_pic_interrupt(env);

            libcpu_log_mask(CPU_LOG_INT, "Servicing hardware INT=0x%02x\n", intno);
            if (intno >= 0) {
#ifdef SE_KVM_DEBUG_IRQ
#endif

                do_interrupt_x86_hardirq(env, intno, 1);
            }

            /* ensure that no TB jump will be modified as
                   the program flow was changed */
            has_interrupt = true;
#ifndef CONFIG_USER_KVM
        } else if ((interrupt_request & CPU_INTERRUPT_VIRQ) && (env->mflags & IF_MASK) &&
                   !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
            int intno;
            /* FIXME: this should respect TPR */
            svm_check_intercept(env, SVM_EXIT_VINTR);
            intno = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_vector));
            libcpu_log_mask(CPU_LOG_TB_IN_ASM, "Servicing virtual hardware INT=0x%02x\n", intno);
            do_interrupt_x86_hardirq(env, intno, 1);
            env->interrupt_request &= ~CPU_INTERRUPT_VIRQ;
            has_interrupt = true;
#endif
        }
    }
#elif defined(TARGET_ARM)
    if (interrupt_request & CPU_INTERRUPT_FIQ
        && !(env->uncached_cpsr & CPSR_F)) {
        env->exception_index = EXCP_FIQ;
        do_interrupt(env);
        has_interrupt = true;
        //next_tb = 0;
    }
    /* ARMv7-M interrupt return works by loading a magic value
       into the PC.  On real hardware the load causes the
       return to occur.  The qemu implementation performs the
       jump normally, then does the exception return when the
       CPU tries to execute code at the magic address.
       This will cause the magic PC value to be pushed to
       the stack if an interrupt occured at the wrong time.
       We avoid this by disabling interrupts when
       pc contains a magic address.  */
    if (interrupt_request & CPU_INTERRUPT_HARD
        && ((IS_M(env) && env->regs[15] < 0xfffffff0)
        || !(env->uncached_cpsr & CPSR_I))) {
        env->exception_index = EXCP_IRQ;
        do_interrupt(env);
        has_interrupt = true;
        //next_tb = 0;
    }
#else
#error unsopported architecture
#endif

    /* Don't use the cached interrupt_request value,
          do_interrupt may have updated the EXITTB flag. */
    if (env->interrupt_request & CPU_INTERRUPT_EXITTB) {
    fprintf(stderr, "%s [6]: interrupt_request = %d\n", __FUNCTION__, interrupt_request);
        env->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
        has_interrupt = true;
    }

    return has_interrupt;
}

static int process_exceptions(CPUArchState *env) {
    int ret = 0;

    if (env->exception_index < 0) {
        return ret;
    }

    /* if an exception is pending, we execute it here */
    if (env->exception_index >= EXCP_INTERRUPT) {
        /* exit request from the cpu execution loop */
        ret = env->exception_index;
        if (ret == EXCP_DEBUG) {
            cpu_handle_debug_exception(env);
        }
    } else {
        do_interrupt(env);
        env->exception_index = -1;
    }

    return ret;
}

static bool execution_loop(CPUArchState *env) {
    uintptr_t next_tb = 0;

    for (;;) {
        bool has_interrupt = false;
        if (process_interrupt_request(env)) {
            /*
             * ensure that no TB jump will be modified as
             * the program flow was changed
             */
            next_tb = 0;
            has_interrupt = true;
        }

        if (unlikely(!has_interrupt && env->exit_request)) {
            env->exit_request = 0;
            env->exception_index = EXCP_INTERRUPT;

            // XXX: return status code instead
            cpu_loop_exit(env);
        }

        env->exit_request = 0;

#if defined(DEBUG_DISAS) || defined(CONFIG_DEBUG_EXEC)
        if (libcpu_loglevel_mask(CPU_LOG_TB_CPU)) {
/* restore flags in standard format */
#if defined(TARGET_I386)
            /*env->eflags = env->eflags | cpu_cc_compute_all(env, CC_OP)
                | (DF & DF_MASK); */
            log_cpu_state(env, X86_DUMP_CCOP);
            // env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
            log_cpu_state(env, 0);
#elif defined(TARGET_ARM)
            log_cpu_state(env, 0);
#endif
        }
#endif /* DEBUG_DISAS || CONFIG_DEBUG_EXEC */
        next_tb = fetch_and_run_tb(next_tb, env);
#ifdef TARGET_I386
        if (env->kvm_request_interrupt_window && (env->mflags & IF_MASK)) {
            env->kvm_request_interrupt_window = 0;
            return true;
        }
#elif defined(TARGET_ARM)
        if (env->kvm_request_interrupt_window) {
            env->kvm_request_interrupt_window = 0;
            return true;
        }
#else
#error wrong architecture
#endif
    }

    return false;
}

int cpu_exec(CPUArchState *env) {
    int ret;
    if (env->halted) {
        if (!cpu_has_work(env)) {
		assert(0 && "Mousse: EXCP_HALTED failed\n");
            return EXCP_HALTED;
        }

        env->halted = 0;
    }

    cpu_single_env = env;

    if (unlikely(exit_request)) {
        env->exit_request = 1;
    }

#ifdef CONFIG_SYMBEX
    if (!g_sqi.exec.is_runnable()) {
        if (g_sqi.exec.is_yielded()) 
        {
            fprintf(stderr, "%s: calling g_sqi.exec.reset_state_switch_timer()\n",__FUNCTION__);
            g_sqi.exec.reset_state_switch_timer();
        }
        return EXCP_SE;
    }
#endif
    env->exception_index = -1;

    /* prepare setjmp context for exception handling */
    for (;;) {
        if (setjmp(env->jmp_env) == 0) {
            /**
             * It is important to reset the current TB everywhere where the CPU loop exits.
             * Otherwise, TB unchaining might get stuck on the next signal.
             * This usually happens when TB cache is flushed but current tb is not reset.
             */
            env->current_tb = NULL;
#ifdef CONFIG_SYMBEX
            assert(env->exception_index != EXCP_SE);
            if (g_sqi.exec.finalize_tb_exec()) {
                g_sqi.exec.cleanup_tb_exec();
                if (env->exception_index == EXCP_SE) {
                    cpu_single_env = NULL;
                    env->current_tb = NULL;
                    return EXCP_SE;
                }
                continue;
            }
#endif
#ifndef CONFIG_USER_KVM
            ret = process_exceptions(env);
            if (ret) {
                if (ret == EXCP_HLT && env->interrupt_request) {
                    env->exception_index = -1;
                    env->halted = 0;
                    continue;
                }
                break;
            }
#else
            ret = NO_EXCP;
            /* if an exception is pending, we execute it here */
            if (env->exception_index >= 0) {
                if (env->exception_index >= EXCP_INTERRUPT) {
                    /* exit request from the cpu execution loop */
                    ret = env->exception_index;
                    if (ret == EXCP_DEBUG) {
                        assert(0 && "Mousse: EXCP_DEBUG failed\n");
                        cpu_handle_debug_exception(env);
                    }
                    if (ret == EXCP_HLT && env->interrupt_request) {
                        assert(0 && "Mousse: EXCP_HLT failed\n");
                        env->exception_index = -1;
                        env->halted = 0;
                        continue;
                	}
                    break;
                } else {
#ifdef TARGET_I386
                    do_interrupt(env);
#endif
                    /* syscall exception and do_strex will go to this path */
                    ret = env->exception_index;
                    break;
                }
            }
#endif
            if (execution_loop(env)) {
                break;
            }
        } else {
#ifdef CONFIG_SYMBEX
            g_sqi.exec.cleanup_tb_exec();
            if (!g_sqi.exec.is_runnable()) {
                cpu_single_env = NULL;
                env->current_tb = NULL;
                return EXCP_SE;
            }
#endif
            /* Reload env after longjmp - the compiler may have smashed all
             * local variables as longjmp is marked 'noreturn'. */
            env = cpu_single_env;
        } /* else (setjmp) */
    } /* for(;;) */

    env->current_tb = NULL;

#if defined(TARGET_I386)
#ifdef CONFIG_SYMBEX
   g_sqi.regs.set_cc_op_eflags(env);
#else
    /* restore flags in standard format */
    WR_cpu(env, cc_src, cpu_cc_compute_all(env, CC_OP));
    WR_cpu(env, cc_op, CC_OP_EFLAGS);
    /* This mask corresponds to bits that must be 0 in eflags */
    assert(((env->mflags | env->cc_src) & 0xffc08028) == 0);
#endif

#elif defined(TARGET_ARM)
/* XXX: Save/restore host fpu exception state?.  */
#ifdef CONFIG_SYMBEX
    g_sqi.regs.set_cc_op_eflags(env);
#endif
#elif defined(TARGET_UNICORE32)
#elif defined(TARGET_SPARC)
#elif defined(TARGET_PPC)
#elif defined(TARGET_LM32)
#elif defined(TARGET_M68K)
    cpu_m68k_flush_flags(env, env->cc_op);
    env->cc_op = CC_OP_FLAGS;
    env->sr = (env->sr & 0xffe0) | env->cc_dest | (env->cc_x << 4);
#elif defined(TARGET_MICROBLAZE)
#elif defined(TARGET_MIPS)
#elif defined(TARGET_SH4)
#elif defined(TARGET_ALPHA)
#elif defined(TARGET_CRIS)
#elif defined(TARGET_S390X)
#elif defined(TARGET_XTENSA)
/* XXXXX */
#else
#error unsupported target CPU
#endif

    env->current_tb = NULL;

    /* fail safe : never use cpu_single_env outside cpu_exec() */
    cpu_single_env = NULL;
    return ret;
}
#if defined(CONFIG_USER_KVM) && defined(TARGET_I386)
void process_cpu_x86_exec(CPUX86State *env)
{
    int trapnr;
    target_ulong pc;
    target_siginfo_t info;
    for(;;) {
    trapnr = cpu_x86_exec(env);
        switch(trapnr) {
        case 0x80:
	    assert(false && "To be implemented\n");
            /* linux syscall from int $0x80 */
            env->regs[R_EAX] = do_syscall(env,
                                          env->regs[R_EAX],
                                          env->regs[R_EBX],
                                          env->regs[R_ECX],
                                          env->regs[R_EDX],
                                          env->regs[R_ESI],
                                          env->regs[R_EDI],
                                          env->regs[R_EBP],
                                          0, 0);
            break;
#ifndef TARGET_ABI32
        case EXCP_SYSCALL:

//reading concrete register values
            env->regs[R_EAX] = RR_cpu(env, regs[R_EAX]);
            env->regs[R_EDX] = RR_cpu(env, regs[R_EDX]);
            env->regs[R_ESI] = RR_cpu(env, regs[R_ESI]);
            env->regs[R_EDI] = RR_cpu(env, regs[R_EDI]);
            env->regs[8] = RR_cpu(env, regs[8]);
            env->regs[9] = RR_cpu(env, regs[9]);
            env->regs[10] = RR_cpu(env, regs[10]);
            /* linux syscall from syscall instruction */
	  	  	EAX_W(do_syscall(env,
                                          env->regs[R_EAX],
                                          env->regs[R_EDI],
                                          env->regs[R_ESI],
                                          env->regs[R_EDX],
                                          env->regs[10],
                                          env->regs[8],
                                          env->regs[9],
                                          0, 0));
            env->eip = env->exception_next_eip;
            break;
#endif
        case EXCP0B_NOSEG:
	    assert(false && "To be implemented\n");
        case EXCP0C_STACK:
	    assert(false && "To be implemented\n");
            info.si_signo = SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0D_GPF:
	    assert(false && "To be implemented\n");
            /* XXX: potential problem if ABI32 */
#ifndef TARGET_X86_64
            if (env->mflags & VM_MASK) {
                handle_vm86_fault(env);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP0E_PAGE:
	    assert(false && "To be implemented\n");
            info.si_signo = SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP00_DIVZ:
	        assert(false && "To be implemented\n");
            {
                /* division by zero */
                info.si_signo = SIGFPE;
                info.si_errno = 0;
                info.si_code = TARGET_FPE_INTDIV;
                info._sifields._sigfault._addr = env->eip;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP01_DB:
	    assert(false && "To be implemented\n");
        case EXCP03_INT3:
	        assert(false && "To be implemented\n");
            break;
        case EXCP04_INTO:
	        assert(false && "To be implemented\n");
        case EXCP05_BOUND:
	        assert(false && "To be implemented\n");
        case EXCP06_ILLOP:
	        assert(false && "To be implemented\n");
        case EXCP_INTERRUPT:
		    return;
        case EXCP_DEBUG:
	        assert(false && "To be implemented\n");
            break;
#ifdef CONFIG_SYMBEX
	case EXCP_SE:
		return;
#endif
	case EXCP_HALTED:
		return;
	case EXCP_HLT:
		return;
	case NO_EXCP:
		return;
        default:
//FIXME, hanle system cpu execption, eg EXCP_SE 0x10004
            pc = env->segs[R_CS].base + env->eip;
            return;
    	}
	process_pending_signals(env);
    }
}
#endif

#if defined(CONFIG_USER_KVM) && defined(TARGET_ARM)
/* copied from main.c: start */
#define get_user_code_u32(x, gaddr, doswap)             \
    ({ abi_long __r = get_user_u32((x), (gaddr));       \
        if (!__r && (doswap)) {                         \
            (x) = bswap32(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_code_u16(x, gaddr, doswap)             \
    ({ abi_long __r = get_user_u16((x), (gaddr));       \
        if (!__r && (doswap)) {                         \
            (x) = bswap16(x);                           \
        }                                               \
        __r;                                            \
    })

/*
 * See the Linux kernel's Documentation/arm/kernel_user_helpers.txt
 * Input:
 * r0 = pointer to oldval
 * r1 = pointer to newval
 * r2 = pointer to target value
 *
 * Output:
 * r0 = 0 if *ptr was changed, non-0 if no exchange happened
 * C set if *ptr was changed, clear if no exchange happened
 *
 * Note segv's in kernel helpers are a bit tricky, we can set the
 * data address sensibly but the PC address is just the entry point.
 */
static void arm_kernel_cmpxchg64_helper(CPUARMState *env)
{
    uint64_t oldval, newval, val;
    uint32_t addr, cpsr;
    target_siginfo_t info;

    /* Based on the 32 bit code in do_kernel_trap */

    /* XXX: This only works between threads, not between processes.
       It's probably possible to implement this with native host
       operations. However things like ldrex/strex are much harder so
       there's not much point trying.  */
    start_exclusive();
    cpsr = cpsr_read(env);
    addr = env->regs[2];

    if (get_user_u64(oldval, env->regs[0])) {
        env->cp15.c6_data = env->regs[0];
        goto segv;
    };

    if (get_user_u64(newval, env->regs[1])) {
        env->cp15.c6_data = env->regs[1];
        goto segv;
    };

    if (get_user_u64(val, addr)) {
        env->cp15.c6_data = addr;
        goto segv;
    }

    if (val == oldval) {
        val = newval;

        if (put_user_u64(val, addr)) {
            env->cp15.c6_data = addr;
            goto segv;
        };

        env->regs[0] = 0;
        cpsr |= CPSR_C;
    } else {
        env->regs[0] = -1;
        cpsr &= ~CPSR_C;
    }
    cpsr_write(env, cpsr, CPSR_C);
    end_exclusive();
    return;

segv:
    end_exclusive();
    /* We get the PC of the entry address - which is as good as anything,
       on a real kernel what you get depends on which mode it uses. */
    info.si_signo = SIGSEGV;
    info.si_errno = 0;
    /* XXX: check env->error_code */
    info.si_code = TARGET_SEGV_MAPERR;
    info._sifields._sigfault._addr = env->cp15.c6_data;
    queue_signal(env, info.si_signo, &info);

    end_exclusive();
}

/* Handle a jump to the kernel code page.  */
static int
do_kernel_trap(CPUARMState *env)
{
    uint32_t addr;
    uint32_t cpsr;
    uint32_t val;

    switch (env->regs[15]) {
    case 0xffff0fa0: /* __kernel_memory_barrier */
        /* ??? No-op. Will need to do better for SMP.  */
        break;
    case 0xffff0fc0: /* __kernel_cmpxchg */
         /* XXX: This only works between threads, not between processes.
            It's probably possible to implement this with native host
            operations. However things like ldrex/strex are much harder so
            there's not much point trying.  */
        start_exclusive();
        cpsr = cpsr_read(env);
        addr = env->regs[2];
        /* FIXME: This should SEGV if the access fails.  */
        if (get_user_u32(val, addr))
            val = ~env->regs[0];
        if (val == env->regs[0]) {
            val = env->regs[1];
            /* FIXME: Check for segfaults.  */
            put_user_u32(val, addr);
            env->regs[0] = 0;
            cpsr |= CPSR_C;
        } else {
            env->regs[0] = -1;
            cpsr &= ~CPSR_C;
        }
        cpsr_write(env, cpsr, CPSR_C);
        end_exclusive();
        break;
    case 0xffff0fe0: /* __kernel_get_tls */
        env->regs[0] = env->cp15.c13_tls2;
        break;
    case 0xffff0f60: /* __kernel_cmpxchg64 */
        arm_kernel_cmpxchg64_helper(env);
        break;

    default:
        return 1;
    }
    /* Jump back to the caller.  */
    addr = env->regs[14];
    if (addr & 1) {
        env->thumb = 1;
        addr &= ~1;
    }
    env->regs[15] = addr;

    return 0;
}
static int do_strex(CPUARMState *env)
{
    uint32_t val;
    int size;
    int rc = 1;
    int segv = 0;
    uint32_t addr;
    start_exclusive();
    g_sqi.mem.write_evaluatedValue_to_symbolicRegion(env->exclusive_addr, 8);
    g_sqi.mem.write_evaluatedValue_to_symbolicRegion(env->exclusive_test, 8);
    addr = env->exclusive_addr;
    if (addr != env->exclusive_test) {
        goto fail;
    }
    size = env->exclusive_info & 0xf;
    switch (size) {
    case 0:
        segv = get_user_u8(val, addr);
        break;
    case 1:
        segv = get_user_u16(val, addr);
        break;
    case 2:
    case 3:
        segv = get_user_u32(val, addr);
        break;
    default:
        abort();
    }
    if (segv) {
        env->cp15.c6_data = addr;
        goto done;
    }
    if (val != env->exclusive_val) {
        goto fail;
    }
    if (size == 3) {
        segv = get_user_u32(val, addr + 4);
        if (segv) {
            env->cp15.c6_data = addr + 4;
            goto done;
        }
        if (val != env->exclusive_high) {
            goto fail;
        }
    }
    val = env->regs[(env->exclusive_info >> 8) & 0xf];

    switch (size) {
    case 0:
        segv = put_user_u8(val, addr);
        break;
    case 1:
        segv = put_user_u16(val, addr);
        break;
    case 2:
    case 3:
        segv = put_user_u32(val, addr);
        break;
    }
    if (segv) {
        env->cp15.c6_data = addr;
        goto done;
    }
    if (size == 3) {
        val = env->regs[(env->exclusive_info >> 12) & 0xf];
        segv = put_user_u32(val, addr + 4);
        if (segv) {
            env->cp15.c6_data = addr + 4;
            goto done;
        }
    }
    rc = 0;
fail:
    REG_W(regs[15], env->regs[15] + 4);
    REG_W(regs[(env->exclusive_info >> 4) & 0xf], rc);
done:
    end_exclusive();
    return segv;
}
//FIXME
uint32_t do_arm_semihosting(CPUARMState *env) {
	assert(false && "do_arm_semihosting failed\n");
}
void process_cpu_arm_exec(CPUARMState *env)
{
    int trapnr;
    unsigned int n, insn;
    target_siginfo_t info;
    uint32_t addr;

    for(;;) {
        guest_thread_cond_lock();

        cpu_exec_start(env);
        trapnr = cpu_arm_exec(env);
        cpu_exec_end(env);
        switch(trapnr) {
        case EXCP_UDEF:
            {
		        assert(false && "EXCP_UDEF failed\n");
            }
            break;
        case EXCP_SWI:
        case EXCP_BKPT:
            {
                env->eabi = 1;
                /* system call */
                if (trapnr == EXCP_BKPT) {
                    assert(0 && "EXCP_BKPT failed\n");
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15], env->bswap_code);
                        n = insn & 0xff;
                        env->regs[15] += 2;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15], env->bswap_code);
                        n = (insn & 0xf) | ((insn >> 4) & 0xff0);
                        env->regs[15] += 4;
                    }
                } else {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15] - 2,
                                          env->bswap_code);
                        n = insn & 0xff;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15] - 4,
                                          env->bswap_code);
                        n = insn & 0xffffff;
                    }
                }

                if (n == ARM_NR_cacheflush) {
                    /* nop */
                } else if (n == ARM_NR_semihosting
                           || n == ARM_NR_thumb_semihosting) {
                    assert(0 && "FIXME for writing to env->regs[0]");
                    env->regs[0] = do_arm_semihosting (env);
                } else if (n == 0 || n >= ARM_SYSCALL_BASE || env->thumb) {
                    /* linux syscall */
                    if (env->thumb || n == 0) {
                        n = env->regs[7];
                    } else {
                        n -= ARM_SYSCALL_BASE;
                        env->eabi = 0;
                    }
                    if ( n > ARM_NR_BASE) {
                        switch (n) {
                        case ARM_NR_cacheflush:
                            /* nop */
                            break;
                        case ARM_NR_set_tls:
                            cpu_set_tls(env, env->regs[0]);
#ifdef CONFIG_SYMBEX
                            REG_W(regs[0],0);
#else
                            env->regs[0] = 0;
#endif
                            break;
                        case ARM_NR_get_tls:
                            //env->regs[0] = cpu_get_tls(env);
                            assert(0 && "ARM_NR_get_tls\n");
                            break;
                        default:
                            gemu_log("qemu: Unsupported ARM syscall: 0x%x\n",
                                     n);
#ifdef CONFIG_SYMBEX
                            REG_W(regs[0], -TARGET_ENOSYS);
#else
                            env->regs[0] = -TARGET_ENOSYS;
#endif
                            break;
                        }
                    } else {
                        struct SyscallArguments args = {env->regs[0],
                                                        env->regs[1],
                                                        env->regs[2],
                                                        env->regs[3],
                                                        env->regs[4],
                                                        env->regs[5], 0, 0};
                        g_sqi.events.on_do_syscall_start(n, &args);
#ifdef CONFIG_SYMBEX
                        abi_long ret = do_syscall(env,
                                                  n,
                                                  env->regs[0],
                                                  env->regs[1],
                                                  env->regs[2],
                                                  env->regs[3],
                                                  env->regs[4],
                                                  env->regs[5],
                                                  0, 0);
                        REG_W(regs[0], ret);
#else
                        abi_long ret = do_syscall(env,
                                                  n,
                                                  env->regs[0],
                                                  env->regs[1],
                                                  env->regs[2],
                                                  env->regs[3],
                                                  env->regs[4],
                                                  env->regs[5],
                                                  0, 0);
                        env->regs[0] = ret;
#endif
                        g_sqi.events.on_do_syscall_end(n, ret, &args);
                    }
                } else {
                    goto error;
                }
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_PREFETCH_ABORT:
            assert(0 && "EXCP_PREFETCH_ABORT failed\n");
            addr = env->cp15.c6_insn;
            goto do_segv;
        case EXCP_DATA_ABORT:
            assert(0 && "EXCP_DATA_ABORT failed\n");
            addr = env->cp15.c6_data;
        do_segv:
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = addr;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP_DEBUG:
            {
            assert(0 && "EXCP_DEBUG failed\n");
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
            break;
        case EXCP_KERNEL_TRAP:
            if (do_kernel_trap(env))
              goto error;
            break;
        case EXCP_STREX:
#ifndef DISABLE_EXCLUSIVE_LOCK
            guest_thread_unlock();
#endif
#ifndef DISABLE_EXCLUSIVE_LOCK
            guest_thread_cond_lock();
#endif
            if (do_strex(env)) {
                addr = env->cp15.c6_data;
                goto do_segv;
            }
            break;
        case NO_EXCP:
            break;
#ifdef CONFIG_SYMBEX
        case EXCP_SE:
            return;
#endif
        default:
        error:
            fprintf(stderr, "%s: unhandled CPU exception 0x%x - aborting\n",__FUNCTION__,
                    trapnr);
            cpu_dump_state(env, stderr, fprintf, 0);
            abort();
        }
        process_pending_signals(env);
        guest_thread_unlock();
    }
}

/* cloned thread will enter this execution loop and exit until it finishes */
void clone_process_cpu_arm_exec(CPUARMState *env)
{
    int trapnr;
    unsigned int n, insn;
    target_siginfo_t info;
    uint32_t addr;

    for(;;) {
        guest_thread_cond_lock();
        cpu_exec_start(env);
        trapnr = cpu_arm_exec(env);
        cpu_exec_end(env);
        switch(trapnr) {
        case EXCP_UDEF:
            {
                assert(false && "EXCP_UDEF failed\n");
            }
            break;
        case EXCP_SWI:
        case EXCP_BKPT:
            {
                env->eabi = 1;
                /* system call */
                if (trapnr == EXCP_BKPT) {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15], env->bswap_code);
                        n = insn & 0xff;
                        env->regs[15] += 2;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15], env->bswap_code);
                        n = (insn & 0xf) | ((insn >> 4) & 0xff0);
                        env->regs[15] += 4;
                    }
                } else {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15] - 2,
                                          env->bswap_code);
                        n = insn & 0xff;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15] - 4,
                                          env->bswap_code);
                        n = insn & 0xffffff;
                    }
                }

                if (n == ARM_NR_cacheflush) {
                    /* nop */
                } else if (n == ARM_NR_semihosting
                           || n == ARM_NR_thumb_semihosting) {
                    assert(0 && "FIXME for writing to env->regs[0]");
                    env->regs[0] = do_arm_semihosting (env);
                } else if (n == 0 || n >= ARM_SYSCALL_BASE || env->thumb) {
                    /* linux syscall */
                    if (env->thumb || n == 0) {
                        n = env->regs[7];
                    } else {
                        n -= ARM_SYSCALL_BASE;
                        env->eabi = 0;
                    }
                    if ( n > ARM_NR_BASE) {
                        switch (n) {
                        case ARM_NR_cacheflush:
                            /* nop */
                            break;
                        case ARM_NR_set_tls:
                            cpu_set_tls(env, env->regs[0]);
#ifdef CONFIG_SYMBEX
                            REG_W(regs[0],0);
#else
                            env->regs[0] = 0;
#endif
                            break;
                        default:
                            gemu_log("qemu: Unsupported ARM syscall: 0x%x\n",
                                     n);
#ifdef CONFIG_SYMBEX
                            REG_W(regs[0],-TARGET_ENOSYS);
#else
                            env->regs[0] = -TARGET_ENOSYS;
#endif
                            break;
                        }
                    } else {
                        struct SyscallArguments args = {env->regs[0],
                                                        env->regs[1],
                                                        env->regs[2],
                                                        env->regs[3],
                                                        env->regs[4],
                                                        env->regs[5], 0, 0};
                        g_sqi.events.on_do_syscall_start(n, &args);
#ifdef CONFIG_SYMBEX
                        abi_long ret = do_syscall(env,
                                                  n,
                                                  env->regs[0],
                                                  env->regs[1],
                                                  env->regs[2],
                                                  env->regs[3],
                                                  env->regs[4],
                                                  env->regs[5],
                                                  0, 0);
                        REG_W(regs[0], ret);
#else
                        abi_long ret = do_syscall(env,
                                                  n,
                                                  env->regs[0],
                                                  env->regs[1],
                                                  env->regs[2],
                                                  env->regs[3],
                                                  env->regs[4],
                                                  env->regs[5],
                                                  0, 0);
                        env->regs[0] = ret;
#endif
                        g_sqi.events.on_do_syscall_end(n, ret, &args);
                    }
                } else {
                    goto error;
                }
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_PREFETCH_ABORT:
            addr = env->cp15.c6_insn;
            goto do_segv;
        case EXCP_DATA_ABORT:
            addr = env->cp15.c6_data;
        do_segv:
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = addr;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
            break;
        case EXCP_KERNEL_TRAP:
            if (do_kernel_trap(env))
              goto error;
            break;
        case EXCP_STREX:
#ifndef DISABLE_EXCLUSIVE_LOCK
            guest_thread_unlock();
#endif
#ifndef DISABLE_EXCLUSIVE_LOCK
            guest_thread_cond_lock();
#endif
            if (do_strex(env)) {
                addr = env->cp15.c6_data;
                goto do_segv;
            }
            break;
        case NO_EXCP:
            break;
#ifdef CONFIG_SYMBEX
        case EXCP_SE:
            abort();
#endif
        default:
        error:
            fprintf(stderr, "%s: unhandled CPU exception 0x%x - aborting\n",__FUNCTION__,
                    trapnr);
            cpu_dump_state(env, stderr, fprintf, 0);
            abort();
        }
        process_pending_signals(env);
        guest_thread_unlock();
    }
}

/* copied from main.c: end */
#endif
