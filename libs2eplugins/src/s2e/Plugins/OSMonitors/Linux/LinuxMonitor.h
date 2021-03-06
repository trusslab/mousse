///
/// Copyright (C) 2014-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LINUX_MONITOR_H
#define S2E_PLUGINS_LINUX_MONITOR_H

#include <s2e/monitors/commands/linux.h>

#include "BaseLinuxMonitor.h"

namespace s2e {
namespace plugins {

template <typename T> T &operator<<(T &stream, const S2E_LINUXMON_COMMANDS &c) {
    switch (c) {
        case LINUX_SEGFAULT:
            stream << "SEGFAULT";
            break;
        case LINUX_PROCESS_LOAD:
            stream << "PROCESS_LOAD";
            break;
        case LINUX_TRAP:
            stream << "TRAP";
            break;
        case LINUX_PROCESS_EXIT:
            stream << "PROCESS_EXIT";
            break;
        default:
            stream << "INVALID(" << (int) c << ")";
            break;
    }

    return stream;
}
/*
enum S2E_LINUXMON_SYSCALL {
    SYSCALL_MMAP = 0x09,
    SYSCALL_MPROTECT = 0x10,
    SYSCALL_MUNMAP = 0x11,
    SYSCALL_BRK = 0x12
}*/

///
/// \brief Detects the loading/unloading of modules and various errors on the
/// Linux operating system.
///
/// This plugin has been specifically developed for a modified version of the
/// Linux 4.9.3 kernel, which can be accessed at
/// https://github.com/S2E/s2e-linux-kernel.git in the linux-4.9.3 branch.
///
class LinuxMonitor : public BaseLinuxMonitor<S2E_LINUXMON_COMMAND, S2E_LINUXMON_COMMAND_VERSION> {
    S2E_PLUGIN
public:
    LinuxMonitor(S2E *s2e) : BaseLinuxMonitor(s2e) {
    }

    void initialize();

    //Not used
    sigc::signal<void, S2EExecutionState *, uint64_t /* syscall id */, uint64_t /* pc */, uint64_t /* stack */
                 >
        onSyscall_d;

    //sigc::signal<void, S2EExecutionState *, const S2E_LINUXMON_COMMAND_SYSCALL &> onSyscall;

private:
    /// Address of the \c current_task object in the Linux kernel (see arch/x86/kernel/cpu/common.c)
    uint64_t m_currentTaskAddr;

    /// Offset of the thread group identifier in the \c task_struct struct (see include/linux/sched.h)
    uint64_t m_taskStructTgidOffset;

    /// Terminate if a trap (e.g. divide by zero) occurs
    bool m_terminateOnTrap;

    //
    // Handle the various commands emitted by the kernel
    //
    virtual void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize,
                               S2E_LINUXMON_COMMAND &cmd);
    void handleSegfault(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleProcessLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleModuleLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleProcessExit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleTrap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleInit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);

    void onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc, enum special_instruction_t type);

    void onTranslateSoftInterruptStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                       uint64_t pc, unsigned vector);

    void onSyscallInst(S2EExecutionState *state, uint64_t pc);
    void onSyscallInt(S2EExecutionState *state, uint64_t pc);
    void processSyscall(S2EExecutionState *state, uint64_t pc, uint64_t syscallId, uint64_t stack);
    void instrumentSyscalls(S2EExecutionState *state);    

public:
    /// Emitted when a trap occurs in the kernel (e.g. divide by zero, etc.)
    sigc::signal<void, S2EExecutionState *, uint64_t, /* pid */
                 uint64_t,                            /* pc */
                 int /* trapnr */>
        onTrap;

    // Get the current process identifier
    virtual uint64_t getPid(S2EExecutionState *state, uint64_t pc);
    virtual uint64_t getPid(S2EExecutionState *state);

    /// Get the current thread identifier
    virtual uint64_t getTid(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif
