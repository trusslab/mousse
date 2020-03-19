/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MEMORYBUGCHECKER_H
#define S2E_PLUGINS_MEMORYBUGCHECKER_H

#include "../DistributedExecution/mousse_common.h"

#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/ExecutionMonitors/ProcessMonitor.h>
#include <s2e/Plugins/ExecutionMonitors/StackMonitor.h>

#include <string>

namespace s2e {

namespace plugins {

class MemoryBugCheckerState;

// MemoryCheker tracks memory that the module is allowed to acces
// and checks each access for validiry
class MemoryBugChecker : public Plugin
{
    S2E_PLUGIN

#if defined(TARGET_I386)
    enum X86_64_SYSCALL_NR {
        SYSCALL_MMAP =      9,
        SYSCALL_MPROTECT =  10,
        SYSCALL_MUNMAP =    11,
        SYSCALL_BRK =       12,
        SYSCALL_MREMAP =    25
    };
#elif defined(TARGET_ARM)
    enum ARM_SYSCALL_NR {
        SYSCALL_CLOSE =     6,
        SYSCALL_BRK =       45,
        SYSCALL_MMAP =      90,
        SYSCALL_MUNMAP =    91,
        SYSCALL_MPROTECT =  125,
        SYSCALL_MREMAP =    163,
        SYSCALL_OPENAT =    322
    };
#endif
    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

    ConcreteInputs m_bugInputs;

    StackMonitor *m_stackMonitor;
    ProcessMonitor *m_pm;

    int m_debugLevel;

    bool m_checkBugs;
    bool m_checkNullPtrDerefBug;
    bool m_checkRetPtrOverrideBug;
    bool m_checkOOBAccessBug;

    bool m_terminateOnBugs;

    bool m_traceMemoryAccesses;

    ImageInfo m_binaryInfo;

public:
    enum Permissions {
        NONE=0, READ=1, WRITE=2, READWRITE=3, EXEC=4, ANY=-1
    };

    MemoryBugChecker(S2E* s2e): Plugin(s2e) {}

    void initialize();

private:
    void printConcreteInputs(llvm::raw_ostream &os, const ConcreteInputs &inputs);

    bool checkRange(S2EExecutionState *state, klee::ref<klee::Expr> expr);

    bool assume(S2EExecutionState *state, klee::ref<klee::Expr> expr);

    void printImageInfo(S2EExecutionState *state, ImageInfo *info);

    void onLoadImage(S2EExecutionState *state, ImageInfo *info);

    void onRegisterRam(S2EExecutionState *state, uint64_t addr, uint64_t size);

    void emitOnBugDetected(S2EExecutionState *state, uint32_t bug, uint64_t pc = 0);

    bool checkNullPtrDeref(S2EExecutionState *state, klee::ref<klee::Expr> addr);

    bool checkAddressRange(S2EExecutionState *state, klee::ref<klee::Expr> addr,
                           uint64_t lower, uint64_t upper);

    bool checkRetPtrOverride(S2EExecutionState *state, klee::ref<klee::Expr> addr);

    bool checkSymbolicMemoryAccess(S2EExecutionState *state,
                                   klee::ref<klee::Expr> start,
                                   klee::ref<klee::Expr> value,
                                   bool isWrite,
                                   llvm::raw_ostream &err);

    void onBeforeSymbolicDataMemoryAccess(S2EExecutionState*,
                                          klee::ref<klee::Expr> virtualAddress,
                                          klee::ref<klee::Expr> value,
                                          bool isWrite);

    bool checkConcreteOOBAccess(S2EExecutionState *state, uint64_t addr, int size,
                                bool isWrite, llvm::raw_ostream &err);

//    bool checkUnallocatedHeapAccess(S2EExecutionState *state, uint64_t addr, int size,
//                                    llvm::raw_ostream &err);

    bool checkMemoryAccess(S2EExecutionState *state,
                           uint64_t start, uint64_t size, uint8_t perms,
                           llvm::raw_ostream &err);

    void onConcreteDataMemoryAccess(S2EExecutionState *state,
                                    uint64_t virtualAddress,
                                    uint64_t value,
                                    uint8_t size,
                                    unsigned flags);

    void onAlwaysConcreteMemoryAccess(S2EExecutionState *state,
                                      klee::ref<klee::Expr> value,
                                      bool isWrite);

    std::string getPrettyCodeLocation(S2EExecutionState *state);

public:
    /**
     * Fired right before the actual checking.
     * This gives a chance for other plugins to perform
     * more fine-grained checks.
     * When all callbacks return, the memory checker proceeds normally.
     */
    sigc::signal<void,
            S2EExecutionState *,
            uint64_t /* virtual address */,
            unsigned /* size */,
            bool /* isWrite */>
        onPreCheck;

    /**
     * Fired if the actual checking failed.
     * This gives a chance for other plugins to perform
     * more fine-grained checks that were missed by MemoryBugChecker.
     */
    sigc::signal<void,
            S2EExecutionState *,
            uint64_t /* virtual address */,
            unsigned /* size */,
            bool /* isWrite */,
            bool * /* success */>
        onPostCheck;

    sigc::signal<void,
            S2EExecutionState *,
            uint32_t /* bug */,
            uint64_t /* pc */,
            uint32_t /* insn */,
            const std::string& /* binary*/,
            const ConcreteInputs& /* inputs */>
        onBugDetected;

protected:
    friend class MemoryBugCheckerState;

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MEMORYBUGCHECKER_H
