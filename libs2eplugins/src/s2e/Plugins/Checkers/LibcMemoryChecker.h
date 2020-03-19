/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef MOUSSE_PLUGINS_LIBC_MEMORY_CHECKER_H
#define MOUSSE_PLUGINS_LIBC_MEMORY_CHECKER_H

#include "../DistributedExecution/mousse_common.h"

#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/ExecutionMonitors/ProcessMonitor.h>
#include <s2e/Plugins/ExecutionMonitors/StackMonitor.h>

namespace s2e {

namespace plugins {

class FreeRecord {
public:
    uint64_t addr;
    StackMonitor::CallStack cs;

    FreeRecord(uint64_t address) {
        addr = address;
    }

    FreeRecord(uint64_t address, const StackMonitor::CallStack &callstack) {
        addr = address;
        cs = callstack;
    }

    bool operator<(const FreeRecord &rhs) const {
        return addr < rhs.addr;
    }

    bool operator>(const FreeRecord &rhs) const {
        return addr > rhs.addr;
    }

    bool operator==(const FreeRecord &rhs) const {
        return addr == rhs.addr;
    }

    bool operator!=(const FreeRecord &rhs) const {
        return !(addr == rhs.addr);
    }
};

class LibcMemoryChecker : public Plugin
{
    S2E_PLUGIN

    enum LIBC_MEM_FUNC {
        LIBC_FREE = 0,
        LIBC_MALLOC,
        LIBC_CALLOC,
        LIBC_REALLOC,
        LIBC_MEMALIGN,
        LIBC_POSIX_MEMALIGN,
        LIBC_PVALLOC,
        LIBC_VALLOC,
        LIBC_ALIGNED_ALLOC,
        LIBC_MEM_FUNC_NUM
    };

    typedef void (LibcMemoryChecker::*call_handler_t)(S2EExecutionState *);
    typedef void (LibcMemoryChecker::*return_handler_t)(S2EExecutionState *, uint64_t);

    struct LibcFunction {
        std::string name;
        uint32_t offset;
        int call_depth;
        int argc;
        uint32_t args[3];
        uint32_t ret;
        call_handler_t call_handler;
        return_handler_t return_handler;

        LibcFunction(const char * nm, int c, uint32_t of)
            : name(std::string(nm)), offset(of), call_depth(0),
              argc(c), call_handler(NULL), return_handler(NULL)
        {
            for (unsigned i = 0; i < argc; i++)
                args[i] = 0;
        };
    };

    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

    typedef std::pair<uint64_t, uint64_t> SimpleMemoryRegion;
    typedef std::vector<SimpleMemoryRegion> SimpleMemoryRegions;

    ConcreteInputs m_bugInputs;

    std::tr1::unordered_map<uint64_t, uint64_t> m_PLTMap;

    std::vector<LibcFunction> m_libcFunctions;

    std::vector<FreeRecord> m_freeAddresses;

    SimpleMemoryRegions m_allocatedRegions;

    ProcessMonitor *m_pm;
    StackMonitor *m_sm;

    int m_debugLevel;

    bool m_checkDoubleFreeBug;

public:
    LibcMemoryChecker(S2E* s2e): Plugin(s2e) {}

    void initialize();

    bool checkUnallocatedHeapAccess(S2EExecutionState *state, uint64_t addr, int size,
                                    llvm::raw_ostream &err);

private:
    void printConcreteInputs(llvm::raw_ostream &os, const ConcreteInputs &inputs);

    std::pair<uint64_t, uint64_t> checkRange(S2EExecutionState *state,
                                             klee::ref<klee::Expr> expr);

    bool assume(S2EExecutionState *state, klee::ref<klee::Expr> expr);

    void emitOnBugDetected(S2EExecutionState *state, uint32_t bug,
                           StackMonitor::CallStack *cs = NULL);

    void libcAllocateMemory(S2EExecutionState *state, uint32_t addr, uint32_t size);

    void onMallocReturn(S2EExecutionState *state, uint64_t pc);
    void onCallocReturn(S2EExecutionState *state, uint64_t pc);
    void onReallocReturn(S2EExecutionState *state, uint64_t pc);
    void onMemalignReturn(S2EExecutionState *state, uint64_t pc);
    void onPosixMemalignReturn(S2EExecutionState *state, uint64_t pc);
    void onAlignedAllocReturn(S2EExecutionState *state, uint64_t pc);
    void onPvallocReturn(S2EExecutionState *state, uint64_t pc);
    void onVallocReturn(S2EExecutionState *state, uint64_t pc);

    void onReturn(S2EExecutionState *state, uint64_t pc);

    void onFreeCall(S2EExecutionState *state);

    void onCall(S2EExecutionState *state, uint64_t pc);

    void onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state,
                                   TranslationBlock *tb, uint64_t pc, uint64_t rmask,
                                   uint64_t wmask, bool accessesMemory);

    void onTranslateBlockEnd(ExecutionSignal *,S2EExecutionState *state,
                             TranslationBlock *tb, uint64_t pc, bool, uint64_t);

    void onAbortCall(S2EExecutionState *state);

    void onPthreadCondTimewaitCall(S2EExecutionState *state);

    bool isSizeArgReg(unsigned func, unsigned reg);

    int whichLibcFunction(uint32_t pc);

    void onIndirectPLTBranch(S2EExecutionState *state, uint64_t pc);

    void onTranslateJumpStart(ExecutionSignal* signal, S2EExecutionState* state,
                              TranslationBlock* tb, uint64_t pc, int jump_type);

public:
    std::string getPrettyCodeLocation(S2EExecutionState *state);

    sigc::signal<void,
            S2EExecutionState *,
            uint32_t /* bug */,
            uint64_t /* pc */,
            uint32_t /* insn */,
            const std::string& /* binary */,
            const ConcreteInputs& /* inptus */>
        onBugDetected;

    sigc::signal<void,
            S2EExecutionState *,
            uint32_t /* bug */,
            uint64_t /* pc */,
            uint32_t /* insn */,
            const std::string& /* binary */,
            const ConcreteInputs& /* inptus */,
            StackMonitor::CallStack* /* call stack 2 */>
        onBugDetected2;

};

} // namespace plugins
} // namespace s2e

#endif // MOUSSE_LIBC_MEMORY_CHECKER_H
