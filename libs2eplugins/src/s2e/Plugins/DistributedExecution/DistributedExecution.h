///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu> Yingtong Liu <yingtong@uci.edu>  
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_DISTRIBUTEDEXECUTION_H
#define S2E_PLUGINS_DISTRIBUTEDEXECUTION_H

#include "mousse_common.h"

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionMonitors/ProcessMonitor.h>
#include <s2e/Plugins/ExecutionMonitors/StackMonitor.h>
#include <s2e/Plugins/Checkers/MemoryBugChecker.h>
#include <s2e/Plugins/Checkers/LibcMemoryChecker.h>
#include <s2e/S2EExecutionState.h>

#include <klee/ExprSerializer.h>
#include <klee/ExprDeserializer.h>

#include <sys/socket.h>
#include <chrono>
#include <mutex>
#include <thread>

#define ARM_SYSCALL_NUM_MAX 400 //FIXME
#define INPUT_REQ_WAIT 2
#define REBOOT_WAIT    60
#define DEFAULT_PORT 8080

#define SYSCALL_STATE_MODIFYING   0x1
#define SYSCALL_STATE_REVEALING   0x2
#define SYSCALL_MAKE_RET_CONCOLIC 0x4
#define SYSCALL_CHECK_FD          0x8

#define MONITOR_PORT 8089
#define SYM_PORT 8190

namespace s2e {
namespace plugins {

class FunctionMonitor;
class FunctionMonitorState;
class MemoryBugChecker;
class StackMonitor;

class argT {
public:
    int size;
    int value; /* support 32-bit argument only*/
    std::string name;
    argT() {};
    argT(int s, int v, std::string nm): size(s), value(v), name(nm) {};
};

class functionT {
public:
    uint64_t addr;
    std::string name;
    std::vector<argT> args;  
};

struct DistributedState {
    S2EExecutionState *state;
    state_t data;
};

class DistributedExecution : public Plugin, public klee::Searcher {
    S2E_PLUGIN
private:
    /* The next two are from TestCaseGenerator */
    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

public:
    DistributedExecution(S2E *s2e) : Plugin(s2e) {
        m_sock_fd = -1;
        m_sym_sock_fd = -1;
        m_monitor_port = MONITOR_PORT;
        m_sym_port = SYM_PORT;
        m_target_accept4 = false;
        mIsSymReceiver = false;
        m_testerPid = 0;
    }

    void terminate(int status);

    void getDeviceId();

    void initialize();

    void onLoadImage(S2EExecutionState *state, ImageInfo *info);

    void makeRegConcolic(S2EExecutionState *state, int address, unsigned size,
                         const std::string &name, char *value);

    void makeMemSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
                         const std::string &name);

    void makeMemSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
                         const std::string &name, bool makeConcolic,
                         std::vector<klee::ref<klee::Expr>> *varData, std::string *varName,
                         uint8_t *alternativeConcreteData);

    void makeArgumentsConcolic(S2EExecutionState *state, functionT &function);

    void initFunctionReturn(S2EExecutionState *state);

    void initFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);

    /* Functions to communicate with mousse server */
    int getDataFromMousseServer(uint32_t opcode, void *buf);

    void sendDataToMousseServer(uint32_t opcode, void *buf);

    uint32_t getNewStateIdFromServer();

    void initializeForkCounters(fork_counters_t *forkCounters);

    void sendStatusToServer(uint32_t status_flag);

    void sendForkCounterToServer();

    void fetchStateFromServer();


    void testFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);

    void registerCallSignalHandler(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, 
                               TranslationBlock *tb, uint64_t pc);

    void concreteInputsToBuffer(const ConcreteInputs &ci, state_t *s);

    void addToPendingStates(llvm::raw_ostream &os, S2EExecutionState *state, int depth);

    void offloadState(S2EExecutionState *currentState,
                      S2EExecutionState *offloadState, const std::string &reason);

    bool updateForkCounter(S2EExecutionState *state, uint64_t offset);

    void onStateFork(S2EExecutionState *state,
                     const std::vector<S2EExecutionState*>& new_states,
                     const std::vector<klee::ref<klee::Expr>>& new_conditions,
                     int type, bool &isChild);

    void spawnTimerThread(S2EExecutionState *state);
    void testAudioProvider(S2EExecutionState *state);
    void testAudioServer(S2EExecutionState *state);

    void onTimer(S2EExecutionState *state);

    void onStateKill(S2EExecutionState *state);

    void addConcolic(S2EExecutionState *state, const std::string &name, int size);

    void onBeforeMakeSymbolic(S2EExecutionState *state, uintptr_t address,
                              unsigned size, const std::string &name,
                              uint8_t *&alternativeConcreteData);

    void onOtherMakeConcolic(S2EExecutionState *state, uint64_t address,
                             unsigned size, const std::string &name);

    bool checkSyscall(uint64_t syscall_num, uint32_t mask);

    bool checkRange(S2EExecutionState *state, klee::ref<klee::Expr> expr);

    void printPathConstraints(S2EExecutionState *state);

    void onConcretizeSyscallArgs(S2EExecutionState *state, int isReg, uint64_t addr, uint64_t size);

    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t virtualAddress,
                                    uint64_t value, uint8_t size, unsigned flags);

    bool checkFd(uint64_t fd);
    bool checkDriverFd(uint64_t fd);

    void onDoSyscallStart(S2EExecutionState *state, uint64_t syscall_num, SyscallArguments *args);

    void addSymbolicSyscallOutput(S2EExecutionState *state, std::string name, uint64_t syscall_num,
                                  uint32_t count, uint64_t hash);

    bool useAlternativeOutput(S2EExecutionState *state, uint64_t syscall_num,
                              uint32_t count, uint64_t hash, char *returnValue);

    bool interceptRecvmsg(S2EExecutionState *state, struct msghdr *msg);

    void onDoSyscallEnd(S2EExecutionState *state, uint64_t syscall_num, uint64_t ret,
                        SyscallArguments *args);

    void onIsSymbolic(S2EExecutionState *state, target_ulong address, target_ulong size);

    void onBugDetected(S2EExecutionState *state, uint32_t type, uint64_t pc,
                       uint32_t insn, const std::string &binary,
                       const ConcreteInputs &ci);

    void onBugDetected2(S2EExecutionState *state, uint32_t type, uint64_t pc,
                        uint32_t insn, const std::string &binary,
                        const ConcreteInputs &ci, StackMonitor::CallStack *cs2);

    void onEngineShutdown();

    void onReceiveSignal(S2EExecutionState *state, uint32_t signal);

    void onThreadCreate(S2EExecutionState *state, uint64_t stack_address,
                        uint64_t parent_tid, uint64_t child_tid);

    void onThreadExit(S2EExecutionState *state, uint64_t tid);

    void onTlbMiss(S2EExecutionState *state, uint64_t address, bool isWrite);

    /* Searcher functions */
    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

    void printName(llvm::raw_ostream &os) {
        os << "DistributedExecutionSearcher\n";
    }

public:
    sigc::signal<void,
            S2EExecutionState *>
            onDistributedExecutionTimer;

    sigc::signal<void,
            S2EExecutionState *,
            int /* state id */ >
            onDistributedStateKill;

private:
    /* Configuration */
    bool m_legacyMode;
    bool m_makeSyscallReturnConcolic;
    bool m_makeEnvReturnConcolic;
    bool m_blockingIoctlDetection;
    bool m_rebootAfterTerminate;

    uint64_t m_stateExecutionThreshold;
    uint64_t m_blockingIoctlThreshold;
    uint64_t m_offloadThreshold;
    uint32_t m_forkLimiterThreshold;
    uint32_t m_multiForkLimit;
    uint32_t m_cameraProviderTestCode;

    std::vector<std::string> m_noForkingFiles;
    std::vector<std::string> m_blockingIoctlFiles;
    std::vector<std::string> m_environmentFiles;
    std::vector<std::string> m_driverFiles;
    std::vector<uint32_t> m_syscalls;

    /*  */
    int m_localForkDepth;
    int m_ignoreForkDepth;

    bool m_forked;
    bool m_initialized;
    bool m_callHandlerRegistered;
    bool m_hasFetchedState;
    bool m_syscallHasSymbolicInputs;
    bool m_stateRevealingSyscallCalled;
    bool m_stateModifyingSyscallCalled;
    bool m_environmentIsClean;

    uint32_t m_threadCount;

    uint32_t m_deviceId;
    uint32_t m_stateId;
    uint32_t m_endReason;

    uint32_t m_multiForkCounter;
    uint32_t m_multiForkTempForkStateId;
    bool m_multiForkTempFork;

    std::tr1::unordered_map<uint64_t, uint32_t> m_forkCounter;
    std::tr1::unordered_map<uint64_t, uint32_t> m_localForkCounter;
    std::tr1::unordered_map<std::string, syscall_symbolic_output_t> m_symbolicSyscalls;

    typedef std::pair<uint64_t, uint64_t> memoryRegion; // start, size
    typedef std::vector<memoryRegion> memoryRegions;

    memoryRegions m_envMemoryMap;

    pid_t m_testerPid;

    uint64_t m_initAddress;
    uint64_t m_loadAddress;
    // concolic variable insertion information
    std::vector<functionT> m_functions;

    // concolic variable insertion information (legacy mode)
    std::vector<argT> m_concolicVariables;
    uint32_t m_symbolicInputSize;
    uint64_t m_input_buf_used;

    ProcessMonitor *m_pm;
    StackMonitor *m_stackMonitor;

    // checkers (optional)
    MemoryBugChecker *m_memoryBugChecker;
    LibcMemoryChecker *m_libcMemoryChecker;

    S2EExecutionState *m_initialState;
    std::vector<DistributedState *> pendingStates;

    std::tr1::unordered_map<uint32_t, int> m_activeIoctls;
    std::mutex m_activeIoctlsMutex;

    std::thread *m_timerThread;

    std::chrono::time_point<std::chrono::system_clock> m_stateEndTime;
    std::chrono::time_point<std::chrono::system_clock> m_stateStartTime;
    bool mousse_tostart_audio_server;
    bool mousse_tostart_audio_app;
    bool m_audioprovider_intercepted;
    bool m_audioserver_intercepted;
    uint32_t m_audioserver_intercepted_thread;
    bool m_testAudioProvider;
    bool m_testAudioServer;
    std::string binderpath;
    int Cam1Sockets = 0;

    int m_portNum;

    int m_sock_fd;
    int m_sym_sock_fd;
    int m_sym_port;
    int m_monitor_port;
    bool m_target_accept4;
    bool mIsSymReceiver;

    void print_data(state_t *data);

    int get_input_buf_pos(std::string varName);

    int get_input_buf_pos(std::string funcName, std::string argName);

    void set_data(std::string vname, const std::vector<unsigned char> &src, char *dest);

    void setSyscallOutput(std::string vname, syscall_symbolic_output_t *syscall_info);

    int waitForConnection(int port, int *sockp, bool doRecoverFd, int recovFd);

    int waitForSymChannel(void); 

    int establishConnection(int port, int *sockp);

    int establishSymChannel(void);

    void recoverFd(int targetFd);

    void fixMonitorSocketReceiver(void);

    void fixMonitorSocketSender(void);

    void sendSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size);

    void recvSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size);

    void sendForkInfo(S2EExecutionState *state, uint16_t new_monitor_port, uint16_t new_sym_port);

    void recvForkInfo(S2EExecutionState *state);
        
    void updateConcolicVariables(std::vector<klee::concolicData> concolicVariables);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_DISTRIBUTEDEXECUTION_H
