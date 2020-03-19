///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2019 TrussLab@University of California, Irvine. 
/// Authors: Ardalan Amiri Sani<ardalan@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MULTIPROCESS_H
#define S2E_PLUGINS_MULTIPROCESS_H

//#include <klee/Expr.h>
#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#define ARGS_SIZE 6
#define ARGS_BUFF_SIZE 64
#define ARG_DATA_SIZE 64
#define PORT 8080 

namespace s2e {
namespace plugins {

//class FunctionMonitor;
//class FunctionMonitorState;

class MultiProcess : public Plugin {
    S2E_PLUGIN
public:
    MultiProcess(S2E *s2e) : Plugin(s2e) {
        m_sock_fd = -1;
        m_sym_sock_fd = -1;
        m_sym_port = 8090;
        m_target_accept4 = false;
    }

    void initialize();

    void onLoadImage(S2EExecutionState *state, ImageInfo *info);
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, 
                             TranslationBlock *tb, uint64_t pc);

    void slotStateForkN(S2EExecutionState *state, 
                        const std::vector<S2EExecutionState*>& new_states, 
                        const std::vector<klee::ref<klee::Expr>>& new_conditions);

    void slotStateFork(S2EExecutionState *state, 
                       const std::vector<S2EExecutionState*>& new_states, 
                       const std::vector<klee::ref<klee::Expr>>& new_conditions);

    void slotStateForkF(S2EExecutionState *state, 
                        const std::vector<S2EExecutionState*>& new_states, 
                        const std::vector<klee::ref<klee::Expr>>& new_conditions);

    //void slotStateForkDecide(S2EExecutionState *state, bool *forkAllowed);

    void slotSymbolicVariableCreation(S2EExecutionState *state,
        const std::string &originalName, const std::vector<klee::ref<klee::Expr>> &expr,
        const klee::MemoryObject *memObj, const klee::Array *array);

    void slotStateSwitch(S2EExecutionState *current_state, S2EExecutionState *next_state);

    void slotStateKill(S2EExecutionState *state);

    void slotDoSyscallStart(S2EExecutionState *state, uint64_t syscall_num, SyscallArguments *args);

    void onDoSyscallEnd(S2EExecutionState *state, uint64_t syscall_id, uint64_t ret,
                        SyscallArguments *args);

    //virtual klee::ExecutionState &selectState();

    //virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
    //                    const klee::StateSet &removedStates);

    //virtual bool empty();

    void printName(llvm::raw_ostream &os) {
        os << "MultiProcessSearcher\n";
    }

private:
    //typedef std::set<S2EExecutionState *> States;

    int m_sock_fd;
    int m_sym_sock_fd;
    int m_sym_port;
    bool m_target_accept4;

    int waitForSymChannel(void); 
    int establishSymChannel(void);
    void sendSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size);
    void recvSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size);
    void makeMemorySymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
                            const std::string &nameStr, bool makeConcolic,
                            std::vector<klee::ref<klee::Expr>> *varData, std::string *varName);


    //bool m_traceBlockTranslation;
    //bool m_traceBlockExecution;

    //bool m_syscallHasSymbolicInputs;

    //uint64_t m_offloadUpperThreshold;
    //uint64_t m_offloadLowerThreshold;

    ///* Test information */
    //std::string m_testerName;
    //uint64_t m_initAddress;
    //uint64_t m_loadAddress;
    //std::vector<functionT> m_functions;

    //FunctionMonitor *m_functionMonitor;

    //S2EExecutionState *m_currentState;
    //S2EExecutionState *m_initialState;
    //std::vector<DistributedState *> pendingStates;

    ///* The next two are from TestCaseGenerator */
    //typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    //typedef std::vector<VarValuePair> ConcreteInputs;

    //int m_ignore_depth;
    //int m_sock; 

    //void addToPendingStates(llvm::raw_ostream &os, S2EExecutionState *state, int depth);
    //int connect_to_server(void); 
    //int get_prog_data_from_server(data_t *data);
    //int send_prog_data_to_server(data_t *data);
    //int read_ignore_depth(void);
    //bool match_name(std::string vname, std::string name);
    //int getArgDataPosition(std::string funcName, std::string argName);
    //void set_data(std::string vname, const std::vector<unsigned char> &src, char *dest);
};

class MultiProcessState: public PluginState
{
public:
    MultiProcess* m_plugin;

public:
    MultiProcessState() {
    }
    ~MultiProcessState() {}

    MultiProcessState *clone() const { return new MultiProcessState(*this); }
    static PluginState *factory(Plugin* p, S2EExecutionState* s) {
        MultiProcessState *ret = new MultiProcessState();
        ret->m_plugin = static_cast<MultiProcess *>(p);
        return ret;
    }

};


} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MULTIPROCESS_H
