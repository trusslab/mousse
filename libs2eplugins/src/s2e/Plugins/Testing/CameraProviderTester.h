/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *   Authors: Hsin-Wei Hung<hsinweih@uci.edu>
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef S2E_PLUGINS_CAMERA_PROVIDER_TESTER_H
#define S2E_PLUGINS_CAMERA_PROVIDER_TESTER_H

#include "../DistributedExecution/mousse_common.h"

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Analyzers/CacheSim.h>
#include <s2e/Plugins/ExecutionMonitors/ProcessMonitor.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/DistributedExecution/DistributedExecution.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class CameraProviderTester : public Plugin {
    S2E_PLUGIN
public:
    CameraProviderTester(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    pid_t executeScript(const char *script);

    void onTimer(S2EExecutionState *state);

    void onDoSyscallStart(S2EExecutionState *state, uint64_t syscallNum,
                          SyscallArguments *args);

    void onDoSyscallEnd(S2EExecutionState *state, uint64_t syscallNum,
                        uint64_t ret, SyscallArguments *args);

    void onInterceptFunctionReturn(S2EExecutionState *state);

    void onInterceptFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);

    void registerCallSignalHandler(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                               TranslationBlock *tb, uint64_t pc);

    void onCall(S2EExecutionState *state, uint64_t pc);

    void on_mct_pipeline_process_serv_msg(S2EExecutionState *state, uint64_t pc);

    void onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state,
                                   TranslationBlock *tb, uint64_t pc, uint64_t rmask,
                                   uint64_t wmask, bool accessesMemory);

    void onReturn(S2EExecutionState *state, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                             TranslationBlock *tb, uint64_t pc, bool isStatic,
                             uint64_t staticTarget);

    void onTranslateJumpStart(ExecutionSignal *signal, S2EExecutionState *state,
                              TranslationBlock *tb, uint64_t pc, int jump_type);

private:
    bool m_distributedExecution;
    bool m_initialized;
    bool m_recvmsgIntercepted;
    bool m_pselect6Start;
    bool m_callHandlerRegistered;
    uint64_t m_pselect6Time;
    uint64_t m_blockingPselect6Threshold;
    uint32_t m_blockingPselect6Count;
    uint32_t m_cameraProviderTestCode;
    uint32_t m_delayedTermination;

    uint32_t m_processServMsgAddr;
    uint32_t m_command;
    uint32_t m_commandCount;
    uint32_t m_startAfterN;
    uint32_t m_configParmOffset;
    uint32_t m_configParmTestOffset;
    uint32_t m_configParmSize;

    bool m_interceptFunctionCalled;
    bool m_interceptFunctionTested;
    int m_interceptFunctionTid;

    bool m_testStarted;
    bool delayDebugSet;
    int delayDebugTimer;

    pid_t m_cameraServerPid;

    DistributedExecution *m_de;
    FunctionMonitor *m_fm;
    ProcessMonitor *m_pm;
    CacheSim *m_cacheSim;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CAMERA_PROVIDER_TESTER_H
