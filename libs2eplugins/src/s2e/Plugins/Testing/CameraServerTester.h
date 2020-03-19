/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *   Authors: Hsin-Wei Hung<hsinweih@uci.edu> Yingtong Liu <yingtong@uci.edu> 
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef S2E_PLUGINS_CAMERA_SERVER_TESTER_H
#define S2E_PLUGINS_CAMERA_SERVER_TESTER_H

#include "../DistributedExecution/mousse_common.h"

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionMonitors/ProcessMonitor.h>
#include <s2e/Plugins/DistributedExecution/DistributedExecution.h>
#include <s2e/S2EExecutionState.h>

#include <chrono>
#include <mutex>
#include <thread>

namespace s2e {
namespace plugins {

class CameraServerTester : public Plugin {
    S2E_PLUGIN
public:
    CameraServerTester(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    void testCameraServer(S2EExecutionState *state);

    void onTimer(S2EExecutionState *state);

    void onDoSyscallStart(S2EExecutionState *state, uint64_t syscallNum,
                          SyscallArguments *args);

    void onDoSyscallEnd(S2EExecutionState *state, uint64_t syscallNum,
                        uint64_t ret, SyscallArguments *args);

private:
    uint64_t m_blockingIoctlThreshold;

    bool m_initialized;
    bool m_distributedExecution;

    pid_t m_testerPid;
    std::string m_testScript;

    DistributedExecution *m_de;
    ProcessMonitor *m_pm;

    std::tr1::unordered_map<uint64_t, int> m_activeIoctls;
    std::mutex m_activeIoctlsMutex;

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CAMERA_SERVER_TESTER_H
