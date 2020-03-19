/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *   Authors: Hsin-Wei Hung<hsinweih@uci.edu> Yingtong Liu <yingtong@uci.edu> 
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#include "CameraServerTester.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <linux/binder.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CameraServerTester, "CameraServerTester S2E Plugin", "",
                  "ProcessMonitor");


void CameraServerTester::initialize()
{
    m_testerPid = 0;
    m_initialized = false;

    ConfigFile *cfg = s2e()->getConfig();
    std::string top = getConfigKey();

    m_testScript = cfg->getString(top + ".testScript");
    m_blockingIoctlThreshold = cfg->getInt(top + ".blockingIoctlThreshold");


    s2e()->getCorePlugin()->onDoSyscallStart.connect(
            sigc::mem_fun(*this, &CameraServerTester::onDoSyscallStart));
    s2e()->getCorePlugin()->onDoSyscallEnd.connect(
            sigc::mem_fun(*this, &CameraServerTester::onDoSyscallEnd));

    m_distributedExecution = true;
    if (!m_distributedExecution) {
//        s2e()->getCorePlugin()->onTimer.connect(
//                sigc::mem_fun(*this, &CameraServerTester::onTimer));
    } else {
        m_de = s2e()->getPlugin<DistributedExecution>();
        assert(m_de);
        s2e()->getPlugin<DistributedExecution>()->onDistributedExecutionTimer.connect(
                sigc::mem_fun(*this, &CameraServerTester::onTimer));
    }

    m_pm = s2e()->getPlugin<ProcessMonitor>();
    assert(m_pm);
}

void CameraServerTester::testCameraServer(S2EExecutionState *state)
{
    pid_t pid = fork();
    if (pid == 0) {
        char * const argv[] = {(char *)"sh", (char *)"start_camera_app.sh", (char *)NULL};
        execv("/system/bin/sh", argv);
        getWarningsStream() << "shell finished\n";
        exit(0);
    } else {
        m_testerPid = pid;
    }
    m_initialized = true;
}

void CameraServerTester::onTimer(S2EExecutionState *state)
{
    //getWarningsStream(state) << "blocking ioctl timer\n";
    bool hasBlockingIoctl = false;
    std::lock_guard<std::mutex> lock(this->m_activeIoctlsMutex);
    for (auto &it : m_activeIoctls) {
        it.second++;
        if (it.second > m_blockingIoctlThreshold) {
            hasBlockingIoctl = true;
        }
    }
    if (hasBlockingIoctl && !m_initialized) {
        getWarningsStream(state) << "blocking ioctl: start testing\n";
        testCameraServer(state);
        for (auto &it : m_activeIoctls)
            it.second = 0;
    } else if (hasBlockingIoctl && m_initialized) {
        getWarningsStream(state) << "blocking ioctl: test finish\n";
        if (m_testerPid)
            kill(m_testerPid, SIGTERM);
        s2e()->getExecutor()->terminateState(*state);
    }

}

void CameraServerTester::onDoSyscallStart(S2EExecutionState *state,
        uint64_t syscallNum, SyscallArguments *args)
{
    if (syscallNum == 54) {
        int fd = m_pm->getFdOfFile("/dev/binder");
        if (args->arg1 == fd && (unsigned long)args->arg2 == BINDER_WRITE_READ) {
            std::lock_guard<std::mutex> lock(this->m_activeIoctlsMutex);
            assert(m_activeIoctls.find(pthread_self()) == m_activeIoctls.end());
            m_activeIoctls[pthread_self()] = 0;
        }
    }
}

void CameraServerTester::onDoSyscallEnd(S2EExecutionState *state,
    uint64_t syscallNum, uint64_t ret, SyscallArguments *args)
{
    if (syscallNum == 54) {
        int fd = m_pm->getFdOfFile("/dev/binder");
        if (args->arg1 == fd && (unsigned long)args->arg2 == BINDER_WRITE_READ) {
            std::lock_guard<std::mutex> lock(this->m_activeIoctlsMutex);
            assert(m_activeIoctls.find(pthread_self()) != m_activeIoctls.end());
            if (m_activeIoctls.find(pthread_self()) != m_activeIoctls.end()) {
                m_activeIoctls.erase(pthread_self());
            }
        }
    }
}


} // namespace plugins
} // namespace s2e
