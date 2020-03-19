/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *   Authors: Hsin-Wei Hung<hsinweih@uci.edu>
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#include "CameraProviderTester.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <sys/socket.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CameraProviderTester, "CameraProviderTester S2E Plugin", "",
                  "ProcessMonitor");


void CameraProviderTester::initialize()
{
    m_recvmsgIntercepted = false;
    m_pselect6Start = false;
    m_pselect6Time = 0;
    m_cameraServerPid = 0;
    m_initialized = false;
    m_callHandlerRegistered = false;
    m_blockingPselect6Count = 0;
    m_interceptFunctionCalled = false;
    m_interceptFunctionTested = false;
    m_interceptFunctionTid = 0;
    m_commandCount = 0;

    m_testStarted = false;
    delayDebugSet = false;
    delayDebugTimer = 0;

    ConfigFile *cfg = s2e()->getConfig();
    std::string top = getConfigKey();

    m_cameraProviderTestCode = cfg->getInt(top + ".testCode");
    m_processServMsgAddr = cfg->getInt(top + ".processServMsgAddr");
    m_command = cfg->getInt(top + ".command", 0x800000e);
    m_startAfterN = cfg->getInt(top + ".startAfterN", 0);
    m_configParmOffset = cfg->getInt(top + ".configParmOffset");
    m_configParmTestOffset = cfg->getInt(top + ".configParmTestOffset", 0);
    m_configParmSize = cfg->getInt(top + ".configParmSize");
    m_blockingPselect6Threshold = cfg->getInt(top + ".blockingPselect6Threshold", 10);
    m_delayedTermination = cfg->getInt(top + ".delayedTermination", 0);

    s2e()->getCorePlugin()->onDoSyscallStart.connect(
            sigc::mem_fun(*this, &CameraProviderTester::onDoSyscallStart));
    s2e()->getCorePlugin()->onDoSyscallEnd.connect(
            sigc::mem_fun(*this, &CameraProviderTester::onDoSyscallEnd));
    s2e()->getCorePlugin()->onTranslateRegisterAccessEnd.connect(
            sigc::mem_fun(*this, &CameraProviderTester::onTranslateRegisterAccess));

    m_distributedExecution = true;
    if (!m_distributedExecution) {
//        s2e()->getCorePlugin()->onTimer.connect(
//                sigc::mem_fun(*this, &CameraProviderTester::onTimer));
    } else {
        m_de = s2e()->getPlugin<DistributedExecution>();
        assert(m_de);
        s2e()->getPlugin<DistributedExecution>()->onDistributedExecutionTimer.connect(
                sigc::mem_fun(*this, &CameraProviderTester::onTimer));
    }

    m_cacheSim = s2e()->getPlugin<CacheSim>();

    m_fm = s2e()->getPlugin<FunctionMonitor>();
    //assert(m_fm);

    m_pm = s2e()->getPlugin<ProcessMonitor>();
    assert(m_pm);
}

pid_t CameraProviderTester::executeScript(const char *script)
{
    char scriptPath[30] = "";
    strcpy(scriptPath, script);

    pid_t pid = fork();
    if (pid == 0) {
        char * const argv[] = {(char *)"sh", scriptPath, (char *)NULL};
        execv("/system/bin/sh", argv);
        exit(0);
    } else {
        getWarningsStream() << "execute script " << script << " pid = " << pid << "\n";
        return pid;
    }
}

void CameraProviderTester::onTimer(S2EExecutionState *state)
{
    if (m_pselect6Start) {
        m_pselect6Time++;
        if (m_pselect6Time > m_blockingPselect6Threshold) {
            getWarningsStream(state) << "blocking pselect6: " << m_blockingPselect6Count << "\n";
            if (m_blockingPselect6Count == 0) {
                m_pselect6Time = 0;
                m_blockingPselect6Count++;
                executeScript("start_camera_server.sh");
            } else if (m_blockingPselect6Count == 1) {
                m_pselect6Time = 0;
                m_blockingPselect6Count++;
                m_initialized = true;
                executeScript("start_camera_app.sh");
            } else if (m_blockingPselect6Count == 2 && m_pselect6Time > m_delayedTermination) {
                getWarningsStream(state) << "test finish\n";
                kill(m_cameraServerPid, SIGTERM);
                s2e()->getExecutor()->terminateState(*state);
            }
        }
    } else {
        m_pselect6Time = 0;
    }

    if (m_testStarted) {
        if (delayDebugTimer++ > 2 && !delayDebugSet) {
            delayDebugSet = true;
//            se_set_debug_var(1);
        }
    }
}

void CameraProviderTester::onDoSyscallStart(S2EExecutionState *state,
        uint64_t syscallNum, SyscallArguments *args)
{
    if (syscallNum == 335)
        m_pselect6Start = true;
}

void CameraProviderTester::onDoSyscallEnd(S2EExecutionState *state,
        uint64_t syscallNum, uint64_t ret, SyscallArguments *args)
{
    switch (syscallNum) {
    case 335: { /* pselect6 */
        m_pselect6Start = false;
        break;
    }
    case 297: { /* recvmsg */
        if (m_initialized && !m_recvmsgIntercepted &&
            args->arg1 == m_pm->getFdOfFile("/data/misc/camera/cam_socket1")) {
        }
        break;
    }
    default: 
        break;
    }
}

void CameraProviderTester::onInterceptFunctionReturn(S2EExecutionState *state) {
    getDebugStream(state) << "intercept function return\n";

    return;
}

void CameraProviderTester::onInterceptFunctionCall(S2EExecutionState *state,
        FunctionMonitorState *fns)
{
    FUNCMON_REGISTER_RETURN(state, fns, CameraProviderTester::onInterceptFunctionReturn);
    getDebugStream(state) << "intercept function called\n";

}

void CameraProviderTester::registerCallSignalHandler(S2EExecutionState *state)
{
    // mct_queue_pop_head()
    uint64_t addr = m_pm->getAddressWithinFile("/vendor/lib/liboemcamera.so", 0x501c);
    if (addr != (uint64_t)-1) {
        getDebugStream(state) << "register intercept function handler " << hexval(addr) << "\n";
        FunctionMonitor::CallSignal *signal = m_fm->getCallSignal(state, addr, -1);
        signal->connect(sigc::mem_fun(*this,
                        &CameraProviderTester::onInterceptFunctionCall));
        m_callHandlerRegistered = true;
    }
}

void CameraProviderTester::on_mct_pipeline_process_serv_msg(S2EExecutionState *state, uint64_t pc)
{
    uint32_t r0 = state->regs()->read<uint32_t>(CPU_OFFSET(regs[0]));
    uint32_t r1 = state->regs()->read<uint32_t>(CPU_OFFSET(regs[1]));

    uint32_t command = *((uint32_t *)(r0 + 0x8));
    uint32_t *config_parm = (uint32_t *)(r1 + m_configParmOffset);

    getWarningsStream(state) << "intercept mct_pipeline_process_serv_msg\n"
            << "v4l2_event:\n"
            << "r0+0x00 = " << hexval(*((uint32_t *)(r0 + 0x0))) << "\n"
            << "r0+0x04 = " << hexval(*((uint32_t *)(r0 + 0x4))) << "\n"
            << "r0+0x08 command   = " << hexval(*((uint32_t *)(r0 + 0x8))) << "\n"
            << "r0+0x0c status    = " << hexval(*((uint32_t *)(r0 + 0xc))) << "\n"
            << "r0+0x10 session   = " << hexval(*((uint32_t *)(r0 + 0x10))) << "\n"
            << "r0+0x14 stream_id = " << hexval(*((uint32_t *)(r0 + 0x14))) << "\n"
            << "r0+0x18 map_op    = " << hexval(*((uint32_t *)(r0 + 0x18))) << "\n"
            << "r0+0x1c map_buf   = " << hexval(*((uint32_t *)(r0 + 0x1c))) << "\n"
            << "r0+0x20 notify    = " << hexval(*((uint32_t *)(r0 + 0x20))) << "\n"
            << "r0+0x24 arg_value = " << hexval(*((uint32_t *)(r0 + 0x24))) << "\n"
            << "r0+0x28 ret_value = " << hexval(*((uint32_t *)(r0 + 0x28))) << "\n"
            << "r0+0x2c v4l2_event_type = " << hexval(*((uint32_t *)(r0 + 0x2c))) << "\n"
            << "r0+0x30 v4l2_event_id   = " << hexval(*((uint32_t *)(r0 + 0x30))) << "\n"
            << "r0+0x34 nop5      = " << hexval(*((uint32_t *)(r0 + 0x34))) << "\n"
            << "r0+0x38 nop6      = " << hexval(*((uint32_t *)(r0 + 0x38))) << "\n"
            << "r0+0x3c nop7      = " << hexval(*((uint32_t *)(r0 + 0x3c))) << "\n"
            << "r0+0x40 nop5      = " << hexval(*((uint32_t *)(r0 + 0x38))) << "\n"
            << "r0+0x44 nop9      = " << hexval(*((uint32_t *)(r0 + 0x3c))) << "\n"
            << "pipeline:\n"
            << "r1+0xd34 config_parm      = " << hexval(*(config_parm + 0)) << "\n"
            << "r1+0xd38 config_parm_size = " << hexval(*(config_parm + 1)) << "\n"
            << "r1+0xd3c config_parm_fd   = " << hexval(*(config_parm + 2)) << "\n"
            << "r1+0xd40 query_buf        = " << hexval(*(config_parm + 3)) << "\n"
            << "r1+0xd44 query_buf_size   = " << hexval(*(config_parm + 4)) << "\n"
            << "r1+0xd48 query_buf_fd     = " << hexval(*(config_parm + 5)) << "\n"
            << "r1+0xd4c modules          = " << hexval(*(config_parm + 6)) << "\n"
            << "r1+0xd50 session          = " << hexval(*(config_parm + 7)) << "\n";

    // test on_mct_pipeline_process_serv_msg
    if (false) {
        m_de->makeMemSymbolic(state, r0 + 0x08, 4, "command");
        m_de->makeMemSymbolic(state, r0 + 0x0c, 4, "status");
        m_de->makeMemSymbolic(state, r0 + 0x10, 4, "session_id");
        m_de->makeMemSymbolic(state, r0 + 0x14, 4, "stream_id");
        m_de->makeMemSymbolic(state, r0 + 0x18, 4, "map_op");
        m_de->makeMemSymbolic(state, r0 + 0x1c, 4, "map_buf_idx");
        m_de->makeMemSymbolic(state, r0 + 0x20, 4, "notify");
        m_de->makeMemSymbolic(state, r0 + 0x24, 4, "arg_value");
        m_de->makeMemSymbolic(state, r0 + 0x28, 4, "ret_value");
        m_de->makeMemSymbolic(state, r0 + 0x2c, 4, "v4l2_event_type");
        m_de->makeMemSymbolic(state, r0 + 0x30, 4, "v4l2_event_id");
        m_de->makeMemSymbolic(state, r0 + 0x34, 4, "nop5");
        m_de->makeMemSymbolic(state, r0 + 0x38, 4, "nop6");
        m_de->makeMemSymbolic(state, r0 + 0x3c, 4, "nop7");
        m_de->makeMemSymbolic(state, r0 + 0x40, 4, "nop5");
        m_de->makeMemSymbolic(state, r0 + 0x44, 4, "nop9");
        m_testStarted = true;
    }

    // test set_parm
    if (true && !m_testStarted) {
        getWarningsStream(state) << "command = " << command <<"\n";
        if (command == m_command && ++m_commandCount > m_startAfterN) {
            if (m_cacheSim)
                m_cacheSim->enable(true);

            m_de->makeMemSymbolic(state, *config_parm + m_configParmTestOffset, m_configParmSize, "config_parm");
            m_testStarted = true;
        }
    }

    //se_set_debug_var(1);
}

void CameraProviderTester::onCall(S2EExecutionState *state, uint64_t pc)
{
    if (m_blockingPselect6Count >= 2) {
        m_interceptFunctionTid = gettid();
        m_interceptFunctionCalled = true;
        getWarningsStream(state) << m_interceptFunctionTid << " mct_queue_pop_head called\n";
    }
}

void CameraProviderTester::onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t pc, uint64_t rmask,
                                                  uint64_t wmask, bool accessesMemory)
{
    static bool registered = false;
    if ((tb->se_tb_type == TB_CALL_IND || tb->se_tb_type == TB_CALL)
         && (wmask & (1 << 14 | 1 << 15)) //&& !registered
         && (pc & 0x00000fff) == (m_processServMsgAddr & 0x00000fff)) {
        uint64_t offset;
        std::string file = m_pm->getFileName(pc, offset);
        if (offset == m_processServMsgAddr && file.compare("/vendor/lib/liboemcamera.so") == 0) {
            registered = true;
            signal->connect(sigc::mem_fun(*this, &CameraProviderTester::on_mct_pipeline_process_serv_msg));
        }
    }
}

void CameraProviderTester::onTranslateBlockStart(ExecutionSignal *signal,
        S2EExecutionState *state, TranslationBlock *tb, uint64_t pc)
{
    if (m_callHandlerRegistered) {
        return;
    } else if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        registerCallSignalHandler(state);
    }
}

void CameraProviderTester::onReturn(S2EExecutionState *state, uint64_t pc)
{
    if (!m_interceptFunctionTested) {
        getWarningsStream(state) << gettid() << " mct_queue_pop_head returned\n";
        uint32_t r0 = state->regs()->read<uint32_t>(CPU_OFFSET(regs[0]));
        uint32_t r7 = state->regs()->read<uint32_t>(CPU_OFFSET(regs[7]));
        getWarningsStream(state) << gettid() << " r0 = " << hexval(r0) << " r7 = " << hexval(r7) <<"\n";
        m_de->makeMemSymbolic(state, (uintptr_t)r0, 136, "mct_serv_msg");
        m_interceptFunctionTested = true;
    }
}

void CameraProviderTester::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                            TranslationBlock *tb, uint64_t pc, bool isStatic,
                                            uint64_t staticTarget)
{
    if (tb->se_tb_type == TB_RET
        && m_interceptFunctionCalled && m_interceptFunctionTid == gettid()
        && (pc & 0x00000fff) == 0x930) {
        uint64_t offset;
        std::string file = m_pm->getFileName(pc, offset);
        if (offset == 0x11930 && file.compare("/vendor/lib/liboemcamera.so") == 0) {
            signal->connect(sigc::mem_fun(*this, &CameraProviderTester::onReturn));
        }
    }
}

void CameraProviderTester::onTranslateJumpStart(ExecutionSignal *signal, S2EExecutionState *state,
                                             TranslationBlock *tb, uint64_t pc, int jump_type)
{
    if (jump_type == JT_RET
        && m_interceptFunctionCalled && m_interceptFunctionTid == gettid()
        && (pc & 0x00000fff) == 0x930) {
        uint64_t offset;
        std::string file = m_pm->getFileName(pc, offset);
        if (offset == 0x11930 && file.compare("/vendor/lib/liboemcamera.so") == 0) {
            signal->connect(sigc::mem_fun(*this, &CameraProviderTester::onReturn));
        }
    }
}

} // namespace plugins
} // namespace s2e
