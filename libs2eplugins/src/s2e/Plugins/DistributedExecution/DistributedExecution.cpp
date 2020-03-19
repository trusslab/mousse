/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>  Yingtong Liu <yingtong@uci.edu>  Ardalan Amiri Sani<ardalan@uci.edu> 
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/// Adopted and modified the MultiSearcher plugin code to implement the searcher in this plugin

#include "DistributedExecution.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <linux/binder.h>

#define FINE_GRAINED_FORK_LIMITER
static char cam_socket1_path[] = "disabled";

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(DistributedExecution, "DistributedExecution S2E Plugin", "",
                  "ProcessMonitor");


void DistributedExecution::print_data(state_t *data)
{
    if (!m_legacyMode) {
        int pos = 0;
        for (auto func : m_functions) {
            g_s2e->getWarningsStream() << "function: " << func.name << "\n";
            int a = 0;
            for (auto arg : func.args) {
                g_s2e->getWarningsStream() << "arg[" << a++ << "]: " << arg.name << " =";
                for (int i = 0; i < arg.size; i++){
                    g_s2e->getWarningsStream() << " [" << pos+i << "]" << hexval(data->input_buf[pos+i]);
                    if (i == arg.size -1) 
                        g_s2e->getWarningsStream() << "\n";
                }
                pos += arg.size;
            }
        }
    } else {
        int pos = 0;
        int a = 0;
        for (auto var : m_concolicVariables) {
            g_s2e->getWarningsStream() << "concolic variable[" << a++ << "]: " << var.name << " =";
            for (int i = 0; i < var.size; i++){
                g_s2e->getWarningsStream() << " [" << pos+i << "]" << hexval(data->input_buf[pos+i]);
                if (i == var.size -1) 
                    g_s2e->getWarningsStream() << "\n";
            }
            pos += var.size;
        }
    }

}

int DistributedExecution::get_input_buf_pos(std::string varName) {
    int pos = 0;
    bool found = false;
    if (!m_legacyMode) {
        for (auto func : m_functions) {
            for (auto arg : func.args) {
                if (varName.compare(func.name + "_" + arg.name) == 0) {
                    found = true;
                    break;
                }
                pos += arg.size;
            }
        }
    } else {
        for (auto var : m_concolicVariables) {
            if (varName.compare(var.name) == 0) {
                found = true;
                break;
            }
            pos += var.size;
        }
    }

    if (!found) {
        g_s2e->getWarningsStream() << "cannot find variable named "
                << varName << "\n";
        //FIXME
        terminate(-1);
    }

    return pos;
}

int DistributedExecution::get_input_buf_pos(std::string funcName, std::string argName) {
    int pos = 0;
    bool found = false;
    for (auto func : m_functions) {
        if (func.name == funcName) {
            for (auto arg : func.args) {
                if (arg.name == argName) {
                    found = true;
                    break;
                }
                pos += arg.size;
            }
        }
    }

    if (!found) {
        g_s2e->getWarningsStream() << "cannot find variable named "
                << funcName << " " << argName << "\n";
        //FIXME
        terminate(-1);
    }

    return pos;
}

void DistributedExecution::set_data(std::string vname, 
                                    const std::vector<unsigned char> &src, 
                                    char *dest) {
    size_t first = vname.find("_");
    size_t last = vname.rfind("_");
    int pos = get_input_buf_pos(vname.substr(first + 1, last - first - 1));
    for (int i = 0; i < src.size(); i++) {
        dest[pos + i] = src[i];
    }
}

void DistributedExecution::setSyscallOutput(std::string vname,
                                            syscall_symbolic_output_t *syscall_info) {
    size_t first = vname.find("_");
    size_t last = vname.rfind("_");
    std::string key = vname.substr(first + 1, last - first - 1);
    auto it = m_symbolicSyscalls.find(key);
    if (it != m_symbolicSyscalls.end())
        memcpy(syscall_info, &it, sizeof(syscall_symbolic_output_t));
}

/* TODO: we have several assertions in the code. We should have the assertions call terminate. */
// TODO multi-process probably should use onEngineShutdown
void DistributedExecution::terminate(int status) {
    if (mIsSymReceiver) {
            uint8_t isFork = 2;
            send(m_sym_sock_fd, &isFork, 1, 0);
    }
    exit(status);
}

void DistributedExecution::getDeviceId()
{
    std::fstream ifs("android_id.txt");

    if (!ifs)
        return;

    std::string deviceIdStr;
    ifs >> deviceIdStr;
    ifs.close();
    int startPos = deviceIdStr.size()-4;
    deviceIdStr = deviceIdStr.substr(startPos);
    memcpy(&m_deviceId, deviceIdStr.c_str(), 4);
}

void DistributedExecution::initialize() {
    m_stateStartTime = std::chrono::system_clock::now();

    m_endReason = STATUS_TERM_UNKNOWN;

    m_forked = false;
    m_stateId = 0;
    m_environmentIsClean = true;
    m_initialState = NULL;
    m_hasFetchedState = false;
    m_callHandlerRegistered = false;
    m_multiForkTempForkStateId = (uint32_t)-1;
    m_multiForkTempFork = false;
    m_multiForkCounter = 0;
    m_localForkDepth = 0;
    m_symbolicInputSize = 0;
    m_syscallHasSymbolicInputs = false;
    m_threadCount = 1;
    mousse_tostart_audio_server = true;
    mousse_tostart_audio_app = false;
    m_audioprovider_intercepted = false;
    m_audioserver_intercepted = false;
    m_audioserver_intercepted_thread = 0;
    Cam1Sockets = 0;
    m_syscalls.resize(ARM_SYSCALL_NUM_MAX + 1, 0);

    ConfigFile *cfg = s2e()->getConfig();
    std::string top = getConfigKey();
    m_testAudioProvider = cfg->getBool(top + ".testAudioProvider", false);
    m_testAudioServer = cfg->getBool(top + ".testAudioServer", false);
    if(m_testAudioProvider)
        binderpath = "/dev/hwbinder";
    else
        binderpath = "/dev/binder";
    m_legacyMode = cfg->getBool(top + ".legacyMode", false);

    m_rebootAfterTerminate = cfg->getBool(top + ".rebootAfterTerminate", true);

    // This will make the execution enter some infeasible paths
    m_makeSyscallReturnConcolic = cfg->getBool(top + ".makeSyscallReturnConcolic", false);
    m_makeEnvReturnConcolic = cfg->getBool(top + ".makeEnvReturnConcolic", false);

    m_forkLimiterThreshold = cfg->getInt(top + ".forkLimiterThreshold", (uint32_t)-1);

    m_offloadThreshold = cfg->getInt(top + ".offloadThreshold", 8);
    unsigned maxProcesses = g_s2e->getMaxProcesses();
    if (m_offloadThreshold > maxProcesses + 1) {
        m_offloadThreshold = maxProcesses + 1;
        getWarningsStream() << "offloadThreshold larger than S2E_MAX_PROCESSES + 1. adjust it to " << m_offloadThreshold << "\n";
    }

    m_noForkingFiles = cfg->getStringList(top + ".noForkingFiles");

    ConfigFile::integer_list checkFd
            = cfg->getIntegerList(top + ".syscalls.checkFd");
    foreach2 (it, checkFd.begin(), checkFd.end()) {
        if (*it <= ARM_SYSCALL_NUM_MAX) {
            m_syscalls.at(*it) |= SYSCALL_CHECK_FD;
        } else {
            getWarningsStream() << "invalid syscall number " << *it << "\n";
            exit(-1);
        }
    }

    ConfigFile::integer_list stateModifying
            = cfg->getIntegerList(top + ".syscalls.stateModifying");
    foreach2 (it, stateModifying.begin(), stateModifying.end()) {
        if (*it <= ARM_SYSCALL_NUM_MAX) {
            m_syscalls.at(*it) |= SYSCALL_STATE_MODIFYING;
        } else {
            getWarningsStream() << "invalid syscall number " << *it << "\n";
            exit(-1);
        }
    }

    ConfigFile::string_list files = cfg->getStringList(top + ".syscalls.stateModifyingIoctlFiles");
    foreach2 (it, files.begin(), files.end()) {
        m_environmentFiles.push_back(*it);
    }
    ConfigFile::string_list driver_files = cfg->getStringList(top + ".syscalls.EnvIoctlFiles");
    foreach2 (it, driver_files.begin(), driver_files.end()) {
        m_driverFiles.push_back(*it);
    }
    ConfigFile::integer_list stateRevealing
            = cfg->getIntegerList(top + ".syscalls.stateRevealing");
    foreach2 (it, stateRevealing.begin(), stateRevealing.end()) {
        if (*it <= ARM_SYSCALL_NUM_MAX) {
            m_syscalls.at(*it) |= SYSCALL_STATE_REVEALING;
        } else {
            getWarningsStream() << "invalid syscall number " << *it << "\n";
            exit(-1);
        }
    }

    ConfigFile::integer_list makeReturnConcolic
            = cfg->getIntegerList(top + ".syscalls.makeReturnConcolic");
    foreach2 (it, makeReturnConcolic.begin(), makeReturnConcolic.end()) {
        if (*it <= ARM_SYSCALL_NUM_MAX) {
            m_syscalls.at(*it) |= SYSCALL_MAKE_RET_CONCOLIC;
        } else {
            getWarningsStream() << "invalid syscall number " << *it << "\n";
            exit(-1);
        }
    }

    m_multiForkLimit = cfg->getInt(top + ".statesForkedOnConcretization", 2);

    m_stateExecutionThreshold = cfg->getInt(top + ".stateExecutionThreshold", (uint64_t)-1);

    m_blockingIoctlDetection = cfg->getBool(top + ".blockingIoctlDetection", false);
    m_blockingIoctlThreshold = cfg->getInt(top + ".blockingIoctlThreshold");
    ConfigFile::string_list ioctlFiles = cfg->getStringList(top + ".blockingIoctlFiles");
    foreach2 (it, ioctlFiles.begin(), ioctlFiles.end()) {
        m_blockingIoctlFiles.push_back(*it);
    }

    m_cameraProviderTestCode = cfg->getInt(top + ".cameraProviderTestCode");
#ifndef TEST_CAMERA_PROVIDER
    m_initialized = !m_blockingIoctlDetection;
#else
    m_initialized = false;
#endif
    m_initAddress = cfg->getInt(top + ".initAddress");

    m_portNum = cfg->getInt(top + ".portNum", DEFAULT_PORT);

    m_input_buf_used = 0;
    if (!m_legacyMode) {
        ConfigFile::string_list functions = cfg->getListKeys(top + ".functions");
        foreach2 (it, functions.begin(), functions.end()) {
            functionT function = functionT();
            const std::string &funcName = *it;
            std::string func = top + ".functions." + funcName;
            function.name = funcName;
            function.addr = cfg->getInt(func + ".address");

            ConfigFile::string_list arguments = cfg->getListKeys(func + ".arguments");
            function.args.resize(arguments.size());
            foreach2 (it, arguments.begin(), arguments.end()) {
                const std::string &argName = *it;
                std::string arg = func + ".arguments." + argName;
                int argNum = cfg->getInt(arg + ".num");
                int argSize = cfg->getInt(arg + ".size");
                int argValue = cfg->getInt(arg + ".value");
                function.args.at(argNum) = argT(argSize, argValue, argName);
            }
            m_functions.push_back(function);
        }

        g_s2e->getDebugStream() << "DistributedExecution: will insert concolic variables at:\n";
        for (auto it : m_functions) {
            g_s2e->getDebugStream() << "function: " << it.name
                    << " @ " << hexval(it.addr) << "\n";
            int i = 0;
            for (auto arg : it.args) {
                m_input_buf_used += arg.size;
                g_s2e->getDebugStream() << "arg[" << i++ << "] " 
                    << "name = " << arg.name <<", size = " << arg.size << "\n";
            }
        }
    }

    //TODO: variable size of input_buf to be sent and a large args buffer
    if (m_input_buf_used > INPUT_BUF_SIZE) {
        getWarningsStream() << "concolic variables exceed buffer size\n";
        exit(-1); 
    }

    getDeviceId();

    s2e()->getCorePlugin()->onStateForkBeforeBranch.connect(
            sigc::mem_fun(*this, &DistributedExecution::onStateFork));
    s2e()->getCorePlugin()->onStateKill.connect(
            sigc::mem_fun(*this, &DistributedExecution::onStateKill));
    s2e()->getCorePlugin()->onConcretizeSyscallArgs.connect(
            sigc::mem_fun(*this, &DistributedExecution::onConcretizeSyscallArgs));
    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
            sigc::mem_fun(*this, &DistributedExecution::onConcreteDataMemoryAccess));
    s2e()->getCorePlugin()->onDoSyscallStart.connect(
            sigc::mem_fun(*this, &DistributedExecution::onDoSyscallStart));
    s2e()->getCorePlugin()->onDoSyscallEnd.connect(
            sigc::mem_fun(*this, &DistributedExecution::onDoSyscallEnd));
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &DistributedExecution::onTranslateBlockStart));
    s2e()->getCorePlugin()->onReceiveSignal.connect(
            sigc::mem_fun(*this, &DistributedExecution::onReceiveSignal));
    s2e()->getPlugin<BaseInstructions>()->onIsSymbolic.connect(
            sigc::mem_fun(*this, &DistributedExecution::onIsSymbolic));

    if (m_legacyMode) {
        s2e()->getPlugin<BaseInstructions>()->onBeforeMakeSymbolic.connect(
                sigc::mem_fun(*this, &DistributedExecution::onBeforeMakeSymbolic));
    }
    s2e()->getCorePlugin()->onOtherMakeConcolic.connect(
            sigc::mem_fun(*this, &DistributedExecution::onOtherMakeConcolic));

    s2e()->getExecutor()->setSearcher(this);

    m_pm = s2e()->getPlugin<ProcessMonitor>();
    assert(m_pm);

    m_stackMonitor = s2e()->getPlugin<StackMonitor>();
    assert(m_stackMonitor);

    m_memoryBugChecker = s2e()->getPlugin<MemoryBugChecker>();
    if (m_memoryBugChecker) {
        m_memoryBugChecker->onBugDetected.connect(
            sigc::mem_fun(*this, &DistributedExecution::onBugDetected));
    }

    m_libcMemoryChecker = s2e()->getPlugin<LibcMemoryChecker>();
    if (m_libcMemoryChecker) {
        m_libcMemoryChecker->onBugDetected.connect(
            sigc::mem_fun(*this, &DistributedExecution::onBugDetected));
        m_libcMemoryChecker->onBugDetected2.connect(
            sigc::mem_fun(*this, &DistributedExecution::onBugDetected2));
    }

    if (g_s2e->connectToServer(m_portNum) != 0) {
        getWarningsStream() << "failed to connect to the server\n";
        exit(-1);
    }
    sendStatusToServer(STATUS_START);

}

void DistributedExecution::onLoadImage(S2EExecutionState *state, ImageInfo *info) {
    m_loadAddress = info->start_code;
}

void DistributedExecution::initFunctionReturn(S2EExecutionState *state) {
    return;
}

void DistributedExecution::makeRegConcolic(S2EExecutionState *state, int address, unsigned size,
                                           const std::string &name, char *value) {
    assert(size <= 4 && "size cannot be larger than 4");

    if (state->isRunningConcrete()) {
        s2e()->getExecutor()->switchToSymbolic(state);
    }
    std::vector<unsigned char> concreteValue;
    for (int i = 0; i < size; i++)
        concreteValue.push_back(value[i]);
    klee::ref<klee::Expr> concolicValue = state->createConcolicValue(name, size * 8, concreteValue);

    state->regs()->write(CPU_OFFSET(regs[address]), concolicValue);
    getDebugStream(state) << "write symbolic value to register[" << address << "]\n"
            << state->regs()->read(CPU_OFFSET(regs[address]), klee::Expr::Int32) << "\n";
}

void DistributedExecution::makeMemSymbolic(S2EExecutionState *state,
        uintptr_t address, unsigned size, const std::string &name)
{
    if (!m_hasFetchedState) {
        fetchStateFromServer();
    }

    DistributedState *dstate = pendingStates.front();
    uint8_t *data = NULL;
    for (unsigned i = 0; i < size; i += 4) {
        std::stringstream ss;
        ss << name << "_" << i/4;
        std::string inputName = ss.str();
        addConcolic(state, inputName, 4);
        if (m_ignoreForkDepth != 0) {
            int pos = get_input_buf_pos(inputName);
            data = (uint8_t *)&dstate->data.input_buf[pos];
        }
        makeMemSymbolic(state, address + i, 4, inputName, true, NULL, NULL, data);
    }
}

//Core/BaseInstruction.cpp makeSymbolic
void DistributedExecution::makeMemSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
                                           const std::string &name, bool makeConcolic,
                                           std::vector<klee::ref<klee::Expr>> *varData = NULL,
                                           std::string *varName = NULL,
                                           uint8_t *alternativeConcreteData = NULL) {
    std::vector<klee::ref<klee::Expr>> symb;
    std::stringstream valueSs;

    if (makeConcolic) {
        std::vector<uint8_t> concreteData;

        valueSs << "='";
        for (unsigned i = 0; i < size; ++i) {
            uint8_t byte = 0;
            if (alternativeConcreteData == NULL) {
                if (!state->mem()->read<uint8_t>(address + i, &byte, VirtualAddress, false)) {
                    getWarningsStream(state) << "Can not concretize/read symbolic value at "
                            << hexval(address + i) << ". System state not modified\n";
                    return;
                }
            } else {
                byte = alternativeConcreteData[i];
            }
            concreteData.push_back(byte);
            valueSs << charval(byte);
        }
        valueSs << "'";
        symb = state->createConcolicArray(name, size, concreteData, varName);
    } else {
        symb = state->createSymbolicArray(name, size, varName);
    }

    uint64_t offset;
    std::string file = m_pm->getFileName(state->regs()->getPc(), offset);
    getWarningsStream(state) << "Inserted symbolic data @" << hexval(address)
            << " of size " << hexval(size) << ": " << (varName ? *varName : name)
            << valueSs.str() << " pc=" << hexval(state->regs()->getPc())
            << " (" << file << ":" << hexval(offset) << ")\n";

    for (unsigned i = 0; i < size; ++i) {
        if (!state->mem()->write(address + i, symb[i])) {
            getWarningsStream(state) << "Can not insert symbolic value at " << hexval(address + i)
                                     << ": can not write to memory\n";
        }
    }

    if (varData) {
        *varData = symb;
    }
}

void DistributedExecution::makeArgumentsConcolic(S2EExecutionState *state, 
                                                 functionT &function) {

    for (int i = 0; i < function.args.size(); i++) {
        std::string vname = function.name + "_" + function.args.at(i).name;
        int size = function.args.at(i).size;
        if (size <= 4) { //XXX size can only be 1 or 4 here 
            /* insert concolic data to register */
            int pos = get_input_buf_pos(function.name, function.args.at(i).name);
            char *data_ptr = &pendingStates.front()->data.input_buf[pos];
            makeRegConcolic(state, i, size, vname, data_ptr);
        } else {
            /* insert concolic data to memory */
            target_ulong address;
            state->regs()->read(CPU_OFFSET(regs[i]), &address, sizeof address, false);
            makeMemSymbolic(state, address, size, vname, true);
        }
    }
}

int DistributedExecution::getDataFromMousseServer(uint32_t opcode, void *buf) {
    return g_s2e->getDataFromServer(opcode, buf, OP_BUF_SIZE(opcode));
}

void DistributedExecution::sendDataToMousseServer(uint32_t opcode, void *buf) {
    g_s2e->sendDataToServer(opcode, buf, OP_BUF_SIZE(opcode));
}

uint32_t DistributedExecution::getNewStateIdFromServer() {
    state_t state;
    while (getDataFromMousseServer(OPC_R_GET_STATE_ID, &state) != 0) {
        sleep(INPUT_REQ_WAIT);
    };
    return state.id;
}

void DistributedExecution::initializeForkCounters(fork_counters_t *forkCounters) {
    for (unsigned i = 0; i < FORK_COUNTERS_SIZE; i++) {
        fork_counter_t *forkCounter = &forkCounters->counter[i];
        if (forkCounter->hash != 0) {
            m_forkCounter[forkCounter->hash] = forkCounter->count;
        } else {
            break;
        }
    }
    m_localForkCounter = m_forkCounter;
}

void DistributedExecution::sendStatusToServer(uint32_t status_flag) {
    status_t status;
    if (status_flag == STATUS_START)
    {
        status.state_id = m_deviceId;
    }
    else
        status.state_id = m_stateId;
    status.status = status_flag;
    auto cur = std::chrono::system_clock::now();
    std::chrono::duration<double> dur = cur - m_stateStartTime;
    status.duration = static_cast<int>(dur.count());
    sendDataToMousseServer(OPC_W_STATUS, &status);
}

void DistributedExecution::sendForkCounterToServer() {
    fork_counters_t forkCounters;
    unsigned i = 0;
    for (auto it : m_localForkCounter) {
        auto originalCounter = m_forkCounter.find(it.first);
        if (originalCounter == m_forkCounter.end()) {
            forkCounters.counter[i].hash = it.first;
            forkCounters.counter[i].count = it.second;
        } else {
            forkCounters.counter[i].hash = it.first;
            forkCounters.counter[i].count = it.second - originalCounter->second;
        }
        i++;
    }
    sendDataToMousseServer(OPC_W_UPDATE_FORK_COUNTERS, &forkCounters);
}

void DistributedExecution::fetchStateFromServer() {
    if (!m_hasFetchedState) {
        DistributedState *dstate = pendingStates.front();
        while (getDataFromMousseServer(OPC_R_GET_STATE, &dstate->data) != 0) {
            sleep(INPUT_REQ_WAIT);
        };
        m_stateId = dstate->data.id;
        g_s2e->addStateIfClean(m_stateId);
        m_ignoreForkDepth = dstate->data.ignore_depth;
        m_hasFetchedState = true;

        sendStatusToServer(STATUS_TEST);

#ifndef FINE_GRAINED_FORK_LIMITER
        fork_counters_t forkCounter;
        getDataFromMousseServer(OPC_R_GET_FORK_COUNTERS, &forkCounter);
        initializeForkCounters(&forkCounter);
#endif
    }
}

void DistributedExecution::testFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns) {
    if (m_legacyMode)
        return;

    fetchStateFromServer();

    uint64_t pc = state->regs()->getPc(); 
    //FIXME prevent inserting symbolic variables multiple times if the function gets called again
    for (auto it : m_functions) {
        getDebugStream(state) << "test function " << it.name << " is called\n";
        if (it.addr + m_loadAddress == pc) {
            makeArgumentsConcolic(state, it);
        }
    }
}

void DistributedExecution::initFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns) {
    FUNCMON_REGISTER_RETURN(state, fns, DistributedExecution::initFunctionReturn)
}

void DistributedExecution::registerCallSignalHandler(S2EExecutionState *state)
{
    spawnTimerThread(state);
    m_callHandlerRegistered = true;
}

void DistributedExecution::onTranslateBlockStart(ExecutionSignal *signal, 
                                                 S2EExecutionState *state, 
                                                 TranslationBlock *tb, 
                                                 uint64_t pc) {
    if (m_callHandlerRegistered) {
        return;
    } else {
        registerCallSignalHandler(state);
    }
}
void DistributedExecution::concreteInputsToBuffer(const ConcreteInputs &ci, state_t *s) {
    ConcreteInputs::const_iterator it;
    for (it = ci.begin(); it != ci.end(); ++it) {
        const VarValuePair &vp = *it;
        set_data(vp.first, vp.second, s->input_buf);
    }
}

/* From TestCaseGenerator */
void DistributedExecution::addToPendingStates(llvm::raw_ostream &os, 
                                              S2EExecutionState *state, int depth) {
    std::stringstream ss;
    ConcreteInputs state_inputs;
    bool success;
    DistributedState *dstate = NULL;

    success = s2e()->getExecutor()->getSymbolicSolution(*state, state_inputs);

    if (!success) {
        getWarningsStream(state) << "Could not get symbolic solutions" << '\n';
        return;
    }

    dstate = new DistributedState();
    if (!dstate) {
        getWarningsStream(state) << "Could not allocate memory for dstate" << '\n';
        return;
    }

    dstate->state = state;
    dstate->data.ignore_depth = depth;

    ConcreteInputs::const_iterator it;
    for (it = state_inputs.begin(); it != state_inputs.end(); ++it) {
        const VarValuePair &vp = *it;
        ss << std::setw(20) << vp.first << " = {";

        for (unsigned i = 0; i < vp.second.size(); ++i) {
            if (i != 0)
                ss << ", ";
            ss << std::setw(2) << std::setfill('0') << "0x" << std::hex
                    << (unsigned) vp.second[i] << std::dec;
        }
        ss << "}" << std::setfill(' ') << "; ";

        if (vp.second.size() == sizeof(int32_t)) {
            int32_t valueAsInt = vp.second[0] | ((int32_t) vp.second[1] << 8) |
                    ((int32_t) vp.second[2] << 16) | ((int32_t) vp.second[3] << 24);
            ss << "(int32_t) " << valueAsInt << ", ";
        }

        if (vp.second.size() == sizeof(int64_t)) {
            int64_t valueAsInt = vp.second[0] | ((int64_t) vp.second[1] << 8) |
                    ((int64_t) vp.second[2] << 16) | ((int64_t) vp.second[3] << 24) |
                    ((int64_t) vp.second[4] << 32) | ((int64_t) vp.second[5] << 40) |
                    ((int64_t) vp.second[6] << 48) | ((int64_t) vp.second[7] << 56);
            ss << "(int64_t) " << valueAsInt << ", ";
        }

        ss << "(string) \"";
        for (unsigned i = 0; i < vp.second.size(); ++i) {
            ss << (char) (std::isprint(vp.second[i]) ? vp.second[i] : '.');
        }
        ss << "\"\n";

        set_data(vp.first, vp.second, dstate->data.input_buf);
        setSyscallOutput(vp.first, dstate->data.syscall_output);
    }

    os << "concrete inputs for the forked state:\n" << ss.str();

    pendingStates.push_back(dstate);
}

void DistributedExecution::offloadState(S2EExecutionState *currentState,
                                        S2EExecutionState *offloadState,
                                        const std::string &reason) {

    assert(pendingStates.size() == 1);
    getWarningsStream(currentState) << "offload state["
            << (m_stateId & 0xffff) << "] (" << reason << ")\n";

    bool offloadTheOtherState = (currentState != offloadState);
    if (offloadTheOtherState) {
        addToPendingStates(getWarningsStream(currentState), offloadState, m_localForkDepth);
        pendingStates.back()->data.id = getNewStateIdFromServer();
    } else {
        pendingStates.back()->data.id = m_stateId;
        // update the ignore depth so that we won't fork duplicate states
        // once it gets executed on another device
        pendingStates.back()->data.ignore_depth = m_localForkDepth;
    }

    sendDataToMousseServer(OPC_W_OFFLOAD_STATE, &pendingStates.back()->data);
    g_s2e->getExecutor()->terminateState(*offloadState);

    if (offloadTheOtherState)
        pendingStates.pop_back();
}

#ifdef FINE_GRAINED_FORK_LIMITER
bool DistributedExecution::updateForkCounter(S2EExecutionState *state, uint64_t offset) {
    bool exceedForkingThreshold;
    uint32_t counter;
    uint64_t forkCounterKey;
    if (m_stackMonitor) {
        forkCounterKey = m_stackMonitor->getCallStackHash(state, 1, pthread_self());
        forkCounterKey = forkCounterKey * 314159 + offset;
    } else {
        forkCounterKey = offset;
    }

    if (g_s2e->sendQueryToServer(OPC_Q_INC_AND_GET_FORK_COUNTER, forkCounterKey, &counter, 4) == 0
        && counter >= m_forkLimiterThreshold) {
        exceedForkingThreshold = true;
    } else {
        exceedForkingThreshold = false;
    }
    getWarningsStream(state) << "inc_and_get hash = " << hexval(forkCounterKey)
            << ", counter = " << counter << "\n";
    return exceedForkingThreshold;
}
#else
bool DistributedExecution::updateForkCounter(S2EExecutionState *state, uint64_t offset) {
    bool exceedForkingThreshold;
    uint64_t forkCounterKey;
    if (m_stackMonitor) {
        forkCounterKey = m_stackMonitor->getCallStackHash(state, 1, pthread_self());
        forkCounterKey = forkCounterKey * 314159 + offset;
    } else {
        forkCounterKey = offset;
    }

    auto forkCounterItr = m_localForkCounter.find(forkCounterKey);
    if (forkCounterItr == m_localForkCounter.end()) {
        getWarningsStream(state) << "forkCounter: hash = " << hexval(forkCounterKey) << " 1\n";
        m_localForkCounter[forkCounterKey] = 1;
    } else {
        getWarningsStream(state) << "forkCounter: hash = " << hexval(forkCounterKey)
                << " " << forkCounterItr->second << "\n";
        forkCounterItr->second++;
    }

    getWarningsStream(state) << "forkLimiterThreshold = " << m_forkLimiterThreshold << "\n";
    if (m_localForkCounter[forkCounterKey] >= m_forkLimiterThreshold) {
        exceedForkingThreshold = true;
    } else {
        exceedForkingThreshold = false;
    }
    return exceedForkingThreshold;
}
#endif

/**
 *  Fork another process for the forked state and offload the state to server
 *  if the number of processes on a device exceeds m_offloadThreshold
 *
 *  intput type:
 *      1: branch
 *      2: concretization of arguments (registers) of external functions
 *      3: concretization of arguments (memory) of syscalls
 *  output isChild for the executor to handle the divering behavior in the forked state
 */
void DistributedExecution::onStateFork(S2EExecutionState *state,
                                       const std::vector<S2EExecutionState*>& new_states,
                                       const std::vector<klee::ref<klee::Expr>>& new_conditions,
                                       int type, bool &isChild) {

    uint64_t offset;
    uint64_t pc = state->regs()->getPc();
    std::string file = m_pm->getFileName(pc, offset);
    getWarningsStream(state) << "onStateFork fork at " << file
            << ":" << hexval(offset) << " type: " << type
            << " pthread_self = " << hexval((uint32_t)pthread_self())
            << " gettid = " << hexval((uint32_t)syscall(SYS_gettid)) << "\n";
    getWarningsStream(state) << "multiForkTempFork: " << m_multiForkTempFork
            << ", multiForkCounter: " << m_multiForkCounter
            << ", localForkDepth: " << m_localForkDepth
            << ", threadCount: " << m_threadCount << "\n";

    // Only increase the depth once at the beginning if it is concretization fork
    if (type == 1 ||
        (m_multiForkLimit != 1 && m_multiForkCounter == 0)) {
        m_localForkDepth++;
    }

    // Decide if we are going to fork the state
    bool forkState = true;
    if (m_localForkDepth <= m_ignoreForkDepth) {
        getWarningsStream(state) << "not forking: m_localForkDepth (" << m_localForkDepth
                << ") <= m_ignoreForkDepth (" << m_ignoreForkDepth << ")\n";
        forkState = false;
    }

    if (type != 1 && m_multiForkCounter + 1 >= m_multiForkLimit) {
        getWarningsStream(state) << "not forking: m_multiForkCounter (" << m_multiForkCounter
                << ") + 1 >= m_multiForkLimit (" << m_multiForkLimit << ")\n";
        forkState = false;
        // offload and terminate the last temporarily forked state
        if (m_multiForkTempFork && m_multiForkCounter + 1 == m_multiForkLimit) {
            offloadState(state, state, "concretization temp fork");
            return; // should not reach here
        }
    }

    if (m_pm) {
        for (auto file: m_noForkingFiles) {
            if (m_pm->isAddressWithinFile(state->regs()->getPc(), file)) {
                getWarningsStream(state) << "not forking: forking disabled within " << file <<"\n";
                forkState = false;
            }
        }
    }

    if (forkState && type == 1 && updateForkCounter(state, offset)) {
        getWarningsStream(state) << "not forking: hit forking limit at current location\n";
        forkState = false;
        getWarningsStream(state) << "audioprovider: test finish\n";
        if(m_testerPid)
            kill(m_testerPid, SIGTERM);
        m_endReason = STATUS_TERM_REACH_FORK_LIMIT;
        s2e()->getExecutor()->terminateState(*state);
    }

    S2EExecutionState *other_state = (state == new_states[0])? new_states[1] : new_states[0];

    if (!forkState) {
        g_s2e->getExecutor()->terminateState(*other_state);
        return;
    }

    new_states[0]->setStateSwitchForbidden(true);
    new_states[1]->setStateSwitchForbidden(true);

    if (g_s2e->getCurrentProcessCount() + 1 >= m_offloadThreshold) {
        if (type == 1) {
            offloadState(state, other_state, "process threshold");
            return;
        } else {
            // still fork using spare process slots and offload
            if (m_multiForkTempForkStateId == (uint32_t)-1) {
                getWarningsStream(state) << "start temp fork\n";
                m_multiForkTempForkStateId = m_multiForkCounter;
                m_multiForkTempFork = true;
            }
        }
    } else {
        m_multiForkTempFork = false;
    }

    int new_monitor_port, new_sym_port;
    if (!m_multiForkTempFork) {
        if (mIsSymReceiver) {
            new_monitor_port = (rand() % 55000) + 10000;
            new_sym_port = (rand() % 55000) + 10000;
            sendForkInfo(state, (uint16_t) new_monitor_port, (uint16_t) new_sym_port);
        }
    }

    // Fork the process
    int child = g_s2e->fork();
    if (child == 1) { /* forked state*/
        m_endReason = STATUS_TERM_UNKNOWN;
        m_stateId = getNewStateIdFromServer() | (m_stateId << 16);
        getWarningsStream(state) << "start forked state[" << (m_stateId & 0xffff)
                << "] pthread_self = " << hexval((uint32_t)pthread_self())
                << " gettid = " << hexval((uint32_t)syscall(SYS_gettid)) << "\n";
        addToPendingStates(getWarningsStream(state), other_state, m_localForkDepth);
        memcpy((void *)&pendingStates.front()->data,
               (void *)&pendingStates.back()->data, sizeof(state_t));
        pendingStates.front()->data.id = m_stateId;
        pendingStates.pop_back();

        // copy s2e state from the other state to the current state since we
        // want to preserve the memory map
        *state->concolics = *other_state->concolics;
        state->constraints = other_state->constraints;
        g_s2e->getExecutor()->terminateState(*other_state);

        spawnTimerThread(state);

        if (type == 2 || type == 3) {
            m_multiForkCounter += 1;
            sendDataToMousseServer(OPC_W_TEMP_FORK_STATE, &pendingStates.front()->data);
        } else {
            // send the locally-executed forked state to server
            sendDataToMousseServer(OPC_W_FORK_STATE, &pendingStates.front()->data);
        }

        if (!m_multiForkTempFork) {
            if (mIsSymReceiver) {
                m_sym_port = new_sym_port;
                waitForSymChannel();
                m_monitor_port = new_monitor_port;
                fixMonitorSocketReceiver();
            }
            m_forked = true;
            m_environmentIsClean = g_s2e->addStateIfClean(m_stateId);
        }

        isChild = true;
    } else if (child == 0) { /* original state */
        if (m_multiForkTempFork && m_multiForkCounter > m_multiForkTempForkStateId) {
            // offload and terminate the temporarily forked state
            offloadState(state, state, "concretization temp fork");
            return; // should not reach here
        } else {
            g_s2e->getExecutor()->terminateState(*other_state);
            m_forked = true;
            m_multiForkCounter = 0;
            m_multiForkTempFork = false;
            m_multiForkTempForkStateId = (uint32_t)-1;
        }
        isChild = false;
    }
}

void DistributedExecution::spawnTimerThread(S2EExecutionState *state) {
    m_timerThread = new std::thread(&DistributedExecution::onTimer, this, state);
}

void DistributedExecution::testAudioProvider(S2EExecutionState *state) {
    char start_proc_name[30] = "start_audio_app.sh";
    if (mousse_tostart_audio_server) {
        strcpy(start_proc_name, "start_audio_server.sh");
        mousse_tostart_audio_server = false;
        mousse_tostart_audio_app = true;
        m_blockingIoctlThreshold = m_blockingIoctlThreshold + 900;
        getWarningsStream() << "starting audioserver\n";
    } else if (mousse_tostart_audio_app) {
        getWarningsStream() << "starting audio application\n";
        m_initialized = true;
        mousse_tostart_audio_app = false;
    } else {
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        char * const argv[] = {(char *)"sh", start_proc_name, (char *)NULL};
        execv("/system/bin/sh", argv);
        exit(0);
    } else {
        m_testerPid = pid;
    }
}
void DistributedExecution::testAudioServer(S2EExecutionState *state) {
    std::fstream ifs("/data/local/mousse/target_AudioServer/audioserver_interface.txt");
    getWarningsStream() << "testAudioServer\n";
    if (ifs.is_open()) {
         getWarningsStream() << "open audioserver_interface.txt\n";
         std::string strTemp;
         while (ifs >> strTemp) {
            if (!strTemp.compare("audioserver_initialized=")) {
                ifs << "true";
                getWarningsStream() << "setting audioserver_initialized to true\n";
            }
        }
    } else {
        assert(0 && "writing audioserver_initialized to audioprovider_interface.txt failed\n");
    }
     m_initialized = true;
}

void DistributedExecution::onTimer(S2EExecutionState *state)
{
    while (1) {
        sleep(2);
        onDistributedExecutionTimer.emit(state);

        if (m_blockingIoctlDetection) {
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
                if(m_testAudioProvider)
                    testAudioProvider(state);
                else if(m_testAudioServer)
                    testAudioServer(state);
                for (auto &it : m_activeIoctls) {
                    it.second = 0;
                }
            } else if (hasBlockingIoctl && m_initialized) {
                if(m_testAudioProvider)
                {
                    getWarningsStream(state) << "blocking ioctl: test finish\n";
                    if(m_testerPid)
                        kill(m_testerPid, SIGTERM);
                    m_endReason = STATUS_TERM_TEST_FINISH;
                    s2e()->getExecutor()->terminateState(*state);
                }
            }
        }

        // state execution limit
        auto cur = std::chrono::system_clock::now();
        std::chrono::duration<double> dur = cur - m_stateStartTime;
        if (dur.count() > m_stateExecutionThreshold) {
            getWarningsStream(state) << "Execution Timeout\n";
            // terminate?
            m_endReason = STATUS_TERM_TIMEOUT;
            g_s2e->getExecutor()->terminateState(*state);
        }
    }
}

void DistributedExecution::onStateKill(S2EExecutionState *state) {

    // only state[0] of each processes are real states
    if (state->getID() == 0) {
        getWarningsStream(state) << "state[" << (m_stateId & 0xffff) << "] terminate [1]\n";
        if (!m_multiForkTempFork) {
            onDistributedStateKill.emit(state, m_stateId);
            sendStatusToServer(m_endReason);
            sleep(2);

#ifndef FINE_GRAINED_FORK_LIMITER
            sendForkCounterToServer();
#endif
        }

        g_s2e->setCurrentProcessFinished();
        sleep(2);
        getWarningsStream(state) << "pid = " << getpid() << " after CurrentProcessCount = " << g_s2e->getCurrentProcessCount() << "\n";

        if (g_s2e->getCurrentProcessCount() == 0 || g_s2e->getCurrentProcessCount() > 400000) {
            if (m_rebootAfterTerminate) {
                getWarningsStream(state) << "reboot [" << (m_stateId & 0xffff) << "]\n";
                sync();
                getWarningsStream(state) << "RB_AUTOBOOT\n";
                reboot(RB_AUTOBOOT);
            } else {
                getWarningsStream(state) << "pid = " << getpid()
                        << " send SIGTERM to state[" << (m_stateId & 0xffff) << "]\n";
                kill(getpid(), SIGTERM);
            }
        }
    }

    if (mIsSymReceiver) {
        uint8_t isFork = 2;
        send(m_sym_sock_fd, &isFork, 1, 0);
    }
}

void DistributedExecution::addConcolic(S2EExecutionState *state, const std::string &name, int size) {
    if (m_input_buf_used + size < INPUT_BUF_SIZE) {
        m_input_buf_used += size;
        m_concolicVariables.push_back(argT(size, 0, name));
    } else {
        getWarningsStream(state) << "concolic variable will exceed buffer size\n";
        s2e()->getExecutor()->terminateState(*state);
    }
}

/**
 *  Intercept s2e_make_concolic/s2e_make_symbolic in BaseInstruction plugin
 *  in legacy mode. Update concolic variable information and send concrete
 *  data to be used to make concolic vriables
 */
void DistributedExecution::onBeforeMakeSymbolic(S2EExecutionState *state,
                                                uintptr_t address, unsigned size,
                                                const std::string &name,
                                                uint8_t *&alternativeConcreteData) {
    addConcolic(state, name, size);

    fetchStateFromServer();
    m_symbolicInputSize += size;
    if (m_ignoreForkDepth == 0) {
        return;
    }
    // Notify BaseInstructions plugin to use the data in input buffer to
    // make concolic variables
    int pos = get_input_buf_pos(name);
    DistributedState *dstate = pendingStates.front();
    alternativeConcreteData = (uint8_t *)&dstate->data.input_buf[pos];
}

/**
 *  When receiving the signal, make the memory concolic.
 *  FIXME: may cause errors if being called more than once and the creation
 *  order of variables are different.
 */
static int syscall_output_count = 0;
void DistributedExecution::onOtherMakeConcolic(S2EExecutionState *state,
                                               uint64_t address, unsigned size,
                                               const std::string &name) {
    /* mark memory as concolic when:
       1. the address is syscall output and the syscall has symbolic inputs 
       2. the address is not syscall output
    */
    if (name.compare(0, 18, "syscall_sym_output") != 0) {
        addConcolic(state, name, size);
    
        fetchStateFromServer();
    
        // Use the concrete value from server if it is not the initial state
        uint8_t *alternativeConcreteData = NULL; 
        if (m_ignoreForkDepth != 0) {
            int pos = get_input_buf_pos(name);
            DistributedState *dstate = pendingStates.front();
            alternativeConcreteData = (uint8_t *)&dstate->data.input_buf[pos];
        }
        makeMemSymbolic(state, address, size, name, true, NULL, NULL, alternativeConcreteData);
    } else if (m_syscallHasSymbolicInputs) {
        int j; 
        char output_name[50];
        uint8_t *alternativeConcreteData = NULL; 
        for (j = 0; j + 4 <= size; j += 4) {
            sprintf(output_name, "syscall_sym_output_%d_%d", syscall_output_count,j);
            addConcolic(state, output_name, 4);
            alternativeConcreteData = (uint8_t *)address;
            /* FIXME: This alternativeConcreteData may not be the actual concrete output from syscall if access_ok(VERIFY_WRITE,...) is being called before the actual syscall */
            makeMemSymbolic(state, address, 4, output_name, true, NULL, NULL, alternativeConcreteData);
            address += 4;
        };
        if (size - j) {
            sprintf(output_name, "syscall_sym_output_%d_%d", syscall_output_count,j);
            addConcolic(state, output_name, size - j);
            alternativeConcreteData = (uint8_t *)address;
            makeMemSymbolic(state, address, size -j, output_name, true, NULL, NULL, alternativeConcreteData);
        }
        syscall_output_count++;
    }
}

bool DistributedExecution::checkSyscall(uint64_t syscall_num, uint32_t mask) {
    return m_syscalls.at(syscall_num) & mask;
}

void DistributedExecution::updateConcolicVariables(std::vector<klee::concolicData> concolicVariables) {

    for (auto var : concolicVariables) {
        /* FIXME: deserializer always returns 0 for value */
        m_concolicVariables.push_back(argT(var.size, var.value, var.name));
    }
}

int DistributedExecution::waitForConnection(int port, int *sockp, bool doRecoverFd, int recovFd) {

    int server_fd, sock;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt))) {
        close(server_fd);
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 3) < 0) {
        close(server_fd);
        return -1;
    }

    if (doRecoverFd)
        recoverFd(recovFd);

    if ((sock = accept(server_fd, (struct sockaddr *)&address,
                                (socklen_t*)&addrlen))<0) {
        close(server_fd);
        return -1;
    }

    if (sockp)
        *sockp = sock;

    close(server_fd);

    return 0;


}

int DistributedExecution::waitForSymChannel(void) {

    int ret = waitForConnection(m_sym_port, &m_sym_sock_fd, false, 0);
    assert((ret == 0) && "failed to receive connection for sym channel");
    return ret;
}

int DistributedExecution::establishConnection(int port, int *sockp) {

    struct sockaddr_in serv_addr;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return -1;
    }

    if (sockp)
        *sockp = sock;

    return 0;

}

int DistributedExecution::establishSymChannel(void) {

    int ret = 1;

    for (int i = 20; i > 0; i--) {
        ret = establishConnection(m_sym_port, &m_sym_sock_fd);
        if (ret)
            sleep(2);
        else
            break;
    }
    assert((ret == 0) && "failed to establish sym channel");
    return ret;
}

void DistributedExecution::recoverFd(int targetFd) {

    int fd = -1;

    /* first inspection */
    fd = open("/dev/null", O_RDONLY);
    assert((fd >= 0) && "failed to open file");

    if (fd > targetFd) {
        close(fd);
        close(targetFd);
        return;
    } else if (fd < targetFd) {
        /* FIXME: we need to later close all these smaller fds */
        while (fd < targetFd) {
            fd = open("/dev/null", O_RDONLY);
            assert((fd >= 0) && "failed to open file");
            if (fd == targetFd) {
                close(fd);
                return;
            }
        }

    } else {
        /* the equal case should not happen */
        assert(0 && "unexpected fd");
    }
}

void DistributedExecution::fixMonitorSocketReceiver(void) {

    int sock = -1;
    waitForConnection(m_monitor_port, &sock, true, m_sock_fd);
    assert((sock == m_sock_fd) && "couldn't redirect the monitor fd correctly in receiver");
}

void DistributedExecution::fixMonitorSocketSender(void) {

    int sock = -1;
    recoverFd(m_sock_fd);

    int ret = 1;
    for (int i = 10; i > 0; i--) {
        ret = establishConnection(m_monitor_port, &sock);
        if (ret)
            sleep(1);
        else
            break;
    }

    assert((ret == 0) && (sock == m_sock_fd) && "couldn't redirect the monitor fd correctly in sender");
}

void DistributedExecution::sendSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size) {
    uint64_t off = 0;
    uint8_t sym = 0;
    while (size > 0) {
        if (size >= 4) {
            uint64_t bufOff = buf + off;
            klee::ref<klee::Expr> ret = state->mem()->read(bufOff, klee::Expr::Int32);
            if (!ret.isNull()) {
                sym = 1;
                send(m_sym_sock_fd, &sym, 1, 0); 
                klee::ExprSerializer *serializer = new klee::ExprSerializer(state->concolics, &state->symbolics);
                serializer->serialize(ret);
                uint64_t bufSize = serializer->getBufSize();
                send(m_sym_sock_fd, &off, 8, 0); /* FIXME: do we need 8 bytes here? */
                send(m_sym_sock_fd, &bufSize, 8, 0); /* FIXME: do we need 8 bytes here? */ 
                send(m_sym_sock_fd, (void *) serializer->getBufPtr(), bufSize, 0); 
                delete serializer;
            }
            size -= 4;
            off += 4;
        } else if (size >= 2) {
            uint64_t bufOff = buf + off;
            klee::ref<klee::Expr> ret = state->mem()->read(bufOff, klee::Expr::Int16);
            if (!ret.isNull()) {
                sym = 1;
                send(m_sym_sock_fd, &sym, 1, 0);
                klee::ExprSerializer *serializer = new klee::ExprSerializer(state->concolics, &state->symbolics);
                serializer->serialize(ret);
                uint64_t bufSize = serializer->getBufSize();
                send(m_sym_sock_fd, &off, 8, 0); /* FIXME: do we need 8 bytes here? */
                send(m_sym_sock_fd, &bufSize, 8, 0); /* FIXME: do we need 8 bytes here? */ 
                send(m_sym_sock_fd, (void *) serializer->getBufPtr(), bufSize, 0);
                delete serializer;
            }
            size -= 2;
            off += 2;
        } else { /* (size >= 1) */
            uint64_t bufOff = buf + off;
            klee::ref<klee::Expr> ret = state->mem()->read(bufOff, klee::Expr::Int8);
            if (!ret.isNull()) {
                sym = 1;
                send(m_sym_sock_fd, &sym, 1, 0);
                klee::ExprSerializer *serializer = new klee::ExprSerializer(state->concolics, &state->symbolics);
                serializer->serialize(ret);
                uint64_t bufSize = serializer->getBufSize();
                send(m_sym_sock_fd, &off, 8, 0); /* FIXME: do we need 8 bytes here? */
                send(m_sym_sock_fd, &bufSize, 8, 0); /* FIXME: do we need 8 bytes here? */ 
                send(m_sym_sock_fd, (void *) serializer->getBufPtr(), bufSize, 0);
                delete serializer;
            }
            size--;
            off++;
        }
    }

    std::set<klee::ref<klee::Expr>> constraints = state->constraints.getConstraintSet();
    for (std::set<klee::ref<klee::Expr>>::iterator it = constraints.begin(), ie = constraints.end(); it != ie; ++it) {
        sym = 2;
        send(m_sym_sock_fd, &sym, 1, 0);
        klee::ExprSerializer *serializer = new klee::ExprSerializer(state->concolics, &state->symbolics);
        serializer->serialize(*it);
        uint64_t bufSize = serializer->getBufSize();
        send(m_sym_sock_fd, &bufSize, 8, 0); /* FIXME: do we need 8 bytes here? */ 
        send(m_sym_sock_fd, (void *) serializer->getBufPtr(), bufSize, 0); 
        delete serializer;
    }
    sym = 0;
    send(m_sym_sock_fd, &sym, 1, 0);
}

void DistributedExecution::recvSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size) {
    uint8_t sym = 0;
    recv(m_sym_sock_fd, &sym, 1, 0);
    while (sym == 1) {
        uint64_t bufOff;
        uint64_t bufSize;
        recv(m_sym_sock_fd, &bufOff, 8, 0);
        recv(m_sym_sock_fd, &bufSize, 8, 0);
        assert((bufOff < size) && "invalid bufOff");
        /* FIXME: w is not needed */
        /* FIXME: Add an assertion for bufSize */
        /* The use of "buf" for both the data buf and serialized expr buff is confusing */
        char *bufPtr = (char *) new char[bufSize]; 
        recv(m_sym_sock_fd, bufPtr, bufSize, 0);
        klee::ExprDeserializer *deserializer =
                new klee::ExprDeserializer((uint64_t) bufPtr, (uint64_t) bufSize,
                                           state->concolics, &state->symbolics);
        bool ret = state->mem()->write(buf + bufOff, deserializer->deserialize());
        updateConcolicVariables(deserializer->getConcolicVariables());
        delete deserializer;
        delete bufPtr;
        assert(ret && "writing symbolic content to memory failed");
        recv(m_sym_sock_fd, &sym, 1, 0);
    }

    while (sym == 2) {
        uint64_t bufSize;
        recv(m_sym_sock_fd, &bufSize, 8, 0);
        /* FIXME: Add an assertion for bufSize */
        /* The use of "buf" for both the data buf and serialized expr buff is confusing */
        char *bufPtr = (char *) new char[bufSize]; 
        recv(m_sym_sock_fd, bufPtr, bufSize, 0);
        klee::ExprDeserializer *deserializer =
                new klee::ExprDeserializer((uint64_t) bufPtr, (uint64_t) bufSize,
                                           state->concolics, &state->symbolics);
        state->addConstraint(deserializer->deserialize());
        updateConcolicVariables(deserializer->getConcolicVariables());
        delete deserializer;
        delete bufPtr;
        recv(m_sym_sock_fd, &sym, 1, 0);
    }
}

void DistributedExecution::sendForkInfo(S2EExecutionState *state, uint16_t new_monitor_port,
                                        uint16_t new_sym_port) {

    uint8_t isFork = 1;
    send(m_sym_sock_fd, &isFork, 1, 0);
    send(m_sym_sock_fd, &new_monitor_port, 2, 0);
    send(m_sym_sock_fd, &new_sym_port, 2, 0);
}

void DistributedExecution::recvForkInfo(S2EExecutionState *state) {

    uint8_t isFork = 0;
    recv(m_sym_sock_fd, &isFork, 1, 0);

    while (isFork) {
        // Fork the process
        uint16_t new_monitor_port, new_sym_port;
        recv(m_sym_sock_fd, &new_monitor_port, 2, 0);
        recv(m_sym_sock_fd, &new_sym_port, 2, 0);
        int child = g_s2e->fork();
        if (child == 1) {
            // forked state
            m_sym_port = new_sym_port;
            establishSymChannel();
            m_monitor_port = new_monitor_port;
            fixMonitorSocketSender();

        } else if (child == 0) {
            // original state
        }

        /* Wait fo the next potential fork message */
        recv(m_sym_sock_fd, &isFork, 1, 0);
        if (isFork == 2) {
            s2e()->getExecutor()->terminateState(*state);
        }
    }
}

// Check if the experssion could have multiple feasible values under current constriants
bool DistributedExecution::checkRange(S2EExecutionState *state, klee::ref<klee::Expr> expr)
{
    std::pair<klee::ref<klee::Expr>, klee::ref<klee::Expr>> range;
    klee::Query query(state->constraints, expr);

    range = s2e()->getExecutor()->getSolver(*state)->getRange(query);

    uint64_t min = dyn_cast<klee::ConstantExpr>(range.first)->getZExtValue();
    uint64_t max = dyn_cast<klee::ConstantExpr>(range.second)->getZExtValue();

    getWarningsStream(state) << "checkRange min = " << hexval(min) << " max = " << hexval(max) << " fd = " << state->regs()->read<uint32_t>(CPU_OFFSET(regs[0])) << "\n";

    return (min != max);
}

#define SYSCALL_NUM_MAX 378
static uint8_t syscall_fd[SYSCALL_NUM_MAX] = {
    0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0,
};

void DistributedExecution::printPathConstraints(S2EExecutionState *state)
{
    std::set<klee::ref<klee::Expr>> constraints = state->constraints.getConstraintSet();
    for (std::set<klee::ref<klee::Expr>>::iterator it = constraints.begin(), ie = constraints.end();
         it != ie; ++it) {
        getWarningsStream(state) << *it << "\n";
    }
}

/* ignore logging writev concretization*/
char logging_file1[50] = "/dev/pmsg0";
char logging_file2[50] = "/dev/socket/logdw";
void DistributedExecution::onConcretizeSyscallArgs(S2EExecutionState *state, int isReg,
                                                   uint64_t addr, uint64_t size)
{
    sym_syscall_t syscall;
    memset(&syscall, 0, sizeof(sym_syscall_t));
    uint32_t syscallNum = state->regs()->read<uint32_t>(CPU_OFFSET(regs[7]));
    bool m_thisSyscallHasSymbolicInputs = false;
    if (isReg) {
        // Concretizing register arguments
        uint8_t reg_mask = (uint8_t)addr;
        for (int i = 0; i < 8; i++) {
            if ((reg_mask & (1 << i) || i == 7)) {
                klee::ref<klee::Expr> argExpr =
                        state->regs()->read(CPU_OFFSET(regs[i]), state->getPointerWidth());
                if (!isa<klee::ConstantExpr>(argExpr) && checkRange(state, argExpr)) {
                    getWarningsStream(state) << "syscall has symbolic argument r" << i
                            << " = " << argExpr << "\n";
                    syscall.symbolic |= (1 << i);
                    m_syscallHasSymbolicInputs = true;
                    m_thisSyscallHasSymbolicInputs = true;
                }
            }
        }
    } else {
        // Concretizing data referenced by pointer arguments
        for (unsigned i = 0; i < size; ++i) {
            klee::ref<klee::Expr> ret = state->mem()->read(addr + i);
            if (ret.isNull()) {
                getWarningsStream() << "Could not read address " << hexval(addr + i) << "\n";
                continue;
            }

            if (!isa<klee::ConstantExpr>(ret) && checkRange(state, ret)) {
                getWarningsStream(state) << "syscall has symbolic argument at addr " << hexval(addr) 
                        << ", offset = " << i << ", total size " << size << ", value =" << ret << "\n";
                syscall.symbolic |= SYM_SYSCALL_PTR_ARG;
                m_syscallHasSymbolicInputs = true;
                m_thisSyscallHasSymbolicInputs = true;
            }
        }
        /* Concretize the symbolic regions */
        if (m_thisSyscallHasSymbolicInputs) {
            if (strcmp((char *)syscall.fd_name_buf, logging_file1)
                && strcmp((char *)syscall.fd_name_buf, logging_file2)) {
                state->writeSyscallSymbolicRegions(addr, size);
            } else if(!(syscallNum == 146)) {
                state->writeSyscallSymbolicRegions(addr, size);
            } else {
                fprintf(stderr, "Ignore concretizing logging writev symbolic pointer\n");
                m_thisSyscallHasSymbolicInputs = false;
            }
        }
    }
    if (m_thisSyscallHasSymbolicInputs) {
        getWarningsStream(state) << "onConcretizeSyscallArgs: syscall number " << syscallNum << "\n";
        // Report symbolic syscall arguments information to the server
        syscall.state_id = m_stateId;
        syscall.num = syscallNum;
        if (syscallNum < SYSCALL_NUM_MAX && syscall_fd[syscallNum] == 1) {
            syscall.symbolic |= SYM_SYSCALL_HAS_FD;
            int fd = state->regs()->read<uint32_t>(CPU_OFFSET(regs[0]));
            std::string fdName = m_pm->getFileOfFd(fd);
            memcpy(syscall.fd_name_buf, fdName.c_str(), fdName.size()+1);
        }
        sendDataToMousseServer(OPC_W_SYSCALL, &syscall);
     }
}

void DistributedExecution::onConcreteDataMemoryAccess(S2EExecutionState *state,
        uint64_t address, uint64_t value, uint8_t size, unsigned flags)
{
    for (auto & it : m_envMemoryMap) {
        if (address < it.second && (address + size) >= it.first ) {
            getWarningsStream(state) << "accessing memory mmaped to env files\n"
                    << "addr:" << hexval(address) << " size:" << hexval(size) << "\n";
        }
    }
}

bool DistributedExecution::checkFd(uint64_t fd) {
    for (auto file : m_environmentFiles) {
        if (fd == m_pm->getFdOfFile(file)) {
            return true;
        }
    }
    return false;
}
bool DistributedExecution::checkDriverFd(uint64_t fd) {
    for (auto file : m_driverFiles) {
        if (fd == m_pm->getFdOfFile(file)) {
            return true;
        }
    }
    return false;
}

void DistributedExecution::onDoSyscallStart(S2EExecutionState *state, 
                                            uint64_t syscall_num, 
                                            SyscallArguments *args) {
    /* IPC */
    switch (syscall_num) {
    case 54: {
        for (auto file : m_blockingIoctlFiles) {
            int fd = m_pm->getFdOfFile(file);
            if (args->arg1 == fd) {
                std::lock_guard<std::mutex> lock(this->m_activeIoctlsMutex);
                if (file.compare(binderpath) == 0) {
                    if ((unsigned long)args->arg2 == BINDER_WRITE_READ) {
                        if(m_testAudioServer && m_audioserver_intercepted) {
                            if(m_audioserver_intercepted_thread == (uint32_t) pthread_self()) {
                                getWarningsStream(state) << "audioserver: test finish\n";
                                if(m_testerPid)
                                    kill(m_testerPid, SIGTERM);
                                m_endReason = STATUS_TERM_TEST_FINISH;
                                s2e()->getExecutor()->terminateState(*state);
                            }
                        }

                        assert(m_activeIoctls.find(pthread_self()) == m_activeIoctls.end());
                        m_activeIoctls[pthread_self()] = 0;
                    }
                } else {
                        assert(0 && "should not come to here [1]\n");
                }
                break;
            }
        }
        break;
    }
    case 322: { /* openat */
        
            if(m_testAudioProvider) {
                if(!strcmp((const char*)args->arg2, "/vendor/lib/hw/audio.primary.sdm845.so"))
                {
                    strcpy((char *)args->arg2, "/vendor/lib/hw/audio.primary.mousse.sdm845.so");
                }
            } else if (m_testAudioServer)
            {
                if(!strcmp((const char*)args->arg2, "/system/lib/libaudioflinger.so"))
                {
                    strcpy((char *)args->arg2, "/system/lib/libaudioflinger_mousse.so");
                }
            }
    }
    case 335: { /* pselect6 */
        if (m_target_accept4) {
                waitForSymChannel();
                mIsSymReceiver = true;
                /* ignore all the following pselect6*/
                m_target_accept4 = false;
        }
        break;
    }
    case 366: { /* accept4 */ //FIXME: support accept too.
        struct sockaddr_in *dst_addr = (struct sockaddr_in *) args->arg2;

        if (ntohl(dst_addr->sin_addr.s_addr) == INADDR_ANY) {
            if (ntohs(dst_addr->sin_port) == m_monitor_port) {
                m_target_accept4 = true;
            }
        }

        break;
    }

    case 289: { /* send */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd) {
            assert(0 && "send not supported");
        }
        break;
    }

    case 290: { /* sendto */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd && mIsSymReceiver) {
            /* Done with forks */
            uint8_t isFork = 0;
            send(m_sym_sock_fd, &isFork, 1, 0);
        }

        break;
    }
    case 296: { /* sendmsg */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd && mIsSymReceiver) {
            /* Done with forks */
            uint8_t isFork = 0;
            send(m_sym_sock_fd, &isFork, 1, 0);
        }
        break;
    }
    case 291: { /* recv */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd) {
            assert(0 && "recv not supported");
        }
        break;
    }

    case 292: { /* recvfrom */
        int sock_fd = (int) args->arg1;

        if (sock_fd == m_sock_fd && mIsSymReceiver) {
           recvForkInfo(state); 
        }
        break;
    }
    case 297: { /* recvmsg */
        int sock_fd = (int) args->arg1;

        if (sock_fd == m_sock_fd && mIsSymReceiver) {
           recvForkInfo(state); 
        }
        break;
    }
    case 3: { /* read */
        int fd = (int) args->arg1;
        if (fd == m_sock_fd) {
            assert(0 && "read not supported");
        }
        break;
    }

    case 4: { /* write */
        int fd = (int) args->arg1;
        if (fd == m_sock_fd) {
            assert(0 && "write not supported");
        }
        break;
    }

    case 1: /* exit */
    case 248: { /* exit_group */
        if (mIsSymReceiver) {
            uint8_t isFork = 2;
            send(m_sym_sock_fd, &isFork, 1, 0);
        }
        break;
    }


    default:
        break;
    }

    bool furtherCheckPass = false;
    if (checkSyscall(syscall_num, SYSCALL_CHECK_FD)) {
        furtherCheckPass |= checkFd(args->arg1);
    } else {
        furtherCheckPass = true;
    }

    m_stateRevealingSyscallCalled = false;
    m_stateModifyingSyscallCalled = false;

    if (m_forked && checkSyscall(syscall_num, SYSCALL_STATE_REVEALING) && furtherCheckPass) {
        if (!m_environmentIsClean || !g_s2e->callStateRevealingStartIfClean(m_stateId)) {
            m_endReason = STATUS_TERM_SYSCALL;
            std::stringstream ss;
            ss << "state cannot call state-revealing syscall " << syscall_num;
            offloadState(state, state, ss.str());
        }
        m_stateRevealingSyscallCalled = true;
    }

    if (m_forked && checkSyscall(syscall_num, SYSCALL_STATE_MODIFYING) && furtherCheckPass) {
        if (!m_environmentIsClean || !g_s2e->callStateModifyingIfClean(m_stateId)) {
            m_endReason = STATUS_TERM_SYSCALL;
            std::stringstream ss;
            ss << "state cannot call state-modifying syscall " << syscall_num;
            offloadState(state, state, ss.str());
        } else {
//            getWarningsStream(state) << "call state-modifying syscall(" << syscall_num << ")\n";
//            m_isStateModifyingSyscallState = true;
        }
        m_stateModifyingSyscallCalled = true;
    }

    if (syscall_num == 248) { // exit_group
        onDistributedStateKill.emit(state, m_stateId);
        sendStatusToServer(STATUS_TERM_EXIT);
    }

}

void DistributedExecution::addSymbolicSyscallOutput(S2EExecutionState *state, std::string name,
                                                    uint64_t syscall_num, uint32_t count, uint64_t hash) {
    syscall_symbolic_output_t syscall_info;
    syscall_info.syscall_num = syscall_num;
    syscall_info.count = count;
    syscall_info.hash = hash;
    m_symbolicSyscalls[name] = syscall_info;
}

bool DistributedExecution::useAlternativeOutput(S2EExecutionState *state, uint64_t syscall_num,
                                                uint32_t count, uint64_t hash, char *returnValue) {
    DistributedState *dstate = pendingStates.front();
    syscall_symbolic_output_t *syscall_info = dstate->data.syscall_output;
    for (unsigned i = 0; i < 10; i ++) {
        if (syscall_info[i].syscall_num == syscall_num &&
            syscall_info[i].hash == hash) {
            returnValue[0] = dstate->data.input_buf[m_symbolicInputSize + i*4];
            returnValue[1] = dstate->data.input_buf[m_symbolicInputSize + i*4 + 1];
            returnValue[2] = dstate->data.input_buf[m_symbolicInputSize + i*4 + 2];
            returnValue[3] = dstate->data.input_buf[m_symbolicInputSize + i*4 + 3];
            return true;
        }
    }
    return false;
}

bool DistributedExecution::interceptRecvmsg(S2EExecutionState *state, struct msghdr *msg) {
    bool intercepted = false;
    struct cmsghdr * cmsg_hdr = NULL;
    uint64_t buffer;
    uint64_t size;
    int *cmsg_data;
    int camera_provider_current_code;
/* ancillary data*/
    size = (uint64_t)msg->msg_controllen;
    if (size) {
        cmsg_hdr = (struct cmsghdr *)msg->msg_control;
        cmsg_data = (int *)CMSG_DATA(cmsg_hdr);
        camera_provider_current_code = *cmsg_data;
    } else {
        camera_provider_current_code = 0;
    }

    m_cameraProviderTestCode = camera_provider_current_code;
    if (camera_provider_current_code == m_cameraProviderTestCode) {
        int count = msg->msg_iovlen;
        struct iovec* io_vec= msg->msg_iov;
        char input_name[30];
        int index;
        int j;
        int i;
        fetchStateFromServer();
        for (i = 0; i < count ; i++) {
            buffer = (uint64_t)io_vec[i].iov_base;
            size = (uint64_t)io_vec[i].iov_len;
            index = 0;
            uint8_t *alternativeConcreteData = NULL;
            for (j = 0; j + 4 <= size; j += 4) {
                sprintf(input_name, "socket_input_%d_%d", i, index);
                addConcolic(state, input_name, 4);
                if (m_ignoreForkDepth != 0) {
                    int pos = get_input_buf_pos(input_name);
                    DistributedState *dstate = pendingStates.front();
                    alternativeConcreteData = (uint8_t *)&dstate->data.input_buf[pos];
                }
                makeMemSymbolic(state, (uintptr_t)buffer, 4, input_name, true,
                                NULL, NULL, alternativeConcreteData);
                index += 1;
                buffer += 4;
            };
            if (size - j) {
                sprintf(input_name, "socket_input_%d_%d", i, index);
                addConcolic(state, input_name, 4);
                if (m_ignoreForkDepth != 0) {
                    int pos = get_input_buf_pos(input_name);
                    DistributedState *dstate = pendingStates.front();
                    alternativeConcreteData = (uint8_t *)&dstate->data.input_buf[pos];
                }
                makeMemSymbolic(state, (uintptr_t)buffer, size - j, input_name, true,
                                NULL, NULL, alternativeConcreteData);
            }
        }
        intercepted = true;
    }
    return intercepted;
}

void DistributedExecution::onDoSyscallEnd(S2EExecutionState *state, uint64_t syscall_num, 
                                          uint64_t ret, SyscallArguments *args) {
    static int syscall_count = 0;
    char returnValue[4];
    int regValue;
    std::stringstream ss;    
    if (m_stateRevealingSyscallCalled)
        g_s2e->callStateRevealingEnd();
    if (m_makeSyscallReturnConcolic && m_syscallHasSymbolicInputs) {
        ss.str("");
        ss << "syscall_ret_" << syscall_count;
        state->regs()->read(CPU_OFFSET(regs[0]), &regValue, sizeof(regValue), false);

        uint64_t hash = m_stackMonitor->getCallStackHash(state, 1, pthread_self());
        if (!useAlternativeOutput(state, syscall_num, 0, hash, returnValue)) {
            returnValue[0] = regValue & 0xff;
            returnValue[1] = (regValue >> 8) & 0xff;
            returnValue[2] = (regValue >> 16) & 0xff;
            returnValue[3] = (regValue >> 24) & 0xff;
        }

        addConcolic(state, ss.str(), 4);
        makeRegConcolic(state, 0, 4, ss.str(), returnValue);
        syscall_count++;
    }

/* symbolic env */
    bool EnvCheckPass = false;
    if (checkSyscall(syscall_num, SYSCALL_CHECK_FD)) {
        EnvCheckPass |= checkDriverFd(args->arg1);
    }
    if (EnvCheckPass && m_makeEnvReturnConcolic) {
        fprintf(stderr, "makeEnvReturnConcolic: syscall = %llu, file = %s\n", syscall_num, (m_pm->getFileOfFd(args->arg1)).c_str());
        ss.str("");
        ss << "syscall_ret_" << syscall_count;
        state->regs()->read(CPU_OFFSET(regs[0]), &regValue, sizeof(regValue), false);
        uint64_t hash1 = m_stackMonitor->getCallStackHash(state, 1, pthread_self());
        if (!useAlternativeOutput(state, syscall_num, 0, hash1, returnValue)) {
            returnValue[0] = regValue & 0xff;
            returnValue[1] = (regValue >> 8) & 0xff;
            returnValue[2] = (regValue >> 16) & 0xff;
            returnValue[3] = (regValue >> 24) & 0xff;
        }
        addConcolic(state, ss.str(), 4);
        fetchStateFromServer();
        makeRegConcolic(state, 0, 4, ss.str(), returnValue);
        syscall_count++;
    }
    if (syscall_num == 192) { // mmap2
        uint64_t fd = args->arg5;
        if (fd != (uint64_t)-1) {
            if (checkFd(fd)) {
                getWarningsStream(state) << "mmap2 on fd " << fd
                        << " (" << m_pm->getFileOfFd(fd) << ")\n";
                //fdMemoryMap[fd].push_back(std::make_pair(ret, args->arg2));
                m_envMemoryMap.push_back(std::make_pair(ret, args->arg2));
            }
        }
    }

    /* IPC support */
    switch (syscall_num) {
    case 54: { /*  ioctl */
        for (auto file : m_blockingIoctlFiles) {
            if (args->arg1 == m_pm->getFdOfFile(file)) {
                std::lock_guard<std::mutex> lock(this->m_activeIoctlsMutex);
                if (file.compare(binderpath) == 0) {
                    if ((unsigned long)args->arg2 == BINDER_WRITE_READ) {
                        assert(m_activeIoctls.find(pthread_self()) != m_activeIoctls.end());
                        if (m_activeIoctls.find(pthread_self()) != m_activeIoctls.end()) {
                            m_activeIoctls.erase(pthread_self());
                        }
                    }
                } else {
                    assert(m_activeIoctls.find(pthread_self()) != m_activeIoctls.end());
                    if (m_activeIoctls.find(pthread_self()) != m_activeIoctls.end()) {
                        m_activeIoctls.erase(pthread_self());
                    }
                }
                break;
            }
        }
        break;
    }
    case 282: { /* bind */
        int sock_fd = (int)args->arg1;
        struct sockaddr *dst_addr = (struct sockaddr *) args->arg2;
        if (dst_addr->sa_family == AF_LOCAL) {
            if (!strcmp(dst_addr->sa_data, cam_socket1_path)) {
                Cam1Sockets += 1;
                if(Cam1Sockets == 2) {
                    m_sock_fd = sock_fd;
                    m_target_accept4 = true;
                }
            }
        }
        break;
    }
    case 283: { /* connect */
        if (ret == 0) {
            int sock_fd = (int) args->arg1;
            struct sockaddr *dst_addr0 = (struct sockaddr *) args->arg2;
            if (dst_addr0->sa_family == AF_LOCAL) {
                if (!strcmp(dst_addr0->sa_data, cam_socket1_path)) {
                    Cam1Sockets += 1;
                    if(Cam1Sockets == 2) {
                        m_sock_fd = sock_fd;
                        establishSymChannel();
                        mIsSymReceiver = true;
                    }
                }
            } else {
                struct sockaddr_in *dst_addr = (struct sockaddr_in *) args->arg2;
                if (ntohl(dst_addr->sin_addr.s_addr) == INADDR_LOOPBACK) {
                    if (ntohs(dst_addr->sin_port) == m_monitor_port) {
                        m_sock_fd = sock_fd;
                        establishSymChannel();
                        mIsSymReceiver = true;
                    }
                }
            }
        }
        break;
    }
    case 366: { /* accept4 */ //FIXME: support accept too.
        if (ret && m_target_accept4) {
            m_sock_fd = ret;
            waitForSymChannel();
            mIsSymReceiver = true;
        }

        break;
    }

    case 289: { /* send */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd) {
            assert(0 && "send not supported");
        }
        break;
    }

    case 290: { /* sendto */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd)
            sendSymInfo(state, (uint64_t) args->arg2, (uint64_t) args->arg3); 

        break;
    }
    case 296: { /* sendmsg */
        getWarningsStream(state) << "sendmsg\n";
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd) {
            struct msghdr * msg_hdr = (struct msghdr *)args->arg2;
            uint64_t buffer;
            uint64_t size;
/* Ignore ancillary data*/
            int count = msg_hdr->msg_iovlen;
            struct iovec* io_vec= msg_hdr->msg_iov;
            for(int i = 0; i < count ; i++) {
                buffer = (uint64_t)io_vec[i].iov_base;
                size = (uint64_t)io_vec[i].iov_len;
                sendSymInfo(state, buffer, size); 
            }
        }
        break;
    }
    case 291: { /* recv */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd) {
            assert(0 && "recv not supported");
        }
        break;
    }

    case 292: { /* recvfrom */
        int sock_fd = (int) args->arg1;

        if (sock_fd == m_sock_fd) {
           recvSymInfo(state, (uint64_t) args->arg2, (uint64_t) args->arg3); 
        }
        break;
    }
    case 297: { /* recvmsg */
        int sock_fd = (int) args->arg1;
        if (sock_fd == m_sock_fd) {
            struct msghdr * msg_hdr = (struct msghdr *)args->arg2;
            uint64_t buffer;
            uint64_t size;
/* Ignore ancillary data*/
            int count = msg_hdr->msg_iovlen;
            struct iovec* io_vec= msg_hdr->msg_iov;
            for(int i = 0; i < count ; i++) {
                buffer = (uint64_t)io_vec[i].iov_base;
                size = (uint64_t)io_vec[i].iov_len;
                recvSymInfo(state, buffer, size); 
            }
        }
        break;
    }
    case 3: { /* read */
        int fd = (int) args->arg1;
        if (fd == m_sock_fd) {
            assert(0 && "read not supported");
        }
        break;
    }

    case 4: { /* write */
        int fd = (int) args->arg1;
        if (fd == m_sock_fd) {
            assert(0 && "write not supported");
        }
        if(m_testAudioServer && fd == 2 && !strcmp((const char*)args->arg2, "audioserver_intercepted"))
        {
              m_audioserver_intercepted = true;
              m_audioserver_intercepted_thread = (uint32_t)pthread_self();
        }
        break;
    }

    default:
        break;
    }
    m_syscallHasSymbolicInputs = false;
}

void DistributedExecution::onIsSymbolic(S2EExecutionState *state,
                                        target_ulong address, target_ulong size) {
    getWarningsStream(state) << "data at " << hexval(address)
            << " and size " << size << " is symbolic\n";

    char buf[4];
    *(int32_t *)buf = m_stateId;
    fprintf(stderr, "%s [1]\n",__FUNCTION__);
    sendDataToMousseServer(OPC_W_IS_SYMBOLIC, buf);
}

void DistributedExecution::onBugDetected2(S2EExecutionState *state, uint32_t type, uint64_t pc,
                                         uint32_t insn, const std::string &binary,
                                         const ConcreteInputs &ci, StackMonitor::CallStack *cs2) {
    if (m_stackMonitor)
        m_stackMonitor->printCallStack(state);

    getWarningsStream() << "path constraints:\n";
    printPathConstraints(state);

    bug_t bug;
    bug.state_id = m_stateId;
    bug.type = type;
    bug.pc = pc;
    bug.insn = insn;
    std::string bin = binary;
    if (bin.size() > BIN_NAME_BUF_SIZE) {
        size_t dir_pos = bin.rfind('/');
        bin = bin.substr(dir_pos + 1);
        assert(bin.size() <= 247);
    }
    memcpy((void *)&bug.binary_name_buf, (void *)bin.c_str(), bin.size()+1);

    StackMonitor::CallStack cs;
    if (!m_stackMonitor->getCallStack(state, 1, pthread_self(), cs)) {
        bug.cs_size = 0;
    } else {
        bug.cs_size = cs.size();
    }
    bug.cs2_size = cs2->size();

    size_t cs_size = cs.size() * sizeof(cs_entry_t);
    size_t cs2_size = cs2->size() * sizeof(cs_entry_t);
    size_t bug_data_size = sizeof(bug_t) + cs_size + cs2_size;

    void *cs_buf = m_stackMonitor->serialize(cs);
    void *cs2_buf = m_stackMonitor->serialize(*cs2);
    char *bug_data_buf = (char *)malloc(bug_data_size);

    memcpy(bug_data_buf, (void *)&bug, sizeof(bug_t));
    memcpy(bug_data_buf + sizeof(bug_t), cs_buf, cs_size);
    memcpy(bug_data_buf + sizeof(bug_t) + cs_size, cs2_buf, cs2_size);

    g_s2e->sendDataToServer(OPC_W_BUG, bug_data_buf, bug_data_size);

    free(cs_buf);
    free(cs2_buf);
    free(bug_data_buf);

    if (bug.type != 0x80000000) {
        state_t bug_inputs;
        concreteInputsToBuffer(ci, &bug_inputs);
        bug_inputs.id = m_stateId;
        bug_inputs.ignore_depth = m_localForkDepth;
        sendDataToMousseServer(OPC_W_BUG_INPUTS, &bug_inputs);
    }
}

void DistributedExecution::onBugDetected(S2EExecutionState *state, uint32_t type, uint64_t pc,
                                         uint32_t insn, const std::string &binary,
                                         const ConcreteInputs &ci) {
    if (m_stackMonitor)
        m_stackMonitor->printCallStack(state);

    getWarningsStream() << "path constraints:\n";
    printPathConstraints(state);

    bug_t bug;
    bug.state_id = m_stateId;
    bug.type = type;
    bug.pc = pc;
    bug.insn = insn;
    std::string bin = binary;
    if (bin.size() > BIN_NAME_BUF_SIZE) {
        size_t dir_pos = bin.rfind('/');
        bin = bin.substr(dir_pos + 1);
        assert(bin.size() <= 247);
    }
    memcpy((void *)&bug.binary_name_buf, (void *)bin.c_str(), bin.size()+1);

    StackMonitor::CallStack cs;
    if (!m_stackMonitor->getCallStack(state, 1, pthread_self(), cs)) {
        bug.cs_size = 0;
    } else {
        bug.cs_size = cs.size();
    }
    bug.cs2_size = 0;

    void *cs_buf = m_stackMonitor->serialize(cs);
    int bug_data_size = sizeof(bug_t) + bug.cs_size * sizeof(cs_entry_t);
    char *bug_data_buf = (char *)malloc(bug_data_size);
    memcpy(bug_data_buf, (void *)&bug, sizeof(bug_t));
    memcpy(bug_data_buf + sizeof(bug_t), cs_buf, sizeof(cs_entry_t) * bug.cs_size);
    g_s2e->sendDataToServer(OPC_W_BUG, bug_data_buf, bug_data_size);
    free(bug_data_buf);

    if (bug.type != 0x80000000) {
        state_t bug_inputs;
        concreteInputsToBuffer(ci, &bug_inputs);
        bug_inputs.id = m_stateId;
        bug_inputs.ignore_depth = m_localForkDepth;
        sendDataToMousseServer(OPC_W_BUG_INPUTS, &bug_inputs);
    }
}

void DistributedExecution::onReceiveSignal(S2EExecutionState *state, uint32_t signal) {
    signal_t sig;
    sig.state_id = m_stateId;
    sig.signal = signal;
    if (signal == 6)
        m_stackMonitor->printCallStack(state);
    sendDataToMousseServer(OPC_W_GOT_SIGNAL, &sig);
}

void DistributedExecution::onThreadCreate(S2EExecutionState *state, uint64_t stack_address,
                    uint64_t parent_tid, uint64_t child_tid) {
    m_threadCount++;
}

void DistributedExecution::onThreadExit(S2EExecutionState *state, uint64_t tid) {
    m_threadCount--;
}

void DistributedExecution::onTlbMiss(S2EExecutionState *state, uint64_t address, bool isWrite)
{
    if (address == 0) {
        getWarningsStream(state) << "tlb_miss on 0\n";
        if (m_stackMonitor)
            m_stackMonitor->printCallStack(state);
    }
}

klee::ExecutionState &DistributedExecution::selectState()
{
    DistributedState *next_state = pendingStates.front();
    return *next_state->state;
}

/**
 *  We only use the update() searcher callback to get the initial state.
 *  Adding or removing states are done in onStateFork() or onStateKill().
 */
void DistributedExecution::update(klee::ExecutionState *current,
        const klee::StateSet &addedStates, const klee::StateSet &removedStates)
{
    S2EExecutionState *cs = dynamic_cast<S2EExecutionState *>(current);
    if (!m_initialState && cs->getID() == 0) {
        m_initialState = cs;
        assert(pendingStates.empty() && "pending state should be empty when mousse just starts");
        addToPendingStates(g_s2e->getDebugStream(), cs, 0);
    }

}

bool DistributedExecution::empty()
{
    return pendingStates.empty();
}

} // namespace plugins
} // namespace s2e
