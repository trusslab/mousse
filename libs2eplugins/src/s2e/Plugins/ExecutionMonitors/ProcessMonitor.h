/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MOUSSE_PLUGINS_PROCESSMONITOR_H
#define MOUSSE_PLUGINS_PROCESSMONITOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <mutex>

namespace s2e {

namespace plugins {


class ProcessMonitor : public Plugin {
    S2E_PLUGIN

#if defined(TARGET_ARM)
    enum ARM_SYSCALL_NR {
        SYSCALL_WRITE =     4,
        SYSCALL_OPEN =      5,
        SYSCALL_CLOSE =     6,
        SYSCALL_CREATE =    8,
        SYSCALL_MMAP =      90,
        SYSCALL_MUNMAP =    91,
        SYSCALL_WRITEV =    146,
        SYSCALL_MREMAP =    163,
        SYSCALL_PRCTL =     172,
        SYSCALL_MMAP2 =     192,
        SYSCALL_SOCKET =    281,
        SYSCALL_BIND =      282,
        SYSCALL_CONNECT =   283,
        SYSCALL_SHMAT =     305,
        SYSCALL_SHMDT =     306,
        SYSCALL_OPENAT =    322,
        SYSCALL_PIPE2 =     359
    };
#endif

public:
    ProcessMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void printProcMaps();

    std::string getFileName(uint64_t addr);

    std::string getFileName(uint64_t address, uint64_t &offset);
    std::string getFileNameD(uint64_t address, uint64_t &offset);

    std::string getFileNameSlow(uint64_t address, uint64_t &offset);

    std::string getFileNameSlowAndUpdate(uint64_t address, uint64_t &offset);

    void updateProcessAddressMap();
    void updateProcessAddressMap(const std::string &file, uint64_t addr = 0);

    uint64_t getOffsetWithinFile(const std::string &file, uint64_t addr);

    uint64_t getAddressWithinFile(const std::string &file, uint64_t offset);

    bool isAddressWithinFile(uint64_t addr, const std::string &file);

    bool isAddressUnknown(uint64_t addr);

    int getFdOfFile(const std::string & file);

    std::string getFileOfFd(int fd);

    std::string getNameOfThread();

    std::string getNameOfThread(uint32_t tid);

    void printProcessFdMap(S2EExecutionState *state);

private:
    typedef enum {
        DEBUGLEVEL_FD_OPEN_CLOSE = 1,
        DEBUGLEVEL_ALL_SYSCALLS
    }DebugLevel;

    struct seg {
        uint64_t start;
        uint64_t end;
        uint64_t offset;
        std::string path;
    };

    std::map<uint64_t, seg> m_processMap;

    typedef std::pair<uint64_t, uint64_t> MemoryRegion;
    typedef std::vector<MemoryRegion> MemoryRegions;
    typedef std::pair<std::string, uint64_t> FileOffsetPair;

    DebugLevel m_debugLevel;

    std::tr1::unordered_map<std::string, MemoryRegions> m_processMemoryMap;

    std::tr1::unordered_map<uint64_t, uint64_t> m_offsetAddressMap;

    std::tr1::unordered_map<uint32_t, std::string> m_processFdMap;

    std::tr1::unordered_map<uint32_t, std::string> m_threadNameMap;

    void openFile(S2EExecutionState *state, uint64_t ret, uint64_t pathNamePtr, const char* syscall);

    void openSocket(S2EExecutionState *state, uint64_t fd);

    void bindSocket(S2EExecutionState *state, uint64_t fd, uint64_t addr);

    void connectSocket(S2EExecutionState *state, uint64_t fd, uint64_t addr);

    void write(S2EExecutionState *state, uint64_t fd, uint64_t addr, uint64_t count);

    void writev(S2EExecutionState *state, uint64_t fd, uint64_t iov, uint64_t iovcnt);

    void printMap();

    void onDoSyscallEnd(S2EExecutionState *state, uint64_t syscallNum, uint64_t ret,
                        SyscallArguments *args);

};

} // namespace plugins
} // namespace s2e

#endif // MOUSSE_PLUGINS_PROCESSMONITOR_H
