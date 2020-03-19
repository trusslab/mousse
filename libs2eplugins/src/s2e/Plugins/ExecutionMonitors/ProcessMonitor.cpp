/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * Copyright (C) 2020, TrussLab@University of California, Irvine.
 * Authors: Hsin-Wei Hung<hsinweih@uci.edu> 
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

#include <cctype>
#include <sys/socket.h>
#include <sys/uio.h>

#include <s2e/cpu.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/s2e_libcpu.h>

#include "ProcessMonitor.h"

//#define TEST_FAST_MEM_TRACKING

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ProcessMonitor, "Tracks memory map and file descriptors of the process", "ProcessMonitor");


void ProcessMonitor::initialize()
{
    m_debugLevel = (DebugLevel) s2e()->getConfig()->getInt(getConfigKey() + ".debugLevel", 0);

    s2e()->getCorePlugin()->onDoSyscallEnd.connect(
            sigc::mem_fun(*this, &ProcessMonitor::onDoSyscallEnd));
}

std::string ProcessMonitor::getFileName(uint64_t addr)
{
    std::stringstream ss;
    std::ifstream ifs;
    std::string line, tmp;

    pid_t pid = getpid();
    ss << "/proc/" << pid << "/maps";
    ifs.open(ss.str());

    if (!ifs.is_open())
        return std::string("<unknown module>");

    bool isMapped = false;
    while (std::getline(ifs, line)) {
        uint64_t start, end;
        sscanf(line.c_str(), "%llx-%llx ", &start, &end);
        if (addr >= start && addr < end) {
            ss.str(std::string());
            ss.clear();
            ss << line;
            ss >> tmp >> tmp >> tmp >> tmp >> tmp >> tmp;
            isMapped = true;
            break;
        }
    }

    ifs.close();

    if (isMapped)
        return tmp;
    else
        return std::string("<unknown module>");
}

void ProcessMonitor::printProcMaps()
{
    std::stringstream ss;
    std::ifstream ifs;
    std::string line;

    pid_t pid = getpid();
    ss << "/proc/" << pid << "/maps";
    ifs.open(ss.str());

    if (!ifs.is_open())
        return;

    while (std::getline(ifs, line)) {
        g_s2e->getWarningsStream() << line << "\n";
    }
}

std::string ProcessMonitor::getFileNameD(uint64_t address, uint64_t &offset)
{
//    std::lock_guard<std::mutex> lock(m_processMapMutex);
    bool found = false;
    std::string fileName;
    for (auto it : m_processMap) {
        if (address >= it.second.start && address < it.second.end) {
            found = true;
            fileName = it.second.path;
            offset = address + it.second.offset - it.second.start;
            break;
        }
    }

    if (!found)
        fileName = getFileNameSlowAndUpdate(address, offset);

    return fileName;    

}

std::string ProcessMonitor::getFileNameSlow(uint64_t address, uint64_t &offset)
{
    std::stringstream ss;
    std::ifstream ifs;
    std::string line, tmp;

    pid_t pid = getpid();
    ss << "/proc/" << pid << "/maps";
    ifs.open(ss.str());

    if (!ifs.is_open())
        return std::string("<unknown module>");

    bool isMapped = false;
    while (std::getline(ifs, line)) {
        uint64_t start, end;
        sscanf(line.c_str(), "%llx-%llx ", &start, &end);
        if (address >= start && address < end) {
            std::string region_offset_str;
            ss.clear();
            ss << line;
            ss >> tmp >> tmp >> region_offset_str >> tmp >> tmp >> tmp;
            uint64_t region_offset = strtoul(region_offset_str.c_str(), NULL, 16);
            offset = address - start + region_offset;
            isMapped = true;
            break;
        }
    }

    ifs.close();

    if (isMapped)
        return tmp;
    else
        return std::string("<unknown module>");
}

std::string ProcessMonitor::getFileName(uint64_t address, uint64_t &offset)
{
    if ((uint32_t)this == 0) {
        return getFileNameSlow(address, offset);
    } else {
        for (auto file : m_processMemoryMap) {
            offset = 0;
            for (auto region : file.second) {
                if (address > region.first && address < region.second) {
                    offset += address - region.first;
                    return file.first;
                } else {
                    offset += region.second - region.first;
                }
            }
        }
        return getFileNameSlowAndUpdate(address, offset);
    }

}

std::string ProcessMonitor::getFileNameSlowAndUpdate(uint64_t address, uint64_t &offset)
{
    std::stringstream ss;
    std::ifstream ifs;
    std::string line, tmp, file;

    pid_t pid = getpid();
    ss << "/proc/" << pid << "/maps";
    ifs.open(ss.str());

    if (!ifs.is_open())
        return std::string("<unknown module>");

    bool isMapped = false;
    m_processMemoryMap.clear();
    while (std::getline(ifs, line)) {
        uint64_t start, end;
        sscanf(line.c_str(), "%llx-%llx ", &start, &end);
        std::string region_offset_str;
        std::string addr_str;
        ss.str(std::string());
        ss.clear();
        ss << line;
        //40000000-40001000 r-xp 00000000 fd:00 654110 /data/local/mousse/test_de_legacy
        ss >> addr_str >> tmp >> region_offset_str >> tmp >> tmp >> tmp;
        if (tmp.at(0) == '/' || tmp.at(0) == '[' ) {
            m_processMemoryMap[tmp].push_back(std::make_pair(start, end));
        }
        if (address >= start && address < end) {
            uint64_t region_offset = strtoul(region_offset_str.c_str(), NULL, 16);
            offset = address - start + region_offset;
            file = tmp;
            isMapped = true;
        }
    }

    ifs.close();

    if (isMapped)
        return file;
    else
        return std::string("<unknown module>");
}

void ProcessMonitor::updateProcessAddressMap()
{
    std::stringstream ss;
    std::ifstream ifs;
    std::string line, tmp;

    pid_t pid = getpid();
    ss << "/proc/" << pid << "/maps";
    ifs.open(ss.str());

    if (!ifs.is_open())
        return;

    m_processMemoryMap.clear();
    while (std::getline(ifs, line)) {
        uint64_t start, end;
        sscanf(line.c_str(), "%llx-%llx ", &start, &end);
        std::string region_offset_str;
        ss.str(std::string());
        ss.clear();
        ss << line;
        //40000000-40001000 r-xp 00000000 fd:00 654110 /data/local/mousse/test_de_legacy
        ss >> tmp >> tmp >> region_offset_str >> tmp >> tmp >> tmp;
        if (tmp.at(0) == '/' || tmp.at(0) == '[' ) {
            m_processMemoryMap[tmp].push_back(std::make_pair(start, end));
        }
    }

    ifs.close();
}

void ProcessMonitor::updateProcessAddressMap(const std::string &file, uint64_t addr)
{
    std::stringstream ss;
    std::ifstream ifs;
    std::string line, tmp;

    pid_t pid = getpid();
    ss << "/proc/" << pid << "/maps";
    ifs.open(ss.str());

    if (!ifs.is_open())
        return;

    bool found = false;
    MemoryRegions memoryRegionsOfFile;
    while (std::getline(ifs, line)) {
        uint64_t start, end;
        sscanf(line.c_str(), "%llx-%llx ", &start, &end);
        ss.str(std::string());
        ss.clear();
        ss << line;
        ss >> tmp >> tmp >> tmp >> tmp >> tmp >> tmp;
        if (tmp.compare(file) == 0) {
            if (tmp.at(0) == '/' || tmp.at(0) == '[' ) {
                memoryRegionsOfFile.push_back(std::make_pair(start, end));
            }
            found = true;
        }
    }
    ifs.close();

    if (found) {
        m_processMemoryMap[file] = memoryRegionsOfFile;
    }
}

uint64_t ProcessMonitor::getOffsetWithinFile(const std::string &file, uint64_t addr)
{
    if (isAddressUnknown(addr))
        updateProcessAddressMap(file, addr);

    if (m_processMemoryMap.find(file) != m_processMemoryMap.end()) {
        for (auto it : m_processMemoryMap[file]) {
            if (addr >= it.first && addr < it.second) {
                return addr - it.first;
            }
        }
    }

    return (uint64_t)-1;
}

uint64_t ProcessMonitor::getAddressWithinFile(const std::string &file, uint64_t offset)
{
    if (m_offsetAddressMap.find(offset) != m_offsetAddressMap.end()) {
        return m_offsetAddressMap[offset];
    }

    uint64_t pos = 0;
    if (m_processMemoryMap.find(file) != m_processMemoryMap.end()) {
        for (auto it : m_processMemoryMap[file]) {
            uint64_t seg_size = it.second - it.first;
            if (offset < pos + seg_size) {
                uint64_t address = it.first + offset - pos;
                m_offsetAddressMap[offset] = address;
                return address;
            }
            pos += seg_size;
        }
    } else {
        updateProcessAddressMap(file);
        for (auto it : m_processMemoryMap[file]) {
            uint64_t seg_size = it.second - it.first;
            if (offset < pos + seg_size) {
                uint64_t address = it.first + offset - pos;
                m_offsetAddressMap[offset] = address;
                return address;
            }
            pos += seg_size;
        }
    }

    return (uint64_t)-1;
}

bool ProcessMonitor::isAddressWithinFile(uint64_t addr, const std::string &file)
{
    if (isAddressUnknown(addr))
        updateProcessAddressMap(file, addr);

    for (auto region : m_processMemoryMap[file]) {
        if (addr > region.first && addr < region.second)
            return true;
    }
    return false;
}

bool ProcessMonitor::isAddressUnknown(uint64_t addr)
{
    for (auto file : m_processMemoryMap) {
        for (auto region : file.second) {
            if (addr > region.first && addr < region.second)
                return false;
        }
    }
    return true;
}

int ProcessMonitor::getFdOfFile(const std::string & file)
{
    for (auto it : m_processFdMap) {
        if (file.compare(it.second) == 0) {
            return it.first;
        }
    }
    return -1;
}

std::string ProcessMonitor::getFileOfFd(int fd)
{
    auto it = m_processFdMap.find(fd);
    if (it != m_processFdMap.end())
        return it->second;
    else
        return std::string("unknown file");
}

std::string ProcessMonitor::getNameOfThread()
{
    auto it = m_threadNameMap.find(gettid());
    if (it != m_processFdMap.end())
        return it->second;
    else
        return std::string("");
}

std::string ProcessMonitor::getNameOfThread(uint32_t tid)
{
    auto it = m_threadNameMap.find(tid);
    if (it != m_processFdMap.end())
        return it->second;
    else
        return std::string("");
}

void ProcessMonitor::printProcessFdMap(S2EExecutionState *state)
{
    for (auto it : m_processFdMap) {
        getWarningsStream(state) << "fd " << it.first << ": " << it.second << "\n";
    }
}

void ProcessMonitor::openFile(S2EExecutionState *state, uint64_t ret, uint64_t pathNamePtr, const char* syscall)
{
    std::string pathName;
    char pathNameChar;
    for (unsigned i = 0; i < 128; i++) {
        if (state->mem()->read<char>(pathNamePtr + i, &pathNameChar, VirtualAddress, false)) {
            if (pathNameChar != '\0')
                pathName.push_back(pathNameChar);
            else
                break;
        } else {
            getWarningsStream(state) << "on " << syscall << ": failed to read file path\n";
            return;
        }
    }

    if ((int32_t)ret < 0) {
        if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE)
            getWarningsStream(state) << syscall << " " << pathName
                    << " failed, ret = " << (int32_t)ret << "\n";
        return;
    } else {
        if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE)
            getWarningsStream(state) << syscall << " " << pathName
                    << " fd = " << ret << "\n";
    }

    m_processFdMap[ret] = pathName;
    updateProcessAddressMap(pathName);

}

void ProcessMonitor::openSocket(S2EExecutionState *state, uint64_t fd)
{
    if (fd == -1) {
        if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE)
            getWarningsStream(state) << getNameOfThread() << " open socket failed\n";
        return;
    } else {
        if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE)
            getWarningsStream(state) << getNameOfThread() << " open socket, fd = " << fd << "\n";
    }
    
    std::stringstream ss;
    ss << "socket_fd" << fd;
    m_processFdMap[fd] = ss.str();
}

void ProcessMonitor::bindSocket(S2EExecutionState *state, uint64_t fd, uint64_t addr)
{
    struct sockaddr *dst_addr = (struct sockaddr *)addr;
    if (dst_addr->sa_family == AF_LOCAL)
        m_processFdMap[fd] = std::string(dst_addr->sa_data);

    if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE) {
        getWarningsStream(state) << getNameOfThread() << " bind socket, fd = " << fd
                << ", pathName = " << dst_addr->sa_data << "\n";
    }
}

void ProcessMonitor::connectSocket(S2EExecutionState *state, uint64_t fd, uint64_t addr)
{
    struct sockaddr *dst_addr = (struct sockaddr *)addr;
    if (dst_addr->sa_family == AF_LOCAL)
        m_processFdMap[fd] = std::string(dst_addr->sa_data);

    if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE) {
        getWarningsStream(state) << getNameOfThread() << " connect socket, fd = " << fd
                << ", pathName = " << dst_addr->sa_data << "\n";
    }
}

std::string to_string(const char *buf, size_t len)
{
    std::stringstream ss;
    ss << "\"";
    for (unsigned i = 0; i < len; i++) {
        if (isprint(buf[i])) {
            ss << buf[i];
        } else {
            ss << "\\" << std::dec << (uint32_t)buf[i];
        }
    }
    ss << "\", " << len;
    return ss.str();
}

void ProcessMonitor::write(S2EExecutionState *state, uint64_t fd, uint64_t addr, uint64_t count)
{
    if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE) {
        auto it = m_processFdMap.find(fd);
        std::string fdPath = (it != m_processFdMap.end())? it->second : std::string("unknown");
        std::string data = to_string((char *)addr, count);
        uint32_t tid = 0;
        if (sscanf(fdPath.c_str(), "/proc/self/task/%u/comm", &tid) > 0) {
            m_threadNameMap[tid] = std::string((char *)addr, count);
        }

        getWarningsStream(state) << getNameOfThread()
                << " write(" << fd << "(" << fdPath << "), " << data << "}\n";
    }
}

void ProcessMonitor::writev(S2EExecutionState *state, uint64_t fd, uint64_t iov, uint64_t iovcnt)
{
    if (m_debugLevel >= DEBUGLEVEL_FD_OPEN_CLOSE) {
        std::stringstream ss;
        auto it = m_processFdMap.find(fd);
        std::string fdPath = (it != m_processFdMap.end())? it->second : std::string("unknown");
        ss << " writev(" << fd << "(" << fdPath << "), [";
        for (unsigned i = 0; i < iovcnt; i++) {
            struct iovec *ioi = ((struct iovec*)iov) + i;
            ss << "{" << to_string((char *)ioi->iov_base, ioi->iov_len) << "}";
            if (i < iovcnt-1)
                ss << ", ";
        }
        ss << "], " << iovcnt << "}\n";
        getWarningsStream(state) << getNameOfThread() << ss.str();
    }
}

uint64_t roundUpToPages(uint64_t len)
{
    return (len & 0xfff)? ((len & 0xfffffffffffff000) + 0x1000) : len;
}

uint64_t roundDownToPages(uint64_t len)
{
    return (len & 0xfffffffffffff000);
}

void ProcessMonitor::printMap() {
    for (auto it : m_processMap) {
        g_s2e->getWarningsStream() << hexval((uint32_t)it.second.start)
                << "-" << hexval(uint32_t(it.second.end))
                << " " << it.second.offset << "\t " << it.second.path << "\n";
    }
}

#define SYSCALL_NUM_MAX 378
static uint8_t syscall_reg_num[SYSCALL_NUM_MAX] = {
    0, 1, 0, 3, 3, 3, 1, 0, 2, 2, 1, 3, 1, 1, 3, 2, 3, 0, 0, 3,
    0, 5, 2, 1, 0, 1, 4, 1, 0, 0, 2, 0, 0, 2, 1, 0, 0, 2, 2, 2,
    1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 2, 0, 3, 3, 0, 2, 0, 0,
    1, 1, 2, 2, 0, 0, 0, 3, 0, 0, 2, 2, 3, 1, 2, 2, 2, 2, 2, 2,
    2, 2, 5, 2, 0, 3, 1, 2, 4, 3, 1, 2, 2, 2, 2, 3, 2, 3, 0, 2,
    2, 0, 2, 3, 3, 2, 2, 2, 2, 0, 0, 0, 0, 0, 4, 1, 1, 6, 1, 0,
    5, 2, 1, 0, 1, 3, 3, 0, 3, 2, 0, 4, 1, 1, 2, 3, 1, 0, 1, 1,
    5, 3, 5, 2, 3, 3, 3, 1, 1, 1, 2, 2, 1, 0, 2, 2, 3, 1, 0, 1,
    1, 2, 2, 5, 3, 3, 0, 0, 3, 0, 3, 3, 5, 0, 4, 4, 2, 4, 3, 2,
    2, 2, 3, 2, 2, 2, 0, 4, 0, 0, 0, 2, 6, 1, 1, 2, 2, 2, 3, 0,
    0, 0, 0, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 3, 2, 3,
    3, 3, 0, 0, 0, 1, 5, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2, 4,
    6, 3, 3, 2, 1, 5, 3, 3, 1, 1, 1, 4, 4, 5, 0, 0, 1, 3, 4, 2,
    1, 1, 2, 2, 2, 4, 3, 3, 3, 2, 4, 0, 5, 5, 4, 1, 5, 5, 2, 3,
    5, 3, 3, 3, 2, 3, 3, 3, 4, 4, 6, 4, 6, 2, 5, 5, 3, 3, 3, 3,
    2, 4, 5, 2, 3, 3, 1, 3, 3, 5, 4, 5, 4, 0, 3, 2, 0, 3, 2, 6,
    5, 3, 4, 3, 4, 5, 3, 4, 3, 4, 5, 3, 4, 3, 3, 6, 5, 1, 2, 3,
    6, 2, 4, 4, 6, 3, 6, 4, 4, 3, 2, 1, 2, 4, 2, 4, 2, 1, 3, 2,
    1, 5, 5, 4, 5, 5, 4, 2, 2, 4, 5, 3, 2, 1, 4, 2, 6, 6
};

void ProcessMonitor::onDoSyscallEnd(S2EExecutionState *state,
        uint64_t syscallNum, uint64_t ret, SyscallArguments *args)
{
    if (m_debugLevel >= DEBUGLEVEL_ALL_SYSCALLS) {
        bool reg_num_exist = (syscallNum < SYSCALL_NUM_MAX);
        int reg_num = reg_num_exist? syscall_reg_num[syscallNum] : 0;
        std::stringstream ss;

        if (reg_num > 0)
            ss << args->arg1;
        if (reg_num > 1)
            ss << ", " << args->arg2;
        if (reg_num > 2)
            ss << ", " << args->arg3;
        if (reg_num > 3)
            ss << ", " << args->arg4;
        if (reg_num > 4)
            ss << ", " << args->arg5;
        if (reg_num > 5)
            ss << ", " << args->arg6;

        getWarningsStream(state) << getNameOfThread() << " syscall_" << syscallNum
                << "(" << ss.str() << ") = " << ret << "\n";
    }

    switch (syscallNum) {
        case SYSCALL_OPEN:
            openFile(state, ret, args->arg1, "open");
            break;
        case SYSCALL_CREATE:
            openFile(state, ret, args->arg1, "create");
            break;
        case SYSCALL_OPENAT:
            openFile(state, ret, args->arg2, "openat");
            break;
        case SYSCALL_SOCKET:
            openSocket(state, ret);
            break;
        case SYSCALL_BIND:
            if (ret == 0)
                bindSocket(state, args->arg1, args->arg2);
            break;
        case SYSCALL_CONNECT:
            if (ret == 0)
                connectSocket(state, args->arg1, args->arg2);
            break;
        case SYSCALL_CLOSE:
            if (ret != -1) {
                std::string file = m_processFdMap[args->arg1];
                //m_processMemoryMap.erase(file);
                m_processFdMap.erase(args->arg1);
            }
            break;
        case SYSCALL_WRITE:
                write(state, args->arg1, args->arg2, args->arg3);
            break;
        case SYSCALL_WRITEV:
                writev(state, args->arg1, args->arg2, args->arg3);
            break;
        case SYSCALL_PIPE2:
            if (ret == 0) {
                std::stringstream ss;
                int *fd = (int *)args->arg1;
                ss << "[" << fd[0] << "," << fd[1] << "]";
                getWarningsStream(state) << getNameOfThread() << " pipe2(" << ss.str() << ", ...) = 0\n";
                m_processFdMap[fd[0]] = std::string("pipe2") + ss.str() + std::string(":0");
                m_processFdMap[fd[1]] = std::string("pipe2") + ss.str() + std::string(":1");
            }
            break;
        case SYSCALL_MMAP:
        case SYSCALL_MMAP2:
        case SYSCALL_MREMAP:
        case SYSCALL_MUNMAP:
        case SYSCALL_SHMAT:
        case SYSCALL_SHMDT:
            updateProcessAddressMap();
            break;
#ifdef TEST_FAST_MEM_TRACKING
        case SYSCALL_PRCTL:
            if (args->arg1 == 0x53564d41) {
                std::string pathName;
                char pathNameChar;
                for (unsigned i = 0; i < 128; i++) {
//                    getWarningsStream(state) << "read " << hexval(args->arg5+i) << " " << pathNameChar << "\n";
                    if (state->mem()->read<char>(args->arg5 + i, &pathNameChar, VirtualAddress, false)) {
                        if (pathNameChar != '\0')
                            pathName.push_back(pathNameChar);
                        else
                            break;
                    } else {
                        getWarningsStream(state) << "on prctl: failed to read file path\n";
                        return;
                    }
                }
                m_processMap[args->arg3].path = pathName;
            }
            break;
        case SYSCALL_MMAP2: {
            uint64_t fd = args->arg5;
            if (fd == (uint64_t)-1) {
            } else {
                uint64_t size = roundUpToPages(args->arg2);
                seg *s = &m_processMap[ret];
                s->start = ret;
                s->end = ret + size;
                s->offset = args->arg6 << 12;
                auto it = m_processFdMap.find(fd);
                if (it != m_processFdMap.end()) {
                    s->path = m_processFdMap[fd];
                }
            }
            break;
        }
        case SYSCALL_MUNMAP: {
            uint64_t start = roundDownToPages(args->arg1);
            if (ret == 0) {
                for (auto it = m_processMap.begin(); it != m_processMap.end(); it++) {
                    //XXX Assuming munmap always exactly delete the
                    //previous mapped region
                    if (it->first == start) {
                        m_processMap.erase(it);
                    }
                }
            }
            break;
        }
#endif
        default: break;
    }
}


} // namespace plugins
} // namespace s2e
