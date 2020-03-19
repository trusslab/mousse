///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2019 TrussLab@University of California, Irvine. 
/// Authors: Ardalan Amiri Sani<ardalan@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/// Adopted and modified the MultiSearcher plugin code to implement the searcher in this plugin
/// Socket code from https://www.geeksforgeeks.org/socket-programming-cc/

#include "MultiProcess.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include <cstdio> 
#include <sys/socket.h> 
#include <cstdlib> 
#include <netinet/in.h> 
#include <cstring> 
#include <arpa/inet.h>

#include <klee/ExprSerializer.h>
#include <klee/ExprDeserializer.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MultiProcess, "MultiProcess S2E Plugin", "");

void MultiProcess::initialize() {

    s2e()->getCorePlugin()->onStateFork.connect(
            sigc::mem_fun(*this, &MultiProcess::slotStateFork));
    s2e()->getCorePlugin()->onSymbolicVariableCreation.connect(
            sigc::mem_fun(*this, &MultiProcess::slotSymbolicVariableCreation));
    s2e()->getCorePlugin()->onStateSwitch.connect(
            sigc::mem_fun(*this, &MultiProcess::slotStateSwitch));
    s2e()->getCorePlugin()->onStateKill.connect(
            sigc::mem_fun(*this, &MultiProcess::slotStateKill));
    s2e()->getCorePlugin()->onDoSyscallStart.connect(
            sigc::mem_fun(*this, &MultiProcess::slotDoSyscallStart));
    s2e()->getCorePlugin()->onDoSyscallEnd.connect(
            sigc::mem_fun(*this, &MultiProcess::onDoSyscallEnd));
    s2e()->getCorePlugin()->onLoadImageEnd.connect(
            sigc::mem_fun(*this, &MultiProcess::onLoadImage));

}

void MultiProcess::onLoadImage(S2EExecutionState *state, ImageInfo *info) {
}

void MultiProcess::onTranslateBlockStart(ExecutionSignal *signal, 
                                                 S2EExecutionState *state, 
                                                 TranslationBlock *tb, 
                                                 uint64_t pc) {
//    registerCallSignalHandler(state);
}

void MultiProcess::slotStateForkN(S2EExecutionState *state, 
                                          const std::vector<S2EExecutionState*>& new_states, 
                                          const std::vector<klee::ref<klee::Expr>>& new_conditions) {
}

//klee::ExprSerializer *gSerializer;

void MultiProcess::slotStateFork(S2EExecutionState *state, 
                                         const std::vector<S2EExecutionState*>& new_states, 
                                         const std::vector<klee::ref<klee::Expr>>& new_conditions) {
    if (state == new_states[0]) {
        new_states[1]->setStateSwitchForbidden(true);
        new_states[0]->setStateSwitchForbidden(true);
    } else {
        new_states[0]->setStateSwitchForbidden(true);
        new_states[1]->setStateSwitchForbidden(true);
    }
}

void MultiProcess::slotStateForkF(S2EExecutionState *state,
                                          const std::vector<S2EExecutionState*>& new_states,
                                          const std::vector<klee::ref<klee::Expr>>& new_conditions) {

}

void MultiProcess::slotSymbolicVariableCreation(S2EExecutionState *state,
        const std::string &originalName, const std::vector<klee::ref<klee::Expr>> &expr,
        const klee::MemoryObject *memObj, const klee::Array *array) {
}

void MultiProcess::slotStateSwitch(S2EExecutionState *current_state, 
                                           S2EExecutionState *next_state) {
}

void MultiProcess::slotStateKill(S2EExecutionState *state) {
    getDebugStream(state) << "remove state[" << state->getID() << "]\n";
}

int MultiProcess::waitForSymChannel(void)
{
	int server_fd; 
	struct sockaddr_in address; 
	int opt = 1; 
	int addrlen = sizeof(address); 
         
	// Creating socket file descriptor 
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
	{ 
            return -1;
	} 
	   
	// Forcefully attaching socket to the port 8080 
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
	                                              &opt, sizeof(opt))) 
	{ 
            return -1;
	} 
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = INADDR_ANY; 
	address.sin_port = htons(m_sym_port); 
	   
	// Forcefully attaching socket to the port 8080 
	if (bind(server_fd, (struct sockaddr *)&address,  
	                             sizeof(address))<0) 
	{ 
            return -1;
	} 

	if (listen(server_fd, 3) < 0) 
	{ 
            return -1;
	} 

	if ((m_sym_sock_fd = accept(server_fd, (struct sockaddr *)&address,  
	                   (socklen_t*)&addrlen))<0) 
	{ 
            return -1;
	} 

        close(server_fd);

        return 0;
}

int MultiProcess::establishSymChannel(void)
{
	struct sockaddr_in serv_addr; 

	if ((m_sym_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
	    return -1; 
	} 
	
	memset(&serv_addr, '0', sizeof(serv_addr)); 
	
	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(m_sym_port); 
	   
	// Convert IPv4 and IPv6 addresses from text to binary form 
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  
	{ 
	    return -1; 
	} 
	
	if (connect(m_sym_sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
	{ 
	    return -1; 
	} 

	return 0;
}

void MultiProcess::slotDoSyscallStart(S2EExecutionState *state, 
                                              uint64_t syscall_num, 
                                              SyscallArguments *args) {

    switch (syscall_num) {
    case 366: { /* accept4 */ //FIXME: support accept too.
        struct sockaddr_in *dst_addr = (struct sockaddr_in *) args->arg2;

        if (ntohl(dst_addr->sin_addr.s_addr) == INADDR_ANY) {
            if (ntohs(dst_addr->sin_port) == 8080) {
                m_target_accept4 = true;
            }
        }

        break;
    }
    default:
        break;
    }

}

void MultiProcess::sendSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size) {
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
                //uint8_t w = 4;
                //send(m_sym_sock_fd, &w, 1, 0);
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
                //uint8_t w = 2;
                //send(m_sym_sock_fd, &w, 1, 0);
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
                //uint8_t w = 1;
                //send(m_sym_sock_fd, &w, 1, 0);
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

void MultiProcess::recvSymInfo(S2EExecutionState *state, uint64_t buf, uint64_t size) {
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
        delete deserializer;
        delete bufPtr;
        recv(m_sym_sock_fd, &sym, 1, 0);
    }
}

void MultiProcess::onDoSyscallEnd(S2EExecutionState *state, uint64_t syscall_id, 
                                      uint64_t ret, SyscallArguments *args) {

    switch (syscall_id) {
    case 283: { /* connect */
        if (ret == 0) {
            int sock_fd = (int) args->arg1;
            struct sockaddr_in *dst_addr = (struct sockaddr_in *) args->arg2;
            if (ntohl(dst_addr->sin_addr.s_addr) == INADDR_LOOPBACK) {
                if (ntohs(dst_addr->sin_port) == 8080) {
                    m_sock_fd = sock_fd;
                    establishSymChannel();
                }
            }
        }

        break;
    }

    case 366: { /* accept4 */ //FIXME: support accept too.
        if (ret && m_target_accept4) {
            m_sock_fd = ret;
            waitForSymChannel();
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

    default:
        break;
    }
}

//Core/BaseInstruction.cpp
void MultiProcess::makeMemorySymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
                                              const std::string &nameStr, bool makeConcolic,
                                              std::vector<klee::ref<klee::Expr>> *varData = NULL, 
                                              std::string *varName = NULL) {
    std::vector<klee::ref<klee::Expr>> symb;
    std::stringstream valueSs;

    if (makeConcolic) {
        std::vector<uint8_t> concreteData;

        valueSs << "='";
        for (unsigned i = 0; i < size; ++i) {
            uint8_t byte = 0;
            if (!state->mem()->read<uint8_t>(address + i, &byte, VirtualAddress, false)) {
                getWarningsStream(state) << "Can not concretize/read symbolic value at " << hexval(address + i)
                                         << ". System state not modified\n";
                return;
            }
            concreteData.push_back(byte);
            valueSs << charval(byte);
        }
        valueSs << "'";
        symb = state->createConcolicArray(nameStr, size, concreteData, varName);
    } else {
        symb = state->createSymbolicArray(nameStr, size, varName);
    }

    getInfoStream(state) << "Inserted symbolic data @" << hexval(address)
            << " of size " << hexval(size) << ": " << (varName ? *varName : nameStr) 
            << valueSs.str() << " pc=" << hexval(state->regs()->getPc()) << "\n";

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


} // namespace plugins
} // namespace s2e
