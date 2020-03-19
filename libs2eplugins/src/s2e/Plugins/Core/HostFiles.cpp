///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Yingtong Liu <yingtong@uci.edu> 
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include "HostFiles.h"

#include <errno.h>
#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <llvm/Config/config.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(HostFiles, "Access to host files", "", );

void HostFiles::initialize() {
    m_allowWrite = s2e()->getConfig()->getBool(getConfigKey() + ".allowWrite", false, NULL);

    ConfigFile::string_list dirs = s2e()->getConfig()->getStringList(getConfigKey() + ".baseDirs");

    foreach2 (it, dirs.begin(), dirs.end()) { m_baseDirectories.push_back(*it); }

    foreach2 (it, m_baseDirectories.begin(), m_baseDirectories.end()) {
        if (!llvm::sys::fs::exists((*it))) {
            getWarningsStream() << "Path " << (*it) << " does not exist\n";
            exit(-1);
        }
    }

    if (m_baseDirectories.empty()) {
        m_baseDirectories.push_back(s2e()->getOutputDirectory());
    }

    s2e()->getCorePlugin()->onCustomInstruction.connect(sigc::mem_fun(*this, &HostFiles::onCustomInstruction));

    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &HostFiles::onStateFork));
}

void HostFiles::open(S2EExecutionState *state) {
	assert(false && "HostFiles::open failed\n");
}

void HostFiles::read(S2EExecutionState *state) {
	assert(false && "HostFiles::read failed\n");
}

void HostFiles::close(S2EExecutionState *state) {
	assert(false && "HostFiles::close failed\n");
    // Get the plugin state for the current path
}

/* Create a new file write only */
void HostFiles::create(S2EExecutionState *state) {
	assert(false && "HostFiles::create failed\n");
}

void HostFiles::write(S2EExecutionState *state) {
	assert(false && "HostFiles::write failed\n");
}

void HostFiles::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    // XXX: find a better way of allocating custom opcodes
    if (!OPCODE_CHECK(opcode, HOST_FILES_OPCODE)) {
        return;
    }

    opcode >>= 16;
    uint8_t op = opcode & 0xFF;
    opcode >>= 8;

    switch (op) {
        case HOST_FILES_OPEN_OPCODE: {
            open(state);
            break;
        }

        case HOST_FILES_CLOSE_OPCODE: {
            close(state);
            break;
        }

        case HOST_FILES_READ_OPCODE: {
            read(state);
            break;
        }

        case HOST_FILES_CREATE_OPCODE: {
            create(state);
            break;
        }

        case HOST_FILES_WRITE_OPCODE: {
            write(state);
            break;
        }

        default:
            getWarningsStream(state) << "Invalid HostFiles opcode " << hexval(op) << '\n';
            break;
    }
}

void HostFiles::onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                            const std::vector<klee::ref<klee::Expr>> &newConditions) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    if (plgState->nb_open > 0) {
        getWarningsStream(state) << "HostFiles : Forking new state with "
                                 << "open files, expect errors!\n";
    }
}

///////////////////////////////////////////////////////////////////////////////

HostFilesState::HostFilesState() : m_openFiles() {
    nb_open = 0;
}

HostFilesState::HostFilesState(S2EExecutionState *s, Plugin *p) : m_openFiles() {
    nb_open = 0;
}

HostFilesState::~HostFilesState() {
}

PluginState *HostFilesState::clone() const {
    return new HostFilesState();
}

PluginState *HostFilesState::factory(Plugin *p, S2EExecutionState *s) {
    return new HostFilesState(s, p);
}

} // namespace plugins
} // namespace s2e
