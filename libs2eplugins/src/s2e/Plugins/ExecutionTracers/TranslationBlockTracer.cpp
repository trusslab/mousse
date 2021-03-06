///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Yingtong Liu <yingtong@uci.edu> 
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <iostream>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include "TranslationBlockTracer.h"

#include <llvm/Support/CommandLine.h>

extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TranslationBlockTracer, "Tracer for executed translation blocks", "TranslationBlockTracer",
                  "ExecutionTracer");

void TranslationBlockTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    // Retrict monitoring to configured modules only
    m_monitorModules = s2e()->getConfig()->getBool(getConfigKey() + ".monitorModules");
    if (m_monitorModules && !m_detector) {
        getWarningsStream() << "TranslationBlockTracer: The monitorModules option requires ModuleExecutionDetector\n";
        exit(-1);
    }

    bool ok = false;
    // Specify whether or not to enable cutom instructions for enabling/disabling tracing
    bool manualTrigger = s2e()->getConfig()->getBool(getConfigKey() + ".manualTrigger", false, &ok);

    // Whether or not to flush the translation block cache when enabling/disabling tracing.
    // This can be useful when tracing is enabled in the middle of a run where most of the blocks
    // are already translated without the tracing instrumentation enabled.
    // The default behavior is ON, because otherwise it may produce confusing results.
    m_flushTbOnChange = s2e()->getConfig()->getBool(getConfigKey() + ".flushTbCache", true);

    if (manualTrigger) {
        s2e()->getCorePlugin()->onCustomInstruction.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onCustomInstruction));
    } else {
        enableTracing();
    }
}

bool TranslationBlockTracer::tracingEnabled() {
    return m_tbStartConnection.connected() || m_tbEndConnection.connected();
}

void TranslationBlockTracer::enableTracing() {
    if (m_tbStartConnection.connected()) {
        return;
    }

    if (g_s2e_state != NULL && m_flushTbOnChange) {
        se_tb_safe_flush();
    }

    if (m_monitorModules) {
        m_tbStartConnection = m_detector->onModuleTranslateBlockStart.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onModuleTranslateBlockStart));

        m_tbEndConnection = m_detector->onModuleTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onModuleTranslateBlockEnd));
    } else {
        m_tbStartConnection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onTranslateBlockStart));

        m_tbEndConnection = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onTranslateBlockEnd));
    }
}

void TranslationBlockTracer::disableTracing() {
    if (m_flushTbOnChange) {
        se_tb_safe_flush();
    }

    m_tbStartConnection.disconnect();
    m_tbEndConnection.disconnect();
}

void TranslationBlockTracer::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockStart));
}

void TranslationBlockTracer::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t endPc, bool staticTarget,
                                                 uint64_t targetPc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockEnd));
}

void TranslationBlockTracer::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                         const ModuleDescriptor &module, TranslationBlock *tb,
                                                         uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockStart));
}

void TranslationBlockTracer::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                       const ModuleDescriptor &module, TranslationBlock *tb,
                                                       uint64_t endPc, bool staticTarget, uint64_t targetPc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockEnd));
}

bool TranslationBlockTracer::getConcolicValue(S2EExecutionState *state, unsigned offset, uint64_t *value,
                                              unsigned size) {
    klee::ref<klee::Expr> expr = state->regs()->read(offset, size * 8);
    if (isa<klee::ConstantExpr>(expr)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(expr);
        *value = ce->getZExtValue();
        return true;
    }

    if (ConcolicMode) {
        klee::ref<klee::ConstantExpr> ce;
        ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
        *value = ce->getZExtValue();
        return true;
    } else {
        *value = 0xdeadbeef;
        return false;
    }
}

// The real tracing is done here
//-----------------------------
void TranslationBlockTracer::trace(S2EExecutionState *state, uint64_t pc, ExecTraceEntryType type) {
	assert(false && "TranslationBlockTracer::trace failed\n");
}

void TranslationBlockTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    trace(state, pc, TRACE_TB_START);
}

void TranslationBlockTracer::onExecuteBlockEnd(S2EExecutionState *state, uint64_t pc) {
    trace(state, pc, TRACE_TB_END);
}

void TranslationBlockTracer::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    // XXX: find a better way of allocating custom opcodes
    if (!OPCODE_CHECK(opcode, TB_TRACER_OPCODE)) {
        return;
    }

    // XXX: remove this mess. Should have a function for extracting
    // info from opcodes.
    opcode >>= 16;
    uint8_t op = opcode & 0xFF;
    opcode >>= 8;

    TbTracerOpcodes opc = (TbTracerOpcodes) op;
    switch (opc) {
        case Enable:
            enableTracing();
            break;

        case Disable:
            disableTracing();
            break;

        default:
            getWarningsStream() << "MemoryTracer: unsupported opcode " << hexval(opc) << '\n';
            break;
    }
}

bool TranslationBlockTracer::getProperty(S2EExecutionState *state, const std::string &name, std::string &value) {
    return false;
}

bool TranslationBlockTracer::setProperty(S2EExecutionState *state, const std::string &name, const std::string &value) {
    if (name == "trace") {
        if (value == "1") {
            enableTracing();
        } else {
            disableTracing();
        }
        return true;
    }
    return false;
}

} // namespace plugins
} // namespace s2e
