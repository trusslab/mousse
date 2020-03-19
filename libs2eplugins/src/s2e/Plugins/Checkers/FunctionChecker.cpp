/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "FunctionChecker.h"

//#include <klee/Expr.h>
#include <klee/Solver.h>
#include <klee/util/ExprTemplates.h>

#include <s2e/cpu.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

// FunctionChecker under system mode would further requires ModuleExecutionDetector
S2E_DEFINE_PLUGIN(FunctionChecker, "FunctionChecker plugin", "FunctionChecker",
                  "FunctionMonitor");

int FunctionChecker::getArgumentType(std::string& type) {
    if (type.compare("int") == 0)
        return INT_ARG;
    if (type.compare("ptr") == 0)
        return PTR_ARG;
    if (type.compare("fp") == 0)
        return FP_ARG;
    getWarningsStream() << "Invlaid argument type: " << type << "\n";
    exit(1);
}

int FunctionChecker::getArgumentReg(int type, int& intArgumentNum, int& fpArgumentNum) {
    switch (type) {
        case INT_ARG:
        case PTR_ARG:
            intArgumentNum++;
            break;
        case FP_ARG:
            fpArgumentNum++;
    }
    // Calling convention of System V AMD64 ABI
    // integer or pointer arguments: RDI, RSI, RDX, RCX, R8, R9
    // floating point arguments: XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7

#ifdef TARGET_I386
    if (type == INT_ARG || type == PTR_ARG) {
        switch (intArgumentNum) {
            case 1: return R_EDI;
            case 2: return R_ESI;
            case 3: return R_EDX;
            case 4: return R_ECX;
            case 5: return 8;
            case 6: return 9;
            default:
                getWarningsStream() << "Do not support functions with more than 6 integer/pointer arguemnts\n";
        }
    }

    if (type == FP_ARG) {
        getWarningsStream() << "Do not support floating-point arguemnts\n";
    }
#endif

#ifdef TARGET_ARM
    int ArgumentNum = intArgumentNum + fpArgumentNum;
    if (ArgumentNum <= 4) {
        return ArgumentNum - 1;
    } else {
        getWarningsStream() << "Do not support functions with more than 4 arguments\n";
    }
#endif

    exit(1);
}

void FunctionChecker::initialize() {
    m_registered = false;
    m_solutionCounter = 0;

    ConfigFile *cfg = s2e()->getConfig();

    m_userMode = cfg->getBool(getConfigKey() + ".userMode", false);

    // Register entry functions
    std::stringstream entrySs;
    entrySs << getConfigKey() << ".entry";    
    ConfigFile::string_list entryFunctions = cfg->getListKeys(entrySs.str());
    foreach2 (it, entryFunctions.begin(), entryFunctions.end()) {
        const std::string &function = *it;
        std::stringstream ss;
        ss << entrySs.str() << "." << function;
        ConfigFile::string_list functionConfigs = cfg->getListKeys(ss.str());

        std::string name = function;
        uint64_t address = cfg->getInt(ss.str() + ".address");
        entryFunctionDescriptor descriptor = {name};
        m_entryFunctionDescriptors.insert(std::make_pair(address, descriptor));
    }

    // Register target functions
    std::stringstream targetSs;
    targetSs << getConfigKey() << ".target";    
    ConfigFile::string_list targetFunctions = cfg->getListKeys(targetSs.str());
    foreach2 (it, targetFunctions.begin(), targetFunctions.end()) {
        const std::string &function = *it;
        std::stringstream ss;
        ss << targetSs.str() << "." << function;
        ConfigFile::string_list functionConfigs = cfg->getListKeys(ss.str());

        std::string functionName = function;
        uint64_t address = cfg->getInt(ss.str() + ".address");
        bool addConstraint = cfg->getBool(ss.str() + ".addConstraint", false);
        bool printConstraint = cfg->getBool(ss.str() + ".printConstraint", false);
        bool solveConstraint = cfg->getBool(ss.str() + ".solveConstraint", false);
        bool terminateState = cfg->getBool(ss.str() + ".terminateState", false);
        bool concretizeArgs = cfg->getBool(ss.str() + ".concretizeArgs", false);
        bool recordArgs = cfg->getBool(ss.str() + ".recordArgs", false);

        // Read configuration for each argument of the function
        int intArgumentNum = 0;
        int fpArgumentNum = 0;
        targetFunctionArgs args;
        ConfigFile::string_list targetArguments = cfg->getListKeys(ss.str() + ".arguments");
        foreach2 (it, targetArguments.begin(), targetArguments.end()) {
            const std::string &argument = *it;
            std::string argumentName = argument;
            std::stringstream argSs;
            argSs << ss.str() << ".arguments." << argument;

            std::string typeName = cfg->getString(argSs.str() + ".type"); 
            int type = getArgumentType(typeName);
            int size = cfg->getInt(argSs.str() + ".size");
            int reg = getArgumentReg(type, intArgumentNum, fpArgumentNum);
            getDebugStream() << "Arguments " << argumentName 
                    << " type:"<< type << " size:" << size << " reg:" << reg << "\n";
            targetFunctionArg arg = {argumentName, type, size, reg};
            args.push_back(arg);
        }

        targetFunctionDescriptor descriptor = { functionName, addConstraint, printConstraint, 
                                                solveConstraint, terminateState, 
                                                concretizeArgs, recordArgs, args};
        m_targetFunctionDescriptors.insert(std::make_pair(address, descriptor));
    }

    //m_functionArgument1 = cfg->getInt(getConfigKey() + ".functionArgument1", 0);
    //m_functionAddress = cfg->getIntegerList(getConfigKey() + ".functionAddress"); 
    //m_solutionNumber = cfg->getInt(getConfigKey() + ".solutionNumber", -1);

    m_functionMonitor = s2e()->getPlugin<FunctionMonitor>();
    assert(m_functionMonitor);

    // Register function call signal handlers
    if (!m_userMode) {
        m_moduleDetector = s2e()->getPlugin<ModuleExecutionDetector>();
        assert(m_moduleDetector);

        m_moduleDetector->onModuleLoad.connect(
                sigc::mem_fun(*this, &FunctionChecker::onModuleLoad));
    } else {
        s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                sigc::mem_fun(*this, &FunctionChecker::onTranslateBlockStart));
    }
}

void FunctionChecker::registerCallSignalHandler(S2EExecutionState *state) {
    if (m_registered) {
        return;
    }

    for (auto& it: m_entryFunctionDescriptors) {
        getDebugStream(state) << "Entry function " << it.second.name
                << " @" << hexval(it.first) << " will be checked\n";

        FunctionMonitor::CallSignal *callSignal = 
                m_functionMonitor->getCallSignal(state, it.first, -1);

        callSignal->connect(sigc::mem_fun(*this, &FunctionChecker::entryFunctionCall));
    }

    for (auto& it: m_targetFunctionDescriptors) {
        getDebugStream(state) << "Target function " << it.second.name
                << " @" << hexval(it.first) << " will be checked\n";

        FunctionMonitor::CallSignal *callSignal = 
                m_functionMonitor->getCallSignal(state, it.first, -1);

        callSignal->connect(sigc::mem_fun(*this, &FunctionChecker::targetFunctionCall));
    }

    m_registered = true;
}

void FunctionChecker::onTranslateBlockStart(ExecutionSignal *signal, 
                                            S2EExecutionState *state, 
                                            TranslationBlock *tb, uint64_t pc) {
    registerCallSignalHandler(state);
}

void FunctionChecker::onModuleLoad(S2EExecutionState *state, 
                                   const ModuleDescriptor& module) {
    registerCallSignalHandler(state);
}

void FunctionChecker::printConstraints(S2EExecutionState *state) {
    getDebugStream(state) << "===== Constraints =====\n";
    for (auto c : state->constraints) {
        getDebugStream(state) << c << '\n';
    }
}

bool FunctionChecker::assume(S2EExecutionState *state, klee::ref<klee::Expr> expr) {
    // Check that the added constraint is consistent with
    // the existing path constraints
    bool isValid = true;
    if (ConcolicMode) {
        klee::ref<klee::Expr> ce = state->concolics->evaluate(expr);
        assert(isa<klee::ConstantExpr>(ce) && "Expression must be constant here");
        if (!ce->isTrue()) {
            isValid = false;
        }
    } else {
        bool truth;
        klee::Solver *solver = s2e()->getExecutor()->getSolver(*state);
        klee::Query query(state->constraints, expr);
        bool res = solver->mustBeTrue(query, truth);
        if (!res || truth) {
            isValid = false;
        }
    }

    if (!isValid) {
        std::stringstream ss;
        ss << "FunctionChecker: specified argument constraint cannot be satisfied " 
           << expr;
        //g_s2e->getExecutor()->terminateStateEarly(*state, ss.str());
    }

    state->addConstraint(expr);
    return isValid;
}

bool FunctionChecker::addArgumentConstraint(S2EExecutionState *state) {
    // Calling convention of System V AMD64 ABI
    // integer or pointer arguments: RDI, RSI, RDX, RCX, R8, R9
    // floating point arguments: XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7

    // Create the argument value constraint
    klee::ref<klee::Expr> argExpr_1 = 
            state->regs()->read(CPU_OFFSET(regs[0]), klee::Expr::Int32);
    klee::ref<klee::Expr> argExpectedValue_1 = 
            E_CONST(m_functionArgument1, klee::Expr::Int32); 
    klee::ref<klee::Expr> argConstraint_1 = 
            klee::EqExpr::create(argExpectedValue_1, argExpr_1);

    // Add the constraint if the argument is not a constant and if it is 
    // compatible with current path constraints
    int isValid = false;
    if (argExpr_1->getKind() == klee::Expr::Constant) {
        int64_t regEDIValue = cast<klee::ConstantExpr>(argExpr_1)->getAPValue().getLimitedValue();
        if (regEDIValue != m_functionArgument1) {
            getDebugStream(state) << "Cannot find a solution. The argument does not depend on inputs.\n";
            //return;
        } else {
            isValid = true;
        }
    } else {
        isValid = assume(state, argConstraint_1);
    }

    return isValid;
}

void FunctionChecker::printSolution(S2EExecutionState *state, solution_t solutions) {
    getInfoStream(state) << "Solution [" << m_solutionCounter << "]\n";
    std::stringstream ss;
    for (int i = 0; i < solutions.size(); i++){
        for (auto c : solutions[i].second) {
            if (!std::isprint(c)) {
                ss << "["<<(int)c<<"]";
                break;
            }
            ss << (char)c;
        }
        getInfoStream(state) << solutions[i].first << " = " << ss.str() << "\n";
        ss.str(std::string());
    }
}

bool FunctionChecker::getSolution(S2EExecutionState *state) {
    solution_t inputs;
    bool hasSolution = s2e()->getExecutor()->getSymbolicSolution(*state, inputs);

    if (!hasSolution) {
        getWarningsStream(state) << "Cannot find a solution under the constraints\n";
    } else {
        printSolution(state, inputs);
    }

    return hasSolution;
}

void FunctionChecker::concretizeMemory(S2EExecutionState *state, uint64_t address, int size) {
    for (unsigned i = 0; i < size; ++i) {
        uint8_t b = 0;
        if (!state->mem()->read<uint8_t>(address + i, &b, VirtualAddress, false)) {
            getWarningsStream(state) << "Can not concretize memory"
                                     << " at " << hexval(address + i) << '\n';
        } else {
            // read memory does not automatically overwrite the destination
            // address if we choose not to add the constraint, so we do it here
            if (!state->mem()->write(address + i, &b, sizeof(b))) {
                getWarningsStream(state) << "Can not write memory"
                                         << " at " << hexval(address + i) << '\n';
            }
        }
    }
}

void FunctionChecker::recordTargetArgs(S2EExecutionState *state, 
                                       targetFunctionDescriptor& descriptor) {
    for (auto &arg: descriptor.arguments) {
        switch (arg.type) {
            case INT_ARG: {
                klee::ref<klee::Expr> argExpr = 
                        state->regs()->read(CPU_OFFSET(regs[arg.reg]), arg.size * 8);
                arg.records.push_back(argExpr);
                getDebugStream(state) << "argument: "<< arg.name << " = "<< argExpr <<"\n";
                break;
            }
            case PTR_ARG:
                // not handled
                break;
            case FP_ARG:
                break; 
        } 
    }
}

void FunctionChecker::concretizeTargetArgs(S2EExecutionState *state, 
                                           targetFunctionDescriptor& descriptor) {
    for (auto &arg: descriptor.arguments) {
        switch (arg.type) {
            case INT_ARG: {
                // Test and concretize the argument if it is symbolic
                klee::ref<klee::Expr> argExpr = 
                        state->regs()->read(CPU_OFFSET(regs[arg.reg]), arg.size*8);
                if (argExpr->getKind() != klee::Expr::Constant) {
                    target_ulong argValue;
                    if (!state->regs()->read(CPU_OFFSET(regs[arg.reg]), &argValue, sizeof argValue, true))
                        getDebugStream(state) << "Failed to concretize argument " << arg.name << "\n";
                }
                break;
            } 
            case PTR_ARG:
                target_ulong address;
                state->regs()->read(CPU_OFFSET(regs[arg.reg]), &address, sizeof address, false);
                concretizeMemory(state, address, arg.size);
                break;
            case FP_ARG:
                break;
        }
    }
}

void FunctionChecker::entryFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns) {
    uint64_t eip = state->regs()->getPc(); 
    entryFunctionDescriptor descriptor = m_entryFunctionDescriptors[eip];
    getDebugStream(state) << "Entry function "<< descriptor.name 
                          << " @" << hexval(eip) <<" is called\n";
    //FUNCMON_REGISTER_RETURN(state, fns, FunctionChecker::entryFunctionReturn)
}

void FunctionChecker::targetFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns) {
    uint64_t eip = state->regs()->getPc(); 
    targetFunctionDescriptor descriptor = m_targetFunctionDescriptors[eip];
    getDebugStream(state) << "Target function "<< descriptor.name 
                          << " @" << hexval(eip) <<" is called\n";

    if (descriptor.recordArgs) {
        recordTargetArgs(state, descriptor);
    }

    if (descriptor.addConstraint && !addArgumentConstraint(state)) {
        return;
    }

    if (descriptor.printConstraint) {
        printConstraints(state);
    }

    if (descriptor.solveConstraint && getSolution(state)) {
        if (++m_solutionCounter == m_solutionNumber) {
            exit(0);
        }
    } 

    if (descriptor.concretizeArgs) {
        concretizeTargetArgs(state, descriptor);
    }

    //TODO: kill state/ kill state after x-th invocation
    //if (descriptor.callDepth > 0 && --descriptor.callDepth == 0)
    if (descriptor.terminateState) {
        std::stringstream ss;
        ss << "FunctionChecker: " << descriptor.name << ".terminateState = true";
        s2e()->getExecutor()->terminateStateEarly(*state, ss.str());
    }

    //FUNCMON_REGISTER_RETURN(state, fns, FunctionChecker::targetFunctionReturn)
}

/*
void FunctionChecker::entryFunctionReturn(S2EExecutionState *state) {
    getDebugStream(state) << "Entry function return\n";
    return;
}

void FunctionChecker::targetFunctionReturn(S2EExecutionState *state) {
    getDebugStream(state) << "Target function return\n";
    return;
}
*/

} // namespace plugins
} // namespace s2e
