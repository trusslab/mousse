/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
///	Authors: Hsin-Wei Hung<hsinweih@uci.edu>
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_FUNCTIONCHECKER_H
#define S2E_PLUGINS_FUNCTIONCHECKER_H

#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <tr1/unordered_map>

namespace s2e {

struct ModuleDescriptor;

namespace plugins {

class FunctionMonitor;
class FunctionMonitorState;
class ModuleExecutionDetector;

/*
class argumentValue {
public:
    bool symbolic;
    klee::ref<klee::Expr>
}
*/

class FunctionChecker : public Plugin {
    S2E_PLUGIN
public:
    FunctionChecker(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void onTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state, 
                               TranslationBlock *tb, uint64_t pc);
    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor& module);

    void entryFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);
//    void entryFunctionReturn(S2EExecutionState *state);
    void targetFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);
//    void targetFunctionReturn(S2EExecutionState *state);

private:
    typedef std::vector<std::pair<std::string, std::vector<unsigned char>>> solution_t;
    typedef std::vector<klee::ref<klee::Expr> > targetFunctionRecords;

    enum argumentType {INT_ARG, PTR_ARG, FP_ARG};

    struct targetFunctionArg {
        std::string name;
        int type;
        int size;
        int reg; 
        targetFunctionRecords records;
    };

    typedef std::vector<targetFunctionArg> targetFunctionArgs;

    struct targetFunctionDescriptor {
        std::string name;
        //bool checkSymbolic;
        bool addConstraint;
        bool printConstraint;
        bool solveConstraint;
        bool terminateState;
        bool concretizeArgs;
        bool recordArgs;
        targetFunctionArgs arguments;
        //int callDepth;     //XXX stateful   
    };

    struct entryFunctionDescriptor {
        std::string name;
        //make arguments symbolic
    };    

    std::tr1::unordered_map<uint64_t, entryFunctionDescriptor> m_entryFunctionDescriptors; 
    std::tr1::unordered_map<uint64_t, targetFunctionDescriptor> m_targetFunctionDescriptors; 

    FunctionMonitor *m_functionMonitor;    
    ModuleExecutionDetector *m_moduleDetector;

    bool m_registered;
    bool m_userMode;
    //uint64_t m_functionAddress;
    ConfigFile::integer_list m_functionAddress;
    uint64_t m_functionArgument1;  
    int m_solutionNumber;   //XXX per function
    int m_solutionCounter;  //XXX per function

    int getArgumentType(std::string& type);
    int getArgumentReg(int type, int& intArgumentNum, int& fpArgumentNum);
    void registerCallSignalHandler(S2EExecutionState *state);
    bool assume(S2EExecutionState *state, klee::ref<klee::Expr> expr);
    bool addArgumentConstraint(S2EExecutionState *state);
    void printConstraints(S2EExecutionState *state);
    void printSolution(S2EExecutionState *state, solution_t solutions);
    bool getSolution(S2EExecutionState *state);
    void concretizeMemory(S2EExecutionState *state, uint64_t address, int size);
    void recordTargetArgs(S2EExecutionState *state, targetFunctionDescriptor& descriptor);
    void concretizeTargetArgs(S2EExecutionState *state, targetFunctionDescriptor& descriptor);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FUNCTIONCHECKER_H
