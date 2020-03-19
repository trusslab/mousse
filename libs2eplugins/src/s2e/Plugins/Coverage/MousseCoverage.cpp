///
/// Copyright (C) 2016, Cyberhaven
/// Copyright (C) 2020, TrussLab@University of California, Irvine. 
///     Authors: Hsin-Wei Hung<hsinweih@uci.edu>
///
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "MousseCoverage.h"
#include "../DistributedExecution/mousse_common.h"

#include <s2e/cpu.h>

extern "C" {
#include "qdict.h"
#include "qint.h"
#include "qjson.h"
#include "qlist.h"
}

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <cstring>

namespace s2e {
namespace plugins {
namespace moussecoverage {

S2E_DEFINE_PLUGIN(MousseCoverage, "MousseCoverage plugin", "");

namespace {

struct TBCoverageState : public PluginState {
    ModuleTBs coverage;

    static PluginState *factory(Plugin *p, S2EExecutionState *) {
        return new TBCoverageState();
    }

    virtual TBCoverageState *clone() const {
        return new TBCoverageState(*this);
    }
};
}

void MousseCoverage::initialize()
{
    m_distributedExecution = s2e()->getPlugin<DistributedExecution>();

    m_processMonitor = s2e()->getPlugin<ProcessMonitor>();

    auto cfg = s2e()->getConfig();

    // This is mainly for debugging, in normal use would generate too many files
    bool writeCoverageOnStateKill = cfg->getBool(getConfigKey() + ".sendCoverageOnStateKill");
    if (writeCoverageOnStateKill) {
        m_distributedExecution->onDistributedStateKill.connect(
                sigc::mem_fun(*this, &MousseCoverage::onStateKill));
    }

    s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &MousseCoverage::onTranslateBlockComplete));

    m_timerTicks = 0;
}

void MousseCoverage::onTranslateBlockComplete(S2EExecutionState *state,
        TranslationBlock *tb, uint64_t last_pc)
{
    uint64_t startPc;
    std::string file = m_processMonitor->getFileName(tb->pc, startPc);
    uint64_t lastPc;
    m_processMonitor->getFileName(last_pc, lastPc);

    TB ntb;
    ntb.startPc = startPc;
    ntb.lastPc = lastPc;
    ntb.size = tb->size;

    DECLARE_PLUGINSTATE(TBCoverageState, state);
    auto &tbs = plgState->coverage[file];
    auto newTbs = tbs.insert(ntb);
    plgState->coverage[file] = newTbs;
}

void MousseCoverage::onModuleTranslateBlockComplete(S2EExecutionState *state,
        const ModuleDescriptor &module, TranslationBlock *tb, uint64_t last_pc)
{
    TB ntb;
    ntb.startPc = module.ToNativeBase(tb->pc);
    ntb.lastPc = module.ToNativeBase(last_pc);
    ntb.startOffset = ntb.startPc - module.NativeBase;
    ntb.size = tb->size;

    DECLARE_PLUGINSTATE(TBCoverageState, state);
    auto &tbs = plgState->coverage[module.Name];
    auto newTbs = tbs.insert(ntb);
    plgState->coverage[module.Name] = newTbs;

    // Also save aggregated coverage info
    // and keep track of the states that discovered
    // new blocks so that it is easier to retrieve
    // them, e.g., every few minutes.
    bool newBlock = false;
    auto mit = m_localCoverage.find(module.Name);
    if (mit == m_localCoverage.end()) {
        newBlock = true;
    } else {
        newBlock = (*mit).second.count(ntb) == 0;
    }

    unsigned moduleidx;
    bool wasCovered = false;
    if (m_detector->getModuleId(module, &moduleidx)) {
        Bitmap *bmp = m_globalCoverage.acquire();
        bmp->setCovered(moduleidx, ntb.startOffset, ntb.size, wasCovered);
        m_globalCoverage.release();
    }

    if (newBlock) {
        m_localCoverage[module.Name].insert(ntb);
        m_newBlockStates.insert(state);
        if (!wasCovered) {
            onNewBlockCovered.emit(state);
        }
    }
}

void MousseCoverage::onUpdateStates(S2EExecutionState *currentState,
        const klee::StateSet &addedStates, const klee::StateSet &removedStates)
{
    for (auto it : removedStates) {
        m_newBlockStates.erase(it);
    }
}

void MousseCoverage::sendCoverageToServer(S2EExecutionState *state, int stateId)
{
    getWarningsStream(state) << "sending coverage to the server\n";
    DECLARE_PLUGINSTATE(TBCoverageState, state);

    int coverage_tbs_num = 0;
    size_t coverage_buf_size = sizeof(tbs_header_t);
    for (auto tbs : plgState->coverage) {
        coverage_buf_size += sizeof(tb_header_t) + tbs.second.size() * sizeof(tb_t);
        coverage_tbs_num++;
    }
    char *coverage_buf = (char *)malloc(coverage_buf_size);
    memset(coverage_buf, 0, coverage_buf_size);

    tbs_header_t *tbs_header = (tbs_header_t *)coverage_buf;
    tbs_header->state_id = stateId;
    tbs_header->size = coverage_tbs_num;
    size_t offset = sizeof(tbs_header_t);

    for (auto tbs : plgState->coverage) {
        tb_header_t *tb_header = (tb_header_t *)(coverage_buf + offset);
        tb_header->size = tbs.second.size();
        strcpy((char *)tb_header->binary_name_buf, tbs.first.c_str());
        offset += sizeof(tb_header_t);

        for (auto it : tbs.second) {
            tb_t *tb = (tb_t *)(coverage_buf + offset);
            tb->start_pc = it.startPc;
            tb->last_pc = it.lastPc;
            offset += sizeof(tb_t);
        }

        getWarningsStream(state) << tbs.first << " " << tbs.second.size() << "\n";
    }

    g_s2e->sendDataToServer(OPC_W_TBS_HEADER, coverage_buf, coverage_buf_size);
    free(coverage_buf);
    getWarningsStream(state) << "finish sending coverage to the server\n";
}

void MousseCoverage::onStateKill(S2EExecutionState *state, int stateId)
{
//    generateJsonCoverageFile(state);
    sendCoverageToServer(state, stateId);
}

// Periodically write the translation block coverage to the JSON file. This is for the case when a state never
//  terminates, we still get some coverage information
void MousseCoverage::onTimer()
{
    ++m_timerTicks;

    if (m_timerTicks < m_writeCoveragePeriod) {
        return;
    }

    m_timerTicks = 0;
    generateJsonCoverageFile(g_s2e_state);
}

const ModuleTBs &MousseCoverage::getCoverage(S2EExecutionState *state)
{
    DECLARE_PLUGINSTATE(TBCoverageState, state);
    return plgState->coverage;
}

std::string MousseCoverage::generateJsonCoverageFile(S2EExecutionState *state)
{
    std::string path;

    std::stringstream fileName;
    fileName << "tbcoverage-" << state->getID() << ".json";
    path = s2e()->getOutputFilename(fileName.str());

    generateJsonCoverageFile(state, path);

    return path;
}

void MousseCoverage::generateJsonCoverageFile(S2EExecutionState *state, const std::string &path)
{
    std::stringstream coverage;
    generateJsonCoverage(state, coverage);

    std::ofstream o(path.c_str());
    o << coverage.str();
    o.close();
}

void MousseCoverage::generateJsonCoverage(S2EExecutionState *state, std::stringstream &coverage)
{
    QDict *pt = qdict_new();

    const ModuleTBs &tbs = getCoverage(state);
    for (auto module : tbs) {
        QList *blocks = qlist_new();
        for (auto &tb : module.second) {

            QList *info = qlist_new();
            qlist_append_obj(info, QOBJECT(qint_from_int(tb.startPc)));
            qlist_append_obj(info, QOBJECT(qint_from_int(tb.lastPc)));
            qlist_append_obj(info, QOBJECT(qint_from_int(tb.size)));

            qlist_append_obj(blocks, QOBJECT(info));
        }

        qdict_put_obj(pt, module.first.c_str(), QOBJECT(blocks));
    }

    QString *json = qobject_to_json(QOBJECT(pt));

    coverage << qstring_get_str(json) << "\n";

    QDECREF(json);
    QDECREF(pt);
}

bool mergeCoverage(ModuleTBs &dest, const ModuleTBs &source)
{
    bool ret = false;

    for (const auto it : source) {
        const std::string &mod = it.first;
        const auto tbs = it.second;
        if (dest.count(mod) == 0) {
            ret = true;
        }

        unsigned prevCount = dest[mod].size();
        for (const auto &tb : tbs) {
            dest[mod] = dest[mod].insert(tb);
        }

        if (prevCount < dest[mod].size()) {
            ret = true;
        }
    }

    return ret;
}

} // namespace coverage
} // namespace plugins
} // namespace s2e
