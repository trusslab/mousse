/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef MOUSSE_COVERAGE_H
#define MOUSSE_COVERAGE_H
#include "mousse_common.h"

#include <algorithm>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <vector>

class translation_blocks;
class basic_blocks;

typedef std::unordered_map<std::string, translation_blocks> file_tbs_map;
typedef std::unordered_map<std::string, basic_blocks> file_bbs_map;

class code_block {
public:
    uint32_t start_pc;
    uint32_t last_pc;

    code_block(): start_pc(0), last_pc(0) {}

    code_block(uint32_t start, uint32_t last): start_pc(start), last_pc(last) {}

    bool operator<(const code_block &rhs) const {
        return start_pc < rhs.start_pc;
    }

    bool operator>(const code_block &rhs) const {
        return start_pc > rhs.start_pc;
    }

    bool operator==(const code_block &rhs) const {
        return (start_pc == rhs.start_pc && last_pc == rhs.last_pc);
    }

    bool operator!=(const code_block &rhs) const {
        return !(start_pc == rhs.start_pc && last_pc == rhs.last_pc);
    }
};

class translation_block : public code_block {
public:
    translation_block(tb_t &tb): code_block(tb.start_pc, tb.last_pc) {}

    translation_block(uint32_t start, uint32_t last)
        : code_block(start, last) {}
};

class translation_blocks {
public:
    std::vector<translation_block> m_tbs;
    std::mutex m_tbs_mutex;

    translation_blocks() {};

    void add(translation_block tb) {
        std::lock_guard<std::mutex> lock(m_tbs_mutex);
        auto it = std::lower_bound(m_tbs.begin(), m_tbs.end(),
                                   translation_block(tb.start_pc, tb.last_pc));
        if (it == m_tbs.end())
            m_tbs.push_back(tb);
        else
            m_tbs.insert(it, tb);
    }

    void add(translation_blocks &tbs) {
        std::lock_guard<std::mutex> lock(m_tbs_mutex);
        for (auto tb : tbs.m_tbs) {
            auto it = std::lower_bound(m_tbs.begin(), m_tbs.end(),
                                       translation_block(tb.start_pc, tb.last_pc));
            if (it == m_tbs.end())
                m_tbs.push_back(tb);
            else if (*it != tb)
                m_tbs.insert(it, tb);
        }
    }

};

class basic_block : public code_block {
public:
    bool covered;

    basic_block(): code_block(), covered(false) {}

    basic_block(uint32_t start, uint32_t last)
        : code_block(start, last), covered(false) {}
};

class basic_blocks {
public:
    std::string m_file_name;
    std::vector<basic_block> m_bbs;
    std::mutex m_bbs_mutex;

    basic_blocks() {}

    void initFromFile(const std::string &file) {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        std::ifstream ifs(file);

        if (!ifs)
            return;

        ifs >> m_file_name;
        basic_block bb;
        while (ifs >> bb.start_pc >> bb.last_pc)
            m_bbs.push_back(bb);

        ifs.close();
    }

    void updateCoverage(const std::string &file) {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        std::ifstream ifs(file);

        if (!ifs)
            return;

        ifs >> m_file_name;
        basic_block bb;
        while (ifs >> bb.start_pc >> bb.last_pc >> bb.covered) {
            auto it = std::lower_bound(m_bbs.begin(), m_bbs.end(), bb);
            if (it->start_pc == bb.start_pc && it->last_pc == bb.last_pc)
                it->covered = bb.covered;
        }

        ifs.close();
    }

    void updateCoverage(translation_blocks &tbs) {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        std::lock_guard<std::mutex> lock_tbs(tbs.m_tbs_mutex);
        for (auto tb : tbs.m_tbs) {
            auto it = std::lower_bound(m_bbs.begin(), m_bbs.end(),
                                       basic_block(tb.start_pc, tb.last_pc));
            for (; it != m_bbs.end(); it++) {
                if (it->start_pc >= tb.start_pc && it->last_pc <= tb.last_pc) {
                    it->covered = true;
                } else if (it->start_pc > tb.last_pc) {
                    break;
                }
            }
        }
    }

    void updateCoverage(const std::vector<translation_block> &tbs) {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        for (auto tb : tbs) {
            auto it = std::lower_bound(m_bbs.begin(), m_bbs.end(),
                                       basic_block(tb.start_pc, tb.last_pc));
            for (; it != m_bbs.end(); it++) {
                if (it->start_pc >= tb.start_pc && it->last_pc <= tb.last_pc) {
                    it->covered = true;
                } else if (it->start_pc > tb.last_pc) {
                    break;
                }
            }
        }
    }

    size_t getCoveredBlocks() {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        size_t covered_blocks = 0;
        for (auto it : m_bbs)
            if (it.covered)
                covered_blocks++;
        return covered_blocks;
    }

    double getCoverage() {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        double covered_blocks = 0;
        for (auto it : m_bbs)
            if (it.covered)
                covered_blocks++;
        return covered_blocks/m_bbs.size();
    }

    void dumpToFile(const std::string &file) {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        std::ofstream ofs;
        ofs.open(file);
        ofs << m_file_name << "\n";
        for (auto it : m_bbs)
            ofs << it.start_pc << " " << it.last_pc << " " << it.covered << "\n";

        ofs.close();
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(m_bbs_mutex);
        return m_bbs.size();
    }
};


#endif //MOUSSE_COVERAGE_H
