/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef MOUSSE_BUG_LIST_H
#define MOUSSE_BUG_LIST_H

#include "mousse_common.h"

#include <vector>
#include <mutex>


typedef std::vector<cs_entry_t> call_stack;

class bug {
public:
    bug_t b;
    call_stack cs;
    size_t count;
    size_t id;

    bug(): count(0), id(0) {}

    bug(bug_t &_b, call_stack &_cs): b(_b), cs(_cs), count(0), id(0) {}

    bool operator==(const bug& rhs) const {
        if (b.type != rhs.b.type ||
            b.insn != rhs.b.insn ||
            b.addr != rhs.b.addr)
            return false;

        if (cs.size() != rhs.cs.size())
            return false;

        for (unsigned i = 0; i < cs.size(); i++)
            if (cs.at(i).addr != rhs.cs.at(i).addr)
                return false;

        return true;
    }

    bug& operator=(const bug& other) {
        b = other.b;
        cs = other.cs;
        return *this;
    }
};

class bug_list {
public:
    bug m_last_bug;
    std::vector<bug> m_list;
    std::mutex m_list_mutex;

    size_t size() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_list.size();
    }

    /* not thread safe*/
    std::vector<bug>::iterator begin() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_list.begin();
    }

    /* not thread safe*/
    std::vector<bug>::iterator end() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_list.end();
    }

    bug get(bug &b) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return *std::find(m_list.begin(), m_list.end(), b);
    }

    std::pair<size_t, size_t> get_id_count(const bug &b) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        std::vector<bug>::iterator bug_itr =
                std::find(m_list.begin(), m_list.end(), b);
        if (bug_itr != m_list.end()) {
            return std::make_pair(bug_itr->id, bug_itr->count);
        } else {
            return std::make_pair((size_t)-1, (size_t)-1);
        }
    }

    /* not thread safe*/
    std::vector<bug>::iterator find(bug &b) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return std::find(m_list.begin(), m_list.end(), b);
    }

    bool add(bug_t &b, call_stack &cs) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        bool duplicate = false;
        for (auto & it : m_list) {
            if (it == bug(b, cs)) {
                duplicate = true;
                it.count++;
                break;
            }
        }
        if (!duplicate) {
            m_list.push_back(bug(b, cs));
            m_list.back().id = m_list.size();
        }
        return !duplicate;
    }

    bool add(bug &b) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        m_last_bug = b;
        bool duplicate = false;
        for (auto & it : m_list) {
            if (it == b) {
                duplicate = true;
                m_last_bug.id = it.id;
                it.count++;
                break;
            }
        }
        if (!duplicate) {
            m_list.push_back(b);
            m_list.back().id = m_list.size();
            m_last_bug.id = m_list.size();
        }
        return !duplicate;
    }

};

#endif //MOUSSE_BUG_LIST_H
