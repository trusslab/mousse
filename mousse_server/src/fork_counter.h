/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef MOUSSE_FORK_COUNTER_H
#define MOUSSE_FORK_COUNTER_H

#include "mousse_common.h"

#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <stdio.h>

class fork_counter {
    std::mutex m_counter_mutex;
    std::unordered_map<uint64_t, uint32_t> m_counter;

public:
    fork_counters_t get() {
        std::lock_guard<std::mutex> lock(m_counter_mutex);
        fork_counters_t counters;
        unsigned i = 0;
        for (auto it : m_counter) {
            counters.counter[i].hash = it.first;
            counters.counter[i].count = it.second;
            i++;
        }
        return counters;
    }

    uint32_t inc_and_get(uint64_t hash) {
        std::lock_guard<std::mutex> lock(m_counter_mutex);
        uint32_t counter;
        auto it = m_counter.find(hash);
        if (it == m_counter.end()) {
            m_counter[hash] = 1;
            counter = 1;
        } else {
            counter = ++m_counter[hash];
        }
        //printf("inc_and_get(0x%lx) counter = %u\n", hash, counter);
        return counter;
    }

    void update(const fork_counters_t &fork_counters) {
        std::lock_guard<std::mutex> lock(m_counter_mutex);
        for (unsigned i = 0; i < FORK_COUNTERS_SIZE; i++) {
            const fork_counter_t *fork_counter = &fork_counters.counter[i];
            if (fork_counter->hash != 0) {
                if (m_counter.find(fork_counter->hash) != m_counter.end()) {
                    m_counter[fork_counter->hash] += fork_counter->count;
                } else {
                    m_counter[fork_counter->hash] = fork_counter->count;
                }
            } else {
                break;
            }
        }
    }

};

#endif // MOUSSE_FORK_COUNTER_H
