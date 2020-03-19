/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef MOUSSE_STAT_H
#define MOUSSE_STAT_H

#include <cstdint>
#include <iostream>
#include <mutex>

class statistics {
    std::mutex m_mutex;
    uint64_t m_reboot_time;
    uint64_t m_init_time;
    uint64_t m_test_time;
    std::unordered_map<uint64_t, uint64_t> m_unknown_time;

public:
    void add_reboot_time(uint64_t t) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_reboot_time += t;
    }

    void add_init_time(uint64_t t) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_init_time += t;
    }

    void add_test_time(uint64_t t) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_test_time += t;
    }

    void add_unknown_time(uint32_t cur_state, uint32_t new_state, uint64_t t) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_unknown_time[((uint64_t)cur_state | ((uint64_t)new_state << 32))] += t;
    }

    std::string get_time() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::stringstream ss;
        ss << "reboot:" << m_reboot_time << " init:" << m_init_time << " test:" << m_test_time;
        return ss.str();
    }

    std::string get_unknown_time() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::stringstream ss;
        for (auto it : m_unknown_time) {
            ss << "0x" << std::hex << (it.first & 0xffff) << "->"
                    << "0x" << std::hex << (it.first >> 32) << ":" << it.second << " ";
        }
        return ss.str();
    }

};

class status_fsm {
    uint32_t m_fsm_state;
    int m_time_stamp;
    statistics *stat;

public:
    status_fsm(statistics* s, int t): m_fsm_state(STATUS_REBOOT), stat(s), m_time_stamp(t) {}

    inline void goto_state(uint32_t new_fsm_state, int time_stamp) {
//        std::cerr << "goto_state 0x" << std::hex << m_fsm_state << "->"
//                << "0x" << std::hex << new_fsm_state
//                << " t:" << std::dec << m_time_stamp << "->" << time_stamp << "\n";
        m_time_stamp = time_stamp;
        m_fsm_state = new_fsm_state;
    }

    void update(uint32_t new_fsm_state, int time_stamp) {
        uint32_t cur_state = m_fsm_state & STATUS_MASK;
        uint32_t new_state = new_fsm_state & STATUS_MASK;
        uint64_t inc_time = time_stamp - m_time_stamp;
        switch (cur_state) {
            case STATUS_REBOOT:
                if (new_state == STATUS_START) {
                    stat->add_reboot_time(inc_time);
                } else {
                    stat->add_unknown_time(cur_state, new_state, inc_time);
                }
                break;
            case STATUS_START:
                if (new_state == STATUS_TEST) {
                    stat->add_init_time(inc_time);
                } else if (new_state == STATUS_REBOOT) {
                    stat->add_unknown_time(cur_state, new_state, inc_time);
                } else {
                    stat->add_unknown_time(cur_state, new_state, inc_time);
                }
                break;
            case STATUS_TEST:
                if (new_state == STATUS_TERM) {
                    stat->add_test_time(inc_time);
                } else if (new_state == STATUS_REBOOT) {
                    stat->add_test_time(inc_time);
                } else {
                    stat->add_unknown_time(cur_state, new_state, inc_time);
                }
                break;
            case STATUS_TERM:
                if (new_state == STATUS_TERM) {
                    stat->add_test_time(inc_time);
                } else if (new_state == STATUS_REBOOT) {
                    stat->add_reboot_time(inc_time);
                } else {
                    stat->add_unknown_time(cur_state, new_state, inc_time);
                }
                break;
            default:
                std::cerr << "invalid fsm_state " << new_fsm_state << "\n";
        }
        goto_state(new_fsm_state, time_stamp);
    }
};

class status_fsms {
    std::mutex m_mutex;
    std::unordered_map<uint32_t, status_fsm*> m_fsms;
    statistics* stat;

public:
    status_fsms(statistics* s): stat(s) {}

    status_fsm* get_fsm(uint32_t device_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_fsms.find(device_id) == m_fsms.end()) {
            m_fsms[device_id] = new status_fsm(stat, 0);
        }
        return m_fsms[device_id];
    }
};

#endif // MOUSSE_STAT_H
