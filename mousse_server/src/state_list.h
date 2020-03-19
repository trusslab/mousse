/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#ifndef MOUSSE_STATE_LIST_H
#define MOUSSE_STATE_LIST_H

#include "mousse_common.h"

#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>

std::string to_string_no_id(const state_t &state)
{
    std::stringstream ss;
    ss << state.ignore_depth;
    for (unsigned i = 0; i + 4 <= INPUT_BUF_SIZE; i += 4) {
        ss << " 0x" << std::hex << *(uint32_t *)&state.input_buf[i];
    }
    return ss.str();
}

std::string to_string(const state_t &state)
{
    std::stringstream ss;
    ss << THIS(state.id) << "\n" << state.ignore_depth;
    for (unsigned i = 0; i + 4 <= INPUT_BUF_SIZE; i += 4) {
        ss << " 0x" << std::hex << *(uint32_t *)&state.input_buf[i];
    }
    return ss.str();
}

state_t* new_state(uint32_t depth, uint32_t *inputs, int size)
{
    state_t *state = (state_t *)calloc(INPUT_BUF_SIZE+8, sizeof(uint8_t));
    if (!state) {
        return NULL;
    }

    unsigned i;
    for (i = 0; i+4 <= size; i+=4) {
        *(uint32_t *)&state->input_buf[i] = inputs[i/4];
    }
    if (i != 0) {
        unsigned start = i;
        for (; i < size; i++) {
            state->input_buf[i] = *((uint8_t *)inputs + i);
        }
    }

    state->ignore_depth = depth;
    return state;
}

class state_list {
public:
    size_t m_state_counter;
    size_t m_local_states;
    size_t m_added_states;
    size_t m_removed_states;
    std::deque<state_t> m_list;
    std::deque<state_t> m_sent_list;
    std::mutex m_list_mutex;
    std::mutex m_sent_list_mutex;

    state_list(): m_state_counter(0), m_added_states(0), m_removed_states(0) {}

    size_t num_added() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_added_states;
    }

    size_t num_removed() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_removed_states;
    }

    size_t num_remaining() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_list.size();
    }

    size_t num_total() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_state_counter;
    }

    size_t get_new_id() {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        return m_state_counter++;
    }

    void add(state_t &state) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        m_list.push_back(state);
        m_added_states++;
    }

    bool get_and_remove(state_t &state) {
        std::lock_guard<std::mutex> lock1(m_list_mutex);
        std::lock_guard<std::mutex> lock2(m_sent_list_mutex);
        if (m_list.empty()) {
            return false;
        } else {
            state = m_list.front();
            m_sent_list.push_back(state);
            m_list.pop_front();
            m_removed_states++;
            return true;
        }
    }

    bool get_sent_state(state_t &state, uint32_t id) {
        std::lock_guard<std::mutex> lock(m_sent_list_mutex);
        bool found = false;
        for (unsigned i = 0; i < m_sent_list.size(); i++) {
            if (m_sent_list.at(i).id == id) {
                state = m_sent_list.at(i);
                found = true;
                break;
            }
        }
        return found;
    }

    bool dump_to_file(const std::string &file) {
        std::lock_guard<std::mutex> lock(m_list_mutex);
        std::ofstream ofs(file);

        if (!ofs)
            return false;

        for (auto it : m_list) {
            ofs << to_string(it) << "\n";
        }

        ofs.close();
        return true;
    }

    int restore_from_file(const std::string &file) {
        uint32_t tmp_int;
        uint32_t state_id_max = 0;
        uint32_t state_added = 0;
        std::string tmp;
        std::ifstream ifs(file);

        if (!ifs) {
            return -1;
        }

        // Saved input file format
        // s1
        // d1 i11 i12 i13 ... i1n
        // s2
        // d2 i21 i22 i23
        // ...
        //
        // s: state id
        // d: depth of the input
        // i: 4-byte inputs
        while (true) {
            bool entry_is_valid = true;
            state_t *state = new_state(0, NULL, 0);
            if (ifs >> tmp_int) {
                state->id = tmp_int;
                if (tmp_int > state_id_max) {
                    state_id_max = tmp_int;
                }
            } else {
                free(state);
                break;
            }

            if (ifs >> tmp_int) {
                state->ignore_depth = tmp_int;
            } else {
                free(state);
                break;
            }

            for (unsigned i = 0; i < INPUT_BUF_SIZE/4; i++) {
                if (ifs >> tmp){
                    tmp_int = strtol(tmp.c_str(), NULL, 0);
                    *(uint32_t *)&state->input_buf[i*4] = tmp_int;
                } else {
                    entry_is_valid = false;
                    break;
                }
            }

            if (entry_is_valid) {
                state_added ++;
                add(*state);
            }
            free(state);
        }
        std::lock_guard<std::mutex> lock(m_sent_list_mutex);
        m_state_counter = state_id_max;

        ifs.close();
        return state_added;
    }

};

#endif //MOUSSE_STATE_LIST_H
