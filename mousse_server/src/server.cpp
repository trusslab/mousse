/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
* socket programming adopted from: https://www.geeksforgeeks.org/socket-programming-cc/
*/
#include "mousse_common.h"
#include "coverage.h"
#include "state_list.h"
#include "bug_list.h"
#include "fork_counter.h"
#include "statistics.h"

#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <experimental/filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <assert.h>

namespace fs = std::experimental::filesystem;

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define RESET "\033[0m"

#define DEFAULT_PORT 8080

//#define DEBUG_INFO
#ifdef DEBUG_INFO
#define DPRINTF(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...)
#endif

const char *config_file = "s2e-config.lua";
const char *state_log_file = "states.log";
const char *save_states_file = "remaining_states.log";
const char *load_states_file = "remaining_states.log";
const char *remaining_state_log_file = "remaining_states.log";

const char *target_work_dir;
static int port_num = DEFAULT_PORT;
static int input_num = 2;
static int input_size[2] = {4, 4};

std::mutex g_log_mutex;

state_list g_states;
state_list g_bug_inputs;
bug_list g_bugs;
fork_counter g_fork_counter;
file_bbs_map g_bbs_map;
file_tbs_map g_tbs_map;
statistics g_stat;
status_fsms g_status_fsms(&g_stat);

std::chrono::time_point<std::chrono::system_clock> g_start_time;


void print_state(state_t* state, int input_num, int *input_size)
{
    int i;
    int pos = 0;
    uint8_t *buf = &state->input_buf[0];
    printf("\t    ignore_depth = %d\n", state->ignore_depth);

    if (state->ignore_depth == 0) {
        printf("\t    inputs of initial state may not be used\n");
    }

    for (i = 0; i < input_num; i++) {
        if (input_size[i] == 1) {
            printf("\t    input[%d] = 0x%x\n", i, buf[pos]);
        } else if (input_size[i] == 4) {
            printf("\t    input[%d] = 0x%x\n", i, *(uint32_t *)(buf + pos));
        } else {
            printf("\t    unsupported size\n");
        }
        pos += input_size[i];
    }
}

int get_elapse_time()
{
    std::chrono::time_point<std::chrono::system_clock> current_time;
    current_time = std::chrono::system_clock::now();
    auto diff_time = current_time - g_start_time;
    return std::chrono::duration<double> (diff_time).count();
}

void write_log(std::string log_str, const char* file = NULL, int state_id = -1)
{
    std::stringstream ss;
    int t = get_elapse_time();

    if (state_id >= 0) {
        std::stringstream state;
        state << " state[" << state_id << "] ";
        ss << std::setw(6) << t << std::left << std::setw(12) << state.str()
                << log_str << "\n";
    } else {
        ss << std::setw(6) << t << " " << log_str << "\n";
    }

    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cout << ss.str();

    if (file) {
        std::ofstream ofs(file, std::ofstream::app);
        ofs << ss.str();
        ofs.close();
    }
    std::ofstream ofs("server.log", std::ofstream::app);
    ofs << ss.str();
    ofs.close();
}

void log_is_symbolic(const status_t &stat)
{
    std::stringstream ss;
    ss << "s2e_is_symbolic check succeeded";
    write_log(ss.str(), "symbolic.log", THIS(stat.state_id));
}

void log_syscall(sym_syscall_t &syscall)
{
    std::stringstream symbolic;
    if (syscall.symbolic & SYM_SYSCALL_PTR_ARG) {
        symbolic << "pointer to symbolic data";
    } else {
        for (unsigned i = 0; i < 8; i++)
            if (syscall.symbolic & (1 << i))
                symbolic << "r" << i << " ";
    }

    std::string fd;
    if (syscall.symbolic & SYM_SYSCALL_HAS_FD) {
        fd = std::string((char *)syscall.fd_name_buf);
    } else {
        fd = std::string("");
    }

    std::stringstream ss;
    ss << "syscall_" << syscall.num << "(" << fd
            << ") has symbolic arguments: " << symbolic.str();
    write_log(ss.str(), "symbolic.log", THIS(syscall.state_id));
}

void log_stat(const status_t &status)
{
    std::stringstream ss;
    if (status.status & STATUS_START) {
        char device_id[4];
        memcpy(device_id, &status.state_id, 4);
        ss << "status: device " << device_id << " started at t = " << status.duration;
        write_log(ss.str(), "status.log");
    } else if (status.status & STATUS_TEST) {
        ss << "status: test started at t = " << status.duration;
        write_log(ss.str(), "status.log", THIS(status.state_id));
    } else if (status.status & STATUS_TERM) {
        ss << "status: test terminated at t = " << status.duration << ", reason = " << std::hex << status.status;
        write_log(ss.str(), "status.log", THIS(status.state_id));
    }
}

void log_signal(const signal_t &sig)
{
    if (sig.signal != 15 && sig.signal != 12) {
        std::stringstream ss;
        ss << "got signal " << sig.signal;
        write_log(ss.str(), "stat.log", THIS(sig.state_id));
    }
}

void log_state(const char* file, const state_t &state)
{
    std::ofstream ofs(file, std::ofstream::app);

    if (!ofs) {
        fprintf(stderr, "Could not open state log %s", file);
        return;
    }

    std::lock_guard<std::mutex> lock(g_log_mutex);
    ofs << "\n" << to_string(state);

    ofs.close();
}

void send_reply(int sock_fd, uint32_t opc)
{
    send(sock_fd, &opc, OPC_SIZE, 0);
}

static void *receive_loop(void *sock)
{
    int size;
    int buf_size;
    uint32_t opcode;
    int new_socket = *(int *)sock;
    status_fsm *l_fsm = NULL;

    while (1) {
        DPRINTF("Waiting for a new request\n");

        size = read(new_socket, &opcode, OPC_SIZE);
        if (size == 0) {
            write_log("device disconnected");
            assert(l_fsm && "l_fsm should not be null");
            l_fsm->update(STATUS_REBOOT, get_elapse_time());
            write_log(g_stat.get_time());
            write_log(g_stat.get_unknown_time());
            close(new_socket);
            return NULL;
        } else if (size == -1) {
            std::stringstream ss;
            ss << "read from socket failed (reason: " << strerror(errno) << ")";
            write_log(ss.str());
            close(new_socket);
            return NULL;
        } else if (size != OPC_SIZE) {
            write_log("read from socket failed (reason: invalid opcode size)");
            close(new_socket);
            return NULL;
        }
        DPRINTF("Got opcode 0x%x\n", opcode);

        buf_size = OP_BUF_SIZE(opcode);
        DPRINTF("buf size = 0x%x\n", buf_size);
        switch(opcode) {
            case OPC_R_GET_STATE_ID:
            {
                state_t state;
                state.id = g_states.get_new_id();
                uint32_t reply = OPC_REPLY_SUCCESS;
                send(new_socket, &reply, 4, 0);
                send(new_socket, &state, buf_size, 0);
                DPRINTF("state id sent\n");
                break;
            }
            case OPC_R_GET_STATE:
            {
                state_t state;
                if (!g_states.get_and_remove(state)) {
                    DPRINTF("Got no state to send\n");
                    uint32_t reply = OPC_REPLY_FAILURE;
                    send(new_socket, &reply, 4, 0);
                    continue;
                }
                std::stringstream ss;
                ss << KGRN << "send state[" << THIS(state.id) << "]" << RESET;
                write_log(ss.str());
                print_state(&state, input_num, input_size);

                uint32_t reply = OPC_REPLY_SUCCESS;
                send(new_socket, &reply, 4, 0);
                send(new_socket, &state, buf_size, 0);
                DPRINTF("state sent\n");
                break;
            }
            case OPC_R_GET_FORK_COUNTERS:
            {
                fork_counters_t fork_counters = g_fork_counter.get();
                uint32_t reply = OPC_REPLY_SUCCESS;
                send(new_socket, &reply, 4, 0);
                send(new_socket, &fork_counters, buf_size, 0);
                DPRINTF("fork counters sent\n");
                break;
            }
            case OPC_W_OFFLOAD_STATE:
            {
                state_t state;
                read(new_socket, &state, buf_size);
                g_states.add(state);
                log_state(state_log_file, state);
                std::stringstream ss;
                ss << KRED << "receive state[" << THIS(state.id) << "]" << RESET;
                write_log(ss.str());
                print_state(&state, input_num, input_size);
                break;
            }
            case OPC_W_TEMP_FORK_STATE:
            {
                state_t state;
                read(new_socket, &state, buf_size);
                std::stringstream ss;
                ss << "new state[" << THIS(state.id) << "]: forked from state["
                        << FROM(state.id) << "] temporarily";
                write_log(ss.str());
                break;
            }
            case OPC_W_FORK_STATE:
            {
                state_t state;
                read(new_socket, &state, buf_size);
                //g_states.add(state);
                log_state(state_log_file, state);
                std::stringstream ss;
                ss << "new state[" << THIS(state.id) << "]: forked from state["
                        << FROM(state.id) << "] and executed locally";
                write_log(ss.str());
                print_state(&state, input_num, input_size);
                break;
            }
            case OPC_W_BUG:
            {
                bug_t b;
                read(new_socket, &b, buf_size);
                call_stack cs;
                for (unsigned i = 0; i < b.cs_size; i++) {
                    cs_entry_t cs_entry;
                    read(new_socket, &cs_entry, sizeof(cs_entry_t));
                    cs.push_back(cs_entry);
                }
                call_stack cs2;
                for (unsigned i = 0; i < b.cs2_size; i++) {
                    cs_entry_t cs_entry;
                    read(new_socket, &cs_entry, sizeof(cs_entry_t));
                    cs2.push_back(cs_entry);
                }
                bug new_bug(b, cs);
                bool is_new_bug = g_bugs.add(new_bug);
                //new_bug = g_bugs.get(new_bug);
                std::pair<size_t, size_t> id_count = g_bugs.get_id_count(new_bug);
                std::stringstream ss;
                ss << "bug#" << id_count.first//new_bug.id
                        << ", count = " << id_count.second//new_bug.count
                        << ", type = 0x" << std::hex << new_bug.b.type
                        << ", insn = 0x" << std::hex << new_bug.b.insn
                        << ", addr = 0x" << std::hex << new_bug.b.addr
                        << ", file = " << (char *)new_bug.b.binary_name_buf;
                if (is_new_bug) {
                    ss << "\n";
                    for (auto cs_e : cs) {
                        ss << std::setw(20) << "0x" << std::hex << std::setfill('0')
                                << std::setw(8) << cs_e.addr << std::setfill(' ')
                                << " " << (char *)cs_e.binary_name_buf << "\n";
                    }
                    ss << "\n";
                    for (auto cs_e : cs2) {
                        ss << std::setw(20) << "0x" << std::hex << std::setfill('0')
                                << std::setw(8) << cs_e.addr << std::setfill(' ')
                                << " " << (char *)cs_e.binary_name_buf << "\n";
                    }
                }
                write_log(ss.str(), "bug.log", THIS(b.state_id));
                break;
            }
            case OPC_W_BUG_INPUTS:
            {
                state_t state;
                read(new_socket, &state, buf_size);
                g_bug_inputs.add(state);
                log_state("bug.log", state);
                std::stringstream ss;
                ss << "receive bug inputs from state[" << THIS(state.id) << "]";
                write_log(ss.str(), "bug.log");
                print_state(&state, input_num, input_size);
                break;
            }
            case OPC_W_SYSCALL:
            {
                sym_syscall_t syscall;
                read(new_socket, &syscall, buf_size);
                log_syscall(syscall);
                break;
            }
            case OPC_W_STATUS:
            {
                status_t status;
                read(new_socket, &status, buf_size);
                if (status.status == STATUS_START)
                    l_fsm = g_status_fsms.get_fsm(status.state_id);
                l_fsm->update(status.status, get_elapse_time());
                log_stat(status);
                break;
            }
            case OPC_W_IS_SYMBOLIC:
            {
                status_t status;
                read(new_socket, &status, buf_size);
                log_is_symbolic(status);
                break;
            }
            case OPC_W_TBS_HEADER:
            {
                tbs_header_t tbs_header;
                file_tbs_map tbs_map;
                bool connection_error = false;
                read(new_socket, &tbs_header, buf_size);
                DPRINTF("receive %d tbs from state[%d]\n", tbs_header.size, tbs_header.state_id);

                std::stringstream ss;
                ss << "coverage:\n";
                for (unsigned i = 0; i < tbs_header.size; i++) {

                    tb_header_t tb_header;
                    read(new_socket, &tb_header, sizeof(tb_header_t));
                    std::string tbs_path((char *)tb_header.binary_name_buf);
                    std::string tbs_file = tbs_path.substr(tbs_path.rfind('/')+1);
                    DPRINTF("receive %d tbs of %s\n", tb_header.size, tbs_path.c_str());
                    DPRINTF("tbs_file = %s\n", tbs_file.c_str());

                    for (unsigned j = 0; j < BIN_NAME_BUF_SIZE; j++) {
                        char name_char = tb_header.binary_name_buf[j];
                        if (!isprint(name_char) && name_char != '\0') {
                            connection_error = true;
                            break;
                        }
                    }

                    if (tb_header.size > 10000) {
                        connection_error = true;
                    }

                    translation_blocks tbs;
                    for (unsigned j = 0; j < tb_header.size; j++) {
                        tb_t tb;
                        read(new_socket, &tb, sizeof(tb_t));
                        tbs.add(translation_block(tb));
                    }

                    tbs_map[tbs_path].add(tbs);
                }

                if (!connection_error) {
                    for (auto & it : tbs_map) {
                        std::string tbs_file = it.first.substr(it.first.rfind('/')+1);
                        if (g_bbs_map.find(tbs_file) != g_bbs_map.end()) {
                            g_bbs_map[tbs_file].updateCoverage(it.second);
                            ss << std::fixed << std::setprecision(2) << std::setw(6)
                                    << g_bbs_map[tbs_file].getCoverage()*100 << "% "
                                    << " (" << g_bbs_map[tbs_file].getCoveredBlocks() << ") " << tbs_file << "\n";
                        }
                    }
                } else {
                    ss << "connection error. not updating coverge!";
                }
                write_log(ss.str(), "coverage.log", THIS(tbs_header.state_id));
                break;
            }
            case OPC_W_GOT_SIGNAL:
            {
                signal_t sig;
                read(new_socket, &sig, buf_size);
                log_signal(sig);
                if (sig.signal == 11) {
                    state_t state;
                    if (g_states.get_sent_state(state, sig.state_id)) {
                        g_states.add(state);
                        std::stringstream ss;
                        ss << "add state[" << THIS(state.id) << "] back due to signal 11";
                        write_log(ss.str());
                    }
                }
                break;
            }
            case OPC_W_UPDATE_FORK_COUNTERS:
            {
                fork_counters_t fork_counters;
                read(new_socket, &fork_counters, buf_size);
                g_fork_counter.update(fork_counters);
                break;
            }
            case OPC_Q_INC_AND_GET_FORK_COUNTER:
            {
                uint32_t counter;
                uint64_t hash;
                read(new_socket, &hash, 8);
                counter = g_fork_counter.inc_and_get(hash);
                send(new_socket, &counter, buf_size, 0);
                break;
            }
            default:
                std::stringstream ss;
                ss << "Unknown opcode 0x" << std::hex << opcode;
                write_log(ss.str());
                close(new_socket);
                return NULL;
        }
    }

    close(new_socket);
    return NULL;
}

static int listen_for_connections()
{
    int new_socket;
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    pthread_t thread;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        write_log("failed to create a socket file descriptor");
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        write_log("failed to set sock opt");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port_num);

    if (bind(server_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        std::stringstream ss;
        ss << "failed to bind socket (reason: " << strerror(errno) << ")";
        write_log(ss.str());
        return -1;
    }

    if (listen(server_fd, 3) < 0) {
        write_log("failed to listen to socket");
        return -1;
    }

    while (1) {
        DPRINTF("Waiting for a new connection\n");

        if ((new_socket = accept(server_fd, (struct sockaddr *) &address,
                                 (socklen_t*) &addrlen)) < 0) {
            write_log("failed to accept socket connection");
            return -1;
        }

        DPRINTF("connection established\n");

        if (pthread_create(&thread, NULL, receive_loop, &new_socket)) {
            write_log("failed to create a new thread");
            return -1;
        }
    }

    return 0;
}

std::vector<std::string> get_files_with_ext(const std::string &directory,
                                            const std::string &extension)
{
    std::vector<std::string> path_list;
    for(auto & f: fs::directory_iterator(directory)) {
        std::stringstream ss;
        std::string path;

        ss << f;
        path = ss.str();
        path.erase(0, 1);
        path.pop_back();

        size_t ext_begin = path.rfind('.') + 1;
        if (path.substr(ext_begin).compare(extension) == 0)
            path_list.push_back(path);
    }
    return path_list;
}

std::string path_to_file_wo_ext(const std::string &path)
{
    size_t ext_begin = path.rfind('.') + 1;
    size_t file_begin = path.rfind('/') + 1;
    return path.substr(file_begin, ext_begin - file_begin - 1);
}

void read_bbs(const std::string &target_work_dir)
{
    std::string bbsDir = target_work_dir + "/basic_blocks";
    std::vector<std::string> bbs_list = get_files_with_ext(bbsDir, "bbs");
    for(auto & path: bbs_list) {
        std::stringstream ss;
        std::string file = path_to_file_wo_ext(path);
        g_bbs_map[file].initFromFile(path);
        ss << "read " << g_bbs_map[file].size() << " basic blocks of "
                << file << " from " << path;
        write_log(ss.str());
    }

    std::vector<std::string> bbsc_list = get_files_with_ext(bbsDir, "bbsc");
    for(auto & path: bbsc_list) {
        std::stringstream ss;
        std::string file = path_to_file_wo_ext(path);
        g_bbs_map[file].updateCoverage(path);
        ss << "update " << g_bbs_map[file].size() << " basic blocks of "
                << file << " from " << path;
        write_log(ss.str());
    }
}

void read_config(const char* file)
{
    std::string line;
    std::ifstream ifs(file);

    if (!ifs) {
        std::cerr << "Could not open config file " << file << "\n";
        exit(1);
    }

    std::regex port_num_regex("^[\t ]*portNum[\t ]*=[\t ]*[0-9]*[\t ]*,");
    while (std::getline(ifs, line)) {
        std::smatch port_match;
        if (std::regex_search(line, port_match, port_num_regex)) {
            sscanf(line.c_str(), "%*[^0123456789]%d", &port_num);
        }
    }

    ifs.close();
}

void finalize(int s)
{
    write_log("server killed. save coverage and remaining states");
    for (auto & it : g_bbs_map) {
        std::string file = it.first + std::string(".bbsc");
        it.second.dumpToFile(file);
    }

    g_states.dump_to_file(save_states_file);

    exit(1);
}

int main(int argc, char const *argv[])
{
    g_start_time = std::chrono::system_clock::now();

    struct sigaction int_action;
    int_action.sa_handler = finalize;
    sigemptyset(&int_action.sa_mask);
    int_action.sa_flags = 0;
    sigaction(SIGINT, &int_action, NULL);

    if (argc == 3 ) {
        std::string arg = argv[1];
        try {
            std::size_t pos;
            port_num = std::stoi(arg, &pos);
            if (pos < arg.size()) {
                printf("trailing characters after <port_num>: %d\n", port_num);
                exit(1);
            }
            if (port_num >= 65536) {
                printf("<port_num> out of range: %d\n", port_num);
                exit(1);
            }
        } catch (std::invalid_argument const &e) {
            printf("invalid <port_num>: %d\n", port_num);
            exit(1);
        } catch (std::out_of_range const &e) {
            printf("<port_num> out of range: %d\n", port_num);
            exit(1);
        }
        target_work_dir = argv[2];
    } else if (argc == 2){
        read_config(config_file);
        target_work_dir = argv[1];
    } else {
       printf("invalid number of args\n");
       exit(1);
    }
    read_bbs(target_work_dir);

    write_log("using port " + std::to_string(port_num));

    int num = g_states.restore_from_file(load_states_file);
    if (num > 0) {
        std::stringstream ss;
        ss << num << " states restored from " << load_states_file;
        write_log(ss.str());
    } else {
        // initial state
        // (input_buf will not be used by mousse under legacy mode)
        state_t *state = new_state(0, NULL, 0);
        state->id = g_states.get_new_id();
        g_states.add(*state);
    }

    if (listen_for_connections() != 0) {
        printf("listen_for_connections() failed\n");
        return -1;
    }

    return 0;
}
