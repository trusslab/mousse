/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2017, Dependable Systems Laboratory, EPFL
 * Copyright (C) 2020, TrussLab@University of California, Irvine. Authors: Yingtong Liu 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef S2E_LINUX_MONITOR_H
#define S2E_LINUX_MONITOR_H

#include <s2e/s2earm.h>

#include "commands/linux.h"

static inline void s2e_linux_load_module(uint64_t pid, const char *name, const char *path,
                                         const struct S2E_LINUXMON_COMMAND_MODULE_LOAD *m) {
    struct S2E_LINUXMON_COMMAND cmd = {0};
    cmd.version = S2E_LINUXMON_COMMAND_VERSION;
    cmd.Command = LINUX_MODULE_LOAD;
    cmd.currentPid = pid;
    strncpy(cmd.currentName, name, sizeof(cmd.currentName));
    cmd.ModuleLoad = *m;

    s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

#endif
