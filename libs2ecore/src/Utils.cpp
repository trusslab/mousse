///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2020, TrussLab@University of California, Irvine.
/// 	Authors: Yingtong Liu <yingtong@uci.edu> 
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#if defined(CONFIG_WIN32)
static void print_stacktrace(const char *reason) {
    std::ostream &os = g_s2e->getDebugStream();
    os << "Stack trace printing unsupported on Windows" << '\n';
}
#else
#include <cxxabi.h>
#include <llvm/Support/raw_ostream.h>
#include <s2e/S2E.h>
#include <s2e/s2e_libcpu.h>
#include <stdio.h>
#include <stdlib.h>

// stacktrace.h (c) 2008, Timo Bingmann from http://idlebox.net/
// published under the WTFPL v2.0

/** Print a demangled stack backtrace of the caller function to FILE* out. */
void print_stacktrace(void (*print_func)(const char *fmt, ...), const char *reason) {
    fprintf(stderr, "%s not implemented in Mousse\n",__func__);
}
#endif // CONFIG_WIN32

namespace s2e {

std::string compress_file(const std::string &path) {
    // Simply call the system's gzip.
    std::stringstream ss;
    ss << "gzip \"" << path << "\"";
    int sret = system(ss.str().c_str());
    if (sret == -1) {
        return path;
    }

    // Check that the file was compressed
    llvm::SmallString<128> compressed(path);
    llvm::sys::path::replace_extension(compressed, "gz");

    if (llvm::sys::fs::exists(compressed)) {
        unlink(path.c_str());
        return compressed.c_str();
    }

    return path;
}
}
