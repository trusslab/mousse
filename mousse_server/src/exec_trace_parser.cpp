/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#include <fstream>
#include <iostream>
#include <vector>

struct header_t {
    uint64_t ts;
    uint32_t size;
    uint8_t type;
    uint32_t state_id;
    uint64_t pid;
} __attribute__((__packed__));

struct cache_trace_t {
    uint8_t type;
    uint8_t cacheId;
    uint64_t pc, address;
    uint8_t size;
    uint8_t isWrite, isCode, missCount;
} __attribute__((__packed__));

int main(int argc, char *argv[]) {
    std::ifstream ifs;
    ifs.open(argv[1], std::ios::binary);

    if (!ifs) {
        std::cout << "error opening file " << argv[1] << "\n";
        return -1;
    }

    uint64_t access = 0;
    uint64_t miss[3] = {0, 0, 0};

    header_t header;
    while (ifs.read((char *)&header, sizeof(header))) {
        std::vector<char> buffer;
        buffer.resize(header.size);
        ifs.read(buffer.data(), header.size);
//        std::cout << header.ts << " " << header.size << " " << (uint32_t)header.type << " " << header.state_id << " " << header.pid << ":\n ";

        access++;

        switch (header.type) {
            case 9: {
                cache_trace_t *ce = (cache_trace_t *)buffer.data();
//                std::cout << (uint32_t)ce->type << " " << (uint32_t)ce->cacheId
//                        << " 0x" << std::hex << ce->pc << " 0x" << ce->address
//                        << " " << std::dec << (uint32_t)ce->size << " " << (uint32_t)ce->isWrite << " " << (uint32_t)ce->isCode << " " << (uint32_t)ce->missCount << "\n";

                miss[ce->cacheId] += ce->missCount;

                } break;
            default:
                std::cout << "not supported yet\n";
                break;
        }
    }

    std::cout << "Access: " << access << "\n";
    std::cout << "Cache miss: " << miss[0] << " " << miss[1] << " " << miss[2] << "\n";

    ifs.close();
    return 0;
}
