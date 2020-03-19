/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *  Authors: Ardalan Amiri Sani<ardalan@uci.edu>
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details..
*/
#ifndef KLEE_EXPRDESERIALIZER_H
#define KLEE_EXPRDESERIALIZER_H

#include "klee/Expr.h"
#include <klee/util/Assignment.h>
#include <klee/AddressSpace.h>

namespace klee {

class concolicData {
public:
    int size;
    int value; /* support 32-bit argument only*/
    std::string name;
    concolicData() {};
    concolicData(int s, int v, std::string nm): size(s), value(v), name(nm) {};
};

class ExprDeserializer {
protected:
    /* Duplicate with the one in the serializer */
    enum exprCode {
        CONSTANT_CODE = 0,
        NOTOPTIMIZED_CODE = 1,
        READ_CODE = 2,
        SELECT_CODE = 3,
        CONCAT_CODE = 4,
        EXTRACT_CODE = 5,
        ZEXT_CODE = 6,
        SEXT_CODE = 7,
        ADD_CODE = 8,
        SUB_CODE = 9,
        MUL_CODE = 10,
        UDIV_CODE = 11,
        SDIV_CODE = 12,
        UREM_CODE = 13,
        SREM_CODE = 14,
        NOT_CODE = 15,
        AND_CODE = 16,
        OR_CODE = 17,
        XOR_CODE = 18,
        SHL_CODE = 19,
        LSHR_CODE = 20,
        ASHR_CODE = 21,
        EQ_CODE = 22,
        NE_CODE = 23,
        ULT_CODE = 24,
        ULE_CODE = 25,
        UGT_CODE = 26,
        UGE_CODE = 27,
        SLT_CODE = 28,
        SLE_CODE = 29,
        SGT_CODE = 30,
        SGE_CODE = 31
    };

    ref<Expr> visitConstant(uint64_t);
    ref<Expr> visitNotOptimized(uint64_t);
    ref<Expr> visitRead(uint64_t);
    ref<Expr> visitSelect(uint64_t);
    ref<Expr> visitConcat(uint64_t);
    ref<Expr> visitExtract(uint64_t);
    ref<Expr> visitZExt(uint64_t);
    ref<Expr> visitSExt(uint64_t);
    ref<Expr> visitAdd(uint64_t);
    ref<Expr> visitSub(uint64_t);
    ref<Expr> visitMul(uint64_t);
    ref<Expr> visitUDiv(uint64_t);
    ref<Expr> visitSDiv(uint64_t);
    ref<Expr> visitURem(uint64_t);
    ref<Expr> visitSRem(uint64_t);
    ref<Expr> visitNot(uint64_t);
    ref<Expr> visitAnd(uint64_t);
    ref<Expr> visitOr(uint64_t);
    ref<Expr> visitXor(uint64_t);
    ref<Expr> visitShl(uint64_t);
    ref<Expr> visitLShr(uint64_t);
    ref<Expr> visitAShr(uint64_t);
    ref<Expr> visitEq(uint64_t);
    ref<Expr> visitNe(uint64_t);
    ref<Expr> visitUlt(uint64_t);
    ref<Expr> visitUle(uint64_t);
    ref<Expr> visitUgt(uint64_t);
    ref<Expr> visitUge(uint64_t);
    ref<Expr> visitSlt(uint64_t);
    ref<Expr> visitSle(uint64_t);
    ref<Expr> visitSgt(uint64_t);
    ref<Expr> visitSge(uint64_t);

private:
    uint64_t mBufSize;
    uint64_t mBufPtr;
    Assignment *mConcolics; 
    std::vector<std::pair<const MemoryObject *, const Array *>> *mSymbolics;
    std::vector<const Array *> mArrays;
    std::vector<concolicData> mConcolicVariables;

    //ref<Expr> &deserializeExpr(uint64_t bufOffset);
    ref<Expr> deserializeExpr(uint64_t bufOffset);
    uint64_t getKidOffset(uint64_t bufOffset, int kidNum);
    const Array *getPreviousArray(std::string Name, std::string RawName);
    void saveArray(const Array *arr);

public:
    ExprDeserializer(uint64_t buf, uint64_t size, Assignment *concolics,
            std::vector<std::pair<const MemoryObject *, const Array *>> *symbolics)
	: mBufSize(size), mBufPtr(buf), mConcolics(concolics), mSymbolics(symbolics) {
    }

    //ref<Expr> &deserialize(void);
    ref<Expr> deserialize(void);
    std::vector<concolicData> getConcolicVariables(void);
};

}

#endif
