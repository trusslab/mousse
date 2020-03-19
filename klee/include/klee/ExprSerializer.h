/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *  Authors: Ardalan Amiri Sani<ardalan@uci.edu>
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details..
*/
#ifndef KLEE_EXPRSERIALIZER_H
#define KLEE_EXPRSERIALIZER_H

#include "klee/Expr.h"
#include "klee/util/Assignment.h"
#include <klee/AddressSpace.h>

namespace klee {

class ExprSerializer {
protected:

#define MAX_BUF_SIZE	0x1000

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

    int visitConstant(ConstantExpr &, uint64_t *);
    int visitNotOptimized(const NotOptimizedExpr &, uint64_t *);
    int visitRead(const ReadExpr &, uint64_t *);
    int visitSelect(const SelectExpr &, uint64_t *);
    int visitConcat(const ConcatExpr &, uint64_t *);
    int visitExtract(const ExtractExpr &, uint64_t *);
    int visitZExt(const ZExtExpr &, uint64_t *);
    int visitSExt(const SExtExpr &, uint64_t *);
    int visitAdd(const AddExpr &, uint64_t *);
    int visitSub(const SubExpr &, uint64_t *);
    int visitMul(const MulExpr &, uint64_t *);
    int visitUDiv(const UDivExpr &, uint64_t *);
    int visitSDiv(const SDivExpr &, uint64_t *);
    int visitURem(const URemExpr &, uint64_t *);
    int visitSRem(const SRemExpr &, uint64_t *);
    int visitNot(const NotExpr &, uint64_t *);
    int visitAnd(const AndExpr &, uint64_t *);
    int visitOr(const OrExpr &, uint64_t *);
    int visitXor(const XorExpr &, uint64_t *);
    int visitShl(const ShlExpr &, uint64_t *);
    int visitLShr(const LShrExpr &, uint64_t *);
    int visitAShr(const AShrExpr &, uint64_t *);
    int visitEq(const EqExpr &, uint64_t *);
    int visitNe(const NeExpr &, uint64_t *);
    int visitUlt(const UltExpr &, uint64_t *);
    int visitUle(const UleExpr &, uint64_t *);
    int visitUgt(const UgtExpr &, uint64_t *);
    int visitUge(const UgeExpr &, uint64_t *);
    int visitSlt(const SltExpr &, uint64_t *);
    int visitSle(const SleExpr &, uint64_t *);
    int visitSgt(const SgtExpr &, uint64_t *);
    int visitSge(const SgeExpr &, uint64_t *);

private:
    uint64_t mBufSize;
    uint64_t mBufPtr;
    uint64_t mCurrentSize;
    Assignment *mConcolics;
    std::vector<std::pair<const MemoryObject *, const Array *>> *mSymbolics;
    std::vector<const Array *> mArrays;

    void serializeExpr(const ref<Expr> &e, uint64_t *bufOffset);
    bool serializedBefore(const Array *arr);
    void addToSerialized(const Array *arr);

public:
    ExprSerializer(Assignment *concolics, std::vector<std::pair<const MemoryObject *, const Array *>> *symbolics)
               : mBufSize(0), mBufPtr(0), mCurrentSize(MAX_BUF_SIZE), mConcolics(concolics), mSymbolics(symbolics) {

        mBufPtr = (uint64_t) new char[mCurrentSize];
    }

    void serialize(const ref<Expr> &e);

    uint64_t getBufPtr(void) {
        return mBufPtr;
    }

    uint64_t getBufSize(void) {
        return mBufSize;
    }
};

}

#endif
