/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *  Authors: Ardalan Amiri Sani<ardalan@uci.edu>
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details..
*/
#include <map>
#include "klee/ExprSerializer.h"

/* FIXME: move out of here */
//#define DEBUG_KLEE_EXPRSERIALIZER

#ifdef DEBUG_KLEE_EXPRSERIALIZER
#define DPRINTF(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__) 
#else
#define DPRINTF(fmt, ...)                              
#endif

using namespace klee;

void ExprSerializer::serialize(const ref<Expr> &e) {

    DPRINTF("%s [1]\n", __FUNCTION__);
    mBufSize = 0;
    serializeExpr(e, &mBufSize);
    assert((mBufSize < MAX_BUF_SIZE) && "serialization buffer is too large");

    DPRINTF("%s [2]: mBufSize = %llu\n", __FUNCTION__, mBufSize);
}

void ExprSerializer::serializeExpr(const ref<Expr> &e, uint64_t *bufOffset) {

    int res = -1;
    DPRINTF("%s [1]\n", __FUNCTION__);
    Expr &ep = *e.get();

    switch (ep.getKind()) {
        case Expr::Constant:
            res = visitConstant(static_cast<ConstantExpr &>(ep), bufOffset);
            break;
        case Expr::NotOptimized:
            res = visitNotOptimized(static_cast<NotOptimizedExpr &>(ep), bufOffset);
            break;
        case Expr::Read:
            res = visitRead(static_cast<ReadExpr &>(ep), bufOffset);
            break;
        case Expr::Select:
            res = visitSelect(static_cast<SelectExpr &>(ep), bufOffset);
            break;
        case Expr::Concat:
            res = visitConcat(static_cast<ConcatExpr &>(ep), bufOffset);
            break;
        case Expr::Extract:
            res = visitExtract(static_cast<ExtractExpr &>(ep), bufOffset);
            break;
        case Expr::ZExt:
            res = visitZExt(static_cast<ZExtExpr &>(ep), bufOffset);
            break;
        case Expr::SExt:
            res = visitSExt(static_cast<SExtExpr &>(ep), bufOffset);
            break;
        case Expr::Add:
            res = visitAdd(static_cast<AddExpr &>(ep), bufOffset);
            break;
        case Expr::Sub:
            res = visitSub(static_cast<SubExpr &>(ep), bufOffset);
            break;
        case Expr::Mul:
            res = visitMul(static_cast<MulExpr &>(ep), bufOffset);
            break;
        case Expr::UDiv:
            res = visitUDiv(static_cast<UDivExpr &>(ep), bufOffset);
            break;
        case Expr::SDiv:
            res = visitSDiv(static_cast<SDivExpr &>(ep), bufOffset);
            break;
        case Expr::URem:
            res = visitURem(static_cast<URemExpr &>(ep), bufOffset);
            break;
        case Expr::SRem:
            res = visitSRem(static_cast<SRemExpr &>(ep), bufOffset);
            break;
        case Expr::Not:
            res = visitNot(static_cast<NotExpr &>(ep), bufOffset);
            break;
        case Expr::And:
            res = visitAnd(static_cast<AndExpr &>(ep), bufOffset);
            break;
        case Expr::Or:
            res = visitOr(static_cast<OrExpr &>(ep), bufOffset);
            break;
        case Expr::Xor:
            res = visitXor(static_cast<XorExpr &>(ep), bufOffset);
            break;
        case Expr::Shl:
            res = visitShl(static_cast<ShlExpr &>(ep), bufOffset);
            break;
        case Expr::LShr:
            res = visitLShr(static_cast<LShrExpr &>(ep), bufOffset);
            break;
        case Expr::AShr:
            res = visitAShr(static_cast<AShrExpr &>(ep), bufOffset);
            break;
        case Expr::Eq:
            res = visitEq(static_cast<EqExpr &>(ep), bufOffset);
            break;
        case Expr::Ne:
            res = visitNe(static_cast<NeExpr &>(ep), bufOffset);
            break;
        case Expr::Ult:
            res = visitUlt(static_cast<UltExpr &>(ep), bufOffset);
            break;
        case Expr::Ule:
            res = visitUle(static_cast<UleExpr &>(ep), bufOffset);
            break;
        case Expr::Ugt:
            res = visitUgt(static_cast<UgtExpr &>(ep), bufOffset);
            break;
        case Expr::Uge:
            res = visitUge(static_cast<UgeExpr &>(ep), bufOffset);
            break;
        case Expr::Slt:
            res = visitSlt(static_cast<SltExpr &>(ep), bufOffset);
            break;
        case Expr::Sle:
            res = visitSle(static_cast<SleExpr &>(ep), bufOffset);
            break;
        case Expr::Sgt:
            res = visitSgt(static_cast<SgtExpr &>(ep), bufOffset);
            break;
        case Expr::Sge:
            res = visitSge(static_cast<SgeExpr &>(ep), bufOffset);
            break;
        default:
            assert(0 && "invalid expression kind");
    }
    DPRINTF("%s [2]\n", __FUNCTION__);

    if (res)
        assert(0 && "visit function returned error");
    
    assert((*bufOffset < MAX_BUF_SIZE) && "serialization buffer is too large");

    uint64_t offset;
    ////ref<Expr> kids[8];
    unsigned count = ep.getNumKids();
    DPRINTF("%s [3]: count = %d\n", __FUNCTION__, count);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = count;
    *bufOffset = *bufOffset + 1;
    offset = *bufOffset;
    *bufOffset = *bufOffset + (count * 2); /* one uint16_t for each reference */
    for (unsigned i = 0; i < count; i++) {
        ref<Expr> kid = ep.getKid(i);
        /* FIXME: why uint16_t? because the max buffer size is 0x1000 and 16 bits are enough. */
        uint16_t *iptr = (uint16_t *) (mBufPtr + offset);
        *iptr = (uint16_t) *bufOffset;
        DPRINTF("%s [4]: kid %d offset = %d\n", __FUNCTION__, i, *bufOffset);
        offset = offset + 2;
        serializeExpr(kid, bufOffset);
        //kids[i] = visit(kid);
        //if (kids[i] != kid)
        //    rebuild = true;
    }
    DPRINTF("%s [4]\n", __FUNCTION__);
}

bool ExprSerializer::serializedBefore(const Array *arr) {
    for (std::vector<const Array *>::iterator it = mArrays.begin(), ie = mArrays.end(); it != ie; it++) {
        if (*it == arr)
            return true;
    }

    return false;
}

void ExprSerializer::addToSerialized(const Array *arr) {
    mArrays.push_back(arr);
}

int ExprSerializer::visitConstant(ConstantExpr &e, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    uint8_t width = e.getWidth();
    *ptr = CONSTANT_CODE;
    ptr++;
    *ptr = width;
    ptr++;
    e.toMemory((void *) ptr);
    *bufOffset += 2 + width;
    DPRINTF("%s [3]: *bufOffset = %llu, width = %d\n", __FUNCTION__, *bufOffset, width);
    return 0;
}

int ExprSerializer::visitNotOptimized(const NotOptimizedExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = NOTOPTIMIZED_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitRead(const ReadExpr &e, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = READ_CODE;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);

    /* UpdateList stuff */
    const UpdateList &updates = e.getUpdates();
    unsigned size = updates.getSize();
    DPRINTF("%s [3]: UpdateList size = %d\n", __FUNCTION__, size);
    ptr++;
    assert((size == 0) && "update list size other than 0 not supported");
    *ptr = (uint8_t) size;

    /* Array stuff */
    const Array *root = updates.getRoot();
    assert(root && "root is NULL");

    DPRINTF("%s [4]: root->isSymbolicArray() = %d\n", __FUNCTION__, root->isSymbolicArray());
    DPRINTF("%s [5]: root->isConstantArray() = %d\n", __FUNCTION__, root->isConstantArray());
    DPRINTF("%s [6]: root->getSize() = %d\n", __FUNCTION__, root->getSize());
    DPRINTF("%s [7]: root->getName() = %s\n", __FUNCTION__, root->getName().c_str());
    DPRINTF("%s [8]: root->getRawName() = %s\n", __FUNCTION__, root->getRawName().c_str());
    DPRINTF("%s [9]: root->getConstantValues().size() = %d\n", __FUNCTION__, root->getConstantValues().size());

    ptr++;
    assert(root->isSymbolicArray() && "only symbolic array is supported");
    assert(!root->isConstantArray() && "constant array not supported");
    *ptr = (uint8_t) root->isSymbolicArray();

    ptr++;
    assert((root->getSize() < 256) && "array size not supported");
    *ptr = (uint8_t) root->getSize();

    ptr++;
    strcpy((char *) ptr, root->getName().c_str());
    size_t strSize = strlen(root->getName().c_str()) + 1;

    ptr = ptr + strSize;
    strcpy((char *) ptr, root->getRawName().c_str());
    size_t strSize2 = strlen(root->getRawName().c_str()) + 1;

    ptr = ptr + strSize2;
    if (serializedBefore(root)) {
        *ptr = 0; 
        *bufOffset += 5 + strSize + strSize2;
        return 0;
    }

    /* concolics */
    *ptr = 1; 
    addToSerialized(root);
    Assignment::bindings_ty bindings = mConcolics->bindings;
    uint64_t valSize = 0;
    const Array *arr;

    for (Assignment::bindings_ty::iterator it = bindings.begin(), ie = bindings.end(); it != ie; it++) {
        const Array *first = it->first;
        arr = it->first;
        std::vector<unsigned char> second = it->second;
        DPRINTF("%s [10]: first->getName() = %s\n", __FUNCTION__, first->getName().c_str());
        DPRINTF("%s [11]: first->getRawName() = %s\n", __FUNCTION__, first->getRawName().c_str());
        if (!first->getName().compare(root->getName()) && !first->getRawName().compare(root->getRawName()))
            DPRINTF("%s [12]: second.size() = %d\n", __FUNCTION__, second.size());
            ptr++;
            valSize = second.size();
            *((uint64_t *) ptr) = valSize;
            ptr += 8; /* FIXME: do we need 8 bytes for this? */
            for (std::vector<unsigned char>::iterator itv = second.begin(), iev = second.end(); itv != iev; itv++) {
                DPRINTF("%s [13]: *itv = %d\n", __FUNCTION__, (int) *itv);
                *ptr = (uint8_t) *itv;
                ptr++;
            }
            break;
    }

    /* symbolics -- print-only for now */
    for (std::vector<std::pair<const MemoryObject *, const Array *>>::iterator its = mSymbolics->begin(),
         ies = mSymbolics->end(); its != ies; its++) {
        if (its->second == arr) {
            DPRINTF("%s [14]: its->first->address = %llu\n", __FUNCTION__, its->first->address);
            DPRINTF("%s [15]: its->first->size = %llu\n", __FUNCTION__, its->first->size);
            DPRINTF("%s [16]: its->first->name = %s\n", __FUNCTION__, its->first->name.c_str());
            DPRINTF("%s [17]: its->first->isLocal = %d\n", __FUNCTION__, its->first->isLocal);
            DPRINTF("%s [18]: its->first->isGlobal = %d\n", __FUNCTION__, its->first->isGlobal);
            DPRINTF("%s [19]: its->first->isFixed = %d\n", __FUNCTION__, its->first->isFixed);
            assert(!its->first->isLocal && "isLocal is not false");
            assert(!its->first->isGlobal && "isGlobal is not false");
            assert(!its->first->isFixed && "isFixed is not false");
            /* FIXME: how about checks for size and address? */
        }
    }

    *bufOffset += 13 + strSize + strSize2 + valSize;

    return 0;
}

int ExprSerializer::visitSelect(const SelectExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SELECT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitConcat(const ConcatExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = CONCAT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitExtract(const ExtractExpr &e, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    uint16_t *bitOffPtr; /* FIXME: why uint16_t? because of max buffer size */
    uint8_t width = e.getWidth();
    *ptr = EXTRACT_CODE;
    ptr++;
    *ptr = width;
    bitOffPtr = (uint16_t *) (ptr + 1);
    *bitOffPtr = e.getOffset();
    *bufOffset += 4;
    DPRINTF("%s [3]: *bufOffset = %llu, width = %d, *bitOffPtr = %d\n", __FUNCTION__,
                                       *bufOffset, width, *bitOffPtr);
    return 0;
}

int ExprSerializer::visitZExt(const ZExtExpr &e, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    uint8_t width = e.getWidth();
    *ptr = ZEXT_CODE;
    ptr++;
    *ptr = width;
    *bufOffset += 2;
    DPRINTF("%s [3]: *bufOffset = %llu, width = %d\n", __FUNCTION__, *bufOffset, width);
    return 0;
}

int ExprSerializer::visitSExt(const SExtExpr &e, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    uint8_t width = e.getWidth();
    *ptr = SEXT_CODE;
    ptr++;
    *ptr = width;
    *bufOffset += 2;
    DPRINTF("%s [3]: *bufOffset = %llu, width = %d\n", __FUNCTION__, *bufOffset, width);
    return 0;
}

int ExprSerializer::visitAdd(const AddExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = ADD_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSub(const SubExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SUB_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitMul(const MulExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = MUL_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitUDiv(const UDivExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = UDIV_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSDiv(const SDivExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SDIV_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitURem(const URemExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = UREM_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSRem(const SRemExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SREM_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitNot(const NotExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = NOT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitAnd(const AndExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = AND_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitOr(const OrExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = OR_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitXor(const XorExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = XOR_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitShl(const ShlExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SHL_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitLShr(const LShrExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = LSHR_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitAShr(const AShrExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = ASHR_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitEq(const EqExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = EQ_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitNe(const NeExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = NE_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitUlt(const UltExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = ULT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitUle(const UleExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = ULE_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitUgt(const UgtExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = UGT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitUge(const UgeExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = UGE_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSlt(const SltExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SLT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSle(const SleExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SLE_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSgt(const SgtExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SGT_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}

int ExprSerializer::visitSge(const SgeExpr &, uint64_t *bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    uint8_t *ptr = (uint8_t *) (mBufPtr + *bufOffset);
    *ptr = SGE_CODE;
    *bufOffset += 1;
    DPRINTF("%s [2]: *bufOffset = %llu\n", __FUNCTION__, *bufOffset);
    return 0;
}
