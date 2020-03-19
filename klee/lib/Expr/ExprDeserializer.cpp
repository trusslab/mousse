/* Mousse
 * Copyright (c) 2019 TrussLab@University of California, Irvine. 
 *  Authors: Ardalan Amiri Sani<ardalan@uci.edu>
 * All rights reserved.
 *
 * This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
#include "klee/ExprDeserializer.h"

/* FIXME: move out of here */
//#define DEBUG_KLEE_EXPRDESERIALIZER

#ifdef DEBUG_KLEE_EXPRDESERIALIZER
#define DPRINTF(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__) 
#else
#define DPRINTF(fmt, ...)                              
#endif
//#define DPRINTF1(fmt, ...)  fprintf(stderr, "(pid %d): " fmt, getpid(), ## __VA_ARGS__)  

using namespace klee;

ref<Expr> ExprDeserializer::deserialize(void) {

    DPRINTF("%s [1]\n", __FUNCTION__);
    ref<Expr> e = deserializeExpr(0);
    //e->dump();
    DPRINTF("%s [2]\n", __FUNCTION__);
    return e;
}

std::vector<concolicData> ExprDeserializer::getConcolicVariables(void) {
    return mConcolicVariables;
}

ref<Expr> ExprDeserializer::deserializeExpr(uint64_t bufOffset) {

    DPRINTF("%s [1]: bufOffset = %llu\n", __FUNCTION__, bufOffset);
    uint8_t exprCode = *((uint8_t *) (mBufPtr + bufOffset));
    bufOffset = bufOffset + 1;
    // = *e.get();

    switch (exprCode) {
        case CONSTANT_CODE:
            return visitConstant(bufOffset);
        case NOTOPTIMIZED_CODE:
            return visitNotOptimized(bufOffset);
        case READ_CODE:
            return visitRead(bufOffset);
        case SELECT_CODE:
            return visitSelect(bufOffset);
        case CONCAT_CODE:
            return visitConcat(bufOffset);
        case EXTRACT_CODE:
            return visitExtract(bufOffset);
        case ZEXT_CODE:
            return visitZExt(bufOffset);
        case SEXT_CODE:
            return visitSExt(bufOffset);
        case ADD_CODE:
            return visitAdd(bufOffset);
        case SUB_CODE:
            return visitSub(bufOffset);
        case MUL_CODE:
            return visitMul(bufOffset);
        case UDIV_CODE:
            return visitUDiv(bufOffset);
        case SDIV_CODE:
            return visitSDiv(bufOffset);
        case UREM_CODE:
            return visitURem(bufOffset);
        case SREM_CODE:
            return visitSRem(bufOffset);
        case NOT_CODE:
            return visitNot(bufOffset);
        case AND_CODE:
            return visitAnd(bufOffset);
        case OR_CODE:
            return visitOr(bufOffset);
            break;
        case XOR_CODE:
            return visitXor(bufOffset);
        case SHL_CODE:
            return visitShl(bufOffset);
        case LSHR_CODE:
            return visitLShr(bufOffset);
        case ASHR_CODE:
            return visitAShr(bufOffset);
        case EQ_CODE:
            return visitEq(bufOffset);
        case NE_CODE:
            return visitNe(bufOffset);
        case ULT_CODE:
            return visitUlt(bufOffset);
        case ULE_CODE:
            return visitUle(bufOffset);
        case UGT_CODE:
            return visitUgt(bufOffset);
        case UGE_CODE:
            return visitUge(bufOffset);
        case SLT_CODE:
            return visitSlt(bufOffset);
        case SLE_CODE:
            return visitSle(bufOffset);
        case SGT_CODE:
            return visitSgt(bufOffset);
        case SGE_CODE:
            return visitSge(bufOffset);
        default:
            assert(0 && "invalid expression kind");
    }
}

uint64_t ExprDeserializer::getKidOffset(uint64_t bufOffset, int kidNum) {
    ///uint64_t offset;
    uint8_t *ptr = (uint8_t *) (mBufPtr + bufOffset);
    uint8_t count = *ptr;
    DPRINTF("%s [1]: bufOffset = %llu, kidNum = %d, count = %d\n", __FUNCTION__, bufOffset, kidNum, count);

    if (kidNum >= count)
        assert(0 && "invalid kid");
        
    uint16_t *iptr = (uint16_t *) (mBufPtr + bufOffset + (kidNum * 2) + 1);
    uint16_t kid_offset = *iptr;
    DPRINTF("%s [2]: offset = %d\n", __FUNCTION__, kid_offset);

    return (uint64_t) kid_offset;
}

const Array *ExprDeserializer::getPreviousArray(std::string Name, std::string RawName) {
    for (std::vector<const Array *>::iterator it = mArrays.begin(), ie = mArrays.end(); it != ie; it++) {
        if (!(*it)->getName().compare(Name) && !(*it)->getRawName().compare(RawName))
            return *it;
    }

    return NULL;
}

void ExprDeserializer::saveArray(const Array *arr) {
    mArrays.push_back(arr);
}

ref<Expr> ExprDeserializer::visitConstant(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);
    uint8_t *ptr = (uint8_t *) (mBufPtr + bufOffset);
    uint8_t width = *ptr;
    DPRINTF("%s [3]: width = %d\n", __FUNCTION__, width);
    return ConstantExpr::fromMemory(ptr + 1, width);
}

ref<Expr> ExprDeserializer::visitNotOptimized(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    
    return NotOptimizedExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)));
}

ref<Expr> ExprDeserializer::visitRead(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);

    uint8_t *ptr = (uint8_t *) (mBufPtr + bufOffset);
    unsigned updateListSize = (unsigned) *ptr;
    DPRINTF("%s [3]: updateListSize = %d\n", __FUNCTION__, updateListSize);
    assert((updateListSize == 0) && "update list size other than 0 not supported");

    ptr++;
    uint8_t isSymbolicArray = *ptr;
    DPRINTF("%s [4]: isSymbolicArray = %d\n", __FUNCTION__, isSymbolicArray);
    assert(isSymbolicArray && "only symbolic array is supported");

    ptr++;
    uint8_t arraySize = *ptr;
    DPRINTF("%s [5]: arraySize = %d\n", __FUNCTION__, arraySize);
//    assert((arraySize < 256) && "array size not supported");

    ptr++;
    DPRINTF("%s [6]: Name = %s\n", __FUNCTION__, (char *) ptr);
    size_t strSize = strlen((char *) ptr) + 1;
    DPRINTF("%s [7]: strSize = %d\n", __FUNCTION__, strSize);
    std::string Name((char *) ptr);

    ptr += strSize;
    DPRINTF("%s [8]: RawName = %s\n", __FUNCTION__, (char *) ptr);
    size_t strSize2 = strlen((char *) ptr) + 1;
    DPRINTF("%s [9]: strSize2 = %d\n", __FUNCTION__, strSize2);
    std::string RawName((char *) ptr);

    ptr = ptr + strSize2;
    uint8_t newArray = *ptr;
    DPRINTF("%s [10]: newArray = %d\n", __FUNCTION__, newArray);

    if (newArray == 0) {
        const Array *arr = getPreviousArray(Name, RawName);
        assert(arr && "arr is NULL");
        ref<Expr> expr = deserializeExpr(getKidOffset(bufOffset + 4 + strSize + strSize2, 0));
        return ReadExpr::alloc(UpdateList(arr, NULL), expr);
    }

    assert((newArray == 1) && "invalid newArray value");

   //DPRINTF("%s [10.01]: mConcolics = %p\n", __FUNCTION__, mConcolics);

    //if (!val) {
    //DPRINTF("%s [10.6]\n", __FUNCTION__);
    std::vector<unsigned char> *val = new std::vector<unsigned char>; /* FIXME: delete? */
    //}

    /* concolics */
    ptr++;
    uint64_t valSize = *((uint64_t *) ptr);
    DPRINTF("%s [11]: valSize = %llu\n", __FUNCTION__, valSize);

    ptr += 8;

    for (uint64_t i = 0; i < valSize; i++) {
        uint8_t valChar = *(ptr);
        DPRINTF("%s [12]: valChar = %d\n", __FUNCTION__, valChar);
        val->push_back((unsigned char) valChar);
        ptr++;
    }

    const Array *arr = NULL;
    bool moFound = false;
    Assignment::bindings_ty bindings = mConcolics->bindings;
    mConcolics->clear();

    for (Assignment::bindings_ty::iterator it = bindings.begin(), ie = bindings.end(); it != ie; it++) {
        const Array *first = it->first;
        std::vector<unsigned char> second = it->second;
        DPRINTF("%s [13]: first->getName() = %s\n", __FUNCTION__, first->getName().c_str());
        DPRINTF("%s [14]: first->getRawName() = %s\n", __FUNCTION__, first->getRawName().c_str());
        if (!first->getName().compare(Name) && !first->getRawName().compare(RawName)) {
            mConcolics->add(first, *val);

            DPRINTF("%s [15]\n", __FUNCTION__);
            arr = first;

            for (std::vector<std::pair<const MemoryObject *, const Array *>>::iterator its = mSymbolics->begin(),
                 ies = mSymbolics->end(); its != ies; its++) {
                DPRINTF("%s [16]\n", __FUNCTION__);
                if (its->second == arr) {
                    DPRINTF("%s [17]\n", __FUNCTION__);
                    moFound = true;
                }
            }
            assert(moFound && "could not find the memory object");
        } else {
            mConcolics->add(first, second); 
        }
    }

    if (arr == NULL) {
        DPRINTF("%s [12.1]\n", __FUNCTION__);
        /* mo should not have been found due to an earlier assertion */
        arr = new Array(Name, arraySize, 0, 0, RawName); /* FIXME: delete? */
        mConcolics->add(arr, *val);
        /* FIXME: do we need to pass the correct val here or 0 is fine? */
        mConcolicVariables.push_back(concolicData(valSize, 0, RawName));
        /* symbolics */
        MemoryObject *mo = new MemoryObject(0, arraySize, false, false, false, NULL);
        mo->setName(Name);
        mSymbolics->push_back(std::make_pair(mo, arr));
    }

    saveArray(arr);

    ref<Expr> expr = deserializeExpr(getKidOffset(bufOffset + 12 + strSize + strSize2 + valSize, 0));
    return ReadExpr::alloc(UpdateList(arr, NULL), expr);
}

ref<Expr> ExprDeserializer::visitSelect(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    
    return SelectExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                             deserializeExpr(getKidOffset(bufOffset, 1)),
                             deserializeExpr(getKidOffset(bufOffset, 2)));
}

ref<Expr> ExprDeserializer::visitConcat(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);
    
    return ConcatExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                             deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitExtract(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);
    uint8_t *ptr = (uint8_t *) (mBufPtr + bufOffset);
    uint8_t width = *ptr;
    DPRINTF("%s [3]: width = %d\n", __FUNCTION__, width);
    uint16_t *bitOffsetPtr = (uint16_t *) (ptr + 1);
    uint16_t bitOffset = *bitOffsetPtr;
    DPRINTF("%s [4]: bitOffset = %d\n", __FUNCTION__, bitOffset);
    /* FIXME: update 3 if not using uint16_t for bitOffset */
    return ExtractExpr::alloc(deserializeExpr(getKidOffset(bufOffset + 3, 0)),
                              (unsigned) bitOffset, width);
}

ref<Expr> ExprDeserializer::visitZExt(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);
    uint8_t *ptr = (uint8_t *) (mBufPtr + bufOffset);
    uint8_t width = *ptr;
    DPRINTF("%s [3]: width = %d\n", __FUNCTION__, width);
    return ZExtExpr::alloc(deserializeExpr(getKidOffset(bufOffset + 1, 0)), width);
}

ref<Expr> ExprDeserializer::visitSExt(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);
    uint8_t *ptr = (uint8_t *) (mBufPtr + bufOffset);
    uint8_t width = *ptr;
    DPRINTF("%s [3]: width = %d\n", __FUNCTION__, width);
    return SExtExpr::alloc(deserializeExpr(getKidOffset(bufOffset + 1, 0)), width);
}

ref<Expr> ExprDeserializer::visitAdd(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return AddExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSub(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SubExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitMul(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return MulExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitUDiv(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return UDivExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                           deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSDiv(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SDivExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                           deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitURem(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return URemExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                           deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSRem(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SRemExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                           deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitNot(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);

    return NotExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)));
}

ref<Expr> ExprDeserializer::visitAnd(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return AndExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitOr(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return OrExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                         deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitXor(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return XorExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitShl(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return ShlExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitLShr(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return LShrExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                           deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitAShr(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return AShrExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                           deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitEq(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);
    DPRINTF("%s [2]: bufOffset = %llu\n", __FUNCTION__, bufOffset);

    return EqExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                         deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitNe(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return NeExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                         deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitUlt(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return UltExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitUle(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return UleExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitUgt(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return UgtExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitUge(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return UgeExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSlt(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SltExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSle(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SleExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSgt(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SgtExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}

ref<Expr> ExprDeserializer::visitSge(uint64_t bufOffset) {
    DPRINTF("%s [1]\n", __FUNCTION__);

    return SgeExpr::alloc(deserializeExpr(getKidOffset(bufOffset, 0)),
                          deserializeExpr(getKidOffset(bufOffset, 1)));
}
