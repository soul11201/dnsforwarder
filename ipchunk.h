#ifndef IPCHUNK_H_INCLUDED
#define IPCHUNK_H_INCLUDED

#include "bst.h"
#include "common.h"

typedef struct _IpElement {
	_32BIT_UINT	Ip;
} IpElement;

typedef Bst	IpChunk;

int IpChunk_Init(IpChunk *ic);

int IpChunk_Add(IpChunk *ic, _32BIT_UINT Ip);

BOOL IpChunk_Find(IpChunk *ic, _32BIT_UINT Ip);


#endif // IPCHUNK_H_INCLUDED
