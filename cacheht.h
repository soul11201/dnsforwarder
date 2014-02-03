#ifndef HASHTABLE_H_INCLUDED
#define HASHTABLE_H_INCLUDED

#include <time.h>
#include "array.h"

typedef struct _Cht_Node{
	_32BIT_INT	Slot;
	_32BIT_INT	Next;
	_32BIT_INT	Offset;
	_32BIT_UINT	TTL;
	time_t		TimeAdded;
	_32BIT_UINT	Length;
} Cht_Node;

typedef struct _HashTable{
	Array		NodeChunk;
	Array		Slots;
	_32BIT_INT	FreeList;
}CacheHT;

int CacheHT_Init(CacheHT *h, char *BaseAddr, int CacheSize);

int CacheHT_ReInit(CacheHT *h, char *BaseAddr, int CacheSize);

_32BIT_INT CacheHT_FindUnusedNode(CacheHT		*h,
								  _32BIT_UINT	ChunkSize,
								  Cht_Node		**Out,
								  void			*Boundary
								  );

int CacheHT_InsertToSlot(CacheHT	*h,
						 const char	*Key,
						 int		Node_index,
						 Cht_Node	*Node,
						 int		*HashValue
						 );

int CacheHT_RemoveFromSlot(CacheHT *h, _32BIT_INT SubScriptOfNode, Cht_Node *Node);

Cht_Node *CacheHT_Get(CacheHT *h, const char *Key, Cht_Node *Start, int *HashValue);

void CacheHT_Free(CacheHT *h);

#endif // HASHTABLE_H_INCLUDED
