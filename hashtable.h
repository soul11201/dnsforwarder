#ifndef HASHTABLE_H_INCLUDED
#define HASHTABLE_H_INCLUDED

#include "array.h"

/* Tail of a linked list */
#define	HASHTABLE_NODE_TAIL			(-1)

#define	HASHTABLE_NODE_FREE			(-2)

#define	HASHTABLE_NODE_UNAVAILABLE	(-3)

#define	HASHTABLE_NODE_STRAY	(-4)

typedef struct _NodeHead{
	_32BIT_INT	Next; /* This value can be HASHTABLE_NODE_TAIL if this node is a end, HASHTABLE_NODE_FREE if this node has been removed, or a non-negative number otherwise. */
	_32BIT_INT	Prev; /* If this value is negative, it denotes the subscript of Slots, Prev == (-1) * (Subscript + 1). A non-negative number otherwise. */
} NodeHead;

typedef struct _HashTable{
	Array		NodeChunk;
	Array		Slots;
	_32BIT_INT	FreeList;

	int			(*HashFunction)(const char *, int);
}HashTable;

int HashTable_Init(HashTable *h,
					int DataLength,
					int InitialCount,
					int (*HashFunction)(const char *, int)
					);

int HashTable_Init_Manually(HashTable	*h,
							void		*SlotsStartAddress,
							_32BIT_INT	SlotsCount,
							void		*NodeChunkStartAddress,
							BOOL		GrowDown,
							_32BIT_INT	DataLength
							);

#define HashTable_SetSlotsStartAddress(h_ptr, addr)	((h_ptr) -> Slots.Data = (addr))

#define HashTable_SetNodeChunkStartAddress(h_ptr, addr)	((h_ptr) -> NodeChunk.Data = (addr))

int HashTable_CalculateAppropriateSlotCount(int ElementCount);

int HashTable_CreateNewNode(HashTable *h, NodeHead **Out, void *Boundary /* Only used by grow down array */);

#define HASHTABLE_FINDFREENODE_START	(-1)
#define HASHTABLE_FINDFREENODE_FAILED	(-2)
_32BIT_INT HashTable_FindUnusedNode(HashTable *h, NodeHead **Out, _32BIT_INT Start, void *Boundary, BOOL AutoCreateNewNode);

_32BIT_INT HashTable_FetchNode(HashTable *h, NodeHead *Node);

int HashTable_AddByNode(HashTable	*h,
						const char	*Key,
						int			KeyLength,
						int			Node_index,
						NodeHead	*Node,
						int			*HashValue
						);

int HashTable_Add(HashTable *h, const char *Key, int KeyLength, void *Data, int *HashValue);

#define	HashTable_GetDataByNode(Node_ptr)	((void *)((NodeHead *)(Node_ptr) + 1))

#define	HashTable_GetNodeBySubscript(h_ptr, Subscript)	((NodeHead *)Array_GetBySubscript(&((h_ptr) -> NodeChunk), (Subscript)))

void *HashTable_Get(HashTable *h, const char *Key, int KeyLength, void *Start, int *HashValue);

int HashTable_RemoveNode(HashTable *h, _32BIT_INT SubScriptOfNode, NodeHead *Node);

void HashTable_Free(HashTable *h);

#endif // HASHTABLE_H_INCLUDED
