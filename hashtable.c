#include <string.h>
#include "hashtable.h"
#include "common.h"
#include "utils.h"

#define	GET_SLOT_SUBSCRIPT(d)	((-1) * (d) - 1)

int HashTable_CalculateAppropriateSlotCount(int ElementCount)
{
	if( ElementCount > 10 )
	{
		ElementCount /= 3;
		return ROUND(ElementCount, 10) + 6;
	} else {
		return 3;
	}
}

int HashTable_Init(HashTable *h,
					int DataLength,
					int InitialCount,
					int (*HashFunction)(const char *, int)
					)
{
	int	loop;
	int	SlotCount;
	if( h == NULL )
		return -1;

	SlotCount = HashTable_CalculateAppropriateSlotCount(InitialCount);

	if( Array_Init(&(h -> NodeChunk), DataLength + sizeof(NodeHead), InitialCount, FALSE, NULL) != 0 )
		return 1;

	if( Array_Init(&(h -> Slots), sizeof(NodeHead), SlotCount, FALSE, NULL) != 0 )
		return 2;

	h -> Slots.Used = h -> Slots.Allocated;

	for(loop = 0; loop != h -> Slots.Allocated; ++loop)
	{
		((NodeHead *)Array_GetBySubscript(&(h -> Slots), loop)) -> Next = HASHTABLE_NODE_TAIL;
	}

	if( HashFunction == NULL )
	{
		h -> HashFunction = ELFHash;
	} else {
		h -> HashFunction = HashFunction;
	}

	h -> FreeList = -1;

	return 0;
}

int HashTable_Init_Manually(HashTable	*h,
							void		*SlotsStartAddress,
							_32BIT_INT	SlotsCount,
							void		*NodeChunkStartAddress,
							BOOL		GrowDown,
							_32BIT_INT	DataLength
							)
{
	h -> Slots.Used = SlotsCount;
	h -> Slots.DataLength = sizeof(NodeHead);
	h -> Slots.Data = SlotsStartAddress;
	h -> Slots.Allocated = SlotsCount;

	h -> NodeChunk.DataLength = DataLength;
	h -> NodeChunk.Data = NodeChunkStartAddress;
	h -> NodeChunk.Used = 0;

	if( GrowDown == TRUE )
	{
		h -> NodeChunk.Allocated = -1;
	} else {
		h -> NodeChunk.Allocated = 0;
	}

	h -> FreeList = -1;

	return 0;
}

int HashTable_CreateNewNode(HashTable *h, NodeHead **Out, void *Boundary /* Only used by grow down array */)
{
	int			NewNode_i;
	NodeHead	*NewNode;

	Array		*NodeChunk;

	NodeChunk = &(h -> NodeChunk);

	NewNode_i = Array_PushBack(NodeChunk, NULL, Boundary);
	if( NewNode_i < 0 )
	{
		return -1;
	}

	NewNode = (NodeHead *)Array_GetBySubscript(NodeChunk, NewNode_i);
	NewNode -> Next = HASHTABLE_NODE_STRAY;

	if( Out != NULL )
	{
		*Out = NewNode;
	}

	return NewNode_i;
}

_32BIT_INT HashTable_FindUnusedNode(HashTable *h,
									NodeHead **Out,
									_32BIT_INT Start, /* Initially HASHTABLE_FINDFREENODE_START(-1) */
									void *Boundary, /* Only used by grow down array */
									BOOL AutoCreateNewNode
									)
{
	_32BIT_INT	Subscript;
	NodeHead	*Node;

	Array		*NodeChunk;

	NodeChunk = &(h -> NodeChunk);

	if( Start == HASHTABLE_FINDFREENODE_START )
	{
		Subscript = h -> FreeList;
	} else if( Start >= 0 ){
		Node = (NodeHead *)Array_GetBySubscript(NodeChunk, Start);
		Subscript = Node -> Next;
	} else {
		if( Out != NULL )
		{
			*Out = NULL;
		}
		return HASHTABLE_FINDFREENODE_FAILED;
	}

	if( Subscript >= 0 )
	{
		Node = (NodeHead *)Array_GetBySubscript(NodeChunk, Subscript);

		if( Out != NULL )
		{
			*Out = Node;
		}

		return Subscript;
	}

	if( AutoCreateNewNode == TRUE )
	{
		return HashTable_CreateNewNode(h, Out, Boundary);
	} else {
		if( Out != NULL )
		{
			*Out = NULL;
		}
		return HASHTABLE_FINDFREENODE_FAILED;
	}
}

_32BIT_INT HashTable_FetchNode(HashTable *h, NodeHead *Node)
{
	Array		*NodeChunk;

	if( Node -> Next == HASHTABLE_NODE_STRAY )
	{
		return 0;
	}

	NodeChunk = &(h -> NodeChunk);

	if( Node -> Prev >= 0 )
	{
		NodeHead	*NextRemovedNode;
		NextRemovedNode = (NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Prev);
		NextRemovedNode -> Next = Node -> Next;
	} else {
		h -> FreeList = Node -> Next;
	}

	if( Node -> Next >= 0 )
	{
		NodeHead	*PreviousRemovedNode;
		PreviousRemovedNode = (NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Next);
		PreviousRemovedNode -> Prev = Node -> Prev;
	}

	Node -> Next = HASHTABLE_NODE_STRAY;
	Node -> Prev = HASHTABLE_NODE_STRAY;

	return 0;
}

int HashTable_AddByNode(HashTable	*h,
						const char	*Key,
						int			KeyLength,
						int			Node_index,
						NodeHead	*Node,
						int			*HashValue
						)
{
	int			Slot_i;
	NodeHead	*Slot;

	if( h == NULL || Key == NULL || Node_index < 0 || Node == NULL )
		return -1;

	if( HashValue != NULL )
	{
		Slot_i = (*HashValue) % (h -> Slots.Allocated - 1);
	} else {
		Slot_i = (h -> HashFunction)(Key, KeyLength) % (h -> Slots.Allocated - 1);
	}

	Slot = (NodeHead *)Array_GetBySubscript(&(h -> Slots), Slot_i);
	if( Slot == NULL )
		return -2;

	if( Slot -> Next >= 0 )
	{
		((NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), Slot -> Next)) -> Prev = Node_index;
	}

	Node -> Next = Slot -> Next;
	Node -> Prev = (-1) * (Slot_i + 1);
	Slot -> Next = Node_index;

	return 0;
}

int HashTable_Add(HashTable *h, const char *Key, int KeyLength, void *Data, int *HashValue)
{
	_32BIT_INT	NewNode_i;
	NodeHead	*NewNode = NULL;

	NewNode_i = HashTable_FindUnusedNode(h, &NewNode, -1, NULL, TRUE);

	if( NewNode_i < 0 )
		return -1;

	HashTable_FetchNode(h, NewNode);

	memcpy(NewNode + 1, Data, h -> NodeChunk.DataLength - sizeof(NodeHead));

	return HashTable_AddByNode(h, Key, KeyLength, NewNode_i, NewNode, HashValue);
}

int HashTable_RemoveNode(HashTable *h, _32BIT_INT SubScriptOfNode, NodeHead *Node)
{
	Array	*NodeChunk;

	NodeChunk = &(h -> NodeChunk);

	/* The node must be given in at least one form */
	if( SubScriptOfNode < 0 && Node == NULL )
	{
		return -1;
	}

	/* If the subscript is not given, compute it */
	if( SubScriptOfNode < 0 )
	{
		SubScriptOfNode = ((char *)Node - (char *)(NodeChunk -> Data)) / (NodeChunk -> DataLength);
		if( NodeChunk -> Allocated < 0 )
		{
			SubScriptOfNode *= (-1);
		}
	}

	/* If the address of the node is not given, get it */
	if( Node == NULL )
	{
		Node = (NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), SubScriptOfNode);
	}

	/* If this node has not been removed */
	if( Node -> Next != HASHTABLE_NODE_FREE )
	{

		/* If this node is not a stray node */
		if( Node -> Next != HASHTABLE_NODE_STRAY )
		{
			/* If this node is not tail */
			if( Node -> Next >= 0 )
			{
				((NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Next)) -> Prev = Node -> Prev;
			}

			if( Node -> Prev < 0 )
			{
				/* Prev is a slot */
				((NodeHead *)Array_GetBySubscript(&(h -> Slots), GET_SLOT_SUBSCRIPT(Node -> Prev))) -> Next = Node -> Next;
			} else {
				/* Prev is a node. */
				((NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Prev)) -> Next = Node -> Next;
			}
		}

		/* If this node is not the last one of NodeChunk, add it into free list,
		 * or simply delete it from NodeChunk
		 */
		if( SubScriptOfNode != NodeChunk -> Used - 1 )
		{

			/* Modify the first node in FreeList */
			if( h -> FreeList >= 0 )
			{
				NodeHead	*PreviousRemovedNode;
				PreviousRemovedNode = (NodeHead *)Array_GetBySubscript(NodeChunk, h -> FreeList);
				PreviousRemovedNode -> Prev = SubScriptOfNode;
			}

			/* Insert this node at the head of the FreeList */
			Node -> Next = h -> FreeList;
			Node -> Prev = -1;
			h -> FreeList = SubScriptOfNode;
		} else {
			--(NodeChunk -> Used);
		}
	} else {
		if( SubScriptOfNode == NodeChunk -> Used - 1 )
		{
			--(NodeChunk -> Used);
		}
	}

	return 0;
}

void *HashTable_Get(HashTable *h, const char *Key, int KeyLength, void *Start, int *HashValue)
{
	NodeHead	*Head;

	if( h == NULL || Key == NULL)
		return NULL;

	if( Start == NULL )
	{
		int			Slot_i;
		NodeHead	*Slot;

		if( HashValue != NULL )
		{
			Slot_i = (*HashValue) % (h -> Slots.Allocated - 1);
		} else {
			Slot_i = (h -> HashFunction)(Key, KeyLength) % (h -> Slots.Allocated - 1);
		}

		Slot = (NodeHead *)Array_GetBySubscript(&(h -> Slots), Slot_i);

		Head = (NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), Slot -> Next);
		if( Head == NULL )
			return NULL;

		return (void *)(Head + 1);

	} else {
		Head = (NodeHead *)Start - 1;

		Head = (NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), Head -> Next);
		if( Head == NULL )
			return NULL;

		return (void *)(Head + 1);
	}

}

void HashTable_Free(HashTable *h)
{
	Array_Free(&(h -> NodeChunk));
	Array_Free(&(h -> Slots));
	h -> FreeList = -1;
}
