#include <string.h>
#include "bst.h"
#include "utils.h"

int Bst_Init(Bst *t, Array *Nodes, int ElementLength, int (*Compare)(const void *, const void *))
{
	t -> Compare = Compare;
	t -> Root = -1;
	t -> FreeList = -1;

	if( Nodes == NULL )
	{
		t -> Nodes = (Array *)SafeMalloc(sizeof(Array));
		if( t -> Nodes == NULL )
		{
			return -1;
		}

		return Bst_NodesInit(t -> Nodes, ElementLength);

	} else {
		t -> Nodes = Nodes;

		return 0;
	}
}

int Bst_NodesInit(Array *Nodes, int ElementLength)
{
	return Array_Init(Nodes, ElementLength + sizeof(Bst_NodeHead), 0, FALSE, NULL);
}

static int32_t GetUnusedNode(Bst *t)
{
	if( t -> FreeList > 0 )
	{
		int32_t ReturnValue = t -> FreeList;
		const Bst_NodeHead *NextNode;

		NextNode = Array_GetBySubscript(t -> Nodes, t -> FreeList);

		t -> FreeList = NextNode -> Right;

		return ReturnValue;
	} else {
		return Array_PushBack(t -> Nodes, NULL, NULL);
	}
}

static int Add(Bst *t, int ParentNode, BOOL IsLeft, const void *Data)
{
	static const Bst_NodeHead	NewHead = {-1, -1, -1};

	int32_t	NewElement = GetUnusedNode(t);

	if( NewElement >= 0 )
	{
		Bst_NodeHead *NewZone = Array_GetBySubscript(t -> Nodes, NewElement);

		memcpy(NewZone, &NewHead, sizeof(Bst_NodeHead));

        if( ParentNode >= 0 )
        {
            Bst_NodeHead *Parent = Array_GetBySubscript(t -> Nodes, ParentNode);

			NewZone -> Parent = ParentNode;

            if( IsLeft == TRUE )
            {
                Parent -> Left = NewElement;
            } else {
                Parent -> Right = NewElement;
            }
        } else {
			NewZone -> Parent = -1;
            t -> Root = NewElement;
        }

		memcpy(NewZone + 1, Data, t -> Nodes -> DataLength - sizeof(Bst_NodeHead));
		return 0;
	} else {
		return -1;
	}
}

int Bst_Add(Bst *t, const void *Data)
{
    if( t -> Root == -1 )
    {
		return Add(t, -1, FALSE, Data);
    } else {
		int32_t CurrentNode = t -> Root;

		Bst_NodeHead *Current;

		while( TRUE )
		{
			Current = Array_GetBySubscript(t -> Nodes, CurrentNode);
			if( (t -> Compare)(Data, ((char *)Current) + sizeof(Bst_NodeHead)) <= 0 )
			{
				if( Current -> Left == -1 )
				{
					return Add(t, CurrentNode, TRUE, Data);
				} else {
					CurrentNode = Current -> Left;
				}
			} else {
				if( Current -> Right == -1 )
				{
					return Add(t, CurrentNode, FALSE, Data);
				} else {
					CurrentNode = Current -> Right;
				}
			}
		}
    }
}

const void *Bst_Search(Bst *t, const void *Data, const void *Start)
{
	int32_t			CurrentNode;
	const Bst_NodeHead	*Current;
	int					CompareResult;

	if( Start == NULL )
	{
		CurrentNode = t -> Root;
	} else {
		const Bst_NodeHead	*Next = (const Bst_NodeHead *)((char *)Start) - sizeof(Bst_NodeHead);

		CurrentNode = Next -> Left;
	}

	while( CurrentNode >= 0 )
	{
		Current = Array_GetBySubscript(t -> Nodes, CurrentNode);
		CompareResult = (t -> Compare)(Data, ((char *)Current) + sizeof(Bst_NodeHead));

		if( CompareResult < 0 )
		{
			CurrentNode = Current -> Left;
		} else if( CompareResult > 0 )
		{
			CurrentNode = Current -> Right;
		} else {
			return ((char *)Current) + sizeof(Bst_NodeHead);
		}
	}

	return  NULL;
}

int32_t *Bst_Minimum_ByNumber(Bst *t, int32_t SubTree)
{
	int32_t Left = SubTree;
	const Bst_NodeHead	*Node;

	while( Left >= 0 )
	{
		Node = Array_GetBySubscript(t -> Nodes, Left);

		SubTree = Left;
		Left = Node -> Left;
	}

	return SubTree;
}

int32_t Bst_Successor_ByNumber(Bst *t, int32_t NodeNumber)
{
	int32_t ParentNum;
	const Bst_NodeHead	*ParentNode;
	const Bst_NodeHead	*Node = Array_GetBySubscript(t -> Nodes, NodeNumber);

	if( Node -> Right >= 0 )
	{
		return Bst_Minimum_ByNumber(t, Node -> Right);
	}

	ParentNum = Node -> Parent;
	while( ParentNum >= 0 )
	{
		ParentNode = Array_GetBySubscript(t -> Nodes, ParentNum);

		if( ParentNode -> Right != NodeNumber )
		{
			break;
		}

		NodeNumber = ParentNum;
		ParentNum = ParentNode -> Parent;
	}

	return ParentNum;
}

int32_t Bst_Delete(Bst *t, int32_t NodeNumber)
{
	Bst_NodeHead *Node = Array_GetBySubscript(t -> Nodes, NodeNumber);

	if( Node -> Left < 0 || Node -> Right < 0 )
	{
		int32_t ParentNum = Node -> Parent;
		int32_t ChildNum;

		if( Node -> Right >= 0 )
		{
			ChildNum = Node -> Right;
		} else {
			ChildNum = Node -> Left;
		}

		if( ParentNum < 0 )
		{
			t -> Root = ChildNum;
		} else {
			Bst_NodeHead	*ParentNode = Array_GetBySubscript(t -> Nodes, ParentNum);
			int32_t ChildNum;

			if( ParentNode -> Right == NodeNumber )
			{
				ParentNode -> Right = ChildNum;
			} else {
				ParentNode -> Left = ChildNum;
			}
		}

		Node -> Right = t -> FreeList;
		t -> FreeList = NodeNumber;

		return NodeNumber;
	} else {
		int32_t DeletedNum = Bst_Delete(t, Bst_Successor_ByNumber(t, NodeNumber));
		Bst_NodeHead *DeletedNode = Array_GetBySubscript(t -> Nodes, DeletedNum);

		memcpy(Node + 1, DeletedNode + 1, t -> Nodes -> DataLength - sizeof(Bst_NodeHead));

        return DeletedNum;
	}
}

