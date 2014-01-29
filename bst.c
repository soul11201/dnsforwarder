#include "string.h"
#include "bst.h"

int Bst_Init(Bst *t, int ElementLength, int (*Compare)(const void *, const void *))
{
	t -> Compare = Compare;
	t -> Root = -1;

	return Array_Init(&(t -> Nodes), ElementLength + sizeof(Bst_NodeHead), 0, FALSE, NULL);
}

static int Add(Bst *t, int ParentNode, BOOL IsLeft, const void *Data)
{
	static const Bst_NodeHead	NewHead = {-1, -1};

	_32BIT_INT	NewElement = Array_PushBack(&(t -> Nodes), NULL, NULL);

	if( NewElement >= 0 )
	{
		char *NewZone = Array_GetBySubscript(&(t -> Nodes), NewElement);

        if( ParentNode >= 0 )
        {
            Bst_NodeHead *Parent = Array_GetBySubscript(&(t -> Nodes), ParentNode);

            if( IsLeft == TRUE )
            {
                Parent -> Left = NewElement;
            } else {
                Parent -> Right = NewElement;
            }
        } else {
            t -> Root = NewElement;
        }

		memcpy(NewZone, &NewHead, sizeof(Bst_NodeHead));
		memcpy(NewZone + sizeof(Bst_NodeHead), Data, t -> Nodes.DataLength - sizeof(Bst_NodeHead));
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
		_32BIT_INT CurrentNode = t -> Root;

		Bst_NodeHead *Current;

		while( TRUE )
		{
			Current = Array_GetBySubscript(&(t -> Nodes), CurrentNode);
			if( (t -> Compare)(((char *)Current) + sizeof(Bst_NodeHead), Data) <= 0 )
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
	_32BIT_INT			CurrentNode;
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
		Current = Array_GetBySubscript(&(t -> Nodes), CurrentNode);
		CompareResult = (t -> Compare)(((char *)Current) + sizeof(Bst_NodeHead), Data);

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
