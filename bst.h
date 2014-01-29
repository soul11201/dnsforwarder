#ifndef BST_H_INCLUDED
#define BST_H_INCLUDED

#include "array.h"

typedef struct _Bst_NodeHead{
	_32BIT_INT	Left;
	_32BIT_INT	Right;
} Bst_NodeHead;

typedef struct _Bst {
	Array		Nodes;

	_32BIT_INT	Root;

	int		(*Compare)(const void *, const void *);
} Bst;

int Bst_Init(Bst *t, int ElementLength, int (*Compare)(const void *, const void *));

int Bst_Add(Bst *t, const void *Data);

const void *Bst_Search(Bst *t, const void *Data, const void *Start);

#endif // BST_H_INCLUDED
