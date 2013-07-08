#ifndef STRINGCHUNK_H_INCLUDED
#define STRINGCHUNK_H_INCLUDED

#include "hashtable.h"
#include "stringlist.h"
#include "array.h"

typedef struct _StringChunk{
	/* Domains without wildcards */
	StringList	List;

	/* Positions of every domain in `List', offsets */
	HashTable	List_Pos;


	/* Domains containing wildcards */
	StringList	List_W;

	/* Positions of every domain in `List_W', offsets */
	Array		List_W_Pos;

} StringChunk;

int StringChunk_Init(StringChunk *dl, int InitialCount /* For no-wildcard domain */);

int StringChunk_Add(StringChunk *dl, const char *Domain);

BOOL StringChunk_Match_NoWildCard(StringChunk *dl, const char *Str);

BOOL StringChunk_Match_OnlyWildCard(StringChunk *dl, const char *Str);

BOOL StringChunk_Match(StringChunk *dl, const char *Str);

void StringChunk_Free(StringChunk *dl);

#endif // STRINGCHUNK_H_INCLUDED
