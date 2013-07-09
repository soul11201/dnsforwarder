#include "stringchunk.h"
#include "utils.h"

typedef struct _EntryForDomain{
	_32BIT_INT	Offset;
} EntryForDomain;

int StringChunk_Init(StringChunk *dl, int InitialCount /* For no-wildcard domain */)
{
	if( StringList_Init(&(dl -> List), NULL, 0) != 0 )
	{
		return -1;
	}

	if( HashTable_Init(&(dl -> List_Pos), sizeof(EntryForDomain), InitialCount) != 0 )
	{
		StringList_Free(&(dl -> List));
		return -2;
	}

	if( StringList_Init(&(dl -> List_W), NULL, 0) != 0 )
	{
		StringList_Free(&(dl -> List));
		HashTable_Free(&(dl -> List_Pos));
		return -3;
	}

	if( Array_Init(&(dl -> List_W_Pos), sizeof(EntryForDomain), 0, FALSE, NULL) != 0 )
	{
		StringList_Free(&(dl -> List));
		HashTable_Free(&(dl -> List_Pos));
		StringList_Free(&(dl -> List_W));
		return -4;
	}

	return 0;
}

int StringChunk_Add(StringChunk *dl, const char *Domain)
{
	EntryForDomain NewEntry;

	if( ContainWildCard(Domain) )
	{
		NewEntry.Offset = StringList_Add(&(dl -> List_W), Domain);

		if( NewEntry.Offset >= 0 )
		{
			Array_PushBack(&(dl -> List_W_Pos), &NewEntry, NULL);
			return 0;
		} else {
			return -1;
		}
	} else {
		NewEntry.Offset = StringList_Add(&(dl -> List), Domain);

		if( NewEntry.Offset >= 0 )
		{
			HashTable_Add(&(dl -> List_Pos), Domain, &NewEntry);
			return 0;
		} else {
			return -2;
		}
	}

}

BOOL StringChunk_Match_NoWildCard(StringChunk *dl, const char *Str)
{
	EntryForDomain *FoundEntry;

	const char *FoundString;

	FoundEntry = HashTable_Get(&(dl -> List_Pos), Str, NULL);
	while( FoundEntry != NULL )
	{
		FoundString = StringList_GetByOffset(&(dl -> List), FoundEntry -> Offset);
		if( strcmp(FoundString, Str) == 0 )
		{
			return TRUE;
		}

		FoundEntry = HashTable_Get(&(dl -> List_Pos), Str, FoundEntry);
	}

	return FALSE;

}

BOOL StringChunk_Match_OnlyWildCard(StringChunk *dl, const char *Str)
{
	EntryForDomain *FoundEntry;

	const char *FoundString;

	int loop;

	for( loop = 0; loop != Array_GetUsed(&(dl -> List_W_Pos)); ++loop )
	{
		FoundEntry = (EntryForDomain *)Array_GetBySubscript(&(dl -> List_W_Pos), loop);
		if( FoundEntry != NULL )
		{
			FoundString = StringList_GetByOffset(&(dl -> List_W), FoundEntry -> Offset);
			if( WILDCARD_MATCH(FoundString, Str) == WILDCARD_MATCHED )
			{
				return TRUE;
			}

		} else {
			return FALSE;
		}
	}

	return FALSE;
}

BOOL StringChunk_Match(StringChunk *dl, const char *Str)
{
	if( StringChunk_Match_NoWildCard(dl, Str) == TRUE ||
		StringChunk_Match_OnlyWildCard(dl, Str) == TRUE
		)
	{
		return TRUE;
	} else {
		return FALSE;
	}
}

void StringChunk_Free(StringChunk *dl)
{
	StringList_Free(&(dl -> List));
	HashTable_Free(&(dl -> List_Pos));
	StringList_Free(&(dl -> List_W));
	Array_Free(&(dl -> List_W_Pos));
}
