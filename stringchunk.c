#include <string.h>
#include "stringchunk.h"
#include "utils.h"

typedef struct _EntryForString{
	_32BIT_INT	OffsetOfString;
	_32BIT_INT	OffsetOfData;
} EntryForString;

int StringChunk_Init(StringChunk *dl)
{
	if( dl == NULL )
	{
		return 0;
	}

	if( StringList_Init(&(dl -> List), NULL, 0) != 0 )
	{
		return -1;
	}

	if( SimpleHT_Init(&(dl -> List_Pos), sizeof(EntryForString), 5, ELFHash) != 0 )
	{
		StringList_Free(&(dl -> List));
		return -2;
	}

	if( StringList_Init(&(dl -> List_W), NULL, 0) != 0 )
	{
		StringList_Free(&(dl -> List));
		SimpleHT_Free(&(dl -> List_Pos));
		return -3;
	}

	if( Array_Init(&(dl -> List_W_Pos), sizeof(EntryForString), 0, FALSE, NULL) != 0 )
	{
		StringList_Free(&(dl -> List));
		SimpleHT_Free(&(dl -> List_Pos));
		StringList_Free(&(dl -> List_W));
		return -4;
	}

	if( ExtendableBuffer_Init(&(dl -> AdditionalDataChunk), 0, -1) != 0 )
	{
		StringList_Free(&(dl -> List));
		SimpleHT_Free(&(dl -> List_Pos));
		StringList_Free(&(dl -> List_W));
		Array_Free(&(dl -> List_W_Pos));
		return -5;
	}

	return 0;
}

int StringChunk_Add(StringChunk	*dl,
					const char	*Str,
					const char	*AdditionalData,
					int			LengthOfAdditionalData /* The length will not be stored. */
					)
{
	EntryForString NewEntry;

	if( AdditionalData != NULL && LengthOfAdditionalData > 0 )
	{
		_32BIT_INT OffsetOfStoredTo;

		char *DataStoredTo =
						ExtendableBuffer_Expand(&(dl -> AdditionalDataChunk),
						LengthOfAdditionalData,
						&OffsetOfStoredTo
						);

		if( DataStoredTo == NULL )
		{
			return -1;
		}

		NewEntry.OffsetOfData = OffsetOfStoredTo;

		memcpy(DataStoredTo, AdditionalData, LengthOfAdditionalData);

	} else {
		NewEntry.OffsetOfData = -1;
	}

	if( ContainWildCard(Str) )
	{
		NewEntry.OffsetOfString = StringList_Add(&(dl -> List_W), Str, ',');

		if( NewEntry.OffsetOfString >= 0 )
		{
			Array_PushBack(&(dl -> List_W_Pos), &NewEntry, NULL);
		} else {
			return -1;
		}
	} else {
		NewEntry.OffsetOfString = StringList_Add(&(dl -> List), Str, ',');

		if( NewEntry.OffsetOfString >= 0 )
		{
			SimpleHT_Add(&(dl -> List_Pos), Str, 0, (const char *)&NewEntry, NULL);
		} else {
			return -2;
		}
	}

	return 0;

}

BOOL StringChunk_Match_NoWildCard(StringChunk	*dl,
								  const char	*Str,
								  int			*HashValue,
								  char			**Data
								  )
{
	EntryForString *FoundEntry;

	const char *FoundString;

	FoundEntry = (EntryForString *)SimpleHT_Find(&(dl -> List_Pos), Str, 0, HashValue, NULL);
	while( FoundEntry != NULL )
	{
		FoundString = StringList_GetByOffset(&(dl -> List),
											 FoundEntry -> OffsetOfString
											 );
		if( strcmp(FoundString, Str) == 0 )
		{
			if( FoundEntry -> OffsetOfData >=0 && Data != NULL )
			{
				*Data = ExtendableBuffer_GetPositionByOffset(
												&(dl -> AdditionalDataChunk),
												FoundEntry -> OffsetOfData
												);
			}

			return TRUE;
		}

		FoundEntry = (EntryForString *)SimpleHT_Find(&(dl -> List_Pos), Str, 0, HashValue, (const char *)FoundEntry);
	}

	return FALSE;

}

BOOL StringChunk_Match_OnlyWildCard(StringChunk	*dl,
									const char	*Str,
									char		**Data
									)
{
	EntryForString *FoundEntry;

	const char *FoundString;

	int loop;

	for( loop = 0; loop != Array_GetUsed(&(dl -> List_W_Pos)); ++loop )
	{
		FoundEntry = (EntryForString *)Array_GetBySubscript(&(dl -> List_W_Pos), loop);
		if( FoundEntry != NULL )
		{
			FoundString = StringList_GetByOffset(&(dl -> List_W), FoundEntry -> OffsetOfString);
			if( WILDCARD_MATCH(FoundString, Str) == WILDCARD_MATCHED )
			{
				if( FoundEntry -> OffsetOfData >=0 && Data != NULL )
				{
					*Data = ExtendableBuffer_GetPositionByOffset(
													&(dl -> AdditionalDataChunk),
													FoundEntry -> OffsetOfData
													);
				}
				return TRUE;
			}

		} else {
			return FALSE;
		}
	}

	return FALSE;
}

BOOL StringChunk_Match(StringChunk *dl, const char *Str, int *HashValue, char **Data)
{
	if( StringChunk_Match_NoWildCard(dl, Str, HashValue, Data) == TRUE ||
		StringChunk_Match_OnlyWildCard(dl, Str, Data) == TRUE
		)
	{
		return TRUE;
	} else {
		return FALSE;
	}
}

const char *StringChunk_Enum(StringChunk *dl, const char *Start, char **Data)
{
	const char *str;

	str = StringList_GetNext(&(dl -> List), Start);

	if( str == NULL )
	{
		str = StringList_GetNext(&(dl -> List_W), Start);
	}

	if( str == NULL )
	{
		return NULL;
	}

	StringChunk_Match(dl, str, NULL, Data);

	return str;
}

void StringChunk_Free(StringChunk *dl)
{
	StringList_Free(&(dl -> List));
	SimpleHT_Free(&(dl -> List_Pos));
	StringList_Free(&(dl -> List_W));
	Array_Free(&(dl -> List_W_Pos));
	ExtendableBuffer_Free(&(dl -> AdditionalDataChunk));
}
