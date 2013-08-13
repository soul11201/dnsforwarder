#include <string.h>
#include <time.h>
#include "excludedlist.h"
#include "querydnsbase.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "array.h"
#include "common.h"
#include "rwlock.h"
#include "stringchunk.h"
#include "array.h"
#include "stringlist.h"

static Array		DisabledTypes;

static StringChunk	DisabledDomains;

typedef struct _ExcludedContainer{
	StringChunk	ExcludedDomains;
} ExcludedContainer;

static volatile ExcludedContainer *MainExcludedContainer = NULL;

/* static StringChunk	ExcludedDomains; */

static RWLock		ExcludedListLock;

BOOL IsDisabledType(int Type)
{
	int Itr = 0;

	int	*TypeInArray = (int *)Array_GetBySubscript(&DisabledTypes, Itr);

	while( TypeInArray != NULL )
	{
		if( Type == *TypeInArray )
		{
			return TRUE;
		}

		++Itr;
		TypeInArray = (int *)Array_GetBySubscript(&DisabledTypes, Itr);
	}

	return FALSE;
}

static BOOL MatchDomain(StringChunk *List, const char *Domain)
{
	if( List == NULL )
	{
		return FALSE;
	}

	if( StringChunk_Match(List, Domain, NULL) == TRUE )
	{
		return TRUE;
	}

	Domain = strchr(Domain + 1, '.');

	while( Domain != NULL )
	{
		if( StringChunk_Match_NoWildCard(List, Domain, NULL) == TRUE ||
			StringChunk_Match_NoWildCard(List, Domain + 1, NULL) == TRUE
			)
		{
			return TRUE;
		}

		Domain = strchr(Domain + 1, '.');
	}

	return FALSE;
}

BOOL IsDisabledDomain(const char *Domain){
	return MatchDomain(&DisabledDomains, Domain);
}

BOOL IsExcludedDomain(const char *Domain)
{
	BOOL Result;

	RWLock_RdLock(ExcludedListLock);

	Result = MatchDomain(&(MainExcludedContainer -> ExcludedDomains), Domain);

	RWLock_UnRLock(ExcludedListLock);
	return Result;
}

static int LoadDisableType(void)
{
	StringList DisableType_Str;
	const char *Types = ConfigGetString(&ConfigInfo, "DisabledType");
	int NumberOfTypes;

	const char *OneTypePendingToAdd_Str;
	int OneTypePendingToAdd;

	if( Types == NULL )
	{
		Array_Init(&DisabledTypes, sizeof(int), 0, FALSE, NULL);
		return 0;
	}

	NumberOfTypes = StringList_Init(&DisableType_Str, Types, ',');
	if( NumberOfTypes <= 0 )
	{
		Array_Init(&DisabledTypes, sizeof(int), 0, FALSE, NULL);
		return 0;
	}

	if( Array_Init(&DisabledTypes, sizeof(int), NumberOfTypes, FALSE, NULL) != 0 )
	{
		Array_Init(&DisabledTypes, sizeof(int), 0, FALSE, NULL);
		StringList_Free(&DisableType_Str);
		return 1;
	}

	OneTypePendingToAdd_Str = StringList_GetNext(&DisableType_Str, NULL);
	while( OneTypePendingToAdd_Str != NULL )
	{
		sscanf(OneTypePendingToAdd_Str, "%d", &OneTypePendingToAdd);
		Array_PushBack(&DisabledTypes, &OneTypePendingToAdd, NULL);

		OneTypePendingToAdd_Str = StringList_GetNext(&DisableType_Str, OneTypePendingToAdd_Str);
	}

	StringList_Free(&DisableType_Str);

	return 0;
}

static int LoadDomains(StringChunk *List, const char *Domains, int ApproximateCount)
{
	StringList TmpList;

	const char *Str;

	if( StringList_Init(&TmpList, Domains, ',') < 0 )
		return -1;

	if( StringChunk_Init(List, ApproximateCount) < 0 )
	{
		StringList_Free(&TmpList);
		return -2;
	}

	Str = StringList_GetNext(&TmpList, NULL);
	while( Str != NULL )
	{
		if( StringChunk_Add(List, Str, NULL, 0) != 0 )
		{
			StringList_Free(&TmpList);
			StringChunk_Free(List);

			return -3;
		}
		Str = StringList_GetNext(&TmpList, Str);
	}

	StringList_Free(&TmpList);
	return 0;
}


static BOOL ParseGfwListItem(char *Item, ExcludedContainer *Container)
{
	if( strchr(Item, '/') != NULL || strchr(Item, '*') != NULL || *Item == '@' || strchr(Item, '?') != NULL || *Item == '!' || strchr(Item, '.') == NULL || *Item == '[' )
	{
		return FALSE;
	}

	if( *Item == '|' )
	{
		for(++Item; *Item == '|'; ++Item);
	}

	if( *Item == '.' )
	{
		++Item;
	}

	if( MatchDomain(&(Container -> ExcludedDomains), Item) == FALSE )
	{
		StringChunk_Add(&(Container -> ExcludedDomains), Item, NULL, 0);
		return TRUE;
	} else {
		return FALSE;
	}

}

static int LoadGfwListFile(const char *File, ExcludedContainer *Container)
{
	FILE	*fp = fopen(File, "r");
	ReadLineStatus Status;
	char	Buffer[64];
	int		Count = 0;

	if( fp == NULL )
	{
		return -1;
	}

	while(TRUE)
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));

		switch(Status)
		{
			case READ_FAILED_OR_END:
				goto DONE;
				break;

			case READ_DONE:
				if( ParseGfwListItem(Buffer, Container) == TRUE )
				{
					++Count;
				}
				break;

			case READ_TRUNCATED:
				ReadLine_GoToNextLine(fp);
				break;
		}
	}

DONE:
	fclose(fp);

	return Count;

}

int LoadGfwList_Thread(void *Unused)
{
	int	FlushTime = ConfigGetInt32(&ConfigInfo, "GfwListFlushTime");
	int	FlushTimeOnFailed = ConfigGetInt32(&ConfigInfo, "GfwListFlushTimeOnFailed");

	const char	*GfwList	=	ConfigGetString(&ConfigInfo, "GfwList");
	const char	*ExcludedList	=	ConfigGetString(&ConfigInfo, "ExcludedDomain");
	const char	*File	=	ConfigGetString(&ConfigInfo, "GfwListDownloadPath");
	const BOOL	NeedBase64Decode	=	ConfigGetBoolean(&ConfigInfo, "GfwListBase64Decode");
	int			Count;

	if( GfwList == NULL )
	{
		return 0;
	}

	if( FlushTimeOnFailed < 0 )
	{
		FlushTimeOnFailed = 0;
	}

	while( TRUE )
	{
		INFO("Loading GFW List From %s ...\n", GfwList);
		if( GetFromInternet(GfwList, File) != 0 )
		{
			ERRORMSG("Downloading GFW List failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
			SLEEP(FlushTimeOnFailed * 1000);
		} else {

			ExcludedContainer *NewContainer = NULL;

			INFO("GFW List saved at %s.\n", File);

			if( (NeedBase64Decode == TRUE) && (Base64Decode(File) != 0) )
			{
				ERRORMSG("Decoding GFW List failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
				SLEEP(FlushTimeOnFailed * 1000);
				continue;
			}

			NewContainer = SafeMalloc(sizeof(ExcludedContainer));
			if( NewContainer == NULL )
			{
				INFO("Loading GFW List failed, no enough memory?\n");
				goto END;
			}

			LoadDomains(&(NewContainer -> ExcludedDomains), ExcludedList, 2000);

			Count = LoadGfwListFile(File, NewContainer);
			if( Count < 0 )
			{
				StringChunk_Free(&(NewContainer -> ExcludedDomains));
				SafeFree(NewContainer);
				ERRORMSG("Loading GFW List failed, cannot open file %s.\n", File);
				goto END;
			}

			RWLock_WrLock(ExcludedListLock);

			StringChunk_Free(&(MainExcludedContainer -> ExcludedDomains));
			SafeFree(MainExcludedContainer);
			MainExcludedContainer = NewContainer;

			RWLock_UnWLock(ExcludedListLock);
			INFO("Loading GFW List completed. %d effective items.\n", Count);
END:
			if( FlushTime < 0 )
			{
				return 0;
			}

			SLEEP(FlushTime * 1000);
		}
	}
}

int LoadGfwList(void)
{
	ThreadHandle gt;
	const char	*GfwList	=	ConfigGetString(&ConfigInfo, "GfwList");
	const char	*File	=	ConfigGetString(&ConfigInfo, "GfwListDownloadPath");
	const char	*ExcludedList	=	ConfigGetString(&ConfigInfo, "ExcludedDomain");
	char		ProtocolStr[8] = {0};
	int			Count;

	ExcludedContainer *NewContainer = NULL;

	strncpy(ProtocolStr, ConfigGetString(&ConfigInfo, "PrimaryServer"), 3);
	StrToLower(ProtocolStr);

	if( GfwList == NULL )
	{
		return 0;
	}

	if( strcmp(ProtocolStr, "udp") != 0 )
	{
		ERRORMSG("Cannot load GFW List because `PrimaryServer' is not udp.\n");
		return -1;
	}

	if( !FileIsReadable(File) )
	{
		goto END;
	}

	INFO("Loading the existing GFW List ...\n");

	NewContainer = SafeMalloc(sizeof(ExcludedContainer));
	if( NewContainer == NULL )
	{
		INFO("Loading the existing GFW List failed, no enough memory?\n");
		goto END;
	}

	LoadDomains(&(NewContainer -> ExcludedDomains), ExcludedList, 2000);

	Count = LoadGfwListFile(File, NewContainer);
	if( Count < 0 )
	{
		StringChunk_Free(&(NewContainer -> ExcludedDomains));
		SafeFree(NewContainer);
		goto END;
	}

	RWLock_WrLock(ExcludedListLock);

	StringChunk_Free(&(MainExcludedContainer -> ExcludedDomains));
	SafeFree(MainExcludedContainer);
	MainExcludedContainer = NewContainer;

	RWLock_UnWLock(ExcludedListLock);

	INFO("Loading the existing GFW List completed. %d effective items.\n", Count);

END:
	CREATE_THREAD(LoadGfwList_Thread, NULL, gt);

	DETACH_THREAD(gt);

	return 0;
}

int ExcludedList_Init(void)
{

	LoadDomains(&DisabledDomains, ConfigGetString(&ConfigInfo, "DisabledDomain"), 31);

	MainExcludedContainer = SafeMalloc(sizeof(ExcludedContainer));

	if( MainExcludedContainer != NULL )
	{
		LoadDomains(&(MainExcludedContainer -> ExcludedDomains), ConfigGetString(&ConfigInfo, "ExcludedDomain"), 31);
	}

	LoadDisableType();

	RWLock_Init(ExcludedListLock);

	INFO("Excluded & Disabled list initialized.\n");
	return 0;
}
