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

static BOOL MatchDomain(StringChunk *List, const char *Domain, int *HashValue)
{
	if( List == NULL )
	{
		return FALSE;
	}

	if( StringChunk_Match(List, Domain, HashValue, NULL) == TRUE )
	{
		return TRUE;
	}

	Domain = strchr(Domain + 1, '.');

	while( Domain != NULL )
	{
		if( StringChunk_Match_NoWildCard(List, Domain, NULL, NULL) == TRUE ||
			StringChunk_Match_NoWildCard(List, Domain + 1, NULL, NULL) == TRUE
			)
		{
			return TRUE;
		}

		Domain = strchr(Domain + 1, '.');
	}

	return FALSE;
}

BOOL IsDisabledDomain(const char *Domain, int *HashValue){
	return MatchDomain(&DisabledDomains, Domain, HashValue);
}

BOOL IsExcludedDomain(const char *Domain, int *HashValue)
{
	BOOL Result;

	RWLock_RdLock(ExcludedListLock);

	Result = MatchDomain((StringChunk *)&(MainExcludedContainer -> ExcludedDomains), Domain, HashValue);

	RWLock_UnRLock(ExcludedListLock);
	return Result;
}

static int LoadDisableType(void)
{
	const StringList *DisableType_Str = ConfigGetStringList(&ConfigInfo, "DisabledType");

	const char *OneTypePendingToAdd_Str;
	int OneTypePendingToAdd;

	Array_Init(&DisabledTypes, sizeof(int), 0, FALSE, NULL);

	if( DisableType_Str == NULL )
	{
		return 0;
	}

	OneTypePendingToAdd_Str = StringList_GetNext(DisableType_Str, NULL);
	while( OneTypePendingToAdd_Str != NULL )
	{
		sscanf(OneTypePendingToAdd_Str, "%d", &OneTypePendingToAdd);
		Array_PushBack(&DisabledTypes, &OneTypePendingToAdd, NULL);

		OneTypePendingToAdd_Str = StringList_GetNext(DisableType_Str, OneTypePendingToAdd_Str);
	}

	return 0;
}

static int LoadDomains(StringChunk *List, const StringList *Domains, int ApproximateCount)
{
	const char *Str;

	if( StringChunk_Init(List, ApproximateCount) < 0 )
	{
		return -1;
	}

	if( Domains == NULL )
	{
		return 0;
	}

	Str = StringList_GetNext(Domains, NULL);
	while( Str != NULL )
	{
		if( *Str == '.' )
		{
			Str++;
		}

		if( StringChunk_Add(List, Str, NULL, 0) != 0 )
		{
			return -2;
		}
		Str = StringList_GetNext(Domains, Str);
	}

	return 0;
}


static BOOL ParseGfwListItem(char *Item, ExcludedContainer *Container)
{
	char *Itr = NULL;

	if( strchr(Item, '/') != NULL || *Item == '@' || strchr(Item, '?') != NULL || *Item == '!' || strchr(Item, '.') == NULL || *Item == '[' )
	{
		return FALSE;
	}

	if( strchr(Item, '*') != NULL )
	{
		if( strstr("wikipedia.org", Item) == 0 )
		{
			Itr = strchr(Item + 13, '*');
			if( Itr != NULL )
			{
				*Itr = '\0';
			}
		} else {
			return FALSE;
		}
	}

	if( *Item == '|' )
	{
		for(++Item; *Item == '|'; ++Item);
	}

	if( *Item == '.' )
	{
		++Item;
	}

	if( strncmp("http://", Item, 7) == 0 )
	{
		Item += 7;
	}

	if( strncmp("https://", Item, 8) == 0 )
	{
		Item += 8;
	}

	Itr = strchr(Item, '/');
	if( Itr != NULL )
	{
		*Itr = '\0';
	}

	if( strchr(Item, '%') != NULL )
	{
		return FALSE;
	}

	if( MatchDomain(&(Container -> ExcludedDomains), Item, NULL) == FALSE )
	{
		StringChunk_Add(&(Container -> ExcludedDomains), Item, NULL, 0);
		return TRUE;
	} else {
		return FALSE;
	}

}

static int LoadGfwListFile(const char *File, const StringList *ExcludedList, BOOL NeedBase64Decode)
{
	FILE	*fp;
	ReadLineStatus Status;
	char	Buffer[256];
	int		Count = 0;

	ExcludedContainer *Container;

	if( (NeedBase64Decode == TRUE) && (Base64Decode(File) != 0) )
	{
		return -1;
	}

	fp = fopen(File, "r");
	if( fp == NULL )
	{
		return -2;
	}

	Container = SafeMalloc(sizeof(ExcludedContainer));
	if( Container == NULL )
	{
		return -3;
	}

	LoadDomains(&(Container -> ExcludedDomains), ExcludedList, 2000);

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
				INFO("GFWList Item is too long : %s\n", Buffer);
				ReadLine_GoToNextLine(fp);
				break;
		}
	}

DONE:
	fclose(fp);

	if( Count == 0 )
	{
		StringChunk_Free((StringChunk *)&(Container -> ExcludedDomains));
		SafeFree(Container);
		return -4;
	}

	/* Evict old container */
	RWLock_WrLock(ExcludedListLock);

	StringChunk_Free((StringChunk *)&(MainExcludedContainer -> ExcludedDomains));
	SafeFree((void *)MainExcludedContainer);

	MainExcludedContainer = Container;

	RWLock_UnWLock(ExcludedListLock);

	return Count;

}

int LoadGfwList_Thread(void *Unused)
{
	int	FlushTime			=	ConfigGetInt32(&ConfigInfo, "GfwListUpdateInterval");
	int	FlushTimeOnFailed	=	ConfigGetInt32(&ConfigInfo, "GfwListRetryInterval");

	const char			*GfwList			=	ConfigGetRawString(&ConfigInfo, "GfwList");
	const StringList	*ExcludedList		=	ConfigGetStringList(&ConfigInfo, "ExcludedDomain");
	const char			*File				=	ConfigGetRawString(&ConfigInfo, "GfwListDownloadPath");
	BOOL				NeedBase64Decode	=	ConfigGetBoolean(&ConfigInfo, "GfwListBase64Decode");
	int					Count;

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
			INFO("GFW List saved at %s.\n", File);

			Count = LoadGfwListFile(File, ExcludedList, NeedBase64Decode);

			switch( Count )
			{
				case -1:
				case -2:
				case -3:
					break;

				case -4:
					ERRORMSG("Loading GFW List failed, cannot open file %s.\n", File);
					break;

				default:
					INFO("Loading GFW List completed. %d effective items.\n", Count);
					SLEEP(FlushTime * 1000);
					continue;
					break;
			}

			if( FlushTime < 0 )
			{
				return 0;
			}

		}
	}
}

int LoadGfwList(void)
{
	ThreadHandle gt;
	const char	*GfwList	=	ConfigGetRawString(&ConfigInfo, "GfwList");
	const char	*File	=	ConfigGetRawString(&ConfigInfo, "GfwListDownloadPath");
	const StringList *ExcludedList	=	ConfigGetStringList(&ConfigInfo, "ExcludedDomain");
	char		*ProtocolStr	=	(char *)ConfigGetRawString(&ConfigInfo, "PrimaryServer");
	int			Count;

	if( GfwList == NULL )
	{
		return 0;
	}

	StrToLower(ProtocolStr);

	if( strncmp(ProtocolStr, "udp", 3) != 0 )
	{
		ERRORMSG("Cannot load GFW List because `PrimaryServer' is not udp.\n");
		return -1;
	}

	if( FileIsReadable(File) )
	{
		INFO("Loading the existing GFW List ...\n");

		Count = LoadGfwListFile(File, ExcludedList, FALSE);

		switch( Count )
		{
			case -1:
			case -2:
			case -3:
				break;

			case -4:
				ERRORMSG("Loading the existing GFW List failed, cannot open file %s.\n", File);
				break;

			default:
				INFO("Loading the existing GFW List completed. %d effective items.\n", Count);
				break;
		}
	}

	CREATE_THREAD(LoadGfwList_Thread, NULL, gt);
	DETACH_THREAD(gt);

	return 0;
}

int ExcludedList_Init(void)
{

	LoadDomains(&DisabledDomains, ConfigGetStringList(&ConfigInfo, "DisabledDomain"), 31);

	StringList_Free(ConfigGetStringList(&ConfigInfo, "DisabledDomain"));

	MainExcludedContainer = SafeMalloc(sizeof(ExcludedContainer));

	if( MainExcludedContainer != NULL )
	{
		LoadDomains((StringChunk *)&(MainExcludedContainer -> ExcludedDomains), ConfigGetStringList(&ConfigInfo, "ExcludedDomain"), 31);
	} else {
		return -1;
	}

	LoadDisableType();

	RWLock_Init(ExcludedListLock);

	INFO("Excluded & Disabled list initialized.\n");
	return 0;
}
