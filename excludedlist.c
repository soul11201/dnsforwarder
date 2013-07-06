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
#include "domainlist.h"

static int			*DisabledTypes	=	NULL;

DomainList			DisabledDomains;
DomainList			ExcludedDomains;

static RWLock		ExcludedListLock;

BOOL IsDisabledType(int Type){
	int *Itr;

	if( DisabledTypes == NULL )
	{
		return FALSE;
	}

	for(Itr = DisabledTypes; *Itr != 0; ++Itr){
		if(*Itr == Type)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static BOOL MatchDomain(DomainList *List, const char *Domain)
{
	while( Domain != NULL )
	{
		if( DomainList_Match(List, Domain) == TRUE )
		{
			return TRUE;
		}

		if( *Domain == '.' && DomainList_Match(List, Domain + 1) == TRUE )
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

	Result = MatchDomain(&ExcludedDomains, Domain);

	RWLock_UnRLock(ExcludedListLock);
	return Result;
}

static int DisableType(void)
{
	int loop, Count = 1;
	char Tmp[10], *TmpItr;
	const char *Types = ConfigGetString(&ConfigInfo, "DisabledType");

	if(Types == NULL) return 0;

	for(loop = 0; Types[loop] != '\0'; ++loop)
		if(Types[loop] == ',') ++Count;

	DisabledTypes = (int *)SafeMalloc((Count + 1) * sizeof(*(DisabledTypes)));
	DisabledTypes[Count--] = 0;

	for(loop = 0, TmpItr = Tmp; ; ++loop){
		if(Types[loop] == '\0'){
			*TmpItr = '\0';
			DisabledTypes[Count--] = atoi(Tmp);
			break;
		}
		if(Types[loop] != ',')
			*TmpItr++ = Types[loop];
		else{
			*TmpItr = '\0';
			DisabledTypes[Count--] = atoi(Tmp);
			TmpItr = Tmp;
		}
	}
	return 0;
}

static int LoadDomains(DomainList *List, const char *Domains, int ApproximateCount)
{
	StringList TmpList;

	const char *Str;

	if( StringList_Init(&TmpList, Domains, ',') < 0 )
		return -1;

	if( DomainList_Init(List, ApproximateCount) < 0 )
	{
		StringList_Free(&TmpList);
		return -2;
	}

	Str = StringList_GetNext(&TmpList, NULL);
	while( Str != NULL )
	{
		if( DomainList_Add(List, Str) != 0 )
		{
			StringList_Free(&TmpList);
			DomainList_Free(List);
			return -3;
		}
		Str = StringList_GetNext(&TmpList, Str);
	}

	StringList_Free(&TmpList);
	return 0;
}


static BOOL ParseGfwListItem(char *Item)
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

	if( DomainList_Match(&ExcludedDomains, Item) == FALSE )
	{
		DomainList_Add(&ExcludedDomains, Item);
		return TRUE;
	} else {
		return FALSE;
	}

}

static int LoadGfwListFile(const char *File)
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
				if( ParseGfwListItem(Buffer) == TRUE )
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

			INFO("GFW List saved at %s.\n", File);

			if( (NeedBase64Decode == TRUE) && (Base64Decode(File) != 0) )
			{
				ERRORMSG("Decoding GFW List failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
				SLEEP(FlushTimeOnFailed * 1000);
				continue;
			}

			RWLock_WrLock(ExcludedListLock);

			DomainList_Free(&ExcludedDomains);

			LoadDomains(&ExcludedDomains, ExcludedList, 2000);

			Count = LoadGfwListFile(File);
			if( Count < 0 )
			{
				ERRORMSG("Loading GFW List failed, cannot open file %s.\n", File);
				RWLock_UnWLock(ExcludedListLock);
				goto END;
			}

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

	RWLock_WrLock(ExcludedListLock);

	DomainList_Free(&ExcludedDomains);

	LoadDomains(&ExcludedDomains, ExcludedList, 2000);

	Count = LoadGfwListFile(File);
	if( Count < 0 )
	{
		RWLock_UnWLock(ExcludedListLock);
		goto END;
	}

	RWLock_UnWLock(ExcludedListLock);
	INFO("Loading the existing GFW List completed. %d effective items.\n", Count);

END:
	CREATE_THREAD(LoadGfwList_Thread, NULL, gt);

	DETACH_THREAD(gt);

	return 0;
}

int ExcludedList_Init(void)
{
	DisabledTypes = NULL;

	LoadDomains(&DisabledDomains, ConfigGetString(&ConfigInfo, "DisabledDomain"), 31);
	LoadDomains(&ExcludedDomains, ConfigGetString(&ConfigInfo, "ExcludedDomain"), 31);
	DisableType();

	RWLock_Init(ExcludedListLock);

	INFO("Excluded & Disabled list initialized.\n");
	return 0;
}
