#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include "hosts.h"
#include "hashtable.h"
#include "dnsrelated.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "stringlist.h"
#include "querydnsbase.h"
#include "rwlock.h"
#include "stringchunk.h"

static BOOL			Inited = FALSE;

static BOOL			Internet = FALSE;

static int			FlushTime;

static time_t		LastFlush = 0;

static const char 	*File = NULL;

static ThreadHandle	GetHosts_Thread;

static RWLock		HostsLock;


typedef struct _OffsetOrAddress{
	_32BIT_INT	Offset;
} OffsetOfHosts;

typedef struct _HostsContainer{
	StringChunk	Ipv4Hosts;
	StringChunk	Ipv6Hosts;
	StringChunk	CNameHosts;
	StringChunk	ExcludedDomains;
/*	StringChunk	ExcludedIPs;*/

	ExtendableBuffer	IPs;
} HostsContainer;

volatile HostsContainer	*MainContainer = NULL;

/* These two below once inited, is never changed */
static StringList	AppendedHosts;
static int			AppendedNum = 0;

typedef enum _HostsRecordType{
	HOSTS_TYPE_UNKNOWN = 0,
	HOSTS_TYPE_WILDCARD_MASK = 1,

	HOSTS_TYPE_A = 1 << 1,
	HOSTS_TYPE_A_W = HOSTS_TYPE_A | HOSTS_TYPE_WILDCARD_MASK,

	HOSTS_TYPE_AAAA = 1 << 2,
	HOSTS_TYPE_AAAA_W = HOSTS_TYPE_AAAA | HOSTS_TYPE_WILDCARD_MASK,

	HOSTS_TYPE_CNAME = 1 << 3,
	HOSTS_TYPE_CNAME_W = HOSTS_TYPE_CNAME | HOSTS_TYPE_WILDCARD_MASK,

	HOSTS_TYPE_EXCLUEDE = 1 << 4,
	HOSTS_TYPE_EXCLUEDE_W = HOSTS_TYPE_EXCLUEDE | HOSTS_TYPE_WILDCARD_MASK

}HostsRecordType;

static HostsRecordType Edition(const char *item)
{
	HostsRecordType WildCard;

	if( item == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	for(; isspace(*item); ++item);

	/* Check if it is a Hosts item */
	if( strchr(item, ' ') == NULL && strchr(item, '\t') == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	if( *item == '@' && *(item + 1) == '@' )
	{
		if( ContainWildCard(item + 1) )
		{
			return HOSTS_TYPE_EXCLUEDE_W;
		} else {
			return HOSTS_TYPE_EXCLUEDE;
		}
	}

	/* Check if it contain wildcard */
	if( ContainWildCard(item) )
	{
		WildCard = HOSTS_TYPE_WILDCARD_MASK;
	} else {
		WildCard = HOSTS_TYPE_UNKNOWN;
	}

	if( isxdigit(*item) )
	{
		const char *Itr;
		/* Check if it is IPv6 */
		if( strchr(item, ':') != NULL )
		{
			return HOSTS_TYPE_AAAA | WildCard;
		}

		/* Check if it is CNAME */
		for(Itr = item; !isspace(*Itr) ; ++Itr)
		{
			if( isalpha(*Itr) )
			{
				return HOSTS_TYPE_CNAME | WildCard;
			}
		}

		for(Itr = item; !isspace(*Itr) ; ++Itr)
		{
			if( isdigit(*Itr) || *Itr == '.' )
			{
				return HOSTS_TYPE_A | WildCard;
			}
		}

		return HOSTS_TYPE_UNKNOWN;

	} else {

		if( *item == ':' )
		{
			return HOSTS_TYPE_AAAA | WildCard;
		}

		for(; !isspace(*item) ; ++item)
		{
			if( !isalnum(*item) && *item != '.' )
			{
				return HOSTS_TYPE_UNKNOWN;
			}
		}

		return HOSTS_TYPE_CNAME | WildCard;
	}
}

static void GetCount(	FILE *fp,
						int *IPv4,
						int *IPv6,
						int *IPv4W,
						int *IPv6W,
						int *CName,
						int *CNameW,
						int *Disabled,
						int *DisabledW
						)
{
	char			Buffer[320];
	ReadLineStatus	Status;

	*IPv4 = 0;
	*IPv6 = 0;
	*IPv4W = 0;
	*IPv6W = 0;
	*CName = 0;
	*CNameW = 0;
	*Disabled = 0;
	*DisabledW = 0;

	if( fp != NULL )
	{
		while(1)
		{
			Status = ReadLine(fp, Buffer, sizeof(Buffer));
	READDONE:
			if( Status == READ_FAILED_OR_END )
				break;

			switch( Edition(Buffer) )
			{
				case HOSTS_TYPE_AAAA:
					++(*IPv6);
					break;
				case HOSTS_TYPE_AAAA_W:
					++(*IPv6W);
					break;
				case HOSTS_TYPE_A:
					++(*IPv4);
					break;
				case HOSTS_TYPE_A_W:
					++(*IPv4W);
					break;
				case HOSTS_TYPE_CNAME:
					++(*CName);
					break;
				case HOSTS_TYPE_CNAME_W:
					++(*CNameW);
					break;
				case HOSTS_TYPE_EXCLUEDE:
					++(*Disabled);
					break;
				case HOSTS_TYPE_EXCLUEDE_W:
					++(*DisabledW);
					break;
				default:
					break;
			}

			if( Status == READ_TRUNCATED )
			{
				while( Status == READ_TRUNCATED )
					Status = ReadLine(fp, Buffer, sizeof(Buffer));
				goto READDONE;
			}
		}
		fseek(fp, 0, SEEK_SET);
	}

	if( AppendedNum > 0 )
	{
		const char *Appended;

		for(Appended = StringList_GetNext(&AppendedHosts, NULL);
			Appended != NULL;
			Appended = StringList_GetNext(&AppendedHosts, Appended)
			)
		{
			switch( Edition(Appended) )
			{
				case HOSTS_TYPE_AAAA:
					++(*IPv6);
					break;
				case HOSTS_TYPE_AAAA_W:
					++(*IPv6W);
					break;
				case HOSTS_TYPE_A:
					++(*IPv4);
					break;
				case HOSTS_TYPE_A_W:
					++(*IPv4W);
					break;
				case HOSTS_TYPE_CNAME:
					++(*CName);
					break;
				case HOSTS_TYPE_CNAME_W:
					++(*CNameW);
					break;
				case HOSTS_TYPE_EXCLUEDE:
					++(*Disabled);
					break;
				case HOSTS_TYPE_EXCLUEDE_W:
					++(*DisabledW);
					break;
				default:
					break;
			}
		}
	}
}

static int InitHostsContainer(	HostsContainer	*Container,
								int			IPv4Count,
								int			IPv6Count,
								int			IPv4WCount,
								int			IPv6WCount,
								int			CNameCount,
								int			CNameWCount,
								int			ExcludedCount,
								int			ExcludedCountW
								)
{

	if( StringChunk_Init(&(Container -> Ipv4Hosts), IPv4Count) != 0 )
	{
		return -1;
	}
	if( StringChunk_Init(&(Container -> Ipv6Hosts), IPv6Count) != 0 )
	{
		return -2;
	}
	if( StringChunk_Init(&(Container -> CNameHosts), CNameCount) != 0 )
	{
		return -3;
	}
	if( StringChunk_Init(&(Container -> ExcludedDomains), ExcludedCount) != 0 )
	{
		return -4;
	}
	if( ExtendableBuffer_Init(&(Container ->IPs), 0, -1) != 0 )
	{
		return -5;
	}

	return 0;
}

static void FreeHostsContainer(HostsContainer *Container)
{
	StringChunk_Free(&(Container -> Ipv4Hosts));
	StringChunk_Free(&(Container -> Ipv6Hosts));
	StringChunk_Free(&(Container -> CNameHosts));
	StringChunk_Free(&(Container -> ExcludedDomains));
	ExtendableBuffer_Free(&(Container -> IPs));
}

static _32BIT_INT IdenticalToLast(HostsContainer	*Container,
								HostsRecordType	CurrentType,
								const char	*CurrentContent,
								int			CurrentLength
								)
{
	static HostsContainer *LastContainer = NULL;
	static HostsRecordType LastType = HOSTS_TYPE_UNKNOWN;
	static _32BIT_INT LastOffset = 0;
	static _32BIT_INT LastLength = 0;

	if( LastContainer == NULL || LastContainer != Container )
	{
		LastContainer = Container;
		LastType = CurrentType;
		LastOffset = 0;
		LastLength = CurrentLength;
		return -1;
	}

	if( LastType == HOSTS_TYPE_UNKNOWN )
	{
		LastType = CurrentType;
		LastOffset = 0;
		LastLength = CurrentLength;
		return -1;
	}

	if( LastType == CurrentType )
	{
		if( memcmp(ExtendableBuffer_GetPositionByOffset(&(Container -> IPs), LastOffset),
					CurrentContent,
					CurrentLength
					) == 0
			)
		{
			return LastOffset;
		} else {
			LastOffset += LastLength;
			LastLength = CurrentLength;
			return -1;
		}
	} else {
		LastType = CurrentType;
		LastOffset += LastLength;
		LastLength = CurrentLength;
		return -1;
	}

}

static int AddHosts(HostsContainer *Container, char *src)
{
	/* Domain position */
	char		*itr;
	OffsetOfHosts	r;
	char		CurrentIP[16];

	switch( Edition(src) )
	{
		case HOSTS_TYPE_UNKNOWN:
			ERRORMSG("Unrecognisable host : %s\n", src);
			return 0;
			break;

		case HOSTS_TYPE_AAAA:
		case HOSTS_TYPE_AAAA_W:

			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';

			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				ERRORMSG("Hosts domain is too long : %s\n", itr);
				return 0;
			}

			if( StringChunk_Match_NoWildCard(&(Container -> Ipv6Hosts), itr, NULL) == TRUE )
			{
				INFO("IPv6 Hosts domain is duplicated : %s, take only the first occurrence.\n", itr);
				return 0;
			}

			IPv6AddressToNum(src, CurrentIP);

			r.Offset = IdenticalToLast(Container, HOSTS_TYPE_AAAA, CurrentIP, 16);


			if( r.Offset < 0 )
			{


				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), CurrentIP, 16);

				if( r.Offset < 0 )
				{
					return -1;
				}

			}

			StringChunk_Add(&(Container -> Ipv6Hosts), itr, (const char *)&r, sizeof(OffsetOfHosts));

			break;

		case HOSTS_TYPE_A:
		case HOSTS_TYPE_A_W:

			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';

			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				ERRORMSG("Hosts domain is too long : %s\n", itr);
				return 0;
			}

			if( StringChunk_Match_NoWildCard(&(Container -> Ipv4Hosts), itr, NULL) == TRUE )
			{
				INFO("IPv4 Hosts domain is duplicated : %s, take only the first occurrence.\n", itr);
				return 0;
			}

			IPv4AddressToNum(src, CurrentIP);

			r.Offset = IdenticalToLast(Container, HOSTS_TYPE_A, CurrentIP, 4);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), CurrentIP, 4);

				if( r.Offset < 0 )
				{
					return -1;
				}

			}

			StringChunk_Add(&(Container -> Ipv4Hosts), itr, (const char *)&r, sizeof(OffsetOfHosts));

			break;

		case HOSTS_TYPE_CNAME:
		case HOSTS_TYPE_CNAME_W:

			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';

			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX || strlen(src) > DOMAIN_NAME_LENGTH_MAX )
			{
				ERRORMSG("Hosts domain is too long : %s\n", itr);
				return 0;
			}

			if( StringChunk_Match_NoWildCard(&(Container -> CNameHosts), itr, NULL) == TRUE )
			{
				INFO("CName Hosts domain is duplicated : %s, take only the first occurrence.\n", itr);
				return 0;
			}

			r.Offset = IdenticalToLast(Container, HOSTS_TYPE_CNAME, src, strlen(src) + 1);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), src, strlen(src) + 1);

				if( r.Offset < 0 )
				{
					return -1;
				}

			}

			StringChunk_Add(&(Container -> CNameHosts), itr, (const char *)&r, sizeof(OffsetOfHosts));

			break;

		case HOSTS_TYPE_EXCLUEDE:
		case HOSTS_TYPE_EXCLUEDE_W:

			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';

			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				ERRORMSG("Hosts domain is too long : %s\n", itr);
				return 0;
			}

			if( StringChunk_Match_NoWildCard(&(Container -> ExcludedDomains), itr, NULL) == TRUE )
			{
				INFO("Excluded Hosts domain is duplicated : %s, take only the first occurrence.\n", itr);
				return 0;
			}

			StringChunk_Add(&(Container -> ExcludedDomains), itr, NULL, 0);

			break;


		default:
			break;
	}
	return 0;
}

static int LoadFileHosts(FILE *fp, HostsContainer *Container)
{
	char			Buffer[256];

	ReadLineStatus	Status;

	if( fp == NULL )
	{
		return 1;
	}

	while(TRUE)
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));
SWITCH:
		switch(Status)
		{
			case READ_FAILED_OR_END:
				goto DONE;

			case READ_DONE:
/*
                {
                    char *itr;

                    for(itr = Buffer + strlen(Buffer) - 1; (*itr == '\r' || *itr == '\n') && itr != Buffer; --itr)
                    {
                        *itr = '\0';
					}

                }
*/
				if( AddHosts(Container, Buffer) != 0 )
				{
					return 1;
				}

				break;

			case READ_TRUNCATED:
				if( strlen(Buffer) > sizeof(Buffer) - 1 )
				{
					ERRORMSG("Hosts Item is too long : %s\n", Buffer);
					do
					{
						Status = ReadLine(fp, Buffer, sizeof(Buffer));
					}
					while( Status == READ_TRUNCATED );
					goto SWITCH;
				}
				break;
		}
	}
DONE:
	return 0;
}

static int LoadAppendHosts(HostsContainer *Container)
{
	if( AppendedNum > 0 )
	{
		const char *Appended;
		char Changable[256];

		for(Appended = StringList_GetNext(&AppendedHosts, NULL); Appended != NULL; Appended = StringList_GetNext(&AppendedHosts, Appended))
		{
			Changable[sizeof(Changable) - 1] = '\0';
			strncpy(Changable, Appended, sizeof(Changable));
			if( Changable[sizeof(Changable) - 1] == '\0' )
			{
				if( AddHosts(Container, Changable) != 0 )
				{
					return 1;
				}
			}
		}
	}
	return 0;
}

static int LoadHosts(void)
{
	FILE	*fp;
	int		Status = 1;

	int		IPv4Count, IPv6Count, CNameCount, ExcludedCount;
	int		IPv4WCount, IPv6WCount, CNameWCount, ExcludedCountW;

	HostsContainer *TempContainer;

	if( File != NULL)
	{
		fp = fopen(File, "r");
	} else {
		fp = NULL;
	}

	GetCount(fp, &IPv4Count, &IPv6Count, &IPv4WCount, &IPv6WCount, &CNameCount, &CNameWCount, &ExcludedCount, &ExcludedCountW);

	TempContainer = (HostsContainer *)SafeMalloc(sizeof(HostsContainer));
	if( TempContainer == NULL )
	{
		return -1;
	}

	if( InitHostsContainer(TempContainer,
							IPv4Count,
							IPv6Count,
							IPv4WCount,
							IPv6WCount,
							CNameCount,
							CNameWCount,
							ExcludedCount,
							ExcludedCountW
							)
		!= 0 )
	{
		if( fp != NULL)
		{
			fclose(fp);
		}
		SafeFree(TempContainer);
		return 1;
	}

	if( AppendedNum > 0 )
	{
		int s;
		s = LoadAppendHosts(TempContainer);
		Status = Status && !s;
	}

	if( fp != NULL )
	{
		int s;
		s = LoadFileHosts(fp, TempContainer);
		Status = Status && !s;
	}

	if( Status != 0 )
	{
		RWLock_WrLock(HostsLock);
		if( MainContainer != NULL )
		{
			FreeHostsContainer(MainContainer);
			SafeFree(MainContainer);
		}
		MainContainer = TempContainer;

		RWLock_UnWLock(HostsLock);

		INFO("Loading Hosts completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Hosts, %d items are excluded, %d Hosts containing wildcards.\n",
			IPv4Count + IPv4WCount,
			IPv6Count + IPv6WCount,
			CNameCount + CNameWCount,
			ExcludedCount + ExcludedCountW,
			IPv4WCount + IPv6WCount + CNameWCount + ExcludedCountW);
		return 0;
	} else {
		SafeFree(TempContainer);
		return -1;
	}

}



static BOOL NeedReload(void)
{
	if( File == NULL )
	{
		return FALSE;
	}

	if( time(NULL) - LastFlush > FlushTime )
	{

#ifdef WIN32

		static FILETIME	LastFileTime = {0, 0};
		WIN32_FIND_DATA	Finddata;
		HANDLE			Handle;

		Handle = FindFirstFile(File, &Finddata);

		if( Handle == INVALID_HANDLE_VALUE )
		{
			return FALSE;
		}

		if( memcmp(&LastFileTime, &(Finddata.ftLastWriteTime), sizeof(FILETIME)) != 0 )
		{
			LastFlush = time(NULL);
			LastFileTime = Finddata.ftLastWriteTime;
			FindClose(Handle);
			return TRUE;
		} else {
			LastFlush = time(NULL);
			FindClose(Handle);
			return FALSE;
		}

#else /* WIN32 */
		static time_t	LastFileTime = 0;
		struct stat		FileStat;

		if( stat(File, &FileStat) != 0 )
		{

			return FALSE;
		}

		if( LastFileTime != FileStat.st_mtime )
		{
			LastFlush = time(NULL);
			LastFileTime = FileStat.st_mtime;

			return TRUE;
		} else {
			LastFlush = time(NULL);

			return FALSE;
		}

#endif /* WIN32 */
	} else {
		return FALSE;
	}
}

static int TryLoadHosts(void)
{
	if( NeedReload() == TRUE )
	{
		ThreadHandle t = INVALID_THREAD;
		CREATE_THREAD(LoadHosts, NULL, t);
		DETACH_THREAD(t);
	}
	return 0;
}

static void GetHostsFromInternet_Thread(void *Unused)
{
	const char *URL = ConfigGetString(&ConfigInfo, "Hosts");
	const char *Script = ConfigGetString(&ConfigInfo, "HostsScript");
	int			FlushTimeOnFailed = ConfigGetInt32(&ConfigInfo, "HostsFlushTimeOnFailed");

	if( FlushTimeOnFailed < 0 )
	{
		FlushTimeOnFailed = INT_MAX;
	}

	while(1)
	{

		INFO("Getting Hosts From %s ...\n", URL);

		if( GetFromInternet(URL, File) == 0 )
		{
			INFO("Hosts saved at %s.\n", File);

			if( Script != NULL )
			{
				INFO("Running script ...\n");
				system(Script);
			}

			LoadHosts();

			if( FlushTime < 0 )
			{
				return;
			}

			SLEEP(FlushTime * 1000);

		} else {
			ERRORMSG("Getting Hosts from Internet failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
			SLEEP(FlushTimeOnFailed * 1000);
		}

	}
}

int Hosts_Init(void)
{
	const char	*Path;
	const char	*Appended;

	Path = ConfigGetString(&ConfigInfo, "Hosts");
	Appended = ConfigGetString(&ConfigInfo, "AppendHosts");


	if( Path == NULL && Appended == NULL )
	{
		Inited = FALSE;
		return 0;
	}

	FlushTime = ConfigGetInt32(&ConfigInfo, "HostsFlushTime");
	RWLock_Init(HostsLock);


	if( Appended != NULL )
	{
		AppendedNum = StringList_Init(&AppendedHosts, Appended, ',');
	} else {
		AppendedNum = 0;
	}

	if( Path != NULL )
	{
		if( strncmp(Path, "http", 4) != 0 && strncmp(Path, "ftp", 3) != 0 )
		{
			/* Local file */
			File = Path;

			if( LoadHosts() != 0 )
			{
				ERRORMSG("Loading Hosts failed.\n");
				return 1;
			}
		} else {
			/* Internet file */
			File = ConfigGetString(&ConfigInfo, "HostsDownloadPath");
			if( ConfigGetInt32(&ConfigInfo, "HostsFlushTimeOnFailed") < 1)
			{
				ERRORMSG("`HostsFlushTimeOnFailed' is too small (< 1).\n");
				return 1;
			}

			Internet = TRUE;

			if( FileIsReadable(File) )
			{
				INFO("Loading the existing Hosts ...\n");
				LoadHosts();
			} else {
				INFO("Hosts file is unreadable, this may cause some failures.\n");
			}

			CREATE_THREAD(GetHostsFromInternet_Thread, NULL, GetHosts_Thread);
		}

	} else {
		File = NULL;
		LoadHosts();
	}

	LastFlush = time(NULL);
	srand(time(NULL));
	Inited = TRUE;
	return 0;

}

BOOL Hosts_IsInited(void)
{
	return Inited;
}

static const char *FindFromA(char *Name)
{
	OffsetOfHosts *IP;

	if( StringChunk_Match(&(MainContainer -> Ipv4Hosts), Name, (char **)&IP) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(MainContainer -> IPs), IP -> Offset);
	} else {
		return NULL;
	}
}

static const char *FindFromAAAA(char *Name)
{
	OffsetOfHosts *IP;

	if( StringChunk_Match(&(MainContainer -> Ipv6Hosts), Name, (char **)&IP) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(MainContainer -> IPs), IP -> Offset);
	} else {
		return NULL;
	}
}

static const char *FindFromCName(char *Name)
{
	OffsetOfHosts *CName;

	if( StringChunk_Match(&(MainContainer -> CNameHosts), Name, (char **)&CName) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(MainContainer -> IPs), CName -> Offset);
	} else {
		return NULL;
	}
}

static BOOL IsExcludedDomain(char *Name)
{
	return StringChunk_Match(&(MainContainer -> ExcludedDomains), Name, NULL);
}


#define	MATCH_STATE_PERFECT	0
#define	MATCH_STATE_ONLY_CNAME	1
#define	MATCH_STATE_NONE	(-1)
static int Hosts_Match(char *Name, DNSRecordType Type, void *OutBuffer)
{
	const char *Result;

	if( MainContainer == NULL )
	{
		return MATCH_STATE_NONE;
	}

	if( IsExcludedDomain(Name) == TRUE )
	{
		return MATCH_STATE_NONE;
	}

	switch( Type )
	{
		case DNS_TYPE_A:
			Result = FindFromA(Name);
			if( Result == NULL )
			{
				break;
			}

			memcpy(OutBuffer, Result, 4);
			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_AAAA:
			Result = FindFromAAAA(Name);
			if( Result == NULL )
			{
				break;
			}

			memcpy(OutBuffer, Result, 16);
			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_CNAME:
			Result = FindFromCName(Name);
			if( Result == NULL )
			{
				return MATCH_STATE_NONE;
			}
			strcpy(OutBuffer, Result);
			return MATCH_STATE_PERFECT;
			break;

		default:
			break;
	}

	if( Type != DNS_TYPE_CNAME )
	{
		Result = FindFromCName(Name);
		if( Result == NULL )
		{
			return MATCH_STATE_NONE;
		}
		strcpy(OutBuffer, Result);
		return MATCH_STATE_ONLY_CNAME;
	} else {
		return MATCH_STATE_NONE;
	}
}

static int GenerateSingleRecord(DNSRecordType Type, void *HostsItem, ExtendableBuffer *Buffer)
{
	switch( Type )
	{
		case DNS_TYPE_A:
			{
				char	*h = (char *)HostsItem;
				char	*HereSaved;

				HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + 4, NULL);

				if( HereSaved == NULL )
				{
					return -1;
				}

				DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_A, DNS_CLASS_IN, 60, h, 4, FALSE);

				HereSaved[0] = 0xC0;
				HereSaved[1] = 0x0C;

				return 2 + 2 + 2 + 4 + 2 + 4;
			}
			break;

		case DNS_TYPE_AAAA:
			{
				char	*h = (char *)HostsItem;
				char	*HereSaved;

				HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + 16, NULL);
				if( HereSaved == NULL )
				{
					return -1;
				}

				DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_AAAA, DNS_CLASS_IN, 60, h, 16, FALSE);

				HereSaved[0] = 0xC0;
				HereSaved[1] = 0x0C;

				return 2 + 2 + 2 + 4 + 2 + 16;
			}
			break;

		case DNS_TYPE_CNAME:
			{
				char		*h = (char *)HostsItem;
				char		*HereSaved;

				HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + strlen(h) + 2, NULL);
				if( HereSaved == NULL )
				{
					return -1;
				}

				DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_CNAME, DNS_CLASS_IN, 60, h, strlen(h) + 1, TRUE);

				HereSaved[0] = 0xC0;
				HereSaved[1] = 0x0C;

				return 2 + 2 + 2 + 4 + 2 + strlen(h) + 2;
			}
			break;

		default:
			return -1;
			break;
	}
}

static int RecursivelyQuery(DNSRecordType Type, void *HostsItem, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context)
{
	char	*h = (char *)HostsItem;

	BOOL	OriCompress = Context -> Compress;

	int		State;

	int		StartOffset = ExtendableBuffer_GetEndOffset(Buffer);
	const char	*StartPos;
	int		EndOffset;
	const char	*AnswerPos;
	int		MoreSpaceNeeded = 0;

	char	*HereSaved;

	HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + strlen(h) + 2, NULL);
	if( HereSaved == NULL )
	{
		return -1;
	}

	Context -> Compress = FALSE;

	DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_CNAME, DNS_CLASS_IN, 60, h, strlen(h) + 1, TRUE);

	HereSaved[0] = 0xC0;
	HereSaved[1] = 0x0C;

	Context -> ProtocolToSrc = DNS_QUARY_PROTOCOL_UDP;

	StartOffset = ExtendableBuffer_GetEndOffset(Buffer);

	State = GetAnswersByName(Context, h, Type, Buffer);
	if( State < 0 )
	{
		Context -> Compress = OriCompress;
		return -1;
	}

	StartPos = ExtendableBuffer_GetPositionByOffset(Buffer, StartOffset);

	EndOffset = DNSJumpOverAnswerRecords(StartPos) - ExtendableBuffer_GetData(Buffer);

	(*AnswerCount) = (int)DNSGetAnswerCount(StartPos) + 1;

	ExtendableBuffer_Eliminate(Buffer, EndOffset, StartOffset + State - EndOffset);

	MoreSpaceNeeded = DNSExpandCName_MoreSpaceNeeded(StartPos);
	if( ExtendableBuffer_Expand(Buffer, MoreSpaceNeeded, NULL) == NULL )
	{
		Context -> Compress = OriCompress;
		return -1;
	}

	EndOffset += MoreSpaceNeeded;

	StartPos = ExtendableBuffer_GetPositionByOffset(Buffer, StartOffset);

	DNSExpandCName(StartPos);

	AnswerPos = DNSJumpOverQuestionRecords(StartPos);

	ExtendableBuffer_Eliminate(Buffer, StartOffset, AnswerPos - StartPos);

	Context -> Compress = OriCompress;
	return EndOffset - StartOffset - (AnswerPos - StartPos) + (2 + 2 + 2 + 4 + 2 + strlen(h) + 2);
}

static int Hosts_GetByQuestion_Inner(char *Question, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context)
{
	char				Name[260];
	DNSRecordType		Type;
	DNSRecordClass		Class;
	int					MatchState;
	char				Result[DOMAIN_NAME_LENGTH_MAX + 1];

	DNSGetHostName(Question, DNSJumpHeader(Question), Name);

	Class = (DNSRecordClass)DNSGetRecordClass(DNSJumpHeader(Question));

	if( Class != DNS_CLASS_IN )
		return -1;

	Type = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(Question));

	RWLock_RdLock(HostsLock);
	MatchState = Hosts_Match(Name, Type, Result);
	RWLock_UnRLock(HostsLock);

	if( MatchState == MATCH_STATE_NONE )
	{
		return -1;
	}

	if( Internet != TRUE && FlushTime > 0 )
		TryLoadHosts();

	if( MatchState == MATCH_STATE_PERFECT )
	{
		*AnswerCount = 1;
		return GenerateSingleRecord(Type, Result, Buffer);
	} else if ( MatchState == MATCH_STATE_ONLY_CNAME )
	{
		return RecursivelyQuery(Type, Result, Buffer, AnswerCount, Context);
	} else {
		return -1;
	}
}

int Hosts_GetByQuestion(char *Question, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context)
{
	if( Inited == FALSE )
		return -1;

	return Hosts_GetByQuestion_Inner(Question, Buffer, AnswerCount, Context);

}
