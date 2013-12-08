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
static StringList	*AppendedHosts;
static int			AppendedNum = 0;

typedef enum _HostsRecordType{
	HOSTS_TYPE_TOO_LONG = -1,

	HOSTS_TYPE_UNKNOWN = 0,

	HOSTS_TYPE_A = 1 << 1,

	HOSTS_TYPE_AAAA = 1 << 2,

	HOSTS_TYPE_CNAME = 1 << 3,

	HOSTS_TYPE_EXCLUEDE = 1 << 4,

} HostsRecordType;

typedef struct _HostsRecord{
	char			Domain[256];
	char			IPOrCName[256];
	HostsRecordType Type;
} HostsRecord;

static HostsRecordType DetermineIPTypes(const char *item)
{
	if( item == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	/* A hosts item started by "@@ " is excluded */
	if( *item == '@' && *(item + 1) == '@' )
	{
		return HOSTS_TYPE_EXCLUEDE;
	}

	if( isxdigit(*item) )
	{
		const char *Itr;
		/* Check if it is IPv6 */
		if( strchr(item, ':') != NULL )
		{
			return HOSTS_TYPE_AAAA;
		}

		/* Check if it is CNAME */
		for(Itr = item; *Itr != '\0'; ++Itr)
		{
			if( isalpha(*Itr) )
			{
				return HOSTS_TYPE_CNAME;
			}
		}

		for(Itr = item; *Itr != '\0'; ++Itr)
		{
			if( isdigit(*Itr) || *Itr == '.' )
			{
				return HOSTS_TYPE_A;
			}
		}

		return HOSTS_TYPE_UNKNOWN;

	} else {

		if( *item == ':' )
		{
			return HOSTS_TYPE_AAAA;
		}

		for(; *item != '\0'; ++item)
		{
			if( !isalnum(*item) && *item != '.' )
			{
				return HOSTS_TYPE_UNKNOWN;
			}
		}

		return HOSTS_TYPE_CNAME;
	}
}

static void RefineARecord(HostsRecord *Record, const char *RawRecord)
{
	for(; isspace(*RawRecord); ++RawRecord);

	if( *RawRecord != '/' )
	{
		const char *Space;

		for( Space = RawRecord; !isspace(*Space) && *Space != '\0'; ++Space );

		if( *Space == '\0' )
		{
			return;
		}

		strncpy(Record -> IPOrCName, RawRecord, Space - RawRecord);
		Record -> IPOrCName[Space - RawRecord] = '\0';

		for(; isspace(*Space); ++Space);

		strcpy(Record -> Domain, Space);

	} else {
		if( strchr(RawRecord + 1, '/') == NULL )
		{
			return;
		}

		sscanf(RawRecord, "/%[^/]/%s", Record -> Domain, Record -> IPOrCName);
	}

	Record -> Type = DetermineIPTypes(Record -> IPOrCName);

	if( strlen(Record -> Domain) > DOMAIN_NAME_LENGTH_MAX )
	{
		Record -> Type = HOSTS_TYPE_TOO_LONG;
	}

	if( Record -> Type == HOSTS_TYPE_CNAME && strlen(Record -> IPOrCName) > DOMAIN_NAME_LENGTH_MAX )
	{
		Record -> Type = HOSTS_TYPE_TOO_LONG;
	}

}

static int LoadMetaInfo(	FILE *fp,
							Array *MetaInfo,
							int *IPv4,
							int *IPv6,
							int *CName,
							int *Disabled
						)
{
	HostsRecord		Record;

	char			Buffer[320];
	ReadLineStatus	Status;

	*IPv4 = 0;
	*IPv6 = 0;
	*CName = 0;
	*Disabled = 0;

	if( fp != NULL )
	{
		while(1)
		{
			Status = ReadLine(fp, Buffer, sizeof(Buffer));
	READDONE:
			if( Status == READ_FAILED_OR_END )
				break;

			RefineARecord(&Record, Buffer);

			switch( Record.Type )
			{
				case HOSTS_TYPE_TOO_LONG:
					ERRORMSG("Hosts is too long : %s\n", Buffer);
					break;

				case HOSTS_TYPE_UNKNOWN:
					ERRORMSG("Unrecognisable host : %s\n", Buffer);
					break;

				case HOSTS_TYPE_AAAA:
					++(*IPv6);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				case HOSTS_TYPE_A:
					++(*IPv4);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				case HOSTS_TYPE_CNAME:
					++(*CName);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				case HOSTS_TYPE_EXCLUEDE:
					++(*Disabled);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				default:
					break;
			}

			if( Status == READ_TRUNCATED )
			{
				ERRORMSG("Hosts is too long : %s\n", Buffer);
				while( Status == READ_TRUNCATED )
				{
					Status = ReadLine(fp, Buffer, sizeof(Buffer));
				}
				goto READDONE;
			}
		}
		fseek(fp, 0, SEEK_SET);
	}

	if( AppendedNum > 0 )
	{
		const char *Appended;

		Appended = StringList_GetNext(AppendedHosts, NULL);
		while( Appended != NULL )
		{
			RefineARecord(&Record, Appended);

			switch( Record.Type )
			{
				case HOSTS_TYPE_TOO_LONG:
					ERRORMSG("Hosts is too long : %s\n", Buffer);
					break;

				case HOSTS_TYPE_UNKNOWN:
					ERRORMSG("Unrecognisable host : %s\n", Buffer);
					break;

				case HOSTS_TYPE_AAAA:
					++(*IPv6);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				case HOSTS_TYPE_A:
					++(*IPv4);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				case HOSTS_TYPE_CNAME:
					++(*CName);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				case HOSTS_TYPE_EXCLUEDE:
					++(*Disabled);
					Array_PushBack(MetaInfo, &Record, NULL);
					break;

				default:
					break;
			}

			Appended = StringList_GetNext(AppendedHosts, Appended);
		}
	}
	return 0;
}

static int InitHostsContainer(	HostsContainer	*Container,
								int			IPv4Count,
								int			IPv6Count,
								int			CNameCount,
								int			ExcludedCount
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

static int AddHosts(HostsContainer *Container, HostsRecord *MetaInfo)
{
	OffsetOfHosts	r;
	char			NumericIP[16];

	if( MetaInfo == NULL )
	{
		return 1;
	}

	switch( MetaInfo -> Type )
	{
		case HOSTS_TYPE_AAAA:
			if( StringChunk_Match_NoWildCard(&(Container -> Ipv6Hosts), MetaInfo -> Domain, NULL, NULL) == TRUE )
			{
				INFO("IPv6 Hosts is duplicated : %s, take only the first occurrence.\n", MetaInfo -> Domain);
				return 0;
			}

			IPv6AddressToNum(MetaInfo -> IPOrCName, NumericIP);

			r.Offset = IdenticalToLast(Container, HOSTS_TYPE_AAAA, NumericIP, 16);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), NumericIP, 16);

				if( r.Offset < 0 )
				{
					return -1;
				}

			}

			StringChunk_Add(&(Container -> Ipv6Hosts), MetaInfo -> Domain, (const char *)&r, sizeof(OffsetOfHosts));

			break;

		case HOSTS_TYPE_A:
			if( StringChunk_Match_NoWildCard(&(Container -> Ipv4Hosts), MetaInfo -> Domain, NULL, NULL) == TRUE )
			{
				INFO("IPv4 Hosts domain is duplicated : %s, take only the first occurrence.\n", MetaInfo -> Domain);
				return 0;
			}

			IPv4AddressToNum(MetaInfo -> IPOrCName, NumericIP);

			r.Offset = IdenticalToLast(Container, HOSTS_TYPE_A, NumericIP, 4);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), NumericIP, 4);

				if( r.Offset < 0 )
				{
					return -1;
				}

			}

			StringChunk_Add(&(Container -> Ipv4Hosts), MetaInfo -> Domain, (const char *)&r, sizeof(OffsetOfHosts));

			break;

		case HOSTS_TYPE_CNAME:
			if( StringChunk_Match_NoWildCard(&(Container -> CNameHosts), MetaInfo -> Domain, NULL, NULL) == TRUE )
			{
				INFO("CName Hosts domain is duplicated : %s, take only the first occurrence.\n", MetaInfo -> Domain);
				return 0;
			}

			r.Offset = IdenticalToLast(Container, HOSTS_TYPE_CNAME, MetaInfo -> IPOrCName, strlen(MetaInfo -> IPOrCName) + 1);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), MetaInfo -> IPOrCName, strlen(MetaInfo -> IPOrCName) + 1);

				if( r.Offset < 0 )
				{
					return -1;
				}

			}

			StringChunk_Add(&(Container -> CNameHosts), MetaInfo -> Domain, (const char *)&r, sizeof(OffsetOfHosts));

			break;

		case HOSTS_TYPE_EXCLUEDE:
			if( StringChunk_Match_NoWildCard(&(Container -> ExcludedDomains), MetaInfo -> Domain, NULL, NULL) == TRUE )
			{
				INFO("Excluded Hosts domain is duplicated : %s, take only the first occurrence.\n", MetaInfo -> Domain);
				return 0;
			}

			StringChunk_Add(&(Container -> ExcludedDomains), MetaInfo -> Domain, NULL, 0);

			break;

		default:
			break;
	}
	return 0;
}

static int LoadFromMetaInfo(HostsContainer *Container, Array *MetaList)
{
	HostsRecord *MetaInfo = NULL;

	int loop;
	for( loop = 0; loop != Array_GetUsed(MetaList); ++loop )
	{
		MetaInfo = (HostsRecord *)Array_GetBySubscript(MetaList, loop);
		if( AddHosts(Container, MetaInfo) != 0 )
		{
			return -1;
		}
	}

	return 0;
}

static int LoadHosts(void)
{
	FILE	*fp;

	int		IPv4Count, IPv6Count, CNameCount, ExcludedCount;

	Array	MetaInfo;
	HostsContainer *TempContainer;

	if( File != NULL)
	{
		fp = fopen(File, "r");
	} else {
		fp = NULL;
	}

	if( Array_Init(&MetaInfo, sizeof(HostsRecord), 128, FALSE, NULL) != 0 )
	{
		return -1;
	}

	LoadMetaInfo(fp, &MetaInfo, &IPv4Count, &IPv6Count, &CNameCount, &ExcludedCount);

	TempContainer = (HostsContainer *)SafeMalloc(sizeof(HostsContainer));
	if( TempContainer == NULL )
	{
		Array_Free(&(MetaInfo));
		return -1;
	}

	if( InitHostsContainer(TempContainer, IPv4Count, IPv6Count, CNameCount, ExcludedCount) != 0 )
	{
		if( fp != NULL)
		{
			fclose(fp);
		}

		SafeFree(TempContainer);
		Array_Free(&(MetaInfo));
		return -1;
	}

	if( LoadFromMetaInfo(TempContainer, &MetaInfo) == 0 )
	{
		RWLock_WrLock(HostsLock);
		if( MainContainer != NULL )
		{
			FreeHostsContainer(MainContainer);
			SafeFree(MainContainer);
		}
		MainContainer = TempContainer;

		RWLock_UnWLock(HostsLock);

		INFO("Loading Hosts completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Hosts, %d items are excluded.\n",
			IPv4Count,
			IPv6Count,
			CNameCount,
			ExcludedCount);

		Array_Free(&(MetaInfo));
		return 0;
	} else {
		SafeFree(TempContainer);
		Array_Free(&(MetaInfo));
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
	const char *URL = ConfigGetRawString(&ConfigInfo, "Hosts");
	const char *Script = ConfigGetRawString(&ConfigInfo, "HostsScript");
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

static int InitAppendedHostsContainer(void)
{
	AppendedHosts = ConfigGetStringList(&ConfigInfo, "AppendHosts");

	if( AppendedHosts == NULL )
	{
		AppendedHosts = ConfigGetStringList(&ConfigInfo, "address");
	} else {
		StringList_Catenate(AppendedHosts, ConfigGetStringList(&ConfigInfo, "address"));
	}

	AppendedNum = StringList_Count(AppendedHosts);

	return AppendedNum;
}

int Hosts_Init(void)
{
	const char	*Path;

	Path = ConfigGetRawString(&ConfigInfo, "Hosts");

	InitAppendedHostsContainer();

	if( Path == NULL && AppendedNum <=0 )
	{
		Inited = FALSE;
		return 0;
	}

	FlushTime = ConfigGetInt32(&ConfigInfo, "HostsFlushTime");
	RWLock_Init(HostsLock);

	/* If hosts file is desinated */
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
			File = ConfigGetRawString(&ConfigInfo, "HostsDownloadPath");
			if( ConfigGetInt32(&ConfigInfo, "HostsFlushTimeOnFailed") < 1 )
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

	if( StringChunk_Match(&(MainContainer -> Ipv4Hosts), Name, NULL, (char **)&IP) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(MainContainer -> IPs), IP -> Offset);
	} else {
		return NULL;
	}
}

static const char *FindFromAAAA(char *Name)
{
	OffsetOfHosts *IP;

	if( StringChunk_Match(&(MainContainer -> Ipv6Hosts), Name, NULL, (char **)&IP) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(MainContainer -> IPs), IP -> Offset);
	} else {
		return NULL;
	}
}

static const char *FindFromCName(char *Name)
{
	OffsetOfHosts *CName;

	if( StringChunk_Match(&(MainContainer -> CNameHosts), Name, NULL, (char **)&CName) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(MainContainer -> IPs), CName -> Offset);
	} else {
		return NULL;
	}
}

static BOOL IsExcludedDomain(char *Name)
{
	return StringChunk_Match(&(MainContainer -> ExcludedDomains), Name, NULL, NULL);
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
			return MATCH_STATE_NONE;
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

static int RecursivelyQuery(DNSRecordType RequestingType, void *HostsItem, int *AnswerCount, ThreadContext *Context)
{
	char	*h = (char *)HostsItem;

	BOOL	OriCompress = Context -> Compress;

	int		State;

	int		StartOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);
	const char	*StartPos;
	int		EndOffset;
	const char	*AnswerPos;
	int		MoreSpaceNeeded = 0;

	char	*HereSaved;

	HereSaved = ExtendableBuffer_Expand(Context -> ResponseBuffer, 2 + 2 + 2 + 4 + 2 + strlen(h) + 2, NULL);
	if( HereSaved == NULL )
	{
		return -1;
	}

	Context -> Compress = FALSE;

	DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_CNAME, DNS_CLASS_IN, 60, h, strlen(h) + 1, TRUE);

	HereSaved[0] = 0xC0;
	HereSaved[1] = 0x0C;

	StartOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);

	State = GetAnswersByName(Context, h, RequestingType);
	if( State < 0 )
	{
		Context -> Compress = OriCompress;
		return -1;
	}

	StartPos = ExtendableBuffer_GetPositionByOffset(Context -> ResponseBuffer, StartOffset);

	EndOffset = DNSJumpOverAnswerRecords(StartPos) - ExtendableBuffer_GetData(Context -> ResponseBuffer);

	(*AnswerCount) = (int)DNSGetAnswerCount(StartPos) + 1;

	ExtendableBuffer_Eliminate(Context -> ResponseBuffer, EndOffset, StartOffset + State - EndOffset);

	MoreSpaceNeeded = DNSExpandCName_MoreSpaceNeeded(StartPos);
	if( ExtendableBuffer_Expand(Context -> ResponseBuffer, MoreSpaceNeeded, NULL) == NULL )
	{
		Context -> Compress = OriCompress;
		return -1;
	}

	EndOffset += MoreSpaceNeeded;

	StartPos = ExtendableBuffer_GetPositionByOffset(Context -> ResponseBuffer, StartOffset);

	DNSExpandCName(StartPos);

	AnswerPos = DNSJumpOverQuestionRecords(StartPos);

	ExtendableBuffer_Eliminate(Context -> ResponseBuffer, StartOffset, AnswerPos - StartPos);

	Context -> Compress = OriCompress;
	return EndOffset - StartOffset - (AnswerPos - StartPos) + (2 + 2 + 2 + 4 + 2 + strlen(h) + 2);
}

static int Hosts_GetByQuestion_Inner(ThreadContext *Context, int *AnswerCount)
{
	DNSRecordClass		Class;
	int					MatchState;
	char				Result[DOMAIN_NAME_LENGTH_MAX + 1]; /* Either an IP address or a CName */

	Class = (DNSRecordClass)DNSGetRecordClass(DNSJumpHeader(Context -> RequestEntity));

	if( Class != DNS_CLASS_IN )
		return -1;

	RWLock_RdLock(HostsLock);
	MatchState = Hosts_Match(Context -> RequestingDomain, Context -> RequestingType, Result);
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
		return GenerateSingleRecord(Context -> RequestingType, Result, Context -> ResponseBuffer);
	} else if ( MatchState == MATCH_STATE_ONLY_CNAME )
	{
		return RecursivelyQuery(Context -> RequestingType, Result, AnswerCount, Context);
	} else {
		return -1;
	}
}

int Hosts_GetByQuestion(ThreadContext *Context, int *AnswerCount)
{
	if( Inited == FALSE )
		return -1;

	return Hosts_GetByQuestion_Inner(Context, AnswerCount);

}
