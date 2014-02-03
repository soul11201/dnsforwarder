#include <ctype.h>
#include "statichosts.h"
#include "dnsgenerator.h"
#include "readconfig.h"
#include "utils.h"

static HostsContainer	MainContainer;
static BOOL				Inited = FALSE;

typedef struct _OffsetOfHosts{
	_32BIT_INT	Offset;
} OffsetOfHosts;

static _32BIT_INT Hosts_IdenticalToLast(HostsContainer	*Container,
										HostsRecordType	CurrentType,
										const char		*CurrentContent,
										int				CurrentLength
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

static HostsRecordType Hosts_DetermineIPTypes(const char *IPOrCName)
{
	if( IPOrCName == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	/* A hosts IPOrCName started by "@@ " is excluded */
	if( *IPOrCName == '@' && *(IPOrCName + 1) == '@' )
	{
		return HOSTS_TYPE_EXCLUEDE;
	}

	if( isxdigit(*IPOrCName) )
	{
		const char *Itr;
		/* Check if it is IPv6 */
		if( strchr(IPOrCName, ':') != NULL )
		{
			return HOSTS_TYPE_AAAA;
		}

		/* Check if it is CNAME */
		for(Itr = IPOrCName; *Itr != '\0'; ++Itr)
		{
			if( isalpha(*Itr) )
			{
				return HOSTS_TYPE_CNAME;
			}
		}

		for(Itr = IPOrCName; *Itr != '\0'; ++Itr)
		{
			if( isdigit(*Itr) || *Itr == '.' )
			{
				return HOSTS_TYPE_A;
			}
		}

		return HOSTS_TYPE_UNKNOWN;

	} else {

		if( *IPOrCName == ':' )
		{
			return HOSTS_TYPE_AAAA;
		}

		for(; *IPOrCName != '\0'; ++IPOrCName)
		{
			if( !isalnum(*IPOrCName) && *IPOrCName != '.' )
			{
				return HOSTS_TYPE_UNKNOWN;
			}
		}

		return HOSTS_TYPE_CNAME;
	}
}

static HostsRecordType Hosts_AddToContainer(HostsContainer *Container, const char *IPOrCName, const char *Domain)
{
	OffsetOfHosts	r;
	char			NumericIP[16];

	switch( Hosts_DetermineIPTypes(IPOrCName) )
	{
		case HOSTS_TYPE_AAAA:
			if( StringChunk_Match_NoWildCard(&(Container -> Ipv6Hosts), Domain, NULL, NULL) == TRUE )
			{
				INFO("IPv6 Host is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			IPv6AddressToNum(IPOrCName, NumericIP);

			r.Offset = Hosts_IdenticalToLast(Container, HOSTS_TYPE_AAAA, NumericIP, 16);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), NumericIP, 16);

				if( r.Offset < 0 )
				{
					return HOSTS_TYPE_UNKNOWN;
				}

			}

			StringChunk_Add(&(Container -> Ipv6Hosts), Domain, (const char *)&r, sizeof(OffsetOfHosts));

			return HOSTS_TYPE_AAAA;
			break;

		case HOSTS_TYPE_A:
			if( StringChunk_Match_NoWildCard(&(Container -> Ipv4Hosts), Domain, NULL, NULL) == TRUE )
			{
				INFO("IPv4 Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			IPv4AddressToNum(IPOrCName, NumericIP);

			r.Offset = Hosts_IdenticalToLast(Container, HOSTS_TYPE_A, NumericIP, 4);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), NumericIP, 4);

				if( r.Offset < 0 )
				{
					return HOSTS_TYPE_UNKNOWN;
				}

			}

			StringChunk_Add(&(Container -> Ipv4Hosts), Domain, (const char *)&r, sizeof(OffsetOfHosts));

			return HOSTS_TYPE_A;
			break;

		case HOSTS_TYPE_CNAME:
			if( StringChunk_Match_NoWildCard(&(Container -> CNameHosts), Domain, NULL, NULL) == TRUE )
			{
				INFO("CName redirection domain is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			r.Offset = Hosts_IdenticalToLast(Container, HOSTS_TYPE_CNAME, IPOrCName, strlen(IPOrCName) + 1);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), IPOrCName, strlen(IPOrCName) + 1);

				if( r.Offset < 0 )
				{
					return HOSTS_TYPE_UNKNOWN;
				}

			}

			StringChunk_Add(&(Container -> CNameHosts), Domain, (const char *)&r, sizeof(OffsetOfHosts));

			return HOSTS_TYPE_CNAME;
			break;

		case HOSTS_TYPE_EXCLUEDE:
			if( StringChunk_Match_NoWildCard(&(Container -> ExcludedDomains), Domain, NULL, NULL) == TRUE )
			{
				INFO("Excluded Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			StringChunk_Add(&(Container -> ExcludedDomains), Domain, NULL, 0);

			return HOSTS_TYPE_EXCLUEDE;
			break;

		default:
			return HOSTS_TYPE_UNKNOWN;
			break;
	}
}

int Hosts_InitContainer(HostsContainer	*Container)
{
	if( StringList_Init(&(Container -> Domains), NULL, ',') != 0 )
	{
		return -1;
	}

	if( StringChunk_Init(&(Container -> Ipv4Hosts), &(Container -> Domains)) != 0 )
	{
		return -2;
	}
	if( StringChunk_Init(&(Container -> Ipv6Hosts), &(Container -> Domains)) != 0 )
	{
		return -3;
	}
	if( StringChunk_Init(&(Container -> CNameHosts), &(Container -> Domains)) != 0 )
	{
		return -4;
	}
	if( StringChunk_Init(&(Container -> ExcludedDomains), &(Container -> Domains)) != 0 )
	{
		return -4;
	}
	if( ExtendableBuffer_Init(&(Container ->IPs), 0, -1) != 0 )
	{
		return -6;
	}

	return 0;
}

HostsRecordType Hosts_LoadFromMetaLine(HostsContainer *Container, char *MetaLine)
{
	const char *IPOrCName;
	const char *Domain;

	IPOrCName = MetaLine;
	Domain = GetKeyNameAndValue(MetaLine);
	if( Domain == NULL )
	{
		INFO("Unrecognisable hosts : %s\n", MetaLine);
		return HOSTS_TYPE_UNKNOWN;
	}

	return Hosts_AddToContainer(Container, IPOrCName, Domain);
}

int StaticHosts_Init(void)
{
	int		IPv4Count = 0, IPv6Count = 0, CNameCount = 0, ExcludedCount = 0;

	StringList *AppendHosts = ConfigGetStringList(&ConfigInfo, "AppendHosts");
	const char *Itr;
	char Buffer[2 * DOMAIN_NAME_LENGTH_MAX + 2];

	if( AppendHosts == NULL )
	{
		return -1;
	}

	if( Hosts_InitContainer(&MainContainer) != 0 )
	{
		return -1;
	}

	Itr = StringList_GetNext(AppendHosts, NULL);
	while( Itr != NULL )
	{
		if( strlen(Itr) > sizeof(Buffer) - 1 )
		{
			ERRORMSG("Hosts is too long : %s\n", Buffer);
		} else {
			strcpy(Buffer, Itr);
			Buffer[sizeof(Buffer) - 1] = '\0';

			switch( Hosts_LoadFromMetaLine(&MainContainer, Buffer) )
			{
				case HOSTS_TYPE_A:
					++IPv4Count;
					break;

				case HOSTS_TYPE_AAAA:
					++IPv6Count;
					break;

				case HOSTS_TYPE_CNAME:
					++CNameCount;
					break;

				case HOSTS_TYPE_EXCLUEDE:
					++ExcludedCount;
					break;

				default:
					break;
			}
		}

		Itr = StringList_GetNext(AppendHosts, Itr);
	}

	INFO("Loading Appendhosts completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Redirections, %d items are excluded.\n",
		IPv4Count,
		IPv6Count,
		CNameCount,
		ExcludedCount);

	Inited = TRUE;
	return 0;
}

static const char *Hosts_FindFromContainer(HostsContainer *Container, StringChunk *SubContainer, const char *Name)
{
	OffsetOfHosts *IP;

	if( StringChunk_Match(SubContainer, Name, NULL, (char **)&IP) == TRUE )
	{
		return ExtendableBuffer_GetPositionByOffset(&(Container -> IPs), IP -> Offset);
	} else {
		return NULL;
	}
}

static const char *Hosts_FindIPv4(HostsContainer *Container, const char *Name)
{
	return Hosts_FindFromContainer(Container, &(Container -> Ipv4Hosts), Name);
}

static const char *Hosts_FindIPv6(HostsContainer *Container, const char *Name)
{
	return Hosts_FindFromContainer(Container, &(Container -> Ipv6Hosts), Name);
}

static const char *Hosts_FindCName(HostsContainer *Container, const char *Name)
{
	return Hosts_FindFromContainer(Container, &(Container -> CNameHosts), Name);
}

static BOOL Hosts_IsExcludedDomain(HostsContainer *Container, const char *Name)
{
	return StringChunk_Match((StringChunk *)&(Container -> ExcludedDomains), Name, NULL, NULL);
}

#define	MATCH_STATE_PERFECT	0
#define	MATCH_STATE_ONLY_CNAME	1
#define	MATCH_STATE_NONE	(-1)
static int Hosts_Match(HostsContainer *Container, const char *Name, DNSRecordType Type, const char **Result)
{
	if( Hosts_IsExcludedDomain(Container, Name) == TRUE )
	{
		return MATCH_STATE_NONE;
	}

	switch( Type )
	{
		case DNS_TYPE_A:
			*Result = Hosts_FindIPv4(Container, Name);
			if( *Result == NULL )
			{
				break;
			}

			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_AAAA:
			*Result = Hosts_FindIPv6(Container, Name);
			if( *Result == NULL )
			{
				break;
			}

			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_CNAME:
			*Result = Hosts_FindCName(Container, Name);
			if( *Result == NULL )
			{
				return MATCH_STATE_NONE;
			}

			return MATCH_STATE_PERFECT;
			break;

		default:
			return MATCH_STATE_NONE;
			break;
	}

	*Result = Hosts_FindCName(Container, Name);
	if( *Result == NULL )
	{
		return MATCH_STATE_NONE;
	}

	return MATCH_STATE_ONLY_CNAME;
}

static int StaticHosts_GenerateSingleRecord(DNSRecordType Type, const char *IPOrCName, ExtendableBuffer *Buffer)
{
	char *HereSaved;
	int RecordLength;

	switch( Type )
	{
		case DNS_TYPE_A:
			RecordLength = 2 + 2 + 2 + 4 + 2 + 4;
			break;

		case DNS_TYPE_AAAA:
			RecordLength = 2 + 2 + 2 + 4 + 2 + 16;
			break;

		case DNS_TYPE_CNAME:
			RecordLength = 2 + 2 + 2 + 4 + 2 + strlen(IPOrCName) + 2;
			break;

		default:
			return -1;
			break;
	}

	HereSaved = ExtendableBuffer_Expand(Buffer, RecordLength, NULL);
	if( HereSaved == NULL )
	{
		return -1;
	}

	DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", Type, DNS_CLASS_IN, 60, IPOrCName, 4, FALSE);

	HereSaved[0] = 0xC0;
	HereSaved[1] = 0x0C;

	return RecordLength;
}

static int Hosts_RecursivelyQuery(const char *IPOrCName, int *AnswerCount, ThreadContext *Context)
{
	int		PrependLength = 2 + 2 + 2 + 4 + 2 + strlen(IPOrCName) + 2;
	BOOL	OriCompress = Context -> Compress;

	int		State;

	int		StartOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);
	char	*StartPos;
	int		EndOffset;
	const char	*AnswerPos;
	int		MoreSpaceNeeded = 0;

	char	*HereSaved;

	HereSaved = ExtendableBuffer_Expand(Context -> ResponseBuffer, PrependLength, NULL);
	if( HereSaved == NULL )
	{
		return -1;
	}

	Context -> Compress = FALSE;

	DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_CNAME, DNS_CLASS_IN, 60, IPOrCName, strlen(IPOrCName) + 1, TRUE);

	HereSaved[0] = 0xC0;
	HereSaved[1] = 0x0C;

	StartOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);

	State = GetAnswersByName(Context, IPOrCName, Context -> RequestingType, "CNameRedirect");
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
	return EndOffset - StartOffset - (AnswerPos - StartPos) + PrependLength;
}

int Hosts_GetFromContainer(HostsContainer *Container, ThreadContext *Context, int *AnswerCount)
{
	DNSRecordClass	Class;
	int				MatchState;
	const char		*Result; /* Either an IP address or a CName */

	Class = (DNSRecordClass)DNSGetRecordClass(DNSJumpHeader(Context -> RequestEntity));

	if( Class != DNS_CLASS_IN )
		return -1;

	MatchState = Hosts_Match(Container, Context -> RequestingDomain, Context -> RequestingType, &Result);

	if( MatchState == MATCH_STATE_NONE )
	{
		return -1;
	}

	if( MatchState == MATCH_STATE_PERFECT )
	{
		*AnswerCount = 1;
		return StaticHosts_GenerateSingleRecord(Context -> RequestingType, Result, Context -> ResponseBuffer);
	} else if ( MatchState == MATCH_STATE_ONLY_CNAME )
	{
		return Hosts_RecursivelyQuery(Result, AnswerCount, Context);
	} else {
		return -1;
	}
}

int StaticHosts_GetByQuestion(ThreadContext *Context, int *AnswerCount)
{
	if( Inited == FALSE )
	{
		return -1;
	} else {
		return Hosts_GetFromContainer(&MainContainer, Context, AnswerCount);
	}
}

BOOL StaticHosts_Inited(void)
{
	return Inited;
}
