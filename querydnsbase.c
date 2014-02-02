#include <time.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif
#include "querydnsbase.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "hosts.h"
#include "utils.h"
#include "excludedlist.h"
#include "gfwlist.h"
#include "addresschunk.h"
#include "stringlist.h"
#include "domainstatistic.h"
#include "request_response.h"

static AddressChunk	Addresses;

static BOOL			ParallelQuery;
static sa_family_t	MainFamily;
static Array		Addresses_Array;

static BOOL			AllowFallBack = FALSE;

void SetFallBack(BOOL FallBack)
{
	AllowFallBack = FallBack;
}

void ShowRefusingMassage(ThreadContext *Context)
{
	char DateAndTime[32];

	if( ShowMassages == TRUE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		printf("%s[R][%s][%s][%s] Refused.\n",
			  DateAndTime,
			  Context -> ClientIP,
			  DNSGetTypeName(Context -> RequestingType),
			  Context -> RequestingDomain
			  );
	}

	DEBUG_FILE("[R][%s][%s][%s].\n",
		   Context -> ClientIP,
		   DNSGetTypeName(Context -> RequestingType),
		   Context -> RequestingDomain
		   );
}

void ShowErrorMassage(ThreadContext *Context, char ProtocolCharacter)
{
	char	DateAndTime[32];

	int		ErrorNum = GET_LAST_ERROR();
	char	ErrorMessage[320];

	if( ErrorMessages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		ErrorMessage[0] ='\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

	}

	if( ErrorMessages == TRUE )
	{
		printf("%s[%c][%s][%s][%s] An error occured : %d : %s .\n",
			   DateAndTime,
			   ProtocolCharacter,
			   Context -> ClientIP,
			   DNSGetTypeName(Context -> RequestingType),
			   Context -> RequestingDomain,
			   ErrorNum,
			   ErrorMessage
			   );
	}

	DEBUG_FILE("[%c][%s][%s][%s] An error occured : %d : %s .\n",
			   ProtocolCharacter,
			   Context -> ClientIP,
			   DNSGetTypeName(Context -> RequestingType),
			   Context -> RequestingDomain,
			   ErrorNum,
			   ErrorMessage
			   );
}

void ShowNormalMassage(ThreadContext *Context, _32BIT_INT Offset, char ProtocolCharacter)
{
	char DateAndTime[32];
	char InfoBuffer[1024];

	if( ShowMassages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		InfoBuffer[0] = '\0';
		GetAllAnswers(ExtendableBuffer_GetPositionByOffset(Context -> ResponseBuffer, Offset), InfoBuffer, sizeof(InfoBuffer));
	}

	if( ShowMassages == TRUE )
	{
		printf("%s[%c][%s][%s][%s] : %d bytes\n%s",
			  DateAndTime,
			  ProtocolCharacter,
			  Context -> ClientIP,
			  DNSGetTypeName(Context -> RequestingType),
			  Context -> RequestingDomain,
			  ExtendableBuffer_GetUsedBytes(Context -> ResponseBuffer) - Offset,
			  InfoBuffer
			  );
	}

	DEBUG_FILE("[%c][%s][%s][%s] :%d bytes\n%s",
			   ProtocolCharacter,
			   Context -> ClientIP,
			   DNSGetTypeName(Context -> RequestingType),
			   Context -> RequestingDomain,
			   ExtendableBuffer_GetUsedBytes(Context -> ResponseBuffer) - Offset,
			   InfoBuffer
			   );
}

void ShowBlockedMessage(const char *RequestingDomain, const char *Package, const char *Message)
{
	char DateAndTime[32];
	char InfoBuffer[1024];

	if( ShowMassages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		InfoBuffer[0] = '\0';
		GetAllAnswers(Package, InfoBuffer, sizeof(InfoBuffer));
	}

	if( ShowMassages == TRUE )
	{
		printf("%s[B][%s] %s :\n%s", DateAndTime, RequestingDomain, Message == NULL ? "" : Message, InfoBuffer);
	}

	DEBUG_FILE("[B][%s] %s :\n%s", RequestingDomain, Message == NULL ? "" : Message, InfoBuffer);
}

int DNSFetchFromHosts(__in ThreadContext *Context)
{
	char		*Header;
	int			RecordsLength;
	_32BIT_INT	HeaderOffset;
	int			AnswerCount;

	Header = ExtendableBuffer_Expand(Context -> ResponseBuffer, Context -> RequestLength, &HeaderOffset);
	if( Header == NULL )
	{
		return -1;
	}

	RecordsLength = DynamicHosts_GetByQuestion(Context, &AnswerCount);
	if( RecordsLength > 0 )
	{
		Header = ExtendableBuffer_GetData(Context -> ResponseBuffer) + HeaderOffset;

		memcpy(Header, Context -> RequestEntity, Context -> RequestLength);
		((DNSHeader *)Header) -> Flags.Direction = 1;
		((DNSHeader *)Header) -> Flags.AuthoritativeAnswer = 0;
		((DNSHeader *)Header) -> Flags.RecursionAvailable = 0;
		((DNSHeader *)Header) -> Flags.ResponseCode = 0;
		((DNSHeader *)Header) -> AnswerCount = htons(AnswerCount);

		if( AnswerCount != 1 && Context -> Compress != FALSE )
		{
			int UnCompressedLength = Context -> RequestLength + RecordsLength;

			int CompressedLength = DNSCompress(Header, UnCompressedLength);

			ExtendableBuffer_Eliminate_Tail(Context -> ResponseBuffer, UnCompressedLength - CompressedLength);

			ShowNormalMassage(Context, HeaderOffset, 'H');

			return CompressedLength;
		} else {
			ShowNormalMassage(Context, HeaderOffset, 'H');

			return Context -> RequestLength + RecordsLength;
		}
	} else {
		return -1;
	}
}

int DNSFetchFromCache(__in ThreadContext *Context)
{
	int			RecordsCount, RecordsLength;
	char		*Header;
	_32BIT_INT	HeaderOffset;

	Header = ExtendableBuffer_Expand(Context -> ResponseBuffer, Context -> RequestLength, &HeaderOffset);
	if( Header == NULL )
	{
		return -1;
	}

	memcpy(Header, Context -> RequestEntity, Context -> RequestLength);
	((DNSHeader *)Header) -> Flags.Direction = 1;
	((DNSHeader *)Header) -> Flags.AuthoritativeAnswer = 0;
	((DNSHeader *)Header) -> Flags.RecursionAvailable = 1;
	((DNSHeader *)Header) -> Flags.ResponseCode = 0;
	((DNSHeader *)Header) -> Flags.Type = 0;

	RecordsCount = DNSCache_GetByQuestion(Context -> RequestEntity, Context -> ResponseBuffer, &RecordsLength, Context -> CurrentTime);
	if( RecordsCount > 0 )
	{
		Header = ExtendableBuffer_GetData(Context -> ResponseBuffer) + HeaderOffset;

		((DNSHeader *)Header) -> AnswerCount = htons(RecordsCount);

		if(Context -> Compress != FALSE)
		{
			int UnCompressedLength = Context -> RequestLength + RecordsLength;
			int CompressedLength = DNSCompress(Header, UnCompressedLength);

			ExtendableBuffer_Eliminate_Tail(Context -> ResponseBuffer, UnCompressedLength - CompressedLength);

			ShowNormalMassage(Context, HeaderOffset, 'C');

			return CompressedLength;
		} else {
			ShowNormalMassage(Context, HeaderOffset, 'C');

			return Context -> RequestLength + RecordsLength;
		}
	} else {
		return -1;
	}
}

int FetchFromHostsAndCache(ThreadContext *Context)
{
	int			StateOfReceiving = -1;
	_32BIT_INT	OriOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);

	if( DNSGetAdditionalCount(Context -> RequestEntity) > 0 )
	{
		return -1;
	}

	if( DynamicHosts_Inited() || StaticHosts_Inited() )
	{
		StateOfReceiving = DNSFetchFromHosts(Context);

		if( StateOfReceiving > 0 ) /* Succeed to query from Hosts  */
		{

			DomainStatistic_Add(Context -> RequestingDomain, &(Context -> RequestingDomainHashValue), STATISTIC_TYPE_HOSTS);

			return StateOfReceiving;
		}

		/* Failed */
		ExtendableBuffer_SetEndOffset(Context -> ResponseBuffer, OriOffset);
	}

	if( Cache_IsInited() )
	{
		StateOfReceiving = DNSFetchFromCache(Context);

		if( StateOfReceiving > 0 ) /* Succeed  */
		{

			DomainStatistic_Add(Context -> RequestingDomain, &(Context -> RequestingDomainHashValue), STATISTIC_TYPE_CACHE);

			return StateOfReceiving;
		}

		ExtendableBuffer_SetEndOffset(Context -> ResponseBuffer, OriOffset);
	}

	return -1;
}

static int LoadDedicatedServer(void)
{
	const StringList	*DedicatedServer	=	ConfigGetStringList(&ConfigInfo, "DedicatedServer");

	const char	*Itr	=	NULL;

	char Domain[256];
	char Server[64];

	Itr = StringList_GetNext(DedicatedServer, NULL);
	while( Itr != NULL )
	{
		if( sscanf(Itr, "%s %s", Domain, Server) < 2 )
		{
			INFO("Invalid Option in `DedicatedServer' : %s\n", Itr);
			continue;
		}
		INFO("Add a dedicated Server %s for %s\n", Server, Domain);
		AddressChunk_AddADedicatedAddress_FromString(&Addresses, Domain, Server);
		Itr = StringList_GetNext(DedicatedServer, Itr);
	}

	StringList_Free(DedicatedServer);

	return 0;
}

int InitAddress(void)
{
	StringList	*tcpaddrs	=	ConfigGetStringList(&ConfigInfo, "TCPServer");
	StringList	*udpaddrs	=	ConfigGetStringList(&ConfigInfo, "UDPServer");

	const char	*Itr	=	NULL;

	if( AddressChunk_Init(&Addresses) != 0 )
	{
		return -1;
	}

	Itr = StringList_GetNext(tcpaddrs, NULL);
	while( Itr != NULL )
	{
		AddressChunk_AddATCPAddress_FromString(&Addresses, Itr);

		DEBUG_FILE("Add TCP address : %s\n", Itr);

		Itr = StringList_GetNext(tcpaddrs, Itr);
	}

	Itr = StringList_GetNext(udpaddrs, NULL);
	while( Itr != NULL )
	{
		AddressChunk_AddAUDPAddress_FromString(&Addresses, Itr);

		DEBUG_FILE("Add UDP address : %s\n", Itr);

		Itr = StringList_GetNext(udpaddrs, Itr);
	}

	ParallelQuery = ConfigGetBoolean(&ConfigInfo, "ParallelQuery");
	if( ParallelQuery == TRUE )
	{
		int NumberOfAddr;

		int AddrLen;

		sa_family_t SubFamily;

		struct sockaddr *OneAddr;

		NumberOfAddr = StringList_Count(udpaddrs);
		if( NumberOfAddr <= 0 )
		{
			ERRORMSG("No UDP server specified, cannot use parallel query.\n")
			ParallelQuery = FALSE;
		} else {
			DEBUG_FILE("Enable parallel query.\n");

			AddressChunk_GetOneUDPBySubscript(&Addresses, &MainFamily, 0);

			if( MainFamily == AF_INET )
			{
				AddrLen = sizeof(struct sockaddr);

				DEBUG_FILE("Parallel query servers family IPv4.\n");

			} else {
				AddrLen = sizeof(struct sockaddr_in6);

				DEBUG_FILE("Parallel query servers family IPv6.\n");
			}

			Array_Init(&Addresses_Array, AddrLen, NumberOfAddr, FALSE, NULL);

			while( NumberOfAddr != 0 )
			{
				OneAddr = AddressChunk_GetOneUDPBySubscript(&Addresses, &SubFamily, NumberOfAddr - 1);
				if( OneAddr != NULL && SubFamily == MainFamily )
				{
					Array_PushBack(&Addresses_Array, OneAddr, NULL);
				}

				--NumberOfAddr;
			}
		}
	}

	StringList_Free(tcpaddrs);
	StringList_Free(udpaddrs);

	return LoadDedicatedServer();

}

static void SelectSocketAndProtocol(ThreadContext		*Context,
									SOCKET				**SocketUsed,
									DNSQuaryProtocol	*ProtocolUsed,
									BOOL				IsSecondary
									)
{
	if( IsSecondary == TRUE )
	{
		*SocketUsed = Context -> SecondarySocket;
		*ProtocolUsed = !(Context -> PrimaryProtocolToServer);
	} else {
		*SocketUsed = Context -> PrimarySocket;
		*ProtocolUsed = Context -> PrimaryProtocolToServer;
	}
}

static void SetAddressAndPrococolLetter(ThreadContext		*Context,
										DNSQuaryProtocol	ProtocolUsed,
										struct sockaddr		**Addresses_List,
										int					*NumberOfAddresses,
										sa_family_t			*Family,
										char				*ProtocolCharacter
										)
{
	*Addresses_List = AddressChunk_GetDedicated(&Addresses, Family, Context -> RequestingDomain, &(Context -> RequestingDomainHashValue), ProtocolUsed);

	if( *Addresses_List == NULL )
	{
		if( ProtocolUsed == DNS_QUARY_PROTOCOL_UDP && ParallelQuery == TRUE )
		{
			*Addresses_List = (struct sockaddr *)Addresses_Array.Data;
			*NumberOfAddresses = Addresses_Array.Used;
			*Family = MainFamily;
		} else {
			*Addresses_List = AddressChunk_GetOne(&Addresses, Family, ProtocolUsed);
			*NumberOfAddresses = 1;
		}
	} else {
		*NumberOfAddresses = 1;
	}

	if( *Addresses_List != Context -> LastServer )
	{
		if( Context -> LastProtocol == DNS_QUARY_PROTOCOL_UDP && ParallelQuery == FALSE )
		{
			CLOSE_SOCKET(Context -> Head -> UDPSocket);
			Context -> UDPSocket = INVALID_SOCKET;
		} else {
			CloseTCPConnection(&(Context -> Head -> TCPSocket));
		}
	}

	Context -> LastServer = *Addresses_List;
	Context -> LastProtocol = ProtocolUsed;

	if( ProtocolUsed == DNS_QUARY_PROTOCOL_UDP )
	{
		/* Assign ProtocolCharacter used by output message */
		if( ProtocolCharacter != NULL )
		{
			*ProtocolCharacter = 'U';
		}
	} else { /* For TCP below */
		if( ProtocolCharacter != NULL )
		{
			*ProtocolCharacter = 'T';
		}
	}
}

static int QueryFromServer(ThreadContext *Context)
{
	char		ProtocolCharacter;

	int			StateOfReceiving;

	SOCKET		*SocketUsed;

	DNSQuaryProtocol	ProtocolUsed;

	struct	sockaddr	*ServerAddr;
	int					NumberOfAddresses;

	sa_family_t	Family;

	BOOL		UseSecondary;

	_32BIT_INT	StartOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);

	int			AnswerCount;

	/* Determine whether the secondaries are used */
	if( Context -> SecondarySocket != NULL &&
		(IsExcludedDomain(Context -> RequestingDomain, &(Context -> RequestingDomainHashValue)) ||
		GfwList_Match(Context -> RequestingDomain, &(Context -> RequestingDomainHashValue)))
		 )
	{
		UseSecondary = TRUE;
	} else {
		UseSecondary = FALSE;
	}

	SelectSocketAndProtocol(Context, &SocketUsed, &ProtocolUsed, UseSecondary);

	SetAddressAndPrococolLetter(Context,
								ProtocolUsed,
								&ServerAddr,
								&NumberOfAddresses,
								&Family,
								&ProtocolCharacter
								);

	StateOfReceiving = QueryFromServerBase(SocketUsed,
										   ServerAddr,
										   NumberOfAddresses,
										   ProtocolUsed,
										   Context -> RequestEntity,
										   Context -> RequestLength,
										   Context -> ResponseBuffer,
										   Context -> RequestingDomain
										   );

	if(StateOfReceiving < 0) /* Failed */
	{
		ShowErrorMassage(Context, ProtocolCharacter);

		/* Move pointer to the next */
		AddressChunk_Advance(&Addresses, ProtocolUsed);

		if( UseSecondary == FALSE && Context -> SecondarySocket != NULL && AllowFallBack == TRUE )
		{
			INFO("Fallback from %c for %s .\n",
				 ProtocolCharacter,
				 Context -> RequestingDomain
				 );

			SelectSocketAndProtocol(Context,
									&SocketUsed,
									&ProtocolUsed,
									TRUE
									);

			SetAddressAndPrococolLetter(Context,
										ProtocolUsed,
										&ServerAddr,
										&NumberOfAddresses,
										&Family,
										&ProtocolCharacter
										);

			StateOfReceiving = QueryFromServerBase(SocketUsed,
												   ServerAddr,
												   NumberOfAddresses,
												   ProtocolUsed,
												   Context -> RequestEntity,
												   Context -> RequestLength,
												   Context -> ResponseBuffer,
												   Context -> RequestingDomain
												   );

			if( StateOfReceiving < 0 )
			{
				ShowErrorMassage(Context, ProtocolCharacter);

				/* Move pointer to the next */
				AddressChunk_Advance(&Addresses, ProtocolUsed);

				return QUERY_RESULT_ERROR;
			}
		} else {
			return QUERY_RESULT_ERROR;
		}
	}

	AnswerCount = DNSGetAnswerCount(ExtendableBuffer_GetPositionByOffset(Context -> ResponseBuffer, StartOffset));

	if( AnswerCount < 1 )
	{
		AddressChunk_Advance(&Addresses, ProtocolUsed);
	}

	ShowNormalMassage(Context, StartOffset, ProtocolCharacter);


	return StateOfReceiving;

}

int QueryBase(ThreadContext *Context)
{
	int StateOfReceiving = -1;

	int	QuestionCount;

	/* Check if this domain or type is disabled */
	if( IsDisabledType(Context -> RequestingType) || IsDisabledDomain(Context -> RequestingDomain, &(Context -> RequestingDomainHashValue)) )
	{
		DomainStatistic_Add(Context -> RequestingDomain, &(Context -> RequestingDomainHashValue), STATISTIC_TYPE_REFUSED);
		ShowRefusingMassage(Context);
		return QUERY_RESULT_DISABLE;
	}

	/* Get the QuestionCount */
	QuestionCount = DNSGetQuestionCount(Context -> RequestEntity);

	if( QuestionCount == 1 )
	{
		/* First query from hosts and cache */
		StateOfReceiving = FetchFromHostsAndCache(Context);
	} else {
		StateOfReceiving = -1;
	}

	/* If hosts or cache has no record, then query from server */
	if( StateOfReceiving < 0 )
	{
		StateOfReceiving = QueryFromServer(Context);
	}

	return StateOfReceiving;

}

static BOOL DefinitionLoop(ThreadContext *Context, const char *Name)
{
	while( Context != NULL )
	{
		if( strcmp(Name, Context -> RequestingDomain) == 0 )
		{
			return TRUE;
		}

		Context = Context -> Previous;
	}

	return FALSE;
}

void InitContext(ThreadContext *Context, char *RequestEntity)
{
	static BOOL Inited = FALSE;
	static DNSQuaryProtocol PrimaryProtocolToServer;
	static BOOL NullSecondary = FALSE;

	Context -> Head = Context;
	Context -> Previous = NULL;

	Context -> TCPSocket = INVALID_SOCKET;
	Context -> UDPSocket = INVALID_SOCKET;

	Context -> LastServer = NULL;

	Context -> Compress = TRUE;

	Context -> ResponseBuffer = &(Context -> ResponseBuffer_Entity);
	ExtendableBuffer_Init(Context -> ResponseBuffer, 512, 10240);
	Context -> RequestEntity = RequestEntity;

	/* Choose and fill default primary and secondary socket */
	if( Inited == FALSE )
	{
		char ProtocolStr[8] = {0};

		strncpy(ProtocolStr, ConfigGetRawString(&ConfigInfo, "PrimaryServer"), 3);
		StrToLower(ProtocolStr);
		if( strcmp(ProtocolStr, "tcp") == 0 )
		{
			PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_TCP;
			NullSecondary = (ConfigGetStringList(&ConfigInfo, "UDPServer") == NULL);
		} else {
			PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_UDP;
			NullSecondary = (ConfigGetStringList(&ConfigInfo, "TCPServer") == NULL);
		}

		Inited = TRUE;
	}

	if( PrimaryProtocolToServer == DNS_QUARY_PROTOCOL_TCP )
	{
		Context -> PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_TCP;
		Context -> PrimarySocket = &(Context -> TCPSocket);

		if( NullSecondary == FALSE )
			Context -> SecondarySocket = &(Context -> UDPSocket);
		else
			Context -> SecondarySocket = NULL;

	} else {
		Context -> PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_UDP;
		Context -> PrimarySocket = &(Context -> UDPSocket);

		if( NullSecondary == FALSE )
			Context -> SecondarySocket = &(Context -> TCPSocket);
		else
			Context -> SecondarySocket = NULL;
	}

}

int	GetAnswersByName(ThreadContext *Context, const char *Name, DNSRecordType Type, const char *Agent)
{
	ThreadContext RecursionContext;
	int	StateOfReceiving;

	char	RequestEntity[384] = {
		00, 00, /* QueryIdentifier */
		01, 00, /* Flags */
		00, 01, /* QuestionCount */
		00, 00, /* AnswerCount */
		00, 00, /* NameServerCount */
		00, 00, /* AdditionalCount */
		/* Header end */
	};

	char *NamePos = RequestEntity + 0x0C;

	if( DefinitionLoop(Context, Name) == TRUE )
	{
		ERRORMSG("Cricular definition for %s.\n", Name);
		return -1;
	}

	if( DNSGenQuestionRecord(NamePos, sizeof(RequestEntity) - 12, Name, Type, DNS_CLASS_IN) == 0 )
	{
        return -1;
	}

	*(_16BIT_UINT *)RequestEntity = rand();

	memcpy(&RecursionContext, Context, sizeof(RecursionContext));

	RecursionContext.Previous = Context;
	RecursionContext.RequestEntity = RequestEntity;

	RecursionContext.RequestLength = 12 + strlen(Name) + 2 + 4;
	RecursionContext.RequestingDomain = Name;
	RecursionContext.RequestingType = Type;
	RecursionContext.RequestingDomainHashValue = ELFHash(Name, 0);
	RecursionContext.ClientIP = Agent;

	StateOfReceiving = QueryBase(&RecursionContext);
	if( StateOfReceiving <= 0 )
	{
		return -1;
	}

	Context -> LastServer = RecursionContext.LastServer;
	Context -> LastProtocol = RecursionContext.LastProtocol;

	return StateOfReceiving;
}

int GetHostsByRaw(const char *RawPackage, StringList *out)
{
	int AnswerCount = DNSGetAnswerCount(RawPackage);

	int loop;
	const char *AnswerRecordPosition;
	const char *DataPos;

	int IpAddressCount = 0;

	char Data[] = "               ";

	for( loop = 1; loop <= AnswerCount; ++loop )
	{
		AnswerRecordPosition = DNSGetAnswerRecordPosition(RawPackage, loop);

		if( DNSGetRecordType(AnswerRecordPosition) == DNS_TYPE_A )
		{
			DataPos = DNSGetResourceDataPos(AnswerRecordPosition);

			DNSParseData(RawPackage, DataPos, 1, Data, sizeof(Data), DNS_RECORD_A, NUM_OF_DNS_RECORD_A, 1);

			StringList_Add(out, Data, ',');

			++IpAddressCount;
		}
	}

	return IpAddressCount;
}

int GetHostsByName(const char *Name, const char *Agent, StringList *out)
{
	ThreadContext Context;

	InitContext(&Context, NULL);

	if( GetAnswersByName(&Context, Name, DNS_TYPE_A, Agent) <= 0 )
	{
		return 0;
	} else {
		return GetHostsByRaw(ExtendableBuffer_GetData(Context.ResponseBuffer), out);
	}

}

int GetMaximumMessageSize(SOCKET sock)
{
#ifdef WIN32
	int		mms = 0;
	int		LengthOfInt = sizeof(mms);

	getsockopt(sock, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&mms, &LengthOfInt);

	return mms;
#else
	return INT_MAX;
#endif
}
