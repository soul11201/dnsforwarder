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
#include "addresschunk.h"
#include "stringlist.h"
#include "domainstatistic.h"
#include "request_response.h"

static AddressChunk Addresses;

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

	RecordsLength = Hosts_GetByQuestion(Context, &AnswerCount);
	if( RecordsLength > 0 )
	{
		Header = ExtendableBuffer_GetData(Context -> ResponseBuffer) + HeaderOffset;

		memcpy(Header, Context -> RequestEntity, Context -> RequestLength);
		((DNSHeader *)Header) -> Flags.Direction = 1;
		((DNSHeader *)Header) -> Flags.AuthoritativeAnswer = 0;
		((DNSHeader *)Header) -> Flags.RecursionAvailable = 1;
		((DNSHeader *)Header) -> Flags.ResponseCode = 0;
		((DNSHeader *)Header) -> Flags.Type = 0;
		((DNSHeader *)Header) -> AnswerCount = htons(AnswerCount);

		if( AnswerCount != 1 && Context -> Compress != FALSE )
		{
			int UnCompressedLength = Context -> RequestLength + RecordsLength;

			int CompressedLength = DNSCompress(Header, UnCompressedLength);

			ExtendableBuffer_Eliminate_Tail(Context -> ResponseBuffer, UnCompressedLength - CompressedLength);
			return CompressedLength;
		} else {
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

	RecordsCount = DNSCache_GetByQuestion(Context -> RequestEntity, Context -> ResponseBuffer, &RecordsLength);
	if( RecordsCount > 0 )
	{
		Header = ExtendableBuffer_GetData(Context -> ResponseBuffer) + HeaderOffset;

		((DNSHeader *)Header) -> AnswerCount = htons(RecordsCount);

		if(Context -> Compress != FALSE)
		{
			int UnCompressedLength = Context -> RequestLength + RecordsLength;
			int CompressedLength = DNSCompress(Header, UnCompressedLength);

			ExtendableBuffer_Eliminate_Tail(Context -> ResponseBuffer, UnCompressedLength - CompressedLength);
			return CompressedLength;
		}
		else
			return Context -> RequestLength + RecordsLength;
	} else {
		return -1;
	}
}

int FetchFromHostsAndCache(ThreadContext *Context, char *ProtocolCharacter)
{
	int	StateOfReceiving = -1;
	int	OriOffset = ExtendableBuffer_GetEndOffset(Context -> ResponseBuffer);

	if( Hosts_IsInited() )
	{
		StateOfReceiving = DNSFetchFromHosts(Context);

		if( StateOfReceiving > 0 ) /* Succeed to query from Hosts  */
		{
			if( ProtocolCharacter != NULL )
				*ProtocolCharacter = 'H';

			DomainStatistic_Add(Context -> RequestingDomain, STATISTIC_TYPE_HOSTS);

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
			if( ProtocolCharacter != NULL )
				*ProtocolCharacter = 'C';

			DomainStatistic_Add(Context -> RequestingDomain, STATISTIC_TYPE_CACHE);

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

	return 0;
}

int InitAddress(void)
{
	const StringList	*tcpaddrs	=	ConfigGetStringList(&ConfigInfo, "TCPServer");
	const StringList	*udpaddrs	=	ConfigGetStringList(&ConfigInfo, "UDPServer");

	const char	*Itr	=	NULL;

	if( AddressChunk_Init(&Addresses, 0) != 0 )
	{
		return -1;
	}

	Itr = StringList_GetNext(tcpaddrs, NULL);
	while( Itr != NULL )
	{
		AddressChunk_AddATCPAddress_FromString(&Addresses, Itr);
		Itr = StringList_GetNext(tcpaddrs, Itr);
	}

	Itr = StringList_GetNext(udpaddrs, NULL);
	while( Itr != NULL )
	{
		AddressChunk_AddAUDPAddress_FromString(&Addresses, Itr);
		Itr = StringList_GetNext(udpaddrs, Itr);
	}

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
										struct sockaddr		**Address,
										sa_family_t			*Family,
										char				*ProtocolCharacter
										)
{
	*Address = AddressChunk_GetOne(&Addresses, Family, Context -> RequestingDomain, ProtocolUsed);

	if( *Address != Context -> LastServer )
	{
		if( Context -> LastProtocol == DNS_QUARY_PROTOCOL_UDP )
		{
			CLOSE_SOCKET(Context -> UDPSocket);
			Context -> UDPSocket = INVALID_SOCKET;
		} else {
			CloseTCPConnection(&(Context -> TCPSocket));
		}
	}

	Context -> LastServer = *Address;
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

static int QueryFromServer(ThreadContext *Context, char *ProtocolCharacter)
{
	int			StateOfReceiving;

	SOCKET		*SocketUsed;

	DNSQuaryProtocol	ProtocolUsed;

	struct	sockaddr	*ServerAddr;

	sa_family_t	Family;

	BOOL		UseSecondary;

	/* Determine whether the secondaries are used */
	if( Context -> SecondarySocket != NULL && IsExcludedDomain(Context -> RequestingDomain) )
	{
		UseSecondary = TRUE;
	} else {
		UseSecondary = FALSE;
	}

	SelectSocketAndProtocol(Context, &SocketUsed, &ProtocolUsed, UseSecondary);

	SetAddressAndPrococolLetter(Context,
								ProtocolUsed,
								&ServerAddr,
								&Family,
								ProtocolCharacter
								);

	StateOfReceiving = QueryFromServerBase(SocketUsed,
										   ServerAddr,
										   Family,
										   ProtocolUsed,
										   Context -> RequestEntity,
										   Context -> RequestLength,
										   Context -> ResponseBuffer,
										   Context -> RequestingDomain
										   );

	if(StateOfReceiving < 0) /* Failed */
	{

		/* Move pointer to the next */
		AddressChunk_Advance(&Addresses, ProtocolUsed);

		if( Context -> SecondarySocket != NULL && AllowFallBack == TRUE )
		{
			if( ProtocolCharacter != NULL )
			{
				INFO("Fallback from %c for %s .\n",
					 *ProtocolCharacter,
					 Context -> RequestingDomain
					 );
			} else {
				INFO("Fallback for %s .\n", Context -> RequestingDomain);
			}

			SelectSocketAndProtocol(Context,
									&SocketUsed,
									&ProtocolUsed,
									!UseSecondary
									);

			SetAddressAndPrococolLetter(Context,
										ProtocolUsed,
										&ServerAddr,
										&Family,
										ProtocolCharacter
										);

			StateOfReceiving = QueryFromServerBase(SocketUsed,
												   ServerAddr,
												   Family,
												   ProtocolUsed,
												   Context -> RequestEntity,
												   Context -> RequestLength,
												   Context -> ResponseBuffer,
												   Context -> RequestingDomain
												   );

			if( StateOfReceiving < 0 )
			{
				/* Move pointer to the next */
				AddressChunk_Advance(&Addresses, ProtocolUsed);

				return QUERY_RESULT_ERROR;
			}
		} else {
			return QUERY_RESULT_ERROR;
		}
	}

	return StateOfReceiving;

}

int QueryBase(ThreadContext *Context, char *ProtocolCharacter)
{
	int StateOfReceiving = -1;

	int	QuestionCount;

	/* Check if this domain or type is disabled */
	if( IsDisabledType(Context -> RequestingType) || IsDisabledDomain(Context -> RequestingDomain) )
	{
		DomainStatistic_Add(Context -> RequestingDomain, STATISTIC_TYPE_REFUSED);
		return QUERY_RESULT_DISABLE;
	}

	/* Get the QuestionCount */
	QuestionCount = DNSGetQuestionCount(Context -> RequestEntity);

	if( QuestionCount == 1 )
	{
		/* First query from hosts and cache */
		StateOfReceiving = FetchFromHostsAndCache(Context, ProtocolCharacter);
	} else {
		StateOfReceiving = -1;
	}

	/* If hosts or cache has no record, then query from server */
	if( StateOfReceiving < 0 )
	{
		StateOfReceiving = QueryFromServer(Context, ProtocolCharacter);
	}

	return StateOfReceiving;

}

int	GetAnswersByName(ThreadContext *Context, const char *Name, DNSRecordType Type)
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
	char *Itr;

	strcpy(NamePos, Name);

	Itr = DNSLabelizedName(NamePos, sizeof(RequestEntity) - 12 - 2);

	if( Itr == NULL )
	{
		return -1;
	}

	SET_16_BIT_U_INT(Itr, Type);
	SET_16_BIT_U_INT(Itr + 2, DNS_CLASS_IN);

	memcpy(&RecursionContext, Context, sizeof(RecursionContext));

	RecursionContext.RequestLength = 12 + strlen(Name) + 2 + 4;
	memcpy(RecursionContext.RequestEntity, RequestEntity, RecursionContext.RequestLength);
	strcpy(RecursionContext.RequestingDomain, Name);
	RecursionContext.RequestingType = Type;

	StateOfReceiving = QueryBase(&RecursionContext, NULL);
	if( StateOfReceiving <= 0 )
	{
		return -1;
	}

	Context -> LastServer = RecursionContext.LastServer;
	Context -> LastProtocol = RecursionContext.LastProtocol;

	return StateOfReceiving;
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
