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
#include "addresslist.h"
#include "stringlist.h"
#include "domainstatistic.h"

ConfigFileInfo	ConfigInfo;
int				TimeToServer;
BOOL			FallBackToSecondary;
BOOL			ShowMassages;
BOOL			ErrorMessages;
#ifdef INTERNAL_DEBUG
EFFECTIVE_LOCK	Debug_Mutex;
FILE			*Debug_File;
#endif

static AddressList	TCPAddresses;
static AddressList	UDPAddresses;

BOOL SocketIsStillReadable(SOCKET Sock)
{
	fd_set rfd;
	struct timeval TimeLimit = {0, 0};

	FD_ZERO(&rfd);
	FD_SET(Sock, &rfd);

	switch(select(Sock + 1, &rfd, NULL, NULL, &TimeLimit))
	{
		case SOCKET_ERROR:
		case 0:
			return FALSE;
			break;
		case 1:
			return TRUE;
			break;
		default:
			return FALSE;
			break;
	}
}

int DNSQueryFromHosts(	__in	QueryContext		*Context,
						__in	char				*QueryingBody,
						__in	int					QueryingLength,
						__inout	ExtendableBuffer	*Buffer
						)
{
	char	*Header;
	int		RecordsLength;
	int		HeaderOffset;
	int		AnswerCount;

	HeaderOffset = ExtendableBuffer_GetEndOffset(Buffer);

	Header = ExtendableBuffer_Expand(Buffer, QueryingLength, NULL);
	if( Header == NULL )
	{
		return -1;
	}

	RecordsLength = Hosts_GetByQuestion(QueryingBody, Buffer, &AnswerCount, Context);
	if( RecordsLength > 0 )
	{
		Header = ExtendableBuffer_GetData(Buffer) + HeaderOffset;

		memcpy(Header, QueryingBody, QueryingLength);
		((DNSHeader *)Header) -> Flags.Direction = 1;
		((DNSHeader *)Header) -> Flags.AuthoritativeAnswer = 0;
		((DNSHeader *)Header) -> Flags.RecursionAvailable = 1;
		((DNSHeader *)Header) -> Flags.ResponseCode = 0;
		((DNSHeader *)Header) -> Flags.Type = 0;
		((DNSHeader *)Header) -> AnswerCount = htons(AnswerCount);

		if( AnswerCount != 1 && Context -> Compress != FALSE )
		{
			int UnCompressedLength = QueryingLength + RecordsLength;

			int CompressedLength = DNSCompress(Header, UnCompressedLength);

			ExtendableBuffer_Eliminate_Tail(Buffer, UnCompressedLength - CompressedLength);
			return CompressedLength;
		} else {
			return QueryingLength + RecordsLength;
		}
	} else {
		return -1;
	}
}

int DNSQueryFromCache(	__in	QueryContext		*Context,
						__in	char				*QueryingBody,
						__in	int					QueryingLength,
						__out	ExtendableBuffer	*Buffer
						)
{
	int RecordsCount, RecordsLength;
	char *Header;
	int HeaderOffset;

	HeaderOffset = ExtendableBuffer_GetEndOffset(Buffer);

	Header = ExtendableBuffer_Expand(Buffer, QueryingLength, NULL);
	if( Header == NULL )
	{
		return -1;
	}

	memcpy(Header, QueryingBody, QueryingLength);
	((DNSHeader *)Header) -> Flags.Direction = 1;
	((DNSHeader *)Header) -> Flags.AuthoritativeAnswer = 0;
	((DNSHeader *)Header) -> Flags.RecursionAvailable = 1;
	((DNSHeader *)Header) -> Flags.ResponseCode = 0;
	((DNSHeader *)Header) -> Flags.Type = 0;

	RecordsCount = DNSCache_GetByQuestion(QueryingBody, Buffer, &RecordsLength);
	if( RecordsCount > 0 )
	{
		Header = ExtendableBuffer_GetData(Buffer) + HeaderOffset;

		((DNSHeader *)Header) -> AnswerCount = htons(RecordsCount);

		if(Context -> Compress != FALSE)
		{
			int UnCompressedLength = QueryingLength + RecordsLength;
			int CompressedLength = DNSCompress(Header, UnCompressedLength);

			ExtendableBuffer_Eliminate_Tail(Buffer, UnCompressedLength - CompressedLength);
			return CompressedLength;
		}
		else
			return QueryingLength + RecordsLength;
	} else {
		return 0;
	}
}

static int DNSQueryRawViaTCP(SOCKET				Sock,
							const void			*Content,
							int					ContentLength,
							ExtendableBuffer	*ResultBuffer,
							_16BIT_UINT			*TCPLength
							)
{
	int		State;
	char	*NewFromServer;
	int		NewTCPLength;

	if(ContentLength == 0) return 0;
	if(ContentLength < 0) return -1;

	if( TCPLength != NULL )
	{
		State = send(Sock, (const char *)TCPLength, 2, MSG_NOSIGNAL);
		if( State < 1 )
		{
			return -2;
		}
	}

	State = send(Sock, (const char *)Content, ContentLength, MSG_NOSIGNAL);
	if( State < 1) return -2;

	/* Get TCPLength */
	NewFromServer = ExtendableBuffer_Expand(ResultBuffer, 2, NULL);
	if( NewFromServer == NULL )
	{
		return -2;
	}

	State = recv(Sock, NewFromServer, 2, MSG_NOSIGNAL);
	if( State < 2 )
	{
		return -2;
	}

	NewTCPLength = GET_16_BIT_U_INT(NewFromServer);

	/* Get DNSBody */
	NewFromServer = ExtendableBuffer_Expand(ResultBuffer, NewTCPLength, NULL);
	if( NewFromServer == NULL )
	{
		return -2;
	}

	State = recv(Sock, NewFromServer, NewTCPLength, MSG_NOSIGNAL);
	if( State < 2 )
	{
		return -2;
	}

	return NewTCPLength + 2;
}

int DNSQueryOriginViaTCP(SOCKET				Sock,
						const void			*OriginDNSBody,
						int					OriginDNSBodyLength,
						DNSQuaryProtocol	OriginProtocol,
						ExtendableBuffer	*ResultBuffer
					  )
{
	if(OriginDNSBodyLength == 0) return 0;
	if(OriginDNSBodyLength < 0) return -1;

	if(OriginProtocol == DNS_QUARY_PROTOCOL_UDP){
		int			State;
		int			CurrentOffset;
		_16BIT_UINT	TCPLength;

		SET_16_BIT_U_INT(&TCPLength, OriginDNSBodyLength);

		CurrentOffset = ExtendableBuffer_GetEndOffset(ResultBuffer);

		State = DNSQueryRawViaTCP(Sock, OriginDNSBody, OriginDNSBodyLength, ResultBuffer, &TCPLength);
		if( State > 2 )
		{
			ExtendableBuffer_Eliminate(ResultBuffer, CurrentOffset, 2);
			return State - 2;
		} else {
			return -1;
		}

	}else{ /* DNS_QUARY_PROTOCOL_TCP */
		return DNSQueryRawViaTCP(Sock, OriginDNSBody, OriginDNSBodyLength, ResultBuffer, NULL);
	}
}

static int DNSQueryRawViaUDP(SOCKET				Sock,
							 struct	sockaddr	*PeerAddr,
							 sa_family_t		Family,
							 const void			*Content,
							 int				ContentLength,
							 ExtendableBuffer	*ResultBuffer
							 ){
	int		AddrLen;
	char	*NewFromServer;
	int		LengthFromServer = 0;
	int		LengthOfNewAllocated = 0;

	int		ReceiveState = 0;

	if(ContentLength == 0) return 0;
	if(ContentLength < 0) return -1;

	if( Family == AF_INET )
	{
		AddrLen = sizeof(struct sockaddr);
	} else {
		AddrLen = sizeof(struct sockaddr_in6);
	}

	if(sendto(Sock, Content, ContentLength, 0, PeerAddr, AddrLen) < 1) return -2;

	do
	{
		if( Family == AF_INET )
		{
			AddrLen = sizeof(struct sockaddr);
		} else {
			AddrLen = sizeof(struct sockaddr_in6);
		}

		NewFromServer = ExtendableBuffer_Expand(ResultBuffer, 384, NULL);

		if( NewFromServer == NULL )
		{
			return -1;
		}

		LengthOfNewAllocated += 384;

		ReceiveState = recvfrom(Sock, NewFromServer, 384, 0, PeerAddr, (socklen_t *)&AddrLen);
		if( ReceiveState > 0 )
		{
			LengthFromServer += ReceiveState;
		} else {
			return -1;
		}

	} while( SocketIsStillReadable(Sock) );

	ExtendableBuffer_Eliminate_Tail(ResultBuffer, LengthOfNewAllocated - LengthFromServer);

	return LengthFromServer;
}

int DNSQueryOriginViaUDP(SOCKET				Sock,
						struct sockaddr		*PeerAddr,
						sa_family_t			Family,
						const void			*OriginDNSBody,
						int					OriginDNSBodyLength,
						DNSQuaryProtocol	OriginProtocol,
						ExtendableBuffer	*ResultBuffer
					  )
{
	if(OriginProtocol == DNS_QUARY_PROTOCOL_UDP)
	{
		return DNSQueryRawViaUDP(Sock, PeerAddr, Family, OriginDNSBody, OriginDNSBodyLength, ResultBuffer);
	} else { /* DNS_QUARY_PROTOCOL_TCP */
		int State;

		char *TCPLength = ExtendableBuffer_Expand(ResultBuffer, 2, NULL);

		if( TCPLength == NULL )
		{
			return -1;
		}

		State = DNSQueryRawViaUDP(Sock, PeerAddr, Family, ((char *)OriginDNSBody) + 2, OriginDNSBodyLength - 2, ResultBuffer);
		if( State > 0 )
		{
			SET_16_BIT_U_INT(TCPLength, State);
			return State + 2;
		} else {
			return -1;
		}
	}
}

int QueryFromHostsAndCache(QueryContext		*Context,
						   const char		*QueryDomain,
						   char				*QueryContent,
						   int				QueryContentLength,
						   ExtendableBuffer	*Buffer,
						   char				*ProtocolCharacter
						  )
{
	int	State = -1;
	int	OriOffset = ExtendableBuffer_GetEndOffset(Buffer);

	if( Hosts_IsInited() )
	{
		char	*TCPLength	=	NULL; /* Only for DNS_QUARY_PROTOCOL_TCP */

		if( Context -> ProtocolToSrc == DNS_QUARY_PROTOCOL_UDP )
			State = DNSQueryFromHosts(Context, QueryContent, QueryContentLength, Buffer);
		else
		{
			TCPLength = ExtendableBuffer_Expand(Buffer, 2, NULL);
			if( TCPLength == NULL )
			{
				State = -1;
			} else { /* DNS_QUARY_PROTOCOL_TCP */
				State = DNSQueryFromHosts(Context, QueryContent + 2, QueryContentLength - 2, Buffer);
			}
		}

		if( State > 0 ) /* Succeed to query from Hosts  */
		{
			if( ProtocolCharacter != NULL )
				*ProtocolCharacter = 'H';

			DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_HOSTS);

			if( Context -> ProtocolToSrc == DNS_QUARY_PROTOCOL_UDP )
			{
				return State;
			}
			else
			{
				SET_16_BIT_U_INT(TCPLength, State);
				return State + 2;
			}
		}
		ExtendableBuffer_SetEndOffset(Buffer, OriOffset);
	}

	if( Cache_IsInited() )
	{

		_32BIT_UINT	TCPLengthStart = 0; /* Only for DNS_QUARY_PROTOCOL_TCP */
		_32BIT_UINT Start = 0;

		if( Context -> ProtocolToSrc == DNS_QUARY_PROTOCOL_UDP )
		{
			Start = ExtendableBuffer_GetEndOffset(Buffer);
			State = DNSQueryFromCache(Context, QueryContent, QueryContentLength, Buffer);
		} else { /* DNS_QUARY_PROTOCOL_TCP */
			TCPLengthStart = ExtendableBuffer_GetEndOffset(Buffer);
			ExtendableBuffer_Expand(Buffer, 2, NULL);
			Start = ExtendableBuffer_GetEndOffset(Buffer);
			State = DNSQueryFromCache(Context, QueryContent + 2, QueryContentLength - 2, Buffer);
		}

		if( State > 0 ) /* Succeed  */
		{
			if( ProtocolCharacter != NULL )
				*ProtocolCharacter = 'C';

			DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_CACHE);

			if( Context -> ProtocolToSrc == DNS_QUARY_PROTOCOL_UDP )
			{
				return DNSCompress(ExtendableBuffer_GetData(Buffer) + Start, State);
			}
			else
			{
				State = DNSCompress(ExtendableBuffer_GetData(Buffer) + Start, State);
				SET_16_BIT_U_INT(ExtendableBuffer_GetData(Buffer) + TCPLengthStart, State);
				return State + 2;
			}
		}

		ExtendableBuffer_SetEndOffset(Buffer, OriOffset);
	}

	return -1;
}

int InitAddress(void)
{
	const StringList	*tcpaddrs	=	ConfigGetStringList(&ConfigInfo, "TCPServer");
	const StringList	*udpaddrs	=	ConfigGetStringList(&ConfigInfo, "UDPServer");

	const char	*Itr	=	NULL;

	if( AddressList_Init(&TCPAddresses) != 0 )
	{
		return -1;
	}

	if( AddressList_Init(&UDPAddresses) != 0 )
	{
		AddressList_Free(&TCPAddresses);
		return -2;
	}


	Itr = StringList_GetNext(tcpaddrs, NULL);
	while( Itr != NULL )
	{
		AddressList_Add_From_String(&TCPAddresses, Itr);
		Itr = StringList_GetNext(tcpaddrs, Itr);
	}

	Itr = StringList_GetNext(udpaddrs, NULL);
	while( Itr != NULL )
	{
		AddressList_Add_From_String(&UDPAddresses, Itr);
		Itr = StringList_GetNext(udpaddrs, Itr);
	}

	return 0;

}

int QueryFromServerBase(SOCKET				*Socket,
						struct	sockaddr	*PeerAddr,
						sa_family_t			Family,
						DNSQuaryProtocol	ProtocolToServer,
						char				*QueryContent,
						int					QueryContentLength,
						DNSQuaryProtocol	ProtocolToSrc,
						ExtendableBuffer	*Buffer,
						const char			*QueryDomain
						)
{
	int State;

	int	StartOffset = ExtendableBuffer_GetEndOffset(Buffer);

	/* Connecting to Server */
	if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
	{
		if(*Socket == INVALID_SOCKET)
		{
			*Socket = socket(Family, SOCK_DGRAM, IPPROTO_UDP);

			if __STILL(*Socket == INVALID_SOCKET)
			{
				DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_REFUSED);
				return -2; /* Failed */
			}
		}

		SetSocketRecvTimeLimit(*Socket, TimeToServer);
	} else {
		if(TCPSocketIsHealthy(Socket) == FALSE)
		{
			if(ConnectToTCPServer(Socket, PeerAddr, Family, TimeToServer) == FALSE)
			{
				DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_REFUSED);
				return -2; /* Failed */
			} else {
				INFO("(Connecting to server Successfully.)\n");
			}
		}
	}
	/* Querying from server */
	if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
    {
		State = DNSQueryOriginViaUDP(*Socket, (struct sockaddr *)PeerAddr, Family, QueryContent, QueryContentLength, ProtocolToSrc, Buffer);
    } else {
		State = DNSQueryOriginViaTCP(*Socket, QueryContent, QueryContentLength, ProtocolToSrc, Buffer);
    }

	if( State > 0 ) /* Succeed  */
	{
		if( Cache_IsInited() )
		{
			int StateOfCacheing;

			if( ProtocolToSrc == DNS_QUARY_PROTOCOL_UDP )
			{
				StateOfCacheing = DNSCache_AddItemsToCache(ExtendableBuffer_GetPositionByOffset(Buffer, StartOffset));
			} else {
				StateOfCacheing = DNSCache_AddItemsToCache(ExtendableBuffer_GetPositionByOffset(Buffer, StartOffset) + 2);
			}

			if( StateOfCacheing != 0 )
			{
				INFO("(Caching in failed. Cache is running out of space?)\n");
			}
		}

		if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
		{
			DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_UDP);
		} else {
			DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_TCP);
		}

		return State;
	} else {
		int OriginErrorCode = GET_LAST_ERROR();

		ExtendableBuffer_SetEndOffset(Buffer, StartOffset);

		if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
		{
			/* Close the bad socket */
			CLOSE_SOCKET(*Socket);
			*Socket = INVALID_SOCKET;

			/* Assume the server is not avaliable now, move to the next server */
			AddressList_Advance(&UDPAddresses);
		} else { /* Similarly, for TCP, below */
			CloseTCPConnection(Socket);
			AddressList_Advance(&TCPAddresses);
		}

		/* For not to overwrite internal error code(may be done by
		 * CLOSE_SOCKET() or CloseTCPConnection() ), write it back */
		SET_LAST_ERROR(OriginErrorCode);

		DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_REFUSED);

		return -1; /* Failed */
	}
}

static void SelectSocketAndProtocol(QueryContext		*Context,
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

static void SetAddressAndPrococolLetter(DNSQuaryProtocol	ProtocolUsed,
										struct sockaddr		**Address,
										sa_family_t			*Family,
										char				*ProtocolCharacter
										)
{
	if( ProtocolUsed == DNS_QUARY_PROTOCOL_UDP )
	{
		/* Assign ProtocolCharacter used by output message */
		if( ProtocolCharacter != NULL )
		{
			*ProtocolCharacter = 'U';
		}

		/* Get a server address */
		*Address = AddressList_GetOne(&UDPAddresses, Family);

	} else { /* For TCP below */
		if( ProtocolCharacter != NULL )
		{
			*ProtocolCharacter = 'T';
		}
		*Address = AddressList_GetOne(&TCPAddresses, Family);
	}
}

static int QueryFromServer(QueryContext		*Context,
						   char				*QueryContent,
						   int				QueryContentLength,
						   ExtendableBuffer	*Buffer,
						   const char		*QueryDomain,
						   char				*ProtocolCharacter
						   )
{
	int			State;

	SOCKET		*SocketUsed;

	DNSQuaryProtocol	ProtocolUsed;

	struct	sockaddr	*ServerAddr;

	sa_family_t	Family;

	BOOL		UseSecondary;

	/* Determine whether the secondaries are used */
	if( Context -> SecondarySocket != NULL && IsExcludedDomain(QueryDomain) )
	{
		UseSecondary = TRUE;
	} else {
		UseSecondary = FALSE;
	}

	SelectSocketAndProtocol(Context, &SocketUsed, &ProtocolUsed, UseSecondary);


	SetAddressAndPrococolLetter(ProtocolUsed,
								&ServerAddr,
								&Family,
								ProtocolCharacter
								);

	State = QueryFromServerBase(SocketUsed,
								ServerAddr,
								Family,
								ProtocolUsed,
								QueryContent,
								QueryContentLength,
								Context -> ProtocolToSrc,
								Buffer,
								QueryDomain
								);

	if(State < 0) /* Failed */
	{
		if( FallBackToSecondary == TRUE )
		{
			if( ProtocolCharacter != NULL )
			{
				INFO("Fallback from %c for %s .\n",
					 *ProtocolCharacter,
					 QueryDomain
					 );
			} else {
				INFO("Fallback for %s .\n", QueryDomain);
			}

			SelectSocketAndProtocol(Context,
									&SocketUsed,
									&ProtocolUsed,
									!UseSecondary
									);

			SetAddressAndPrococolLetter(ProtocolUsed,
										&ServerAddr,
										&Family,
										ProtocolCharacter
										);

			State = QueryFromServerBase(SocketUsed,
										ServerAddr,
										Family,
										ProtocolUsed,
										QueryContent,
										QueryContentLength,
										Context -> ProtocolToSrc,
										Buffer,
										QueryDomain
										);

			if( State < 0 )
			{
				return QUERY_RESULT_ERROR;
			}
		} else {
			return QUERY_RESULT_ERROR;
		}
	}

	return State;

}

int QueryBase(QueryContext		*Context,
			  char				*QueryContent,
			  int				QueryContentLength,
			  ExtendableBuffer	*Buffer,
			  const char		*QueryDomain,
			  DNSRecordType		SourceType,
			  char				*ProtocolCharacter
					)
{
	int State = -1;

	int	QuestionCount;

	/* Check if this domain or type is disabled */
	if( IsDisabledType(SourceType) || IsDisabledDomain(QueryDomain) )
	{
		DomainStatistic_Add(QueryDomain, STATISTIC_TYPE_REFUSED);
		return QUERY_RESULT_DISABLE;
	}

	/* Get the QuestionCount */
	if( Context -> ProtocolToSrc == DNS_QUARY_PROTOCOL_UDP )
	{
		QuestionCount = DNSGetQuestionCount(QueryContent);
	} else {
		QuestionCount = DNSGetQuestionCount(DNSGetDNSBody(QueryContent));
	}

	if( QuestionCount == 1 )
	{
		/* First query from hosts and cache */
		State = QueryFromHostsAndCache(Context, QueryDomain, QueryContent, QueryContentLength, Buffer, ProtocolCharacter);
	} else {
		State = -1;
	}

	/* If hosts or cache has no record, then query from server */
	if( State < 0 )
	{
		State = QueryFromServer(Context,
								QueryContent,
								QueryContentLength,
								Buffer,
								QueryDomain,
								ProtocolCharacter
								);
	}

	return State;

}

int	GetAnswersByName(QueryContext *Context, const char *Name, DNSRecordType Type, ExtendableBuffer	*Buffer)
{
	char	QueryContent[384] = {
		00, 00, /* QueryIdentifier */
		01, 00, /* Flags */
		00, 01, /* QuestionCount */
		00, 00, /* AnswerCount */
		00, 00, /* NameServerCount */
		00, 00, /* AdditionalCount */
		/* Header end */
	};

	char *NamePos = QueryContent + 0x0C;
	char *Itr;

	strcpy(NamePos, Name);

	Itr = DNSLabelizedName(NamePos, sizeof(QueryContent) - 12 - 2);

	if( Itr == NULL )
	{
		return -1;
	}

	SET_16_BIT_U_INT(Itr, Type);
	SET_16_BIT_U_INT(Itr + 2, DNS_CLASS_IN);

	return QueryBase(Context, QueryContent, 12 + strlen(Name) + 2 + 4, Buffer, Name, Type, NULL);
}

int SetSocketWait(SOCKET sock, BOOL Wait)
{
	return setsockopt(sock, SOL_SOCKET, SO_DONTLINGER, (const char *)&Wait, sizeof(BOOL));
}

int SetSocketSendTimeLimit(SOCKET sock, int time)
{
#ifdef WIN32
	return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&time, sizeof(time));
#else
	struct timeval Time = {time / 1000, (time % 1000) * 1000};
	return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Time, sizeof(Time));
#endif
}

int SetSocketRecvTimeLimit(SOCKET sock, int time)
{
#ifdef WIN32
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&time, sizeof(time));
#else
	struct timeval Time = {time / 1000, (time % 1000) * 1000};
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Time, sizeof(Time));
#endif
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

void CloseTCPConnection(SOCKET *sock)
{
	if(*sock != INVALID_SOCKET){
		CLOSE_SOCKET(*sock);
		*sock = INVALID_SOCKET;
	}
}

BOOL TCPSocketIsHealthy(SOCKET *sock)
{
	if(*sock != INVALID_SOCKET){
		/* Testing effectiveness of `*sock' */
		fd_set rfd;
		struct timeval TimeLimit = {0, 0};

		FD_ZERO(&rfd);
		FD_SET((*sock), &rfd);

		switch(select((*sock) + 1, &rfd, NULL, NULL, &TimeLimit)){
			case 0:
				/* Effective */
				return TRUE;
				break;
			case 1:{
				char Buffer[1];
				int state = recv(*sock, Buffer, 1, MSG_NOSIGNAL);

				if(state == 0 || state == SOCKET_ERROR)
					break;
				else
					/* Effective */
					return TRUE;
				   }
				break;
			case SOCKET_ERROR:
				break;
			default:
				break;
		}
		/* Ineffective */
	}
	/* Ineffective */
	return FALSE;
}

/* BOOL ConnectToServer(SOCKET *sock, struct sockaddr_in *addr);
 * Description:
 *  Let the `sock' Connect to the server addressed by `addr'.
 * Parameters:
 *  sock:A pointer to a `SOCKET' that hold the connection.
 *  addr:A pointer to a `struct sockaddr_in' specifying the address to connect.
*/
BOOL ConnectToTCPServer(SOCKET *sock, struct sockaddr *addr, sa_family_t Family, int TimeToServer)
{
	int SizeOfAddr;

	if(*sock != INVALID_SOCKET) CloseTCPConnection(sock);

	if( Family == AF_INET )
	{
		SizeOfAddr = sizeof(struct sockaddr);
	} else {
		SizeOfAddr = sizeof(struct sockaddr_in6);
	}

	/* Rebuild connection */
	*sock = socket(Family, SOCK_STREAM, IPPROTO_TCP);
	if(*sock == INVALID_SOCKET){
		return FALSE;
	}

	/* Do not Wait after closed. */
	SetSocketWait(*sock, TRUE);

	/* Set time limit. */
	SetSocketSendTimeLimit(*sock, TimeToServer);
	SetSocketRecvTimeLimit(*sock, TimeToServer);

	if(connect(*sock, addr, SizeOfAddr) != 0){
		int OriginErrorCode = GET_LAST_ERROR();
		CloseTCPConnection(sock);
		SET_LAST_ERROR(OriginErrorCode);
		return FALSE;
	}
	return TRUE;
}

