#include "request_response.h"
#include "extendablebuffer.h"
#include "domainstatistic.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "ipchunk.h"
#include "utils.h"
#include "common.h"

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

void ClearSocketBuffer(SOCKET Sock)
{
	char BlackHole[128];

	int OriginErrorCode = GET_LAST_ERROR();

	while( SocketIsStillReadable(Sock) )
	{
		recvfrom(Sock, BlackHole, sizeof(BlackHole), 0, NULL, NULL);
	}

	SET_LAST_ERROR(OriginErrorCode);
}

int SendAndReveiveRawMessageViaTCP(SOCKET			Sock,
								   const void		*Content,
								   int				ContentLength,
								   ExtendableBuffer	*ResultBuffer,
								   uint16_t		*TCPLength /* Big-endian */
								   )
{
	int		StateOfReceiving;
	char	*NewlyReceived;
	int		NewTCPLength;

	if(ContentLength == 0) return 0;
	if(ContentLength < 0) return -1;

	if( TCPLength != NULL )
	{
		StateOfReceiving = send(Sock, (const char *)TCPLength, 2, MSG_NOSIGNAL);

		if( StateOfReceiving < 1 )
		{
			return -2;
		}
	}

	StateOfReceiving = send(Sock, (const char *)Content, ContentLength, MSG_NOSIGNAL);
	if( StateOfReceiving < 1) return -2;

	/* Get TCPLength field of response */
	NewlyReceived = ExtendableBuffer_Expand(ResultBuffer, 2, NULL);
	if( NewlyReceived == NULL )
	{
		return -2;
	}

	StateOfReceiving = recv(Sock, NewlyReceived, 2, MSG_NOSIGNAL);
	if( StateOfReceiving < 2 )
	{
		return -2;
	}

	NewTCPLength = GET_16_BIT_U_INT(NewlyReceived);

	/* Get DNS entity */
	NewlyReceived = ExtendableBuffer_Expand(ResultBuffer, NewTCPLength, NULL);
	if( NewlyReceived == NULL )
	{
		return -2;
	}

	StateOfReceiving = recv(Sock, NewlyReceived, NewTCPLength, MSG_NOSIGNAL);
	if( StateOfReceiving < 2 )
	{
		return -2;
	}

	return NewTCPLength + 2;
}

int QueryDNSViaTCP(SOCKET			Sock,
				   const void		*RequestEntity,
				   int				RequestLength,
				   ExtendableBuffer	*ResultBuffer
				   )
{
	int			StateOfReceiving;
	int			CurrentOffset;
	uint16_t	TCPLength;

	if(RequestLength == 0) return 0;
	if(RequestLength < 0) return -1;

	SET_16_BIT_U_INT(&TCPLength, RequestLength);

	CurrentOffset = ExtendableBuffer_GetEndOffset(ResultBuffer);

	StateOfReceiving = SendAndReveiveRawMessageViaTCP(Sock, RequestEntity, RequestLength, ResultBuffer, &TCPLength);
	if( StateOfReceiving > 2 )
	{
		ExtendableBuffer_Eliminate(ResultBuffer, CurrentOffset, 2);
		return StateOfReceiving - 2;
	} else {
		return -1;
	}
}

static char OptPseudoRecord[] = {
	0x00,
	0x00, 0x29,
	0x05, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00
};

static BOOL UDPAppendEDNSOpt = FALSE;
static BOOL UDPAntiPollution = FALSE;

void SetUDPAntiPollution(BOOL State)
{
	UDPAntiPollution = State;
}

void SetUDPAppendEDNSOpt(BOOL State)
{
	UDPAppendEDNSOpt = State;
}

static IpChunk	*BlockedIP = NULL;

int InitBlockedIP(StringList *l)
{
	const char	*Itr = NULL;
	uint32_t	Ip;

	if( l == NULL )
	{
		return 0;
	}

	BlockedIP = SafeMalloc(sizeof(IpChunk));
	IpChunk_Init(BlockedIP);

	Itr = StringList_GetNext(l, NULL);

	while( Itr != NULL )
	{
		IPv4AddressToNum(Itr, &Ip);

		IpChunk_Add(BlockedIP, Ip);

		Itr = StringList_GetNext(l, Itr);
	}

	StringList_Free(l);

	return 0;
}

int QueryDNSViaUDP(SOCKET			Sock,
				   struct sockaddr	*PeerAddr_List,
				   int				NumberOfAddresses,
				   void				*RequestEntity,
				   int				RequestLength,
				   ExtendableBuffer	*ResultBuffer,
				   const char		*RequestingDomain
				   )
{
	int		AddrLen;
	char	*NewlyReceived;
	static int	LengthOfNewlyAllocated = 2048;

	int		StateOfReceiving = 0;

	int		StateOfSending = 0;

	sa_family_t	Family;

	BOOL	ThereExistAdditionalRecord = FALSE;

	int		AnswerCount = 0;

	if(RequestLength == 0) return 0;
	if(RequestLength < 0) return -1;

	if( UDPAppendEDNSOpt == TRUE && DNSGetAdditionalCount(RequestEntity) == 0 )
	{
		memcpy((char *)RequestEntity + RequestLength, OptPseudoRecord, sizeof(OptPseudoRecord));

		DNSSetAdditionalCount(RequestEntity, 1);

		RequestLength += sizeof(OptPseudoRecord);
	}

	if( DNSGetAdditionalCount(RequestEntity) > 0 )
	{
		ThereExistAdditionalRecord = TRUE;
	}

	Family = PeerAddr_List -> sa_family;

	if( Family == AF_INET )
	{
		AddrLen = sizeof(struct sockaddr);
	} else {
		AddrLen = sizeof(struct sockaddr_in6);
	}

	while( NumberOfAddresses != 0 )
	{
		StateOfSending |= (sendto(Sock, RequestEntity, RequestLength, 0, PeerAddr_List, AddrLen) > 0);

		PeerAddr_List = (struct sockaddr *)(((char *)PeerAddr_List) + AddrLen);

		--NumberOfAddresses;
	}

	if( StateOfSending == 0 )
	{
		return -1;
	}

	NewlyReceived = ExtendableBuffer_Expand(ResultBuffer, LengthOfNewlyAllocated, NULL);

	if( NewlyReceived == NULL )
	{
		return -1;
	}

	while( TRUE )
	{
		StateOfReceiving = recvfrom(Sock, NewlyReceived, LengthOfNewlyAllocated, 0, NULL, NULL);

		if( StateOfReceiving <= 0 )
		{
			break;
		}

		if( *(uint16_t *)RequestEntity != *(uint16_t *)NewlyReceived )
		{
			continue;
		}

		if( ((DNSHeader *)NewlyReceived) -> Flags.ResponseCode != 0 )
		{
			continue;
		}

		AnswerCount = DNSGetAnswerCount(NewlyReceived);

		if( UDPAntiPollution == TRUE &&
			AnswerCount > 0)
		{
			const unsigned char *Answer;
			uint32_t *Data;

			Answer = (const unsigned char *)DNSGetAnswerRecordPosition(NewlyReceived, 1);

			Data = (uint32_t *)DNSGetResourceDataPos(Answer);

			if( DNSGetRecordType(Answer) == DNS_TYPE_A && *Answer != 0xC0 )
			{
				if( BlockedIP != NULL )
				{
					if( IpChunk_Find(BlockedIP, *Data) == TRUE )
					{
						ShowBlockedMessage(RequestingDomain, NewlyReceived, "False package, discarded");
					} else {
						ShowBlockedMessage(RequestingDomain, NewlyReceived, "False package, discarded. And its IP address is not in `UDPBlock_IP'");
					}
				} else {
					ShowBlockedMessage(RequestingDomain, NewlyReceived, "False package, discarded");
				}

				continue;
			}

			if( BlockedIP != NULL )
			{
				int					Loop		=	1;
				const unsigned char	*Answer1	=	Answer;
				uint32_t			*Data1		=	Data;

				do
				{
					if( DNSGetRecordType(Answer1) == DNS_TYPE_A && IpChunk_Find(BlockedIP, *Data1) == TRUE )
					{
						ShowBlockedMessage(RequestingDomain, NewlyReceived, "Containing blocked ip, discarded");
						Loop = -1;
						break;
					}

					++Loop;

					Answer1 = (const unsigned char *)DNSGetAnswerRecordPosition(NewlyReceived, Loop);
					Data1 = (uint32_t *)DNSGetResourceDataPos(Answer1);

				} while( Loop <= AnswerCount );

				if( Loop == -1 )
				{
					continue;
				}

			}

			if( ThereExistAdditionalRecord == TRUE && DNSGetAdditionalCount(NewlyReceived) <= 0 )
			{
				ShowBlockedMessage(RequestingDomain, NewlyReceived, "False package, discarded");
				continue;
			}
		}

		break;
	}

	ExtendableBuffer_Eliminate_Tail(ResultBuffer, LengthOfNewlyAllocated - StateOfReceiving);

	return StateOfReceiving;
}

int ProbeFakeAddresses(const char	*ServerAddress,
					   const char	*RequestingDomain,
					   StringList	*out
					   )
{
	char	RequestEntity[384] = {
		00, 00, /* QueryIdentifier */
		01, 00, /* Flags */
		00, 01, /* QuestionCount */
		00, 00, /* AnswerCount */
		00, 00, /* NameServerCount */
		00, 00, /* AdditionalCount */
		/* Header end */
	};

	struct sockaddr_in	PeerAddr;
	SOCKET	Sock;

	int		NumberOfAddresses = 0;

	int		RequestLength;

	int		AddrLen = sizeof(struct sockaddr);
	char	NewlyReceived[2048];

	if( DNSGenQuestionRecord(RequestEntity + 12, sizeof(RequestEntity) - 12, RequestingDomain, DNS_TYPE_NS, DNS_CLASS_IN) == 0 )
	{
		return -1;
	}

	FILL_ADDR4(PeerAddr, AF_INET, ServerAddress, 53);

	Sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if( Sock == INVALID_SOCKET )
	{
		return -1;
	}

	SetSocketRecvTimeLimit(Sock, 2000);

	RequestLength = 12 + strlen(RequestingDomain) + 2 + 4;

	*(uint16_t *)RequestEntity = rand();

	if( sendto(Sock, RequestEntity, RequestLength, 0, (struct sockaddr *)&PeerAddr, AddrLen) == 0 )
	{
		CLOSE_SOCKET(Sock);
		return -1;
	}

	while( TRUE )
	{
		if( recvfrom(Sock, NewlyReceived, sizeof(NewlyReceived), 0, NULL, NULL) <= 0 )
		{
			break;
		}

		if( *(uint16_t *)RequestEntity != *(uint16_t *)NewlyReceived )
		{
			continue;
		}

		if( ((DNSHeader *)NewlyReceived) -> Flags.ResponseCode != 0 )
		{
			continue;
		}

		if( DNSGetAnswerCount(NewlyReceived) > 0 )
		{
			const char *FirstAnswer;

			FirstAnswer = DNSGetAnswerRecordPosition(NewlyReceived, 1);

			if( DNSGetRecordType(FirstAnswer) == DNS_TYPE_A )
			{
				NumberOfAddresses += GetHostsByRaw(NewlyReceived, out);

				continue;
			} else {
				break;
			}
		}

		if( DNSGetNameServerCount(NewlyReceived) == 0 && DNSGetAdditionalCount(NewlyReceived) == 0 )
		{
			continue;
		}

		break;
	}

	ClearSocketBuffer(Sock);

	CLOSE_SOCKET(Sock);
	return NumberOfAddresses;
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

static int	ServerTimeOut = 2000;

void SetServerTimeOut(int TimeOut)
{
	ServerTimeOut = TimeOut;
}

/* BOOL ConnectToServer(SOCKET *sock, struct sockaddr_in *addr);
 * Description:
 *  Let the `sock' Connect to the server addressed by `addr'.
 * Parameters:
 *  sock:A pointer to a `SOCKET' that hold the connection.
 *  addr:A pointer to a `struct sockaddr_in' specifying the address to connect.
*/
BOOL ConnectToTCPServer(SOCKET *sock, struct sockaddr *addr, sa_family_t Family)
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
	SetSocketSendTimeLimit(*sock, ServerTimeOut);
	SetSocketRecvTimeLimit(*sock, ServerTimeOut);

	if(connect(*sock, addr, SizeOfAddr) != 0){
		int OriginErrorCode = GET_LAST_ERROR();
		CloseTCPConnection(sock);
		SET_LAST_ERROR(OriginErrorCode);
		return FALSE;
	}
	return TRUE;
}

void CloseTCPConnection(SOCKET *sock)
{
	if(*sock != INVALID_SOCKET){
		CLOSE_SOCKET(*sock);
		*sock = INVALID_SOCKET;
	}
}

int QueryFromServerBase(SOCKET				*Socket,
						struct	sockaddr	*ServerAddress_List,
						int					NumberOfAddresses,
						DNSQuaryProtocol	ProtocolToServer,
						char				*RequestEntity,
						int					RequestLength,
						ExtendableBuffer	*ResultBuffer,
						const char			*RequestingDomain
						)
{
	int			StateOfReceiving;

	int32_t	StartOffset = ExtendableBuffer_GetEndOffset(ResultBuffer);

	/* Connecting to Server */
	if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
	{
		if(*Socket == INVALID_SOCKET)
		{
			*Socket = socket(ServerAddress_List -> sa_family, SOCK_DGRAM, IPPROTO_UDP);

			if __STILL(*Socket == INVALID_SOCKET)
			{
				DomainStatistic_Add(RequestingDomain, NULL, STATISTIC_TYPE_REFUSED);
				return -2; /* Failed */
			}
		}

		SetSocketRecvTimeLimit(*Socket, ServerTimeOut);
	} else {
		if(TCPSocketIsHealthy(Socket) == FALSE)
		{
			if(ConnectToTCPServer(Socket, ServerAddress_List, ServerAddress_List -> sa_family) == FALSE)
			{
				DomainStatistic_Add(RequestingDomain, NULL, STATISTIC_TYPE_REFUSED);
				return -2; /* Failed */
			} else {
				INFO("(Connecting to server Successfully.)\n");
			}
		}
	}
	/* Querying from server */
	if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
    {
		StateOfReceiving = QueryDNSViaUDP(*Socket, ServerAddress_List, NumberOfAddresses, RequestEntity, RequestLength, ResultBuffer, RequestingDomain);
    } else {
		StateOfReceiving = QueryDNSViaTCP(*Socket, RequestEntity, RequestLength, ResultBuffer);
    }

	if( StateOfReceiving > 0 ) /* Succeed  */
	{
		if( Cache_IsInited() )
		{
			DNSCache_AddItemsToCache(ExtendableBuffer_GetPositionByOffset(ResultBuffer, StartOffset), time(NULL));
		}

		if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
		{
			DomainStatistic_Add(RequestingDomain, NULL, STATISTIC_TYPE_UDP);
		} else {
			DomainStatistic_Add(RequestingDomain, NULL, STATISTIC_TYPE_TCP);
		}

		return StateOfReceiving;
	} else {
		int OriginErrorCode = GET_LAST_ERROR();

		ExtendableBuffer_SetEndOffset(ResultBuffer, StartOffset);

		if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
		{
			/* Close the bad socket */
			CLOSE_SOCKET(*Socket);
			*Socket = INVALID_SOCKET;
		} else { /* Similarly, for TCP, below */
			CloseTCPConnection(Socket);
		}

		/* For not to overwrite internal error code(may be done by
		 * CLOSE_SOCKET() or CloseTCPConnection() ), write it back */
		SET_LAST_ERROR(OriginErrorCode);

		DomainStatistic_Add(RequestingDomain, NULL, STATISTIC_TYPE_REFUSED);

		return -1; /* Failed */
	}
}
