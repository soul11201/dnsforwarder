#include "request_response.h"
#include "extendablebuffer.h"
#include "domainstatistic.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
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

	while( SocketIsStillReadable(Sock) )
	{
		recvfrom(Sock, BlackHole, sizeof(BlackHole), 0, NULL, NULL);
	}
}

int SendAndReveiveRawMessageViaTCP(SOCKET			Sock,
								   const void		*Content,
								   int				ContentLength,
								   ExtendableBuffer	*ResultBuffer,
								   _16BIT_UINT		*TCPLength /* Big-endian */
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
	_16BIT_UINT	TCPLength;

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

int QueryDNSViaUDP(SOCKET			Sock,
				   struct sockaddr	**PeerAddr_List,
				   int				NumberOfAddresses,
				   const void		*RequestEntity,
				   int				RequestLength,
				   ExtendableBuffer	*ResultBuffer
				   )
{
	int		AddrLen;
	char	*NewlyReceived;
	static int	LengthOfNewlyAllocated = 2048;

	int		StateOfReceiving = 0;

	int		StateOfSending = 0;

	sa_family_t	Family;

	if(RequestLength == 0) return 0;
	if(RequestLength < 0) return -1;

	Family = (*PeerAddr_List) -> sa_family;

	if( Family == AF_INET )
	{
		AddrLen = sizeof(struct sockaddr);
	} else {
		AddrLen = sizeof(struct sockaddr_in6);
	}

	while( NumberOfAddresses != 0 )
	{
		StateOfSending |= (sendto(Sock, RequestEntity, RequestLength, 0, *PeerAddr_List, AddrLen) > 0);

		++PeerAddr_List;
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

		if( *(_16BIT_UINT *)RequestEntity != *(_16BIT_UINT *)NewlyReceived )
		{
			continue;
		}

		if( ((DNSHeader *)NewlyReceived) -> Flags.ResponseCode != 0 )
		{
			continue;
		}

		ClearSocketBuffer(Sock);

		break;
	}

	ExtendableBuffer_Eliminate_Tail(ResultBuffer, LengthOfNewlyAllocated - StateOfReceiving);

	return StateOfReceiving;
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

void CloseTCPConnection(SOCKET *sock)
{
	if(*sock != INVALID_SOCKET){
		CLOSE_SOCKET(*sock);
		*sock = INVALID_SOCKET;
	}
}

int QueryFromServerBase(SOCKET				*Socket,
						struct	sockaddr	**ServerAddress_List,
						int					NumberOfAddresses,
						DNSQuaryProtocol	ProtocolToServer,
						const char			*RequestEntity,
						int					RequestLength,
						ExtendableBuffer	*ResultBuffer,
						const char			*RequestingDomain
						)
{
	int			StateOfReceiving;

	_32BIT_INT	StartOffset = ExtendableBuffer_GetEndOffset(ResultBuffer);

	/* Connecting to Server */
	if( ProtocolToServer == DNS_QUARY_PROTOCOL_UDP )
	{
		if(*Socket == INVALID_SOCKET)
		{
			*Socket = socket((*ServerAddress_List) -> sa_family, SOCK_DGRAM, IPPROTO_UDP);

			if __STILL(*Socket == INVALID_SOCKET)
			{
				DomainStatistic_Add(RequestingDomain, NULL, STATISTIC_TYPE_REFUSED);
				return -2; /* Failed */
			}
		}

		SetSocketRecvTimeLimit(*Socket, TimeToServer);
	} else {
		if(TCPSocketIsHealthy(Socket) == FALSE)
		{
			if(ConnectToTCPServer(Socket, *ServerAddress_List, (*ServerAddress_List) -> sa_family, TimeToServer) == FALSE)
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
		StateOfReceiving = QueryDNSViaUDP(*Socket, ServerAddress_List, NumberOfAddresses, RequestEntity, RequestLength, ResultBuffer);
    } else {
		StateOfReceiving = QueryDNSViaTCP(*Socket, RequestEntity, RequestLength, ResultBuffer);
    }

	if( StateOfReceiving > 0 ) /* Succeed  */
	{
		if( Cache_IsInited() )
		{
			int StateOfCacheing;

			StateOfCacheing = DNSCache_AddItemsToCache(ExtendableBuffer_GetPositionByOffset(ResultBuffer, StartOffset), time(NULL));

			if( StateOfCacheing != 0 )
			{
				INFO("(Caching in failed. Cache is running out of space?)\n");
			}
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
