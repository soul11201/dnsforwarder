#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "querydnslistentcp.h"
#include "querydnsbase.h"
#include "dnsrelated.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "stringlist.h"
#include "excludedlist.h"
#include "addresslist.h"

/* Variables */
static BOOL			Inited = FALSE;

static SOCKET		ListenSocketTCP;

static sa_family_t	Family;

typedef struct _RecvInfo{
	SOCKET				Socket;
	CompatibleAddr		Peer;
	DNSQuaryProtocol	PrimaryProtocolToServer;
	BOOL				SecondaryExists;
} RecvInfo;

/* Functions */
int QueryDNSListenTCPInit(void)
{
	static struct _Address	ListenAddr;

	const char	*LocalAddr = ConfigGetRawString(&ConfigInfo, "LocalInterface");
	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");

	int			AddrLen;

	Family = GetAddressFamily(LocalAddr);

	ListenSocketTCP = socket(Family, SOCK_STREAM, IPPROTO_TCP);
	if(ListenSocketTCP == INVALID_SOCKET)
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Creating TCP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -1;
	}

	memset(&ListenAddr, 0, sizeof(ListenAddr));

	if( Family == AF_INET )
	{
		FILL_ADDR4(ListenAddr.Addr.Addr4, AF_INET, LocalAddr, LocalPort);

		AddrLen = sizeof(struct sockaddr);
	} else {
		char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

		sscanf(LocalAddr, "[%s]", Addr);

		ListenAddr.Addr.Addr6.sin6_family = Family;
		ListenAddr.Addr.Addr6.sin6_port = htons(LocalPort);
		IPv6AddressToNum(Addr, &(ListenAddr.Addr.Addr6.sin6_addr));

		AddrLen = sizeof(struct sockaddr_in6);
	}

	if(	bind(ListenSocketTCP, (struct sockaddr*)&(ListenAddr.Addr), AddrLen) != 0 )
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Opening TCP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -2;
	}

	if( listen(ListenSocketTCP, 16) == SOCKET_ERROR )
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Opening TCP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -3;
	}

	Inited = TRUE;

	return 0;
}

static int Query(ThreadContext *Context, _16BIT_UINT TCPLength, SOCKET *ClientSocket, CompatibleAddr *ClientAddr)
{
	int		State;

	char	RequestingDomain[256];

	char	ClientIP[LENGTH_OF_IPV6_ADDRESS_ASCII + 1];

	if( Family == AF_INET )
	{
		strcpy(ClientIP, inet_ntoa(ClientAddr -> Addr4.sin_addr));
		Context -> ClientPort = htons(ClientAddr -> Addr4.sin_port);
	} else {
		IPv6AddressToAsc(&(ClientAddr -> Addr6.sin6_addr), ClientIP);
		Context -> ClientPort = htons(ClientAddr -> Addr6.sin6_port);
	}

	Context -> ClientIP = ClientIP;

	RequestingDomain[0] = '\0';
	DNSGetHostName(Context -> RequestEntity,
				   DNSJumpHeader(Context -> RequestEntity),
				   RequestingDomain
				   );

	Context -> RequestingDomain = RequestingDomain;

	Context -> RequestingType =
		(DNSRecordType)DNSGetRecordType(DNSJumpHeader(Context -> RequestEntity));

	Context -> RequestingDomainHashValue = ELFHash(RequestingDomain, 0);

	State = QueryBase(Context);

	switch( State )
	{
		case QUERY_RESULT_DISABLE:
			((DNSHeader *)(Context -> RequestEntity)) -> Flags.Direction = 1;
			((DNSHeader *)(Context -> RequestEntity)) -> Flags.ResponseCode = 5;
			send(*ClientSocket, &TCPLength, 2, 0);
			send(*ClientSocket, Context -> RequestEntity, Context -> RequestLength, 0);
			return -1;
			break;

		case QUERY_RESULT_ERROR:
			return -1;
			break;

		default: /* Succeed */
			{
				_16BIT_UINT ResponseLength;
				SET_16_BIT_U_INT(&ResponseLength, State);
				send(*ClientSocket, &ResponseLength, 2, 0);
				send(*ClientSocket, ExtendableBuffer_GetData(Context -> ResponseBuffer), State, 0);
				return 0;
				break;
			}
	}
}

static int ReceiveFromClient(RecvInfo *Info)
{
	SOCKET				Socket	=	Info -> Socket;
	CompatibleAddr		Peer	=	Info -> Peer;
	int					state;

	_16BIT_UINT			TCPLength = 0; /* Big-endian */

	ThreadContext		Context;

	char				RequestEntity[1024];

	Context.Head = &Context;
	Context.Previous = NULL;
	Context.TCPSocket = INVALID_SOCKET;
	Context.UDPSocket = INVALID_SOCKET;
	Context.LastServer = NULL;
	Context.Compress = TRUE;
	Context.ResponseBuffer = &(Context.ResponseBuffer_Entity);
	ExtendableBuffer_Init(Context.ResponseBuffer, 512, 10240);
	Context.RequestEntity = RequestEntity + 2;

	if( Info -> PrimaryProtocolToServer == DNS_QUARY_PROTOCOL_TCP )
	{
		Context.PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_TCP;
		Context.PrimarySocket = &(Context.TCPSocket);

		if( Info -> SecondaryExists == TRUE )
			Context.SecondarySocket = &(Context.UDPSocket);
		else
			Context.SecondarySocket = NULL;

	} else {
		Context.PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_UDP;
		Context.PrimarySocket = &(Context.UDPSocket);

		if( Info -> SecondaryExists == TRUE )
			Context.SecondarySocket = &(Context.TCPSocket);
		else
			Context.SecondarySocket = NULL;
	}

	while(TRUE){
		state = recv(Socket, RequestEntity, sizeof(RequestEntity), MSG_NOSIGNAL);
		if(GET_LAST_ERROR() == TCP_TIME_OUT)
		{
			break;
		}

		if( state <= 2 )
		{
			break;
		}

		memcpy(&TCPLength, RequestEntity, sizeof(TCPLength));
		Context.RequestLength = state - 2;

		Query(&Context,
			  TCPLength,
			  &Socket,
			  &Peer
			  );

		ExtendableBuffer_Reset(Context.ResponseBuffer);

	}

	CLOSE_SOCKET(Context.TCPSocket);
	CLOSE_SOCKET(Context.UDPSocket);

	CLOSE_SOCKET(Socket);

	if( Family == AF_INET )
	{
		INFO("Closed TCP connection to %s:%d\n",
			 inet_ntoa(Peer.Addr4.sin_addr),
			 Peer.Addr4.sin_port
			 );
	} else {
		char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

		IPv6AddressToAsc(&(Peer.Addr6.sin6_addr), Addr);

		INFO("Closed TCP connection to %s:%d\n", Addr, Peer.Addr6.sin6_port);
	}

	SafeFree(Info);

	EXIT_THREAD(0);
}

static int QueryDNSListenTCP(void *Unused)
{
	ThreadHandle		NewSpawnedThread;
	RecvInfo			*Info = NULL;
	CompatibleAddr		*Peer;
	socklen_t			AddrLen;

	DNSQuaryProtocol	PrimaryProtocolToServer;
	BOOL				SecondaryExists;

	char				ProtocolStr[8] = {0};

	strncpy(ProtocolStr, ConfigGetRawString(&ConfigInfo, "PrimaryServer"), 3);
	StrToLower(ProtocolStr);

	if( strcmp(ProtocolStr, "tcp") == 0 )
	{
		PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_TCP;
		if( ConfigGetStringList(&ConfigInfo, "UDPServer") == NULL )
		{
			SecondaryExists = FALSE;
		} else {
			SecondaryExists = TRUE;
		}
	} else {
		PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_UDP;
		if( ConfigGetStringList(&ConfigInfo, "TCPServer") == NULL )
		{
			SecondaryExists = FALSE;
		} else {
			SecondaryExists = TRUE;
		}
	}

	while(TRUE){

		Info = SafeMalloc(sizeof(RecvInfo));
		if( Info == NULL )
		{
			break;
		}

		Peer = &(Info -> Peer);
		memset(Info, 0, sizeof(CompatibleAddr));
		Info -> PrimaryProtocolToServer = PrimaryProtocolToServer;
		Info -> SecondaryExists = SecondaryExists;

		if( Family == AF_INET )
		{
			AddrLen = sizeof(struct sockaddr);
			Info -> Socket = accept(ListenSocketTCP,
									(struct sockaddr *)&(Peer -> Addr4),
									(socklen_t *)&AddrLen
									);
		} else {
			AddrLen = sizeof(struct sockaddr_in6);
			Info -> Socket = accept(ListenSocketTCP,
									(struct sockaddr *)&(Peer -> Addr6),
									(socklen_t *)&AddrLen
									);
		}

		if(Info -> Socket == INVALID_SOCKET)
		{
			SafeFree(Info);
			continue;
		}

		SetSocketWait(Info -> Socket, TRUE);
		SetSocketRecvTimeLimit(Info -> Socket, 2000);

		if( Family == AF_INET )
		{
			INFO("Established TCP connection to %s:%d\n",
				 inet_ntoa(Peer -> Addr4.sin_addr),
				 Peer -> Addr4.sin_port
				 );
		} else {
			char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

			IPv6AddressToAsc(&(Peer -> Addr6.sin6_addr), Addr);

			INFO("Established TCP connection to [%s]:%d\n",
				 Addr,
				 Peer -> Addr6.sin6_port
				 );
		}

		CREATE_THREAD(ReceiveFromClient, (void *)Info, NewSpawnedThread);
		DETACH_THREAD(NewSpawnedThread);
	}
	CLOSE_SOCKET(ListenSocketTCP);
	return 0;
}

void QueryDNSListenTCPStart(void)
{
	static ThreadHandle	Unused;

	if(Inited == FALSE)
		return;

	INFO("Starting TCP socket %s:%d successfully.\n",
		 ConfigGetRawString(&ConfigInfo, "LocalInterface"),
		 ConfigGetInt32(&ConfigInfo, "LocalPort")
		 );
	CREATE_THREAD(QueryDNSListenTCP, NULL, Unused);

	DETACH_THREAD(Unused);

}
