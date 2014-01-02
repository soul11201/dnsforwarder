#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "querydnslistenudp.h"
#include "querydnsbase.h"
#include "dnsrelated.h"
#include "dnsparser.h"
#include "common.h"
#include "utils.h"
#include "stringlist.h"
#include "excludedlist.h"

/* Variables */
static BOOL			Inited = FALSE;

static MutexHandle	ListenMutex;
static EFFECTIVE_LOCK	LockOfSendBack;

static SOCKET		ListenSocketUDP;

static sa_family_t	Family;

static ThreadHandle	*Threads;

static int			MaximumMessageSize;

static int			RefusingResponseCode = 0;

#define _SendTo(...)	EFFECTIVE_LOCK_GET(LockOfSendBack); \
						sendto(__VA_ARGS__); \
						EFFECTIVE_LOCK_RELEASE(LockOfSendBack);

/* Functions */
int QueryDNSListenUDPInit(void)
{
	CompatibleAddr ListenAddr;

	const char	*LocalAddr = ConfigGetRawString(&ConfigInfo, "LocalInterface");

	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");

	int			AddrLen;

	RefusingResponseCode = ConfigGetInt32(&ConfigInfo, "RefusingResponseCode");

	Family = GetAddressFamily(LocalAddr);

	ListenSocketUDP = socket(Family, SOCK_DGRAM, IPPROTO_UDP);

	if(ListenSocketUDP == INVALID_SOCKET)
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Creating UDP socket failed. %d : %s\n",
				 ErrorNum,
				 ErrorMessage
				 );
		return -1;
	}

	memset(&ListenAddr, 0, sizeof(ListenAddr));

	if( Family == AF_INET )
	{
		FILL_ADDR4(ListenAddr.Addr4, AF_INET, LocalAddr, LocalPort);

		AddrLen = sizeof(struct sockaddr);
	} else {
		char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

		sscanf(LocalAddr, "[%s]", Addr);

		ListenAddr.Addr6.sin6_family = Family;
		ListenAddr.Addr6.sin6_port = htons(LocalPort);
		IPv6AddressToNum(Addr, &(ListenAddr.Addr6.sin6_addr));

		AddrLen = sizeof(struct sockaddr_in6);
	}

	if(	bind(ListenSocketUDP, (struct sockaddr*)&(ListenAddr), AddrLen)
			!= 0
		)
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Opening UDP socket failed. %d : %s\n",
				 ErrorNum,
				 ErrorMessage
				 );
		return -2;
	}

	CREATE_MUTEX(ListenMutex);
	EFFECTIVE_LOCK_INIT(LockOfSendBack);

	MaximumMessageSize = GetMaximumMessageSize(ListenSocketUDP);
	if(MaximumMessageSize < 0)
	{
		MaximumMessageSize = 1000;
	}
	Inited = TRUE;

	return 0;
}

static int Query(ThreadContext *Context, CompatibleAddr *ClientAddr)
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

	Context -> CurrentTime = time(NULL);

	State = QueryBase(Context);

	switch( State )
	{
		case QUERY_RESULT_DISABLE:
			((DNSHeader *)(Context -> RequestEntity)) -> Flags.Direction = 1;
			((DNSHeader *)(Context -> RequestEntity)) -> Flags.RecursionAvailable = 1;
			((DNSHeader *)(Context -> RequestEntity)) -> Flags.ResponseCode = RefusingResponseCode;
			if( Family == AF_INET )
			{
				_SendTo(ListenSocketUDP,
						Context -> RequestEntity,
						Context -> RequestLength,
						0,
						(struct sockaddr *)&(ClientAddr -> Addr4),
						sizeof(struct sockaddr)
						);
			} else {
				_SendTo(ListenSocketUDP,
						Context -> RequestEntity,
						Context -> RequestLength,
						0,
						(struct sockaddr *)&(ClientAddr -> Addr6),
						sizeof(struct sockaddr_in6)
						);
			}
			return -1;
			break;

		case QUERY_RESULT_ERROR:
			return -1;
			break;

		default: /* Succeed */
			if(State > MaximumMessageSize)
			{
				State = MaximumMessageSize;
				((DNSHeader *)(ExtendableBuffer_GetData(Context -> ResponseBuffer))) -> Flags.TrunCation = 1;
			}

			if( Family == AF_INET )
			{
				_SendTo(ListenSocketUDP,
						ExtendableBuffer_GetData(Context -> ResponseBuffer),
						State,
						0,
						(struct sockaddr *)&(ClientAddr -> Addr4),
						sizeof(struct sockaddr)
						);
			} else {
				_SendTo(ListenSocketUDP,
						ExtendableBuffer_GetData(Context -> ResponseBuffer),
						State,
						0,
						(struct sockaddr *)&(ClientAddr -> Addr6),
						sizeof(struct sockaddr_in6)
						);
			}
			return 0;
	}
}

static int QueryDNSListenUDP(void *ID){
	socklen_t			AddrLen;

	CompatibleAddr		ClientAddr;

	int					State;

	ThreadContext		Context;

	char				ProtocolStr[8] = {0};

	char				RequestEntity[1024];

	Context.Head = &Context;
	Context.Previous = NULL;
	Context.TCPSocket = INVALID_SOCKET;
	Context.UDPSocket = INVALID_SOCKET;
	Context.LastServer = NULL;
	Context.Compress = TRUE;
	Context.ResponseBuffer = &(Context.ResponseBuffer_Entity);
	ExtendableBuffer_Init(Context.ResponseBuffer, 512, 10240);
	Context.RequestEntity = RequestEntity;

	/* Choose and fill default primary and secondary socket */
	strncpy(ProtocolStr, ConfigGetRawString(&ConfigInfo, "PrimaryServer"), 3);
	StrToLower(ProtocolStr);

	if( strcmp(ProtocolStr, "tcp") == 0 )
	{
		Context.PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_TCP;
		Context.PrimarySocket = &(Context.TCPSocket);

		if( ConfigGetStringList(&ConfigInfo, "UDPServer") != NULL )
			Context.SecondarySocket = &(Context.UDPSocket);
		else
			Context.SecondarySocket = NULL;

	} else {
		Context.PrimaryProtocolToServer = DNS_QUARY_PROTOCOL_UDP;
		Context.PrimarySocket = &(Context.UDPSocket);

		if( ConfigGetStringList(&ConfigInfo, "TCPServer") != NULL )
			Context.SecondarySocket = &(Context.TCPSocket);
		else
			Context.SecondarySocket = NULL;
	}

	/* Listen and accept requests */
	while(TRUE)
	{
		memset(&ClientAddr, 0, sizeof(ClientAddr));

		GET_MUTEX(ListenMutex);

		if( Family == AF_INET )
		{
			AddrLen = sizeof(struct sockaddr);
			State = recvfrom(ListenSocketUDP,
							 RequestEntity,
							 sizeof(RequestEntity),
							 0,
							 (struct sockaddr *)&(ClientAddr.Addr4),
							 &AddrLen
							 );

		} else {
			AddrLen = sizeof(struct sockaddr_in6);
			State = recvfrom(ListenSocketUDP,
							 RequestEntity,
							 sizeof(RequestEntity),
							 0,
							 (struct sockaddr *)&(ClientAddr.Addr6),
							 &AddrLen
							 );

		}
		RELEASE_MUTEX(ListenMutex);

		if(State < 1)
		{
			if( ErrorMessages == TRUE )
			{
				int		ErrorNum = GET_LAST_ERROR();
				char	ErrorMessage[320];

				ErrorMessage[0] ='\0';

				GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));
				if( Family == AF_INET )
				{
					printf("An error occured while receiving from %s : %d : %s .\n",
						   inet_ntoa(ClientAddr.Addr4.sin_addr),
						   ErrorNum,
						   ErrorMessage
						   );
				} else {
					char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

					IPv6AddressToAsc(&(ClientAddr.Addr6.sin6_addr), Addr);

					printf("An error occured while receiving from %s : %d : %s .\n",
						   Addr,
						   ErrorNum,
						   ErrorMessage
						   );

				}
			}
			continue;
		}

		Context.RequestLength = State;

		Query(&Context, &ClientAddr);
		ExtendableBuffer_Reset(Context.ResponseBuffer);

	}

	return 0;
}

void QueryDNSListenUDPStart(int _ThreadCount)
{
	if(Inited == FALSE) return;
	if(_ThreadCount < 1) return;
	Threads = SafeMalloc(_ThreadCount * sizeof(ThreadHandle));

	for(; _ThreadCount != 0; --_ThreadCount)
	{
		CREATE_THREAD(QueryDNSListenUDP,
					  (void *)(long)_ThreadCount,
					  Threads[_ThreadCount - 1]
					  );
	}
	INFO("Starting UDP socket %s:%d successfully.\n",
		 ConfigGetRawString(&ConfigInfo, "LocalInterface"),
		 ConfigGetInt32(&ConfigInfo, "LocalPort")
		 );
}
