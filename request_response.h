#ifndef REQUEST_RESPONSE_H_INCLUDED
#define REQUEST_RESPONSE_H_INCLUDED

#include "querydnsbase.h"
#include "readconfig.h"
#include "dnscache.h"
#include "common.h"

BOOL SocketIsStillReadable(SOCKET Sock);

void ClearSocketBuffer(SOCKET Sock);

int SendAndReveiveRawMessageViaTCP(SOCKET			Sock,
								   const void		*Content,
								   int				ContentLength,
								   ExtendableBuffer	*ResultBuffer,
								   _16BIT_UINT		*TCPLength /* Big-endian */
								   );

int QueryDNSViaTCP(SOCKET			Sock,
				   const void		*RequestEntity,
				   int				RequestLength,
				   ExtendableBuffer	*ResultBuffer
				   );

void SetUDPAntiPollution(BOOL State);

void SetUDPAppendEDNSOpt(BOOL State);

int InitBlockedIP(StringList *l);

int QueryDNSViaUDP(SOCKET			Sock,
				   struct sockaddr	*PeerAddr_List,
				   int				NumberOfAddresses,
				   void		*RequestEntity,
				   int				RequestLength,
				   ExtendableBuffer	*ResultBuffer,
				   const char		*RequestingDomain
				   );

int ProbeFakeAddresses(const char	*ServerAddress,
					   const char	*RequestingDomain,
					   StringList	*out
					   );

int SetSocketWait(SOCKET sock, BOOL Wait);

int SetSocketSendTimeLimit(SOCKET sock, int time);

int SetSocketRecvTimeLimit(SOCKET sock, int time);

BOOL TCPSocketIsHealthy(SOCKET *sock);

void SetServerTimeOut(int TimeOut);

BOOL ConnectToTCPServer(SOCKET *sock, struct sockaddr *addr, sa_family_t Family);

void CloseTCPConnection(SOCKET *sock);

int QueryFromServerBase(SOCKET				*Socket,
						struct	sockaddr	*ServerAddress_List,
						int					NumberOfAddresses,
						DNSQuaryProtocol	ProtocolToServer,
						char				*RequestEntity,
						int					RequestLength,
						ExtendableBuffer	*ResultBuffer,
						const char			*RequestingDomain
						);

#endif // REQUEST_RESPONSE_H_INCLUDED
