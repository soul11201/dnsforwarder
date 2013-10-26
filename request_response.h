#ifndef REQUEST_RESPONSE_H_INCLUDED
#define REQUEST_RESPONSE_H_INCLUDED

#include "querydnsbase.h"
#include "readconfig.h"
#include "dnscache.h"
#include "common.h"

BOOL SocketIsStillReadable(SOCKET Sock);

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

int QueryDNSViaUDP(SOCKET			Sock,
				   struct sockaddr	*PeerAddr,
				   sa_family_t		AddressFamily,
				   const void		*RequestEntity,
				   int				RequestLength,
				   ExtendableBuffer	*ResultBuffer
				   );

int SetSocketWait(SOCKET sock, BOOL Wait);

int SetSocketSendTimeLimit(SOCKET sock, int time);

int SetSocketRecvTimeLimit(SOCKET sock, int time);

BOOL TCPSocketIsHealthy(SOCKET *sock);

BOOL ConnectToTCPServer(SOCKET *sock, struct sockaddr *addr, sa_family_t Family, int TimeToServer);

void CloseTCPConnection(SOCKET *sock);

int QueryFromServerBase(SOCKET				*Socket,
						struct	sockaddr	*ServerAddress,
						sa_family_t			AddressFamily,
						DNSQuaryProtocol	ProtocolToServer,
						char				*RequestEntity,
						int					RequestLength,
						ExtendableBuffer	*ResultBuffer,
						const char			*RequestingDomain
						);

#endif // REQUEST_RESPONSE_H_INCLUDED
