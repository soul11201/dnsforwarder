#ifndef _QUERY_DNS_BASE_H_
#define _QUERY_DNS_BASE_H_

#ifdef INTERNAL_DEBUG
#define	DEBUG_FILE(...)	EFFECTIVE_LOCK_GET(Debug_Mutex); \
						fprintf(Debug_File, "THREAD : %d : ", GET_THREAD_ID()); \
						fprintf(Debug_File, __VA_ARGS__); \
						fflush(Debug_File); \
						EFFECTIVE_LOCK_RELEASE(Debug_Mutex);


#define	DEBUG(...)		fprintf(stderr, "[DEBUG] "__VA_ARGS__); \
						DEBUG_FILE(__VA_ARGS__);


#else
#define	DEBUG_FILE(...)
#define	DEBUG(...)
#endif

#define	PRINT(...)		if(ShowMassages == TRUE){ printf(__VA_ARGS__); DEBUG_FILE(__VA_ARGS__); }
#define	INFO(...)		if(ShowMassages == TRUE){ printf("[INFO] "__VA_ARGS__); DEBUG_FILE(__VA_ARGS__); }
#define	ERRORMSG(...)	if(ErrorMessages == TRUE){ fprintf(stderr, "[ERROR] "__VA_ARGS__); DEBUG_FILE(__VA_ARGS__); }

typedef enum _DnsQuaryProtocol{
	DNS_QUARY_PROTOCOL_UDP = 0,
	DNS_QUARY_PROTOCOL_TCP = 1
} DNSQuaryProtocol;

#include "common.h"
#include "dnscache.h"
#include "readconfig.h"
#include "extendablebuffer.h"
#include "request_response.h"

/* Global Varibles */
extern ConfigFileInfo	ConfigInfo;
extern int				TimeToServer;
extern BOOL				AllowFallBack;
extern BOOL				ShowMassages;
extern BOOL				ErrorMessages;
#ifdef INTERNAL_DEBUG
extern EFFECTIVE_LOCK	Debug_Mutex;
extern FILE				*Debug_File;
#endif

typedef struct _QueryContext ThreadContext;

struct _QueryContext{
	ThreadContext	*Head;
	ThreadContext	*Previous;

	SOCKET	TCPSocket;
	SOCKET	UDPSocket;

	SOCKET	*PrimarySocket;
	SOCKET	*SecondarySocket;

	DNSQuaryProtocol	PrimaryProtocolToServer;
	struct sockaddr		*LastServer;
	DNSQuaryProtocol	LastProtocol;

	const char			*RequestEntity;
	int					RequestLength;
	const char			*RequestingDomain;
	DNSRecordType		RequestingType;
	int					RequestingDomainHashValue;

	const char			*ClientIP;
	int					ClientPort; /* host's byte order */

	BOOL	Compress;


	ExtendableBuffer	*ResponseBuffer;

	/* Do not refer this, let `ResponseBuffer' point to this and use `ResponseBuffer' instead */
	ExtendableBuffer	ResponseBuffer_Entity;

};

void ShowRefusingMassage(ThreadContext *Context);

void ShowErrorMassage(ThreadContext *Context, char ProtocolCharacter);

void ShowNormalMassage(ThreadContext *Context, _32BIT_INT Offset, char ProtocolCharacter);

int DNSFetchFromCache(__in ThreadContext *Context);

int InitAddress(void);

int FetchFromHostsAndCache(ThreadContext *Context);

#define QUERY_RESULT_DISABLE	(-1)
#define QUERY_RESULT_ERROR		(-2)

int QueryBase(ThreadContext *Context);

int	GetAnswersByName(ThreadContext *Context, const char *Name, DNSRecordType Type);

int GetMaximumMessageSize(SOCKET sock);

#endif /* _QUERY_DNS_BASE_H_ */
