#ifndef STATICHOSTS_H_INCLUDED
#define STATICHOSTS_H_INCLUDED

#include "stringchunk.h"
#include "dnsrelated.h"
#include "querydnsbase.h"

#define DOMAIN_NAME_LENGTH_MAX 128

typedef struct _HostsContainer{
	StringList	Domains;

	StringChunk	Ipv4Hosts;
	StringChunk	Ipv6Hosts;
	StringChunk	CNameHosts;
	StringChunk	ExcludedDomains;
/*	StringChunk	ExcludedIPs;*/

	ExtendableBuffer	IPs;
} HostsContainer;

typedef enum _HostsRecordType{
	HOSTS_TYPE_TOO_LONG = -1,

	HOSTS_TYPE_UNKNOWN = 0,

	HOSTS_TYPE_A = 1 << 1,

	HOSTS_TYPE_AAAA = 1 << 2,

	HOSTS_TYPE_CNAME = 1 << 3,

	HOSTS_TYPE_EXCLUEDE = 1 << 4,

} HostsRecordType;

#define	MATCH_STATE_PERFECT		0
#define	MATCH_STATE_ONLY_CNAME	1
#define	MATCH_STATE_NONE		(-1)
#define	MATCH_STATE_DISABLED	(-2)

int Hosts_InitContainer(HostsContainer	*Container);

HostsRecordType Hosts_LoadFromMetaLine(HostsContainer *Container, char *MetaLine);

int StaticHosts_Init(ConfigFileInfo *ConfigInfo);

int Hosts_GetFromContainer(HostsContainer *Container, ThreadContext *Context, int *AnswerCount);

int StaticHosts_GetByQuestion(ThreadContext *Context, int *AnswerCount);

BOOL StaticHosts_Inited(void);

#endif // STATICHOSTS_H_INCLUDED
