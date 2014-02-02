#ifndef HOSTS_H_INCLUDED
#define HOSTS_H_INCLUDED

#include "querydnsbase.h"
#include "extendablebuffer.h"

#define DOMAIN_NAME_LENGTH_MAX 128

int DynamicHosts_Init(void);

int DynamicHosts_GetByQuestion(ThreadContext *Context, int *AnswerCount);

BOOL DynamicHosts_Inited(void);

#endif // HOSTS_H_INCLUDED
