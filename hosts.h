#ifndef HOSTS_H_INCLUDED
#define HOSTS_H_INCLUDED

#include "querydnsbase.h"
#include "extendablebuffer.h"

#define DOMAIN_NAME_LENGTH_MAX 128

int Hosts_Init(void);

BOOL Hosts_IsInited(void);

int Hosts_GetByQuestion(char *Question, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context);

#endif // HOSTS_H_INCLUDED
