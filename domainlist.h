#ifndef DOMAINLIST_H_INCLUDED
#define DOMAINLIST_H_INCLUDED

#include "hashtable.h"
#include "stringlist.h"
#include "array.h"

typedef struct _DomainList{
	/* Domains without wildcards */
	StringList	List;

	/* Positions of every domain in `List', offsets */
	HashTable	List_Pos;


	/* Domains containing wildcards */
	StringList	List_W;

	/* Positions of every domain in `List_W', offsets */
	Array		List_W_Pos;

} DomainList;

int DomainList_Init(DomainList *dl, int InitialCount /* For no-wildcard domain */);

int DomainList_Add(DomainList *dl, const char *Domain);

BOOL DomainList_Match_NoWildCard(DomainList *dl, const char *Str);

BOOL DomainList_Match_OnlyWildCard(DomainList *dl, const char *Str);

BOOL DomainList_Match(DomainList *dl, const char *Str);

void DomainList_Free(DomainList *dl);

#endif // DOMAINLIST_H_INCLUDED
