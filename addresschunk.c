#include "addresschunk.h"

int AddressChunk_Init(AddressChunk *ac, int NumberOfDedicated)
{
	if( AddressList_Init(&(ac -> TCPAddresses)) != 0 )
	{
		return 1;
	}

	if( AddressList_Init(&(ac -> UDPAddresses)) != 0 )
	{
		return 2;
	}

	if( StringChunk_Init(&(ac -> Dedicated), NumberOfDedicated) != 0 )
	{
		return 3;
	}

	return 0;
}

int AddressChunk_AddATCPAddress_FromString(AddressChunk *ac, const char *Addr_Port)
{
	return AddressList_Add_From_String(&(ac -> TCPAddresses), Addr_Port);
}

int AddressChunk_AddAUDPAddress_FromString(AddressChunk *ac, const char *Addr_Port)
{
	return AddressList_Add_From_String(&(ac -> UDPAddresses), Addr_Port);
}

int AddressChunk_AddADedicatedAddress_FromString(AddressChunk *ac, const char *Domain, const char *Addr_Port)
{
	struct	_Address	Tmp;

	if( AddressList_ConvertToAddressFromString(&Tmp, Addr_Port, 53) == AF_UNSPEC )
	{
		return -1;
	}

	if( StringChunk_Add(&(ac -> Dedicated), Domain, &Tmp, sizeof(struct _Address)) != 0 )
	{
		return -2;
	}

	return 0;

}

struct sockaddr *AddressChunk_GetOne(AddressChunk *ac, sa_family_t *family, const char *RequestingDomain, DNSQuaryProtocol Protocol)
{
	struct _Address *Result;

	if( StringChunk_Match(&(ac -> Dedicated), RequestingDomain, &Result) == TRUE )
	{
		if( Result -> family == AF_INET )
		{
			*family = Result -> family;
			return &(Result -> Addr.Addr4);
		} else {
			*family = Result -> family;
			return &(Result -> Addr.Addr6);
		}

	}

	if( Protocol == DNS_QUARY_PROTOCOL_UDP )
	{
		return AddressList_GetOne(&(ac -> UDPAddresses), family);
	} else {
		return AddressList_GetOne(&(ac -> TCPAddresses), family);
	}
}

int AddressChunk_Advance(AddressChunk *ac, DNSQuaryProtocol Protocol)
{
	if( Protocol == DNS_QUARY_PROTOCOL_UDP )
	{
		AddressList_Advance(&(ac -> UDPAddresses));
	} else {
		AddressList_Advance(&(ac -> TCPAddresses));
	}

	return 0;
}
