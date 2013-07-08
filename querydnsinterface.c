#include <string.h>
#include "common.h"
#include "querydnsinterface.h"
#include "querydnsbase.h"
#include "querydnslistentcp.h"
#include "querydnslistenudp.h"
#include "readconfig.h"
#include "hosts.h"
#include "excludedlist.h"
#include "utils.h"

#ifdef WIN32
#define GetFileDirectory(out)	(GetModulePath(out, sizeof(out)))
#else /* WIN32 */
#define GetFileDirectory(out)	(GetConfigDirectory(out))
#endif /* WIN32 */

static int CheckArgs(void)
{
	VType tmp;
    if(ConfigGetString(&ConfigInfo, "UDPServer") == NULL && ConfigGetString(&ConfigInfo, "ExcludedDomain") != NULL)
    {
        INFO("Ignored option `ExcludeDomain', because no UDP server was specified.\n");
        tmp.str = NULL;
        ConfigSetValue(&ConfigInfo, tmp, "ExcludedDomain");
    }

    if( ConfigGetBoolean(&ConfigInfo, "UseCache") == TRUE )
    {
        if( ConfigGetInt32(&ConfigInfo, "MultipleTTL") == 0 )
		{
            INFO("Option `MultipleTTL' was set to be 0, if you don't want to use cache, please set `NoCache' to TRUE. Now restored option `MultipleTTL' to 1.\n");
            tmp.INT32 = 1;
            ConfigSetValue(&ConfigInfo, tmp, "MultipleTTL");
		}
        if(ConfigGetInt32(&ConfigInfo, "MultipleTTL") != 1 && ConfigGetBoolean(&ConfigInfo, "IgnoreTTL") == TRUE)
        {
            INFO("Ignored option `MultipleTTL', because TTL was ignored.\n");
            tmp.INT32 = 1;
            ConfigSetValue(&ConfigInfo, tmp, "MultipleTTL");
        }
        if(ConfigGetInt32(&ConfigInfo, "ForceTTL") > -1 && ConfigGetBoolean(&ConfigInfo, "IgnoreTTL") == TRUE)
        {
            INFO("Ignored option `ForceTTL', because TTL was ignored.\n");
            tmp.INT32 = 1;
            ConfigSetValue(&ConfigInfo, tmp, "ForceTTL");
        }
        if(ConfigGetInt32(&ConfigInfo, "MultipleTTL") != 1 && ConfigGetInt32(&ConfigInfo, "ForceTTL") > -1)
        {
            INFO("Ignored option `MultipleTTL', because TTLs were forced to be %d.\n", ConfigGetInt32(&ConfigInfo, "ForceTTL"));
            tmp.INT32 = 1;
            ConfigSetValue(&ConfigInfo, tmp, "MultipleTTL");
        }
    }
    else
    {

    }

    return 0;
}

int QueryDNSInterfaceInit(char *ConfigFile, BOOL _ShowMassages, BOOL OnlyErrorMessages)
{
	VType	TmpTypeDescriptor;
	char	TmpStr[1024];

	ShowMassages = _ShowMassages;
	ErrorMessages = OnlyErrorMessages;

	ConfigInitInfo(&ConfigInfo);

    TmpTypeDescriptor.str = "127.0.0.1";
    ConfigAddOption(&ConfigInfo, "LocalInterface", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Local working interface");

    TmpTypeDescriptor.INT32 = 53;
    ConfigAddOption(&ConfigInfo, "LocalPort", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, "Local working port");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "OpenLocalTCP", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Local TCP is opened");

    TmpTypeDescriptor.str = "TCP";
    ConfigAddOption(&ConfigInfo, "PrimaryServer", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Primary server");

    TmpTypeDescriptor.INT32 = 3;
    ConfigAddOption(&ConfigInfo, "UDPThreads", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DisabledType", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = "8.8.4.4";
    ConfigAddOption(&ConfigInfo, "TCPServer", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "TCP Server");

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPServer", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "UDP Server");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "FallBackToSecondary", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 3000;
    ConfigAddOption(&ConfigInfo, "TimeToServer", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "Hosts", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Hosts File");

    TmpTypeDescriptor.INT32 = 600;
    ConfigAddOption(&ConfigInfo, "HostsFlushTime", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 30;
    ConfigAddOption(&ConfigInfo, "HostsFlushTimeOnFailed", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "hosts.txt");

    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "HostsDownloadPath", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Download Hosts to");

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "HostsScript", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "AppendHosts", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 1048576;
    ConfigAddOption(&ConfigInfo, "CacheSize", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "cache");

    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "CacheFile", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, "Cache File");

    TmpTypeDescriptor.boolean = TRUE;
    ConfigAddOption(&ConfigInfo, "UseCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Use cache");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "IgnoreTTL", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Ignore TTL");

    TmpTypeDescriptor.INT32 = -1;
    ConfigAddOption(&ConfigInfo, "ForceTTL", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 1;
    ConfigAddOption(&ConfigInfo, "MultipleTTL", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "ReloadCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "OverwriteCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "ExcludedDomain", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DisabledDomain", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "GfwList", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "GFW List");

    TmpTypeDescriptor.boolean = TRUE;
    ConfigAddOption(&ConfigInfo, "GfwListBase64Decode", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 7200;
    ConfigAddOption(&ConfigInfo, "GfwListFlushTime", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 30;
    ConfigAddOption(&ConfigInfo, "GfwListFlushTimeOnFailed", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "gfwlist.txt");

    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "GfwListDownloadPath", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, NULL);

	if( ConfigOpenFile(&ConfigInfo, ConfigFile) == 0 )
	{
		ConfigRead(&ConfigInfo);
		ConfigCloseFile(&ConfigInfo);
		return CheckArgs();
	} else {
		ERRORMSG("WARNING: Cannot load configuration file : %s, use default options.\n", ConfigFile);
		return 0;
	}
}

int QueryDNSInterfaceStart(void)
{
	int state = 0;

	if( ShowMassages == TRUE )
	{
		ConfigDisplay(&ConfigInfo);
		putchar('\n');
	}

#ifdef INTERNAL_DEBUG
	{
		char	FilePath[1024];

		GetFileDirectory(FilePath);
		strcat(FilePath, PATH_SLASH_STR);
		strcat(FilePath, "Debug.log");


		Debug_File = fopen(FilePath, "a");
		if( Debug_File == NULL )
		{
			ERRORMSG("Cannot open debug file : %s\n", FilePath);
			return -1;
		}

		EFFECTIVE_LOCK_INIT(Debug_Mutex);

		DEBUG_FILE("\n\n\n\n\nNew session\n");
		INFO("Debug mode.\n");
	}
#endif

	InitAddress();
	ExcludedList_Init();

	TimeToServer = ConfigGetInt32(&ConfigInfo, "TimeToServer");
	FallBackToSecondary = ConfigGetBoolean(&ConfigInfo, "FallBackToSecondary");

    if( ConfigGetBoolean(&ConfigInfo, "UseCache") == TRUE)
    {
        if(DNSCache_Init() != 0)
        {
            ERRORMSG("Cache initializing Failed.\n");
            return 2;
        }
    }

	if( ConfigGetInt32(&ConfigInfo, "UDPThreads") > 0)
	{
		if( QueryDNSListenUDPInit() == 0 )
		{
			++state;
			QueryDNSListenUDPStart(ConfigGetInt32(&ConfigInfo, "UDPThreads"));
		}
	}

	if( ConfigGetBoolean(&ConfigInfo, "OpenLocalTCP") == TRUE )
	{
		if( QueryDNSListenTCPInit() == 0 )
		{
			++state;
			QueryDNSListenTCPStart();
		}
	}

	if(state == 0)
	{
		return 1;
	} else {
		if( Hosts_Init() == 0 )
		{
			const char *LocalAddr = ConfigGetString(&ConfigInfo, "LocalInterface");
			int IsZeroZeroZeroZero = !strncmp(LocalAddr, "0.0.0.0", 7);
			INFO("Now you can set DNS%s%s.\n", IsZeroZeroZeroZero ? "" : " to ", IsZeroZeroZeroZero ? "" : LocalAddr);
		}
	}

	LoadGfwList();

	return 0;
}

void QueryDNSInterfaceWait(void)
{
#ifdef WIN32
	ThreadHandle CurrentThread = GetCurrentThread();
#endif /* WIN32 */
Start:
#ifdef WIN32
	SuspendThread(CurrentThread);
#else /* WIN32 */
	pause();
#endif /* WIN32 */
	goto Start;

#ifdef WIN32
	CloseHandle(CurrentThread);
#endif /* WIN32 */
}
