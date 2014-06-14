#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "hosts.h"
#include "dnsrelated.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "rwlock.h"

static int			UpdateInterval;
static int			HostsRetryInterval;

static time_t		LastUpdate = 0;

static const char 	*File = NULL;

static ThreadHandle	GetHosts_Thread;

static RWLock		HostsLock;

static volatile HostsContainer	*MainContainer = NULL;

static void DynamicHosts_FreeHostsContainer(HostsContainer *Container)
{
	StringChunk_Free(&(Container -> Ipv4Hosts), FALSE);
	StringChunk_Free(&(Container -> Ipv6Hosts), FALSE);
	StringChunk_Free(&(Container -> CNameHosts), FALSE);
	StringChunk_Free(&(Container -> ExcludedDomains), FALSE);
	StringList_Free(&(Container -> Domains));
	ExtendableBuffer_Free(&(Container -> IPs));
}

static int DynamicHosts_Load(void)
{
	FILE			*fp;
	char			Buffer[320];
	ReadLineStatus	Status;

	int		IPv4Count = 0, IPv6Count = 0, CNameCount = 0, ExcludedCount = 0;

	HostsContainer *TempContainer;

	fp = fopen(File, "r");
	if( fp == NULL )
	{
		return -1;
	}

	TempContainer = (HostsContainer *)SafeMalloc(sizeof(HostsContainer));
	if( TempContainer == NULL )
	{
		return -1;
	}

	if( Hosts_InitContainer(TempContainer) != 0 )
	{
		fclose(fp);

		SafeFree(TempContainer);
		return -1;
	}

	while( TRUE )
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));
		if( Status == READ_FAILED_OR_END )
			break;

		switch( Hosts_LoadFromMetaLine(TempContainer, Buffer) )
		{
			case HOSTS_TYPE_AAAA:
				++IPv6Count;
				break;

			case HOSTS_TYPE_A:
				++IPv4Count;
				break;

			case HOSTS_TYPE_CNAME:
				++CNameCount;
				break;

			case HOSTS_TYPE_EXCLUEDE:
				++ExcludedCount;
				break;

			default:
				break;
		}

		if( Status == READ_TRUNCATED )
		{
			ERRORMSG("Hosts is too long : %s\n", Buffer);
			ReadLine_GoToNextLine(fp);
		}
	}

	RWLock_WrLock(HostsLock);
	if( MainContainer != NULL )
	{
		DynamicHosts_FreeHostsContainer((HostsContainer *)MainContainer);
		SafeFree((void *)MainContainer);
	}
	MainContainer = TempContainer;

	RWLock_UnWLock(HostsLock);

	INFO("Loading Hosts completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Redirections, %d items are excluded.\n",
		IPv4Count,
		IPv6Count,
		CNameCount,
		ExcludedCount);

	return 0;
}

const char **GetURLs(StringList *s)
{
	const char **URLs;
	int NumberOfURLs = 0;
	int Count = StringList_Count(s);
	const char *Str_Itr;

	URLs = malloc(sizeof(char *) * (Count + 1));
	if( URLs == NULL )
	{
		return NULL;
	}

	Str_Itr = StringList_GetNext(s, NULL);
	while( Str_Itr != NULL )
	{
		URLs[NumberOfURLs] = Str_Itr;
		++NumberOfURLs;

		Str_Itr = StringList_GetNext(s, Str_Itr);
	}

	URLs[NumberOfURLs] = NULL;

	return URLs;
}

static void GetHostsFromInternet_Failed(int ErrorCode, const char *URL, const char *File)
{
	ERRORMSG("Getting Hosts %s failed. Waiting %d second(s) to try again.\n", URL, HostsRetryInterval);
}

static void GetHostsFromInternet_Succeed(const char *URL, const char *File)
{
	INFO("Hosts %s saved.\n", URL);
}

static void GetHostsFromInternet_Thread(ConfigFileInfo *ConfigInfo)
{
	const char	*Script = ConfigGetRawString(ConfigInfo, "HostsScript");
	int			DownloadState;
	const char	**URLs;

	URLs = GetURLs(ConfigGetStringList(ConfigInfo, "Hosts"));

	while(1)
	{

		if( URLs[1] == NULL )
		{
			INFO("Getting hosts from %s ...\n", URLs[0]);
		} else {
			INFO("Getting hosts from various places ...\n");
		}

		DownloadState = GetFromInternet_MultiFiles(URLs, File, HostsRetryInterval, -1, GetHostsFromInternet_Failed, GetHostsFromInternet_Succeed);
		if( DownloadState == 0 )
		{
			INFO("Hosts saved at %s.\n", File);

			if( Script != NULL )
			{
				INFO("Running script ...\n");
				system(Script);
			}

			DynamicHosts_Load();

			if( UpdateInterval < 0 )
			{
				return;
			}
		}

		SLEEP(UpdateInterval * 1000);
	}
}

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo)
{
	const char	*Path;

	StaticHosts_Init(ConfigInfo);

	Path = ConfigGetRawString(ConfigInfo, "Hosts");

	if( Path == NULL )
	{
		File = NULL;
		return 0;
	}

	UpdateInterval = ConfigGetInt32(ConfigInfo, "HostsUpdateInterval");
	HostsRetryInterval = ConfigGetInt32(ConfigInfo, "HostsRetryInterval");

	RWLock_Init(HostsLock);

	File = ConfigGetRawString(ConfigInfo, "HostsDownloadPath");

	if( HostsRetryInterval < 0 )
	{
		ERRORMSG("`HostsRetryInterval' is too small (< 0).\n");
		File = NULL;
		return 1;
	}

	INFO("Local hosts file : \"%s\"\n", File);

	if( FileIsReadable(File) )
	{
		INFO("Loading the existing hosts file ...\n");
		DynamicHosts_Load();
	} else {
		INFO("Hosts file is unreadable, this may cause some failures.\n");
	}

	CREATE_THREAD(GetHostsFromInternet_Thread, ConfigInfo, GetHosts_Thread);

	LastUpdate = time(NULL);

	return 0;

}

int DynamicHosts_GetByQuestion(ThreadContext *Context, int *AnswerCount)
{
	int ret = MATCH_STATE_NONE;

	ret = StaticHosts_GetByQuestion(Context, AnswerCount);

	if( ret > 0 || ret == MATCH_STATE_DISABLED )
	{
		return ret;
	}

	if( DynamicHosts_Inited() )
	{
		RWLock_RdLock(HostsLock);

		ret =  Hosts_GetFromContainer(MainContainer, Context, AnswerCount);

		RWLock_UnRLock(HostsLock);

		return ret;
	} else {
		return MATCH_STATE_NONE;
	}
}

BOOL DynamicHosts_Inited(void)
{
	return (File != NULL && MainContainer != NULL);
}
