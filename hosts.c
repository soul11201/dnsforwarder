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

static BOOL			Internet = FALSE;

static int			UpdateInterval;

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

static BOOL NeedReload(void)
{
	if( File == NULL )
	{
		return FALSE;
	}

	if( time(NULL) - LastUpdate > UpdateInterval )
	{

#ifdef WIN32

		static FILETIME	LastFileTime = {0, 0};
		WIN32_FIND_DATA	Finddata;
		HANDLE			Handle;

		Handle = FindFirstFile(File, &Finddata);

		if( Handle == INVALID_HANDLE_VALUE )
		{
			return FALSE;
		}

		if( memcmp(&LastFileTime, &(Finddata.ftLastWriteTime), sizeof(FILETIME)) != 0 )
		{
			LastUpdate = time(NULL);
			LastFileTime = Finddata.ftLastWriteTime;
			FindClose(Handle);
			return TRUE;
		} else {
			LastUpdate = time(NULL);
			FindClose(Handle);
			return FALSE;
		}

#else /* WIN32 */
		static time_t	LastFileTime = 0;
		struct stat		FileStat;

		if( stat(File, &FileStat) != 0 )
		{

			return FALSE;
		}

		if( LastFileTime != FileStat.st_mtime )
		{
			LastUpdate = time(NULL);
			LastFileTime = FileStat.st_mtime;

			return TRUE;
		} else {
			LastUpdate = time(NULL);

			return FALSE;
		}

#endif /* WIN32 */
	} else {
		return FALSE;
	}
}

static int TryLoadHosts(void)
{
	if( NeedReload() == TRUE )
	{
		ThreadHandle t = INVALID_THREAD;
		CREATE_THREAD(DynamicHosts_Load, NULL, t);
		DETACH_THREAD(t);
	}
	return 0;
}

static void GetHostsFromInternet_Thread(void *Unused)
{
	const char *URL = ConfigGetRawString(&ConfigInfo, "Hosts");
	const char *Script = ConfigGetRawString(&ConfigInfo, "HostsScript");
	int			HostsRetryInterval = ConfigGetInt32(&ConfigInfo, "HostsRetryInterval");

	INFO("Hosts File : \"%s\" -> \"%s\"\n", URL, File);

	while(1)
	{

		INFO("Getting Hosts From %s ...\n", URL);

		if( GetFromInternet(URL, File) == 0 )
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

			SLEEP(UpdateInterval * 1000);

		} else {
			ERRORMSG("Getting Hosts from Internet failed. Waiting %d second(s) for retry.\n", HostsRetryInterval);
			SLEEP(HostsRetryInterval * 1000);
		}
	}
}

int DynamicHosts_Init(void)
{
	const char	*Path;

	StaticHosts_Init();

	Path = ConfigGetRawString(&ConfigInfo, "Hosts");

	if( Path == NULL )
	{
		File = NULL;
		return 0;
	}

	UpdateInterval = ConfigGetInt32(&ConfigInfo, "HostsUpdateInterval");

	RWLock_Init(HostsLock);

	if( strncmp(Path, "http", 4) != 0 && strncmp(Path, "ftp", 3) != 0 )
	{
		/* Local file */
		File = Path;

		if( DynamicHosts_Load() != 0 )
		{
			ERRORMSG("Loading Hosts failed.\n");
			File = NULL;
			return 1;
		}

	} else {
		/* Internet file */
		File = ConfigGetRawString(&ConfigInfo, "HostsDownloadPath");

		if( ConfigGetInt32(&ConfigInfo, "HostsRetryInterval") < 1 )
		{
			ERRORMSG("`HostsFlushTimeOnFailed' is too small (< 1).\n");
			File = NULL;
			return 1;
		}

		Internet = TRUE;

		if( FileIsReadable(File) )
		{
			INFO("Loading the existing Hosts ...\n");
			DynamicHosts_Load();
		} else {
			INFO("Hosts file is unreadable, this may cause some failures.\n");
		}

		CREATE_THREAD(GetHostsFromInternet_Thread, NULL, GetHosts_Thread);
	}

	LastUpdate = time(NULL);

	return 0;

}

int DynamicHosts_GetByQuestion(ThreadContext *Context, int *AnswerCount)
{
	int ret = -1;

	ret = StaticHosts_GetByQuestion(Context, AnswerCount);

	if( ret > 0 )
	{
		return ret;
	}

	if( DynamicHosts_Inited() )
	{
		if( Internet == TRUE )
		{
			TryLoadHosts();
		}

		RWLock_RdLock(HostsLock);

		ret =  Hosts_GetFromContainer(MainContainer, Context, AnswerCount);

		RWLock_UnRLock(HostsLock);

		return ret;
	} else {
		return -1;
	}
}

BOOL DynamicHosts_Inited(void)
{
	return (File != NULL && MainContainer != NULL);
}
