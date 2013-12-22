#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "readconfig.h"
#include "utils.h"
#include "readline.h"

void ConfigInitInfo(ConfigFileInfo *Info)
{
	Info -> fp = NULL;
	Info -> Options = NULL;
	Info -> NumOfOptions = 0;
}

int ConfigOpenFile(ConfigFileInfo *Info, const char *File)
{
	Info -> fp = fopen(File, "r");
	if( Info -> fp == NULL )
		return GET_LAST_ERROR();
	else
		return 0;
}

int ConfigCloseFile(ConfigFileInfo *Info)
{
	return fclose(Info -> fp);
}

int ConfigAddOption(ConfigFileInfo *Info, char *KeyName, MultilineStrategy Strategy, OptionType Type, VType Initial, char *Caption)
{
	int loop;

	if( strlen(KeyName) > sizeof(Info -> Options -> KeyName) - 1 )
	{
		return -1;
	}

	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if(Info -> Options[loop].Status == STATUS_UNUSED)
			break;
	}

	if(loop == Info -> NumOfOptions)
	{
		int loop2;

		if( SafeRealloc((void *)&(Info -> Options), (Info -> NumOfOptions + 10) * sizeof(ConfigOption)) != 0)
		{
			return 1;
		}

		(Info -> NumOfOptions) += 10;

		for(loop2 = loop; loop2 != Info -> NumOfOptions; ++loop2)
			Info -> Options[loop2].Status = STATUS_UNUSED;
	}

	strcpy(Info -> Options[loop].KeyName, KeyName);
	Info -> Options[loop].Type = Type;
	Info -> Options[loop].Status = STATUS_DEFAULT_VALUE;
	if( Caption != NULL )
	{
		strncpy(Info -> Options[loop].Caption, Caption, CAPTION_MAX_SIZE);
		Info -> Options[loop].Caption[CAPTION_MAX_SIZE] = '\0';
	} else {
		*(Info -> Options[loop].Caption) = '\0';
	}

	Info -> Options[loop].Strategy = Strategy;

	switch( Type )
	{
		case TYPE_INT32:
			Info -> Options[loop].Holder.INT32 = Initial.INT32;
			break;

		case TYPE_BOOLEAN:
			Info -> Options[loop].Holder.boolean = Initial.boolean;
			break;

		case TYPE_STRING:
			if( StringList_Init(&(Info -> Options[loop].Holder.str), Initial.str, ',') != 0 )
			{
				return 2;
			}

			break;

		default:
			break;
	}

	return 0;
}

int ConfigAddAlias(ConfigFileInfo *Info, char *Alias, char *Target)
{
	int loop;

	if( strlen(Alias) > sizeof(Info -> Options -> KeyName) - 1 )
	{
		return -1;
	}

	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if(Info -> Options[loop].Status == STATUS_UNUSED)
			break;
	}

	if(loop == Info -> NumOfOptions)
	{
		int loop2;

		if( SafeRealloc((void *)&(Info -> Options), (Info -> NumOfOptions + 10) * sizeof(ConfigOption)) != 0)
		{
			return 1;
		}

		(Info -> NumOfOptions) += 10;

		for(loop2 = loop; loop2 != Info -> NumOfOptions; ++loop2)
			Info -> Options[loop2].Status = STATUS_UNUSED;
	}

	strcpy(Info -> Options[loop].KeyName, Alias);
	Info -> Options[loop].Status = STATUS_ALIAS;
	strncpy(Info -> Options[loop].Caption, Target, CAPTION_MAX_SIZE);
	Info -> Options[loop].Caption[CAPTION_MAX_SIZE] = '\0';

	return 0;
}

static ConfigOption *GetOptionOfAInfo(const ConfigFileInfo *Info, const char *KeyName)
{
	int	loop;

	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if(strcmp(KeyName, Info -> Options[loop].KeyName) == 0)
		{
			if( Info -> Options[loop].Status == STATUS_ALIAS )
			{
				return GetOptionOfAInfo(Info, Info -> Options[loop].Caption);
			} else {
				return Info -> Options + loop;
			}
		}
	}
	return NULL;
}

static char *GetKeyNameFromLine(const char *Line, char *Buffer)
{
	const char	*itr = Line;
	const char	*Delimiter;

	for(; isspace(*itr); ++itr);

	Delimiter = strchr(itr, ' ');

	if( Delimiter == NULL )
	{
		Delimiter = strchr(itr, '=');
	}

	if(Delimiter == NULL)
		return NULL;

	strncpy(Buffer, itr, Delimiter - Line);
	Buffer[Delimiter - Line] = '\0';

	return Buffer;
}

static const char *GetValuePosition(const char *Line)
{
	const char	*itr = Line;

	for(; isspace(*itr); ++itr);

	itr = strchr(itr, ' ');

	if(itr == NULL)
	{
		itr = strchr(Line, '=');
	}

	if( itr == NULL )
	{
		return NULL;
	}

	++itr;

	for(; isspace(*itr) && *itr != '\0'; ++itr);

	if( *itr == '\0' )
		return NULL;
	else
		return itr;
}

static BOOL GetBoolealValueFromString(char *str)
{
	if( isdigit(*str) )
	{
		if( *str == '0' )
			return FALSE;
		else
			return TRUE;
	} else {
		StrToLower(str);

		if( strstr(str, "false") != NULL )
			return FALSE;
		else if( strstr(str, "true") != NULL )
			return TRUE;

		if( strstr(str, "no") != NULL )
			return FALSE;
		else if( strstr(str, "yes") != NULL )
			return TRUE;
	}

	return FALSE;
}

int ConfigRead(ConfigFileInfo *Info)
{
	int				NumOfRead	=	0;

	char			Buffer[3072];
	char			*ValuePos;
	ReadLineStatus	ReadStatus;

	char			KeyName[KEY_NAME_MAX_SIZE + 1];
	ConfigOption	*Option;

	while(TRUE){
		ReadStatus = ReadLine(Info -> fp, Buffer, sizeof(Buffer));
		if( ReadStatus == READ_FAILED_OR_END )
			return NumOfRead;

		if( GetKeyNameFromLine(Buffer, KeyName) == NULL )
			continue;

		Option = GetOptionOfAInfo(Info, KeyName);
		if( Option == NULL )
			continue;

		ValuePos = (char *)GetValuePosition(Buffer);
		if( ValuePos == NULL )
			continue;

		switch( Option -> Type )
		{
			case TYPE_INT32:
				switch (Option -> Strategy)
				{
					case STRATEGY_APPEND_DISCARD_DEFAULT:
						if( Option -> Status == STATUS_DEFAULT_VALUE )
						{
							Option -> Strategy = STRATEGY_APPEND;
						}
						/* No break */

					case STRATEGY_DEFAULT:
					case STRATEGY_REPLACE:
						sscanf(ValuePos, "%d", &(Option -> Holder.INT32));
						Option -> Status = STATUS_SPECIAL_VALUE;
						break;

					case STRATEGY_APPEND:
						{
							_32BIT_INT SpecifiedValue;

							sscanf(ValuePos, "%d", &SpecifiedValue);
							Option -> Holder.INT32 += SpecifiedValue;

							Option -> Status = STATUS_SPECIAL_VALUE;
						}
						break;

					default:
						continue;
						break;
				}
				break;

			case TYPE_BOOLEAN:
				switch (Option -> Strategy)
				{
					case STRATEGY_APPEND_DISCARD_DEFAULT:
						if( Option -> Status == STATUS_DEFAULT_VALUE )
						{
							Option -> Strategy = STRATEGY_APPEND;
						}
						/* No break */

					case STRATEGY_DEFAULT:
					case STRATEGY_REPLACE:

						Option -> Holder.boolean = GetBoolealValueFromString(ValuePos);

						Option -> Status = STATUS_SPECIAL_VALUE;
						break;

					case STRATEGY_APPEND:
						{
							BOOL SpecifiedValue;

							SpecifiedValue = GetBoolealValueFromString(ValuePos);
							Option -> Holder.boolean |= SpecifiedValue;

							Option -> Status = STATUS_SPECIAL_VALUE;
						}
						break;

						default:
							continue;
							break;

				}
				break;

			case TYPE_STRING:
				{
					switch (Option -> Strategy)
					{
						case STRATEGY_APPEND_DISCARD_DEFAULT:
							if( Option -> Status == STATUS_DEFAULT_VALUE )
							{
								Option -> Strategy = STRATEGY_APPEND;
							}
							/* No break */

						case STRATEGY_DEFAULT:
						case STRATEGY_REPLACE:
							StringList_Clear(&(Option -> Holder.str));
							Option -> Status = STATUS_SPECIAL_VALUE;
							if( StringList_Add(&(Option -> Holder.str), ValuePos, ',') != 0 )
							{
								continue;
							}

							break;

						case STRATEGY_APPEND:
							if( StringList_Add(&(Option -> Holder.str), ValuePos, ',') != 0 )
							{
								continue;
							}
							Option -> Status = STATUS_SPECIAL_VALUE;
							break;

						default:
							continue;
							break;
					}

					while( ReadStatus != READ_DONE ){

						ReadStatus = ReadLine(Info -> fp, Buffer, sizeof(Buffer));
						if( ReadStatus == READ_FAILED_OR_END )
							break;

						StringList_AppendLast(&(Option -> Holder.str), Buffer, ',');
					}

				}
				break;

			default:
				break;
		}
		++NumOfRead;
	}
	return NumOfRead;
}

const char *ConfigGetRawString(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		if( Option -> Holder.str.Used == 0 )
		{
			return NULL;
		} else {
			return Option -> Holder.str.Data;
		}
	}

	return NULL;
}

StringList *ConfigGetStringList(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		if( Option -> Holder.str.Used == 0 )
		{
			return NULL;
		} else {
			return &(Option -> Holder.str);
		}
	}

	return NULL;
}

_32BIT_INT ConfigGetNumberOfStrings(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return StringList_Count(&(Option -> Holder.str));
	}

	return 0;
}

_32BIT_INT ConfigGetInt32(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option -> Holder.INT32;
	}

	return 0;
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option -> Holder.boolean;
	}

	return FALSE;
}

void ConfigSetValue(ConfigFileInfo *Info, VType Value, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		Option -> Status = STATUS_SPECIAL_VALUE;
		switch( Option -> Type )
		{
			case TYPE_INT32:
				Option -> Holder.INT32 = Value.INT32;
				break;

			case TYPE_BOOLEAN:
				Option -> Holder.boolean = Value.boolean;
				break;

			case TYPE_STRING:
				StringList_Clear(&(Option -> Holder.str));
				StringList_Add(&(Option -> Holder.str), Value.str, ',');
				break;

			default:
				break;
		}
	}
}

void ConfigDisplay(ConfigFileInfo *Info)
{
	int loop;
	for(loop = 0; loop != Info -> NumOfOptions; ++loop)
	{
		if( *(Info -> Options[loop].Caption) != '\0' )
		{
			switch( Info -> Options[loop].Type )
			{
				case TYPE_INT32:
					printf("%s:%d\n", Info -> Options[loop].Caption, Info -> Options[loop].Holder.INT32);
					break;
				case TYPE_BOOLEAN:
					printf("%s:%s\n", Info -> Options[loop].Caption, BoolToYesNo(Info -> Options[loop].Holder.boolean));
					break;
				case TYPE_STRING:
					if( Info -> Options[loop].Holder.str.Used >= 0 )
					{
						const char *Str = StringList_GetNext(&(Info -> Options[loop].Holder.str), NULL);

						while( Str != NULL )
						{
							printf("%s:%s\n", Info -> Options[loop].Caption, Str);
							Str = StringList_GetNext(&(Info -> Options[loop].Holder.str), Str);
						}
					}
					break;
				default:
					break;
			}
		}
	}
}
