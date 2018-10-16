/* -------------------------------------------------------------------------
 *
 * connection_control.c
 *
 * Copyright (c) 2010-2017, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/connection_control/connection_control.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h> 
#include <string.h>

#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/types.h>   
#include <sys/stat.h>   
#include <fcntl.h> 
#include <unistd.h>
#endif


#include "executor/spi.h"
#include "libpq/auth.h"
#include "port.h"
#include "utils/guc.h"
#include "utils/timestamp.h"


#define LOGIN_REFUSE_FILE "connection_control"
#define LOCK_FILE "connection_control.lock"

PG_MODULE_MAGIC;

void		_PG_init(void);

bool		fileExist(char* file_name);
int			createNewfile(char* file_name);
void		create_and_lock_record_file(void);
void		unlock_record_file(void);
bool		user_exist(char * user_name);
int			failed_count(char * user_name);
int			failed_time_interval(char * user_name);
void		remove_user(char * user_name);
void		insert_user(char * user_name, int count, long timestamp);
void		increase_failed_count(char * user_name);
/* GUC Variables */
static int	login_refuse_minutes;
static int	login_refuse_threshold;
static char *full_path;
static char *lock_path;

/* Original Hook */
static ClientAuthentication_hook_type original_client_auth_hook = NULL;

/*
 * Check authentication
 */
static void
login_refuse_checks(Port *port, int status)
{
	//elog(LOG,"-----------------------begin-------------------------");
	
	int threshold;
	
	if (strcmp(GetConfigOption("ssl",false, true), "on") == 0)
	{
		threshold = login_refuse_threshold * 2;
		elog(LOG, "on");
	}
	else
	{
		elog(LOG, "off");
		threshold = login_refuse_threshold;
	}
	/*
	 * Any other plugins which use ClientAuthentication_hook.
	 */
	if (original_client_auth_hook)
		original_client_auth_hook(port, status);
/*
	if (port->hba->auth_method != uaPassword && 
		port->hba->auth_method != uaSCRAM &&
		port->hba->auth_method != uaMD5)
	{
		return;
	}
*/		

	
	switch(port->hba->auth_method)
	{
		case uaReject:
			elog(LOG,"auth_method is uaReject");
			break;
		case uaImplicitReject:
			elog(LOG,"auth_method is uaImplicitReject");
			break;
		case uaTrust:
			elog(LOG,"auth_method is uaTrust");
			break;
		case uaIdent:
			elog(LOG,"auth_method is uaIdent");
			break;
		case uaPassword:
			elog(LOG,"auth_method is uaPassword");
			break;
		case uaMD5:
			elog(LOG,"auth_method is uaMD5");
			break;
		case uaSCRAM:
			elog(LOG,"auth_method is uaSCRAM");
			break;
		case uaGSS:
			elog(LOG,"auth_method is uaGSS");
			break;
		case uaSSPI:
			elog(LOG,"auth_method is uaSSPI");
			break;
		case uaPAM:
			elog(LOG,"auth_method is uaPAM");
			break;
		case uaBSD:
			elog(LOG,"auth_method is uaBSD");
			break;
		case uaLDAP:
			elog(LOG,"auth_method is uaLDAP");
			break;
		case uaCert:
			elog(LOG,"auth_method is uaCert");
			break;
		case uaRADIUS:
			elog(LOG,"auth_method is uaRADIUS");
			break;
		case uaPeer:
			elog(LOG,"auth_method is uaPeer");
			break;
		default:
			break;
	}	
	
	switch(status)
	{
		case STATUS_OK:
			elog(LOG,"status is STATUS_OK");
			break;
		case STATUS_ERROR:
			elog(LOG,"status is STATUS_ERROR");
			break;
		case STATUS_EOF:
			elog(LOG,"status is STATUS_EOF");
			break;
		case STATUS_FOUND:
			elog(LOG,"status is STATUS_FOUND");
			break;
		case STATUS_WAITING:
			elog(LOG,"status is STATUS_WAITING");
			break;
		default:
			break;
	}

	if (status != STATUS_OK && status != STATUS_ERROR)
	{	
		return;	
	}
	
	create_and_lock_record_file();

	elog(LOG,"login_refuse_minutes is %d", login_refuse_minutes);

	
	if (user_exist(port->user_name))
	{
		if (failed_count(port->user_name) >= threshold)
		{
			if (failed_time_interval(port->user_name) < login_refuse_minutes * 60)
			{
				elog(LOG,"this connection should be refused!");
				free(full_path);
				unlock_record_file();
				free(lock_path);
				ereport(FATAL,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					errmsg("You are not allow to access the database!!!\n"
					"		Please try after %d minutes!!!", login_refuse_minutes)));	
			}
			else
			{
				elog(LOG,"222");
				remove_user(port->user_name);
			}
		}
		else
		{
			if (failed_time_interval(port->user_name) > login_refuse_minutes * 60)
			{
				elog(LOG,"233");
				remove_user(port->user_name);
			}
			elog(LOG,"234");
		}
	}
	 
	if (status != STATUS_OK)
	{

		if (!user_exist(port->user_name))
		{
			elog(LOG,"333");
			insert_user(port->user_name, 1, time(NULL));

		}
		else
		{
			elog(LOG,"444");
			increase_failed_count(port->user_name); // update failed_time also
		}
	}
	else
	{
		elog(LOG,"445");
		if (user_exist(port->user_name))
		{
			remove_user(port->user_name);
		}		
	}
	elog(LOG,"555");
	free(full_path);
	unlock_record_file();
	free(lock_path);
	
	//	elog(LOG,"------------------------end--------------------------");
}

/*
 * if the file exist
 */
bool
fileExist(char* file_name)
{
	if (access(file_name, F_OK) == 0)
		return true;
	return false;
}

/*
 * create new file
 */
int
createNewfile(char* file_name)
{
#ifdef WIN32	
	FILE *fp;
	fp = fopen(file_name, "w");
	if (fp)
	{
		fclose(fp);
		return true;
	}
	return false;

#else
	return creat(file_name, 0755);
#endif
}


/*
 * create the record_file
 */
void
create_and_lock_record_file(void)
{
	char	   *configdir;
	
	configdir = make_absolute_path(getenv("PGDATA"));
	
	full_path = malloc(strlen(configdir) + strlen(LOGIN_REFUSE_FILE) + 2);
	sprintf(full_path, "%s/%s", configdir, LOGIN_REFUSE_FILE);
	
	lock_path = malloc(strlen(configdir) + strlen(LOCK_FILE) + 2);
	sprintf(lock_path, "%s/%s", configdir, LOCK_FILE);
	
	//elog(DEBUG1,"path is %s", full_path);
	//elog(DEBUG1,"lock_path is %s", lock_path);

	if (!fileExist(full_path))//file does not exist
	{
		//elog(LOG,"file does not exist");
		if (createNewfile(full_path) < 0)
		{
			elog(ERROR,"Can not create connection_control file");
		}
	}

	while (fileExist(lock_path))// lock file already exist,wait
	{
		pg_usleep(1000L);
		//elog(LOG,"Wait");
	}
	if (createNewfile(lock_path) < 0)
	{
		elog(ERROR,"Can not create lock file");
	}
	
	//elog(LOG,"LINUX!!!!");
}

/*
 * delete the lock file
 */
void
unlock_record_file(void)
{
#ifdef WIN32
	if (!DeleteFile(lock_path))
	{
		elog(ERROR,"Can not remove lock file");		
	}
	
#else
	if (remove(lock_path) != 0)
	{
		elog(ERROR,"Can not remove lock file");
	}
#endif
}

/*
 * if the user exist in record_file
 */
bool
user_exist(char * user_name)
{
	FILE *fp;
	char line[200];
	char id[30];
	
	//elog(DEBUG1,"path is %s", full_path);
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file connection_control");
	}
	
	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	//elog(DEBUG1,"id is a%sa", id);
	
	while(!feof(fp))
	{
		fgets(line, 200, fp);
		if (strstr(line, id))
		{
			//elog(DEBUG1,"xxxx");
			fclose(fp);
			return true;			
		}	
	}
	fclose(fp);	
	return false;
}

/*
 * times user_name has failed
 */
int
failed_count(char * user_name)
{
	FILE *fp;
	char line[200];
	char id[30];
	int fail_count;
	char *ptr;

	//elog(DEBUG1,"path is %s", full_path);	
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file connection_control");
	}
	
	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	//elog(DEBUG1,"id is a%sa", id);
	
	while(!feof(fp))
	{
		fgets(line, 200, fp);
		if (strstr(line, id))
		{
			//elog(DEBUG1,"failed_count");
			//get the failed_count of the line match the user_name
			ptr = strtok(line," ");
			ptr = strtok(NULL, " ");
			//elog(DEBUG1,"ptr is %s",ptr);
			sscanf(ptr,"%d", &fail_count);
			//elog(DEBUG1,"failed_count is %d",fail_count);
			fclose(fp);	
			return fail_count;			
		}	
	}
	
	fclose(fp);	
	return 0;
}

/*
 * time interval(in seconds) from last failed for user_name
 */
int
failed_time_interval(char * user_name)
{
	FILE *fp;
	char *ptr;
	char line[200];
	char id[30];
	time_t failed_time;

	//elog(DEBUG1,"path is %s", full_path);	
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file connection_control");
	}
	
	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	//elog(DEBUG1,"id is a%sa", id);
	
	while(!feof(fp))
	{
		fgets(line, 200, fp);
		if (strstr(line, id))
		{
			//elog(DEBUG1,"failed_time_interval");
			//get the failed_time of the line match the user_name
			ptr = strtok(line," ");
			ptr = strtok(NULL, " ");
			ptr = strtok(NULL, " ");
			//elog(DEBUG1,"ptr is %s",ptr);
			sscanf(ptr,"%ld", &failed_time);
			//elog(DEBUG1,"failed_time is %ld",failed_time);
			fclose(fp);	
			return time(NULL) - failed_time;			
		}	
	}
	fclose(fp);	
	return login_refuse_minutes * 60;
}


/*
 * remove record of user_name from record_file
 */
void
remove_user(char * user_name)
{
	FILE *fp;
	long length;
	char *buffer;
	char line[200];
	char id[30];
	
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file connection_control");
	}
	
	fseek(fp, 0, SEEK_END);
	memset(line, 0x00, 200);
	length = ftell(fp);
	//elog(DEBUG1,"length is:%ld", length);
	buffer = (char*)malloc(sizeof(char)*length);
	memset(buffer, 0x00, sizeof(char)*length);
	rewind(fp);
	
	//elog(DEBUG1,"buffer is:%s", buffer);
	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	//elog(DEBUG1,"id is a%sa", id);
	//elog(DEBUG1,"line is:%s", line);
	while(fgets(line, 200, fp))
	{	
		//elog(DEBUG1,"line is:%s", line);
		if (strstr(line, id))
		{
			continue;
		}
		strcat(buffer, line);
		//elog(DEBUG1,"buffer is:%s", buffer);
	}
	fclose(fp);
	//elog(DEBUG1,"buffer is:%s", buffer);	
	fp = fopen(full_path, "w");
	fputs(buffer, fp);
	fclose(fp);
	free(buffer);
	
}

/*
 * insert user_name into record_file
 */
void
insert_user(char * user_name, int count, long timestamp)
{
	FILE *fp;
	
	fp = fopen(full_path, "a");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file connection_control");
	}
	//elog(DEBUG1," %s %d %ld\n", user_name, count, timestamp);
	fprintf(fp," %s %d %ld\n", user_name, count, timestamp);
	
	fclose(fp);
	
}

/*
 * increase failed_count and update timestamp 
 * for user_name in record_file
 */
void
increase_failed_count(char * user_name)
{
	int count;
	
	count = failed_count(user_name) + 1;
	remove_user(user_name);
	insert_user(user_name, count, time(NULL));
}

/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	/* Define custom GUC variables */
	DefineCustomIntVariable("connection_control.minutes",
							"minutes to refuse users login",
							NULL,
							&login_refuse_minutes,
							0,
							0, INT_MAX,
							PGC_SIGHUP,
							GUC_UNIT_MIN,
							NULL,
							NULL,
							NULL);
							
	DefineCustomIntVariable("connection_control.threshold",
							"failed times before refuse users login",
							NULL,
							&login_refuse_threshold,
							0,
							0, INT_MAX,
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);
	/* Install Hooks */
	original_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = login_refuse_checks;
}
