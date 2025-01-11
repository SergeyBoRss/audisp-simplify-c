#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#include "audisp-simplify-c-thread.h"
#include "audisp-simplify-c-str-function.h"
#include "audisp-simplify-c-filter.h"

using namespace std;

bool DEBUG=false;
bool DEBUG_DISPLAY=false;
int  DEBUG_LEVEL=0;

const char *ignorefile="/etc/audit/simplify.ignores";
const char *logfile="/var/log/audisp-simplify-c";
const char *storefile="/var/log/audisp-simplify-c.store";
const char *deblogfile="/var/log/audisp-simplify-c.log";
const char *statfile="/var/log/audisp-simplify-c.stat";
const char *adminfile="/var/lib/audisp-simplify-c";

int main(int argc,char *argv[])
{
  char msg_main[256];
  pid=getpid();
  ppid=getppid();

  if (argc>1)
  {
    if (strcmp(argv[1],"-d")==0)
    {
      DEBUG=true;
      DEBUG_DISPLAY=false;
    }
    if (strcmp(argv[1],"-D")==0)
    {
      DEBUG=false;
      DEBUG_DISPLAY=true;
    }
  }
  //if (DEBUG==true)
    msg=(char *)malloc(sizeof(char) * SIZE_MSG);
  deblog((char *)"=======================\n================== start =========");
  if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    snprintf(msg_main,255,"pid=%d ppid=%d",pid,ppid);
  deblog(msg_main);
  // === allocate memory ===
  read_buf=(char *)malloc(sizeof(char) * SIZE_BUF);
  memset(read_buf,0,sizeof(char) * SIZE_BUF);
  array_audit=(s_audit *)malloc(sizeof(s_audit) * SIZE_AUDIT);
  memset(array_audit,0,sizeof(s_audit) * SIZE_AUDIT);
  array_pass=(s_pass *)malloc(sizeof(s_pass) * COUNT_CACHE_LOGIN);
  memset(array_pass,0,sizeof(s_pass) * COUNT_CACHE_LOGIN);
  array_group=(s_group *)malloc(sizeof(s_group) * COUNT_CACHE_GROUP);
  memset(array_group,0,sizeof(s_group) * COUNT_CACHE_GROUP);
  array_STAT_UID=(s_STAT_UID *)malloc(sizeof(s_STAT_UID) * COUNT_STAT_UID);
  memset(array_STAT_UID,0,sizeof(s_STAT_UID) * COUNT_STAT_UID);
  //skipped_queue=(s_skipped_queue *)malloc(sizeof(s_skipped_queue) * SIZE_SKIPPED_QUEUE);
  //memset(skipped_queue,0,sizeof(s_skipped_queue) * SIZE_SKIPPED_QUEUE);
  // === allocate memory ===
	// === ignore file ===
	//print_hash_audit_reserved_key();

  size_audit_reserved_key=init_available_hash_ignore_key();
	read_ignorefile_to_buf(read_buf,size_buf);
	if (ATOM_count_ignore_key.load()>0)
	{
		array_ignore=(s_ignore *)malloc(sizeof(s_ignore) * ATOM_count_ignore_key);
	  memset(array_ignore,0,sizeof(s_ignore) * ATOM_count_ignore_key);
		buf_to_ignore_array(read_buf,SIZE_BUF);
    deblog("-------- ignore -----");
    if (DEBUG_LEVEL>2)
      printignore();
	}

	// === ignore file ===


  sem_init(&SEM_relocate_buf,0,0);
  sem_init(&SEM_relocate_audit,0,0);
  sem_init(&SEM_line_read,0,0);
  sem_init(&SEM_run_parsing_line,0,0);
  sem_init(&SEM_array_audit_lock,0,3);
  sem_init(&SEM_save,0,0);


  pthread_create(&T_coordinator,           NULL, F_coordinator,          (void*)read_buf);
  pthread_create(&T_read_STDIN,            NULL, F_read_STDIN,           (void*)read_buf);
  pthread_create(&T_relocate_buf_to_start, NULL, F_relocate_buf_to_start,(void*)read_buf);
  pthread_create(&T_parsing_buf,           NULL, F_parsing_buf,          (void*)read_buf);
  for (int i=0; i<COUNT_PARALLEL_PARSING; i++)
  {
    ATOM_auditid_thread[i].store(0);
    pthread_create(&T_parsing_line[i],     NULL, F_parsing_line,         (void*)read_buf);
  }
  pthread_create(&T_save_file,             NULL, F_save_file,            (void*)array_audit);
  pthread_create(&T_relocate_audit,        NULL, F_relocate_audit,       (void*)array_audit);
  pthread_create(&T_stat,                  NULL, F_stat,                 NULL);


  pthread_join(T_read_STDIN,NULL);
  deblog("end T_read_STDIN");
  pthread_join(T_relocate_buf_to_start,NULL);
  deblog("end T_relocate_buf_to_start");
  pthread_join(T_parsing_buf,NULL);
  deblog("end T_parsing_buf");

  for (int i=0; i<COUNT_PARALLEL_PARSING; i++)
  {
    pthread_join(T_parsing_line[i],NULL);
    deblog("end T_parsing_line[i]");
  }
  deblog("end T_parsing_line");
  pthread_join(T_relocate_audit,NULL);
  deblog("end T_relocate_audit");
  pthread_join(T_save_file,NULL);
  deblog("end T_save_file");
  pthread_join(T_stat,NULL);
  deblog("end T_stat");
  pthread_join(T_coordinator,NULL);
  deblog("end T_coordinator");
  //free(skipped_queue);

  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("start free\n");
  free(read_buf);
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("free read_buf\n");
  free(array_pass);
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("free array_pass\n");
  free(array_group);
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("free array_group\n");
  free(array_STAT_UID);
  free(array_audit);
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("free array_audit\n");
  free(available_hash_ignore_key);
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("free available_hash_ignore_key\n");

  if ((DEBUG==true) && (ATOM_save_debug_run.load()==true))
  {
    printf("wait save debug\n");
    sleep(1);
  }
  free(msg);
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
    printf("free msg\n");
  return 0;
}
