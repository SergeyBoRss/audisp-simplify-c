#include "audisp-simplify-c-thread.h"
#include "audisp-simplify-c-str-function.h"
#include "audisp-simplify-c-filter.h"

FILE *f_ignorefile;
FILE *f_logfile;
FILE *f_debug;
FILE *f_stat;
FILE *f_admin;

int pid;
int ppid;

pthread_t T_coordinator;
pthread_t T_read_STDIN;
pthread_t T_relocate_buf_to_start;
pthread_t T_parsing_buf;
pthread_t T_parsing_line[COUNT_PARALLEL_PARSING];
pthread_t T_relocate_audit;
pthread_t T_save_file;
pthread_t T_stat;

atomic_bool ATOM_THREAD_read_STDIN_run=false;
atomic_int  ATOM_line_read=0;
atomic_int  ATOM_start_seq_mem_relocate=0;
atomic_int  ATOM_end_seq_mem_relocate=0;
atomic_bool ATOM_THREAD_parsing_line_run[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_THREAD_start_seq_mem[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_THREAD_end_seq_mem[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_last_end_seq_mem=0;
atomic_bool ATOM_THREAD_relocate_buf_to_start_run=false;
atomic_bool ATOM_relocate_run=false;
atomic_bool ATOM_relocate_processed=false;
atomic_bool ATOM_THREAD_parsing_buf_run=false;
atomic_int  ATOM_run_parsing_line=0;
atomic_int  ATOM_parsing_line_processed=0;
atomic_int  ATOM_start_seq_mem_parsing[COUNT_SEQ_MEM_PARSING];
atomic_int  ATOM_end_seq_mem_parsing[COUNT_SEQ_MEM_PARSING];
atomic_int  ATOM_prev_id=0;
atomic_int  ATOM_auditid_thread[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_add_to_array_id[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_add_to_array_auditid[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_start_audit_relocate=0;
atomic_int  ATOM_end_audit_relocate=0;
atomic_int  ATOM_post_relocate=0;
atomic_bool ATOM_need_save=false;
atomic_bool ATOM_THREAD_save_run=false;
atomic_bool ATOM_save_run=false;
atomic_int  ATOM_save_count=0;
atomic_int  ATOM_save_line=0;
atomic_bool ATOM_relocate_auditid_run=false;
atomic_int  ATOM_filtering_pid=0;

atomic_bool ATOM_STAT=true;
atomic_int  ATOM_STAT_read_byte=0;
atomic_int  ATOM_STAT_filtering=0;
atomic_int  ATOM_STAT_line_auditd=0;


atomic_bool ATOM_cmd_stop=false;
atomic_bool ATOM_cmd_logrotate=false;
atomic_bool ATOM_cmd_pause=false;

int       size_buf=SIZE_BUF;

char       *read_buf;
s_audit    *array_audit;
s_pass     *array_pass;
s_group    *array_group;
s_STAT_UID *array_STAT_UID;
s_ignore   *array_ignore;
//s_skipped_queue *skipped_queue;

mutex MTX_parsing_line_read_seq;
//mutex MTX_skipped_queue;
//mutex MTX_relocate;
mutex MTX_STAT_UID;

sem_t SEM_relocate_buf;
sem_t SEM_relocate_audit;
sem_t SEM_line_read;
sem_t SEM_run_parsing_line;
sem_t SEM_array_audit_lock;
sem_t SEM_save;

void admin_file(const char *adminfile)
{
  char str_cmd[25];
  //========== admin file ===========
  if ((f_admin=fopen(adminfile,"r"))!=NULL)
  {
    fgets(str_cmd,25,f_admin);
    fclose(f_admin);
  }
  else
    printf("error create admin file %s\n",adminfile);
  //========== admin file ===========

  if (strlen(str_cmd)>3)
  {
    //========== admin file ===========
    if ((f_admin=fopen(adminfile,"w"))!=NULL)
    {
      fputs("",f_admin);
      fclose(f_admin);
    }
    else
      printf("error create admin file %s\n",adminfile);
    //========== admin file ===========

    //======== execute cmd from admin file ===========
    int len_cmd=strlen(str_cmd);
    if (len_cmd>3)
    {
      if (str_cmd[len_cmd-1]=='\n')
      {
        str_cmd[len_cmd-1]='\0';
        len_cmd--;
      }
      if ((DEBUG==true) || (DEBUG_DISPLAY==true))
        snprintf(msg,255,"cmd[%s]\n",str_cmd);
      deblog(msg);
      if (strncmp(str_cmd,"pause on",24)==0)
      {
        ATOM_cmd_pause.store(true);
      }
      if (strncmp(str_cmd,"pause off",24)==0)
      {
        ATOM_cmd_pause.store(false);
      }
      if (strncmp(str_cmd,"stop",24)==0)
      {
        ATOM_cmd_stop.store(true);
      }
      if (strncmp(str_cmd,"logrotate",24)==0)
      {
        ATOM_cmd_logrotate.store(true);
      }
      if (strncmp(str_cmd,"debug to file",24)==0)
      {
        DEBUG=true;
      }
      if (strncmp(str_cmd,"debug to display",24)==0)
      {
        DEBUG_DISPLAY=true;
      }
      if (strncmp(str_cmd,"debug off",24)==0)
      {
        deblog((char *)"debug off");
        save_deblog();
        DEBUG=false;
        DEBUG_DISPLAY=false;
      }
      if (strncmp(str_cmd,"print buffer",24)==0)
      {
        printbuf(read_buf);//======TESTING======
      }
      if (strncmp(str_cmd,"print audit array",24)==0)
      {
        print_ALL_audit();
      }
      if (strncmp(str_cmd,"print stat",24)==0)
      {
        print_stat();
      }
      if (strncmp(str_cmd,"help",24)==0)
      {
        printf("use cmd: echo 'cmd' > %s\n",adminfile);
        printf("    pause on         : read STDIO but not store to buffer and not parsing\n");
        printf("    pause off        : read STDIO, store to buffer and parsing\n");
        printf("    stop             : set signal to stop all thread, and close programm\n");
        printf("    logrotate        : move %s to %s\n",logfile,storefile);
        //printf("    compress        : compress %s to %s\n",logfile,storefile);
        printf("    debug to file    : set on debug to file %s",deblogfile);
        printf("    debug to display : set on debug to display");
        printf("    debug off        : set off debug to file and display");
        printf("    print buffer     : print internal buffer and position parsing thread");//<------- may be BUG === TESTING ====
        printf("    print audit array: print internal buffer audit, before save to file %s",logfile);
        printf("    print stat       : print statistic, \"they are automatically written to a file %s\"",statfile);
        printf("    help             : print this messages");
      }
    }

    str_cmd[0]='\0';
    //======== execute cmd from admin file ===========
  }
}


void *F_coordinator(void* vbuf)
{
  char*   buf = (char*)vbuf;
  char    msg[256];

  int n_thread;
  deblog((char *)"=== thread coordinator start ===");
  //========== admin file ===========
  if ((f_admin=fopen(adminfile,"w"))!=NULL)
  {
    fputs("",f_admin);
    fclose(f_admin);
  }
  else
    printf("error create admin file %s\n",adminfile);
  //========== admin file ===========

  while (true)
  {
    bool flag_sleep=true;
    admin_file(adminfile);

    //========= stop read STDIN ==================
    if (ATOM_THREAD_read_STDIN_run.load()==false)
    {
      deblog((char *)"thread read STDIN stoped");
      if (ATOM_THREAD_relocate_buf_to_start_run.load()==true)
      {
        deblog((char *)"thread relocate_buf_to_start not stop");
        sem_post(&SEM_relocate_buf);
        //sleep(1);
        if (pthread_kill(T_relocate_buf_to_start,0)!=ESRCH)
        {
          deblog((char *)"=== kill thread relocate_buf_to_start ===");
          pthread_cancel(T_relocate_buf_to_start);
          //pthread_join(T_relocate_buf_to_start,0x00);
          ATOM_THREAD_relocate_buf_to_start_run.store(false);
          deblog((char *)"=== end kill thread relocate_buf_to_start ===");
        }
        T_relocate_buf_to_start=0;
      }
      if (ATOM_THREAD_parsing_buf_run.load()==true)
      {
        deblog((char *)"thread parsing_buf not stop");
        sleep(1);
        ATOM_THREAD_save_run.store(false);
        if (pthread_kill(T_parsing_buf,0)!=ESRCH)
        {
          deblog((char *)"=== kill thread parsing_buf ===");
          pthread_cancel(T_parsing_buf);
          //pthread_join(T_parsing_buf,0x00);
          ATOM_THREAD_parsing_buf_run.store(false);
        }
        T_parsing_buf=0;
      }
      else
        deblog((char *)"thread parsing_buf allready stopped");

      if (ATOM_run_parsing_line.load()>0)
      {
        if (DEBUG==true)
        {
          if ((DEBUG==true) || (DEBUG_DISPLAY==true))
            snprintf(msg,255,"run parsing_line thread=%d",ATOM_run_parsing_line.load());
          deblog(msg);

          for (int i=0; i<COUNT_PARALLEL_PARSING; i++)
          {
              if ( ATOM_THREAD_parsing_line_run[i].load() == true )
              {
                if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                  snprintf(msg,255,"run parsing_line [%d]",i);
                deblog(msg);
              }

          }
        }
        for (int nmbr_kill=0; nmbr_kill<ATOM_run_parsing_line.load();nmbr_kill++)
        {
          sem_post(&SEM_run_parsing_line);
        }
      }

      //stop relocate_audit
      if ((ATOM_THREAD_parsing_buf_run.load()==false) && (ATOM_relocate_auditid_run.load()==true))
      {
        if (DEBUG_LEVEL>2)
          deblog("COORDINATOR:stop relocate_audit");
        sem_post(&SEM_relocate_audit);
      }
      //sem_post(&SEM_line_read);
      //pthread_kill(T_parsing_buf);

      for (int k=0; k<COUNT_SEQ_MEM_PARSING; k++)
      {
        //seq in not parsing buffer
        if (ATOM_end_seq_mem_parsing[k].load()!=0)
        {
          MTX_parsing_line_read_seq.lock();

          int i_line_start=ATOM_start_seq_mem_parsing[k].load();
          int i_line_end  =ATOM_end_seq_mem_parsing[k].load();

          ATOM_start_seq_mem_parsing[k].store(0);
          ATOM_end_seq_mem_parsing[k].store(0);

          MTX_parsing_line_read_seq.unlock();
          //snprintf(msg,255,"end [%d]process not parsing str[%d-%d]\n",k,i_line_start,i_line_end);
          //deblog(msg);
          F_parsing_string_to_auditid(buf,i_line_start,i_line_end,array_audit,-1);
          ATOM_line_read.fetch_sub(1);
          int number_line_in_queue;
          sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
          if (number_line_in_queue>0)
            sem_wait(&SEM_run_parsing_line);

        }
      }
      //scan and save all array

      ATOM_THREAD_save_run.store(false);
      ATOM_save_run.store(true);
      deblog((char *)"finish save");
      if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
        print_ALL_audit();
      //deblog((char *)"F_coordinator");
      //int count_a_save=count_array_audit(0);
      //if ((DEBUG==true) && (DEBUG_LEVEL>2))
      //{
        //snprintf(msg,255,"count_a_save=%d",count_a_save);
        //deblog(msg);
      //}
      //ATOM_save_count.store(count_a_save);
      ATOM_save_count.store(SIZE_AUDIT);
      sem_post(&SEM_save);


      //deblog((char *)"=== thread coordinator stop ===");
      //snprintf(msg,255,"line not read:%d",ATOM_line_read.load());
      //deblog(msg);
      int number_line_in_queue;
      sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
      //snprintf(msg,255,"sem for read:%d",number_line_in_queue);
      //deblog(msg);

      /*if (DEBUG_DISPLAY==true)
      {
        printf("========= ATOM_xxx_seq_mem_parsing ======\n");
        for (int k=0; k<COUNT_SEQ_MEM_PARSING; k++)
        {
          if (ATOM_end_seq_mem_parsing[k].load()!=0)
          {
            printf("[%d]not parsing [%d-%d]\n",k,ATOM_start_seq_mem_parsing[k].load(),ATOM_end_seq_mem_parsing[k].load());
          }
        }
        printf("========= ATOM_xxx_seq_mem_parsing ======\n");
      }*/

      /*if (DEBUG_DISPLAY==true)
      {
        //sleep(1);
        sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
        printf("=========================\n");
        printf("line not read:%d\n",ATOM_line_read.load());
        printf("SEM_run_parsing_line:%d\n",number_line_in_queue);
        printf("=========================\n");
        printbuf(buf);
      }*/
      //return NULL;
      if (ATOM_relocate_auditid_run.load()==false)
      {
        if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
        {
          printf("! relocate_auditid not stop\n");
        }
        sem_post(&SEM_relocate_audit);
      }
      while (ATOM_THREAD_save_run.load()==true)
      {



        if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>2))
        {
          printf("!wait save file, save_count=%d\n",ATOM_save_count.load());
        }
        sleep(1);
        if (ATOM_THREAD_save_run.load()==true)
          sem_post(&SEM_save);
      }


      break;
    }
    //========= stop read STDIN ==================



    //==============not porcessed mesg in quiet========
    for (int k=1; k<COUNT_SEQ_MEM_PARSING; k++)
    {
      //mesg in quiet
      if (ATOM_end_seq_mem_parsing[k].load()!=0)
      {
        flag_sleep=false;
        MTX_parsing_line_read_seq.lock();

        int i_line_start=ATOM_start_seq_mem_parsing[k].load();
        int i_line_end  =ATOM_end_seq_mem_parsing[k].load();

        ATOM_start_seq_mem_parsing[k].store(0);
        ATOM_end_seq_mem_parsing[k].store(0);

        //search free thread
        if (ATOM_end_seq_mem_parsing[0].load()==0)
        {
          ATOM_start_seq_mem_parsing[0].store(i_line_start);
          ATOM_end_seq_mem_parsing[0].store(i_line_end);
          MTX_parsing_line_read_seq.unlock();
          //snprintf(msg,255,"[%d]->[0]process not parsing str[%d-%d]\n",k,i_line_start,i_line_end);
          //deblog(msg);
        }
        else
        {
          MTX_parsing_line_read_seq.unlock();
          //snprintf(msg,255,"[%d]process not parsing str[%d-%d]\n",k,i_line_start,i_line_end);
          //deblog(msg);
          F_parsing_string_to_auditid(buf,i_line_start,i_line_end,array_audit,-1);
          ATOM_line_read.fetch_sub(1);
          int number_line_in_queue;
          sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
          if (number_line_in_queue>0)
            sem_wait(&SEM_run_parsing_line);
        }
      }
    }
    //==============not porcessed mesg in quiet========


    if (flag_sleep==true)
      sleep(1);
    if (DEBUG_DISPLAY==true)
      printf(".\n");
  }
  //sem_init
  //pthread_cond_init



  /*sleep(10);
  //stop thread
  //pthread_cancel(T_read_STDIN);
  deblog("set stop flag for read_STDIN");
  ATOM_THREAD_read_STDIN_run.store(false);*/

  deblog((char *)"===== finish coordinator =====");
  return NULL;
}

void *F_read_STDIN(void* vbuf)
{
  char    msg[256];
  deblog((char *)"=== thread read_STDIN start ===");
  int     i=0;
  ssize_t nr;
  char    c_char;
  int     i_line_end=0;
  char*   buf = (char*)vbuf;
  int     coun_line_for_read;
  int     TMP_STAT_read_byte=0;

  ATOM_THREAD_read_STDIN_run.store(true);

  //int pid=getpid();
  //int ppid=getppid();

  //snprintf(msg,255,"pid=%u ppid=%u",pid,ppid);
  //deblog(msg);

  while(read(STDIN_FILENO, &c_char, 1) > 0)
  {
    buf[i]=c_char;
    TMP_STAT_read_byte++;
		if (buf[i]=='\n' || buf[i]=='\0')
	  {
      //=== sync stat=====
      ATOM_STAT_read_byte.fetch_add(TMP_STAT_read_byte);

      TMP_STAT_read_byte=0;
      //=== sync stat=====
      if ((i-i_line_end)==1)
      {
        i--;
      }
      else
      {
        i_line_end=i;
        /*if (DEBUG_DISPLAY==true)
        {
          printf("Alr+");
          printf("[%d]",i);
        }*/
        ATOM_line_read.fetch_add(1);
        /*if (DEBUG_DISPLAY==true)
        {
          int val_SEM_line_read;
          sem_getvalue(&SEM_line_read,&val_SEM_line_read);
          printf("Slr(%d)+\n",val_SEM_line_read);


        }*/
        sem_post(&SEM_line_read);
      }
      if (ATOM_cmd_stop.load()==true)
      {
          deblog((char *)"cmd stop, read_STDIN stopped");
          break;
      }

    }
    i++;
    if (i>=SIZE_BUF)
    {
      //deblog("i>=size_buf");
      ATOM_line_read.store(0);//count string from start buffer
      //snprintf(msg,255,"thread read_STDIN over memory buf: last pos %d (i_line_end=%d)",i,i_line_end);
      //deblog(msg);
      if (i_line_end==0)
      {
        //deblog("=========> relocate none");
        i=0;
      }
      else
      {
        //====relocate not pasring memory to start==== (T_relocate_memory_to_start)
        /*if (ATOM_relocate_run.load()==true)
        {
          deblog("=========> relocate is running, wait");

        }*/
        ATOM_start_seq_mem_relocate.store(i_line_end+1);
        ATOM_end_seq_mem_relocate.store(i);
        i=i-(i_line_end+1);
        /*if (i>0)
        {
          //printbuf(buf);
          snprintf(msg,255,"new pos %d buf[i-1]=%x",i,buf[i-1]);
        }
        else
          snprintf(msg,255,"new pos %d",i);
        deblog(msg);
        deblog("=========> set sem relocate ");*/
        sem_post(&SEM_relocate_buf);
        //====relocate not pasring memory to start====
      }
    }
  }

  //i_line_end=i;

  //ATOM_start_seq_mem_relocate.store(i_line_end+1);
  //ATOM_end_seq_mem_relocate.store(i);
  //snprintf(msg,255,"END read STDIN i=%d",i);
  //deblog(msg);
  ATOM_line_read.fetch_add(1);
  sem_post(&SEM_line_read);



  //deblog((char *)">");
  ATOM_THREAD_read_STDIN_run.store(false);
  //deblog((char *)"=== thread read_STDIN stop ===");

  //pthread_cancel(T_parsing_read_buf);
  return NULL;
}

void *F_relocate_buf_to_start(void* vbuf)
{
  char* buf = (char*)vbuf;
  char  msg[256];
  int   i,i_start,i_end;

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0x00);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0x00);

  deblog((char *)"=== therad relocate_buf_to_start start ===");
  ATOM_THREAD_relocate_buf_to_start_run.store(true);
  while (true)
  {
    sem_wait(&SEM_relocate_buf);



    /*snprintf(msg,255,"relocate: line not read:%d",ATOM_line_read.load());
    deblog(msg);
    int number_line_in_queue;
    sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
    snprintf(msg,255,"relocate: sem for read:%d",number_line_in_queue);
    deblog(msg);*/

    if ( ATOM_THREAD_read_STDIN_run.load() == false )
      break;
    ATOM_relocate_run.store(true);
    //deblog((char *)"start relocate buf");
    i_start=ATOM_start_seq_mem_relocate.load();
    i_end=ATOM_end_seq_mem_relocate.load();
    for (i=i_start; i < i_end; i++)
    {
      buf[i-i_start]=buf[i];
      buf[i]='\0';
    }
    //deblog((char *)"stop relocate buf");
    ATOM_relocate_run.store(false);
  }
  ATOM_relocate_run.store(false);
  ATOM_THREAD_relocate_buf_to_start_run.store(false);
  //deblog((char *)"=== therad relocate_buf_to_start stop ===");
  return NULL;
}

void *F_parsing_buf(void* vbuf)
{
  char* buf = (char*)vbuf;
  char  msg[256];
  int i,i_start;
  int i_line_start=0;
	int i_line_end=0;
  int coun_line_for_read;
  int coun_thread_parsing_run;

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0x00);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0x00);

  ATOM_parsing_line_processed.store(0);
  ATOM_THREAD_parsing_buf_run.store(true);
  int count_string_in_buf=0;
  sem_wait(&SEM_line_read);
  deblog("=== thread parsing_buf start ===");

  //snprintf(msg,255,"ATOM_line_read:%d",ATOM_line_read.load());
  //deblog(msg);

  while(true)
  {
    //protection on null buffer circle
    if (i==0)
    {
      //reset count
      count_string_in_buf=0;
    }
    //protection on null buffer circle
    if (buf[i]=='\n' || buf[i]=='\0')
    {
      count_string_in_buf++;
      i_line_end=i;

      if (i_line_end-i_line_start>6)
      {

        buf[i]='\0';
        if (i_line_start>i_line_end)
        {
          //snprintf(msg,255,"i_line_start=%d > i_line_end=%d",i_line_start,i_line_end);
          //deblog(msg);
          i_line_start=0;
        }
        //========== parsing line ============
        //snprintf(msg,255,"parsing line i_line_start=%d i_line_end=%d",i_line_start,i_line_end);
        //deblog(msg);
        MTX_parsing_line_read_seq.lock();
        int k=0;
        if (ATOM_end_seq_mem_parsing[k].load()!=0)
        {
          //push_skipped_queue(buf,ATOM_start_seq_mem_parsing.load(),ATOM_end_seq_mem_parsing.load());
          for (k=1; k<COUNT_SEQ_MEM_PARSING; k++)
          {
            if (ATOM_end_seq_mem_parsing[k].load()==0)
            {
              if (DEBUG_LEVEL>1)
              {
                if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                {
                  snprintf(msg,255,"add seq to array for parsing store seq mem in k el:%d,<%d;%d>",k,i_line_start,i_line_end);
                  deblog(msg);
                }
              }
              ATOM_start_seq_mem_parsing[k].store(i_line_start);
              ATOM_end_seq_mem_parsing[k].store(i_line_end);
              break;
            }
          }
          if (k>=COUNT_SEQ_MEM_PARSING)
          {
            printf("error, too many audit events, write audit to stdout\n");
            for (int i=i_line_start; i<i_line_end; i++)
            {
              printf("%c",buf[i]);
              //clear str in buf
              buf[i]='\0';
            }
            printf("\n");
          }
        }
        else
        {
          ATOM_start_seq_mem_parsing[k].store(i_line_start);
          ATOM_end_seq_mem_parsing[k].store(i_line_end);
        }
        MTX_parsing_line_read_seq.unlock();
        sem_post(&SEM_run_parsing_line);
        sem_getvalue(&SEM_run_parsing_line,&coun_thread_parsing_run);
        /*if (DEBUG==true)
        {
          snprintf(msg,255,"SEM_run_parsing_line:%d",coun_thread_parsing_run);
          deblog(msg);
        }*/
        if (coun_thread_parsing_run>(COUNT_PARALLEL_PARSING*4))
        {
          deblog((char *)"over read line for pasring, increase COUNT_PARALLEL_PARSING parameter");
          //sem_wait()
        }

        //========== parsing line ============
      }
      i_line_start=i+1;
      //==========================
      if (ATOM_THREAD_read_STDIN_run.load()==false)
      {
        if (coun_line_for_read==0)
        {
          deblog((char *)"=== end parsing_buf ===");
          break;
        }
      }
      //==========================
      //snprintf(msg,255,"ATOM_line_read:%d",ATOM_line_read.load());
      //deblog(msg);
      if (ATOM_need_save.load()==true)
      {
        if (ATOM_save_run.load()==false)
        {
          //test use size buf audit
          //if count filled array audit >= 80 % size audit F_save_file
          if (DEBUG_LEVEL>0)
            deblog((char *)"F_parsing_buf:");
          if (count_array_audit(0)>MAX_AUDIT_BEFORE_SAVE_TO_FILE)
          {
              //save_to file 60% audit
              ATOM_save_count.store(SAVE_AUDIT);
              ATOM_save_run.store(true);
              sem_post(&SEM_save);
              ATOM_need_save.store(false);
          }
        }
      }

      //if (DEBUG_DISPLAY==true)
        //printf("Slr(%d) --",i);
      sem_wait(&SEM_line_read);

      i++;
      //clear zerro at row
      for (; i<SIZE_BUF; i++)
      {
        if (buf[i]!='\n' && buf[i]!='\0')
        { i_line_end=i-1;
          break;
        }
      }
    }
    else
      i++;
    if (i>=SIZE_BUF)
    {
      i=0;
      i_line_start=0;

      //====sync SEM_line_read and ATOM_line_read=====
      int val_ATOM_line_read=ATOM_line_read.load();
      int number_line_in_queue;
      sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);


      //snprintf(msg,255,"====sync=== line not read:%d",val_ATOM_line_read);
      //deblog(msg);
      //snprintf(msg,255,"====sync=== sem for read:%d",number_line_in_queue);
      //deblog(msg);


      if ((val_ATOM_line_read-1)>number_line_in_queue)
      {
        //deblog((char *)"====== corect sem++ !!!");
        sem_post(&SEM_line_read);
      }
      //====sync SEM_line_read and ATOM_line_read=====
      //protection fron nul circle
      if (count_string_in_buf==0)
      {
        //deblog("null buf, sem--");
        ATOM_line_read.store(0);
        sem_wait(&SEM_line_read);
      }
      //protection null
    }
  }

  ATOM_THREAD_parsing_buf_run.store(false);
  return NULL;
}

void *F_parsing_line(void* vbuf)
{
  char* buf = (char*)vbuf;
  char  msg[256];
  int i_line_start;
  int i_line_end;
  int n_thread=ATOM_run_parsing_line.fetch_add(1);
  ATOM_THREAD_parsing_line_run[n_thread].store(true);
  if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    snprintf(msg,255,"=== start thread parsing [%d] ===",n_thread);
  deblog(msg);
  ATOM_THREAD_start_seq_mem[n_thread].store(0);
  ATOM_THREAD_end_seq_mem[n_thread].store(0);
  while(true)
  {

    sem_wait(&SEM_run_parsing_line);
    //if ( ATOM_THREAD_parsing_buf_run.load() == false )
      //break;
    MTX_parsing_line_read_seq.lock();
    //====read and clrar====
    int k=0;
    i_line_start=ATOM_start_seq_mem_parsing[k].load();
    i_line_end  =ATOM_end_seq_mem_parsing[k].load();

    if (i_line_end==0)
    {
      for (k=1; k<COUNT_SEQ_MEM_PARSING; k++)
      {
        if (ATOM_end_seq_mem_parsing[k].load()!=0)
        {

          //snprintf(msg,255,"[%d]==============read seq mem el from k:%d",n_thread,k);
          //deblog(msg);
          i_line_start=ATOM_start_seq_mem_parsing[k].load();
          i_line_end  =ATOM_end_seq_mem_parsing[k].load();
          break;
        }
      }
      if (k==COUNT_SEQ_MEM_PARSING)
        k=0;
    }
    ATOM_start_seq_mem_parsing[k].store(0);
    ATOM_end_seq_mem_parsing[k].store(0);
    //====read and clear====
    MTX_parsing_line_read_seq.unlock();
    if (i_line_end!=0)
      ATOM_last_end_seq_mem.store(i_line_end);
    ATOM_THREAD_start_seq_mem[n_thread].store(i_line_start);
    ATOM_THREAD_end_seq_mem[n_thread].store(i_line_end);

    if (i_line_end!=0)
    {
      //snprintf(msg,255,"parsing[%d] %d %d",n_thread,i_line_start,i_line_end);
      //deblog(msg);
      //debbuf(i_line_start,i_line_end,buf);
      F_parsing_string_to_auditid(buf,i_line_start,i_line_end,array_audit,n_thread);
      ATOM_line_read.fetch_sub(1);
    }
    /*else
    {

      //snprintf(msg,255,"parsing[%d] error run parsing, end is null(i_line_start:%d,i_line_end:%d ATOM_last_end_seq_mem:%d)!!!",n_thread,i_line_start,i_line_end,ATOM_last_end_seq_mem.load());
      //deblog(msg);
      //printbuf(buf);
    }*/




    if ( ATOM_THREAD_parsing_buf_run.load() == false )
      break;
  }
  if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    snprintf(msg,255,"end thread parsing [%d]",n_thread);
  deblog(msg);
  ATOM_run_parsing_line.fetch_sub(1);
  ATOM_THREAD_parsing_line_run[n_thread].store(false);
  return NULL;
}

void STAT_UID_add(int c_uid)
{
  int i;
  bool flag_find=false;
  MTX_STAT_UID.lock();
  if (c_uid==0)
  {
    array_STAT_UID[0].uid=0;
    array_STAT_UID[0].count++;
  }
  for (i=1;i<COUNT_STAT_UID;i++)
  {
    if ((array_STAT_UID[i].uid==c_uid) || (array_STAT_UID[i].uid==0))
    {
      if (array_STAT_UID[i].uid==0)
        array_STAT_UID[i].uid=c_uid;
      array_STAT_UID[i].count++;
      flag_find=true;
      break;
    }
  }
  if (flag_find==false)
  {
    array_STAT_UID[COUNT_STAT_UID-1].uid=c_uid;
    array_STAT_UID[COUNT_STAT_UID-1].count=1;
    deblog("COUNT_STAT_UID is small");
  }
  MTX_STAT_UID.unlock();
}

void sort_STAT_UID()
{
  int max_el;
  int id_max_el;
  int not_max_el=0;
  int uid_not_max_el=0;
  MTX_STAT_UID.lock();
  for (int i=0;i<COUNT_STAT_UID;i++)
  {
    max_el=0;
    id_max_el=i;
    for (int j=i;j<COUNT_STAT_UID;j++)
    {
      if (array_STAT_UID[j].count>max_el)
      {
        max_el=array_STAT_UID[j].count;
        id_max_el=j;
      }
      //move max el to start
      if (id_max_el!=i)
      {
        uid_not_max_el=array_STAT_UID[i].uid;
        not_max_el=array_STAT_UID[i].count;

        array_STAT_UID[i].uid=array_STAT_UID[id_max_el].uid;
        array_STAT_UID[i].count=array_STAT_UID[id_max_el].count;

        array_STAT_UID[id_max_el].uid=uid_not_max_el;
        array_STAT_UID[id_max_el].count=not_max_el;
      }
    }
  }
  MTX_STAT_UID.unlock();
}

void clear_STAT_UID()
{
  for (int i=0;i<COUNT_STAT_UID;i++)
  {
      array_STAT_UID[i].count=0;
  }
}

void *F_save_file(void* varray_audit)
{
  char msg[256];
  int array_count_save;
  struct tm *local_tm;
  struct tm  l_tm;
  s_audit* f_array = (s_audit*)varray_audit;
  ATOM_THREAD_save_run.store(true);
  deblog("=== thread save to file start ===");

  int pid=getpid();
  int ppid=getppid();

  //snprintf(msg,255,"|pid=%u ppid=%u",pid,ppid);
  //deblog(msg);

  while (1)
  {
    //deblog("sem wait:SEM_save");
    sem_wait(&SEM_save);
    //===== adminfile cmd storefile ====
    if (ATOM_cmd_logrotate.load()==true)
    {
      rename(logfile,storefile);
      ATOM_cmd_logrotate.store(false);
      sem_wait(&SEM_save);
    }
    //===== adminfile cmd storefile ====
    array_count_save=ATOM_save_count.load();
    //== start save ===
    ATOM_save_run.store(true);
    if (DEBUG_LEVEL>1)
      deblog("==== > filtering");
    filtering(f_array,array_count_save);

    if (DEBUG_LEVEL>0)
      if ((DEBUG==true) || (DEBUG_DISPLAY==true))
      {
        snprintf(msg,255,"save_to_file:count=%d",array_count_save);
        deblog(msg);
      }
    if (DEBUG_LEVEL>1)
      deblog("open logfile");
    if ((f_logfile=fopen(logfile,"a"))!=NULL)
    {
      int i;
      for (i = 0; i < array_count_save; i++)
      {

        if (f_array[i].auditid>0)
        {
          if (f_array[i].pid != pid && f_array[i].ppid != ppid)
          {
            // === date time ====
      	    local_tm=localtime(&f_array[i].t_shtamp);
      	    l_tm=*local_tm;
      	    fprintf(f_logfile,"%04d-%02d-%02d %02d:%02d:%02d.%i ",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec,f_array[i].t_mls);
      	    fprintf(f_logfile,"auditid=\"%d\" ",f_array[i].auditid);

            if (DEBUG_LEVEL>2)
            {
              if ((DEBUG==true) || (DEBUG_DISPLAY==true))
              {
                snprintf(msg,255,"   >> save >> [%d].auditid=%d",i,f_array[i].auditid);
                deblog(msg);
              }
            }

      	    fprintf(f_logfile,"date=\"%04d-%02d-%02d\" ",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday);
      	    fprintf(f_logfile,"time=\"%02d:%02d:%02d.%i\" ",l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec,f_array[i].t_mls);


            if (f_array[i].auid_isset==true)
            {
              fprintf(f_logfile,"auid=\"%u\" ",f_array[i].auid);
              fprintf(f_logfile,"auid_user=\"%s\" ",f_array[i].auid_user);
            }
            //=====================================13
            if (f_array[i].uid_isset==true)
            {
              fprintf(f_logfile,"uid=\"%u\" ",f_array[i].uid);
              fprintf(f_logfile,"uid_user=\"%s\" ",f_array[i].uid_user);

              STAT_UID_add(f_array[i].uid);

              if (DEBUG_LEVEL>2)
              {
                if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                {
                  snprintf(msg,255,"   >>> auditid(%d)",f_array[i].auditid);
                  deblog(msg);
                }
              }
            }
            if (f_array[i].euid_isset==true)
            {
              fprintf(f_logfile,"euid=\"%u\" ",f_array[i].euid);
              if (strlen(f_array[i].euid_user)==0)
                uidtouser(f_array[i].euid_user,f_array[i].euid);
              fprintf(f_logfile,"euid_user=\"%s\" ",f_array[i].euid_user);
            }
            if (f_array[i].suid_isset==true)
            {
              fprintf(f_logfile,"suid=\"%u\" ",f_array[i].suid);
              if (strlen(f_array[i].suid_user)==0)
                uidtouser(f_array[i].suid_user,f_array[i].suid);
              fprintf(f_logfile,"suid_user=\"%s\" ",f_array[i].suid_user);
            }
            if (f_array[i].fsuid_isset==true)
            {
              fprintf(f_logfile,"fsuid=\"%u\" ",f_array[i].fsuid);
              if (strlen(f_array[i].fsuid_user)==0)
                uidtouser(f_array[i].fsuid_user,f_array[i].fsuid);
              fprintf(f_logfile,"fsuid_user=\"%s\" ",f_array[i].fsuid_user);
            }
            if (f_array[i].ouid_isset==true)
            {
              fprintf(f_logfile,"ouid=\"%u\" ",f_array[i].ouid);
              if (strlen(f_array[i].ouid_user)==0)
                uidtouser(f_array[i].ouid_user,f_array[i].ouid);
              fprintf(f_logfile,"ouid_user=\"%s\" ",f_array[i].ouid_user);
            }
            if (f_array[i].agid_isset==true)
            {
              fprintf(f_logfile,"agid=\"%u\" ",f_array[i].agid);
              if (strlen(f_array[i].agid_group)==0)
                gidtogroup(f_array[i].agid_group,f_array[i].agid);
              fprintf(f_logfile,"agid_group=\"%s\" ",f_array[i].agid_group);
            }
            if (f_array[i].agid_isset==true)
            {
              fprintf(f_logfile,"gid=\"%u\" ",f_array[i].gid);
              if (strlen(f_array[i].gid_group)==0)
                gidtogroup(f_array[i].gid_group,f_array[i].gid);
              fprintf(f_logfile,"gid_group=\"%s\" ",f_array[i].gid_group);
            }
            if (f_array[i].egid_isset==true)
            {
              fprintf(f_logfile,"egid=\"%u\" ",f_array[i].egid);
              if (strlen(f_array[i].egid_group)==0)
                gidtogroup(f_array[i].egid_group,f_array[i].egid);
              fprintf(f_logfile,"egid_group=\"%s\" ",f_array[i].egid_group);
            }
            if (f_array[i].sgid_isset==true)
            {
              fprintf(f_logfile,"sgid=\"%u\" ",f_array[i].sgid);
              if (strlen(f_array[i].sgid_group)==0)
                gidtogroup(f_array[i].sgid_group,f_array[i].sgid);
              fprintf(f_logfile,"sgid_group=\"%s\" ",f_array[i].sgid_group);
            }
            if (f_array[i].fsgid_isset==true)
            {
              fprintf(f_logfile,"fsgid=\"%u\" ",f_array[i].fsgid);
              if (strlen(f_array[i].fsgid_group)==0)
                gidtogroup(f_array[i].fsgid_group,f_array[i].fsgid);
              fprintf(f_logfile,"fsgid_group=\"%s\" ",f_array[i].fsgid_group);
            }
            if (f_array[i].ogid_isset==true)
            {
              fprintf(f_logfile,"ogid=\"%u\" ",f_array[i].ogid);
              if (strlen(f_array[i].ogid_group)==0)
                gidtogroup(f_array[i].ogid_group,f_array[i].ogid);
              fprintf(f_logfile,"ogid_group=\"%s\" ",f_array[i].ogid_group);
            }

            if (strlen(f_array[i].addr)>0)
              fprintf(f_logfile,"addr=\"%s\" ",f_array[i].addr);
            if (strlen(f_array[i].exe)>0)
              fprintf(f_logfile,"exe=\"%s\" ",f_array[i].exe);
            if (strlen(f_array[i].hostname)>0)
              fprintf(f_logfile,"hostname=\"%s\" ",f_array[i].hostname);
            if (strlen(f_array[i].key)>0)
              fprintf(f_logfile,"key=\"%s\" ",f_array[i].key);

            if (strlen(f_array[i].newcontext)>0)
              fprintf(f_logfile,"newcontext=\"%s\" ",f_array[i].newcontext);
            if (strlen(f_array[i].oldcontext)>0)
              fprintf(f_logfile,"oldcontext=\"%s\" ",f_array[i].oldcontext);
            if (f_array[i].pid_isset==true)
              fprintf(f_logfile,"pid=\"%u\" ",f_array[i].pid);
            if (f_array[i].ppid_isset==true)
              fprintf(f_logfile,"ppid=\"%u\" ",f_array[i].ppid);
            if (strlen(f_array[i].res)>0)
              fprintf(f_logfile,"res=\"%s\" ",f_array[i].res);
            if (strlen(f_array[i].seresult)>0)
              fprintf(f_logfile,"seresult=\"%s\" ",f_array[i].seresult);
            if (f_array[i].ses_isset==true)
              fprintf(f_logfile,"ses=\"%u\" ",f_array[i].ses);
            if (strlen(f_array[i].subj)>0)
              fprintf(f_logfile,"subj=\"%s\" ",f_array[i].subj);
            if (strlen(f_array[i].terminal)>0)
              fprintf(f_logfile,"terminal=\"%s\" ",f_array[i].terminal);
            if (strlen(f_array[i].tty)>0)
              fprintf(f_logfile,"tty=\"%s\" ",f_array[i].tty);
            if (strlen(f_array[i].direction)>0)
              fprintf(f_logfile,"direction=\"%s\" ",f_array[i].direction);
            if (strlen(f_array[i].cipher)>0)
              fprintf(f_logfile,"cipher=\"%s\" ",f_array[i].cipher);
            if (strlen(f_array[i].ksize)>0)
              fprintf(f_logfile,"ksize=\"%s\" ",f_array[i].ksize);
            if (strlen(f_array[i].mac)>0)
              fprintf(f_logfile,"mac=\"%s\" ",f_array[i].mac);
            if (strlen(f_array[i].pfs)>0)
              fprintf(f_logfile,"pfs=\"%s\" ",f_array[i].pfs);
            if (strlen(f_array[i].spid)>0)
              fprintf(f_logfile,"spid=\"%s\" ",f_array[i].spid);
            if (strlen(f_array[i].laddr)>0)
              fprintf(f_logfile,"laddr=\"%s\" ",f_array[i].laddr);
            if (strlen(f_array[i].lport)>0)
              fprintf(f_logfile,"lport=\"%s\" ",f_array[i].lport);

            if (strlen(f_array[i].SYSCALL)>0)
              fprintf(f_logfile,"syscall=\"%s\" ",f_array[i].SYSCALL);
            if (f_array[i].syscall>=0)
              fprintf(f_logfile,"syscall=\"%d\" ",f_array[i].syscall);

            if (strlen(f_array[i].op)>0)
              fprintf(f_logfile,"op=\"%s\" ",f_array[i].op);
            if (strlen(f_array[i].vm)>0)
              fprintf(f_logfile,"vm=\"%s\" ",f_array[i].vm);
            if (strlen(f_array[i].cwd)>0)
              fprintf(f_logfile,"cwd=\"%s\" ",f_array[i].cwd);
            /*if (strlen(f_array[i].cmd)>0)
              fprintf(f_logfile,"cmd=\"%s\" ",f_array[i].cmd);*/
            if (strlen(f_array[i].proctitle)>0)
              fprintf(f_logfile,"proctitle=\"%s\" ",f_array[i].proctitle);

            if (strlen(f_array[i].errcode)>0)
              fprintf(f_logfile,"errcode=\"%s\" ",f_array[i].errcode);
            if (strlen(f_array[i].errdesc)>0)
              fprintf(f_logfile,"errdesc=\"%s\" ",f_array[i].errdesc);
            //if (strlen(f_array[i].saddr)>0)
              //fprintf(f_logfile,"saddr=\"%s\" ",f_array[i].saddr);
            if (strlen(f_array[i].res_saddr)>0)
              fprintf(f_logfile,"saddr=\"%s\" ",f_array[i].res_saddr);
            if (strlen(f_array[i].avc)>0)
              fprintf(f_logfile,"avc=\"%s\" ",f_array[i].avc);
            if (strlen(f_array[i].types)>0)
              fprintf(f_logfile,"types=\"%s\" ",f_array[i].types);
            if (strlen(f_array[i].names)>0)
              fprintf(f_logfile,"names=\"%s\" ",f_array[i].names);
            if (strlen(f_array[i].acct)>0)
              fprintf(f_logfile,"acct=\"%s\" ",f_array[i].acct);
            if (strlen(f_array[i].unit)>0)
              fprintf(f_logfile,"unit=\"%s\" ",f_array[i].unit);
            if (strlen(f_array[i].success)>0)
              fprintf(f_logfile,"success=\"%s\" ",f_array[i].success);

            if (strlen(f_array[i].command)>0)
              fprintf(f_logfile,"command=\"%s\" ",f_array[i].command);

            //syscall
            if (strlen(f_array[i].args)>0)
              fprintf(f_logfile,"an=\"%s\" ",f_array[i].args);


            //=====================================13
            ATOM_save_line.fetch_add(1);
            fprintf(f_logfile,"\n");
      		}
          else
          {
            if (DEBUG_LEVEL>1)
            {
              if ((DEBUG==true) || (DEBUG_DISPLAY==true))
              {
                snprintf(msg,255,"auditid[%d]=%d not save, pid(%d)=audisp-simplify-c",i,f_array[i].auditid,pid);
                deblog(msg);
              }
            }
            ATOM_filtering_pid.fetch_add(1);
          }
          //clear
          f_array[i].auditid=0;
        }
      }
      if (DEBUG_LEVEL==3)
        deblog("close logfile");
      fclose(f_logfile);
    }
    else
      printf("error save file %s\n",logfile);


    if (ATOM_THREAD_save_run.load()==false)
      break;
    // lock array and remove not save array to start array

    //count el in array start with array_count_save
    int max_array_count=count_array_audit(array_count_save);

    ATOM_start_audit_relocate.store(array_count_save);
    ATOM_end_audit_relocate.store(max_array_count);
    if (DEBUG_LEVEL>0)
      deblog("end step save, run relocate");
    sem_post(&SEM_relocate_audit);
    // unlock all
    if (DEBUG_LEVEL>1)
    {
      if ((DEBUG==true) || (DEBUG_DISPLAY==true))
      {
    	  snprintf(msg,255,"ATOM_start_audit_relocate=%d ATOM_end_audit_relocate=%d",array_count_save,max_array_count);
    	  deblog(msg);
      }
    }
    ATOM_save_count.store(0);
    ATOM_save_run.store(false);
    //=== end save ===


    //ATOM_relocate_auditid_run.store(array_count);
  }
  ATOM_save_run.store(false);
  ATOM_THREAD_save_run.store(false);
  deblog((char *)"== end save thread ==");
  return NULL;
}

void *F_relocate_audit(void* varray_audit)
{
  s_audit* f_array = (s_audit*)varray_audit;
  ATOM_relocate_auditid_run.store(true);
  while(true)
  {
    sem_wait(&SEM_relocate_audit);
    if (ATOM_THREAD_parsing_buf_run.load()==false)
      break;
    ATOM_relocate_processed.store(true);

    int start_i=ATOM_start_audit_relocate.load();
    int end_i = ATOM_end_audit_relocate.load();
    ATOM_post_relocate.store(end_i-start_i);
    //count_relocate_auditid=ATOM_relocate_auditid.load();
    for (int i=start_i; i<end_i; i++)
    {
      if (f_array[i].auditid!=0)
      {
        if (DEBUG_LEVEL>2)
        {
          if ((DEBUG==true) || (DEBUG_DISPLAY==true))
          {
            //if (ATOM_save_run.load()==true)
              //deblog("========= save is run ===========");
            snprintf(msg,255,"  relocate f_array[%d].auditid(%d) ==> f_array[%d].auditid uid_user=%s",i,f_array[i].auditid,(i-start_i),f_array[i].uid_user);
            deblog(msg);
          }
        }
        //f_array[i-start_i].auditid=f_array[i].auditid;
        memcpy((&f_array[i-start_i]),(&f_array[i]),sizeof(s_audit));
        memset((&f_array[i]),0,sizeof(s_audit));
        //f_array[i].auditid=0;
      }
    }

    ATOM_start_audit_relocate.store(0);
    ATOM_end_audit_relocate.store(0);
    ATOM_relocate_processed.store(false);
    //unlock
    //ATOM_relocate_auditid.store(0);
    /*deblog("unlock0 SEM_run_parsing_line_in_buf");
    sem_post(&SEM_run_parsing_line_in_buf);
    deblog("unlock1 SEM_run_parsing_line_in_buf");
    sem_post(&SEM_run_parsing_line_in_buf);
    deblog("unlock2 SEM_run_parsing_line_in_buf");
    sem_post(&SEM_run_parsing_line_in_buf);
    deblog("unlocked SEM_run_parsing_line_in_buf");*/
  }
  ATOM_relocate_auditid_run.store(false);
  return NULL;
}

void write_stat(FILE *f_stat)
{
  //========== stat file ===========
  if ((f_stat=fopen(statfile,"w"))!=NULL)
  {
    //====curent time====
    struct tm *local_tm;
    struct tm  l_tm;
    time_t t_shtamp;
    t_shtamp = time(NULL);
    local_tm=localtime(&t_shtamp);
    l_tm=*local_tm;
    fprintf(f_stat,"%04d-%02d-%02d %02d:%02d:%02d\n",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec);
    fprintf(f_stat,"\n");
    //====curent time====
    fprintf(f_stat,"interval:%dsec\n",STAT_INTERVAL);
    fprintf(f_stat,"size buffer for read:%d\n",SIZE_BUF);
    fprintf(f_stat,"max thread parsing:%d\n",COUNT_PARALLEL_PARSING);
    fprintf(f_stat,"array size for auditid:%d\n",SIZE_AUDIT);
    fprintf(f_stat,"max count array pos seq for parsing in buffer:%d\n",COUNT_SEQ_MEM_PARSING);
    fprintf(f_stat,"max count cache login:%d\n",COUNT_CACHE_LOGIN);
    fprintf(f_stat,"max count cache group:%d\n",COUNT_CACHE_GROUP);

    fprintf(f_stat,"\n");

    if ( ATOM_THREAD_read_STDIN_run.load() == true )
      fprintf(f_stat,"thread write buf running\n");
    fprintf(f_stat,"read byte:%d\n",ATOM_STAT_read_byte.load());
    fprintf(f_stat,"string in buf not parsing:%d\n",ATOM_line_read.load());
    fprintf(f_stat,"raw audit line:%d\n",ATOM_STAT_line_auditd.load());

    for (int i=0; i<COUNT_PARALLEL_PARSING; i++)
    {
        if ( ATOM_THREAD_parsing_line_run[i].load() == true )
        {
          fprintf(f_stat,"thread parsing line [%d] running, ",i);
          fprintf(f_stat,"buffer processing <%d;%d>, ",ATOM_THREAD_start_seq_mem[i].load(),ATOM_THREAD_end_seq_mem[i].load());

          fprintf(f_stat," last element to added to array auditid [%d]<-(%d)\n",ATOM_add_to_array_id[i].load(),ATOM_add_to_array_auditid[i].load());

        }
    }

    if (ATOM_count_ignore_key.load()>0)
    {
      fprintf(f_stat,"filtering on one record:%d\n",ATOM_filtering.load());
      fprintf(f_stat,"filtering:%d\n",ATOM_STAT_filtering.load());
    }
    fprintf(f_stat,"filtering pid and ppid:%d\n",ATOM_filtering_pid.load());

    fprintf(f_stat,"save count to log:%d\n",ATOM_save_line.load());

    fprintf(f_stat,"==== max record uid ====\n");
    sort_STAT_UID();

    for (int i=0; i<=5; i++)
    {
      if (array_STAT_UID[i].count!=0)
      fprintf(f_stat,"uid:%d\tcount rec:%d\n",array_STAT_UID[i].uid,array_STAT_UID[i].count);
    }
    fprintf(f_stat,"==== max record uid ====\n");
    fprintf(f_stat,"\n");
    if (ATOM_relocate_processed.load()==true)
      fprintf(f_stat,"relocate array audit processed\n");
    if (ATOM_save_run.load()==true)
      fprintf(f_stat,"save\n");
    fclose(f_stat);
  }
  else
    printf("error create statistic file %s\n",statfile);
  ATOM_STAT_read_byte.store(0);
  ATOM_STAT_line_auditd.store(0);
  ATOM_STAT_filtering.store(0);
  ATOM_filtering_pid.store(0);
  ATOM_save_line.store(0);
  clear_STAT_UID();
  //========== stat file ===========
}

void print_stat()
{
  write_stat(f_debug);
}

void *F_stat(void*)
{
  deblog((char *)"=== thread stat start ===");
  write_stat(f_stat);
  while (true)
  {
    for (int t=0;t<STAT_INTERVAL;t++)
    {
      if (ATOM_THREAD_read_STDIN_run.load()==true)
        sleep(1);
    }
    save_deblog();
    write_stat(f_stat);
    if (ATOM_THREAD_read_STDIN_run.load()==false)
      break;
  }
  deblog((char *)"=== thread end stat ===");
  return NULL;
}
