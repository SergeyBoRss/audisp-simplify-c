#include "audisp-simplify-c-thread.h"
#include "audisp-simplify-c-str-function.h"
#include "audisp-simplify-c-filter.h"

FILE *f_ignorefile;
FILE *f_logfile;
FILE *f_err;
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
pthread_t T_compress_file;

atomic_bool ATOM_THREAD_read_STDIN_run=false;
atomic_int  ATOM_line_read=0;
atomic_int  ATOM_start_seq_mem_relocate=0;
atomic_int  ATOM_end_seq_mem_relocate=0;
atomic_bool ATOM_THREAD_parsing_line_run[COUNT_PARALLEL_PARSING];
atomic_bool ATOM_THREAD_parsing_line_processing[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_THREAD_start_seq_mem[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_THREAD_end_seq_mem[COUNT_PARALLEL_PARSING];
atomic_int  ATOM_last_end_seq_mem=0;
atomic_bool ATOM_THREAD_relocate_buf_to_start_run=false;
atomic_bool ATOM_relocate_run=false;
atomic_bool ATOM_relocate_processed=false;
atomic_int  ATOM_relocate_RED_ZONE_start_section=0;
atomic_int  ATOM_relocate_RED_ZONE_end_section=0;
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
//atomic_bool ATOM_need_save=false;
atomic_bool ATOM_THREAD_save_run=false;
atomic_bool ATOM_save_run=false;
atomic_int  ATOM_save_count=0;
atomic_int  ATOM_save_line=0;
atomic_int  ATOM_save_step=0;
atomic_bool ATOM_relocate_auditid_run=false;
atomic_int  ATOM_filtering_pid=0;

atomic_bool ATOM_STAT=true;
atomic_int  ATOM_STAT_read_byte=0;
atomic_int  ATOM_STAT_read_block=0;
atomic_int  ATOM_STAT_memory_read_block_size=0;
atomic_int  ATOM_STAT_current_read_block_size=0;
atomic_int  ATOM_STAT_read_byte_in_block=0;
atomic_int  ATOM_STAT_filtering=0;
atomic_int  ATOM_STAT_line_auditd=0;
atomic_int  ATOM_STAT_raw_auditd_error=0;
atomic_int  ATOM_STAT_auditd_error=0;
atomic_int  ATOM_STAT_leak=0;

atomic_bool ATOM_cmd_stop=false;
atomic_bool ATOM_cmd_logrotate=false;
atomic_bool ATOM_cmd_logrotated=false;
atomic_bool ATOM_cmd_logrotategz=false;
atomic_bool ATOM_compress_gz=false;
atomic_bool ATOM_cmd_pause=false;

int       size_buf=SIZE_BUF;
bool      resize_size_b_char=true;
bool      reduce_size_b_char=true;

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
mutex MTX_debug;

sem_t SEM_relocate_buf;
sem_t SEM_relocate_audit;
sem_t SEM_line_read;
sem_t SEM_run_parsing_line;
sem_t SEM_array_audit_lock;
sem_t SEM_save;

void admin_file(const char *adminfile)
{
  char str_cmd[25];
  str_cmd[0]='\0';
  str_cmd[24]='\0';
  //========== admin file ===========
  if ((f_admin=fopen(adminfile,"r"))!=NULL)
  {
    fgets(str_cmd,24,f_admin);
    str_cmd[24]='\0';
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

      if (strncmp(str_cmd,"stop",24)==0)
      {
        ATOM_cmd_stop.store(true);
      }
      if (strncmp(str_cmd,"help",24)==0)
      {
        printf("use cmd: echo 'cmd' > %s\n",adminfile);
        printf("    filter on        : filtering audit array use file %s\n",ignorefile);
        printf("    filter off       : filtering off\n");
        printf("    pause on         : read STDIO but not store to buffer and not parsing\n");
        printf("    pause off        : read STDIO, store to buffer and parsing\n");
        printf("    stop             : set signal to stop all thread, and close programm\n");
        printf("    logrotate        : move %s to %s\n",logfile,storefile);
        printf("    logrotated       : move %s to %s.yyyymmdd_HHMMSS\n",logfile,storefile);
        printf("    compress         : compress %s to %s.gz\n",logfile,storefile);
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

      //====== stop THREAD_relocate_buf ==========
      if (ATOM_THREAD_relocate_buf_to_start_run.load()==true)
      {
        deblog((char *)"thread relocate_buf_to_start not stop");
        sem_post(&SEM_relocate_buf);
        //sleep(1);

        T_relocate_buf_to_start=0;
      }
      //====== stop THREAD_relocate_buf ==========

      //======  stop THREAD_parsing_buf ==========
      if (ATOM_THREAD_parsing_buf_run.load()==true)
      {
        deblog((char *)"thread parsing_buf not stop");
        sleep(1);
        ATOM_THREAD_save_run.store(false);
        if (pthread_kill(T_parsing_buf,0)!=ESRCH)
        {
          for (int i=0; i<COUNT_PARALLEL_PARSING; i++)
          {
              if ( ATOM_THREAD_parsing_line_run[i].load() == true )
              {
                if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                  snprintf(msg,255,"run parsing_line [%d]",i);
                deblog(msg);
              }
          }
          deblog((char *)"=== kill thread parsing_buf === start");
          pthread_cancel(T_parsing_buf);
          deblog((char *)"=== kill thread parsing_buf === end");

          //pthread_join(T_parsing_buf,0x00);
          ATOM_THREAD_parsing_buf_run.store(false);
        }
        T_parsing_buf=0;
      }
      else
        deblog((char *)"thread parsing_buf allready stopped");
      //======  stop THREAD_parsing_buf ==========

      //======   check parsing_line  for stop   ==========
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
      //======   check parsing_line  for stop   ==========


      //=========  scan and save all array  =============
      ATOM_THREAD_save_run.store(false);
      ATOM_save_run.store(true);
      deblog((char *)"coordinator:finish save");
      if (DEBUG_LEVEL>3)
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
      //=========  scan and save all array  =============

      //======= relocate_audit ===========
      if (ATOM_relocate_auditid_run.load()==true)
      {
        if (DEBUG_LEVEL>0)
        {
          deblog((char *)"coordinator:!relocate_auditid not stop\n");
        }
        ATOM_start_seq_mem_relocate.store(0);
        ATOM_end_seq_mem_relocate.store(0);
        sem_post(&SEM_relocate_audit);
      }
      //======= relocate_audit ===========

      //======= save before stop ===========
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
      //======= save before stop ===========
      break;
    }
    //========= stop read STDIN ==================

    //==============not porcessed mesg in quiet========

    if (flag_sleep==true)
      sleep(1);
    deblog((char *)".");
    if (DEBUG_DISPLAY==true)
      printf((char *)".\n");
  }


  deblog((char *)"===== finish coordinator =====");
  return NULL;
}

void *F_read_STDIN(void* vbuf)
{
  char    msg[256];
  deblog((char *)"=== thread read_STDIN start ===");
  int     i=0;
  int     n_step=0;
  ssize_t nr;
  char    c_char;
  //char    b_char[512];
  char    *b_char;
  int     len_b_char=0;
  int     size_b_char=DEFAULT_READ_BLOCK_SIZE;
  int     i_line_end=0;
  char*   buf = (char*)vbuf;
  int     coun_line_for_read;
  int     TMP_STAT_read_byte=0;
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;

  b_char=(char *)malloc(sizeof(char) * size_b_char);
  if (!b_char)
  {
    ATOM_STAT_memory_read_block_size.store(0);
    ATOM_STAT_current_read_block_size.store(0);
    deblog((char *)"error:malloc block read STDIN");
    ATOM_THREAD_read_STDIN_run.store(false);
    printf("error:malloc block read STDIN");
    return NULL;
  }

  ATOM_THREAD_read_STDIN_run.store(true);
  ATOM_STAT_memory_read_block_size.store(size_b_char);
  ATOM_STAT_current_read_block_size.store(size_b_char);

  while((len_b_char=read(STDIN_FILENO, b_char, size_b_char)) > 0)
  {
    //======== read block ===============
    for (int i_b_char=0; i_b_char<len_b_char; i_b_char++)
    {
      if (i_b_char>=size_b_char)
      {
        deblog((char *)"error:i el >= size_b_char");
        break;
      }

      buf[i]=b_char[i_b_char];
      TMP_STAT_read_byte++;
      if (buf[i]=='\n' || buf[i]=='\0')
      {
        //=== sync stat=====
        ATOM_STAT_read_byte.fetch_add(TMP_STAT_read_byte);
        ATOM_STAT_read_byte_in_block.store(len_b_char);
        TMP_STAT_read_byte=0;
        //=== sync stat=====
          i_line_end=i;
          ATOM_line_read.fetch_add(1);
          sem_post(&SEM_line_read);
      }

      i++;
      if (ATOM_cmd_stop.load()==true)
      {
          deblog((char *)"cmd stop, read_block STDIN stopped");
          if (i<SIZE_BUF)
            buf[i]='\0';
          else
            buf[i-1]='\0';
          break;
      }

      if (i>=SIZE_BUF)
      {
        if (DEBUG_LEVEL>4)
          deblog((char *)"i>=size_buf");
        ATOM_line_read.store(0);//count string from start buffer
        if (DEBUG_LEVEL>5)
        {
          snprintf(msg,255,"thread read_STDIN over memory buf: last pos %d (i_line_end=%d)",i,i_line_end);
          deblog(msg);
        }

        if (i_line_end==0)
        {
          if (DEBUG_LEVEL>5)
            deblog((char *)"=========> relocate none");
          i=0;
        }
        else
        {
          //====relocate not pasring memory to start==== (T_relocate_memory_to_start)
          if (ATOM_relocate_run.load()==true)
          {
            deblog((char *)"=========> relocate is running");
          }
          ATOM_start_seq_mem_relocate.store(i_line_end+1);
          ATOM_end_seq_mem_relocate.store(i);
          if (DEBUG_LEVEL>4)
          {
            snprintf(msg,255,"seq_mem_relocate[%d][%d]",i_line_end+1,i);
            deblog(msg);
          }
          i=i-(i_line_end+1);
          if (DEBUG_LEVEL>4)
          {
            snprintf(msg,255,"new pos %d buf[i-1]=%x",i,buf[i-1]);
            deblog(msg);
          }

          if ((i<0) || (i>4096))
          {
            deblog((char *)"error position for relocate, reset position");
            ATOM_start_seq_mem_relocate.store(0);
            ATOM_end_seq_mem_relocate.store(0);
            i=0;
            if (DEBUG_LEVEL>8)
              printbuf(buf);
          }
          else
          {
            if (DEBUG_LEVEL>5)
              deblog((char *)"=========> set sem relocate ");
            sem_post(&SEM_relocate_buf);
          }
          //====relocate not pasring memory to start====

        }
      }
    }
    //======== read block ===============

    if (ATOM_cmd_stop.load()==true)
    {
        deblog((char *)"cmd stop, read_STDIN stopped");
        break;
    }
    ATOM_STAT_read_block.fetch_add(1);
    if (resize_size_b_char==true)
    {
      //======= analiz size size_b_char =======
      n_step++;
      if (n_step>4)
      {
        if (ATOM_STAT_read_block.load()>32)
        {
          switch (size_b_char)
          {
            case 64:
                size_b_char=128;
                break;
            case 128:
                size_b_char=256;
                break;
            case 256:
                size_b_char=512;
                break;
            case 512:
                size_b_char=1024;
                break;
            case 1024:
                size_b_char=2048;
                break;
            case 2048:
                size_b_char=4096;
                break;
            case 4096:
                size_b_char=8192;
                break;
            case 8192:
                size_b_char=16384;
                break;
            default:
                size_b_char=32768;
          }
          if (DEBUG_LEVEL>7)
          {
            if (ATOM_STAT_memory_read_block_size.load()!=size_b_char)
            {
              snprintf(msg,255,"+ size_b_char=%d",size_b_char);
              deblog(msg);
            }
          }
        }

          if (ATOM_STAT_read_block.load()<4)
          {
            switch (size_b_char)
            {
              case 16384:
                  size_b_char=8192;
                  break;
              case 8192:
                  size_b_char=4096;
                  break;
              case 4096:
                  size_b_char=2048;
                  break;
              case 2048:
                  size_b_char=1024;
                  break;
              case 1024:
                  size_b_char=512;
                  break;
              case 512:
                  size_b_char=256;
                  break;
              case 256:
                  size_b_char=128;
                  break;
              case 128:
                  size_b_char=64;
                  break;
              default:
                  size_b_char=32;
            }
            if (DEBUG_LEVEL>7)
            {
              if (ATOM_STAT_memory_read_block_size.load()!=size_b_char)
              {
                snprintf(msg,255,"- size_b_char=%d",size_b_char);
                deblog(msg);
              }
            }
          }
        if (ATOM_STAT_current_read_block_size.load()!=size_b_char)
          ATOM_STAT_current_read_block_size.store(size_b_char);

        if (ATOM_STAT_memory_read_block_size.load()!=size_b_char)
        {
          ATOM_STAT_current_read_block_size.store(size_b_char);
          if (size_b_char>ATOM_STAT_memory_read_block_size.load())
          {
            b_char=(char *)realloc(b_char,sizeof(char) * size_b_char);
            if (DEBUG_LEVEL>7)
              deblog((char *)"realloc(b_char +)");
            if (!b_char)
            {
              ATOM_STAT_memory_read_block_size.store(0);
              ATOM_STAT_current_read_block_size.store(0);
              deblog((char *)"error:realloc block read STDIN");
              ATOM_THREAD_read_STDIN_run.store(false);
              printf("error:realloc block read STDIN");
              return NULL;
            }
            ATOM_STAT_memory_read_block_size.store(size_b_char);
          }
          else
          {
            if (reduce_size_b_char==true)
            {
              b_char=(char *)realloc(b_char,sizeof(char) * size_b_char);
              if (DEBUG_LEVEL>7)
                deblog((char *)"realloc(b_char -)");
              if (!b_char)
              {
                ATOM_STAT_memory_read_block_size.store(0);
                ATOM_STAT_current_read_block_size.store(0);
                deblog((char *)"error:realloc block read STDIN");
                ATOM_THREAD_read_STDIN_run.store(false);
                printf("error:realloc block read STDIN");
                return NULL;
              }
              ATOM_STAT_memory_read_block_size.store(size_b_char);
            }
            else
            {
              if (DEBUG_LEVEL>7)
                deblog((char *)"reduce_size_b_char=false, no realloc(b_char)");
            }
          }

        }

        n_step=0;
      }
      //======= analiz size size_b_char ========
    }

  }
  ATOM_line_read.fetch_add(1);
  sem_post(&SEM_line_read);
  ATOM_THREAD_read_STDIN_run.store(false);
  //deblog((char *)"=== thread read_STDIN stop ===");
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
    if ( ATOM_THREAD_read_STDIN_run.load() == false )
    {
      deblog((char *)"=== therad relocate_buf_to_start stop ===");
      break;
    }
    ATOM_relocate_run.store(true);
    if (DEBUG_LEVEL>0)
      deblog((char *)"> relocate buf");

    i_start=ATOM_start_seq_mem_relocate.load();
    i_end=ATOM_end_seq_mem_relocate.load();
    if (i_end>i_start)
    {
      ATOM_relocate_RED_ZONE_start_section.store(i_end-i_start);
      ATOM_relocate_RED_ZONE_end_section.store(i_start);

      for (i=i_start; i < i_end; i++)
      {
        buf[i-i_start]=buf[i];
        buf[i]='\0';
      }
      if (DEBUG_LEVEL>6)
        deblog((char *)"< relocate buf");
      ATOM_relocate_RED_ZONE_start_section.store(0);
      ATOM_relocate_RED_ZONE_end_section.store(0);
    }
    else
    {
      if (DEBUG_LEVEL>6)
        deblog((char *)"error pos for relocate buf star > end");
    }
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
  char  msg[512];
  int i,i_start;
  int i_line_start=0;
	int i_line_end=0;
  int coun_line_for_read=-1;
  int coun_thread_parsing_run;

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0x00);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0x00);

  ATOM_parsing_line_processed.store(0);
  ATOM_THREAD_parsing_buf_run.store(true);
  int count_string_in_buf=0;
  int tr_i;
  sem_wait(&SEM_line_read);
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;
  deblog((char *)"=== thread parsing_buf start ===");


  while(true)
  {
    //protection on null buffer circle
    if (i==0)
    {
      //reset count
      count_string_in_buf=0;
    }

    if (buf[i]=='\n' || buf[i]=='\0')
    {
      count_string_in_buf++;
      buf[i]='\0';


      //if ((i_line_end=='\0') || (i_line_end=='\n'))
        //i_line_start=i_line_end+1;
      //else
      i_line_start=i_line_end;
      i_line_end=i;

      if (i_line_start>i_line_end)
      {
        if (DEBUG_LEVEL>3)
        {
          snprintf(msg,255,"i_line_start=%d > i_line_end=%d",i_line_start,i_line_end);
          deblog(msg);
        }
        i_line_start=0;
      }

      //===cut header [0]===
      if ((buf[i_line_start]=='\0') || (buf[i_line_start]=='\n'))
      {

        for (tr_i=i_line_start; tr_i<i_line_end; tr_i++)
        {
          if ((buf[tr_i]=='\0') || (buf[tr_i]=='\n'))
          {
            buf[tr_i]='\0';
          }
          else
          {
            i_line_start=tr_i;
            break;
          }
        }

      }
      //===cut header [0]===



      //========== parsing line ==================================================
      MTX_parsing_line_read_seq.lock();
      if (DEBUG_LEVEL>7)
      {
        snprintf(msg,255,"parsing line i_line_start=%d i_line_end=%d",i_line_start,i_line_end);
        deblog(msg);
      }
      if (i_line_start!=i_line_end)
      {
        int k;
        for (k=0; k<COUNT_SEQ_MEM_PARSING; k++)
        {
          if (ATOM_end_seq_mem_parsing[k].load()==0)
          {
            if (DEBUG_LEVEL>5)
            {
              snprintf(msg,255,"add seq to array for parsing store seq mem in k el:%d,<%d;%d>",k,i_line_start,i_line_end);
              deblog(msg);
            }
            ATOM_start_seq_mem_parsing[k].store(i_line_start);
            ATOM_end_seq_mem_parsing[k].store(i_line_end);
            break;
          }
        }

        if (k>=COUNT_SEQ_MEM_PARSING)
        {
          ATOM_STAT_raw_auditd_error.fetch_add(1);
          /*snprintf(msg,511,"too many audit events\nCOUNT_SEQ_MEM_PARSING=%d\nk=%d\ni_line_start=%d\ni_line_end=%d\nATOM_save_run=%d\nATOM_THREAD_parsing_line_processing[0]=%d",COUNT_SEQ_MEM_PARSING,k,i_line_start,i_line_end,ATOM_save_run.load(),ATOM_THREAD_parsing_line_processing[0].load());
          save_err(msg);
          printf("error, too many audit events, write audit to stdout\n");*/
        }
      }
      else
      {
        if (DEBUG_LEVEL>0)
        {
          snprintf(msg,255,"skeep add to ATOM_end_seq_mem_parsing (i_line_start=i_line_end)");
          deblog(msg);
        }
      }
      MTX_parsing_line_read_seq.unlock();
      sem_post(&SEM_run_parsing_line);
      //========== parsing line ==================================================

      if (DEBUG_PROFILE==true)
      {
        end_time=(double)(clock())/CLOCKS_PER_SEC;
        exec_time=end_time-start_time;
        if (exec_time>DISPLAY_PROFILE_OVER)
        {
          snprintf(msg,255,"profiling[F_parsing_buf(iteration)]:%f",exec_time);
          deblog(msg);
        }
      }
      sem_wait(&SEM_line_read);
      if (DEBUG_PROFILE==true)
        start_time=(double)(clock())/CLOCKS_PER_SEC;

      if (ATOM_THREAD_read_STDIN_run.load()==false)
      {
        coun_line_for_read=0;
        for (int n=0; n<SIZE_BUF; n++)
        {
          if (buf[n]=='\n')
            coun_line_for_read++;
        }
        if (coun_line_for_read==0)
        {
          deblog((char *)"=== end parsing_buf ===");
          if (DEBUG_LEVEL>8)
            printbuf(buf);
          break;
        }
      }
    }

    i++;
    if (i>=SIZE_BUF)
    {
      i=0;
      i_line_start=0;
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
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;
  int n_thread=ATOM_run_parsing_line.fetch_add(1);
  ATOM_THREAD_parsing_line_run[n_thread].store(true);
  if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    snprintf(msg,255,"=== start thread parsing [%d] ===",n_thread);
  deblog(msg);
  ATOM_THREAD_start_seq_mem[n_thread].store(0);
  ATOM_THREAD_end_seq_mem[n_thread].store(0);

  while(true)
  {
    ATOM_THREAD_parsing_line_processing[n_thread].store(false);
    if (DEBUG_PROFILE==true)
    {
      end_time=(double)(clock())/CLOCKS_PER_SEC;
      exec_time=end_time-start_time;
      if (exec_time>DISPLAY_PROFILE_OVER_F_parsing_line)
      {
        snprintf(msg,255,"profiling[F_parsing_line %d (iteration)]:%f",n_thread,exec_time);
        deblog(msg);
      }
    }
    sem_wait(&SEM_run_parsing_line);
    if (DEBUG_PROFILE==true)
      start_time=(double)(clock())/CLOCKS_PER_SEC;
    ATOM_THREAD_parsing_line_processing[n_thread].store(true);
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
      F_parsing_string_to_auditid(buf,i_line_start,i_line_end,array_audit,n_thread);
      ATOM_line_read.fetch_sub(1);
    }

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
    deblog((char *)"COUNT_STAT_UID is small");
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
  double exec_time,start_time,end_time;
  int array_count_save;
  struct tm *local_tm;
  struct tm  l_tm;

  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;

  s_audit* f_array = (s_audit*)varray_audit;
  ATOM_THREAD_save_run.store(true);
  deblog((char *)"=== thread save to file start ===");

  int pid=getpid();
  int ppid=getppid();

  //snprintf(msg,255,"|pid=%u ppid=%u",pid,ppid);
  //deblog(msg);

  while (1)
  {
    //===== adminfile cmd storefile ====
    if (ATOM_cmd_logrotate.load()==true)
    {
      deblog((char *)"logrotate start");
      rename(logfile,storefile);
      ATOM_cmd_logrotate.store(false);
      deblog((char *)"logrotate end");

    }
    if (ATOM_cmd_logrotated.load()==true)
    {
      deblog((char *)"logrotated start");
      char storefiled_extdate[256];
      //====curent time====
      struct tm *local_tm;
      struct tm  l_tm;
      time_t t_shtamp;
      t_shtamp = time(NULL);
      local_tm=localtime(&t_shtamp);
      l_tm=*local_tm;
      snprintf(storefiled_extdate,255,"%s.%04d%02d%02d_%02d%02d%02d",storefile,l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec);
      rename(logfile,storefiled_extdate);
      ATOM_cmd_logrotated.store(false);
      deblog((char *)"logrotated end");

    }
    if (ATOM_cmd_logrotategz.load()==true)
    {
      deblog((char *)"logrotatgz start");
      rename(logfile,uncompressfile);
      //set detach thread compress
      pthread_attr_t threadAttr;
      pthread_attr_init(&threadAttr);
      pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
      pthread_create(&T_compress_file,&threadAttr,F_compress_file,NULL);

      ATOM_cmd_logrotategz.store(false);
      deblog((char *)"logrotatgz end");

    }
    //===== adminfile cmd storefile ====
    //====================wait=========================================
    if (DEBUG_PROFILE==true)
    {
      end_time=(double)(clock())/CLOCKS_PER_SEC;
      exec_time=end_time-start_time;
      snprintf(msg,255,"profiling[F_save_file(iteration)]:%f",exec_time);
      deblog(msg);
    }
    if (DEBUG_LEVEL>4)
      deblog((char *)"sem wait:SEM_save");
    sem_wait(&SEM_save);
    if (DEBUG_PROFILE==true)
      start_time=(double)(clock())/CLOCKS_PER_SEC;
    //====================wait=========================================
    array_count_save=ATOM_save_count.load();
    //== start save ===
    ATOM_save_run.store(true);
    if (FILTER==ON)
    {
      if (DEBUG_LEVEL>1)
        deblog((char *)"==== > filtering");
      filtering(f_array,array_count_save);
    }
    if (DEBUG_LEVEL>0)
      if ((DEBUG==true) || (DEBUG_DISPLAY==true))
      {
        snprintf(msg,255,"save_to_file:count=%d",array_count_save);
        deblog(msg);
      }
    if (DEBUG_LEVEL>1)
      deblog((char *)"open logfile");
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

            if (DEBUG_LEVEL>1)
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
            else
            {
              if (f_array[i].syscall>=0)
                fprintf(f_logfile,"syscall=\"%d\" ",f_array[i].syscall);
            }
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
            if (f_array[i].items_isset==true)
              fprintf(f_logfile,"items=\"%d\" ",f_array[i].items);
            if (f_array[i].exit_isset==true)
              fprintf(f_logfile,"exit=\"%d\" ",f_array[i].exit);
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
          memset((&f_array[i]),0,sizeof(s_audit));
          //clear_array_audit_id(f_array,i);
        }
      }
      if (DEBUG_LEVEL>1)
        deblog((char *)"close logfile");
      fclose(f_logfile);
      ATOM_save_step.fetch_add(1);
    }
    else
      printf("error save file %s\n",logfile);


    if (ATOM_THREAD_save_run.load()==false)
      break;
    // lock array and remove not save array to start array


    //-------- set val for relocate ----------------
    //count el in array start with array_count_save
    int max_array_count=count_array_audit(array_count_save);

    ATOM_start_audit_relocate.store(array_count_save);
    ATOM_end_audit_relocate.store(max_array_count);
    if (DEBUG_LEVEL>2)
      deblog((char *)"end step save, run relocate");

    sem_post(&SEM_relocate_audit);
    // unlock all

    if (DEBUG_LEVEL>3)
    {
    	  snprintf(msg,255,"ATOM_start_audit_relocate=%d ATOM_end_audit_relocate=%d",array_count_save,max_array_count);
    	  deblog(msg);
    }
    //-------- set val for relocate ----------------
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
  char msg[256];
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;
  s_audit* f_array = (s_audit*)varray_audit;
  ATOM_relocate_auditid_run.store(true);
  while(true)
  {
    if (DEBUG_PROFILE==true)
    {
      end_time=(double)(clock())/CLOCKS_PER_SEC;
      exec_time=end_time-start_time;
      if (exec_time>DISPLAY_PROFILE_OVER)
      {
        snprintf(msg,255,"profiling[F_relocate_audit(iteration)]:%f",exec_time);
        deblog(msg);
      }
    }
    sem_wait(&SEM_relocate_audit);
    if (DEBUG_PROFILE==true)
      start_time=(double)(clock())/CLOCKS_PER_SEC;
    if (ATOM_THREAD_parsing_buf_run.load()==false)
      break;
    ATOM_relocate_processed.store(true);

    int start_i=ATOM_start_audit_relocate.load();
    int end_i = ATOM_end_audit_relocate.load();
    ATOM_post_relocate.store(end_i-start_i);
    //count_relocate_auditid=ATOM_relocate_auditid.load();
    if (DEBUG_LEVEL>2)
      deblog((char *)"==== relocate f_array ====");
    int delta_first_free=0;
    for (int i=start_i; i<end_i; i++)
    {
      //el already use
      if (f_array[i-start_i+delta_first_free].auditid!=0)
      {
        //search first free el
        if ((i-start_i+delta_first_free)<SAVE_AUDIT)
        {
          for (int j=(i-start_i+delta_first_free);j<SAVE_AUDIT;j++)
          {
            if (f_array[j].auditid==0)
            {
              delta_first_free=j-(i-start_i);
              //move end relocate
              ATOM_end_audit_relocate.store(end_i+delta_first_free);

              if (DEBUG_LEVEL>2)
              {
                if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                {
                  snprintf(msg,255,"  relocate: f_array[%d] already use, step to %d",(i-start_i+delta_first_free),delta_first_free);
                  deblog(msg);
                }
              }
              break;
            }
          }
        }
        else
        {
          deblog((char *)"  relocate: error search free el in f_array");
        }
      }

      if (f_array[i].auditid!=0)
      {
        if (DEBUG_LEVEL>1)
        {
          if ((DEBUG==true) || (DEBUG_DISPLAY==true))
          {
            snprintf(msg,255,"  relocate f_array[%d].auditid(%d) ==> f_array[%d].auditid",i,f_array[i].auditid,(i-start_i+delta_first_free));
            deblog(msg);
          }
        }
        //f_array[i-start_i].auditid=f_array[i].auditid;
        memcpy((&f_array[i-start_i+delta_first_free]),(&f_array[i]),sizeof(s_audit));
        // ===== clear ======
        memset((&f_array[i]),0,sizeof(s_audit));
        //clear_array_audit_id(f_array,i);

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
    fprintf(f_stat,"memory size read block:%d\n",ATOM_STAT_memory_read_block_size.load());
    fprintf(f_stat,"current size read block:%d\n",ATOM_STAT_current_read_block_size.load());
    if (ATOM_STAT_read_byte_in_block.load()>0)
      fprintf(f_stat,"read block in:%d\n",ATOM_STAT_read_byte_in_block.load());
    fprintf(f_stat,"read block:%d\n",ATOM_STAT_read_block.load());


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
    fprintf(f_stat,"\n");
    if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    {
      fprintf(f_stat,"==== DEBUG ====\n");
      fprintf(f_stat,"DEBUG_LEVEL:%d\n",DEBUG_LEVEL);
      fprintf(f_stat,"==== DEBUG ====\n");
    }
    if (DEBUG_PROFILE==true)
    {
      fprintf(f_stat,"==== PROFILING ====\n");
      fprintf(f_stat,"DISPLAY PROFILE OVER:%f\n",DISPLAY_PROFILE_OVER);
      fprintf(f_stat,"==== PROFILING ====\n");
    }
    if (FILTER==ON)
    {
      if (ATOM_count_ignore_key.load()>0)
      {
        fprintf(f_stat,"filtering on one record:%d\n",ATOM_filtering.load());
        fprintf(f_stat,"filtering:%d\n",ATOM_STAT_filtering.load());
      }
    }
    fprintf(f_stat,"filtering pid and ppid:%d\n",ATOM_filtering_pid.load());
    fprintf(f_stat,"\n");
    fprintf(f_stat,"save line to log:%d\n",ATOM_save_line.load());
    fprintf(f_stat,"\n");
    fprintf(f_stat,"save step:%d\n",ATOM_save_step.load());
    fprintf(f_stat,"\n");
    fprintf(f_stat,"raw audit error:%d\n",ATOM_STAT_raw_auditd_error.load());
    fprintf(f_stat,"audit error:%d\n",ATOM_STAT_auditd_error.load());
    if (ATOM_STAT_leak.load()>0)
      fprintf(f_stat,"leak:%d\n",ATOM_STAT_leak.load());
    fprintf(f_stat,"\n");
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
  ATOM_STAT_read_block.store(0);
  ATOM_STAT_line_auditd.store(0);
  ATOM_STAT_filtering.store(0);
  ATOM_STAT_raw_auditd_error.store(0);
  ATOM_STAT_auditd_error.store(0);
  ATOM_filtering_pid.store(0);
  ATOM_save_line.store(0);
  ATOM_save_step.store(0);
  clear_STAT_UID();
  //========== stat file ===========
}

void print_stat()
{
  write_stat(f_stat);
}

void *F_stat(void*)
{
  deblog((char *)"=== thread stat start ===");
  write_stat(f_stat);
  while (true)
  {sleep(1);
    for (int t=0;t<STAT_INTERVAL;t++)
    {
      if (ATOM_THREAD_read_STDIN_run.load()==true)
        sleep(1);
    }

    if (ATOM_THREAD_read_STDIN_run.load()==false)
    {
      ATOM_STAT_read_byte.store(0);
      ATOM_STAT_read_block.store(0);
      ATOM_STAT_memory_read_block_size.store(0);
      ATOM_STAT_current_read_block_size.store(0);
      ATOM_STAT_read_byte_in_block.store(0);
      ATOM_STAT_line_auditd.store(0);
      ATOM_STAT_filtering.store(0);
      ATOM_STAT_raw_auditd_error.store(0);
      ATOM_STAT_auditd_error.store(0);
      ATOM_filtering_pid.store(0);
      ATOM_save_line.store(0);
      ATOM_save_step.store(0);

      write_stat(f_stat);

      break;
    }
    else
    {
      save_deblog();
      write_stat(f_stat);
    }
  }
  deblog((char *)"=== thread end stat ===");
  return NULL;
}

void *F_compress_file(void* vbuf)
{
  FILE       *fp_src;
  FILE       *fp_dst;

  char compressfile_extdate[256];
  //====curent time====
  struct tm *local_tm;
  struct tm  l_tm;
  time_t t_shtamp;
  t_shtamp = time(NULL);
  local_tm=localtime(&t_shtamp);
  l_tm=*local_tm;
  snprintf(compressfile_extdate,255,"%s.%04d%02d%02d_%02d%02d%02d.gzip",compressfile,l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec);

  //compress a file
  //fp_src = fopen(uncompressfile,"r");
  //fp_dst = fopen(compressfile_extdate,"w");
  //int ret = f_zlib(fp_src,fp_dst,ZLEVEL);
  int ret = f_zlib((char*)uncompressfile,(char*)compressfile_extdate,ZLEVEL);
  return NULL;
}

int f_zlib(char *ufile, char *cfile, int level)
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    ATOM_compress_gz.store(true);
    deblog((char *)"compress start");
    FILE *source = fopen(ufile,"r");
    FILE *dest = fopen(cfile,"w");

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    //ret = deflateInit(&strm, level);
    ret = deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
    {
      ATOM_compress_gz.store(false);
      deblog((char *)"error compress (deflateInit2)");
      //fclose(dest);
      //fclose(source);
      return ret;
    }
    /* compress until end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            ATOM_compress_gz.store(false);
            deblog((char *)"error compress: read");
            fclose(dest);
            fclose(source);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;
        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                ATOM_compress_gz.store(false);
                deblog((char *)"error compress: write");
                fclose(dest);
                fclose(source);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */
        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */
    /* clean up and return */
    (void)deflateEnd(&strm);
    deblog((char *)"compress finish");
    fclose(dest);
    fclose(source);
    deblog((char *)"remove uncompresed file");
    remove(ufile);
    ATOM_compress_gz.store(false);
    return Z_OK;
}

int f_zlib_decompress(char *cfile, char *ufile)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    FILE *source = fopen(cfile,"r");
    FILE *dest = fopen(ufile,"w");

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;
    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;
        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);
    /* clean up and return */
    (void)inflateEnd(&strm);
    fclose(dest);
    fclose(source);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
