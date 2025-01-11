#include "audisp-simplify-c-thread.h"
#include "audisp-simplify-c-str-function.h"
//#include "audisp-simplify-c-filter.h"

//FILE *f_debug;
char *msg;
mutex MTX_deblog;
atomic_int  ATOM_i_msg=0;
atomic_bool ATOM_save_debug_run=false;
atomic_int  ATOM_prev_delta_strpos_istart=0;
atomic_bool ATOM_enable_scan_extend_UID=true;

void save_deblog()
{
  if (DEBUG==true)
  {
    if (ATOM_save_debug_run.load()==false)
    {
      ATOM_save_debug_run.store(true);
      if ((f_debug=fopen(deblogfile,"a"))!=NULL)
      {
        fprintf(f_debug,"%s",msg);
        fclose(f_debug);
        ATOM_i_msg.store(0);
        ATOM_save_debug_run.store(false);
      }
      else
        printf("error save debug file %s\n",deblogfile);
    }
  }
}

void deblog(char *inmsg)
{
  if (DEBUG_DISPLAY==true)
  {
    double seconds=(double)(clock())/CLOCKS_PER_SEC;
    printf("%f: %s\n",seconds,inmsg);
  }
  if (DEBUG==true)
  {
    char char_sec[20];
		double seconds=(double)(clock())/CLOCKS_PER_SEC;
    snprintf(char_sec,19,"%f: ",seconds);
    int lensec=strlen(char_sec);
    int i_msg=ATOM_i_msg.load();
    int lenmsg=strlen(inmsg);
    //save to file
    if ((i_msg+lensec+lenmsg+1)>=SIZE_MSG)
    {
      ATOM_i_msg.store(0);
      if (ATOM_save_debug_run.load()==false)
      {
        ATOM_save_debug_run.store(true);
        if ((f_debug=fopen(deblogfile,"a"))!=NULL)
        {
          //fprintf(f_debug,"[%f]:%s\n",seconds,msg);
          fprintf(f_debug,"%s",msg);
          fclose(f_debug);
        }
        else
          printf("error open debug file %s\n",deblogfile);

        i_msg=0;
        ATOM_i_msg.store(0);
        ATOM_save_debug_run.store(false);
      }
      else
        printf("debug already saved: drop msg(%s)\n",inmsg);

    }
    MTX_deblog.lock();
    i_msg=ATOM_i_msg.load();
    for (int i=i_msg; i<(i_msg+lensec); i++)
      msg[i]=char_sec[i-i_msg];
    i_msg=i_msg+lensec;
    for (int i=i_msg; i<(i_msg+lenmsg+1); i++)
      msg[i]=inmsg[i-i_msg];
    i_msg=i_msg+lenmsg;
    msg[i_msg]='\n';
    i_msg++;
    ATOM_i_msg.store(i_msg);
    MTX_deblog.unlock();
  }
}

void printbuf(char *buf)
{
  if (DEBUG_DISPLAY==true)
  {
    printf("==================== buf ======================\n");
    int pos_left=210;
    int i_pos=0;
    int i_start=0;
    for (int i=0; i<SIZE_BUF; i++)
    {
      if (buf[i]=='\n')
      {
        i_pos=0;
        printf("   [%d]",i);
        for (int n_thread=0; n_thread<=COUNT_PARALLEL_PARSING; n_thread++)
        {
          if ((ATOM_THREAD_start_seq_mem[n_thread].load()>=i_start) && (ATOM_THREAD_end_seq_mem[n_thread].load()<=i) && (ATOM_THREAD_end_seq_mem[n_thread].load()!=0))
          printf(">t%d:%d-%d",n_thread,ATOM_THREAD_start_seq_mem[n_thread].load(),ATOM_THREAD_end_seq_mem[n_thread].load());
        }
        i_start=i+1;
      }
      if (buf[i]=='\0')
      printf(".");
      else
      printf("%c",buf[i]);
      i_pos++;

      if (i_pos>pos_left)
      {
        i_pos=0;
        printf("  [%d]",i);
        for (int n_thread=0; n_thread<=COUNT_PARALLEL_PARSING; n_thread++)
        {
          if ((ATOM_THREAD_start_seq_mem[n_thread].load()>=i_start) && (ATOM_THREAD_end_seq_mem[n_thread].load()<=i) && (ATOM_THREAD_end_seq_mem[n_thread].load()!=0))
          printf(">t%d:%d-%d",n_thread,ATOM_THREAD_start_seq_mem[n_thread].load(),ATOM_THREAD_end_seq_mem[n_thread].load());
        }
        printf("\n");
        i_start=i+1;
      }
    }
    printf("\n==================== buf ======================\n");
  }

  if ((DEBUG==true) && (DEBUG_LEVEL>2))
  {
    FILE *f_debug;
    if ((f_debug=fopen(deblogfile,"a"))!=NULL)
    {
      fprintf(f_debug,"==================== buf ======================\n");
      int pos_left=210;
      int i_pos=0;
      int i_start=0;
      for (int i=0; i<SIZE_BUF; i++)
      {
        if (buf[i]=='\n')
        {
          i_pos=0;
          fprintf(f_debug,"   [%d]",i);
          for (int n_thread=0; n_thread<=COUNT_PARALLEL_PARSING; n_thread++)
          {
            if ((ATOM_THREAD_start_seq_mem[n_thread].load()>=i_start) && (ATOM_THREAD_end_seq_mem[n_thread].load()<=i) && (ATOM_THREAD_end_seq_mem[n_thread].load()!=0))
            fprintf(f_debug,">t%d:%d-%d",n_thread,ATOM_THREAD_start_seq_mem[n_thread].load(),ATOM_THREAD_end_seq_mem[n_thread].load());
          }
          i_start=i+1;
        }
        if (buf[i]=='\0')
        fprintf(f_debug,".");
        else
        fprintf(f_debug,"%c",buf[i]);
        i_pos++;

        if (i_pos>pos_left)
        {
          i_pos=0;
          fprintf(f_debug,"  [%d]",i);
          for (int n_thread=0; n_thread<=COUNT_PARALLEL_PARSING; n_thread++)
          {
            if ((ATOM_THREAD_start_seq_mem[n_thread].load()>=i_start) && (ATOM_THREAD_end_seq_mem[n_thread].load()<=i) && (ATOM_THREAD_end_seq_mem[n_thread].load()!=0))
            fprintf(f_debug,">t%d:%d-%d",n_thread,ATOM_THREAD_start_seq_mem[n_thread].load(),ATOM_THREAD_end_seq_mem[n_thread].load());
          }
          fprintf(f_debug,"\n");
          i_start=i+1;
        }
      }
      fprintf(f_debug,"\n==================== buf ======================\n");
      fclose(f_debug);
    }
    else
      printf("error open debug file %s\n",deblogfile);
  }
}

void debbuf(int istart,int iend,char *buf)
{
  if (DEBUG_DISPLAY==true)
  {
    printf("(%d)[%d][%d]",ATOM_line_read.load(),istart,iend);
    for (int i=istart; i<iend; i++)
      printf("%c",buf[i]);
    printf("\n");
  }

  if ((DEBUG==true) && (DEBUG_LEVEL==3))
  {
      FILE *f_debug;
      if ((f_debug=fopen(deblogfile,"a"))!=NULL)
      {
        fprintf(f_debug,"[%d][%d]",istart,iend);
        for (int i=istart; i<iend; i++)
          fprintf(f_debug,"%c",buf[i]);
        fprintf(f_debug,"\n");
        fclose(f_debug);
      }
      else
        printf("error open debug file %s\n",deblogfile);
  }
}

void print_ALL_audit()
{
  if (DEBUG_DISPLAY==true)
  {
    printf("=================== audit ====================\n");
    for (int i=0; i<SIZE_AUDIT; i++)
    {
      if (array_audit[i].auditid!=0)
        printf("array_audit[%d].auditid=%d pid_isset=%d pid=%d names=%s\n",i,array_audit[i].auditid,array_audit[i].pid_isset,array_audit[i].pid,array_audit[i].names);
      //if (array_audit[i].auditid==0)
        //break;
    }
    printf("=================== audit ====================\n");
  }
}

void print_audit(s_audit *f_array,int auditid)
{
  char msg[256];
  struct tm *local_tm;
  struct tm  l_tm;
  if (f_array[auditid].pid != pid && f_array[auditid].ppid != ppid)
  {
    // === date time ====
    local_tm=localtime(&f_array[auditid].t_shtamp);
    l_tm=*local_tm;
    printf("%04d-%02d-%02d %02d:%02d:%02d.%i ",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec,f_array[auditid].t_mls);
    printf("auditid=\"%d\" ",f_array[auditid].auditid);


    printf("date=\"%04d-%02d-%02d\" ",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday);
    printf("time=\"%02d:%02d:%02d.%i\" ",l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec,f_array[auditid].t_mls);


    if (f_array[auditid].auid_isset==true)
    {
      printf("auid=\"%u\" ",f_array[auditid].auid);
      printf("auid_user=\"%s\" ",f_array[auditid].auid_user);
    }
    //=====================================13
    if (f_array[auditid].uid_isset==true)
    {
      printf("uid=\"%u\" ",f_array[auditid].uid);
      printf("uid_user=\"%s\" ",f_array[auditid].uid_user);
    }
    if (f_array[auditid].euid_isset==true)
    {
      printf("euid=\"%u\" ",f_array[auditid].euid);
      if (strlen(f_array[auditid].euid_user)==0)
        uidtouser(f_array[auditid].euid_user,f_array[auditid].euid);
      printf("euid_user=\"%s\" ",f_array[auditid].euid_user);
    }
    if (f_array[auditid].suid_isset==true)
    {
      printf("suid=\"%u\" ",f_array[auditid].suid);
      if (strlen(f_array[auditid].suid_user)==0)
        uidtouser(f_array[auditid].suid_user,f_array[auditid].suid);
      printf("suid_user=\"%s\" ",f_array[auditid].suid_user);
    }
    if (f_array[auditid].fsuid_isset==true)
    {
      printf("fsuid=\"%u\" ",f_array[auditid].fsuid);
      if (strlen(f_array[auditid].fsuid_user)==0)
        uidtouser(f_array[auditid].fsuid_user,f_array[auditid].fsuid);
      printf("fsuid_user=\"%s\" ",f_array[auditid].fsuid_user);
    }
    if (f_array[auditid].ouid_isset==true)
    {
      printf("ouid=\"%u\" ",f_array[auditid].ouid);
      if (strlen(f_array[auditid].ouid_user)==0)
        uidtouser(f_array[auditid].ouid_user,f_array[auditid].ouid);
      printf("ouid_user=\"%s\" ",f_array[auditid].ouid_user);
    }
    if (f_array[auditid].agid_isset==true)
    {
      printf("agid=\"%u\" ",f_array[auditid].agid);
      if (strlen(f_array[auditid].agid_group)==0)
        gidtogroup(f_array[auditid].agid_group,f_array[auditid].agid);
      printf("agid_group=\"%s\" ",f_array[auditid].agid_group);
    }
    if (f_array[auditid].agid_isset==true)
    {
      printf("gid=\"%u\" ",f_array[auditid].gid);
      if (strlen(f_array[auditid].gid_group)==0)
        gidtogroup(f_array[auditid].gid_group,f_array[auditid].gid);
      printf("gid_group=\"%s\" ",f_array[auditid].gid_group);
    }
    if (f_array[auditid].egid_isset==true)
    {
      printf("egid=\"%u\" ",f_array[auditid].egid);
      if (strlen(f_array[auditid].egid_group)==0)
        gidtogroup(f_array[auditid].egid_group,f_array[auditid].egid);
      printf("egid_group=\"%s\" ",f_array[auditid].egid_group);
    }
    if (f_array[auditid].sgid_isset==true)
    {
      printf("sgid=\"%u\" ",f_array[auditid].sgid);
      if (strlen(f_array[auditid].sgid_group)==0)
        gidtogroup(f_array[auditid].sgid_group,f_array[auditid].sgid);
      printf("sgid_group=\"%s\" ",f_array[auditid].sgid_group);
    }
    if (f_array[auditid].fsgid_isset==true)
    {
      printf("fsgid=\"%u\" ",f_array[auditid].fsgid);
      if (strlen(f_array[auditid].fsgid_group)==0)
        gidtogroup(f_array[auditid].fsgid_group,f_array[auditid].fsgid);
      printf("fsgid_group=\"%s\" ",f_array[auditid].fsgid_group);
    }
    if (f_array[auditid].ogid_isset==true)
    {
      printf("ogid=\"%u\" ",f_array[auditid].ogid);
      if (strlen(f_array[auditid].ogid_group)==0)
        gidtogroup(f_array[auditid].ogid_group,f_array[auditid].ogid);
      printf("ogid_group=\"%s\" ",f_array[auditid].ogid_group);
    }

    if (strlen(f_array[auditid].addr)>0)
      printf("addr=\"%s\" ",f_array[auditid].addr);
    if (strlen(f_array[auditid].exe)>0)
      printf("exe=\"%s\" ",f_array[auditid].exe);
    if (strlen(f_array[auditid].hostname)>0)
      printf("hostname=\"%s\" ",f_array[auditid].hostname);
    if (strlen(f_array[auditid].key)>0)
      printf("key=\"%s\" ",f_array[auditid].key);

    if (strlen(f_array[auditid].newcontext)>0)
      printf("newcontext=\"%s\" ",f_array[auditid].newcontext);
    if (strlen(f_array[auditid].oldcontext)>0)
      printf("oldcontext=\"%s\" ",f_array[auditid].oldcontext);
    if (f_array[auditid].pid_isset==true)
      printf("pid=\"%u\" ",f_array[auditid].pid);
    if (f_array[auditid].ppid_isset==true)
      printf("ppid=\"%u\" ",f_array[auditid].ppid);
    if (strlen(f_array[auditid].res)>0)
      printf("res=\"%s\" ",f_array[auditid].res);
    if (strlen(f_array[auditid].seresult)>0)
      printf("seresult=\"%s\" ",f_array[auditid].seresult);
    if (f_array[auditid].ses_isset==true)
      printf("ses=\"%u\" ",f_array[auditid].ses);
    if (strlen(f_array[auditid].subj)>0)
      printf("subj=\"%s\" ",f_array[auditid].subj);
    if (strlen(f_array[auditid].terminal)>0)
      printf("terminal=\"%s\" ",f_array[auditid].terminal);
    if (strlen(f_array[auditid].tty)>0)
      printf("tty=\"%s\" ",f_array[auditid].tty);
    if (strlen(f_array[auditid].direction)>0)
      printf("direction=\"%s\" ",f_array[auditid].direction);
    if (strlen(f_array[auditid].cipher)>0)
      printf("cipher=\"%s\" ",f_array[auditid].cipher);
    if (strlen(f_array[auditid].ksize)>0)
      printf("ksize=\"%s\" ",f_array[auditid].ksize);
    if (strlen(f_array[auditid].mac)>0)
      printf("mac=\"%s\" ",f_array[auditid].mac);
    if (strlen(f_array[auditid].pfs)>0)
      printf("pfs=\"%s\" ",f_array[auditid].pfs);
    if (strlen(f_array[auditid].spid)>0)
      printf("spid=\"%s\" ",f_array[auditid].spid);
    if (strlen(f_array[auditid].laddr)>0)
      printf("laddr=\"%s\" ",f_array[auditid].laddr);
    if (strlen(f_array[auditid].lport)>0)
      printf("lport=\"%s\" ",f_array[auditid].lport);

    if (strlen(f_array[auditid].SYSCALL)>0)
      printf("syscall=\"%s\" ",f_array[auditid].SYSCALL);
    if (f_array[auditid].syscall>=0)
      printf("syscall=\"%d\" ",f_array[auditid].syscall);

    if (strlen(f_array[auditid].op)>0)
      printf("op=\"%s\" ",f_array[auditid].op);
    if (strlen(f_array[auditid].vm)>0)
      printf("vm=\"%s\" ",f_array[auditid].vm);
    if (strlen(f_array[auditid].cwd)>0)
      printf("cwd=\"%s\" ",f_array[auditid].cwd);
    /*if (strlen(f_array[auditid].cmd)>0)
      printf("cmd=\"%s\" ",f_array[auditid].cmd);*/
    if (strlen(f_array[auditid].proctitle)>0)
      printf("proctitle=\"%s\" ",f_array[auditid].proctitle);

    if (strlen(f_array[auditid].errcode)>0)
      printf("errcode=\"%s\" ",f_array[auditid].errcode);
    if (strlen(f_array[auditid].errdesc)>0)
      printf("errdesc=\"%s\" ",f_array[auditid].errdesc);
    //if (strlen(f_array[auditid].saddr)>0)
      //printf("saddr=\"%s\" ",f_array[auditid].saddr);
    if (strlen(f_array[auditid].res_saddr)>0)
      printf("saddr=\"%s\" ",f_array[auditid].res_saddr);
    if (strlen(f_array[auditid].avc)>0)
      printf("avc=\"%s\" ",f_array[auditid].avc);
    if (strlen(f_array[auditid].types)>0)
      printf("types=\"%s\" ",f_array[auditid].types);
    if (strlen(f_array[auditid].names)>0)
      printf("names=\"%s\" ",f_array[auditid].names);
    if (strlen(f_array[auditid].acct)>0)
      printf("acct=\"%s\" ",f_array[auditid].acct);
    if (strlen(f_array[auditid].unit)>0)
      printf("unit=\"%s\" ",f_array[auditid].unit);
    if (strlen(f_array[auditid].success)>0)
      printf("success=\"%s\" ",f_array[auditid].success);

    if (strlen(f_array[auditid].command)>0)
      printf("command=\"%s\" ",f_array[auditid].command);

    //syscall
    if (strlen(f_array[auditid].args)>0)
      printf("an=\"%s\" ",f_array[auditid].args);


    //=====================================13
    printf("\n");
  }
}

void clear_buf(int istart,int iend,char *buf)
{
  for (int i=istart; i<iend; i++)
    buf[i]='\0';
}

int strpos_istart(char *bufstr,int start_i,int end_i,char *searchstr)
{
  int indx=-1;
  //int n_max=strlen(bufstr);

	int i_start=start_i+ATOM_prev_delta_strpos_istart.load();
	/*if (DEBUG)
	{
		snprintf(msg,255,"function strpos_istart: searchstr=%s start_i=%d, prev_delta_strpos_istart=%d, end_i=%d",searchstr,start_i,prev_delta_strpos_istart,end_i);
		deblog(msg);
	}*/
	/*if (i_start>n_max)
	{
		if (DEBUG)
		{
			snprintf(msg,255,"function strpos_istart: pre pos > len buf, i_start=%d, prev_delta_strpos_istart=%d",i_start,prev_delta_strpos_istart);
			deblog(msg);
		}

		prev_delta_strpos_istart=0;
		i_start=start_i;
	}*/
  /*if (n_max<=strlen(searchstr))
  {
    return -1;
  }
  if (n_max>size_buf)
    n_max=size_buf;*/
  int i;
  for (i = i_start; i < end_i; i++)
  {
    if (bufstr[i]==searchstr[0])
    {
      indx=i;
      for (int j=0; j<strlen(searchstr); j++)
        if (bufstr[i+j]!=searchstr[j])
          indx=-1;
      if (indx>=0)
      {
				ATOM_prev_delta_strpos_istart.store(indx-start_i);
        return indx;
      }
    }
  }
	//not find pos
	if (ATOM_prev_delta_strpos_istart.load()!=0)
	{
		/*if (DEBUG==true)
		{
			snprintf(msg,512,"function strpos_istart: not find searchstr=%s start pos=%d, try find start pos=0",searchstr,prev_delta_strpos_istart);
			deblog(msg);
		}*/
		//prev_delta_strpos_istart=0;
		i_start=start_i;
		for (i = i_start; i < end_i; i++)
	  {
	    if (bufstr[i]==searchstr[0])
	    {
	      indx=i;
	      for (int j=0; j<strlen(searchstr); j++)
	        if (bufstr[i+j]!=searchstr[j])
	          indx=-1;
	      if (indx>=0)
	      {
					ATOM_prev_delta_strpos_istart.store(indx-start_i);
	        return indx;
	      }
	    }
			if (i>(start_i+ATOM_prev_delta_strpos_istart.load()))
			{
				//deblog("function strpos_istart: no not find in pos start_i to start_i+ATOM_prev_delta_strpos_istart.load()");
				return false;
			}
	  }
	}
  return indx;
}

int copy_val_istart(char *val, char *bufstr, int start_i, int end_i, char *filter, char stop_char,int max_char,int prev_delta_pos_find_val)
{
  char msg[256];
  /*deblog((char *)"===== function copy_val_istart ====== ");
  snprintf(msg,255,"filter %s stop_char[%c] start_i=%d end_i=%d max_char=%d prev_delta_pos_find_val=%d",filter,stop_char,start_i,end_i,max_char,prev_delta_pos_find_val);
	deblog(msg);
  debbuf(start_i,end_i,bufstr);*/
  val[0]='\0';
  int indx=-1;
  if (strlen(filter)<=2)
  {
    //deblog("function copy_val_istart:filter is short\n");
    return -1;
  }

  if (((start_i+prev_delta_pos_find_val+strlen(filter))>end_i) || (prev_delta_pos_find_val<0))
    prev_delta_pos_find_val=0;


  int i_start=start_i+prev_delta_pos_find_val;
  int i_end=end_i;
  //====== prev_delta_pos_find_val ======
  int i;
  for (i = i_start; i < i_end; i++)
  {
    bool find_char=false;
		if (bufstr[i]=='\n' || bufstr[i]=='\0')
		{
			return -1;
		}
    if (bufstr[i]==filter[0])
      find_char=true;
    else
    {
      if ((filter[0]==' ') && (bufstr[i]==0x1d))
        find_char=true;
      else
        find_char=false;
    }
    if (find_char==true)
    {
      //===============comparison filter and text=================
      //comparison filter and text
      indx=i;
      int j;
      int j_start;
      if ((filter[0]==' ') && (bufstr[indx]==0x1d))
        j_start=1;
      else
        j_start=0;

      for (j=j_start; j<(strlen(filter)); j++)
      {
        if (bufstr[i+j]!=filter[j])
        {
          indx=-1;
          break;
        }
      }

      if (indx>=0)
      {
        for (int k=indx+j; k<(indx+j+max_char); k++)
        {
          //
          if (k>=end_i)
          {
            val[0]='\0';
            return -1;
          }
          val[k-indx-j]=bufstr[k];
          if (stop_char==' ')
          {
            if ((val[k-indx-j]==' ') || (val[k-indx-j]=='\0') || (val[k-indx-j]=='\n'))
            {
              val[k-indx-j]='\0';
              return k-start_i;
            }
          }
          else
          {
            if (val[k-indx-j]==stop_char)
            {
              val[k-indx-j]='\0';
              return k-start_i;
            }
          }

        }
        //
        val[0]='\0';
        //deblog("not find stop char");
        indx=-1;
      }
      //===============comparison filter and text=================
    }
  }
  val[0]='\0';
  indx=-1;

  //=====  prev_delta_pos_find_val
  if (prev_delta_pos_find_val>0)
  {
    int i_start=start_i;
    int i_end=start_i+prev_delta_pos_find_val+strlen(filter);
    //======  i_end======
    int i;
    for (i = i_start; i < i_end; i++)
    {
      bool find_char=false;
  		if (bufstr[i]=='\n' || bufstr[i]=='\0')
  		{
  			return -1;
  		}
      if (bufstr[i]==filter[0])
        find_char=true;
      else
      {
        if ((filter[0]==' ') && (bufstr[i]==0x1d))
          find_char=true;
        else
          find_char=false;
      }
      if (find_char==true)
      {
        //===============comparison filter and text=================
        //comparison filter and text
        indx=i;
        int j;
        int j_start;
        if ((filter[0]==' ') && (bufstr[indx]==0x1d))
          j_start=1;
        else
          j_start=0;

        for (j=j_start; j<(strlen(filter)); j++)
        {
          if (bufstr[i+j]!=filter[j])
          {
            indx=-1;
            break;
          }
        }

        if (indx>=0)
        {
          for (int k=indx+j; k<(indx+j+max_char); k++)
          {
            // val
            if (k>=end_i)
            {
              val[0]='\0';
              return -1;
            }
            val[k-indx-j]=bufstr[k];
            if (stop_char==' ')
            {
              if ((val[k-indx-j]==' ') || (val[k-indx-j]=='\0') || (val[k-indx-j]=='\n'))
              {
                val[k-indx-j]='\0';
                return k-start_i;
              }
            }
            else
            {
              if (val[k-indx-j]==stop_char)
              {
                val[k-indx-j]='\0';
                return k-start_i;
              }
            }

          }
          //
          val[0]='\0';
          indx=-1;
        }
        //===============comparison filter and text=================
      }
    }
    val[0]='\0';
  }
  val[0]='\0';
	//deblog("function copy_val_istart:no exist");
  return -1;
}

int copystr_start_posi_end_char(char *bufout,char *bufin,int start_i,int end_i,char stop_char,int max_char)
{
	/*if (DEBUG==true)
	{
		snprintf(msg,255,"function copystr_start_posi_end_char: start_i=%d");
		deblog(msg);
	}*/
  bufout[max_char-1]='\0';
	int i_end=end_i;
	if (end_i>(start_i+max_char))
		i_end=start_i+max_char;
  int i;
  for (i = start_i; i < i_end; i++)
  {
    bufout[i-start_i]=bufin[i];
    if (bufin[i]==stop_char)
    {
      bufout[i-start_i]='\0';
      return i;
    }
  }
  bufout[i-start_i]='\0';
  return i;
}


int copystr_start_posi_end_posi(char *bufout,char *bufin,int start_i,int end_i,int sz)
{
  int i;
  for (i = start_i; i<=end_i; i++)
  {
    if ((i-start_i)>=sz)
    {
      bufout[sz-1]='\0';
      return i;
    }
		else
		{
			bufout[i-start_i]=bufin[i];
		}
		if (bufin[i]=='\0' || bufin[i]=='\n')
		{
			bufout[i-start_i]='\0';
			return i;
		}
  }
  bufout[i-start_i]='\0';
  return i;
}


int strnaddchar(char *dst, char add_char, int sz)
{
  char msg[512];
  int i=0;
  if (sz>0)
  {
    if (dst[i]=='\0')
    {
      if (add_char!=',')
      {
        dst[i]=add_char;
        i++;
        dst[i]='\0';
      }
      return i;
    }

    i=strlen(dst);
    if (i<(sz-1))
		{
	    dst[i]=add_char;
      i++;
	    dst[i]='\0';
		}
		/*else
		{
			snprintf(msg,511,"function strnaddchar:size>sz sz=%d len=%d str=''%s'",sz,strlen(dst),dst);
			deblog(msg);
		}*/
	}
  return i;
}

//=== add string to string, src (size < sz_src) to dst size <  sz_dst
int strnadd(char *dst, char *src, int sz_src, int sz_dst)
{
  char msg[512];
	int i=0;
	if (sz_src>0 && sz_dst>0)
	{
		int start_i=strlen(dst);
		if (start_i>=sz_dst)
		{
			//deblog("function strnadd:dst is full\n");
			return 0;
		}
		int copy_len=strlen(src);
		if (copy_len>sz_src)
			copy_len=sz_src;
		int end_i=start_i+copy_len;
		if (end_i>sz_dst)
			end_i=sz_dst;
		for (i=start_i;i<end_i;i++)
		{
			dst[i]=src[i-start_i];
			if (i>=(sz_dst-1))
			{
				dst[i]='\0';
        if ((DEBUG==true) || (DEBUG_DISPLAY==true))
        {
				   snprintf(msg,511,"function strnadd:write to dst is stop, i_src=%d i_dst=%d src=%s dst=%s\n",i-start_i,i,src,dst);
				   deblog(msg);
        }
				return (i-start_i);
			}
		}
		dst[i]='\0';
		return (i-start_i);
	}
	else
		return 0;
}

//
int auditid_to_id(s_audit *f_array, int array_count, unsigned int test_auditid)
{
  //deblog((char *)"auditid_to_id->");
  int prev_id=ATOM_prev_id.load();
  if (ATOM_save_run.load()==true)
  {
    //run process save from 0 to ATOM_save_count
    if (DEBUG_LEVEL>2)
    {
      deblog("run process save, prev_id<ATOM_save_count");
    }
    if (ATOM_relocate_processed.load()==false)
    {//stage save
      if (prev_id<ATOM_save_count.load())
        prev_id=ATOM_save_count.load();
    }
    else
    {//stage relocate
      if (DEBUG_LEVEL>2)
      {
        deblog("auditid_to_id stage relocate");
      }
      if (prev_id<ATOM_post_relocate.load())
        prev_id=ATOM_post_relocate.load();
    }
  }
  //prev_id=0;//==============================
	if (f_array[prev_id].auditid==test_auditid)
  {
    ATOM_prev_id.store(prev_id);
		return prev_id;
  }
	if ((prev_id+1)<array_count)
	{
		if (f_array[prev_id+1].auditid==test_auditid)
		{
			//snprintf(msg,1024,"[str:725(auditid_to_id)]return %d\n",(prev_id+1));
			//deblog(msg);
      ATOM_prev_id.store(prev_id+1);
			return prev_id+1;
		}
	}
	int i;
  int start_i=0;
  if (ATOM_save_run.load()==true)
  {
    if (ATOM_relocate_processed.load()==false)
    {
      //run process save from 0 to ATOM_save_count
      start_i=ATOM_save_count.load();
    }
    else
    {
      if (DEBUG_LEVEL>1)
      deblog("auditid_to_id stage relocate, move start i");
      start_i=ATOM_post_relocate.load();
    }
  }
  for (i=start_i; i<array_count; i++)
  {
    if (f_array[i].auditid==test_auditid)
		{
			prev_id=i;
      ATOM_prev_id.store(i);
			return i;
		}
		if (f_array[i].auditid==0)
		{
			prev_id=i;
      ATOM_prev_id.store(i);
      if (i>MAX_AUDIT_BEFORE_SAVE_TO_FILE)
        ATOM_need_save.store(true);
			return i;
		}
	}
	if (i>=array_count)
		i=array_count-1;
	prev_id=i;
  ATOM_prev_id.store(i);
	//snprintf(msg,1024,"[str:740(auditid_to_id)]array_count=%d return %d\n",array_count,i);
	//deblog(msg);
	return i;
}


int uidtouser(char *login,uid_t uid)
{
  struct passwd *pw;
  if (uid==0)
  {
    strncpy(login,"root",5);
    return 0;
  }
  if (uid==-1)
  {
    strncpy(login,"unset",6);
    return 0;
  }
  //find in cache
  uid_t i;
  for (i=0; i<COUNT_CACHE_LOGIN; i++)
  {
    if (array_pass[i].uid==uid)
    {
      strncpy(login,array_pass[i].login,255);

      return i;
    }
    if (array_pass[i].uid==0)
      break;
  }
  pw=getpwuid(uid);
  if (!pw)
  {
      login[0]='\0';
      return -1;
  }
  else
  {
    strncpy(array_pass[i].login,pw->pw_name,255);
    strncpy(login,pw->pw_name,255);
    return i;
  }
}

int gidtogroup(char *grp,gid_t gid)
{
  struct group *gr;
  if (gid==0)
  {
    strncpy(grp,"root",5);
    return 0;
  }
  if (gid==-1)
  {
    strncpy(grp,"unset",6);
    return 0;
  }
  //find in cache
  gid_t i;
  for (i=0; i<COUNT_CACHE_GROUP; i++)
  {
    if (array_group[i].gid==gid)
    {
      strncpy(grp,array_group[i].group,255);
      return i;
    }
    if (array_group[i].gid==0)
      break;
  }
  gr=getgrgid(gid);
  if (!gr)
  {
      grp[0]='\0';
      return -1;
  }
  else
  {
    strncpy(array_group[i].group,gr->gr_name,255);
    strncpy(grp,gr->gr_name,255);
    return i;
  }
}


bool xlate_saddr(s_audit *c_audit, char *saddr)
{
  if (DEBUG_LEVEL==3)
    deblog("xlate_saddr");
	int fam1=0;
	int fam2=0;
	int family=0;
	int port1=0;
	int port2=0;
	int port=0;
	char tmp_str[64];
	int addr1=0;
	int addr2=0;
	int addr3=0;
	int addr4=0;
	char ipv6_addr1[5];
	char ipv6_addr2[5];
	char ipv6_addr3[5];
	char ipv6_addr4[5];
	char ipv6_addr5[5];
	char ipv6_addr6[5];
	char ipv6_addr7[5];
	char ipv6_addr8[5];

  if (strncmp(saddr,"100000000000000000000000",32)==0)
  {
    strncpy(c_audit->res_saddr,"netlink pid:0",2048);
    return true;
  }
	copystr_start_posi_end_posi(tmp_str,saddr,0,1,3);
	fam1=strtol(tmp_str, NULL,16);
	copystr_start_posi_end_posi(tmp_str,saddr,2,3,3);
	fam2=strtol(tmp_str, NULL,16);
	family=fam1+fam2*256;
	c_audit->family=family;
	//ipv6
	if (family==10)
	{
		//FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
		copystr_start_posi_end_posi(tmp_str,saddr,4,5,3);
		port1=strtol(tmp_str, NULL,16);
		copystr_start_posi_end_posi(tmp_str,saddr,6,7,3);
		port2=strtol(tmp_str, NULL,16);
		port=port1*256+port2;
		c_audit->port=port;
		//ipv6
		//8-15 junk
		copystr_start_posi_end_posi(ipv6_addr6,saddr,36,39,5);
		if (strcmp(ipv6_addr6,"0000")==0)
			ipv6_addr6[0]='\0';
		// is really ipv4 in ipv6 notation
		if (strcmp(ipv6_addr6,"FFFF")==0)
		{
			//ipv4
			copystr_start_posi_end_posi(tmp_str,saddr,8,9,3);
			addr1=strtol(tmp_str, NULL,16);
			copystr_start_posi_end_posi(tmp_str,saddr,10,11,3);
			addr2=strtol(tmp_str, NULL,16);
			copystr_start_posi_end_posi(tmp_str,saddr,12,13,3);
			addr3=strtol(tmp_str, NULL,16);
			copystr_start_posi_end_posi(tmp_str,saddr,14,15,3);
			addr4=strtol(tmp_str, NULL,16);
			snprintf(c_audit->ipv6,40,":::::FFFF:%d.%d.%d.%d",addr1,addr2,addr3,addr4);
		}
		else
		{
			copystr_start_posi_end_posi(ipv6_addr1,saddr,16,19,5);
			if (strcmp(ipv6_addr1,"0000")==0)
				ipv6_addr1[0]='\0';
			copystr_start_posi_end_posi(ipv6_addr2,saddr,20,23,5);
			if (strcmp(ipv6_addr2,"0000")==0)
				ipv6_addr2[0]='\0';
			copystr_start_posi_end_posi(ipv6_addr3,saddr,24,27,5);
			if (strcmp(ipv6_addr3,"0000")==0)
				ipv6_addr3[0]='\0';
			copystr_start_posi_end_posi(ipv6_addr4,saddr,28,31,5);
			if (strcmp(ipv6_addr4,"0000")==0)
				ipv6_addr4[0]='\0';
			copystr_start_posi_end_posi(ipv6_addr5,saddr,32,35,5);
			if (strcmp(ipv6_addr5,"0000")==0)
				ipv6_addr5[0]='\0';

			copystr_start_posi_end_posi(ipv6_addr7,saddr,40,43,5);
			if (strcmp(ipv6_addr7,"0000")==0)
				ipv6_addr7[0]='\0';
			copystr_start_posi_end_posi(ipv6_addr8,saddr,44,47,5);
			if (strcmp(ipv6_addr8,"0000")==0)
				ipv6_addr8[0]='\0';
			snprintf(c_audit->ipv6,40,"%s:%s:%s:%s:%s:%s:%s:%s",ipv6_addr1,ipv6_addr2,ipv6_addr3,ipv6_addr4,ipv6_addr5,ipv6_addr6,ipv6_addr7,ipv6_addr8);
		}
		snprintf(c_audit->res_saddr,1024,"saddr_fam=inet laddr=%s lport=%d",c_audit->ipv6,port);
		return true;
	}
	//ipv4
	if (family==2)
	{
		copystr_start_posi_end_posi(tmp_str,saddr,4,5,3);
		port1=strtol(tmp_str, NULL,16);
		copystr_start_posi_end_posi(tmp_str,saddr,6,7,3);
		port2=strtol(tmp_str, NULL,16);
		port=port1*256+port2;
		c_audit->port=port;
		//ipv4
		copystr_start_posi_end_posi(tmp_str,saddr,8,9,3);
		addr1=strtol(tmp_str, NULL,16);
		copystr_start_posi_end_posi(tmp_str,saddr,10,11,3);
		addr2=strtol(tmp_str, NULL,16);
		copystr_start_posi_end_posi(tmp_str,saddr,12,13,3);
		addr3=strtol(tmp_str, NULL,16);
		copystr_start_posi_end_posi(tmp_str,saddr,14,15,3);
		addr4=strtol(tmp_str, NULL,16);
		snprintf(c_audit->res_saddr,1024,"saddr_fam=inet laddr=%d.%d.%d.%d lport=%d",addr1,addr2,addr3,addr4,port);
		return true;
	}
	if (family==1)
	{
		strncpy(c_audit->res_saddr,saddr,2048);
		return true;
	}
	return false;
}

/*int filtering(s_audit *f_array,int array_count,int n_thread)
{
  return 0;
}*/

int cur_audit_to_array(s_audit *f_array,int array_count,s_audit cur_audit,int n_thread)
{
	//clock_t t_start = clock();
  ATOM_STAT_line_auditd.fetch_add(1);
  char msg[256];
  int find_id_in_auditid=auditid_to_id(f_array,SIZE_AUDIT,cur_audit.auditid);

  while ((find_id_in_auditid>=ATOM_start_audit_relocate.load()) && (find_id_in_auditid<ATOM_end_audit_relocate) && (ATOM_relocate_processed.load()==true))
  {
    //re find auditid
    if (DEBUG_LEVEL>1)
      deblog("re find auditid_to_id");
    find_id_in_auditid=auditid_to_id(f_array,SIZE_AUDIT,cur_audit.auditid);
  }

  if (n_thread>=0)
  ATOM_add_to_array_id[n_thread].store(find_id_in_auditid);
  ATOM_add_to_array_auditid[n_thread].store(cur_audit.auditid);

	int i;
  if (find_id_in_auditid>=(SIZE_AUDIT-1))
  {
    if (f_array[find_id_in_auditid].auditid!=0)
    {
      deblog("over max SIZE_AUDIT, print to stdout");
      print_audit(f_array,find_id_in_auditid);
    }
  }

  f_array[find_id_in_auditid].auditid=cur_audit.auditid;

  if (cur_audit.pid_isset==true)
  {
    f_array[find_id_in_auditid].pid_isset=true;
    f_array[find_id_in_auditid].pid=cur_audit.pid;
  }

  if (cur_audit.ppid_isset==true)
  {
    f_array[find_id_in_auditid].ppid_isset=true;
    f_array[find_id_in_auditid].ppid=cur_audit.ppid;
  }
  if (cur_audit.t_shtamp!=0)
  {
    f_array[find_id_in_auditid].t_shtamp=cur_audit.t_shtamp;
    f_array[find_id_in_auditid].t_mls=cur_audit.t_mls;
  }
  if (cur_audit.auid_isset==true)
  {
    f_array[find_id_in_auditid].auid_isset=cur_audit.auid_isset;
    f_array[find_id_in_auditid].auid=cur_audit.auid;
  }
  if (cur_audit.uid_isset==true)
  {
    f_array[find_id_in_auditid].uid_isset=cur_audit.uid_isset;
    f_array[find_id_in_auditid].uid=cur_audit.uid;
  }
  if (cur_audit.gid_isset==true)
  {
    f_array[find_id_in_auditid].gid_isset=cur_audit.gid_isset;
    f_array[find_id_in_auditid].gid=cur_audit.gid;
  }
  if (cur_audit.euid_isset==true)
  {
    f_array[find_id_in_auditid].euid_isset=cur_audit.euid_isset;
    f_array[find_id_in_auditid].euid=cur_audit.euid;
  }
  if (cur_audit.suid_isset==true)
  {
    f_array[find_id_in_auditid].suid_isset=cur_audit.suid_isset;
    f_array[find_id_in_auditid].suid=cur_audit.suid;
  }
  if (cur_audit.fsuid_isset==true)
  {
    f_array[find_id_in_auditid].fsuid_isset=cur_audit.fsuid_isset;
    f_array[find_id_in_auditid].fsuid=cur_audit.fsuid;
  }
  if (cur_audit.ouid_isset==true)
  {
    f_array[find_id_in_auditid].ouid_isset=cur_audit.ouid_isset;
    f_array[find_id_in_auditid].ouid=cur_audit.ouid;
  }
  if (cur_audit.ogid_isset==true)
  {
    f_array[find_id_in_auditid].ogid_isset=cur_audit.ogid_isset;
    f_array[find_id_in_auditid].ogid=cur_audit.ogid;
  }
  if (cur_audit.agid_isset==true)
  {
    f_array[find_id_in_auditid].agid_isset=cur_audit.agid_isset;
    f_array[find_id_in_auditid].agid=cur_audit.agid;
  }
  if (cur_audit.egid_isset==true)
  {
    f_array[find_id_in_auditid].egid_isset=cur_audit.egid_isset;
    f_array[find_id_in_auditid].egid=cur_audit.egid;
  }
  if (cur_audit.sgid_isset==true)
  {
    f_array[find_id_in_auditid].sgid_isset=cur_audit.sgid_isset;
    f_array[find_id_in_auditid].sgid=cur_audit.sgid;
  }
  if (cur_audit.fsgid_isset==true)
  {
    f_array[find_id_in_auditid].fsgid_isset=cur_audit.fsgid_isset;
    f_array[find_id_in_auditid].fsgid=cur_audit.fsgid;
  }
  if (cur_audit.addr[0]!='\0')
    strncpy(f_array[find_id_in_auditid].addr,cur_audit.addr,255);
  if (cur_audit.exe[0]!='\0')
    strncpy(f_array[find_id_in_auditid].exe,cur_audit.exe,4096);
  if (cur_audit.hostname[0]!='\0')
    strncpy(f_array[find_id_in_auditid].hostname,cur_audit.hostname,255);
  if (cur_audit.key[0]!='\0')
    strncpy(f_array[find_id_in_auditid].key,cur_audit.key,255);
  if (cur_audit.newcontext[0]!='\0')
    strncpy(f_array[find_id_in_auditid].newcontext,cur_audit.newcontext,255);
  if (cur_audit.oldcontext[0]!='\0')
    strncpy(f_array[find_id_in_auditid].oldcontext,cur_audit.oldcontext,255);
  if (cur_audit.res[0]!='\0')
    strncpy(f_array[find_id_in_auditid].res,cur_audit.res,11);
  if (cur_audit.seresult[0]!='\0')
    strncpy(f_array[find_id_in_auditid].seresult,cur_audit.seresult,255);

  if (cur_audit.ses_isset==true)
  {
    f_array[find_id_in_auditid].ses_isset=cur_audit.ses_isset;
    f_array[find_id_in_auditid].ses=cur_audit.ses;
  }
  if (cur_audit.subj[0]!='\0')
    strncpy(f_array[find_id_in_auditid].subj,cur_audit.subj,255);
  if (cur_audit.terminal[0]!='\0')
    strncpy(f_array[find_id_in_auditid].terminal,cur_audit.terminal,255);
  if (cur_audit.tty[0]!='\0')
    strncpy(f_array[find_id_in_auditid].tty,cur_audit.tty,255);
  if (cur_audit.direction[0]!='\0')
    strncpy(f_array[find_id_in_auditid].direction,cur_audit.direction,255);
  if (cur_audit.cipher[0]!='\0')
    strncpy(f_array[find_id_in_auditid].cipher,cur_audit.cipher,255);
  if (cur_audit.ksize[0]!='\0')
    strncpy(f_array[find_id_in_auditid].ksize,cur_audit.ksize,255);
  if (cur_audit.mac[0]!='\0')
    strncpy(f_array[find_id_in_auditid].mac,cur_audit.mac,255);
  if (cur_audit.pfs[0]!='\0')
    strncpy(f_array[find_id_in_auditid].pfs,cur_audit.pfs,255);
  if (cur_audit.spid[0]!='\0')
    strncpy(f_array[find_id_in_auditid].spid,cur_audit.spid,255);
  if (cur_audit.laddr[0]!='\0')
    strncpy(f_array[find_id_in_auditid].laddr,cur_audit.laddr,255);
  if (cur_audit.lport[0]!='\0')
    strncpy(f_array[find_id_in_auditid].lport,cur_audit.lport,255);
  if (cur_audit.SYSCALL[0]!='\0')
    strncpy(f_array[find_id_in_auditid].SYSCALL,cur_audit.SYSCALL,25);

  if (cur_audit.syscall_isset==true)
  {
    f_array[find_id_in_auditid].syscall_isset=cur_audit.syscall_isset;
    f_array[find_id_in_auditid].syscall=cur_audit.syscall;
  }
  if (cur_audit.op[0]!='\0')
    strncpy(f_array[find_id_in_auditid].op,cur_audit.op,255);
  if (cur_audit.vm[0]!='\0')
    strncpy(f_array[find_id_in_auditid].vm,cur_audit.vm,255);
  if (cur_audit.cwd[0]!='\0')
    strncpy(f_array[find_id_in_auditid].cwd,cur_audit.cwd,4096);

  if ( cur_audit.command_isset==true )
  {
    f_array[find_id_in_auditid].command_isset=true;
    if (f_array[find_id_in_auditid].command[0]!='\0')
    {
      strnaddchar(f_array[find_id_in_auditid].command,';',10240);
    }
    strnadd(f_array[find_id_in_auditid].command,cur_audit.command,10240,10240);
  }
  if (cur_audit.proctitle[0]!='\0')
    strncpy(f_array[find_id_in_auditid].proctitle,cur_audit.proctitle,10240);
  if (cur_audit.errcode[0]!='\0')
    strncpy(f_array[find_id_in_auditid].errcode,cur_audit.errcode,254);
  if (cur_audit.errdesc[0]!='\0')
    strncpy(f_array[find_id_in_auditid].errdesc,cur_audit.errdesc,254);
  if (cur_audit.res_saddr[0]!='\0')
    strncpy(f_array[find_id_in_auditid].res_saddr,cur_audit.res_saddr,2048);
  if (cur_audit.saddr[0]!='\0')
    strncpy(f_array[find_id_in_auditid].saddr,cur_audit.saddr,63);
  if (f_array[find_id_in_auditid].family==0)
    f_array[find_id_in_auditid].family=cur_audit.family;
  if (cur_audit.ip[0]!='\0')
    strncpy(f_array[find_id_in_auditid].ip,cur_audit.ip,15);
  if (cur_audit.ipv6[0]!='\0')
    strncpy(f_array[find_id_in_auditid].ipv6,cur_audit.ipv6,39);
  f_array[find_id_in_auditid].port=cur_audit.port;
  if (cur_audit.avc[0]!='\0')
    strncpy(f_array[find_id_in_auditid].avc,cur_audit.avc,63);
  if (cur_audit.type_isset==true)
  {
    f_array[find_id_in_auditid].type_isset=cur_audit.type_isset;
    strncpy(f_array[find_id_in_auditid].types,cur_audit.types,4095);
  }
  if ( cur_audit.name_isset==true )
  {
    f_array[find_id_in_auditid].name_isset=true;
    if (cur_audit.names[0]!='\0')
    {
      //snprintf(msg,255,"==== cur_audit.names=%s",cur_audit.names);
      //deblog(msg);
      strnaddchar(f_array[find_id_in_auditid].names,',',10240);
    }
    strnadd(f_array[find_id_in_auditid].names,cur_audit.names,10240,10240);
  }
  if (cur_audit.acct[0]!='\0')
    strncpy(f_array[find_id_in_auditid].acct,cur_audit.acct,255);
  if (cur_audit.unit[0]!='\0')
    strncpy(f_array[find_id_in_auditid].unit,cur_audit.unit,255);
  if (cur_audit.success[0]!='\0')
    strncpy(f_array[find_id_in_auditid].success,cur_audit.success,255);

  //strnadd(f_array[find_id_in_auditid].command,cur_audit.command,10240,10240);
  strnadd(f_array[find_id_in_auditid].args,cur_audit.args,10240,10240);

  if (cur_audit.auid_isset==true)
    strncpy(f_array[find_id_in_auditid].auid_user,cur_audit.auid_user,255);
  if (cur_audit.uid_isset==true)
  {
    strncpy(f_array[find_id_in_auditid].uid_user,cur_audit.uid_user,255);
    /*if (DEBUG_LEVEL==3)
    {
      if ((DEBUG==true) || (DEBUG_DISPLAY==true))
      {
        snprintf(msg,255,"  add audit array [%d] auditid(%d)  uid_user=%s",find_id_in_auditid,cur_audit.auditid,cur_audit.uid_user);
        deblog(msg);
      }
    }*/
  }
  if (cur_audit.gid_isset==true)
    strncpy(f_array[find_id_in_auditid].gid_group,cur_audit.gid_group,255);
  if (cur_audit.euid_isset==true)
    strncpy(f_array[find_id_in_auditid].euid_user,cur_audit.euid_user,255);
  if (cur_audit.suid_isset==true)
    strncpy(f_array[find_id_in_auditid].suid_user,cur_audit.suid_user,255);
  if (cur_audit.fsuid_isset==true)
    strncpy(f_array[find_id_in_auditid].fsuid_user,cur_audit.fsuid_user,255);
  if (cur_audit.ouid_isset==true)
    strncpy(f_array[find_id_in_auditid].ouid_user,cur_audit.ouid_user,255);
  if (cur_audit.agid_isset==true)
    strncpy(f_array[find_id_in_auditid].agid_group,cur_audit.agid_group,255);
  if (cur_audit.egid_isset==true)
    strncpy(f_array[find_id_in_auditid].egid_group,cur_audit.egid_group,255);
  if (cur_audit.sgid_isset==true)
    strncpy(f_array[find_id_in_auditid].sgid_group,cur_audit.sgid_group,255);
  if (cur_audit.fsgid_isset==true)
    strncpy(f_array[find_id_in_auditid].fsgid_group,cur_audit.fsgid_group,255);
  if (cur_audit.ogid_isset==true)
    strncpy(f_array[find_id_in_auditid].ogid_group,cur_audit.ogid_group,255);


  if (DEBUG_LEVEL>1)
  {
    if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    {
      snprintf(msg,255,"[%d]>> cur_audit_to_array: add %d to array[%d] uid_user=%s",n_thread,cur_audit.auditid,find_id_in_auditid,cur_audit.uid_user);
      deblog(msg);
    }
  }
  //ATOM_add_to_array_id[n_thread].store(-1);
  //ATOM_add_to_array_auditid[n_thread].store(0);
  return find_id_in_auditid;
}

int count_array_audit(int start_calc=0)
{
  if (DEBUG_LEVEL>1)
    deblog("calc count..");
  char msg[128];
  if (start_calc>=SIZE_AUDIT)
  {
    //deblog("in function count_array_audit > size array_audit");
    start_calc=0;
  }
  int prev_id=ATOM_prev_id.load();
  if (start_calc>prev_id)
    prev_id=start_calc;
	if ((prev_id+1)<SIZE_AUDIT)
	{
		if (array_audit[prev_id+1].auditid==0)
    {
      //snprintf(msg,127,"count_array_audit: array_audit[%d].auditid=%d",prev_id+1,array_audit[prev_id+1].auditid);
      //deblog((char *)msg);
      return (prev_id+1);
    }
	}
  if ((prev_id+2)<SIZE_AUDIT)
	{
		if (array_audit[prev_id+2].auditid==0)
    {
      //snprintf(msg,127,"count_array_audit:  array_audit[%d].auditid=%d",prev_id+2,array_audit[prev_id+2].auditid);
      //deblog((char *)msg);
      return (prev_id+2);
    }
	}

  int i;
  for (i = start_calc; i < SIZE_AUDIT; i++)
  {
    if (array_audit[i].auditid == 0)
    {
      //snprintf(msg,127,"count_array_audit:   array_audit[%d].auditid=%d",i,array_audit[i].auditid);
      //deblog((char *)msg);
      return i;
    }

  }
  //snprintf(msg,127,"count_array_audit:    array_audit[%d].auditid=%d",i,array_audit[i].auditid);
  //deblog((char *)msg);
  return i;
}

int F_parsing_string_to_auditid(char *buf, int start_i, int end_i, s_audit *f_array,int n_thread)
{
  char msg[256];
  char pos_filter[20];

  int i_line_start=start_i;
  int i_line_end=end_i;
  int first_i=i_line_start;

  int size_time_t;
  time_t t_shtamp;
  struct tm *local_tm;
  struct tm  l_tm;

  char str_auditid[12];
  char str_mls[4];
  char str_unixtime[20];
  int prev_delta_pos_find_val;
  int test_delta_pos_find_val;

  char str_tmp[10240];
  //bool last_isset=false;
  char name_ai[10];

  s_audit cur_audit;
  //snprintf(msg,255,"F_parsing_string_to_auditid[%d] s=%d e=%d >",n_thread,start_i,end_i);
  //deblog(msg);

  if (DEBUG_DISPLAY==true)
  {
    printf("F_parsing_string_to_auditid[%d] s=%d e=%d >",n_thread,start_i,end_i);
    printf(" |line not read:%d| ",ATOM_line_read.load());
    int number_line_in_queue;
    sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
    printf(" |sem for read:%d|\n",number_line_in_queue);
  }
  memset(&cur_audit,0,sizeof(s_audit));

  //=========================
  debbuf(i_line_start,i_line_end,buf); //<=========== BUG ========= TESTING =====
  strncpy(pos_filter,"msg=audit(",16);
  if (ATOM_prev_delta_strpos_istart.load()>=4)
    ATOM_prev_delta_strpos_istart.store(ATOM_prev_delta_strpos_istart.load()-4);
  first_i=strpos_istart(buf,i_line_start,i_line_end,pos_filter);
  if (first_i>=0)
  {
    prev_delta_pos_find_val=0;
    first_i=first_i+strlen(pos_filter);

    //unixtime
    first_i=copystr_start_posi_end_char(str_unixtime,buf,first_i,i_line_end,'.',15)+1;
    switch (size_time_t)
    {
      case 0: t_shtamp=atoi(str_unixtime); break;
      case 1: t_shtamp=atol(str_unixtime); break;
      case 2: t_shtamp=atoll(str_unixtime); break;
    }
    cur_audit.t_shtamp=t_shtamp;
    local_tm=localtime(&t_shtamp);
    l_tm=*local_tm;
    //millisec
    first_i=copystr_start_posi_end_char(str_mls,buf,first_i,i_line_end,':',3)+1;
    cur_audit.t_mls=atoi(str_mls);
    first_i=copystr_start_posi_end_char(str_auditid,buf,first_i,i_line_end,')',12)+1;
    //snprintf(msg,255,"[thread:%d]function F_parsing_string_to_auditid:find auditid=%s",n_thread,str_auditid);
    //deblog(msg);
    cur_audit.auditid=atoi(str_auditid);
    //========================== ============================================================
    //=======clear====

    str_tmp[0]='\0';
    cur_audit.uid_isset=false;
    cur_audit.uid_user[0]='\0';
    cur_audit.auid_isset=false;
    cur_audit.auid_user[0]='\0';
    cur_audit.euid_isset=false;
    cur_audit.euid_user[0]='\0';
    cur_audit.suid_isset=false;
    cur_audit.suid_user[0]='\0';
    cur_audit.fsuid_isset=false;
    cur_audit.fsuid_user[0]='\0';
    cur_audit.ouid_isset=false;
    cur_audit.ouid_user[0]='\0';
    cur_audit.agid_isset=false;
    cur_audit.agid_group[0]='\0';
    cur_audit.gid_isset=false;
    cur_audit.gid_group[0]='\0';
    cur_audit.egid_isset=false;
    cur_audit.egid_group[0]='\0';
    cur_audit.sgid_isset=false;
    cur_audit.sgid_group[0]='\0';
    cur_audit.fsgid_isset=false;
    cur_audit.fsgid_group[0]='\0';
    cur_audit.ogid_isset=false;
    cur_audit.ogid_group[0]='\0';
    cur_audit.pid_isset=false;
    cur_audit.ppid_isset=false;
    cur_audit.ses_isset=false;
    cur_audit.syscall_isset=false;
    cur_audit.type_isset=false;
    cur_audit.types[0]='\0';
    cur_audit.command_isset=false;
    cur_audit.command[0]='\0';
    cur_audit.name_isset=false;
    cur_audit.names[0]='\0';
    cur_audit.argc_isset=false;
    cur_audit.args_isset=false;
    cur_audit.args[0]='\0';

    //=======clear====

    test_delta_pos_find_val=copy_val_istart(str_tmp,buf,start_i,end_i," pid=",' ',12, prev_delta_pos_find_val);
    if (test_delta_pos_find_val>=0)
    {
      prev_delta_pos_find_val=test_delta_pos_find_val;
      cur_audit.pid_isset=true;
      cur_audit.pid=atoi(str_tmp);

    }
    test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end," ppid=",' ',12, prev_delta_pos_find_val);
    if (test_delta_pos_find_val>=0)
    {
      prev_delta_pos_find_val=test_delta_pos_find_val;
      cur_audit.ppid_isset=true;
      cur_audit.ppid=atoi(str_tmp);
    }

    if (cur_audit.pid != pid && cur_audit.ppid != ppid)
    {
    //======================================================13
      test_delta_pos_find_val=copy_val_istart(cur_audit.auid_user,read_buf,i_line_start,i_line_end,"auid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.auid_isset=true;
        cur_audit.auid=atoi(cur_audit.auid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.uid_user,read_buf,i_line_start,i_line_end," uid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.uid_isset=true;
        cur_audit.uid=atoi(cur_audit.uid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.gid_group,read_buf,i_line_start,i_line_end," gid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.gid_isset=true;
        cur_audit.gid=atoi(cur_audit.gid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.euid_user,read_buf,i_line_start,i_line_end," euid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.euid_isset=true;
        cur_audit.euid=atoi(cur_audit.euid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start,i_line_end," suid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.suid_isset=true;
        cur_audit.suid=atoi(cur_audit.suid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.fsuid_user,read_buf,i_line_start,i_line_end," fsuid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.fsuid_isset=true;
        cur_audit.fsuid=atoi(cur_audit.fsuid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.ouid_user,read_buf,i_line_start,i_line_end," ouid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.ouid_isset=true;
        cur_audit.ouid=atoi(cur_audit.ouid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.ogid_group,read_buf,i_line_start,i_line_end," ogid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.ogid_isset=true;
        cur_audit.ogid=atoi(cur_audit.ogid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.agid_group,read_buf,i_line_start,i_line_end," agid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.agid_isset=true;
        cur_audit.agid=atoi(cur_audit.agid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.egid_group,read_buf,i_line_start,i_line_end," egid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.egid_isset=true;
        cur_audit.egid=atoi(cur_audit.egid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start,i_line_end," sgid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.sgid_isset=true;
        cur_audit.sgid=atoi(cur_audit.sgid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.fsgid_group,read_buf,i_line_start,i_line_end," fsgid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.fsgid_isset=true;
        cur_audit.fsgid=atoi(cur_audit.fsgid_group);
      }



      test_delta_pos_find_val=copy_val_istart(cur_audit.addr,read_buf,i_line_start,i_line_end," addr=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.exe,read_buf,i_line_start,i_line_end," exe=\"",'"',4095, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.hostname,read_buf,i_line_start,i_line_end," hostname=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.key,read_buf,i_line_start,i_line_end," key=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.newcontext,read_buf,i_line_start,i_line_end," newcontext=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.oldcontext,read_buf,i_line_start,i_line_end," oldcontext=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;



      test_delta_pos_find_val=copy_val_istart(cur_audit.res,read_buf,i_line_start,i_line_end," res=",0x1d,11, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;

      test_delta_pos_find_val=copy_val_istart(cur_audit.seresult,read_buf,i_line_start,i_line_end," seresult=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end," ses=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.ses_isset=true;
        cur_audit.ses=atoi(str_tmp);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.subj,read_buf,i_line_start,i_line_end," subj=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.terminal,read_buf,i_line_start,i_line_end," terminal=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.tty,read_buf,i_line_start,i_line_end," tty=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.direction,read_buf,i_line_start,i_line_end," direction=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.cipher,read_buf,i_line_start,i_line_end," cipher=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.ksize,read_buf,i_line_start,i_line_end," ksize=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.mac,read_buf,i_line_start,i_line_end," mac=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.pfs,read_buf,i_line_start,i_line_end," pfs=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.spid,read_buf,i_line_start,i_line_end," spid=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.laddr,read_buf,i_line_start,i_line_end," laddr=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.lport,read_buf,i_line_start,i_line_end," lport=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.SYSCALL,read_buf,i_line_start,i_line_end," SYSCALL=",' ',25, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end," syscall=",' ',25, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.syscall_isset=true;
        cur_audit.syscall=atoi(str_tmp);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.op,read_buf,i_line_start,i_line_end," op=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.vm,read_buf,i_line_start,i_line_end," vm=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.cwd,read_buf,i_line_start,i_line_end," cwd=\"",'"',4096, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;


      test_delta_pos_find_val=copy_val_istart(cur_audit.cmd,read_buf,i_line_start,i_line_end," comm=\"",'"',10240, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.command_isset=true;
        strncpy(cur_audit.command,cur_audit.cmd,10240);
      }
      /*if (cur_audit.command_isset==true)
      {
        if (strlen(array_audit[find_id_in_auditid].command)>0)
        {
          strncpy(cur_audit.command,array_audit[find_id_in_auditid].command,10240);
          strnaddchar(cur_audit.command,';',10240);
        }
        strnadd(cur_audit.command,cur_audit.cmd,10240,10240);
      }*/

      test_delta_pos_find_val=copy_val_istart(cur_audit.proctitle,read_buf,i_line_start,i_line_end," proctitle=\"",'"',10240, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.errcode,read_buf,i_line_start,i_line_end," errcode=\"",'"',254, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.errdesc,read_buf,i_line_start,i_line_end," errdesc=\"",'"',254, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.res_saddr,read_buf,i_line_start,i_line_end," SADDR={",'}',1024, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      if (strlen(cur_audit.res_saddr)==0)
      {
        test_delta_pos_find_val=copy_val_istart(cur_audit.saddr,read_buf,i_line_start,i_line_end," saddr=",' ',63, prev_delta_pos_find_val);
        if (test_delta_pos_find_val>=0)
        {
          prev_delta_pos_find_val=test_delta_pos_find_val;
          if (strlen(cur_audit.saddr)>0)
          {
            xlate_saddr(&cur_audit,cur_audit.saddr);
          }
        }
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.avc,read_buf,i_line_start,i_line_end," avc: ",'}',25, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      str_tmp[0]='\0';


      test_delta_pos_find_val=copy_val_istart(cur_audit.types,read_buf,i_line_start,i_line_end,"type=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.type_isset=true;

      }
      /*if (cur_audit.type_isset==true)
      {
        if (strlen(array_audit[find_id_in_auditid].types)>0)
        {
          strncpy(cur_audit.types,array_audit[find_id_in_auditid].types,4096);
          strnaddchar(cur_audit.types,',',4096);
        }
        strnadd(cur_audit.types,str_tmp,255,4096);
      }
      if (last_isset==true)
        cur_audit.type_isset=last_isset;
      */
      //str_tmp[0]='\0';
      //last_isset=array_audit[find_id_in_auditid].name_isset;

      test_delta_pos_find_val=copy_val_istart(cur_audit.names,read_buf,i_line_start,i_line_end," name=\"",'"',10240, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.name_isset=true;
      }
      /*if (cur_audit.name_isset==true)
      {
        array_audit[find_id_in_auditid].name_isset=true;
        if (strlen(array_audit[find_id_in_auditid].names)>0)
        {
          strncpy(cur_audit.names,array_audit[find_id_in_auditid].names,10240);
          strnaddchar(cur_audit.names,',',10240);
        }
        strnadd(cur_audit.names,str_tmp,10240,10240);
      }
      if (array_audit[find_id_in_auditid].name_isset==true)
        cur_audit.name_isset=true;*/

      test_delta_pos_find_val=copy_val_istart(cur_audit.acct,read_buf,i_line_start,i_line_end," acct=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.unit,read_buf,i_line_start,i_line_end," unit=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.success,read_buf,i_line_start,i_line_end," success=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      //=================arg=====================

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end," argc=",' ',20, prev_delta_pos_find_val);
      bool args_isset=false;
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.argc_isset=true;
        cur_audit.argc=atoi(str_tmp);
        cur_audit.args[0]='\0';
        //field argc, count arg
        for (int ai=0; ai<cur_audit.argc; ai++)
        {
          snprintf(name_ai,9,"a%d=\"",ai);
          str_tmp[0]='\0';
          test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,name_ai,'"',10240, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            snprintf(name_ai,9,"a%d=",ai);
            str_tmp[0]='\0';
            test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,name_ai,' ',10240, prev_delta_pos_find_val);
            if (test_delta_pos_find_val>=0)
              prev_delta_pos_find_val=test_delta_pos_find_val;
            else
              break;
          }

          if (strlen(cur_audit.args)>0)
          {
            strnaddchar(cur_audit.args,' ',10240);
          }
          strnadd(cur_audit.args,str_tmp,10240,10240);
        }

        if (strlen(cur_audit.args)>0)
        {
          if (cur_audit.command_isset==true)
          {
            if (strlen(cur_audit.command)>0)
            {
              strnaddchar(cur_audit.command,' ',10240);
            }
            strnadd(cur_audit.command,cur_audit.args,10240,10240);
            cur_audit.args[0]='\0';
          }
        }
      }
      else
      {
        int ai=0;
        cur_audit.args[0]='\0';
        do
        {
          snprintf(name_ai,9,"a%d=",ai);
          str_tmp[0]='\0';
          test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,name_ai,' ',10240, prev_delta_pos_find_val);
          i_line_start=i_line_start+3;
          if (i_line_start>=strlen(read_buf))
          {
            break;
          }

          if (test_delta_pos_find_val>=0)
          {
            prev_delta_pos_find_val=test_delta_pos_find_val;
            cur_audit.argc_isset=true;
            if (strlen(cur_audit.args)>0)
            {
              strnaddchar(cur_audit.args,' ',10240);
            }
            strnadd(cur_audit.args,str_tmp,10240,10240);

            ai++;
            cur_audit.argc=ai;
            if (ai>255)
            {
              break;
            }
          }
        } while(args_isset);

      }

      //===============EXT ARG============
      //=============== uidtouser ========
      if (cur_audit.auid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.auid_user,read_buf,i_line_start,i_line_end," AUID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            deblog("ATOM_enable_scan_extend_UID=false");
            uidtouser(cur_audit.auid_user,cur_audit.auid);
          }
        }
        else
          uidtouser(cur_audit.auid_user,cur_audit.auid);
      }

      if (cur_audit.uid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.uid_user,read_buf,i_line_start,i_line_end," UID=\"",'"',255, prev_delta_pos_find_val);
          /*if (DEBUG_LEVEL==3)
          {
            if ((DEBUG==true) || (DEBUG_DISPLAY==true))
            {
              snprintf(msg,255," cur_audit(%d) UID=%s",cur_audit.auditid,cur_audit.uid_user);
              deblog(msg);
            }
          }*/
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            //deblog("ATOM_enable_scan_extend_UID=false");
            uidtouser(cur_audit.uid_user,cur_audit.uid);
          }
        }
        else
          uidtouser(cur_audit.uid_user,cur_audit.uid);
      }

      if (cur_audit.gid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.gid_group,read_buf,i_line_start,i_line_end," GID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            gidtogroup(cur_audit.gid_group,cur_audit.gid);
          }
        }
        else
          gidtogroup(cur_audit.gid_group,cur_audit.gid);
      }

      if (cur_audit.euid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start,i_line_end," EUID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            uidtouser(cur_audit.euid_user,cur_audit.euid);
          }
        }
        else
          uidtouser(cur_audit.euid_user,cur_audit.euid);
      }

      if (cur_audit.suid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start,i_line_end," SUID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            uidtouser(cur_audit.suid_user,cur_audit.suid);
          }
        }
        else
          uidtouser(cur_audit.suid_user,cur_audit.suid);
      }

      if (cur_audit.fsuid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.fsuid_user,read_buf,i_line_start,i_line_end," FSUID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            uidtouser(cur_audit.fsuid_user,cur_audit.fsuid);
          }
        }
        else
          uidtouser(cur_audit.fsuid_user,cur_audit.fsuid);
      }

      if (cur_audit.ouid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.ouid_user,read_buf,i_line_start,i_line_end," OUID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            uidtouser(cur_audit.ouid_user,cur_audit.ouid);
          }
        }
        else
          uidtouser(cur_audit.ouid_user,cur_audit.ouid);
      }

      if (cur_audit.ogid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.ogid_group,read_buf,i_line_start,i_line_end," OGID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
            gidtogroup(cur_audit.ogid_group,cur_audit.ogid);
        }
        else
          gidtogroup(cur_audit.ogid_group,cur_audit.ogid);
      }

      if (cur_audit.agid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.agid_group,read_buf,i_line_start,i_line_end," AGID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
            gidtogroup(cur_audit.agid_group,cur_audit.agid);
        }
        else
          gidtogroup(cur_audit.agid_group,cur_audit.agid);
      }

      if (cur_audit.egid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start,i_line_end," EGID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
            gidtogroup(cur_audit.egid_group,cur_audit.egid);
        }
        else
          gidtogroup(cur_audit.egid_group,cur_audit.egid);
      }

      if (cur_audit.sgid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start,i_line_end," SGID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
            gidtogroup(cur_audit.sgid_group,cur_audit.sgid);
        }
        else
          gidtogroup(cur_audit.sgid_group,cur_audit.sgid);
      }

      if (cur_audit.fsgid_isset==true)
      {
        if ( ATOM_enable_scan_extend_UID.load()==true )
        {
          test_delta_pos_find_val=copy_val_istart(cur_audit.fsgid_group,read_buf,i_line_start,i_line_end," FSGID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
            gidtogroup(cur_audit.fsgid_group,cur_audit.fsgid);
        }
        else
          gidtogroup(cur_audit.fsgid_group,cur_audit.fsgid);
      }

      //===============EXT ARG============

      //=================arg=====================
    //======================================================13
    }
    //==========================  ============================================================
    cur_audit_to_array(array_audit,SIZE_AUDIT,cur_audit,n_thread);

  }

  //
  clear_buf(start_i,end_i,buf);
  /*if (DEBUG_DISPLAY==true)
    printf("F_parsing_string_to_auditid[%d] s=%d e=%d <\n",n_thread,start_i,end_i);*/
  return 0;
}
