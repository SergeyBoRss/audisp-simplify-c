#include "audisp-simplify-c-thread.h"
#include "audisp-simplify-c-str-function.h"

char *msg;
mutex MTX_deblog;
mutex MTX_save_debug_run;
atomic_int  ATOM_i_msg=0;
atomic_bool ATOM_debug_simply=false;
atomic_int  ATOM_prev_delta_strpos_istart=0;
atomic_bool ATOM_enable_scan_extend_UID=true;

void save_err(char *msg)
{
  //====curent time====
  struct tm *local_tm;
  struct tm  l_tm;
  time_t t_shtamp;
  t_shtamp = time(NULL);
  local_tm=localtime(&t_shtamp);
  l_tm=*local_tm;
  MTX_save_debug_run.lock();
  if ((f_err=fopen(errfile,"a"))!=NULL)
  {
    fprintf(f_err,"%04d.%02d.%02d %02d:%02d:%02d|%s\n",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec,msg);
    fclose(f_err);
  }
  else
    printf("error save err file %s\n",errfile);
  MTX_save_debug_run.unlock();
}

void save_deblog()
{
  if (ATOM_debug_simply.load()==false)
  {
    if (DEBUG==true)
    {
      MTX_save_debug_run.lock();
      if ((f_debug=fopen(deblogfile,"a"))!=NULL)
      {
        fprintf(f_debug,"%s",msg);
        fclose(f_debug);
        ATOM_i_msg.store(0);
      }
      else
        printf("error save debug file %s\n",deblogfile);
      MTX_save_debug_run.unlock();
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
    if (ATOM_debug_simply.load()==true)
    {
      MTX_save_debug_run.lock();
      if ((f_debug=fopen(deblogfile,"a"))==NULL)
      {
        printf("error open debug file %s\n",deblogfile);
        exit(1);
      }
        fwrite(inmsg,sizeof(char),strlen(inmsg),f_debug);
        fprintf(f_debug,"\n");
      fclose(f_debug);
      MTX_save_debug_run.unlock();
    }
    else
    {
      char char_sec[20];
      double seconds=(double)(clock())/CLOCKS_PER_SEC;
      snprintf(char_sec,19,"%f: ",seconds);
      int lensec=strlen(char_sec);
      int lenmsg=strlen(inmsg);
      int i_msg=ATOM_i_msg.load();

      //save to file
      if ((i_msg+lensec+lenmsg+1)>=SIZE_MSG)
      {
        ATOM_i_msg.store(0);
        MTX_save_debug_run.lock();
        if ((f_debug=fopen(deblogfile,"a"))!=NULL)
        {
          //fprintf(f_debug,"[%f]:%s\n",seconds,msg);
          fprintf(f_debug,"%s",msg);
          fclose(f_debug);
          //memzerro
          memset(msg,0,sizeof(char) * SIZE_MSG);
        }
        else
          printf("error open debug file %s\n",deblogfile);
        i_msg=0;
        MTX_save_debug_run.unlock();
      }
      MTX_deblog.lock();
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
    MTX_save_debug_run.lock();
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
    MTX_save_debug_run.unlock();
  }
}

void debbuf(int istart,int iend,char *buf)
{
  if (DEBUG_DISPLAY==true)
  {
    MTX_deblog.lock();
    printf("(%d)[%d][%d]",ATOM_line_read.load(),istart,iend);
    for (int i=istart; i<iend; i++)
      printf("%c",buf[i]);
    printf("\n");
    MTX_deblog.unlock();
  }

  if ((DEBUG==true) && (DEBUG_LEVEL>2))
  {
      FILE *f_debug;
      MTX_save_debug_run.lock();
      if ((f_debug=fopen(deblogfile,"a"))!=NULL)
      {
        fprintf(f_debug,"[%d][%d]{%d}",istart,iend,buf[istart]);
        for (int i=istart; i<iend; i++)
          fprintf(f_debug,"%c",buf[i]);
        fprintf(f_debug,"\n");
        fclose(f_debug);
      }
      else
        printf("error open debug file %s\n",deblogfile);
      MTX_save_debug_run.unlock();
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

void clear_buf(int istart,int iend,char *buf)
{
  for (int i=istart; i<iend; i++)
    buf[i]='\0';
}

void space_buf(int istart,int iend,char *buf)
{
  if ((istart>=0) && (iend<SIZE_BUF))
  {
    if ((DEBUG_DISPLAY==true) || (DEBUG_LEVEL>7))
    {
      //debbuf(istart,iend,buf);
      MTX_deblog.lock();
      printf("=========== space_buf(%d,%d) =========<",istart,iend);
    }
    for (int i=istart; i<iend; i++)
    {
      if ((DEBUG_DISPLAY==true) || (DEBUG_LEVEL>7))
      {
        printf("%c",buf[i]);
      }
      buf[i]=' ';
    }
    if ((DEBUG_DISPLAY==true) || (DEBUG_LEVEL>7))
    {
      printf(">\n");
      MTX_deblog.unlock();
    }
  }
  else
  {
    deblog((char *)"error space_buf()");
  }
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
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;
  if (DEBUG_LEVEL>8)
  {
    deblog((char *)"===== function copy_val_istart ======");
    //debbuf(start_i,end_i,bufstr);
  }
  if (DEBUG_LEVEL>7)
  {
    snprintf(msg,255,"filter %s stop_char[%c] start_i=%d end_i=%d max_char=%d prev_delta_pos_find_val=%d",filter,stop_char,start_i,end_i,max_char,prev_delta_pos_find_val);
	  deblog(msg);
    //debbuf(start_i,end_i,bufstr);
  }

  val[0]='\0';
  int indx=-1;
  if (strlen(filter)<=2)
  {
    if (DEBUG_LEVEL>7)
    {
      deblog((char *)"function copy_val_istart:filter is short");
    }
    if (DEBUG_PROFILE==true)
    {
      end_time=(double)(clock())/CLOCKS_PER_SEC;
      exec_time=end_time-start_time;
      if (exec_time>DISPLAY_PROFILE_OVER)
      {
        snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret -1){return pointer 1}]:%f",filter,prev_delta_pos_find_val,exec_time);
        deblog(msg);
      }
    }
    return -1;
  }

  if (((start_i+prev_delta_pos_find_val+strlen(filter))>end_i) || (prev_delta_pos_find_val<0))
    prev_delta_pos_find_val=0;


    int i_start=start_i+prev_delta_pos_find_val;
    int i_end=end_i;
    //====== start find from position prev_delta_pos_find_val + 1 ======
    int i;
    for (i = (i_start+1); i < i_end; i++)
    {
      bool find_char=false;
      if (bufstr[i]=='\n' || bufstr[i]=='\0')
  		{
        if (DEBUG_PROFILE==true)
        {
          end_time=(double)(clock())/CLOCKS_PER_SEC;
          exec_time=end_time-start_time;
          if (exec_time>DISPLAY_PROFILE_OVER)
          {
            snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret -1){return pointer 2}]:%f",filter,prev_delta_pos_find_val,exec_time);
            deblog(msg);
          }
        }
  			return -1;
  		}
      if (bufstr[i]==filter[1])
      {
        if (filter[0]==bufstr[i-1])
        {
          if (DEBUG_LEVEL>8)
          {
            snprintf(msg,255,"\n^%s^",filter);
            deblog(msg);
          }
          find_char=true;
        }
        else
        {
          if ((filter[0]==' ') && (bufstr[i-1]==0x1d))
          {
            if (DEBUG_LEVEL>8)
            {
              snprintf(msg,255,"\n^%s^",filter);
              deblog(msg);
            }
            find_char=true;
          }
          else
            find_char=false;
        }
      }
      if (find_char==true)
      {
        //===============comparison filter and text=================
        //comparison filter and text
        indx=i-1;
        int j;
        int j_start;
        j_start=2;

        for (j=j_start; j<(strlen(filter)); j++)
        {
          if (bufstr[i-1+j]!=filter[j])
          {
            indx=-1;
            if (DEBUG_LEVEL>8)
            {
              snprintf(msg,255,"- [%c]",bufstr[i-1+j]);
              deblog(msg);
            }
            break;
          }
          else
          {
            if (DEBUG_LEVEL>8)
            {
              snprintf(msg,255,"+ [%c]",bufstr[i-1+j]);
              deblog(msg);
            }

          }
        }

        if (indx>=0)
        {
          if (DEBUG_LEVEL>8)
          {
            deblog((char *)"+++++++++++ find");
          }
          for (int k=indx+j; k<(indx+j+max_char); k++)
          {
            //copy res to val
            if (k>=end_i)
            {
              val[0]='\0';
              if (DEBUG_PROFILE==true)
              {
                end_time=(double)(clock())/CLOCKS_PER_SEC;
                exec_time=end_time-start_time;
                if (exec_time>DISPLAY_PROFILE_OVER)
                {
                  snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret -1){return pointer 3}]:%f",filter,prev_delta_pos_find_val,exec_time);
                  deblog(msg);
                }
              }
              return -1;
            }
            if (DEBUG_LEVEL>7)
            {
              snprintf(msg,255,"copy_val_istart >>>>>>>>>> val[%d-%d-%d]=bufstr[%d]  (%c)",k,indx,j,k,bufstr[k]);
              deblog(msg);
            }
            val[k-indx-j]=bufstr[k];
            if (stop_char==' ')
            {
              if ((val[k-indx-j]==' ') || (val[k-indx-j]=='\0') || (val[k-indx-j]=='\n'))
              {
                val[k-indx-j]='\0';
                if (DEBUG_LEVEL>7)
                {
                  snprintf(msg,255,"copy_val_istart ++++++ val=%s",val);
                  deblog(msg);
                }
                if (DEBUG_PROFILE==true)
                {
                  end_time=(double)(clock())/CLOCKS_PER_SEC;
                  exec_time=end_time-start_time;
                  if (exec_time>DISPLAY_PROFILE_OVER)
                  {
                    snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret %d){return pointer 4}]:%f",filter,prev_delta_pos_find_val,(k-start_i),exec_time);
                    deblog(msg);
                  }
                }
                space_buf(indx,k,bufstr);//replace parsing sting to space char
                return k-start_i;
              }
            }
            else
            {
              if (val[k-indx-j]==stop_char)
              {
                val[k-indx-j]='\0';
                if (DEBUG_PROFILE==true)
                {
                  end_time=(double)(clock())/CLOCKS_PER_SEC;
                  exec_time=end_time-start_time;
                  if (exec_time>DISPLAY_PROFILE_OVER)
                  {
                    snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret %d){return pointer 5}]:%f",filter,prev_delta_pos_find_val,(k-start_i),exec_time);
                    deblog(msg);
                  }
                }
                return k-start_i;
              }
            }

          }

        }
        //not find stop char
        val[0]='\0';
        if (DEBUG_LEVEL>7)
          deblog((char *)"copy_val_istart:not find stop char");
        indx=-1;

        //===============comparison filter and text=================
      }
    }
    val[0]='\0';
    indx=-1;

  //===== not find from prev_delta_pos_find_val
  if (prev_delta_pos_find_val>0)
  {
    int i_start=start_i;
    int i_end=start_i+prev_delta_pos_find_val+strlen(filter);
    //====== start find from start_i and finish i_end======
    int i;
    for (i = (i_start+1); i < i_end; i++)
    {
      bool find_char=false;
      if (bufstr[i]=='\n' || bufstr[i]=='\0')
  		{
        if (DEBUG_PROFILE==true)
        {
          end_time=(double)(clock())/CLOCKS_PER_SEC;
          exec_time=end_time-start_time;
          if (exec_time>DISPLAY_PROFILE_OVER)
          {
            snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret -1){return pointer 6}]:%f",filter,prev_delta_pos_find_val,exec_time);
            deblog(msg);
          }
        }
  			return -1;
  		}
      if (bufstr[i]==filter[1])
      {
        if (filter[0]==bufstr[i-1])
        {
          if (DEBUG_LEVEL>8)
          {
            snprintf(msg,255,"\n^%s^",filter);
            deblog(msg);
          }
          find_char=true;
        }
        else
        {
          if ((filter[0]==' ') && (bufstr[i-1]==0x1d))
          {
            if (DEBUG_LEVEL>8)
            {
              snprintf(msg,255,"\n^%s^",filter);
              deblog(msg);
            }
            find_char=true;
          }
          else
            find_char=false;
        }
      }
      if (find_char==true)
      {
        //===============comparison filter and text=================
        //comparison filter and text
        indx=i-1;
        int j;
        int j_start;
        j_start=2;

        for (j=j_start; j<(strlen(filter)); j++)
        {
          if (bufstr[i-1+j]!=filter[j])
          {
            indx=-1;
            if (DEBUG_LEVEL>8)
            {
              snprintf(msg,255,"- [%c]",bufstr[i-1+j]);
              deblog(msg);
            }
            break;
          }
          else
          {
            if (DEBUG_LEVEL>8)
            {
              snprintf(msg,255,"+ [%c]",bufstr[i-1+j]);
              deblog(msg);
            }

          }
        }

        if (indx>=0)
        {
          if (DEBUG_LEVEL>8)
          {
            deblog((char *)"+++++++++++ find");
          }
          for (int k=indx+j; k<(indx+j+max_char); k++)
          {
            //copy res to val
            if (k>=end_i)
            {
              val[0]='\0';
              if (DEBUG_PROFILE==true)
              {
                end_time=(double)(clock())/CLOCKS_PER_SEC;
                exec_time=end_time-start_time;
                if (exec_time>DISPLAY_PROFILE_OVER)
                {
                  snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret -1){return pointer 7}]:%f",filter,prev_delta_pos_find_val,exec_time);
                  deblog(msg);
                }
              }
              return -1;
            }
            if (DEBUG_LEVEL>7)
            {
              snprintf(msg,255,"copy_val_istart >>>>>>>>>> val[%d-%d-%d]=bufstr[%d]  (%c)",k,indx,j,k,bufstr[k]);
              deblog(msg);
            }
            val[k-indx-j]=bufstr[k];
            if (stop_char==' ')
            {
              if ((val[k-indx-j]==' ') || (val[k-indx-j]=='\0') || (val[k-indx-j]=='\n'))
              {
                val[k-indx-j]='\0';
                if (DEBUG_LEVEL>7)
                {
                  snprintf(msg,255,"copy_val_istart ++++++ val=%s",val);
                  deblog(msg);
                }
                if (DEBUG_PROFILE==true)
                {
                  end_time=(double)(clock())/CLOCKS_PER_SEC;
                  exec_time=end_time-start_time;
                  if (exec_time>DISPLAY_PROFILE_OVER)
                  {
                    snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret %d){return pointer 8}]:%f",filter,prev_delta_pos_find_val,(k-start_i),exec_time);
                    deblog(msg);
                  }
                }
                space_buf(indx,k,bufstr);//replace parsing sting to space char
                return k-start_i;
              }
            }
            else
            {
              if (val[k-indx-j]==stop_char)
              {
                val[k-indx-j]='\0';
                if (DEBUG_PROFILE==true)
                {
                  end_time=(double)(clock())/CLOCKS_PER_SEC;
                  exec_time=end_time-start_time;
                  if (exec_time>DISPLAY_PROFILE_OVER)
                  {
                    snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret %d){return pointer 9}]:%f",filter,prev_delta_pos_find_val,(k-start_i),exec_time);
                    deblog(msg);
                  }
                }
                return k-start_i;
              }
            }

          }

        }
        //not find stop char
        val[0]='\0';
        if (DEBUG_LEVEL>7)
          deblog((char *)"copy_val_istart:not find stop char");
        indx=-1;

        //===============comparison filter and text=================
      }

    }
  }
  //===== not find from prev_delta_pos_find_val


  val[0]='\0';
  if (DEBUG_LEVEL>8)
  {
  	 deblog((char *)"function copy_val_istart:no exist");
  }
  if (DEBUG_PROFILE==true)
  {
    end_time=(double)(clock())/CLOCKS_PER_SEC;
    exec_time=end_time-start_time;
    if (exec_time>DISPLAY_PROFILE_OVER)
    {
      snprintf(msg,255,"profiling[copy_val_istart(filter=%s prev position=%d ret -1){return pointer 10}]:%f",filter,prev_delta_pos_find_val,exec_time);
      deblog(msg);
    }
  }
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
      //space_buf(start_i,i,bufin);
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

//преобразование номера auditid в номер элемента массива
int auditid_to_id(s_audit *f_array, int array_count, unsigned int test_auditid)
{
  char msg[256];
  int prev_id=ATOM_prev_id.load();

  if (ATOM_save_run.load()==true)
  {
    //run process save from 0 to ATOM_save_count
    if (DEBUG_LEVEL>3)
    {
      deblog((char *)"run process save, prev_id<ATOM_save_count");
    }
    if (ATOM_relocate_processed.load()==false)
    {//stage save
      if (prev_id<ATOM_save_count.load())
        prev_id=ATOM_save_count.load();
    }
    else
    {//stage relocate
      if (DEBUG_LEVEL>3)
      {
        deblog((char *)"auditid_to_id stage relocate");
      }
      if (prev_id<ATOM_post_relocate.load())
        prev_id=ATOM_post_relocate.load();
    }
  }


	if (f_array[prev_id].auditid==test_auditid)
  {
    ATOM_prev_id.store(prev_id);
    if (DEBUG_LEVEL>4)
    {
      snprintf(msg,254,"auditid_to_id(%d)-> %d (prev_id=%d) [prev_id]",test_auditid,prev_id,prev_id);
      deblog(msg);
    }
		return prev_id;
  }
  //==== test next el =====
	if ((prev_id+1)<array_count)
	{
		if (f_array[prev_id+1].auditid==test_auditid)
		{
      ATOM_prev_id.store(prev_id+1);
      if (DEBUG_LEVEL>4)
      {
        snprintf(msg,254,"auditid_to_id(%d)-> %d (prev_id=%d) [next]",test_auditid,(prev_id+1),prev_id);
        deblog(msg);
      }
			return prev_id+1;
		}
	}
  //==== test next el =====
  //==== test prev el =====
	if ((prev_id-1)>=0)
	{
		if (f_array[prev_id-1].auditid==test_auditid)
		{
      ATOM_prev_id.store(prev_id-1);
      if (DEBUG_LEVEL>4)
      {
        snprintf(msg,254,"auditid_to_id(%d)-> %d (prev_id=%d) [prev]",test_auditid,(prev_id-1),prev_id);
        deblog(msg);
      }
			return prev_id-1;
		}
	}
  //==== test prev el =====

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
      if (DEBUG_LEVEL>2)
        deblog((char *)"auditid_to_id stage relocate, move start i");
      start_i=ATOM_post_relocate.load();
    }
  }
  for (i=start_i; i<array_count; i++)
  {
    if (f_array[i].auditid==test_auditid)
		{
			prev_id=i;
      ATOM_prev_id.store(i);
      if (DEBUG_LEVEL>4)
      {
        snprintf(msg,254,"auditid_to_id(%d)-> %d (prev_id=%d) [=]",test_auditid,i,prev_id);
        deblog(msg);
      }
			return i;
		}
		if (f_array[i].auditid==0)
		{
			prev_id=i;
      ATOM_prev_id.store(i);
      //if (i>MAX_AUDIT_BEFORE_SAVE_TO_FILE)
        //ATOM_need_save.store(true);
      if (DEBUG_LEVEL>3)
      {
        snprintf(msg,254,"auditid_to_id(%d)-> %d (prev_id=%d) [0]",test_auditid,i,prev_id);
        deblog(msg);
      }
			return i;
		}
	}

	/*if (i>=array_count)
		i=array_count-1;
	prev_id=i;
  ATOM_prev_id.store(i);*/
	//snprintf(msg,1024,"[str:740(auditid_to_id)]array_count=%d return %d\n",array_count,i);
	//deblog(msg);
  if (DEBUG_LEVEL>2)
  {
    snprintf(msg,254,"auditid_to_id(%d)-> %d (prev_id=%d) not find",test_auditid,i,prev_id);
    deblog(msg);
  }
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
  if (DEBUG_LEVEL>3)
    deblog((char *)"xlate_saddr");
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

int cur_audit_to_array(s_audit *f_array,int array_count,s_audit cur_audit,int n_thread)
{
  char msg[512];
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;

  ATOM_STAT_line_auditd.fetch_add(1);

  int find_id_in_auditid=auditid_to_id(f_array,SIZE_AUDIT,cur_audit.auditid);

  if (find_id_in_auditid>MAX_AUDIT_BEFORE_SAVE_TO_FILE)
  {
    if ((ATOM_save_run.load()==false) && (ATOM_relocate_processed.load()==false))
    {
      //save_to file SAVE_AUDIT audit lines
      ATOM_save_count.store(SAVE_AUDIT);
      ATOM_save_run.store(true);
      sem_post(&SEM_save);
    }


  }
  /*while ((find_id_in_auditid>=ATOM_start_audit_relocate.load()) && (find_id_in_auditid<ATOM_end_audit_relocate.load()) && (ATOM_relocate_processed.load()==true))
  {
    //re find auditid
    if (DEBUG_LEVEL>1)
      deblog((char *)"re find auditid_to_id");
    find_id_in_auditid=auditid_to_id(f_array,SIZE_AUDIT,cur_audit.auditid);
  }*/

  if (n_thread>=0)
  ATOM_add_to_array_id[n_thread].store(find_id_in_auditid);
  ATOM_add_to_array_auditid[n_thread].store(cur_audit.auditid);

	//int i;



  if (find_id_in_auditid<SIZE_AUDIT)
  {
    if (f_array[find_id_in_auditid].auditid==0)
    {

      if (DEBUG_LEVEL>3)
      {
        snprintf(msg,511,"clear f_array[%d].auditid",find_id_in_auditid);
        deblog(msg);
      }
      //=====clear=====
      f_array[find_id_in_auditid].exe[0]='\0';
      f_array[find_id_in_auditid].cmd[0]='\0';
      f_array[find_id_in_auditid].command[0]='\0';
      f_array[find_id_in_auditid].args[0]='\0';
      f_array[find_id_in_auditid].proctitle[0]='\0';
      f_array[find_id_in_auditid].types[0]='\0';
      f_array[find_id_in_auditid].names[0]='\0';
      //=====clear=====
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

      //anti dublicate
      //if (strstr(f_array[find_id_in_auditid].command,cur_audit.command)==NULL)
      if (find_in_text(f_array[find_id_in_auditid].command,cur_audit.command,';')==false)
      {
        if (f_array[find_id_in_auditid].command[0]!='\0')
        {
          strnaddchar(f_array[find_id_in_auditid].command,';',10240);
        }
        strnadd(f_array[find_id_in_auditid].command,cur_audit.command,10240,10240);
        if (strlen(f_array[find_id_in_auditid].command)>10200)
        {
          ATOM_STAT_leak.fetch_add(1);
          //DEBUG=true;
          //DEBUG_LEVEL=3;
          deblog((char *)"leak command");
        }
      }

    }
    if (cur_audit.proctitle[0]!='\0')
    {
      strncpy(f_array[find_id_in_auditid].proctitle,cur_audit.proctitle,10240);
      cur_audit.proctitle[0]='\0';
    }
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
      //anti dublicate
      //if (strstr(f_array[find_id_in_auditid].names,cur_audit.names)==NULL)
      if (find_in_text(f_array[find_id_in_auditid].names,cur_audit.names,',')==false)
      {
        if (f_array[find_id_in_auditid].names[0]!='\0')
        {
          if (DEBUG_LEVEL>2)
          {
            if (strlen(f_array[find_id_in_auditid].names)>2048)
            {
              snprintf(msg,510,"==== cur_audit.names=%s",cur_audit.names);
              deblog(msg);
              snprintf(msg,510,"==== f_array[%d].names=%s",find_id_in_auditid,f_array[find_id_in_auditid].names);
              deblog(msg);
            }
          }
          strnaddchar(f_array[find_id_in_auditid].names,',',10240);
        }
        strnadd(f_array[find_id_in_auditid].names,cur_audit.names,10240,10240);
        //memset(cur_audit.names,0,10240);

        if (strlen(f_array[find_id_in_auditid].names)>10200)
        {
          ATOM_STAT_leak.fetch_add(1);
          //DEBUG=true;
          //DEBUG_LEVEL=3;
          deblog((char *)"leak names");
        }
      }
      cur_audit.names[0]='\0';
    }

    if ( cur_audit.items_isset==true )
    {
      f_array[find_id_in_auditid].items_isset=cur_audit.items_isset;
      f_array[find_id_in_auditid].items=cur_audit.items;
    }
    if ( cur_audit.exit_isset==true )
    {
      f_array[find_id_in_auditid].exit_isset=cur_audit.exit_isset;
      f_array[find_id_in_auditid].exit=cur_audit.exit;
    }

    if (cur_audit.acct[0]!='\0')
      strncpy(f_array[find_id_in_auditid].acct,cur_audit.acct,255);
    if (cur_audit.unit[0]!='\0')
      strncpy(f_array[find_id_in_auditid].unit,cur_audit.unit,255);
    if (cur_audit.success[0]!='\0')
      strncpy(f_array[find_id_in_auditid].success,cur_audit.success,255);

    //strnadd(f_array[find_id_in_auditid].command,cur_audit.command,10240,10240);
    if ( cur_audit.args_isset==true )
    {
      //anti dublicate
      //if (strstr(f_array[find_id_in_auditid].args,cur_audit.args)==NULL)
      if (find_in_text(f_array[find_id_in_auditid].args,cur_audit.args,';')==false)
      {
        if (f_array[find_id_in_auditid].args[0]!='\0')
        {
          strnaddchar(f_array[find_id_in_auditid].args,';',10240);
        }
        strnadd(f_array[find_id_in_auditid].args,cur_audit.args,10240,10240);
        if (strlen(f_array[find_id_in_auditid].args)>10200)
        {
          ATOM_STAT_leak.fetch_add(1);
          //DEBUG=true;
          //DEBUG_LEVEL=3;
          deblog((char *)"leak args");
        }
      }
    }
    if (cur_audit.auid_isset==true)
      strncpy(f_array[find_id_in_auditid].auid_user,cur_audit.auid_user,255);
    if (cur_audit.uid_isset==true)
    {
      strncpy(f_array[find_id_in_auditid].uid_user,cur_audit.uid_user,255);

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
      snprintf(msg,255,"[%d]>> cur_audit_to_array: add %d to array[%d] uid=%d",n_thread,cur_audit.auditid,find_id_in_auditid,cur_audit.uid);
      deblog(msg);
    }
  }
  else
  {
    ATOM_STAT_auditd_error.fetch_add(1);
    if (DEBUG_LEVEL>1)
    {
      //snprintf(msg,255,"auditd error\nSIZE_AUDIT=%d\nfind_id_in_auditid=%d\nn_thread=%d\ncur_audit.auditid=%d\nATOM_save_run=%d\nATOM_THREAD_parsing_line_processing=%d",SIZE_AUDIT,find_id_in_auditid,n_thread,cur_audit.auditid,ATOM_save_run.load(),ATOM_THREAD_parsing_line_processing[n_thread].load());
      //deblog(msg);
      snprintf(msg,255,"thread [%d] audit id [%d] not added to audit array\nSIZE_AUDIT=%d\nfind_id_in_auditid=%d",n_thread,cur_audit.auditid,SIZE_AUDIT,find_id_in_auditid);
      deblog(msg);
      save_err(msg);
    }
    return (SIZE_AUDIT-1);
  }
  //ATOM_add_to_array_id[n_thread].store(-1);
  //ATOM_add_to_array_auditid[n_thread].store(0);
  if (DEBUG_PROFILE==true)
  {
    end_time=(double)(clock())/CLOCKS_PER_SEC;
    exec_time=end_time-start_time;
    if (exec_time>DISPLAY_PROFILE_OVER)
    {
      snprintf(msg,255,"profiling[cur_audit_to_array]:%f",exec_time);
      deblog(msg);
    }
  }
  return find_id_in_auditid;
}

int count_array_audit(int start_calc=0)
{
  if (DEBUG_LEVEL>1)
    deblog((char *)"calc count..");
  char msg[128];
  if (start_calc>=SIZE_AUDIT)
  {
    deblog((char *)"in function count_array_audit > size array_audit");
    start_calc=0;
  }
  int prev_id=ATOM_prev_id.load();
  if (start_calc>prev_id)
    prev_id=start_calc;
	if ((prev_id+1)<SIZE_AUDIT)
	{
		if (array_audit[prev_id+1].auditid==0)
    {
      if (DEBUG_LEVEL>2)
      {
        snprintf(msg,127,"count_array_audit: array_audit[%d].auditid=%d",prev_id+1,array_audit[prev_id+1].auditid);
        deblog((char *)msg);
      }
      return (prev_id+1);
    }
	}
  if ((prev_id+2)<SIZE_AUDIT)
	{
		if (array_audit[prev_id+2].auditid==0)
    {
      if (DEBUG_LEVEL>2)
      {
        snprintf(msg,127,"count_array_audit:  array_audit[%d].auditid=%d",prev_id+2,array_audit[prev_id+2].auditid);
        deblog((char *)msg);
      }
      return (prev_id+2);
    }
	}

  int i;
  for (i = start_calc; i < SIZE_AUDIT; i++)
  {
    if (array_audit[i].auditid == 0)
    {
      if (DEBUG_LEVEL>2)
      {
        snprintf(msg,127,"count_array_audit:   array_audit[%d].auditid=%d",i,array_audit[i].auditid);
        deblog((char *)msg);
      }
      return i;
    }

  }
  if (DEBUG_LEVEL>2)
  {
    snprintf(msg,127,"count_array_audit:    array_audit[%d].auditid=%d",i,array_audit[i].auditid);
    deblog((char *)msg);
  }
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
  double exec_time,start_time,end_time;
  if (DEBUG_PROFILE==true)
    start_time=(double)(clock())/CLOCKS_PER_SEC;

  if (DEBUG_LEVEL>6)
  {
    snprintf(msg,255,"--[%d]------------------------------------------------------",n_thread);
    deblog(msg);
  }
  if ((DEBUG_DISPLAY==true) && (DEBUG_LEVEL>0))
  {
    printf("F_parsing_string_to_auditid[%d] s=%d e=%d >",n_thread,start_i,end_i);
    if (DEBUG_LEVEL>1)
      printf(" |line not read:%d| ",ATOM_line_read.load());
    int number_line_in_queue;
    sem_getvalue(&SEM_run_parsing_line,&number_line_in_queue);
    if (DEBUG_LEVEL>2)
      printf(" |sem for read:%d|",number_line_in_queue);
    printf("\n");
  }

  memset(&cur_audit,0,sizeof(s_audit));

  //=========================
  if (DEBUG_LEVEL>5)
    debbuf(i_line_start,i_line_end,buf);
  strncpy(pos_filter,"msg=audit(",16);
  //if (ATOM_prev_delta_strpos_istart.load()>=4)
    //ATOM_prev_delta_strpos_istart.store(ATOM_prev_delta_strpos_istart.load()-4);
  first_i=strpos_istart(buf,i_line_start,i_line_end,pos_filter);
  if (first_i>=0)
  {
    prev_delta_pos_find_val=0;
    int start_i_space=first_i;
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

    if (first_i<(SIZE_BUF-1))
    {

      if (buf[first_i]==':')
      {
        int end_i_space=first_i+1;
        space_buf(start_i_space,end_i_space,buf);
      }
    }

    //snprintf(msg,255,"[thread:%d]function F_parsing_string_to_auditid:find auditid=%s",n_thread,str_auditid);
    //deblog(msg);

    cur_audit.auditid=atoi(str_auditid);
    //========================== парсинг строки ============================================================
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
    cur_audit.items_isset=false;
    cur_audit.exit_isset=false;
    cur_audit.argc_isset=false;
    cur_audit.args_isset=false;
    cur_audit.args[0]='\0';

    //=======clear====

    test_delta_pos_find_val=copy_val_istart(str_tmp,buf,start_i,end_i,(char *)" pid=",' ',12, prev_delta_pos_find_val);
    if (DEBUG_LEVEL>7)
    {
      snprintf(msg,255,"copy_val_istart -> pid=%s",str_tmp);
      deblog(msg);
    }
    if (test_delta_pos_find_val>=0)
    {
      prev_delta_pos_find_val=test_delta_pos_find_val;
      cur_audit.pid_isset=true;
      cur_audit.pid=atoi(str_tmp);

    }
    test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" ppid=",' ',12, prev_delta_pos_find_val);
    if (test_delta_pos_find_val>=0)
    {
      prev_delta_pos_find_val=test_delta_pos_find_val;
      cur_audit.ppid_isset=true;
      cur_audit.ppid=atoi(str_tmp);
    }

    if (cur_audit.pid != pid && cur_audit.ppid != ppid)
    {
    //======================================================13
      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)"node=",' ',255, prev_delta_pos_find_val);

      test_delta_pos_find_val=copy_val_istart(cur_audit.types,read_buf,i_line_start,i_line_end,(char *)"type=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.type_isset=true;
      }
      if (DEBUG_LEVEL>6)
      {
        debbuf(i_line_start,i_line_end,buf);
      }
      reduce_line(&i_line_start,&i_line_end,read_buf);

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" item=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.item_isset=true;
        cur_audit.item=atoi(str_tmp);
      }

      //str_tmp[0]='\0';
      //last_isset=array_audit[find_id_in_auditid].name_isset;

      test_delta_pos_find_val=copy_val_istart(cur_audit.names,read_buf,i_line_start,i_line_end,(char *)" name=\"",'"',10240, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.name_isset=true;
      }
      //if (cur_audit.name_isset==true)
      //{
      //  array_audit[find_id_in_auditid].name_isset=true;
      //  if (strlen(array_audit[find_id_in_auditid].names)>0)
      //  {
      //    strncpy(cur_audit.names,array_audit[find_id_in_auditid].names,10240);
      //    strnaddchar(cur_audit.names,',',10240);
      //  }
      //  strnadd(cur_audit.names,str_tmp,10240,10240);
      //}
      //if (array_audit[find_id_in_auditid].name_isset==true)
      //  cur_audit.name_isset=true;

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)"arch=",' ',11, prev_delta_pos_find_val);
      /*if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.arch_isset=true;
      }*/

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" syscall=",' ',25, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.syscall_isset=true;
        cur_audit.syscall=atoi(str_tmp);
      }

      reduce_line(&i_line_start,&i_line_end,read_buf);
      //====test space_buf
      if (DEBUG_LEVEL>6)
        debbuf(i_line_start,i_line_end,buf);
      //====test space_buf

      test_delta_pos_find_val=copy_val_istart(cur_audit.success,read_buf,i_line_start,i_line_end,(char *)" success=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" exit=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.exit_isset=true;
        cur_audit.exit=atoi(str_tmp);
      }


      reduce_line(&i_line_start,&i_line_end,read_buf);
      //====test space_buf
      if (DEBUG_LEVEL>6)
        debbuf(i_line_start,i_line_end,buf); //<=========== BUG ========= TESTING =====
      //====test space_buf



      test_delta_pos_find_val=copy_val_istart(cur_audit.auid_user,read_buf,i_line_start,i_line_end,(char *)"auid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        if (DEBUG_LEVEL>3)
        {
          snprintf(msg,255,"cur_audit.auid_user=%s",cur_audit.auid_user);
          deblog(msg);
        }
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.auid_isset=true;
        cur_audit.auid=atoi(cur_audit.auid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.uid_user,read_buf,i_line_start,i_line_end," uid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        if (DEBUG_LEVEL>3)
        {
          snprintf(msg,255,"cur_audit.uid_user=%s",cur_audit.uid_user);
          deblog(msg);
        }
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.uid_isset=true;
        cur_audit.uid=atoi(cur_audit.uid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.gid_group,read_buf,i_line_start,i_line_end,(char *)" gid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.gid_isset=true;
        cur_audit.gid=atoi(cur_audit.gid_group);
      }
      //====test space_buf
      if (DEBUG_LEVEL>6)
        debbuf(i_line_start,i_line_end,buf); //<=========== BUG ========= TESTING =====
      //====test space_buf


      test_delta_pos_find_val=copy_val_istart(cur_audit.euid_user,read_buf,i_line_start,i_line_end,(char *)" euid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.euid_isset=true;
        cur_audit.euid=atoi(cur_audit.euid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start,i_line_end,(char *)" suid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.suid_isset=true;
        cur_audit.suid=atoi(cur_audit.suid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.fsuid_user,read_buf,i_line_start,i_line_end,(char *)" fsuid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.fsuid_isset=true;
        cur_audit.fsuid=atoi(cur_audit.fsuid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.ouid_user,read_buf,i_line_start,i_line_end,(char *)" ouid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.ouid_isset=true;
        cur_audit.ouid=atoi(cur_audit.ouid_user);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.ogid_group,read_buf,i_line_start,i_line_end,(char *)" ogid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.ogid_isset=true;
        cur_audit.ogid=atoi(cur_audit.ogid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.agid_group,read_buf,i_line_start,i_line_end,(char *)" agid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.agid_isset=true;
        cur_audit.agid=atoi(cur_audit.agid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.egid_group,read_buf,i_line_start,i_line_end,(char *)" egid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.egid_isset=true;
        cur_audit.egid=atoi(cur_audit.egid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start,i_line_end,(char *)" sgid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.sgid_isset=true;
        cur_audit.sgid=atoi(cur_audit.sgid_group);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.fsgid_group,read_buf,i_line_start,i_line_end,(char *)" fsgid=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.fsgid_isset=true;
        cur_audit.fsgid=atoi(cur_audit.fsgid_group);
      }

      //====test space_buf
      if (DEBUG_LEVEL>6)
        debbuf(i_line_start,i_line_end,buf); //<=========== BUG ========= TESTING =====
      //====test space_buf
      reduce_line(&i_line_start,&i_line_end,read_buf);



      test_delta_pos_find_val=copy_val_istart(cur_audit.addr,read_buf,i_line_start,i_line_end,(char *)" addr=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.exe,read_buf,i_line_start,i_line_end,(char *)" exe=\"",'"',4095, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.hostname,read_buf,i_line_start,i_line_end,(char *)" hostname=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.key,read_buf,i_line_start,i_line_end,(char *)" key=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.newcontext,read_buf,i_line_start,i_line_end,(char *)" newcontext=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.oldcontext,read_buf,i_line_start,i_line_end,(char *)" oldcontext=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;



      test_delta_pos_find_val=copy_val_istart(cur_audit.res,read_buf,i_line_start,i_line_end,(char *)" res=",0x1d,11, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;

      test_delta_pos_find_val=copy_val_istart(cur_audit.seresult,read_buf,i_line_start,i_line_end,(char *)" seresult=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" ses=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.ses_isset=true;
        cur_audit.ses=atoi(str_tmp);
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.subj,read_buf,i_line_start,i_line_end,(char *)" subj=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.terminal,read_buf,i_line_start,i_line_end,(char *)" terminal=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.tty,read_buf,i_line_start,i_line_end,(char *)" tty=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.direction,read_buf,i_line_start,i_line_end,(char *)" direction=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.cipher,read_buf,i_line_start,i_line_end,(char *)" cipher=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.ksize,read_buf,i_line_start,i_line_end,(char *)" ksize=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.mac,read_buf,i_line_start,i_line_end,(char *)" mac=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.pfs,read_buf,i_line_start,i_line_end,(char *)" pfs=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.spid,read_buf,i_line_start,i_line_end,(char *)" spid=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.laddr,read_buf,i_line_start,i_line_end,(char *)" laddr=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.lport,read_buf,i_line_start,i_line_end,(char *)" lport=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.SYSCALL,read_buf,i_line_start,i_line_end,(char *)" SYSCALL=",' ',25, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;



      test_delta_pos_find_val=copy_val_istart(cur_audit.op,read_buf,i_line_start,i_line_end,(char *)" op=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.vm,read_buf,i_line_start,i_line_end,(char *)" vm=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.cwd,read_buf,i_line_start,i_line_end,(char *)" cwd=\"",'"',4096, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;


      test_delta_pos_find_val=copy_val_istart(cur_audit.cmd,read_buf,i_line_start,i_line_end,(char *)" comm=\"",'"',10240, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.command_isset=true;
        strncpy(cur_audit.command,cur_audit.cmd,10240);

      }
      //if (cur_audit.command_isset==true)
      //{
      //  if (strlen(array_audit[find_id_in_auditid].command)>0)
      //  {
      //    strncpy(cur_audit.command,array_audit[find_id_in_auditid].command,10240);
      //    strnaddchar(cur_audit.command,';',10240);
      //  }
      //  strnadd(cur_audit.command,cur_audit.cmd,10240,10240);
      //}

      test_delta_pos_find_val=copy_val_istart(cur_audit.proctitle,read_buf,i_line_start,i_line_end,(char *)" proctitle=\"",'"',10240, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.errcode,read_buf,i_line_start,i_line_end,(char *)" errcode=\"",'"',254, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.errdesc,read_buf,i_line_start,i_line_end,(char *)" errdesc=\"",'"',254, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.res_saddr,read_buf,i_line_start,i_line_end,(char *)" SADDR={",'}',1024, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      if (strlen(cur_audit.res_saddr)==0)
      {
        test_delta_pos_find_val=copy_val_istart(cur_audit.saddr,read_buf,i_line_start,i_line_end,(char *)" saddr=",' ',63, prev_delta_pos_find_val);
        if (test_delta_pos_find_val>=0)
        {
          prev_delta_pos_find_val=test_delta_pos_find_val;
          if (strlen(cur_audit.saddr)>0)
          {
            xlate_saddr(&cur_audit,cur_audit.saddr);
          }
        }
      }

      test_delta_pos_find_val=copy_val_istart(cur_audit.avc,read_buf,i_line_start,i_line_end,(char *)" avc: ",'}',25, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      str_tmp[0]='\0';



      //if (cur_audit.type_isset==true)
      //{
      //  if (strlen(array_audit[find_id_in_auditid].types)>0)
      //  {
      //    strncpy(cur_audit.types,array_audit[find_id_in_auditid].types,4096);
      //    strnaddchar(cur_audit.types,',',4096);
      //  }
      //  strnadd(cur_audit.types,str_tmp,255,4096);
      //}
      //if (last_isset==true)
      //  cur_audit.type_isset=last_isset;






      test_delta_pos_find_val=copy_val_istart(cur_audit.acct,read_buf,i_line_start,i_line_end,(char *)" acct=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;
      test_delta_pos_find_val=copy_val_istart(cur_audit.unit,read_buf,i_line_start,i_line_end,(char *)" unit=\"",'"',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
        prev_delta_pos_find_val=test_delta_pos_find_val;


      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" items=",' ',255, prev_delta_pos_find_val);
      if (test_delta_pos_find_val>=0)
      {
        prev_delta_pos_find_val=test_delta_pos_find_val;
        cur_audit.items_isset=true;
        cur_audit.items=atoi(str_tmp);
      }

      //=================arg=====================

      test_delta_pos_find_val=copy_val_istart(str_tmp,read_buf,i_line_start,i_line_end,(char *)" argc=",' ',20, prev_delta_pos_find_val);
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
          if (strlen(cur_audit.args)>10200)
          {
            ATOM_STAT_leak.fetch_add(1);
            //DEBUG=true;
            //DEBUG_LEVEL=3;
            deblog((char *)"leak cur args");
          }
          str_tmp[0]='\0';
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

          if ((DEBUG_LEVEL>2) && (DEBUG_DISPLAY==true))
          {
            printf("args pos=%d -> %s \n",test_delta_pos_find_val,name_ai);
          }

          if (test_delta_pos_find_val>=0)
            args_isset=true;
          else
            args_isset=false;
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
            str_tmp[0]='\0';
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.auid_user,read_buf,i_line_start,i_line_end,(char *)" AUID=\"",'"',255, prev_delta_pos_find_val);
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            deblog((char *)"ATOM_enable_scan_extend_UID=false");
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.uid_user,read_buf,i_line_start,i_line_end,(char *)" UID=\"",'"',255, prev_delta_pos_find_val);
          if (DEBUG_LEVEL>4)
          {
            if ((DEBUG==true) || (DEBUG_DISPLAY==true))
            {
              snprintf(msg,255," cur_audit(%d) UID=%s",cur_audit.auditid,cur_audit.uid_user);
              deblog(msg);
            }
          }
          if (test_delta_pos_find_val>=0)
            prev_delta_pos_find_val=test_delta_pos_find_val;
          else
          {
            ATOM_enable_scan_extend_UID.store(false);
            if (DEBUG_LEVEL>4)
              deblog((char *)"ATOM_enable_scan_extend_UID=false");

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
          test_delta_pos_find_val=copy_val_istart(cur_audit.gid_group,read_buf,i_line_start,i_line_end,(char *)" GID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start,i_line_end,(char *)" EUID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start,i_line_end,(char *)" SUID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.fsuid_user,read_buf,i_line_start,i_line_end,(char *)" FSUID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.ouid_user,read_buf,i_line_start,i_line_end,(char *)" OUID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.ogid_group,read_buf,i_line_start,i_line_end,(char *)" OGID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.agid_group,read_buf,i_line_start,i_line_end,(char *)" AGID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start,i_line_end,(char *)" EGID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start,i_line_end,(char *)" SGID=\"",'"',255, prev_delta_pos_find_val);
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
          test_delta_pos_find_val=copy_val_istart(cur_audit.fsgid_group,read_buf,i_line_start,i_line_end,(char *)" FSGID=\"",'"',255, prev_delta_pos_find_val);
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
    //========================== парсинг строки ============================================================

    cur_audit_to_array(array_audit,SIZE_AUDIT,cur_audit,n_thread);

  }


  //очистка распарсенной строки
  clear_buf(start_i,end_i,buf);
  if (DEBUG_PROFILE==true)
  {
    end_time=(double)(clock())/CLOCKS_PER_SEC;
    exec_time=end_time-start_time;
    if (exec_time>DISPLAY_PROFILE_OVER_parsing_string_to_auditid)
    {
      snprintf(msg,255,"profiling[F_parsing_string_to_auditid %d]:%f",n_thread,exec_time);
      deblog(msg);
    }
  }
  return 0;
}

void clear_array_audit_id(s_audit *f_array,int id)
{
  f_array[id].auditid=0;

  f_array[id].uid_isset=false;
  f_array[id].uid_user[0]='\0';
  f_array[id].auid_isset=false;
  f_array[id].auid_user[0]='\0';
  f_array[id].euid_isset=false;
  f_array[id].euid_user[0]='\0';
  f_array[id].suid_isset=false;
  f_array[id].suid_user[0]='\0';
  f_array[id].fsuid_isset=false;
  f_array[id].fsuid_user[0]='\0';
  f_array[id].ouid_isset=false;
  f_array[id].ouid_user[0]='\0';
  f_array[id].agid_isset=false;
  f_array[id].agid_group[0]='\0';
  f_array[id].gid_isset=false;
  f_array[id].gid_group[0]='\0';
  f_array[id].egid_isset=false;
  f_array[id].egid_group[0]='\0';
  f_array[id].sgid_isset=false;
  f_array[id].sgid_group[0]='\0';
  f_array[id].fsgid_isset=false;
  f_array[id].fsgid_group[0]='\0';
  f_array[id].ogid_isset=false;
  f_array[id].ogid_group[0]='\0';
  f_array[id].pid_isset=false;
  f_array[id].ppid_isset=false;
  f_array[id].ses_isset=false;
  f_array[id].syscall_isset=false;
  f_array[id].type_isset=false;
  f_array[id].types[0]='\0';
  f_array[id].command_isset=false;
  f_array[id].command[0]='\0';
  f_array[id].name_isset=false;
  f_array[id].names[0]='\0';
  f_array[id].items_isset=false;
  f_array[id].items=0;
  f_array[id].exit_isset=false;
  f_array[id].exit=0;
  f_array[id].argc_isset=false;
  f_array[id].args_isset=false;
  f_array[id].args[0]='\0';
}

bool find_in_text(char * str, char *search_str, char separate)
{
  bool flag_find=false;
  int j;
  if ((strlen(search_str)==0) || (strlen(str)==0))
    return false;
  if (strlen(search_str)>strlen(str))
    return false;

  //for (int i=0; i<=(strlen(str)-strlen(search_str)); i++)
  int i_val_start=0;
  for (int i=0; i<=(strlen(str)-strlen(search_str)); i++)
  {

    if (i==i_val_start)
    {
      if (str[i_val_start]==search_str[0])
      {//find first char
        flag_find=true;

        for (j=1;j<strlen(search_str);j++)
        {
          if ((i_val_start+j)>=strlen(str))
            return false;

          if (str[i_val_start+j]!=search_str[j])
          {
            flag_find=false;
            break;
          }
        }

        if (flag_find==true)
        {
          if ((i_val_start+j)==strlen(str))
            return true;
          if (str[i_val_start+j]==separate)
            return true;
        }
        flag_find=false;
      }
    }
    if (str[i]==separate)
      i_val_start=i+1;
  }
  return false;
}

int reduce_line(int *i_start,int *i_end,char *buf)
{
  //char msg[128];
  int reduse_start_i=*i_start;
  int reduse_end_i=*i_end;
  int i=reduse_start_i;
  if (buf[i]==' ')
  {
    for (i=reduse_start_i;i<reduse_end_i;i++)
    {
      if (buf[i]!=' ')
      {
        *i_start=(i-1);
        if (DEBUG_LEVEL>6)
        {
          deblog((char *)"=== reduce_line ===");
        }
        return (i-1);
      }
    }
  }
  return -1;
}
