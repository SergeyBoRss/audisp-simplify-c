#include "audisp-simplify-c-thread.h"
#include "audisp-simplify-c-str-function.h"
#include "audisp-simplify-c-filter.h"

int size_audit_reserved_key=0;
const char *audit_reserved_key="auid auid_user uid uid_user euid euid_user suid suid_user fsuid fsuid_user ouid ouid_user agid agid_group gid gid_group egid egid_group sgid sgid_group fsgid fsgid_group ogid ogid_group addr exe key newcontext oldcontext terminal tty cipher mac laddr lport SYSCALL cwd cmd command args proctitle saddr avc types acct unit names success";
size_t *array_hash_uniq_ignore_key;
atomic_int ATOM_filtering=0;
atomic_int ATOM_count_ignore_key=0;
int    max_count_uniq_ignore_key=2048;
size_t *available_hash_ignore_key;
char   str_ignore_key[255];
size_t hash_ignore_key;
char   str_ignore_val[1024];


void printignore()
{
  if (DEBUG_DISPLAY==true)
  {
    printf("=================== ignore ====================\n");
    for (int i=0; i<ATOM_count_ignore_key.load(); i++)
    {
      printf("array_ignore[%d] hash=%u val=%s\n",i,array_ignore[i].hash_key,array_ignore[i].value);
    }
    printf("=================== ignore ====================\n");
  }

  if ((DEBUG==true) && (DEBUG_LEVEL>2))
  {
      FILE *f_debug;
      if ((f_debug=fopen(deblogfile,"a"))!=NULL)
      {
        fprintf(f_debug,"=================== ignore ====================\n");
        for (int i=0; i<ATOM_count_ignore_key.load(); i++)
        {
          fprintf(f_debug,"array_ignore[%d] hash=%u val=%s\n",i,array_ignore[i].hash_key,array_ignore[i].value);
        }
        fprintf(f_debug,"=================== ignore ====================\n");
        fclose(f_debug);
      }
      else
        printf("error open debug file %s\n",deblogfile);
  }
}

/* D. J. Bernstein hash function */
static size_t djb_hash(const char* cp)
{
    size_t hash = 5381;
    while (*cp)
        hash = 33 * hash ^ (unsigned char) *cp++;
    return hash;
}


/* Fowler/Noll/Vo (FNV) hash function, variant 1a */
static size_t fnv1a_hash(const char* cp)
{
    size_t hash = 0x811c9dc5;
    while (*cp) {
        hash ^= (unsigned char) *cp++;
        hash *= 0x01000193;
    }
    return hash;
}

void print_hash_audit_reserved_key()
{
  char key[255];
  //char val[1024];
	if (DEBUG==true)
	{
  	if ((f_debug=fopen(deblogfile,"a"))!=NULL)
    {
      int i=0;
      for (int j=0; j<strlen(audit_reserved_key); j++)
      {
        key[i]=audit_reserved_key[j];
        if ((key[i]==' ') || (key[i]=='\0'))
        {
          key[i]='\0';
          i=0;
          fprintf(f_debug,"#define HASH_%s %zu\n",key,fnv1a_hash(key));
        }
        else
         i++;
      }
        fclose(f_debug);
    }
    else
      printf("error open debug file %s\n",deblogfile);
	}
}

int init_available_hash_ignore_key()
{
  char   key[255];
  char   msg[256];
  size_t hash_key;
  int size_audit_reserved_key=0;
  //int i=0;
  for (int j=0; j<strlen(audit_reserved_key); j++)
  {
    if (audit_reserved_key[j]==' ' || audit_reserved_key[j]=='\0')
      size_audit_reserved_key++;
  }
  if ((DEBUG==true) || (DEBUG_DISPLAY==true))
  {
	 snprintf(msg,255,"function init_available_hash_ignore_key:size_audit_reserved_key=%d",size_audit_reserved_key);
	 deblog(msg);
  }
  available_hash_ignore_key=(size_t*)malloc(sizeof(size_t)*size_audit_reserved_key);
	memset(available_hash_ignore_key,0,sizeof(size_t)*size_audit_reserved_key);
  size_audit_reserved_key=0;
  int i=0;
  for (int j=0; j<strlen(audit_reserved_key); j++)
  {
    key[i]=audit_reserved_key[j];
    if ((key[i]==' ') || (key[i]=='\0'))
    {
      key[i]='\0';
      hash_key=fnv1a_hash(key);
      available_hash_ignore_key[size_audit_reserved_key]=hash_key;
      size_audit_reserved_key++;
      i=0;
    }
    else
      i++;
  }
  return size_audit_reserved_key;
}

bool is_hash_in_array_available_hash_ignore_key(size_t key)
{
  int i;
  if (key==0)
	{
		return false;
	}

  for (i = 0; i < size_audit_reserved_key; i++)
  {
    if (available_hash_ignore_key[i]==key)
    {
      //if (DEBUG_LEVEL==3)
        //deblog("find filtering key");

      return true;
    }
  }
  return false;
}

int add_ignore_key(size_t *a_hash_uniq_ignore_key,int sz,size_t key)
{

  int i;
  for (i = 0; i < sz; i++)
  {
    if (a_hash_uniq_ignore_key[i]==0 || a_hash_uniq_ignore_key[i]==key)
    {
      a_hash_uniq_ignore_key[i]=key;
      return i;
    }
  }
  deblog("[add_ignore_key]over max_count_uniq_ignore_key\n");
  return i;
}

int add_ignore(size_t key, char *val)
{
  int i=0;
  char msg[256];
  for (i=0; i<ATOM_count_ignore_key.load(); i++)
  {
    if (array_ignore[i].hash_key==0 || array_ignore[i].hash_key==key)
    {
      array_ignore[i].hash_key=key;
      if (strlen(array_ignore[i].value)>0)
  	  {
        if (DEBUG_LEVEL>0)
				  deblog("function add_ignore:append");
        strnaddchar(array_ignore[i].value,' ',1024);
  	  }
      if (DEBUG_LEVEL>1)
  			if ((DEBUG==true) || (DEBUG_DISPLAY==true))
  			{
  				snprintf(msg,255,"function add_ignore:i=%d,key=%zu,val=%s",i,key,val);
  	      deblog(msg);
  			}
      strnadd(array_ignore[i].value, val, 255, 1024);
      return i;
    }
  }
  return i;
}

int count_uniq_ignore_key(size_t *a_hash_uniq_ignore_key,int sz)
{
  int i;
  char msg[256];
  for (i = 0; i < sz; i++)
  {
    if (a_hash_uniq_ignore_key[i]==0)
    {
      sprintf(msg,"func count_uniq_ignore_key:count=%d",i);
      deblog(msg);
      return i;
    }
  }
  deblog("count_uniq_ignore_key max\n");
  if ((DEBUG==true) || (DEBUG_DISPLAY==true))

    snprintf(msg,255,"function count_uniq_ignore_key:count=%d",i);
    deblog(msg);

  return i;
}

bool is_filter_d(size_t hash_ignore_key,int val)
{
  char msg[256];


  //empty array
  int count_ignore_key=ATOM_count_ignore_key.load();
	if (count_ignore_key==0)
		return false;

  if ( is_hash_in_array_available_hash_ignore_key(hash_ignore_key)==true )
  {
    int i=0;
    for (i=0; i<count_ignore_key; i++)
    {
      //search i in array
      if (array_ignore[i].hash_key==hash_ignore_key)
      {
        //search val in array
        bool flag_find=false;
        int j;
        int j_start_value=0;
        for (j=0; j<=strlen(array_ignore[i].value); j++)
        {
          //find matches

          char cur_ignore_value[1024];
          int  cur_ignore_clear_value=0;

          if ((j==strlen(array_ignore[i].value)) || (array_ignore[i].value[j]==' '))
          {
            int start_j=j_start_value;
            int end_j=j-1;
            j_start_value=j+1;
            copystr_start_posi_end_posi(cur_ignore_value,array_ignore[i].value,start_j,end_j,1024);

            cur_ignore_clear_value=atoi(cur_ignore_value);
            if (val==cur_ignore_clear_value)
            {
              if (DEBUG_LEVEL>2)
              {
                snprintf(msg,255,"dig filtered %s",cur_ignore_value);
                deblog(msg);
              }
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

bool is_filter(size_t hash_ignore_key,char *val, bool multi_val=false)
{
  char msg[256];

  //empty val
  if ((val[0]=='\0') || (val[0]=='\n'))
  	return false;
  //empty array
  int count_ignore_key=ATOM_count_ignore_key.load();
	if (count_ignore_key==0)
		return false;

  if ( is_hash_in_array_available_hash_ignore_key(hash_ignore_key)==true )
  {
    int i=0;
    for (i=0; i<count_ignore_key; i++)
    {
  		//search i in array
  		if (array_ignore[i].hash_key==hash_ignore_key)
  		{
  			//search val in array
  			bool flag_find=false;
  			int j;
        int j_start_value=0;
  			for (j=0; j<=strlen(array_ignore[i].value); j++)
  			{
          //find matches
          //patern with *
  				char cur_ignore_value[1024];
  				//patern without *
  				char cur_ignore_clear_value[1024];

          if ((j==strlen(array_ignore[i].value)) || (array_ignore[i].value[j]==' '))
          {
            int start_j=j_start_value;
  					int end_j=j-1;
            j_start_value=j+1;
            copystr_start_posi_end_posi(cur_ignore_value,array_ignore[i].value,start_j,end_j,1024);

            if (array_ignore[i].value[start_j]=='*' && start_j<(strlen(array_ignore[i].value)-1))
              start_j++;
            if (array_ignore[i].value[end_j]=='*' && end_j>0)
              end_j--;
            copystr_start_posi_end_posi(cur_ignore_clear_value,array_ignore[i].value,start_j,end_j,1024);

            //=========== search ===============
            if (multi_val==true)
            {
              if (array_ignore[i].value[start_j]!='*')
              {
                int end_k;
                end_k=strlen(val)-strlen(cur_ignore_clear_value);
                int k;
                for (k=0;k<end_k;k++)
                {
                  bool flag_match=false;
                  if (cur_ignore_clear_value[0]==val[k])
                  {
                    if (k==0)
                      flag_match=true;
                    else
                    {
                      if (val[k-1]==',')
                        flag_match=true;
                    }

                    if (flag_match==true)
                    {
                      //start comparison
                      //====scan and comparison two string====
                      int m;
                      for (m=1;m<strlen(cur_ignore_clear_value);m++)
                      {
                        if ((m+k)>=strlen(val))
                        {
                          flag_match=false;
                          break;
                        }
                        if (cur_ignore_clear_value[m]!=val[m+k])
                        {
                          flag_match=false;
                          break;
                        }
                      }
                      //====scan and comparison two string====
                      //======res process=====
                      if (flag_match==true)
                      {
                        if ((m+k)<(strlen(val)))
                        {
                          if (array_ignore[i].value[end_j]!='*' && val[m+k]!=',')
                            flag_match=false;
                        }
                        if (flag_match==true)
                        {
                          if (DEBUG_LEVEL>2)
                          {
                            snprintf(msg,255,"filtered %s",cur_ignore_value);
                            deblog(msg);
                          }
                          return true;
                        }
                      }
                      //======res process=====
                    }
                  }
                }
                /*
                if ((array_ignore[i].value[start_j]!='*') && (cur_ignore_clear_value[0]==val[0]))
                {

                }*/
              }
            }
            //=========== search ===============
            //=========== search ===============
            if (multi_val==false)
            {
              if ((array_ignore[i].value[start_j]!='*') && (cur_ignore_clear_value[0]==val[0]))
              {
                bool flag_match=true;
                //start comparison
                //====scan and comparison two string====
                int m;
                for (m=1;m<strlen(cur_ignore_clear_value);m++)
                {
                  if (m>=strlen(val))
                  {
                    flag_match=false;
                    break;
                  }
                  if (cur_ignore_clear_value[m]!=val[m])
                  {
                    flag_match=false;
                    break;
                  }
                }
                //====scan and comparison two string====
                //======res process=====
                if (flag_match==true)
                {
                  if (m<(strlen(val)))
                  {
                    if (array_ignore[i].value[end_j]!='*' && val[m]!=',')
                      flag_match=false;
                  }
                  if (flag_match==true)
                  {
                    if (DEBUG_LEVEL>2)
                    {
                      snprintf(msg,255," filtered %s | val %s",cur_ignore_value,val);
                      deblog(msg);
                    }
                    return true;
                  }
                }
                //======res process=====
              }
            }
            //=========== search ===============

            //=========== search ===============
            if (array_ignore[i].value[start_j]=='*')
            {
              int end_k;
              end_k=strlen(val)-strlen(cur_ignore_clear_value);
              int k;
              for (k=0;k<end_k;k++)
              {
                if (cur_ignore_clear_value[0]==val[k])
                {
                  bool flag_match=true;
                  //start comparison
                  //====scan and comparison two string====
                  int m;
                  for (m=1;m<strlen(cur_ignore_clear_value);m++)
                  {
                    if ((m+k)>=strlen(val))
                    {
                      flag_match=false;
                      break;
                    }
                    if (cur_ignore_clear_value[m]!=val[m+k])
                    {
                      flag_match=false;
                      break;
                    }
                  }
                  //====scan and comparison two string====
                  //======res process=====
                  if (flag_match==true)
                  {
                    if ((m+k)<(strlen(val)))
                    {
                      if (array_ignore[i].value[end_j]!='*' && val[m+k]!=',')
                        flag_match=false;
                    }
                    if (flag_match==true)
                    {
                      if (DEBUG_LEVEL>2)
                      {
                        snprintf(msg,255,"  filtered %s",cur_ignore_value);
                        deblog(msg);
                      }
                      return true;
                    }
                  }
                  //======res process=====
                }
              }
            }
            //=========== search ===============
  /*
            for (k=0;k<end_k;k++)
  					{
              if (cur_clear_value[0]==val[k])
              {
                bool flag_match=true;
                //start comparison
                if (k==0 || cur_value[0]=='*')
        				{
                  int m;
                  //====scan and comparison two string====
                  for (m=1;m<strlen(val);m++)
                  {
                    if (cur_clear_value[m]!=val[k+m])
                    {
                      flag_match=false;
                      if ((DEBUG_LEVEL>2) && (DEBUG_DISPLAY==true))
                          printf("![%c!=%c]!\n",cur_clear_value[m],val[k+m]);
                      break;
                    }
                    else
                    {
                      if ((DEBUG_LEVEL>2) && (DEBUG_DISPLAY==true))
                          printf("%c",val[k+m]);
                    }
                  }
                  //not end string val
                  if (flag_match==true)
                  {
                    if (m<(strlen(val)-1) && cur_value[strlen(cur_value)-1]!='*')
                      flag_match=false;
                  }
                  //====scan and comparison two string====
                }
                else
                {
                  flag_match=false;
                }

                if (flag_match==true)
                {
                  if (DEBUG_LEVEL>2)
                  {
                    if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                    {
                      deblog("find filter text");
                    }
                  }
                  return true;
                }
              }
            }
  */
          }




  /*				int j_start_value=0;
  				//patern with *
  				char cur_value[1024];
  				//patern without *
  				char cur_clear_value[1024];
  				if ((array_ignore[i].value[j]==' ') || (array_ignore[i].value[j]=='\0') || (j==(strlen(array_ignore[i].value)-1)))
  				{
  					int start_j=j_start_value;
  					int end_j=j-1;
  					copystr_start_posi_end_posi(cur_value,array_ignore[i].value,start_j,end_j,1024);
            if ((DEBUG_LEVEL>2) && (DEBUG_DISPLAY==true))
              printf("cur_value:%s\n",cur_value);
  					if (array_ignore[i].value[start_j]=='*' && start_j<(strlen(array_ignore[i].value)-1))
  						start_j++;
  					if (array_ignore[i].value[end_j]=='*' && end_j>0)
  						end_j--;
  					copystr_start_posi_end_posi(cur_clear_value,array_ignore[i].value,start_j,end_j,1024);
            if ((DEBUG_LEVEL>2) && (DEBUG_DISPLAY==true))
              printf("cur_clear_value:%s\n",cur_clear_value);

            int end_k;
  					end_k=strlen(val)-strlen(cur_clear_value);
            int k;
  					for (k=0;k<end_k;k++)
  					{
  						if (cur_clear_value[0]==val[k])
              {
        				bool flag_match=true;
        				if (k==0 || cur_value[0]=='*')
        				{
                  int m;
                  //scan and comparison two string
                  for (m=1;m<strlen(val);m++)
                  {
                    if (cur_clear_value[m]!=val[k+m])
                    {
            					flag_match=false;
                      if (DEBUG_LEVEL>2)
                        if (DEBUG_DISPLAY==true)
                        {
                          printf("![%c!=%c]!\n",cur_clear_value[m],val[k+m]);
                        }
                    }
                    else
                    {
                      if (DEBUG_LEVEL>2)
                        if (DEBUG_DISPLAY==true)
                        {
                          printf("%c",val[k+m]);
                        }
                    }
                  }
                  if (flag_match==true)
                  {
                    if (m<(strlen(val)-1) && cur_value[strlen(cur_value)-1]!='*')
            					flag_match=false;
                  }
        				}
        				else
        					flag_match=false;

        				if (flag_match==true)
                {
                  if (DEBUG_LEVEL>2)
                  {
                    if ((DEBUG==true) || (DEBUG_DISPLAY==true))
                    {
                      snprintf(msg,255,"[is_filter]filtering scan text=%s, filter: key=%s filter=%s\n",val,array_ignore[i].hash_key,array_ignore[i].value);
                      deblog(msg);
                    }
                  }
        					return true;
                }
  						}
  					}
  					j_start_value=j;
  				}*/
  			}
  		}
    }
  }
  return false;
}

int read_ignorefile_to_buf(char *buf,int sz)
{
  char msg[256];
  deblog("function read_ignorefile_to_buf");
  f_ignorefile = fopen(ignorefile,"r");

  if( f_ignorefile == NULL )
  {
    if ((DEBUG==true) || (DEBUG_DISPLAY==true))
    {
      snprintf(msg,255,"function read_ignorefile_to_buf:no ignore file %s",ignorefile);
      deblog(msg);
    }
		ATOM_count_ignore_key.store(0);
    return 0;
  }
  if (DEBUG_LEVEL==3)
  {
    snprintf(msg,255,"max_count_uniq_ignore_key %d",max_count_uniq_ignore_key);
    deblog(msg);
  }
  array_hash_uniq_ignore_key=(size_t*)malloc(sizeof(size_t)*max_count_uniq_ignore_key);
  memset(array_hash_uniq_ignore_key,0,sizeof(size_t)*max_count_uniq_ignore_key);

  //==== read ignore file to buffer =======
  int i=0;
  int i_line_start=0;
	int i_line_end=0;
  char c_char;
  do
  {
    c_char=getc(f_ignorefile);
    buf[i]=c_char;
    if (c_char=='\n' || c_char=='\0' || c_char==EOF)
    {
			i_line_end=i;
      int first_i=-1;
      first_i=copystr_start_posi_end_char(str_ignore_key,buf,i_line_start,i_line_end,'=',255)+1;
      if (strlen(str_ignore_key)>0)
      {
        hash_ignore_key=fnv1a_hash(str_ignore_key);

        if (is_hash_in_array_available_hash_ignore_key(hash_ignore_key)==true)
				{
          add_ignore_key(array_hash_uniq_ignore_key,max_count_uniq_ignore_key,hash_ignore_key);
				}
      }
      i_line_start=i+1;
    }
    i++;
    if (i>=sz)
    {
      if ((DEBUG==true) || (DEBUG_DISPLAY==true))
      {
        snprintf(msg,255,"function read_ignorefile_to_buf:read size to buffer over max size limit sz=%d",sz);
        deblog(msg);
      }
      ATOM_count_ignore_key.store(count_uniq_ignore_key(array_hash_uniq_ignore_key,max_count_uniq_ignore_key));
      free(array_hash_uniq_ignore_key);
      fclose(f_ignorefile);
      return i;
    }
  } while (c_char!=EOF);
  buf[i]='\0';
  ATOM_count_ignore_key.store(count_uniq_ignore_key(array_hash_uniq_ignore_key,max_count_uniq_ignore_key));
  free(array_hash_uniq_ignore_key);
  fclose(f_ignorefile);
  return i;
}

int buf_to_ignore_array(char *buf, int sz)
{
  char msg[256];
  int end_buf=0;
  end_buf=strlen(buf);
  if (end_buf>sz)
    end_buf=sz;

  int i;
  int i_line_start=0;
	int i_line_end=0;
	int i_ignore_key=0;
  //printbuf(buf);
  for (i = 0; i<end_buf; i++)
  {
    //printf("%c",buf[i]);
    if (buf[i]=='\n' || buf[i]=='\0' || i==(end_buf-1))
    {
      //printf("_|");
			i_line_end=i;
      int first_i=-1;
      first_i=copystr_start_posi_end_char(str_ignore_key,buf,i_line_start,i_line_end,'=',255)+1;

      if (strlen(str_ignore_key)>0)
      {
        if (DEBUG_LEVEL==3)
        {
          if ((DEBUG==true) || (DEBUG_DISPLAY==true))
          {
            snprintf(msg,255,"str_ignore_key=%s",str_ignore_key);
            deblog(msg);
          }
        }

        hash_ignore_key=fnv1a_hash(str_ignore_key);
				if (is_hash_in_array_available_hash_ignore_key(hash_ignore_key)==true)
				{
          if (DEBUG_LEVEL==3)
          {
            if ((DEBUG==true) || (DEBUG_DISPLAY==true))
            {
              snprintf(msg,255,"i_ignore_key=%d",i_ignore_key);
              deblog(msg);
            }
          }

					first_i=copystr_start_posi_end_char(str_ignore_val,buf,first_i,i_line_end,'\n',1024);
					if (strlen(str_ignore_val)>0)
					{
            if (DEBUG_LEVEL==3)
            {
              if ((DEBUG==true) || (DEBUG_DISPLAY==true))
              {
                snprintf(msg,255,"str_ignore_val=%s",str_ignore_val);
                deblog(msg);
              }
            }
						add_ignore(hash_ignore_key,str_ignore_val);
						i_ignore_key++;
					}
				}
      }
      i_line_start=i+1;
    }
  }
	return i_ignore_key;
}

int filtering(s_audit *f_array,int array_count)
{
	int i;
  char msg[256];
  int count_filtering=0;
  if (ATOM_count_ignore_key.load()>0)
  {
    for (i = 0; i < array_count; i++)
    {
  		if (f_array[i].auditid>0)
  		{
        if (is_filter_d(HASH_auid,f_array[i].auid))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_auid_user,f_array[i].auid_user))
  				f_array[i].auditid=0;
        if (is_filter_d(HASH_uid,f_array[i].uid))
  				f_array[i].auditid=0;
        if (is_filter(HASH_uid_user,f_array[i].uid_user)==true)
        {
          if ((DEBUG==true) && (DEBUG_LEVEL>2))
          {
            snprintf(msg,255,"filtering auditid=%d f_array[%d].uid_user=%s",f_array[i].auditid,i,f_array[i].uid_user);
            deblog(msg);
          }
  				f_array[i].auditid=0;
        }

        if (is_filter_d(HASH_euid,f_array[i].euid))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_euid_user,f_array[i].euid_user))
  				f_array[i].auditid=0;
        if (is_filter_d(HASH_suid,f_array[i].suid))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_suid_user,f_array[i].suid_user))
  				f_array[i].auditid=0;


  			if (is_filter(HASH_addr,f_array[i].addr))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_exe,f_array[i].exe))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_key,f_array[i].key))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_newcontext,f_array[i].newcontext))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_oldcontext,f_array[i].oldcontext))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_proctitle,f_array[i].proctitle))
  				f_array[i].auditid=0;
  			if (is_filter(HASH_saddr,f_array[i].res_saddr))
  				f_array[i].auditid=0;
        if (is_filter(HASH_names,f_array[i].names,true))
  				f_array[i].auditid=0;

        if (f_array[i].auditid==0)
        {
          count_filtering++;
          ATOM_STAT_filtering.fetch_add(1);
        }
  		}
  	}
  }
  ATOM_filtering.store(count_filtering);
}
