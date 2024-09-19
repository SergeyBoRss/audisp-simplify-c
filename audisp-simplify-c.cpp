#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
using namespace std;

#define TRUE 1
#define FALSE 0

bool DEBUG=false;
bool DEBUG_display=false;

#define DEF_auid 13613018040941040726
#define DEF_auid_user 13656647726036782632
#define DEF_uid 10955702004391339725
#define DEF_uid_user 3938668164485485161
#define DEF_euid 871798743508355010
#define DEF_euid_user 10948158456794314516
#define DEF_suid 13108325456421036720
#define DEF_suid_user 14864699176026009418
#define DEF_fsuid 14893058268820981764
#define DEF_fsuid_user 8158073555037962446
#define DEF_ouid 9979330787271672132
#define DEF_ouid_user 592126323889268494
#define DEF_agid 8853161959966652772
#define DEF_agid_group 16545232644930974712
#define DEF_gid 6191342109307098523
#define DEF_gid_group 7464545109782502303
#define DEF_egid 14558686735975076768
#define DEF_egid_group 14589685920414363924
#define DEF_sgid 6960200796775488690
#define DEF_sgid_group 10402384097751566302
#define DEF_fsgid 1206170276085818102
#define DEF_fsgid_group 9394881868022378306
#define DEF_ogid 14739186868246060086
#define DEF_ogid_group 15845013486556938626
#define DEF_addr 7795352702591393650
#define DEF_exe 5460895801564100055
#define DEF_key 10219907418818988140
#define DEF_newcontext 377149691622168344
#define DEF_oldcontext 5836347532563258625
#define DEF_terminal 12263889614316767921
#define DEF_tty 11281094534931099108
#define DEF_cipher 15412320365546398282
#define DEF_mac 8176912935715800104
#define DEF_laddr 18328266349478308740
#define DEF_lport 4888577779727190228
#define DEF_SYSCALL 4060446847906805050
#define DEF_cwd 7510364519295740225
#define DEF_cmd 7517683220277778411
#define DEF_command 3240173079180692146
#define DEF_args 15263907219604416316
#define DEF_proctitle 15619253929484439213
#define DEF_saddr 9003893607000676913
#define DEF_avc 6855357130340698807
#define DEF_types 14056168898733065370
#define DEF_acct 10176688188897101994
#define DEF_unit 6749571354727881223
#define DEF_names 13727201964245479823

//from socket.h
/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_RDS		21	/* RDS sockets 			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_LLC		26	/* Linux LLC			*/
#define AF_IB		27	/* Native InfiniBand address	*/
#define AF_MPLS		28	/* MPLS */
#define AF_CAN		29	/* Controller Area Network      */
#define AF_TIPC		30	/* TIPC sockets			*/
#define AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
#define AF_IUCV		32	/* IUCV sockets			*/
#define AF_RXRPC	33	/* RxRPC sockets 		*/
#define AF_ISDN		34	/* mISDN sockets 		*/
#define AF_PHONET	35	/* Phonet sockets		*/
#define AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define AF_CAIF		37	/* CAIF sockets			*/
#define AF_ALG		38	/* Algorithm sockets		*/
#define AF_NFC		39	/* NFC sockets			*/
#define AF_VSOCK	40	/* vSockets			*/
#define AF_KCM		41	/* Kernel Connection Multiplexor*/
#define AF_QIPCRTR	42	/* Qualcomm IPC Router          */
#define AF_SMC		43	/* smc sockets: reserve number for
				 * PF_SMC protocol family that
				 * reuses AF_INET address family
				 */
#define AF_XDP		44	/* XDP sockets			*/
#define AF_MCTP		45	/* Management component
				 * transport protocol
				 */

#define AF_MAX		46	/* For now.. */


int pid;
int ppid;

int size_buf=655360;
int count_cache_login=20;
int count_cache_group=15;
int end_buf=0;
char *read_buf;
FILE *f_ignorefile;
FILE *f_logfile;
FILE *f_debug;

int size_time_t;
time_t timv;
struct tm *local_tm;
struct tm  l_tm;
time_t t_file,t_shtamp,t_now;
char *str_0_time;
char str_unixtime[20];

unsigned int uniq_auditid[2048];
int c_uniq_auditid=0;

int    count_ignore_key=0;
int    max_count_uniq_ignore_key=2048;
size_t *available_hash_ignore_key;
char   str_ignore_key[255];
size_t hash_ignore_key;
char   str_ignore_val[1024];

//const char *ignorefile="/etc/audisp/simplify.ignores";
const char *ignorefile="/etc/audit/simplify.ignores";

const char *logfile="/share/my/audisp-simplify-c/audisp-simplify-c.txt";
//const char *logfile="/var/log/audisp-simplify";
//const char *deblogfile="/tmp/ram/audit/audisp-simplify-c.log";
const char *deblogfile="/share/my/audisp-simplify-c/audisp-simplify-c.log";
//const char *deblogfile="/var/log/audisp-simplify-c.log";

char pos_filter[1024];
char str_tmp[10240];

struct s_ignore
{
  size_t hash_key;
  char value[1024];
};

struct s_pass
{
  int  uid;
  char login[255];
};

struct s_group
{
  int  gid;
  char group[255];
};

struct s_audit
{
  unsigned int auditid;
  time_t t_shtamp;
  int    t_mls;
	bool   auid_isset;
  int    auid;
  char   auid_user[255];
	bool   uid_isset;
  int    uid;
  char   uid_user[255];
	bool   euid_isset;
  int    euid;
  char   euid_user[255];
	bool   suid_isset;
  int    suid;
  char   suid_user[255];
	bool   fsuid_isset;
  int    fsuid;
  char   fsuid_user[255];
	bool   ouid_isset;
  int    ouid;
  char   ouid_user[255];
	bool   agid_isset;
  int    agid;
  char   agid_group[255];
	bool   gid_isset;
  int    gid;
  char   gid_group[255];
	bool   egid_isset;
  int    egid;
  char   egid_group[255];
	bool   sgid_isset;
  int    sgid;
  char   sgid_group[255];
	bool   fsgid_isset;
  int    fsgid;
  char   fsgid_group[255];
	bool   ogid_isset;
  int    ogid;
  char   ogid_group[255];
  char   addr[255];
  char   exe[4096];
  char   hostname[255];
  char   key[255];
  char   newcontext[255];
  char   oldcontext[255];
	bool   pid_isset;
  int    pid;
	bool   ppid_isset;
  int    ppid;
  char   res[255];
  char   seresult[255];
  //char   ses[255];
	bool   ses_isset;
  int    ses;
  //ses 4294967295| );
  char   subj[255];
  char   terminal[255];
  char   tty[255];
  char   direction[255];
  char   cipher[255];
  char   ksize[255];
  char   mac[255];
  char   pfs[255];
  char   spid[255];
  char   laddr[255];
  char   lport[255];

  char   SYSCALL[255];
	bool   syscall_isset;
  int    syscall;

  char   op[255];
  char   vm[255];
  char   cwd[4096];
  char   cmd[10240];
	bool   command_isset;
  char   command[10240];
	bool   argc_isset;
  int    argc;
	bool   args_isset;
  char   args[10240];
  char   proctitle[10240];
  char   errcode[255];
  char   errdesc[255];
  char   saddr[64];
  char   res_saddr[2048];
  char   ip[16];//255.255.255.255

  int    port;
  int    family;
  char   ipv6[40];//FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF

  char   avc[64];
	bool   type_isset;
  char   types[4096];
	bool   name_isset;
  char   names[10240];
  char   acct[255];
  char   unit[255];
	char   success[255];
};

int prev_id=0;
s_audit  *array_audit;
s_pass   *array_pass;
s_group  *array_group;
s_ignore *array_ignore;


int size_audit_reserved_key=0;
const char *audit_reserved_key="auid auid_user uid uid_user euid euid_user suid suid_user fsuid fsuid_user ouid ouid_user agid agid_group gid gid_group egid egid_group sgid sgid_group fsgid fsgid_group ogid ogid_group addr exe key newcontext oldcontext terminal tty cipher mac laddr lport SYSCALL cwd cmd command args proctitle saddr avc types acct unit names success";
size_t *array_hash_uniq_ignore_key;


char name_ai[10];
char str_auditid[12];
char str_mls[4];
char msg[4096];

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

void deblog(char *msg)
{
  if (DEBUG==true)
  {
		double seconds=(double)(clock())/CLOCKS_PER_SEC;
    if ((f_debug=fopen(deblogfile,"a"))==NULL)
    {
      printf("error open debug file %s\n",deblogfile);
      exit(1);
    }
			if (DEBUG_display==true)
			{

				printf("[%f]:%s\n",seconds,msg);
			}
			fprintf(f_debug,"[%f]:%s\n",seconds,msg);
      //fwrite(msg,sizeof(char),strlen(msg),f_debug);
    fclose(f_debug);
  }
}


void print_hash_audit_reserved_key()
{
  char key[255];
  //char val[1024];
	if (DEBUG)
	{
	if ((f_debug=fopen(deblogfile,"a"))==NULL)
    {
      printf("error open debug file %s\n",deblogfile);
      exit(1);
    }
	int i=0;
	for (int j=0; j<strlen(audit_reserved_key); j++)
	{
	  key[i]=audit_reserved_key[j];
	  if ((key[i]==' ') || (key[i]=='\0'))
	  {
		  key[i]='\0';
		  i=0;
			fprintf(f_debug,"#define DEF_%s %zu\n",key,fnv1a_hash(key));
	  }
    else
	   i++;
	}
    fclose(f_debug);
	}
}

int init_available_hash_ignore_key()
{
  char   key[255];
  size_t hash_key;
  int size_audit_reserved_key=0;
  //int i=0;
  for (int j=0; j<strlen(audit_reserved_key); j++)
  {
    if (audit_reserved_key[j]==' ' || audit_reserved_key[j]=='\0')
      size_audit_reserved_key++;
  }
	snprintf(msg,255,"[str:351(init_available_hash_ignore_key]size_audit_reserved_key=%d\n",size_audit_reserved_key);
	deblog(msg);
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
      return true;
  }
  return false;
}

int strpos_istart(char *bufstr,int start_i,char *searchstr)
{
  int indx=-1;
  int n_max=strlen(bufstr);
  if (n_max<=strlen(searchstr))
  {
    return -1;
  }
  if (n_max>size_buf)
    n_max=size_buf;
  int i;
  for (i = start_i; i < n_max; i++)
  {
    if (bufstr[i]==searchstr[0])
    {
      indx=i;
      for (int j=0; j<strlen(searchstr); j++)
        if (bufstr[i+j]!=searchstr[j])
          indx=-1;
      if (indx>=0)
      {
        return indx;
      }
    }
  }
  return indx;
}

bool copy_val_istart(char *val, char *bufstr, int start_i, char *filter, char stop_char,int max_char)
{
  val[0]='\0';
  int indx=-1;
  char end_char;
  if (strlen(filter)<=2)
  {
    deblog("[str:447]filter is short\n");
    return false;
  }
  //end_char=filter[strlen(filter)-1];
  end_char=stop_char;
  int n_max=strlen(bufstr)-strlen(filter)-start_i;
  if (n_max<=0)
  {
    deblog("[str:373]strpos:buf < find str\n");
    deblog(bufstr);
    deblog("\n");
    deblog(filter);
    deblog("\n");
    return false;
  }
  if (n_max>(size_buf-start_i))
    n_max=size_buf-start_i;

  for (int i = start_i; i < (start_i+n_max); i++)
  {
    bool find_char=FALSE;

		if (bufstr[i]=='\n' || bufstr[i]=='\0')
		{
			return false;
		}
    if (bufstr[i]==filter[0])
      find_char=TRUE;
    else
    {
      if ((filter[0]==' ') && (bufstr[i]==0x1d))
      {
        find_char=TRUE;
      }
      else
			{
        find_char=FALSE;
			}
    }
    if (find_char==TRUE)
    {
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
        for (int k=indx+j; k<strlen(bufstr); k++)
        {
          val[k-indx-j]=bufstr[k];
          if (val[k-indx-j]==end_char)
          {
            val[k-indx-j]='\0';
            return true;
          }
          if (k-indx-j>=max_char)
          {
            return false;
          }
        }
        return false;
      }
    }
  }
  return false;
}

int start_posi_end_char(char *bufin,int start_i,char stop_char,int max_char)
{
  int i;
  for (i = start_i; i < (start_i+max_char); i++)
  {
    if (bufin[i]==stop_char)
    {
      return i;
    }
  }
  return i;
}

int copystr_start_posi_end_char(char *bufout,char *bufin,int start_i,char stop_char,int max_char)
{
  bufout[max_char-1]='\0';
  int i;
  for (i = start_i; i < (start_i+max_char); i++)
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
  bufout[i-start_i+1]='\0';
  return i;
}

int clear_uniq_auditid()
{
  int i;
  for (i = 0; i < sizeof(uniq_auditid)/sizeof(unsigned int); i++)
  {
    uniq_auditid[i]=0;
  }
  return i;
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
  deblog("[str:496(add_ignore_key)]over max_count_uniq_ignore_key\n");
  return i;
}

void strnaddchar(char *dst, char add_char, int sz)
{
  int i=0;
  if (sz>0)
  {
    i=strlen(dst);
    if (i<(sz-1))
		{
	    dst[i]=add_char;
	    dst[i+1]='\0';
		}
		else
		{
			snprintf(msg,1024,"[str:630]size>sz sz=%d len=%d str=%s\n",sz,strlen(dst),dst);
			deblog(msg);
		}
	}
}

//=== add string to string, src (size < sz_src) to dst size <  sz_dst
int strnadd(char *dst, char *src, int sz_src, int sz_dst)
{
	int i=0;
	if (sz_src>0 && sz_dst>0)
	{
		int start_i=strlen(dst);
		if (start_i>=sz_dst)
		{
			deblog("[str:650]dst is full\n");
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
				snprintf(msg,1024,"[str:660]write to dst is stop, i_src=%d i_dst=%d src=%s dst=%s\n",i-start_i,i,src,dst);
				deblog(msg);
				return (i-start_i);
			}
		}
		dst[i]='\0';
		return (i-start_i);
	}
	else
		return 0;
}

int add_ignore(size_t key, char *val)
{
  int i=0;
  for (i=0; i<count_ignore_key; i++)
  {
    if (array_ignore[i].hash_key==0 || array_ignore[i].hash_key==key)
    {
      array_ignore[i].hash_key=key;
      if (strlen(array_ignore[i].value)>0)
  	  {
				deblog("[str:664(add_ignore)]append");
        strnaddchar(array_ignore[i].value,' ',1024);
        deblog("[str:666]\n");
  	  }
			sprintf(msg,"[str:668(add_ignore)]i=%d,key=%zu,val=%s",i,key,val);
      deblog(msg);
      strnadd(array_ignore[i].value, val, 255, 1024);
      deblog("[str:671]\n");
      return i;
    }
  }
  return i;
}

int add_auditid(unsigned int test_auditid,int prev_id)
{
  if (uniq_auditid[prev_id]==test_auditid)
		return prev_id;
	// === iterating ===
  int i;
  for (i = 0; i < sizeof(uniq_auditid)/sizeof(unsigned int); i++)
  {
    if (uniq_auditid[i] == 0)
    {
      uniq_auditid[i]=test_auditid;
      return i;
    }
    else
    {
      if (uniq_auditid[i]==test_auditid)
      {
        return i;
      }
    }
  }
	sprintf(msg,"[str:799]error size uniq_auditid is small %d\n",i);
	deblog(msg);
	return 0;
}

int auditid_to_id(s_audit *f_array, int array_count, unsigned int test_auditid)
{
	snprintf(msg,1024,"[str:725(auditid_to_id)]array_count=%d, test_auditid=%d prev_id=%d\n",array_count,test_auditid,prev_id);
	deblog(msg);
	if (f_array[prev_id].auditid==test_auditid)
		return prev_id;
	if ((prev_id+1)<array_count)
	{
		if (f_array[prev_id+1].auditid==test_auditid)
		{
			//snprintf(msg,1024,"[str:725(auditid_to_id)]return %d\n",(prev_id+1));
			//deblog(msg);
			return prev_id+1;
		}
	}
	int i;
  for (i=0; i<array_count; i++)
  {
    if (f_array[i].auditid==test_auditid)
		{
			prev_id=i;
			return i;
		}
		if (f_array[i].auditid==0)
		{
			prev_id=i;
			return i;
		}
	}
	if (i>=array_count)
		i=array_count-1;
	prev_id=i;
	//snprintf(msg,1024,"[str:740(auditid_to_id)]array_count=%d return %d\n",array_count,i);
	//deblog(msg);
	return i;
}

int count_uniq_ignore_key(size_t *a_hash_uniq_ignore_key,int sz)
{
  int i;
  for (i = 0; i < sz; i++)
  {
    if (a_hash_uniq_ignore_key[i]==0)
    {
      sprintf(msg,"[str:711(count_uniq_ignore_key)]count=%d\n",i);
      deblog(msg);
      return i;
    }
  }
  deblog("[str:716(count_uniq_ignore_key)]count_uniq_ignore_key max\n");
  snprintf(msg,1024,"[str:717(count_uniq_ignore_key)]count=%d\n",i);
  deblog(msg);
  return i;
}

int count_uniq_auditid()
{
	if (uniq_auditid[prev_id]==0)
		return prev_id;
	if ((prev_id+1)<sizeof(uniq_auditid)/sizeof(unsigned int))
	{
		if (uniq_auditid[prev_id+1]==0)
			return prev_id+1;
	}

  int i;
  for (i = 0; i < sizeof(uniq_auditid)/sizeof(unsigned int); i++)
  {
    if (uniq_auditid[i] == 0)
      return i;
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
  for (i=0; i<count_cache_login; i++)
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
  for (i=0; i<count_cache_group; i++)
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

bool is_filter(size_t hash_ignore_key,char *val)
{
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
			for (j=0; j<strlen(array_ignore[i].value); j++)
			{
				int j_start_value=0;
				//patern with *
				char cur_value[1024];
				//patern without *
				char cur_clear_value[1024];
				if (array_ignore[i].value[j]==' ' || array_ignore[i].value[j]=='\0')
				{
					int start_j=j_start_value;
					int end_j=j-1;
					copystr_start_posi_end_posi(cur_value,array_ignore[i].value,start_j,end_j,1024);
					if (array_ignore[i].value[start_j]=='*' && start_j<(strlen(array_ignore[i].value)-1))
						start_j++;
					if (array_ignore[i].value[end_j]=='*' && end_j>0)
						end_j--;
					copystr_start_posi_end_posi(cur_clear_value,array_ignore[i].value,start_j,end_j,1024);

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
          					flag_match=false;
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
                snprintf(msg,2048,"[str:873(is_filter)]filtering scan text=%s, filter: key=%s filter=%s\n",val,array_ignore[i].hash_key,array_ignore[i].value);
      					return true;
              }
						}
					}
					j_start_value=j;
				}
			}
		}
    }
  }
  return false;
}

int save_to_file(s_audit *f_array,int array_count)
{
  sprintf(msg,"[str:889(save_to_file)]array_count=%d\n",array_count);
  deblog(msg);

  if ((f_logfile=fopen(logfile,"a"))==NULL)
  {
    printf("error open audit file\n");
    exit(1);
  }
  int i;
  for (i = 0; i < array_count; i++)
  {
		if (f_array[i].auditid>0)
		{
	    // === date time ====
	    local_tm=localtime(&f_array[i].t_shtamp);
	    l_tm=*local_tm;
	    fprintf(f_logfile,"%04d-%02d-%02d %02d:%02d:%02d.%i ",l_tm.tm_year+1900,l_tm.tm_mon+1,l_tm.tm_mday,l_tm.tm_hour,l_tm.tm_min,l_tm.tm_sec,f_array[i].t_mls);
	    fprintf(f_logfile,"auditid=\"%d\" ",f_array[i].auditid);
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
	    fprintf(f_logfile,"\n");
		}
  }
  fclose(f_logfile);
}

int cur_audit_to_array(s_audit *f_array,int array_count,s_audit f_cur)
{
	sprintf(msg,"function cur_audit_to_array: add %d to array\n",f_cur.auditid);
	deblog(msg);
	int i;
	/*for (i = 0; i < array_count; i++)
	{
		sprintf(msg,"[str:1152(cur_audit_to_array)]f_array[%d].auditid=%d\n",i,f_array[i].auditid);
    deblog(msg);
	}
	i=0;
*/

	if (f_array[prev_id].auditid==f_cur.auditid)
	{
		memcpy((&f_array[prev_id]),(&f_cur),sizeof(s_audit));
		return prev_id;
	}

	if (f_array[prev_id].auditid!=0 && (prev_id+1)<array_count)
	{
		if (f_array[prev_id+1].auditid==0 || f_array[prev_id+1].auditid==f_cur.auditid)
		{
			prev_id++;
			memcpy((&f_array[prev_id]),(&f_cur),sizeof(s_audit));
			return prev_id;
		}
	}

  //search key auditid in f_array
  for (i = 0; i < array_count; i++)
  {
    if (f_array[i].auditid==f_cur.auditid)
    {
      memcpy((&f_array[i]),(&f_cur),sizeof(s_audit));
			prev_id=i;
			return i;
		}
		if (f_array[i].auditid==0)
    {
      memcpy((&f_array[i]),(&f_cur),sizeof(s_audit));
			prev_id=i;
			return i;
		}
      /*if (strlen(f_cur.cmd)>0)
      {
        if (strlen(f_array[i].command)>0)
          strnaddchar(f_array[i].command,' ',10240);
        strnadd(f_array[i].command,f_cur.cmd,10240,10240);
      }
      if (strlen(f_cur.args)>0)
      {
        if (strlen(f_array[i].command)>0)
          strnaddchar(f_array[i].command,' ',10240);
        strnadd(f_array[i].command,f_cur.args,10240,10240);
      }
      return i;
    }
    if (f_array[i].auditid==0)
    {
      memcpy((&f_array[i]),(&f_cur),sizeof(s_audit));
      if (strlen(f_cur.cmd)>0)
      {
        if (strlen(f_array[i].command)>0)
          strnaddchar(f_array[i].command,' ',10240);
        strnadd(f_array[i].command,f_cur.cmd,10240,10240);
      }
      if (strlen(f_cur.args)>0)
      {
        if (strlen(f_array[i].command)>0)
          strnaddchar(f_array[i].command,' ',10240);
        strnadd(f_array[i].command,f_cur.args,10240,10240);
      }*/


  }
}

int read_ignorefile_to_buf(char *buf,int sz)
{
  deblog("[str:1129]read_ignorefile_to_buf\n");
  f_ignorefile = fopen(ignorefile,"r");

  if( f_ignorefile == NULL )
  {
      sprintf(msg,"[str:1134(read_ignorefile_to_buf)]no ignore file %s\n",ignorefile);
      deblog(msg);
			count_ignore_key=0;
      return 0;
  }
  array_hash_uniq_ignore_key=(size_t*)malloc(sizeof(size_t)*max_count_uniq_ignore_key);
  memset(array_hash_uniq_ignore_key,0,sizeof(size_t)*max_count_uniq_ignore_key);

  int i=0;
  int i_line_start=0;
  char c_char;
  do
  {
    c_char=getc(f_ignorefile);
    buf[i]=c_char;
    if (c_char=='\n' || c_char=='\0' || c_char==EOF)
    {
      int first_i=-1;
      first_i=copystr_start_posi_end_char(str_ignore_key,buf,i_line_start,'=',255)+1;
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
      sprintf(msg,"\n[str:1167(read_ignorefile_to_buf)]read size to buffer over max size limit sz=%d\n",sz);
      deblog(msg);
      count_ignore_key=count_uniq_ignore_key(array_hash_uniq_ignore_key,max_count_uniq_ignore_key);
      free(array_hash_uniq_ignore_key);
      fclose(f_ignorefile);
      return i;
    }
  } while (c_char!=EOF);
  buf[i]='\0';
  count_ignore_key=count_uniq_ignore_key(array_hash_uniq_ignore_key,max_count_uniq_ignore_key);
  free(array_hash_uniq_ignore_key);
  fclose(f_ignorefile);
  return i;
}

int buf_to_ignore_array(char *buf, int sz)
{
  end_buf=strlen(buf);
  if (end_buf>sz)
    end_buf=sz;

  int i;
  int i_line_start=0;
	int i_ignore_key=0;
  for (i = 0; i<end_buf; i++)
  {
    if (buf[i]=='\n' || buf[i]=='\0')
    {
      int first_i=-1;
      first_i=copystr_start_posi_end_char(str_ignore_key,buf,i_line_start,'=',255)+1;
      if (strlen(str_ignore_key)>0)
      {
        hash_ignore_key=fnv1a_hash(str_ignore_key);
				if (is_hash_in_array_available_hash_ignore_key(hash_ignore_key)==true)
				{
					if (i_ignore_key>=count_ignore_key)
						return count_ignore_key;
					first_i=copystr_start_posi_end_char(str_ignore_val,buf,first_i,'\n',1024);
					if (strlen(str_ignore_val)>0)
					{
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

bool xlate_saddr(s_audit *c_audit, char *saddr)
{
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


int read_STDIN_to_buf(char *buf,int sz,int start_i)
{
	deblog("[str:1447]read_STDIN_to_buf start");
	char c_char;
	int i=start_i;
	int i_line_start=0;
	int prev_id=0;


	clear_uniq_auditid();

	strncpy(pos_filter,"msg=audit(",255);
	while(read(STDIN_FILENO, &c_char, 1) > 0)
  {
		buf[i]=c_char;
		if (buf[i]=='\n' || buf[i]=='\0')
	  {
			int first_i=-1;
			first_i=strpos_istart(buf,i_line_start,pos_filter);
			if (first_i>=0)
			{
	        first_i=first_i+strlen(pos_filter);
	        //unixtime
	        first_i=copystr_start_posi_end_char(str_unixtime,read_buf,first_i,'.',15)+1;
	        //mls
	        first_i=copystr_start_posi_end_char(str_mls,read_buf,first_i,':',3)+1;

	        copystr_start_posi_end_char(str_auditid,read_buf,first_i,')',12);
	        unsigned int auditid=atoi(str_auditid);
	        prev_id=add_auditid(auditid,prev_id);
			}
			i_line_start=i+1;
		}
		i++;
		if (i>=sz)
		{
			if (i_line_start>0)
				buf[i_line_start-1]='\0';
			buf[sz-1]='\0';
			deblog("[str:1484]read_STDIN_to_buf end");
			return i_line_start;
		}
  }
	deblog("[str:1488]read_STDIN_to_buf end");
  return 0;
}

int memcopy_up_to_down(char *buf,int sz,int start_i)
{
	for (int i=start_i; i<sz; i++)
	{
		buf[i-start_i]=buf[i];
	}
	for (int i=(sz-start_i); i<sz; i++)
	{
		buf[i]='\0';
	}
	return sz-start_i;
}


int parsing_buf(char *buf,int sz)
{
	bool last_isset=false;
  if (sizeof(time_t) == sizeof(int))
  	size_time_t=0;
  if (sizeof(time_t) == sizeof(long))
  	size_time_t=1;
  if (sizeof(time_t) == sizeof(long long))
  	size_time_t=2;

	s_audit cur_audit;
	memset(&cur_audit,0,sizeof(s_audit));
	int i=0;
	int i_line_start=0;

  strncpy(pos_filter,"msg=audit(",255);

  for (i = 0; i<strlen(buf); i++)
  {
    //parsing string
    if (buf[i]=='\n' || buf[i]=='\0')
    {
      int first_i=-1;
      first_i=strpos_istart(buf,i_line_start,pos_filter);
      if (first_i>=0)
      {
        first_i=first_i+strlen(pos_filter);
				//unixtime
        first_i=copystr_start_posi_end_char(str_unixtime,buf,first_i,'.',15)+1;
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
        first_i=copystr_start_posi_end_char(str_mls,buf,first_i,':',3)+1;
        cur_audit.t_mls=atoi(str_mls);
        first_i=copystr_start_posi_end_char(str_auditid,buf,first_i,')',12)+1;
        cur_audit.auditid=atoi(str_auditid);
				int find_id_in_auditid=auditid_to_id(array_audit,c_uniq_auditid,cur_audit.auditid);
				//snprintf(msg,255,"[str:1511]cur_audit.auditid=%d find_id_in_auditid=%d\n",cur_audit.auditid,find_id_in_auditid);
				//deblog(msg);

				//=======clear====
				if (array_audit[find_id_in_auditid].auditid==0)
				{
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
				}
				//=======clear====
				/*if (DEBUG_display)
				{
					copystr_start_posi_end_posi(msg,read_buf,i_line_start,i,4096);
					printf("[%d:%d]%s\n",i_line_start,i,msg);
				}*/
				//======================================================13
				last_isset=array_audit[find_id_in_auditid].uid_isset;

				cur_audit.uid_isset=copy_val_istart(cur_audit.uid_user,read_buf,i_line_start," uid=",' ',255);
				if (cur_audit.uid_isset==true)
				{
					cur_audit.uid=atoi(cur_audit.uid_user);
					if (cur_audit.uid>=0)
					{
						copy_val_istart(cur_audit.uid_user,read_buf,i_line_start," UID=\"",'"',255);
						if (strlen(cur_audit.uid_user)==0)
							uidtouser(cur_audit.uid_user,cur_audit.uid);
					}
				}
				if (last_isset==true)
					cur_audit.uid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].auid_isset;
				cur_audit.auid_isset=copy_val_istart(cur_audit.auid_user,read_buf,i_line_start,"auid=",' ',255);
				if (cur_audit.auid_isset==true)
				{
					cur_audit.auid=atoi(cur_audit.auid_user);
					copy_val_istart(cur_audit.auid_user,read_buf,i_line_start," AUID=\"",'"',255);
					if (strlen(cur_audit.auid_user)==0)
						uidtouser(cur_audit.auid_user,cur_audit.auid);
				}
				if (last_isset==true)
					cur_audit.auid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].euid_isset;
				cur_audit.euid_isset=copy_val_istart(cur_audit.euid_user,read_buf,i_line_start," euid=",' ',255);
				if (cur_audit.euid_isset==true)
				{
					cur_audit.euid=atoi(cur_audit.euid_user);
					copy_val_istart(cur_audit.suid_user,read_buf,i_line_start," EUID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.euid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].suid_isset;
				cur_audit.suid_isset=copy_val_istart(cur_audit.suid_user,read_buf,i_line_start," suid=",' ',255);
				if (cur_audit.suid_isset==true)
				{
					cur_audit.suid=atoi(cur_audit.suid_user);
					copy_val_istart(cur_audit.suid_user,read_buf,i_line_start," SUID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.suid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].fsuid_isset;
				cur_audit.fsuid_isset=copy_val_istart(cur_audit.fsuid_user,read_buf,i_line_start," fsuid=",' ',255);
				if (cur_audit.fsuid_isset==true)
				{
					cur_audit.fsuid=atoi(cur_audit.fsuid_user);
					copy_val_istart(cur_audit.fsuid_user,read_buf,i_line_start," FSUID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.fsuid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].ouid_isset;
				cur_audit.ouid_isset=copy_val_istart(cur_audit.ouid_user,read_buf,i_line_start," ouid=",' ',255);
				if (cur_audit.ouid_isset==true)
				{
					cur_audit.ouid=atoi(cur_audit.ouid_user);
					copy_val_istart(cur_audit.ouid_user,read_buf,i_line_start," OUID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.ouid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].gid_isset;
				cur_audit.gid_isset=copy_val_istart(cur_audit.gid_group,read_buf,i_line_start," gid=",' ',255);
				if (cur_audit.gid_isset==true)
				{
					cur_audit.gid=atoi(cur_audit.gid_group);
					copy_val_istart(cur_audit.gid_group,read_buf,i_line_start," GID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.gid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].agid_isset;
				cur_audit.agid_isset=copy_val_istart(cur_audit.agid_group,read_buf,i_line_start," agid=",' ',255);
				if (cur_audit.agid_isset==true)
				{
					cur_audit.agid=atoi(cur_audit.agid_group);
					copy_val_istart(cur_audit.agid_group,read_buf,i_line_start," AGID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.agid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].egid_isset;
				cur_audit.egid_isset=copy_val_istart(cur_audit.egid_group,read_buf,i_line_start," egid=",' ',255);
				if (cur_audit.egid_isset==true)
				{
					cur_audit.egid=atoi(cur_audit.egid_group);
					copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start," EGID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.egid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].sgid_isset;
				cur_audit.sgid_isset=copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start," sgid=",' ',255);
				if (cur_audit.sgid_isset==true)
				{
					cur_audit.sgid=atoi(cur_audit.sgid_group);
					copy_val_istart(cur_audit.sgid_group,read_buf,i_line_start," SGID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.sgid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].fsgid_isset;
				cur_audit.fsgid_isset=copy_val_istart(cur_audit.fsgid_group,read_buf,i_line_start," fsgid=",' ',255);
				if (cur_audit.fsgid_isset==true)
				{
					cur_audit.fsgid=atoi(cur_audit.fsgid_group);
					copy_val_istart(cur_audit.fsgid_group,read_buf,i_line_start," FSGID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.fsgid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].ogid_isset;
				cur_audit.ogid_isset=copy_val_istart(cur_audit.ogid_group,read_buf,i_line_start," ogid=",' ',255);
				if (cur_audit.ogid_isset==true)
				{
					cur_audit.ogid=atoi(cur_audit.ogid_group);
					copy_val_istart(cur_audit.ogid_group,read_buf,i_line_start," OGID=\"",'"',255);
				}
				if (last_isset==true)
					cur_audit.ogid_isset=last_isset;

				copy_val_istart(cur_audit.addr,read_buf,i_line_start," addr=\"",'"',255);
				copy_val_istart(cur_audit.exe,read_buf,i_line_start," exe=\"",'"',4096);
				copy_val_istart(cur_audit.hostname,read_buf,i_line_start," hostname=\"",'"',255);
				copy_val_istart(cur_audit.key,read_buf,i_line_start," key=\"",'"',255);
				copy_val_istart(cur_audit.newcontext,read_buf,i_line_start," newcontext=\"",'"',255);
				copy_val_istart(cur_audit.oldcontext,read_buf,i_line_start," oldcontext=\"",'"',255);
				last_isset=array_audit[find_id_in_auditid].pid_isset;
				cur_audit.pid_isset=copy_val_istart(str_tmp,read_buf,i_line_start," pid=",' ',12);
				if (cur_audit.pid_isset==true)
					cur_audit.pid=atoi(str_tmp);
				if (last_isset==true)
					cur_audit.pid_isset=last_isset;

				last_isset=array_audit[find_id_in_auditid].ppid_isset;
				cur_audit.ppid_isset=copy_val_istart(str_tmp,read_buf,i_line_start," ppid=",' ',12);
				if (cur_audit.ppid_isset==true)
					cur_audit.ppid=atoi(str_tmp);
				if (last_isset==true)
					cur_audit.ppid_isset=last_isset;

				copy_val_istart(cur_audit.res,read_buf,i_line_start," res=",0x1d,11);
				copy_val_istart(cur_audit.seresult,read_buf,i_line_start," seresult=\"",'"',255);
				last_isset=array_audit[find_id_in_auditid].ses_isset;
				cur_audit.ses_isset=copy_val_istart(str_tmp,read_buf,i_line_start," ses=",' ',255);
				if (cur_audit.ses_isset==true)
					cur_audit.ses=atoi(str_tmp);
				if (last_isset==true)
					cur_audit.ses_isset=last_isset;

				copy_val_istart(cur_audit.subj,read_buf,i_line_start," subj=",' ',255);
				copy_val_istart(cur_audit.terminal,read_buf,i_line_start," terminal=\"",'"',255);
				copy_val_istart(cur_audit.tty,read_buf,i_line_start," tty=",' ',255);
				copy_val_istart(cur_audit.direction,read_buf,i_line_start," direction=\"",'"',255);
				copy_val_istart(cur_audit.cipher,read_buf,i_line_start," cipher=\"",'"',255);
				copy_val_istart(cur_audit.ksize,read_buf,i_line_start," ksize=\"",'"',255);
				copy_val_istart(cur_audit.mac,read_buf,i_line_start," mac=\"",'"',255);
				copy_val_istart(cur_audit.pfs,read_buf,i_line_start," pfs=\"",'"',255);
				copy_val_istart(cur_audit.spid,read_buf,i_line_start," spid=\"",'"',255);
				copy_val_istart(cur_audit.laddr,read_buf,i_line_start," laddr=\"",'"',255);
				copy_val_istart(cur_audit.lport,read_buf,i_line_start," lport=\"",'"',255);
				copy_val_istart(cur_audit.SYSCALL,read_buf,i_line_start," SYSCALL=",' ',25);

				last_isset=array_audit[find_id_in_auditid].syscall_isset;
				cur_audit.syscall_isset=copy_val_istart(str_tmp,read_buf,i_line_start," syscall=",' ',25);
				if (cur_audit.syscall_isset==true)
					cur_audit.syscall=atoi(str_tmp);
				if (last_isset==true)
					cur_audit.syscall_isset=last_isset;

				copy_val_istart(cur_audit.op,read_buf,i_line_start," op=",' ',255);
				copy_val_istart(cur_audit.vm,read_buf,i_line_start," vm=",' ',255);
				copy_val_istart(cur_audit.cwd,read_buf,i_line_start," cwd=\"",'"',4096);


				last_isset=array_audit[find_id_in_auditid].command_isset;
				cur_audit.command_isset=copy_val_istart(cur_audit.cmd,read_buf,i_line_start," comm=\"",'"',10240);
				if (cur_audit.command_isset==true)
				{
					if (strlen(array_audit[find_id_in_auditid].command)>0)
					{
						strncpy(cur_audit.command,array_audit[find_id_in_auditid].command,10240);
						strnaddchar(cur_audit.command,';',10240);
					}
					strnadd(cur_audit.command,cur_audit.cmd,10240,10240);
				}
				if (last_isset==true)
					cur_audit.command_isset=last_isset;

				copy_val_istart(cur_audit.proctitle,read_buf,i_line_start," proctitle=\"",'"',10240);
				copy_val_istart(cur_audit.errcode,read_buf,i_line_start," errcode=\"",'"',254);
				copy_val_istart(cur_audit.errdesc,read_buf,i_line_start," errdesc=\"",'"',254);
				copy_val_istart(cur_audit.res_saddr,read_buf,i_line_start," SADDR={",'}',1024);
				if (strlen(cur_audit.res_saddr)==0)
				{
					copy_val_istart(cur_audit.saddr,read_buf,i_line_start," saddr=",' ',63);
					if (strlen(cur_audit.saddr)>0)
					{
						xlate_saddr(&cur_audit,cur_audit.saddr);
					}
				}
				copy_val_istart(cur_audit.avc,read_buf,i_line_start," avc: ",'}',25);
				str_tmp[0]='\0';
				last_isset=array_audit[find_id_in_auditid].type_isset;
				cur_audit.type_isset=copy_val_istart(str_tmp,read_buf,i_line_start,"type=",' ',255);
				if (cur_audit.type_isset==true)
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

				str_tmp[0]='\0';
				last_isset=array_audit[find_id_in_auditid].name_isset;
				cur_audit.name_isset=copy_val_istart(str_tmp,read_buf,i_line_start," name=\"",'"',10240);

				if (cur_audit.name_isset==true)
				{
					if (strlen(array_audit[find_id_in_auditid].names)>0)
					{
						strncpy(cur_audit.names,array_audit[find_id_in_auditid].names,10240);
						strnaddchar(cur_audit.names,',',10240);
					}
					strnadd(cur_audit.names,str_tmp,10240,10240);
				}
				if (last_isset==true)
					cur_audit.name_isset=last_isset;

				sprintf(msg,"[str:1829(parsing_buf)]cur_audit.auditid=%d\n",cur_audit.auditid);
				deblog(msg);
				copy_val_istart(cur_audit.acct,read_buf,i_line_start," acct=\"",'"',255);
				copy_val_istart(cur_audit.unit,read_buf,i_line_start," unit=\"",'"',255);
				copy_val_istart(cur_audit.success,read_buf,i_line_start," success=",' ',255);
				//=================arg=====================
				last_isset=array_audit[find_id_in_auditid].argc_isset;
				cur_audit.argc_isset=copy_val_istart(str_tmp,read_buf,i_line_start," argc=",' ',20);
				bool args_isset=false;
				if (cur_audit.argc_isset==true)
				{
					cur_audit.argc=atoi(str_tmp);
					cur_audit.args[0]='\0';
					//field argc, count arg
					//snprintf(msg,255,"[str:1677]i_line_start=%d,argc=%d\n",i_line_start,cur_audit.argc);
					//deblog(msg);
					for (int ai=0; ai<cur_audit.argc; ai++)
					{
						snprintf(name_ai,9,"a%d=\"",ai);
						str_tmp[0]='\0';
						args_isset=copy_val_istart(str_tmp,read_buf,i_line_start,name_ai,'"',10240);
						if (args_isset!=true)
						{
							snprintf(name_ai,9,"a%d=",ai);
							str_tmp[0]='\0';
							args_isset=copy_val_istart(str_tmp,read_buf,i_line_start,name_ai,' ',10240);
						}
						if (args_isset!=true)
						{

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
						args_isset=copy_val_istart(str_tmp,read_buf,i_line_start,name_ai,' ',10240);
						i_line_start=i_line_start+3;
						if (i_line_start>=strlen(read_buf))
						{

							break;
						}

						if (args_isset==true)
						{
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

				if (last_isset==true)
					cur_audit.argc_isset=last_isset;
				//=================arg=====================
				//======================================================13
      }

      i_line_start=i+1;
			deblog("[str:1904(parsing_buf)]cur_audit_to_array\n");
	   cur_audit_to_array(array_audit,c_uniq_auditid,cur_audit);
    }
  }

}


int filtering(s_audit *f_array,int array_count)
{
	int i;
  for (i = 0; i < array_count; i++)
  {
		if (f_array[i].auditid>0)
		{
			if (f_array[i].pid == pid || f_array[i].pid == ppid)
			{
				snprintf(msg,1024,"[str:1630(filtering)]delete auditid=%u filter pid\n",f_array[i].auditid);
				deblog(msg);
				f_array[i].auditid=0;
			}
			if (f_array[i].ppid == pid || f_array[i].pid == ppid)
			{
				snprintf(msg,1024,"[str:1636(filtering)]delete auditid=%u filter ppid\n",f_array[i].auditid);
				deblog(msg);
				f_array[i].auditid=0;
			}
			if (is_filter(DEF_uid_user,f_array[i].uid_user))
				f_array[i].auditid=0;
			if (is_filter(DEF_auid_user,f_array[i].auid_user))
				f_array[i].auditid=0;
			if (is_filter(DEF_addr,f_array[i].addr))
				f_array[i].auditid=0;
			if (is_filter(DEF_exe,f_array[i].exe))
				f_array[i].auditid=0;
			if (is_filter(DEF_key,f_array[i].key))
				f_array[i].auditid=0;
			if (is_filter(DEF_newcontext,f_array[i].newcontext))
				f_array[i].auditid=0;
			if (is_filter(DEF_oldcontext,f_array[i].oldcontext))
				f_array[i].auditid=0;
			if (is_filter(DEF_proctitle,f_array[i].proctitle))
				f_array[i].auditid=0;
			if (is_filter(DEF_saddr,f_array[i].res_saddr))
				f_array[i].auditid=0;
      if (is_filter(DEF_names,f_array[i].names))
				f_array[i].auditid=0;
		}
	}
}

int main(int argc,char *argv[])
{
	if (argc>1)
	{
 		if (strcmp(argv[1],"-d")==0)
		{
   		DEBUG=true;
			DEBUG_display=false;
		}
 		if (strcmp(argv[1],"-D")==0)
		{
   		DEBUG=true;
			DEBUG_display=true;
		}
	}
	deblog("\n[str:1856]start\n");
	pid=getpid();
  ppid=getppid();

  // === allocate memory ===
  read_buf=(char *)malloc(sizeof(char) * size_buf);
  memset(read_buf,0,sizeof(char) * size_buf);
  array_pass=(s_pass *)malloc(sizeof(s_pass) * count_cache_login);
  memset(array_pass,0,sizeof(s_pass) * count_cache_login);
  array_group=(s_group *)malloc(sizeof(s_group) * count_cache_group);
  memset(array_group,0,sizeof(s_group) * count_cache_group);
  // === allocate memory ===
	// === ignore file ===
	//print_hash_audit_reserved_key();
  size_audit_reserved_key=init_available_hash_ignore_key();
	read_ignorefile_to_buf(read_buf,size_buf);
	if (count_ignore_key>0)
	{
		array_ignore=(s_ignore *)malloc(sizeof(s_ignore) * count_ignore_key);
	  memset(array_ignore,0,sizeof(s_ignore) * count_ignore_key);
		buf_to_ignore_array(read_buf,size_buf);
	}
	// === ignore file ===

	// === clear buf ===
	memset(read_buf,0,sizeof(char) * size_buf);

	int pos_i_in_STDIN=0;
	do
	{
		pos_i_in_STDIN=read_STDIN_to_buf(read_buf,size_buf,pos_i_in_STDIN);
		// === parsing ===
		deblog("[str:1974]parsing...\n");
		c_uniq_auditid=count_uniq_auditid();

		sprintf(msg,"[str:1976]c_uniq_auditid=%d\n",c_uniq_auditid);
		deblog(msg);
		array_audit=(s_audit *)malloc(sizeof(s_audit) * c_uniq_auditid);
		memset(array_audit,0,sizeof(s_audit) * c_uniq_auditid);
		deblog("[str:1718]parsing_buf\n");
		parsing_buf(read_buf,size_buf);
		deblog("[str:1720]filtering\n");
		filtering(array_audit,c_uniq_auditid);
		deblog("[str:1722]save_to_file\n");
		save_to_file(array_audit,c_uniq_auditid);
		deblog("[str:1724]free\n");
		free(array_audit);
		// === parsing ===
		if (pos_i_in_STDIN!=0)
			pos_i_in_STDIN=memcopy_up_to_down(read_buf,size_buf,pos_i_in_STDIN);
	} while(pos_i_in_STDIN!=0);

  free(array_ignore);
  free(available_hash_ignore_key);
  free(array_pass);
  free(array_group);
  free(read_buf);
  return 0;
}
