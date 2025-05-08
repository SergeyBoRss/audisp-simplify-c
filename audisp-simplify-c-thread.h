#ifndef __AUDISP_SIMPLIFY_C_THREAD_H__
#define __AUDISP_SIMPLIFY_C_THREAD_H__

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <mutex>
#include <semaphore.h>
#include <string.h>
#ifdef __cplusplus
    #include <atomic> // for `atomic_*` types in C++
    // This is required for C++ since all `atomic_*` type aliases are in
    // namespace `std`, as in `std::atomic_bool`, for instance, instead of
    // just `atomic_bool`!
    //
    // Using all of namespace std is overkill; just do this instead:
    using atomic_bool   = std::atomic_bool;
    using atomic_int    = std::atomic_int;
    using atomic_size_t = std::atomic_size_t;
#else
    #include <stdatomic.h> // for `atomic_*` types in C
#endif
#include <assert.h>
#include <zlib.h>

#define ON true
#define OFF false
#define COUNT_PARALLEL_PARSING 3
#define SIZE_BUF 262144
#define DEFAULT_READ_BLOCK_SIZE 4096

#define COUNT_SEQ_MEM_PARSING 120
#define COUNT_CACHE_LOGIN 20
#define COUNT_CACHE_GROUP 15
#define COUNT_STAT_UID 20
#define SIZE_AUDIT 600
#define MAX_AUDIT_BEFORE_SAVE_TO_FILE 500
#define SAVE_AUDIT 470
#define STAT_INTERVAL 60
#define ZLEVEL 9
#define CHUNK 16384

using namespace std;

extern bool FILTER;
extern const char *ignorefile;
extern const char *logfile;
extern const char *errfile;
extern const char *storefile;
extern const char *compressfile;
extern const char *uncompressfile;
extern const char *deblogfile;
extern const char *statfile;
extern const char *adminfile;

extern FILE *f_ignorefile;
extern FILE *f_logfile;
extern FILE *f_err;
extern FILE *f_debug;
extern FILE *f_stat;
extern FILE *f_admin;

extern int pid;
extern int ppid;







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

struct s_STAT_UID
{
  int  uid;
  int  count;
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
  //bool   arch_isset;
  //char   arch[12];
  bool   item_isset;
  int    item;
	bool   name_isset;
  char   names[10240];
  char   acct[255];
  char   unit[255];
	char   success[255];

  bool   items_isset;
  int    items;

  bool   exit_isset;
  int    exit;
};

extern pthread_t T_coordinator;
extern pthread_t T_read_STDIN;
extern pthread_t T_relocate_buf_to_start;
extern pthread_t T_parsing_buf;
extern pthread_t T_parsing_line[COUNT_PARALLEL_PARSING];
extern pthread_t T_relocate_audit;
extern pthread_t T_save_file;
extern pthread_t T_stat;
extern pthread_t T_compress_file;

extern atomic_bool ATOM_read_STDIN_run;
extern atomic_int  ATOM_line_read;
extern atomic_int  ATOM_start_seq_mem_relocate;
extern atomic_int  ATOM_end_seq_mem_relocate;
extern atomic_bool ATOM_THREAD_parsing_line_run[COUNT_PARALLEL_PARSING];
extern atomic_bool ATOM_THREAD_parsing_line_processing[COUNT_PARALLEL_PARSING];
extern atomic_int  ATOM_THREAD_start_seq_mem[COUNT_PARALLEL_PARSING];
extern atomic_int  ATOM_THREAD_end_seq_mem[COUNT_PARALLEL_PARSING];
extern atomic_int  ATOM_last_end_seq_mem;
extern atomic_bool ATOM_THREAD_relocate_buf_to_start_run;
extern atomic_bool ATOM_relocate_run;
extern atomic_bool ATOM_relocate_processed;
extern atomic_int  ATOM_relocate_RED_ZONE_start_section;
extern atomic_int  ATOM_relocate_RED_ZONE_end_section;
extern atomic_bool ATOM_THREAD_parsing_buf_run;
extern atomic_int  ATOM_run_parsing_line;
extern atomic_int  ATOM_parsing_line_processed;
extern atomic_int  ATOM_start_seq_mem_parsing[COUNT_SEQ_MEM_PARSING];
extern atomic_int  ATOM_end_seq_mem_parsing[COUNT_SEQ_MEM_PARSING];
extern atomic_int  ATOM_prev_id;
extern atomic_int  ATOM_auditid_thread[COUNT_PARALLEL_PARSING];
extern atomic_int  ATOM_add_to_array_id[COUNT_PARALLEL_PARSING];
extern atomic_int  ATOM_add_to_array_auditid[COUNT_PARALLEL_PARSING];
extern atomic_int  ATOM_start_audit_relocate;
extern atomic_int  ATOM_end_audit_relocate;
extern atomic_int  ATOM_post_relocate;
//extern atomic_bool ATOM_need_save;
extern atomic_bool ATOM_THREAD_save_run;
extern atomic_bool ATOM_save_run;
extern atomic_int  ATOM_save_count;

extern atomic_bool ATOM_STAT;
extern atomic_int  ATOM_STAT_read_byte;
extern atomic_int  ATOM_STAT_read_block;
extern atomic_int  ATOM_STAT_memory_read_block_size;
extern atomic_int  ATOM_STAT_current_read_block_size;
extern atomic_int  ATOM_STAT_read_byte_in_block;
extern atomic_int  ATOM_STAT_filtering;
extern atomic_int  ATOM_STAT_line_auditd;
extern atomic_int  ATOM_STAT_raw_auditd_error;
extern atomic_int  ATOM_STAT_auditd_error;
extern atomic_int  ATOM_STAT_leak;

extern atomic_bool ATOM_cmd_stop;
extern atomic_bool ATOM_cmd_logrotate;
extern atomic_bool ATOM_cmd_logrotated;
extern atomic_bool ATOM_cmd_logrotategz;
extern atomic_bool ATOM_compress_gz;
extern atomic_bool ATOM_cmd_pause;

extern int         size_buf;
extern bool        resize_size_b_char;
extern bool        reduce_size_b_char;
extern char       *read_buf;
extern s_audit    *array_audit;
extern s_pass     *array_pass;
extern s_group    *array_group;
extern s_STAT_UID *array_STAT_UID;
extern s_ignore   *array_ignore;

extern mutex MTX_parsing_line_read_seq;
extern mutex MTX_debug;

extern sem_t SEM_relocate_buf;
extern sem_t SEM_relocate_audit;
extern sem_t SEM_line_read;
extern sem_t SEM_run_parsing_line;

extern sem_t SEM_save;

void  admin_file             (const char *adminfile);
void *F_coordinator          (void* vbuf);
void *F_read_STDIN           (void* vbuf);
void *F_relocate_buf_to_start(void* vbuf);
void *F_parsing_buf          (void* vbuf);
void *F_parsing_line         (void* vbuf);
void  STAT_UID_add           (int c_uid);
void sort_STAT_UID           ();
void clear_STAT_UID          ();
void *F_save_file            (void* varray_audit);
void *F_relocate_audit       (void* varray_audit);
void  write_stat();
void  print_stat();
void *F_stat                 (void*);
void *F_compress_file        (void*);
int   f_zlib                 (char *ufile, char *cfile, int level);

#endif // __AUDISP_SIMPLIFY_C_THREAD_H__
