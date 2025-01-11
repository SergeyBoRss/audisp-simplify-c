#ifndef __AUDISP_SIMPLIFY_C_STR_FUNCTION_H__
#define __AUDISP_SIMPLIFY_C_STR_FUNCTION_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#define SIZE_MSG 1024
extern bool DEBUG;
extern bool DEBUG_DISPLAY;
extern int  DEBUG_LEVEL;
extern char *msg;
extern mutex MTX_deblog;
extern atomic_int ATOM_i_msg;
extern atomic_bool ATOM_save_debug_run;
//extern FILE *f_debug;
extern const char *deblogfile;

extern atomic_int ATOM_prev_delta_strpos_istart;
extern atomic_bool ATOM_enable_scan_extend_UID;

void save_deblog();
void deblog(char *msg);
void debbuf(int istart,int iend,char *buf);
void printbuf(char *buf);
void print_ALL_audit();
void print_audit(s_audit *f_array,int auditid);
void clear_buf(int istart,int iend,char *buf);
int strpos_istart(char *bufstr,int start_i,int end_i,char *searchstr);
int copy_val_istart(char *val, char *bufstr, int start_i, int end_i, char *filter, char stop_char,int max_char,int prev_delta_pos_find_val);
int copystr_start_posi_end_char(char *bufout,char *bufin,int start_i,int end_i,char stop_char,int max_char);
int copystr_start_posi_end_posi(char *bufout,char *bufin,int start_i,int end_i,int sz);
int strnaddchar(char *dst, char add_char, int sz);
int strnadd(char *dst, char *src, int sz_src, int sz_dst);
int auditid_to_id(s_audit *f_array, int array_count, unsigned int test_auditid);
int uidtouser(char *login,uid_t uid);
int gidtogroup(char *grp,gid_t gid);
bool xlate_saddr(s_audit *c_audit, char *saddr);
//int filtering(s_audit *f_array,int array_count,int n_thread);
int cur_audit_to_array(s_audit *f_array,int array_count,s_audit cur_audit,int n_thread);
int count_array_audit(int start_calc /*0*/);
int F_parsing_string_to_auditid(char *buf, int start_i, int end_i, s_audit *f_array,int n_thread);

#endif // __AUDISP_SIMPLIFY_C_STR_FUNCTION_H__
