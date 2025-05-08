#ifndef __AUDISP_SIMPLIFY_C_STR_FUNCTION_H__
#define __AUDISP_SIMPLIFY_C_STR_FUNCTION_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#define SIZE_MSG 2048
#define SIZE_PROFILING 1024
extern bool DEBUG;
extern bool DEBUG_DISPLAY;
extern int  DEBUG_LEVEL;
extern bool DEBUG_PROFILE;
extern double DISPLAY_PROFILE_OVER;
extern double DISPLAY_PROFILE_OVER_F_parsing_line;
extern double DISPLAY_PROFILE_OVER_parsing_string_to_auditid;

extern char *msg;
extern mutex MTX_deblog;
extern mutex MTX_save_debug_run;
extern atomic_int ATOM_i_msg;
extern atomic_bool ATOM_debug_simply;
//extern FILE *f_debug;
extern const char *deblogfile;

extern atomic_int ATOM_prev_delta_strpos_istart;
extern atomic_bool ATOM_enable_scan_extend_UID;

void save_err(char *msg);
void save_deblog();
void deblog(char *inmsg);
void debbuf(int istart,int iend,char *buf);
void printbuf(char *buf);
void print_ALL_audit();

void clear_buf(int istart,int iend,char *buf);
void space_buf(int istart,int iend,char *buf);
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

int cur_audit_to_array(s_audit *f_array,int array_count,s_audit cur_audit,int n_thread);
int count_array_audit(int start_calc /*0*/);
int F_parsing_string_to_auditid(char *buf, int start_i, int end_i, s_audit *f_array,int n_thread);
void clear_array_audit_id(s_audit *f_array,int id);
bool find_in_text(char * str, char *search_str, char separate);
int reduce_line(int *i_start,int *i_end,char *buf);

#endif // __AUDISP_SIMPLIFY_C_STR_FUNCTION_H__
