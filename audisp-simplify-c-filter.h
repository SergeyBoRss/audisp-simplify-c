#ifndef __AUDISP_SIMPLIFY_C_FILTER_H__
#define __AUDISP_SIMPLIFY_C_FILTER_H__


#define HASH_auid 13613018040941040726
#define HASH_auid_user 13656647726036782632
#define HASH_uid 10955702004391339725
#define HASH_uid_user 3938668164485485161
#define HASH_euid 871798743508355010
#define HASH_euid_user 10948158456794314516
#define HASH_suid 13108325456421036720
#define HASH_suid_user 14864699176026009418
#define HASH_fsuid 14893058268820981764
#define HASH_fsuid_user 8158073555037962446
#define HASH_ouid 9979330787271672132
#define HASH_ouid_user 592126323889268494
#define HASH_agid 8853161959966652772
#define HASH_agid_group 16545232644930974712
#define HASH_gid 6191342109307098523
#define HASH_gid_group 7464545109782502303
#define HASH_egid 14558686735975076768
#define HASH_egid_group 14589685920414363924
#define HASH_sgid 6960200796775488690
#define HASH_sgid_group 10402384097751566302
#define HASH_fsgid 1206170276085818102
#define HASH_fsgid_group 9394881868022378306
#define HASH_ogid 14739186868246060086
#define HASH_ogid_group 15845013486556938626
#define HASH_addr 7795352702591393650
#define HASH_exe 5460895801564100055
#define HASH_key 10219907418818988140
#define HASH_newcontext 377149691622168344
#define HASH_oldcontext 5836347532563258625
#define HASH_terminal 12263889614316767921
#define HASH_tty 11281094534931099108
#define HASH_cipher 15412320365546398282
#define HASH_mac 8176912935715800104
#define HASH_laddr 18328266349478308740
#define HASH_lport 4888577779727190228
#define HASH_SYSCALL 4060446847906805050
#define HASH_cwd 7510364519295740225
#define HASH_cmd 7517683220277778411
#define HASH_command 3240173079180692146
#define HASH_args 15263907219604416316
#define HASH_proctitle 15619253929484439213
#define HASH_saddr 9003893607000676913
#define HASH_avc 6855357130340698807
#define HASH_types 14056168898733065370
#define HASH_acct 10176688188897101994
#define HASH_unit 6749571354727881223
#define HASH_names 13727201964245479823

extern int size_audit_reserved_key;
extern const char *audit_reserved_key;
extern size_t *array_hash_uniq_ignore_key;
extern atomic_int ATOM_filtering;
extern atomic_int ATOM_count_ignore_key;
extern size_t *available_hash_ignore_key;

void printignore();
static size_t djb_hash(const char* cp);
static size_t fnv1a_hash(const char* cp);
void print_hash_audit_reserved_key();
int init_available_hash_ignore_key();
bool is_hash_in_array_available_hash_ignore_key(size_t key);
int add_ignore_key(size_t *a_hash_uniq_ignore_key,int sz,size_t key);
int add_ignore(size_t key, char *val);
int count_uniq_ignore_key(size_t *a_hash_uniq_ignore_key,int sz);
bool is_filter_d(size_t hash_ignore_key,int val);
bool is_filter(size_t hash_ignore_key,char *val,bool multi_val);
int read_ignorefile_to_buf(char *buf,int sz);
int buf_to_ignore_array(char *buf, int sz);
int filtering(s_audit *f_array,int array_count);

#endif // __AUDISP_SIMPLIFY_C_FILTER_H__
