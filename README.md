audisp-simplify-c plugin for auditd


project:
  audisp-simplify-c
  audisp-simplify-c-thread.h
  audisp-simplify-c-thread.cpp
  audisp-simplify-c-str-function.h
  audisp-simplify-c-str-function.h
  audisp-simplify-c-filter.h
  audisp-simplify-c-filter.cpp

compiling:
  gcc -c audisp-simplify-c-filter.cpp
  gcc -c audisp-simplify-c-str-function.cpp
  gcc -c audisp-simplify-c-thread.cpp
  gcc -c audisp-simplify-c-d.cpp
  gcc -o audisp-simplify-c audisp-simplify-c.o audisp-simplify-c-thread.o audisp-simplify-c-str-function.o audisp-simplify-c-filter.o -lstdc++ -lm -lpthread -lz


install:
  cp audisp-simplify-c /bin/audisp-simplify-c
  chmod 755 /bin/audisp-simplify-c


  ## for debian based ##
  /etc/audit/plugins.d/simplify-c.conf

    active = yes
    direction = out
    path = /bin/audisp-simplify-c
    type = always
    format = string

  /etc/audit/auditd.conf
    #
    # This file controls the configuration of the audit daemon
    #

    local_events = yes
    write_logs = no
    log_file = /var/log/audit/audit.log
    log_group = adm
    log_format = ENRICHED
    flush = INCREMENTAL_ASYNC
    freq = 50
    max_log_file = 3
    num_logs = 3
    priority_boost = 4
    name_format = NONE
    ##name = mydomain
    max_log_file_action = ROTATE
    space_left = 75
    space_left_action = SYSLOG
    verify_email = yes
    action_mail_acct = root
    admin_space_left = 50
    admin_space_left_action = SUSPEND
    disk_full_action = SUSPEND
    disk_error_action = SUSPEND
    use_libwrap = yes
    ##tcp_listen_port = 60
    tcp_listen_queue = 5
    tcp_max_per_addr = 1
    ##tcp_client_ports = 1024-65535
    tcp_client_max_idle = 0
    transport = TCP
    krb5_principal = auditd
    ##krb5_key_file = /etc/audit/audit.key
    distribute_network = no
    q_depth = 65536
    overflow_action = SYSLOG
    max_restarts = 10
    plugin_dir = /etc/audit/plugins.d
    end_of_event_timeout = 2

  /etc/audit/rules.d/audit.rules

    -D
    -e 1
    -f 0
    -r 0
    -i
    -c

    -w /etc/ -p w -k FILE-etc
    -a exit,always -F arch=b32 -F exit=0 -S execve -k EXECVE
    -a exit,always -F arch=b64 -F exit=0 -S execve -k EXECVE
    -a exit,always -F arch=b32 -F exit=0 -S socketcall -k SOCKETCALL
    -a exit,always -F arch=b64 -F exit=0 -S connect -k CONNECT

  ## for debian based ##



auditd -----> /bin/audisp-simplify-c
                    |
                    |
                    v
              thread F_read_STDIN
               -------------------------------------------------------
  read buffer |type=PATH msg=audit(1737577205.034:1425438): .....     | ----> thread F_parsing_buf
               -------------------------------------------------------                  |
                                                                                        |
                                                                                        v
                                      --------------------------------------------------------
                                      |                          |                           |                                                                           command file /var/lib/audisp-simplify-c
                                      |                          |                           |                                                                                          |
                                      v                          v                           v                                                                                          |
                              thread F_parsing_line      thread F_parsing_line        thread F_parsing_line                                                                             v
                                      |                          |                           |                                                                                  thread F_coordinator
                                      |                          |                           |                                                                                          |
                                      v                          v                           v                                                                                          |
                                   filtering                   filtering                   filtering (/etc/audit/simplify.ignores)                                                      |
                                      |                          |                           |                                                                                          |
                                      |                          |                           |                                                                                          |
                                      |                          |                           |                      array_audit                                                         |
                                      |                          |                           |                     --------------------------------------------                         |
                                      |                          |                            ------------------->|auditid(1425438):                           |                        |
                                      |                          |                                                |auditid(xxxxxxx):                           |                        |
                                      |                          |                                                |auditid(yyyyyyy):                           |                        |
                                      |                          |                                                |                                            |                        |
                                      |                           ----------------------------------------------->|                                            |                        |
                                      |                                                                           |                                            |                        |
                                      |                                                                           |                                            |                        |
                                      --------------------------------------------------------------------------->|                                            |                        |
                                                                                                                  |                                            |                        |
                |                                                                                                 |                                            |                        |
                |                                                                                                 |                                            |                        |
                v                                                                                                 |                                            |                        |
        thread F_stat <------                                                                                     |                                            |                        |
                |                                                                                                 |                                            |                        |
                |                                                                                                 |                                            |                        |
                |                                                                                                 |                                            |                        |
                |                                                                                                  --------------------------------------------                         |
                v                                                                                                                  |                                                    |
       ---------------------------------                                                                                           |                                                    |
      | /var/log/audisp-simplify-c.stat |                                                                                          |                                                    |
       ---------------------------------                                                                                           |                                                    |
                                                                      --------------------------------------------------------------                                                    |
                                                                      |                                                                                                                 |
                                                                      |                                                                                                                 |
                                                                      |                                                                                                                 |
                                                                      |                                                                                                                 |
                                                                      |                                                                             -------------------------------------
                                                                      v                                                                             |
                                                              thread F_save_file                                                                    |
                                                          -----------------------------------------------------------------------------------------------
                                                         |  /var/log/audisp-simplify-c                                                                   |
                                                          -----------------------------------------------------------------------------------------------
                                                                                                                                                    |
                                                                                                                                                    |
                                                                                                                                                    v
                                                                                                     -----------------------------------------------------------
                                                                                                    | /var/log/audisp-simplify-c.(date yyyyddmm_HHMMSS).gzip    |
                                                                                                     -----------------------------------------------------------
