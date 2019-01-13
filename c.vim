
" ctype.h
syn keyword cFunction isalnum isalpha iscntrl isdigit isgraph islower isprint
syn keyword cFunction ispunct isspace isupper isxdigit tolower toupper isblank
syn keyword cFunction isascii toascii _tolower _toupper isalnum_l isalpha_l
syn keyword cFunction isblank_l iscntrl_l isdigit_l isgraph_l islower_l isprint_l
syn keyword cFunction ispunct_l isspace_l isupper_l isxdigit_l tolower_l
syn keyword cFunction toupper_l

" time.h
syn keyword cFunction times sysconf asctime clock ctime difftime gmtime localtime
syn keyword cFunction mktime strftime time strptime asctime_r ctime_r gmtime_r
syn keyword cFunction localtime_r tzset clock_getres clock_gettime clock_settime
syn keyword cFunction nanosleep clock_getcpuclockid strftime_l tzsetwall
syn keyword cFunction timelocal timegm timeoff

" sys/uio.h
syn keyword cFunction preadv pwritev readv writev ureadc iovec_copyin iovec_free
syn keyword cFunction dofilereadv dofilewritev

" sys/mman.h
syn keyword cFunction mmap mprotect munmap msync mlock munlock mlockall
syn keyword cFunction munlockall madvise mincore minherit mquery posix_madvise
syn keyword cFunction shm_open shm_unlink shm_mkstemp

" sys/fcntl.h
syn keyword cFunction open fcntl flock creat openat

" arpa/inet.h
syn keyword cFunction inet inet_addr inet_ntoa inet_ntop inet_pton inet_aton
syn keyword cFunction inet_lnaof inet_makeaddr inet_neta inet_netof inet_network
syn keyword cFunction inet_net_ntop inet_net_pton

" sched.h
syn keyword cFunction sched_setparam sched_getparam sched_setscheduler
syn keyword cFunction sched_getscheduler sched_yield sched_get_priority_max
syn keyword cFunction sched_get_priority_min sched_rr_get_interval

" sys/socket.h
syn keyword cFunction sockopt shutdown getsockopt flag listen accept bind connect
syn keyword cFunction getpeername getsockname recv recvfrom recvmsg send sendto
syn keyword cFunction sendmsg setsockopt sockatmark socket socketpair accept4
syn keyword cFunction getpeereid getrtable setrtable pfctlinput sstosa

" regex.h
syn keyword cFunction regcomp regerror regexec regfree

" dirent.h
syn keyword cFunction getdents opendir fdopendir readdir rewinddir closedir
syn keyword cFunction telldir seekdir readdir_r scandir alphasort dirfd

" poll.h
syn keyword cFunction poll

" stdlib.h
syn keyword cFunction abort abs atexit atof atoi atol bsearch calloc div exit
syn keyword cFunction _Exit free getenv labs ldiv malloc freezero reallocarray
syn keyword cFunction recallocarray qsort rand realloc srand srand_deterministic
syn keyword cFunction strtod strtof strtol strtold strtoul system mblen mbstowcs
syn keyword cFunction wctomb mbtowc wcstombs rand_r drand48 erand48 jrand48
syn keyword cFunction lcong48 lcong48_deterministic lrand48 mrand48 nrand48
syn keyword cFunction seed48 seed48_deterministic srand48 srand48_deterministic
syn keyword cFunction putenv ecvt fcvt gcvt mktemp a64l l64a initstate random
syn keyword cFunction setstate srandom srandom_deterministic realpath ttyslot
syn keyword cFunction valloc mkstemp atoll llabs lldiv strtoll strtoull
syn keyword cFunction posix_memalign setenv unsetenv ptsname grantpt unlockpt
syn keyword cFunction posix_openpt mkdtemp getsubopt mkostemp getbsize cgetcap
syn keyword cFunction cgetclose cgetent cgetfirst cgetmatch cgetnext cgetnum
syn keyword cFunction cgetset cgetusedb cgetstr cgetustr daemon devname
syn keyword cFunction getloadavg getprogname setprogname mkstemps mkostemps
syn keyword cFunction heapsort mergesort radixsort sradixsort srandomdev strtonum
syn keyword cFunction setproctitle qabs qdiv strtoq strtouq arc4random
syn keyword cFunction arc4random_uniform arc4random_buf

" pthread.h
syn keyword cFunction pthread_atfork pthread_attr_destroy pthread_attr_getstack
syn keyword cFunction pthread_attr_getstacksize pthread_attr_getstackaddr
syn keyword cFunction pthread_attr_getguardsize pthread_attr_getdetachstate
syn keyword cFunction pthread_attr_init pthread_attr_setstacksize
syn keyword cFunction pthread_attr_setstack pthread_attr_setstackaddr
syn keyword cFunction pthread_attr_setguardsize pthread_attr_setdetachstate
syn keyword cFunction pthread_cleanup_pop pthread_cleanup_push
syn keyword cFunction pthread_condattr_destroy pthread_condattr_init
syn keyword cFunction pthread_cond_broadcast pthread_cond_destroy
syn keyword cFunction pthread_cond_init pthread_cond_signal
syn keyword cFunction pthread_cond_timedwait pthread_cond_wait pthread_create
syn keyword cFunction pthread_detach pthread_equal pthread_exit
syn keyword cFunction pthread_getspecific pthread_join pthread_key_create
syn keyword cFunction pthread_key_delete pthread_kill pthread_mutexattr_init
syn keyword cFunction pthread_mutexattr_destroy pthread_mutexattr_gettype
syn keyword cFunction pthread_mutexattr_settype pthread_mutex_destroy
syn keyword cFunction pthread_mutex_init pthread_mutex_lock
syn keyword cFunction pthread_mutex_timedlock pthread_mutex_trylock
syn keyword cFunction pthread_mutex_unlock pthread_once pthread_rwlock_destroy
syn keyword cFunction pthread_rwlock_init pthread_rwlock_rdlock
syn keyword cFunction pthread_rwlock_timedrdlock pthread_rwlock_timedwrlock
syn keyword cFunction pthread_rwlock_tryrdlock pthread_rwlock_trywrlock
syn keyword cFunction pthread_rwlock_unlock pthread_rwlock_wrlock
syn keyword cFunction pthread_rwlockattr_init pthread_rwlockattr_getpshared
syn keyword cFunction pthread_rwlockattr_setpshared pthread_rwlockattr_destroy
syn keyword cFunction pthread_self pthread_setspecific pthread_cancel
syn keyword cFunction pthread_setcancelstate pthread_setcanceltype
syn keyword cFunction pthread_testcancel pthread_getprio pthread_setprio
syn keyword cFunction pthread_yield pthread_mutexattr_getprioceiling
syn keyword cFunction pthread_mutexattr_setprioceiling
syn keyword cFunction pthread_mutex_getprioceiling pthread_mutex_setprioceiling
syn keyword cFunction pthread_mutexattr_getprotocol pthread_mutexattr_setprotocol
syn keyword cFunction pthread_condattr_getclock pthread_condattr_setclock
syn keyword cFunction pthread_attr_getinheritsched pthread_attr_getschedparam
syn keyword cFunction pthread_attr_getschedpolicy pthread_attr_getscope
syn keyword cFunction pthread_attr_setinheritsched pthread_attr_setschedparam
syn keyword cFunction pthread_attr_setschedpolicy pthread_attr_setscope
syn keyword cFunction pthread_getschedparam pthread_setschedparam
syn keyword cFunction pthread_getconcurrency pthread_setconcurrency
syn keyword cFunction pthread_barrier_init pthread_barrier_destroy
syn keyword cFunction pthread_barrier_wait pthread_barrierattr_init
syn keyword cFunction pthread_barrierattr_destroy pthread_barrierattr_getpshared
syn keyword cFunction pthread_barrierattr_setpshared pthread_spin_init
syn keyword cFunction pthread_spin_destroy pthread_spin_trylock pthread_spin_lock
syn keyword cFunction pthread_spin_unlock pthread_getcpuclockid

" net/if.h
syn keyword cFunction if_nametoindex if_indextoname if_nameindex if_freenameindex
syn keyword cFunction if_alloc_sadl if_free_sadl if_attach if_attach_queues
syn keyword cFunction if_attach_iqueues if_attach_ifq if_attachtail if_attachhead
syn keyword cFunction if_deactivate if_detach if_down if_downall
syn keyword cFunction if_link_state_change if_up if_getdata ifinit ifioctl
syn keyword cFunction ifpromisc if_creategroup if_addgroup if_delgroup
syn keyword cFunction if_group_routechange ifunit if_get if_put ifnewlladdr
syn keyword cFunction if_congestion if_congested unhandled_af if_setlladdr net_tq

" sys/stat.h
syn keyword cFunction chmod fstat mknod mkdir mkfifo stat umask fchmod lstat
syn keyword cFunction fchmodat fstatat mkdirat mkfifoat mknodat utimensat
syn keyword cFunction futimens chflags chflagsat fchflags isfdtype

" stdio.h
syn keyword cFunction ungetc getc putc malloc fgetln fseek setvbuf clearerr
syn keyword cFunction dprintf fclose feof ferror fflush fgetc fgetpos fgets fopen
syn keyword cFunction fprintf fputc fputs fread freopen fscanf fseeko fsetpos
syn keyword cFunction ftell ftello fwrite getchar getdelim getline perror printf
syn keyword cFunction putchar puts remove rename renameat rewind scanf setbuf
syn keyword cFunction sprintf sscanf tmpfile tmpnam vfprintf vprintf vsprintf
syn keyword cFunction vdprintf snprintf vsnprintf vfscanf vscanf vsscanf ctermid
syn keyword cFunction fdopen fileno pclose popen flockfile ftrylockfile
syn keyword cFunction funlockfile getc_unlocked getchar_unlocked putc_unlocked
syn keyword cFunction putchar_unlocked fmemopen open_memstream tempnam asprintf
syn keyword cFunction fpurge getw putw setbuffer setlinebuf vasprintf funopen

" setjmp.h
syn keyword cFunction setjmp longjmp sigsetjmp siglongjmp _setjmp _longjmp

" netinet/tcp.h
syn keyword cFunction min

" ifaddrs.h
syn keyword cFunction getifaddrs freeifaddrs

" string.h
syn keyword cFunction memchr memcmp memcpy memmove memset strcat strchr strcmp
syn keyword cFunction strcoll strcpy strcspn strerror strlen strncat strncmp
syn keyword cFunction strncpy strpbrk strrchr strspn strstr strtok strtok_r
syn keyword cFunction strxfrm memccpy strerror_r strdup stpcpy stpncpy strcoll_l
syn keyword cFunction strerror_l strndup strnlen strsignal strxfrm_l
syn keyword cFunction explicit_bzero memmem memrchr strcasestr strlcat strlcpy
syn keyword cFunction strmode strsep timingsafe_bcmp timingsafe_memcmp

" getopt.h
syn keyword cFunction getopt_long getopt_long_only getopt

" event.h
syn keyword cFunction event_dispatch kqueue epoll event_init event_set event_add
syn keyword cFunction bufferevent_new bufferevent_enable bufferevent_read
syn keyword cFunction evtimer_set evtimer_add timeout_set timeout_add timeout_del
syn keyword cFunction evdns_init evdns_resolve_ipv4 evdns_resolve_reverse
syn keyword cFunction evhttp_new evhttp_bind_socket evhttp_set_cb
syn keyword cFunction evhttp_set_gencb TAILQ_ENTRY event_base_new event_base_set
syn keyword cFunction event_reinit event_base_dispatch event_base_get_method
syn keyword cFunction event_base_free event_set_log_callback event_loop
syn keyword cFunction event_loopexit event_base_loop event_base_loopexit
syn keyword cFunction event_loopbreak event_base_loopbreak event_del event_once
syn keyword cFunction event event_base_once event_active event_pending
syn keyword cFunction event_initialized event_get_version event_get_method
syn keyword cFunction event_priority_init event_base_priority_init
syn keyword cFunction event_priority_set event_asr_run event_asr_abort
syn keyword cFunction bufferevent_base_set pipe bufferevent_priority_set
syn keyword cFunction bufferevent_free bufferevent_setcb bufferevent_setfd
syn keyword cFunction bufferevent_write bufferevent_write_buffer
syn keyword cFunction bufferevent_disable bufferevent_settimeout
syn keyword cFunction bufferevent_setwatermark evbuffer_new evbuffer_free
syn keyword cFunction evbuffer_expand evbuffer_add evbuffer_remove
syn keyword cFunction evbuffer_readline evbuffer_readln evbuffer_add_buffer
syn keyword cFunction printf evbuffer_add_printf vprintf evbuffer_add_vprintf
syn keyword cFunction evbuffer_drain evbuffer_read evbuffer_write evbuffer_find
syn keyword cFunction evbuffer_setcb evtag_init evtag_marshal encode_int
syn keyword cFunction evtag_marshal_int evtag_marshal_string
syn keyword cFunction evtag_marshal_timeval evtag_unmarshal evtag_peek
syn keyword cFunction evtag_peek_length evtag_payload_length evtag_consume
syn keyword cFunction evtag_unmarshal_int evtag_unmarshal_fixed
syn keyword cFunction evtag_unmarshal_string evtag_unmarshal_timeval

" signal.h
syn keyword cFunction raise bsd_signal kill sigaction sigaddset sigdelset
syn keyword cFunction sigemptyset sigfillset sigismember sigpending sigprocmask
syn keyword cFunction pthread_sigmask sigsuspend sigmask killpg siginterrupt
syn keyword cFunction sigaltstack sigblock sigpause sigsetmask sigvec thrkill
syn keyword cFunction sigwait psignal

" semaphore.h
syn keyword cFunction sem_init sem_destroy sem_open sem_close sem_unlink sem_wait
syn keyword cFunction sem_timedwait sem_trywait sem_post sem_getvalue

" sys/ioctl.h
syn keyword cFunction ioctl

" netdb.h
syn keyword cFunction gethostbyname getaddrinfo getrrsetbyname endhostent
syn keyword cFunction endnetent endprotoent endservent gethostbyaddr
syn keyword cFunction gethostbyname2 gethostent getnetbyaddr getnetbyname
syn keyword cFunction getnetent getprotobyname getprotobynumber getprotoent
syn keyword cFunction getservbyname getservbyport getservent herror hstrerror
syn keyword cFunction sethostent sethostfile setnetent setprotoent setservent
syn keyword cFunction endprotoent_r endservent_r getprotobyname_r
syn keyword cFunction getprotobynumber_r getservbyname_r getservbyport_r
syn keyword cFunction getservent_r getprotoent_r setprotoent_r setservent_r
syn keyword cFunction freeaddrinfo getnameinfo gai_strerror freerrset

" locale.h
syn keyword cFunction localeconv setlocale duplocale freelocale newlocale
syn keyword cFunction uselocale

" math.h
syn keyword cFunction acos asin atan atan2 cos sin tan cosh sinh tanh exp frexp
syn keyword cFunction ldexp log log10 modf pow sqrt ceil fabs floor fmod acosh
syn keyword cFunction asinh atanh exp2 expm1 ilogb log1p log2 logb scalbn scalbln
syn keyword cFunction cbrt hypot erf erfc lgamma tgamma nearbyint rint lrint
syn keyword cFunction llrint round lround llround trunc remainder remquo copysign
syn keyword cFunction nan nextafter nexttoward fdim fmax fmin fma j0 j1 jn scalb
syn keyword cFunction y0 y1 yn gamma drem finite gamma_r lgamma_r sincos
syn keyword cFunction significand acosf asinf atanf atan2f cosf sinf tanf acoshf
syn keyword cFunction asinhf atanhf coshf sinhf tanhf expf exp2f expm1f frexpf
syn keyword cFunction ilogbf ldexpf logf log10f log1pf log2f logbf modff scalbnf
syn keyword cFunction scalblnf cbrtf fabsf hypotf powf sqrtf erff erfcf lgammaf
syn keyword cFunction tgammaf ceilf floorf nearbyintf rintf lrintf llrintf roundf
syn keyword cFunction lroundf llroundf truncf fmodf remainderf remquof copysignf
syn keyword cFunction nanf nextafterf nexttowardf fdimf fmaxf fminf fmaf j0f j1f
syn keyword cFunction jnf scalbf y0f y1f ynf gammaf dremf finitef isinff isnanf
syn keyword cFunction gammaf_r lgammaf_r sincosf significandf acosl asinl atanl
syn keyword cFunction atan2l cosl sinl tanl acoshl asinhl atanhl coshl sinhl
syn keyword cFunction tanhl expl exp2l expm1l frexpl ilogbl ldexpl logl log10l
syn keyword cFunction log1pl log2l logbl modfl scalbnl scalblnl cbrtl fabsl
syn keyword cFunction hypotl powl sqrtl erfl erfcl lgammal tgammal ceill floorl
syn keyword cFunction nearbyintl rintl lrintl llrintl roundl lroundl llroundl
syn keyword cFunction truncl fmodl remainderl remquol copysignl nanl nextafterl
syn keyword cFunction nexttowardl fdiml fmaxl fminl fmal sincosl

" ncurses.h
syn keyword cFunction name tparm _nc_timed_wait printw vid_attr is_leaveok getyx
syn keyword cFunction while leaveok wmove wgetch

" wchar.h
syn keyword cFunction btowc mbrlen mbrtowc mbsinit mbsrtowcs wcrtomb wcscat
syn keyword cFunction wcschr wcscmp wcscoll wcscpy wcscspn wcslen wcsncat wcsncmp
syn keyword cFunction wcsncpy wcspbrk wcsrchr wcsrtombs wcsspn wcsstr wcstok
syn keyword cFunction wcsxfrm wcswcs wmemchr wmemcmp wmemcpy wmemmove wmemset
syn keyword cFunction wcswidth wctob wcwidth wcstod wcstol wcstoul
syn keyword cFunction open_wmemstream wcscoll_l wcsdup wcscasecmp wcscasecmp_l
syn keyword cFunction wcsncasecmp wcsncasecmp_l wcsxfrm_l mbsnrtowcs wcsnrtombs
syn keyword cFunction wcstof wcstold wcsftime wcstoll wcstoull ungetwc fgetwc
syn keyword cFunction fgetws getwc getwchar fputwc fputws putwc putwchar fwide
syn keyword cFunction fwprintf swprintf vfwprintf vswprintf vwprintf wprintf
syn keyword cFunction fwscanf swscanf vfwscanf vswscanf vwscanf wscanf fgetwln
syn keyword cFunction wcslcat wcslcpy

" complex.h
syn keyword cFunction cacos casin catan ccos csin ctan cacosh casinh catanh ccosh
syn keyword cFunction csinh ctanh cexp clog cabs cpow csqrt carg cimag conj cproj
syn keyword cFunction creal cacosf casinf catanf ccosf csinf ctanf cacoshf
syn keyword cFunction casinhf catanhf ccoshf csinhf ctanhf cexpf clogf cabsf
syn keyword cFunction cpowf csqrtf cargf cimagf conjf cprojf crealf cacosl casinl
syn keyword cFunction catanl ccosl csinl ctanl cacoshl casinhl catanhl ccoshl
syn keyword cFunction csinhl ctanhl cexpl clogl cabsl cpowl csqrtl cargl cimagl
syn keyword cFunction conjl cprojl creall

" tls.h
syn keyword cFunction tls_init tls_config_error tls_error tls_config_new
syn keyword cFunction tls_config_free tls_config_add_keypair_file
syn keyword cFunction tls_config_add_keypair_mem tls_config_add_keypair_ocsp_file
syn keyword cFunction tls_config_add_keypair_ocsp_mem tls_config_set_alpn
syn keyword cFunction tls_config_set_ca_file tls_config_set_ca_path
syn keyword cFunction tls_config_set_ca_mem tls_config_set_cert_file
syn keyword cFunction tls_config_set_cert_mem tls_config_set_ciphers
syn keyword cFunction tls_config_set_crl_file tls_config_set_crl_mem
syn keyword cFunction tls_config_set_dheparams tls_config_set_ecdhecurve
syn keyword cFunction tls_config_set_ecdhecurves tls_config_set_key_file
syn keyword cFunction tls_config_set_key_mem tls_config_set_keypair_file
syn keyword cFunction tls_config_set_keypair_mem tls_config_set_keypair_ocsp_file
syn keyword cFunction tls_config_set_keypair_ocsp_mem
syn keyword cFunction tls_config_set_ocsp_staple_mem
syn keyword cFunction tls_config_set_ocsp_staple_file tls_config_set_protocols
syn keyword cFunction tls_config_set_session_fd tls_config_set_verify_depth
syn keyword cFunction tls_config_prefer_ciphers_client
syn keyword cFunction tls_config_prefer_ciphers_server
syn keyword cFunction tls_config_insecure_noverifycert
syn keyword cFunction tls_config_insecure_noverifyname
syn keyword cFunction tls_config_insecure_noverifytime tls_config_verify
syn keyword cFunction tls_config_ocsp_require_stapling tls_config_verify_client
syn keyword cFunction tls_config_verify_client_optional tls_config_clear_keys
syn keyword cFunction tls_config_parse_protocols tls_config_set_session_id
syn keyword cFunction tls_config_set_session_lifetime tls_config_add_ticket_key
syn keyword cFunction tls_client tls_server tls_configure tls_reset tls_free
syn keyword cFunction tls_accept_fds tls_accept_socket tls_accept_cbs tls_connect
syn keyword cFunction tls_connect_fds tls_connect_servername tls_connect_socket
syn keyword cFunction tls_connect_cbs tls_handshake tls_read tls_write tls_close
syn keyword cFunction tls_peer_cert_provided tls_peer_cert_contains_name
syn keyword cFunction tls_peer_cert_hash tls_peer_cert_issuer
syn keyword cFunction tls_peer_cert_subject tls_peer_cert_notbefore
syn keyword cFunction tls_peer_cert_notafter tls_peer_cert_chain_pem
syn keyword cFunction tls_conn_alpn_selected tls_conn_cipher tls_conn_servername
syn keyword cFunction tls_conn_session_resumed tls_conn_version tls_load_file
syn keyword cFunction tls_unload_file tls_ocsp_process_response
syn keyword cFunction tls_peer_ocsp_cert_status tls_peer_ocsp_crl_reason
syn keyword cFunction tls_peer_ocsp_next_update tls_peer_ocsp_response_status
syn keyword cFunction tls_peer_ocsp_result tls_peer_ocsp_revocation_time
syn keyword cFunction tls_peer_ocsp_this_update tls_peer_ocsp_url

" unistd.h
syn keyword cFunction sysconf _exit access alarm chdir chown close dup dup2 execl
syn keyword cFunction execle execlp execv execve execvp execvpe fork fpathconf
syn keyword cFunction getcwd getegid geteuid getgid getgroups getlogin getpgrp
syn keyword cFunction getpid getppid getuid isatty link lseek pathconf pause pipe
syn keyword cFunction read rmdir setgid setuid sleep tcgetpgrp tcsetpgrp ttyname
syn keyword cFunction unlink write setsid setpgid confstr getopt fsync ftruncate
syn keyword cFunction getlogin_r readlink fdatasync crypt fchdir fchown gethostid
syn keyword cFunction getwd lchown mkstemp mktemp nice setregid setreuid swab
syn keyword cFunction sync truncate ualarm usleep vfork getpgid getsid pread
syn keyword cFunction pwrite ttyname_r brk chroot getdtablesize getpagesize
syn keyword cFunction getpass sbrk lockf symlink gethostname setegid seteuid
syn keyword cFunction faccessat fchownat linkat readlinkat symlinkat unlinkat
syn keyword cFunction dup3 pipe2 acct closefrom crypt_checkpass crypt_newhash
syn keyword cFunction endusershell fflagstostr getdomainname getdtablecount
syn keyword cFunction getgrouplist getmode getresgid getresuid getthrid
syn keyword cFunction getusershell initgroups issetugid mkdtemp mkstemps nfssvc
syn keyword cFunction profil quotactl rcmd rcmd_af rcmdsh reboot revoke rresvport
syn keyword cFunction rresvport_af ruserok setdomainname setgroups sethostid
syn keyword cFunction sethostname setlogin setmode setpgrp setresgid setresuid
syn keyword cFunction setusershell strtofflags swapctl syscall getentropy pledge
syn keyword cFunction unveil
