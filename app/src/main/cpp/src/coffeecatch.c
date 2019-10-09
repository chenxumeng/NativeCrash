//
// Created by ThinkPad on 2019/10/8.
//
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <unwind.h>
#include <dlfcn.h>
#include <errno.h>
#include "JniLog.h"



/****************************************
 * 重要的宏
 *******************************************/
#define USE_UNWIND
// 使用libcorkscrew获取 backtrace
#define USE_CORKSCREW
// 使用libunwind 获取 backtrace
#define USE_LIBUNWIND

#ifdef USE_UNWIND
/* Number of backtraces to get. */
// 获取堆栈的栈大小
#define BACKTRACE_FRAMES_MAX 32
#endif

/****************************************
 * 辅助数据结构
 *******************************************/
/* Extracted from Android's include/corkscrew/backtrace.h */
typedef struct {
    uintptr_t absolute_pc;
    uintptr_t stack_top;
    size_t stack_size;
} backtrace_frame_t;
/****************************************
 * 重要数据结构
 *******************************************/
#define SIG_STACK_BUFFER_SIZE SIGSTKSZ
typedef struct native_code_handler_struct{
    // 信号跳转环境变量
    sigjmp_buf ctx;
    int ctx_is_set;
    int reenter;
    // 信号栈的地址
    char *stack_buffer;
    // 堆栈大小
    size_t stack_buffer_size;
    stack_t stack_old;
    int code;
    siginfo_t si;
    // 协程是一种用户态的轻量级线程
    ucontext_t uc;
#if (defined(USE_CORKSCREW) || defined(USE_UNWIND))
    backtrace_frame_t frames[BACKTRACE_FRAMES_MAX];
#endif

#ifdef USE_LIBUNWIND
    void* uframes[BACKTRACE_FRAMES_MAX];
#endif
    size_t frames_size;
    size_t frames_skip;

    const char *expression;
    const char *file;
    int line;

    /* Alarm was fired. */
    int alarm;
}native_code_handler_struct;


/* Process-wide crash handler structure. */
typedef struct native_code_global_struct {
    /* Initialized. */
    int initialized;

    /* Lock. */
    pthread_mutex_t mutex;

    /* Backup of sigaction. */
    struct sigaction *sa_old;
} native_code_global_struct;

#define NATIVE_CODE_GLOBAL_INITIALIZER { 0, PTHREAD_MUTEX_INITIALIZER, NULL }
/****************************************
 * 全局变量
 *******************************************/
static native_code_global_struct native_code_g = NATIVE_CODE_GLOBAL_INITIALIZER;
pthread_key_t native_code_thread;
// 申请native_code_handler_struct变量空间
static native_code_handler_struct* coffeecatch_native_code_handler_struct_init(void);
// 释放native_code_handler_struct变量空间
static int coffeecatch_native_code_handler_struct_free(native_code_handler_struct *const t);
// 获取native_code_handler_struct变量
static native_code_handler_struct* coffeecatch_get();
/****************************************
 * 信号捕获函数
 *******************************************/
#define SIG_NUMBER_MAX 32
#define SIG_CATCH_COUNT 7
// backtrace的函数接口
static void coffeecatch_start_alarm(void);
        static void coffeecatch_mark_alarm(native_code_handler_struct *const t);
static void coffeecatch_copy_context(native_code_handler_struct *const t,
                                     const int code, siginfo_t *const si,
                                     void *const sc);
static void coffeecatch_try_jump_userland(native_code_handler_struct*const t,
                                          const int code,
                                          siginfo_t *const si,
                                          void * const sc);
static void coffeecatch_call_old_signal_handler(const int code, siginfo_t *const si,
                                                void * const sc);

//  定义程序处理的信号
static const int native_sig_catch[SIG_CATCH_COUNT]
        = { SIGABRT, SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV, SIGSTKFLT};
static void coffeecatch_signal_abort(const int code, siginfo_t *const si,
                                     void *const sc){
    native_code_handler_struct *t;
    LOGD("caught abort %d\n",code);
    //设置信号默认处理方式
    signal(code, SIG_DFL);
    coffeecatch_start_alarm();
    // 获取线程局部变量
    t = coffeecatch_get();
    if (t != NULL) {
        /* An alarm() call was triggered. */
        coffeecatch_mark_alarm(t);
        /* Take note (real "abort()") */
        coffeecatch_copy_context(t, code, si, sc);
        /* Back to the future. */
        coffeecatch_try_jump_userland(t, code, si, sc);
    }
    /* No such restore point, call old signal handler then. */
    LOGD("calling old signal handler\n");
    coffeecatch_call_old_signal_handler(code, si, sc);
    /* Nope. (abort() is signal-safe) */
    LOGD("calling abort()\n");
    abort();
}
static void coffeecatch_signal_pass(const int code, siginfo_t *const si,
                                    void *const sc){
    native_code_handler_struct *t;
    LOGD("caught signal %d\n",code);
    coffeecatch_call_old_signal_handler(code, si, sc);
    //设置信号默认处理方式
    signal(code, SIG_DFL);
    coffeecatch_start_alarm();
    /* Available context ? */
    t = coffeecatch_get();
    if (t != NULL) {
        /* An alarm() call was triggered. */
        coffeecatch_mark_alarm(t);
        /* Take note of the signal. */
        coffeecatch_copy_context(t, code, si, sc);
        /* Back to the future. */
        coffeecatch_try_jump_userland(t, code, si, sc);
    }

    /* Nope. (abort() is signal-safe) */
    LOGD("calling abort()\n");
    signal(SIGABRT, SIG_DFL);
    abort();
}
/****************************************
 * 辅助函数
 *******************************************/

 /**初始化全局变量**/
static int coffeecatch_handler_setup_global(void){
     if (native_code_g.initialized++ == 0){
         size_t i;
         struct sigaction sa_abort;
         struct sigaction sa_pass;
         LOGD("installing global signal handlers\n");
         memset(&sa_abort, 0, sizeof(sa_abort));
         sigemptyset(&sa_abort.sa_mask);
         sa_abort.sa_sigaction = coffeecatch_signal_abort;
         /**
          * SA_SIGINFO 信号处理函数跳转到 sa_sigaction
          * SA_ONSTACK 建立信号专用栈 参见 sigaltstack
          * 系统将在用sigaltstack指定的替代信号栈上运行的信号句柄.否则使用用户栈来交付信号
          */
         sa_abort.sa_flags = SA_SIGINFO | SA_ONSTACK;

         memset(&sa_pass, 0, sizeof(sa_pass));
         sigemptyset(&sa_pass.sa_mask);
         sa_pass.sa_sigaction = coffeecatch_signal_pass;
         sa_pass.sa_flags = SA_SIGINFO | SA_ONSTACK;
         // 申请old信号的空间
         native_code_g.sa_old = calloc(sizeof(struct sigaction), SIG_NUMBER_MAX);
         if (native_code_g.sa_old == NULL) {
             return -1;
         }
         for (i = 0; i < SIG_CATCH_COUNT; i++){
             const int sig = native_sig_catch[i];
             const struct sigaction * const action =
                     sig == SIGABRT ? &sa_abort : &sa_pass;
             LOGD("sig = %d\n",sig);
             assert(sig < SIG_NUMBER_MAX);
             // 重要，设置信号处理函数
             if (sigaction(sig, action, &native_code_g.sa_old[sig]) != 0) {
                 return -1;
             }
         }
         // 初始化线程局部变量
         if (pthread_key_create(&native_code_thread, NULL) != 0) {
             return -1;
         }
     }
     return 0;
 }
 /**
  * 申请 native_code_handler_struct变量 空间
  * @return
  */
static native_code_handler_struct* coffeecatch_native_code_handler_struct_init(void) {
     stack_t stack;
     native_code_handler_struct *const t =
             calloc(sizeof(native_code_handler_struct), 1);
     if (t == NULL) {
         return NULL;
     }
     LOGI("installing thread alternative stack\n");
     t->stack_buffer_size = SIG_STACK_BUFFER_SIZE;
     t->stack_buffer = malloc(t->stack_buffer_size);
     if (t->stack_buffer == NULL) {
         coffeecatch_native_code_handler_struct_free(t);
         return NULL;
     }
     //初始化信号栈
     memset(&stack, 0, sizeof(stack));
     stack.ss_sp = t->stack_buffer;
     stack.ss_size = t->stack_buffer_size;
     stack.ss_flags = 0;
     // 设置用户信号栈，参见 coffeecatch_handler_setup_global中的sa_flags
     if (sigaltstack(&stack, &t->stack_old) != 0){
         coffeecatch_native_code_handler_struct_free(t);
         return NULL;
     }
     return t;
 }
/**
 * 释放 native_code_handler_struct变量 空间
 * @return
 */
static int coffeecatch_native_code_handler_struct_free(native_code_handler_struct *const t) {
    int code = 0;
    if (t == NULL) {
        // 防止多次释放
        return -1;
    }
    // 释放old 信号栈
    if (t->stack_old.ss_sp != NULL && sigaltstack(&t->stack_old, NULL) != 0){
        code = -1;
    }
    if (t->stack_buffer != NULL) {
        free(t->stack_buffer);
        t->stack_buffer = NULL;
        t->stack_buffer_size = 0;
    }

    /* Free structure. */
    free(t);
    return code;
}
    /**
     *
     * @param setup_thread  是否线程
     * @return
     */
static int coffeecatch_handler_setup(int setup_thread){
     int code;
     LOGD("setup for a new handler\n");
     /* Initialize globals. */
     if (pthread_mutex_lock(&native_code_g.mutex) != 0) {
         return -1;
     }
     // 全局变量初始化,线程安全
      code = coffeecatch_handler_setup_global();
     if (pthread_mutex_unlock(&native_code_g.mutex) != 0) {
         return -1;
     }
     if (code != 0) {
         LOGE("Global initialization failed\n");
         return -1;
     }
     if (setup_thread && coffeecatch_get() == NULL){
         // 申请 native_code_handler_struct 的变量
         native_code_handler_struct *const t =
                 coffeecatch_native_code_handler_struct_init();
         if (t == NULL) {
             return -1;
         }
         LOGI("installing thread alternative stack start\n");
         // 将native_code_handler_struct设置线程局部变量中
         if (pthread_setspecific(native_code_thread, t) != 0) {
             coffeecatch_native_code_handler_struct_free(t);
             return -1;
         }
         LOGI("installing thread alternative stack success \n");
     }
     return 0;
}
/**
 * 返回线程局部变量
 * @return
 */
static native_code_handler_struct* coffeecatch_get() {
    return (native_code_handler_struct*)
            pthread_getspecific(native_code_thread);
}

/**
 * Release the resources allocated by a previous call to
 * coffeecatch_handler_setup().
 * This function must be called as many times as
 * coffeecatch_handler_setup() was called to fully release allocated
 * resources.
 **/
static int coffeecatch_handler_cleanup() {
    /* Cleanup locals. */
    native_code_handler_struct *const t = coffeecatch_get();
    if (t != NULL) {
        LOGD("removing thread alternative stack\n");

        /* Erase thread-specific value now (detach). */
        if (pthread_setspecific(native_code_thread, NULL) != 0) {
            assert(! "pthread_setspecific() failed");
        }

        /* Free handler and reset slternate stack */
        if (coffeecatch_native_code_handler_struct_free(t) != 0) {
            return -1;
        }

        LOGD("removed thread alternative stack\n");
    }

    /* Cleanup globals. */
    if (pthread_mutex_lock(&native_code_g.mutex) != 0) {
        assert(! "pthread_mutex_lock() failed");
    }
    assert(native_code_g.initialized != 0);
    if (--native_code_g.initialized == 0) {
        size_t i;

        LOGD("removing global signal handlers\n");

        /* Restore signal handler. */
        for(i = 0; i < SIG_CATCH_COUNT; i++) {
            const int sig = native_sig_catch[i];
            assert(sig < SIG_NUMBER_MAX);
            if (sigaction(sig, &native_code_g.sa_old[sig], NULL) != 0) {
                return -1;
            }
        }

        /* Free old structure. */
        free(native_code_g.sa_old);
        native_code_g.sa_old = NULL;

        /* Delete thread var. */
        if (pthread_key_delete(native_code_thread) != 0) {
            assert(! "pthread_key_delete() failed");
        }

        LOGD("removed global signal handlers\n");
    }
    if (pthread_mutex_unlock(&native_code_g.mutex) != 0) {
        assert(! "pthread_mutex_unlock() failed");
    }

    return 0;
}

/*******************************************
 * libunwind.so
 *******************************************/
#ifdef USE_LIBUNWIND
static ssize_t coffeecatch_unwind_signal(siginfo_t* si, void* sc,
                                         void** frames,
                                         size_t ignore_depth,
                                         size_t max_depth) {
    void *libunwind = dlopen("libunwind.so", RTLD_LAZY | RTLD_LOCAL);
    if (libunwind != NULL) {
        int (*backtrace)(void **buffer, int size) =
        dlsym(libunwind, "unw_backtrace");
        if (backtrace != NULL) {
            LOGD("unw_backtrace in libunwind.so\n");
            int nb = backtrace(frames, max_depth);
            if (nb > 0) {
            }
            return nb;
        } else {
            LOGD("symbols not found in libunwind.so\n");
        }
        dlclose(libunwind);
    } else {
        LOGD("libunwind.so could not be loaded\n");
    }
    return -1;
}
#endif
/*******************************************
 * 获取backtrace的函数接口
 *******************************************/
static void coffeecatch_start_alarm(void) {
    /* Ensure we do not deadlock. Default of ALRM is to die.
     * (signal() and alarm() are signal-safe) */
    (void) alarm(30);
}
static void coffeecatch_mark_alarm(native_code_handler_struct *const t) {
    t->alarm = 1;
}
static _Unwind_Reason_Code
coffeecatch_unwind_callback(struct _Unwind_Context* context, void* arg) {
    native_code_handler_struct *const s = (native_code_handler_struct*) arg;

    const uintptr_t ip = _Unwind_GetIP(context);

    if (ip != 0x0) {
        if (s->frames_skip == 0) {
            s->frames[s->frames_size].absolute_pc = (uintptr_t)ip;
            s->frames_size++;
        } else {
            s->frames_skip--;
        }
    }

    if (s->frames_size == BACKTRACE_FRAMES_MAX) {
        return _URC_END_OF_STACK;
    } else {
        LOGD("returned _URC_OK\n");
        return _URC_NO_REASON;
    }
}
/* Unflag "on stack" */
static void coffeecatch_revert_alternate_stack(void) {
    stack_t ss;
    if (sigaltstack(NULL, &ss) == 0) {
        ss.ss_flags &= ~SS_ONSTACK;
        sigaltstack (&ss, NULL);
    }
}
static void coffeecatch_copy_context(native_code_handler_struct *const t,
                                     const int code, siginfo_t *const si,
                                     void *const sc){
    t->code = code;
    t->si = *si;
    if (sc != NULL) {
        ucontext_t *const uc = (ucontext_t*) sc;
        t->uc = *uc;
    } else {
        memset(&t->uc, 0, sizeof(t->uc));
    }
    /* Frame buffer initial position. */
    t->frames_size = 0;
    /* Skip us and the caller. */
    t->frames_skip = 2;
    //使用libunwind.so进行backtrace解析
    //_Unwind_Backtrace(coffeecatch_unwind_callback, t);
    if (t->frames_size == 0){
        size_t i;
        t->frames_size = coffeecatch_unwind_signal(si, sc, t->uframes, 0,
                                                   BACKTRACE_FRAMES_MAX);
        for(i = 0 ; i < t->frames_size ; i++) {
            t->frames[i].absolute_pc = (uintptr_t) t->uframes[i];
            t->frames[i].stack_top = 0;
            t->frames[i].stack_size = 0;
        }
    }
    if (t->frames_size != 0) {
        LOGD("called _Unwind_Backtrace()\n");
    } else {
        LOGD("called _Unwind_Backtrace(), but no traces\n");
    }

}
static void coffeecatch_try_jump_userland(native_code_handler_struct*const t,
                                          const int code,
                                          siginfo_t *const si,
                                          void * const sc){
    /* Valid context ? */
    if (t != NULL && t->ctx_is_set) {
        LOGD("calling siglongjmp()\n");

        /* Invalidate the context */
        t->ctx_is_set = 0;

        /* We need to revert the alternate stack before jumping. */
        coffeecatch_revert_alternate_stack();

        /*
         * Note on async-signal-safety of siglongjmp() [POSIX] :
         * "Note that longjmp() and siglongjmp() are not in the list of
         * async-signal-safe functions. This is because the code executing after
         * longjmp() and siglongjmp() can call any unsafe functions with the same
         * danger as calling those unsafe functions directly from the signal
         * handler. Applications that use longjmp() and siglongjmp() from within
         * signal handlers require rigorous protection in order to be portable.
         * Many of the other functions that are excluded from the list are
         * traditionally implemented using either malloc() or free() functions or
         * the standard I/O library, both of which traditionally use data
         * structures in a non-async-signal-safe manner. Since any combination of
         * different functions using a common data structure can cause
         * async-signal-safety problems, this volume of POSIX.1-2008 does not
         * define the behavior when any unsafe function is called in a signal
         * handler that interrupts an unsafe function."
         */
        LOGD("siglongjmp code = %d\n",code);
        siglongjmp(t->ctx, code);
    }

}
static void coffeecatch_call_old_signal_handler(const int code, siginfo_t *const si,
                                                void * const sc){
    if (code >= 0 && code < SIG_NUMBER_MAX) {
        if (native_code_g.sa_old[code].sa_sigaction != NULL) {
            native_code_g.sa_old[code].sa_sigaction(code, si, sc);
        } else if (native_code_g.sa_old[code].sa_handler != NULL) {
            native_code_g.sa_old[code].sa_handler(code);
        }
    }
}
/****************************************
 * 异常信息解析接口
 *******************************************/
/* Signal descriptions.
  See <http://pubs.opengroup.org/onlinepubs/009696699/basedefs/signal.h.html>
*/
static const char* coffeecatch_desc_sig(int sig, int code){
    switch(sig) {
        case SIGILL:
            switch(code) {
                case ILL_ILLOPC:
                    return "Illegal opcode";
                case ILL_ILLOPN:
                    return "Illegal operand";
                case ILL_ILLADR:
                    return "Illegal addressing mode";
                case ILL_ILLTRP:
                    return "Illegal trap";
                case ILL_PRVOPC:
                    return "Privileged opcode";
                case ILL_PRVREG:
                    return "Privileged register";
                case ILL_COPROC:
                    return "Coprocessor error";
                case ILL_BADSTK:
                    return "Internal stack error";
                default:
                    return "Illegal operation";
            }
            break;
        case SIGFPE:
            switch(code) {
                case FPE_INTDIV:
                    return "Integer divide by zero";
                case FPE_INTOVF:
                    return "Integer overflow";
                case FPE_FLTDIV:
                    return "Floating-point divide by zero";
                case FPE_FLTOVF:
                    return "Floating-point overflow";
                case FPE_FLTUND:
                    return "Floating-point underflow";
                case FPE_FLTRES:
                    return "Floating-point inexact result";
                case FPE_FLTINV:
                    return "Invalid floating-point operation";
                case FPE_FLTSUB:
                    return "Subscript out of range";
                default:
                    return "Floating-point";
            }
            break;
        case SIGSEGV:
            switch(code) {
                case SEGV_MAPERR:
                    return "Address not mapped to object";
                case SEGV_ACCERR:
                    return "Invalid permissions for mapped object";
                default:
                    return "Segmentation violation";
            }
            break;
        case SIGBUS:
            switch(code) {
                case BUS_ADRALN:
                    return "Invalid address alignment";
                case BUS_ADRERR:
                    return "Nonexistent physical address";
                case BUS_OBJERR:
                    return "Object-specific hardware error";
                default:
                    return "Bus error";
            }
            break;
        case SIGTRAP:
            switch(code) {
                case TRAP_BRKPT:
                    return "Process breakpoint";
                case TRAP_TRACE:
                    return "Process trace trap";
                default:
                    return "Trap";
            }
            break;
        case SIGCHLD:
            switch(code) {
                case CLD_EXITED:
                    return "Child has exited";
                case CLD_KILLED:
                    return "Child has terminated abnormally and did not create a core file";
                case CLD_DUMPED:
                    return "Child has terminated abnormally and created a core file";
                case CLD_TRAPPED:
                    return "Traced child has trapped";
                case CLD_STOPPED:
                    return "Child has stopped";
                case CLD_CONTINUED:
                    return "Stopped child has continued";
                default:
                    return "Child";
            }
            break;
        case SIGPOLL:
            switch(code) {
                case POLL_IN:
                    return "Data input available";
                case POLL_OUT:
                    return "Output buffers available";
                case POLL_MSG:
                    return "Input message available";
                case POLL_ERR:
                    return "I/O error";
                case POLL_PRI:
                    return "High priority input available";
                case POLL_HUP:
                    return "Device disconnected";
                default:
                    return "Pool";
            }
            break;
        case SIGABRT:
            return "Process abort signal";
        case SIGALRM:
            return "Alarm clock";
        case SIGCONT:
            return "Continue executing, if stopped";
        case SIGHUP:
            return "Hangup";
        case SIGINT:
            return "Terminal interrupt signal";
        case SIGKILL:
            return "Kill";
        case SIGPIPE:
            return "Write on a pipe with no one to read it";
        case SIGQUIT:
            return "Terminal quit signal";
        case SIGSTOP:
            return "Stop executing";
        case SIGTERM:
            return "Termination signal";
        case SIGTSTP:
            return "Terminal stop signal";
        case SIGTTIN:
            return "Background process attempting read";
        case SIGTTOU:
            return "Background process attempting write";
        case SIGUSR1:
            return "User-defined signal 1";
        case SIGUSR2:
            return "User-defined signal 2";
        case SIGPROF:
            return "Profiling timer expired";
        case SIGSYS:
            return "Bad system call";
        case SIGVTALRM:
            return "Virtual timer expired";
        case SIGURG:
            return "High bandwidth data is available at a socket";
        case SIGXCPU:
            return "CPU time limit exceeded";
        case SIGXFSZ:
            return "File size limit exceeded";
        default:
            switch(code) {
                case SI_USER:
                    return "Signal sent by kill()";
                case SI_QUEUE:
                    return "Signal sent by the sigqueue()";
                case SI_TIMER:
                    return "Signal generated by expiration of a timer set by timer_settime()";
                case SI_ASYNCIO:
                    return "Signal generated by completion of an asynchronous I/O request";
                case SI_MESGQ:
                    return
                            "Signal generated by arrival of a message on an empty message queue";
                default:
                    return "Unknown signal";
            }
            break;
    }
}
static uintptr_t coffeecatch_get_pc_from_ucontext(const ucontext_t *uc) {
#if (defined(__arm__))
    return uc->uc_mcontext.arm_pc;
#elif defined(__aarch64__)
    return uc->uc_mcontext.pc;
#elif (defined(__x86_64__))
  return uc->uc_mcontext.gregs[REG_RIP];
#elif (defined(__i386))
  return uc->uc_mcontext.gregs[REG_EIP];
#elif (defined (__ppc__)) || (defined (__powerpc__))
  return uc->uc_mcontext.regs->nip;
#elif (defined(__hppa__))
  return uc->uc_mcontext.sc_iaoq[0] & ~0x3UL;
#elif (defined(__sparc__) && defined (__arch64__))
  return uc->uc_mcontext.mc_gregs[MC_PC];
#elif (defined(__sparc__) && !defined (__arch64__))
  return uc->uc_mcontext.gregs[REG_PC];
#elif (defined(__mips__))
  return uc->uc_mcontext.gregs[31];
#else
#error "Architecture is unknown, please report me!"
#endif
}
/* Is this module name look like a DLL ?
   FIXME: find a better way to do that...  */
static int coffeecatch_is_dll(const char *name) {
    size_t i;
    for(i = 0; name[i] != '\0'; i++) {
        if (name[i + 0] == '.' &&
            name[i + 1] == 's' &&
            name[i + 2] == 'o' &&
            ( name[i + 3] == '\0' || name[i + 3] == '.') ) {
            return 1;
        }
    }
    return 0;
}
/* Extract a line information on a PC address. */
static void format_pc_address_cb(uintptr_t pc,
                                 void (*fun)(void *arg, const char *module,
                                             uintptr_t addr,
                                             const char *function,
                                             uintptr_t offset), void *arg) {
    if (pc != 0) {
        Dl_info info;
        void * const addr = (void*) pc;
        /* dladdr() returns 0 on error, and nonzero on success. */
        if (dladdr(addr, &info) != 0 && info.dli_fname != NULL) {
            const uintptr_t near = (uintptr_t) info.dli_saddr;
            const uintptr_t offs = pc - near;
            const uintptr_t addr_rel = pc - (uintptr_t) info.dli_fbase;
            /* We need the absolute address for the main module (?).
               TODO FIXME to be investigated. */
            const uintptr_t addr_to_use = coffeecatch_is_dll(info.dli_fname)
                                          ? addr_rel : pc;
            fun(arg, info.dli_fname, addr_to_use, info.dli_sname, offs);
        } else {
            fun(arg, NULL, pc, NULL, 0);
        }
    }
}
typedef struct t_print_fun {
    char *buffer;
    size_t buffer_size;
} t_print_fun;
static void print_fun(void *arg, const char *module, uintptr_t uaddr,
                      const char *function, uintptr_t offset) {
    t_print_fun *const t = (t_print_fun*) arg;
    char *const buffer = t->buffer;
    const size_t buffer_size = t->buffer_size;
    const void*const addr = (void*) uaddr;
    if (module == NULL) {
        snprintf(buffer, buffer_size, "[at %p]", addr);
    } else if (function != NULL) {
        snprintf(buffer, buffer_size, "[at %s:%p (%s+0x%x)]", module, addr,
                 function, (int) offset);
    } else {
        snprintf(buffer, buffer_size, "[at %s:%p]", module, addr);
    }
}
/* Format a line information on a PC address. */
static void format_pc_address(char *buffer, size_t buffer_size, uintptr_t pc) {
    t_print_fun t;
    t.buffer = buffer;
    t.buffer_size = buffer_size;
    format_pc_address_cb(pc, print_fun, &t);
}
/****************************************
 * 对外API接口
 *******************************************/
int coffeecatch_setup(){
    if (coffeecatch_handler_setup(1) == 0) {
        native_code_handler_struct *const t = coffeecatch_get();
        assert(t != NULL);
        assert(t->reenter == 0);
        t->reenter = 1;
        t->ctx_is_set = 1;
        return 0;
    } else {
        return -1;
    }
}

int coffeecatch_inside() {
    native_code_handler_struct *const t = coffeecatch_get();
    if (t != NULL && t->reenter > 0) {
        t->reenter++;
        return 1;
    }
    return 0;
}
sigjmp_buf* coffeecatch_get_ctx() {
    native_code_handler_struct* t = coffeecatch_get();
    assert(t != NULL);
    return &t->ctx;
}

void coffeecatch_abort(const char* exp, const char* file, int line) {
    native_code_handler_struct *const t = coffeecatch_get();
    if (t != NULL) {
        t->expression = exp;
        t->file = file;
        t->line = line;
    }
    abort();
}

void coffeecatch_cleanup() {
    native_code_handler_struct *const t = coffeecatch_get();
    assert(t != NULL);
    assert(t->reenter > 0);
    t->reenter--;
    if (t->reenter == 0) {
        t->ctx_is_set = 0;
        coffeecatch_handler_cleanup();
    }
}
// 获取异常信息
const char* coffeecatch_get_message(){
    LOGD("entry coffeecatch_get_message");
    const int error = errno;
    const native_code_handler_struct* const t = coffeecatch_get();
    /* Found valid handler. */
    if (t != NULL){
        char * const buffer = t->stack_buffer;
        const size_t buffer_len = t->stack_buffer_size;
        size_t buffer_offs = 0;
        const char* const posix_desc =
                coffeecatch_desc_sig(t->si.si_signo, t->si.si_code);
        /* See Android BUG #16672:* "C assert() failure causes SIGSEGV when it should cause SIGABRT" */
        if ((t->code == SIGABRT|| (t->code == SIGSEGV && (uintptr_t) t->si.si_addr == 0xdeadbaad))
        && t->expression != NULL){
            snprintf(&buffer[buffer_offs], buffer_len - buffer_offs,
                     "assertion '%s' failed at %s:%d",
                     t->expression, t->file, t->line);
            buffer_offs += strlen(&buffer[buffer_offs]);
        } else{
            snprintf(&buffer[buffer_offs], buffer_len - buffer_offs, "signal %d",
                     t->si.si_signo);
            buffer_offs += strlen(&buffer[buffer_offs]);
            snprintf(&buffer[buffer_offs], buffer_len - buffer_offs, " (%s)",
                     posix_desc);
            buffer_offs += strlen(&buffer[buffer_offs]);
            /* Address of faulting instruction */
            if (t->si.si_signo == SIGILL || t->si.si_signo == SIGSEGV) {
                snprintf(&buffer[buffer_offs], buffer_len - buffer_offs, " at address %p",
                         t->si.si_addr);
                buffer_offs += strlen(&buffer[buffer_offs]);
            }
        }
        /* [POSIX] If non-zero, an errno value associated with this signal,
     as defined in <errno.h>. */
        if (t->si.si_errno != 0) {
            snprintf(&buffer[buffer_offs], buffer_len - buffer_offs, ": ");
            buffer_offs += strlen(&buffer[buffer_offs]);
            if (strerror_r(t->si.si_errno, &buffer[buffer_offs],
                           buffer_len - buffer_offs) == 0) {
                snprintf(&buffer[buffer_offs], buffer_len - buffer_offs,
                         "unknown error");
                buffer_offs += strlen(&buffer[buffer_offs]);
            }
        }
        /* Sending process ID. */
        if (t->si.si_signo == SIGCHLD && t->si.si_pid != 0) {
            snprintf(&buffer[buffer_offs], buffer_len - buffer_offs,
                     " (sent by pid %d)", (int) t->si.si_pid);
            buffer_offs += strlen(&buffer[buffer_offs]);
        }
        /* Faulting program counter location. */
        if (coffeecatch_get_pc_from_ucontext(&t->uc) != 0) {
            const uintptr_t pc = coffeecatch_get_pc_from_ucontext(&t->uc);
            snprintf(&buffer[buffer_offs], buffer_len - buffer_offs, " ");
            buffer_offs += strlen(&buffer[buffer_offs]);
            format_pc_address(&buffer[buffer_offs], buffer_len - buffer_offs, pc);
            buffer_offs += strlen(&buffer[buffer_offs]);
        }
        /* Return string. */
        buffer[buffer_offs] = '\0';
        return t->stack_buffer;
    } else{
        /* Static buffer in case of emergency */
        static char buffer[256];
#ifdef _GNU_SOURCE
        return strerror_r(error, &buffer[0], sizeof(buffer));
#else
        const int code = strerror_r(error, &buffer[0], sizeof(buffer));
        errno = error;
        if (code == 0) {
            return buffer;
        } else {
            return "unknown error during crash handler setup";
        }
#endif
    }
}
/**
 * Enumerate backtrace information.
 */
void coffeecatch_get_backtrace_info(void (*fun)(void *arg,
                                                const char *module,
                                                uintptr_t addr,
                                                const char *function,
                                                uintptr_t offset), void *arg) {
    const native_code_handler_struct* const t = coffeecatch_get();
    if (t != NULL) {
        size_t i;
        for(i = 0; i < t->frames_size; i++) {
            const uintptr_t pc = t->frames[i].absolute_pc;
            format_pc_address_cb(pc, fun, arg);
        }
    }
}

size_t coffeecatch_get_backtrace_size(void) {
#ifdef USE_UNWIND
    const native_code_handler_struct* const t = coffeecatch_get();
    if (t != NULL) {
        return t->frames_size;
    } else {
        return 0;
    }
#else
    return 0;
#endif
}







