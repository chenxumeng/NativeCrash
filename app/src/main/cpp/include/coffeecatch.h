//
// Created by ThinkPad on 2019/10/8.
//

#ifndef NATIVECRASH_COFFEECATCH_H
#define NATIVECRASH_COFFEECATCH_H
#ifdef __cplusplus
extern "C" {
#endif

#include <setjmp.h>
extern const char* coffeecatch_get_message();
extern int coffeecatch_inside(void);
extern int coffeecatch_setup(void);
extern sigjmp_buf* coffeecatch_get_ctx(void);
extern void coffeecatch_cleanup(void);
extern void coffeecatch_get_backtrace_info(void (*fun)(void *arg,
                                                       const char *module,
                                                       uintptr_t addr,
                                                       const char *function,
                                                       uintptr_t offset), void *arg);
extern size_t coffeecatch_get_backtrace_size(void);
#define COFFEE_TRY()                                \
  if (coffeecatch_inside() || \
      (coffeecatch_setup() == 0 \
       && sigsetjmp(*coffeecatch_get_ctx(), 1) == 0))
#define COFFEE_CATCH() else
#define COFFEE_END() coffeecatch_cleanup()
#ifdef __cplusplus
}
#endif
#endif //NATIVECRASH_COFFEECATCH_H
