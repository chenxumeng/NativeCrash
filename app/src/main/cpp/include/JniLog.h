//
// Created by ThinkPad on 2019/10/8.
//

#ifndef NATIVECRASH_JNILOG_H
#define NATIVECRASH_JNILOG_H
#include  <android/log.h>

// log标签
#define  TAG    "NativeCatch"
// 定义info信息
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
// 定义debug信息
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
// 定义error信息
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
#endif //NATIVECRASH_JNILOG_H
