#include <jni.h>
#include <string>
#include <coffeecatch.h>
#include <coffeejni.h>
#include "JniLog.h"
extern "C" {
    #include "test.h"
}

extern "C" JNIEXPORT jstring JNICALL

Java_com_exam_nativecrash_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    COFFEE_TRY_JNI(env,test3());
    return env->NewStringUTF(hello.c_str());
}
