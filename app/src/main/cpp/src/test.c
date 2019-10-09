//
// Created by ThinkPad on 2019/10/8.
//
#include <stdio.h>
#include <stdlib.h>
#include "JniLog.h"
#include "JniLog.h"

#define  MY_TEST

void test1(){
    int a = 0;
    int b = 10;
    int c = 0;
    c = b / a;

    LOGD("this is function test1");
}

void test2(){
#if defined(MY_TEST)
    LOGD("this is function test2 define MY_TEST");
#endif
    LOGD("this is function test2 simple logout");
#if defined(MY_TEST1)
    LOGD("this is function test2 define MY_TEST1");
#endif
#if !defined(MY_TEST2)
    LOGD("this is function test2 define MY_TEST2");
#endif
}

void test3(){
    int *point = NULL;
    *point = 500;

    LOGD("this is function test1");
}



