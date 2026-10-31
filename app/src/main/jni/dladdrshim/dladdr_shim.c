/*
 * libdladdrshim.so —— 为 Android 4.x 补上缺失的 bionic 符号 `dladdr`
 *
 * 背景：
 *   bionic 直到 Android 5.0 (API 21) 才提供 dladdr / dl_iterate_phdr。
 *   部分第三方爬虫内嵌的加固库（如 ftyguard/wexguard/FishGuard）导入了 dladdr，
 *   在 API<21 上 PLT 懒绑定解析失败 → 首次调用跳转到无效地址 → SIGSEGV。
 *
 * 做法：
 *   本库导出同名符号 `dladdr`，在爬虫 System.load() 之前先被加载。
 *   Android 4.x 的 dlopen 没有命名空间隔离（隔离是 Android 7 才有），
 *   先加载库的导出符号在全局可见，后加载的加固库懒绑定时即可命中。
 *
 * 实现：
 *   解析 /proc/self/maps，找到包含目标地址的那段映射，
 *   由 `起始地址 - 文件偏移` 反推出模块加载基址。
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#ifndef __LP64__
typedef struct {
    const char *dli_fname;
    void       *dli_fbase;
    const char *dli_sname;
    void       *dli_saddr;
} Dl_info;
#endif

#define SHIM_PATH_MAX 256

/* 保存最近一次命中的路径，避免每次 strdup 造成泄漏。
 * 加固库一般在初始化阶段调用一次，简单静态缓冲足够。 */
static char g_path[SHIM_PATH_MAX];

__attribute__((visibility("default")))
int dladdr(const void *addr, Dl_info *info) {
    __android_log_print(ANDROID_LOG_INFO, "dladdrshim", "our dladdr called: addr=%p", addr);
    if (info == NULL) return 0;
    memset(info, 0, sizeof(Dl_info));
    if (addr == NULL) return 0;

    uintptr_t target = (uintptr_t) addr;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) return 0;

    char line[512];
    int hit = 0;
    unsigned long seg_start = 0, seg_end = 0, file_off = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0, end = 0, offset = 0;
        char perms[8];
        int consumed = 0;

        /* 形如：  b6f00000-b6f20000 r-xp 00001000 b3:01 1234   /data/app/.../libfoo.so */
        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %n",
                   &start, &end, perms, &offset, &consumed) < 4) {
            continue;
        }
        if (target < start || target >= end) continue;

        /* 只认带真实文件路径的映射；[anon]、[stack] 之类直接放弃 */
        char *path = line + consumed;
        while (*path == ' ' || *path == '\t') path++;
        char *nl = strpbrk(path, "\r\n");
        if (nl != NULL) *nl = '\0';
        if (*path != '/') continue;

        seg_start = start;
        seg_end   = end;
        file_off  = offset;
        strncpy(g_path, path, SHIM_PATH_MAX - 1);
        g_path[SHIM_PATH_MAX - 1] = '\0';
        hit = 1;
        break;
    }
    fclose(fp);

    if (!hit) return 0;

    info->dli_fname = g_path;
    /* 模块基址 = 该映射起始地址 - 该映射在文件中的偏移 */
    info->dli_fbase = (void *) (uintptr_t) (seg_start - file_off);
    /* 符号级信息（dli_sname/dli_saddr）按 dladdr 规范允许为 NULL */
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    (void) seg_end;
    return 1;
}

/*
 * 编译（NDK r21+，产物放进 app/src/main/jniLibs/armeabi-v7a/）：
 *
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi18-clang \
 *       -shared -fPIC -O2 -Wl,-soname,libdladdrshim.so \
 *       -o libdladdrshim.so dladdr_shim.c
 *
 * 说明：仓库只提交预编译产物（6.6KB），本文件是它的唯一来源。
 * 改完必须重新编译并替换 jniLibs 里的 .so，否则 APK 里仍是旧实现。
 */
