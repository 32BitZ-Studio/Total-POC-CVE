#include <jni.h>
#include <string.h>
#include <linux/ashmem.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <string>


#define MAPS_LINE_SIZE (256)


extern "C" JNIEXPORT jstring
JNICALL
Java_com_lulu_changxinlu_arbitraryunmap_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_lulu_changxinlu_arbitraryunmap_MainActivity_findLibAddress(JNIEnv *env, jobject instance,
                                                                    jstring libraryName) {
    jlong address = 0;
    const char *library= env->GetStringUTFChars(libraryName, 0);

    FILE* mapsFile = fopen("/proc/self/maps", "rb");
    if (!mapsFile)
        return -errno;

    char lineBuf[MAPS_LINE_SIZE];
    memset(lineBuf, 0, MAPS_LINE_SIZE);

    for (;;) {

        //Stop if we reach EOF
        if (!fgets(lineBuf, sizeof(lineBuf), mapsFile))
            break;

        //Is this a text segment?
        if (!strstr(lineBuf, "r-xp"))
            continue;

        //Is this the library we're looking for?
        if (!strstr(lineBuf, library))
            continue;

        //Find the start and end addresses
        char* tok = strtok(lineBuf, "-");
        address = strtoll(tok, NULL, 16);
        break;
    }

    fclose(mapsFile);
    env->ReleaseStringUTFChars(libraryName, library);
    return address;
}

extern "C"
jint
Java_com_lulu_changxinlu_arbitraryunmap_MainActivity_setAshmemSize(
        JNIEnv *env,
        jobject /* this */,
        jint fd,
        jint size) {
    return ioctl(fd, ASHMEM_SET_SIZE, size);
}