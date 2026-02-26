#include <jni.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <thread>
#include <android/log.h>
#include <sys/mman.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "cheat_native", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "cheat_native", __VA_ARGS__)

void patchAtPerfectTiming() {
    LOGI("=== Perfect Timing URL Patcher ===");
    
    const char* oldUrl = "https://gunyahjohn.pythonanywhere.com:443";
    const char* newUrl = "https://AC-XeraBackend.pythonaywhere.com:443/////";
    
    LOGI("Target URL: %s", oldUrl);
    LOGI("Replacement: %s", newUrl);
    
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return;
    }
    
    char line[1024];
    int patchCount = 0;
    int regionsScanned = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        char path[256] = {0};
        
        if (sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %255s", &start, &end, perms, path) >= 3) {
            
            // Focus on areas where decrypted IL2CPP strings would be
            bool shouldScan = false;
            const char* regionType = "unknown";
            
            if (strstr(path, "libil2cpp.so")) {
                shouldScan = true;
                regionType = "il2cpp";
            } else if (strstr(path, "[heap]")) {
                shouldScan = true;
                regionType = "heap";
            } else if (strstr(path, "[anon:") && (end - start) > 0x100000) {
                shouldScan = true;
                regionType = "large_anon";
            } else if (path[0] == '\0' && (end - start) > 0x50000) {
                shouldScan = true;
                regionType = "anonymous";
            }
            
            if (shouldScan && perms[0] == 'r') {
                regionsScanned++;
                LOGI("Scanning region #%d (%s): 0x%lx-0x%lx %s", regionsScanned, regionType, start, end, perms);
                
                char* mem = (char*)start;
                size_t size = end - start;
                size_t oldLen = strlen(oldUrl);
                
                // Search for the URL
                for (size_t i = 0; i <= size - oldLen; i++) {
                    if (memcmp(mem + i, oldUrl, oldLen) == 0) {
                        LOGI("*** FOUND URL at 0x%lx in %s region ***", start + i, regionType);
                        
                        // Show context around the found URL
                        char before[64] = {0}, after[64] = {0};
                        if (i >= 32) memcpy(before, mem + i - 32, 32);
                        if (i + oldLen + 32 < size) memcpy(after, mem + i + oldLen, 32);
                        LOGI("Before: [%s]", before);
                        LOGI("After:  [%s]", after);
                        
                        // Attempt to patch
                        void* pageAddr = (void*)((start + i) & ~0xFFF);
                        bool patched = false;
                        
                        if (perms[1] == 'w') {
                            // Already writable
                            LOGI("Memory is writable, patching directly");
                            memcpy(mem + i, newUrl, oldLen);
                            patched = true;
                        } else {
                            // Make writable temporarily
                            LOGI("Making memory writable at %p", pageAddr);
                            if (mprotect(pageAddr, 0x1000, PROT_READ | PROT_WRITE) == 0) {
                                memcpy(mem + i, newUrl, oldLen);
                                mprotect(pageAddr, 0x1000, PROT_READ);
                                patched = true;
                                LOGI("Successfully patched with mprotect");
                            } else {
                                LOGE("mprotect failed: %s", strerror(errno));
                            }
                        }
                        
                        if (patched) {
                            patchCount++;
                            LOGI("*** PATCH #%d SUCCESSFUL ***", patchCount);
                            
                            // Verify the patch
                            if (memcmp(mem + i, newUrl, strlen(newUrl)) == 0) {
                                LOGI("Patch verification: SUCCESS");
                            } else {
                                LOGE("Patch verification: FAILED");
                            }
                        }
                    }
                }
            }
        }
    }
    
    fclose(maps);
    
    if (patchCount > 0) {
        LOGI("=== PATCHING SUCCESSFUL! ===");
        LOGI("Successfully patched %d URL instances", patchCount);
    } else {
        LOGE("=== NO URLs FOUND ===");
        LOGI("The URL may not be decrypted yet or might be in a different format");
    }
}

void timedPatcher() {
    LOGI("=== Timed URL Patcher Starting ===");
    
    // Start much earlier - try multiple attempts to catch it right after decryption
    LOGI("=== EARLY PATCH ATTEMPT (5s) ===");
    sleep(5);
    patchAtPerfectTiming();
    
    LOGI("=== PATCH ATTEMPT (7s) ===");
    sleep(2);
    patchAtPerfectTiming();
    
    LOGI("=== PATCH ATTEMPT (9s) ===");
    sleep(2);
    patchAtPerfectTiming();
    
    LOGI("=== PATCH ATTEMPT (11s) ===");
    sleep(2);
    patchAtPerfectTiming();
    
    LOGI("=== FINAL PATCH ATTEMPT (13s) ===");
    sleep(2);
    patchAtPerfectTiming();
    
    LOGI("=== PATCHING SEQUENCE COMPLETE ===");
    LOGI("If any patches succeeded, the URL should be redirected before first use at 15s");
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, [[maybe_unused]] void *reserved) {
    JNIEnv *env;
    vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    
    LOGI("=== JNI_OnLoad - Starting timed patcher ===");
    
    std::thread(timedPatcher).detach();
    
    return JNI_VERSION_1_6;
}
