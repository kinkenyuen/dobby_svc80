#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <Dobby/Dobby.h>
#include <sys/syscall.h>

void scan_executable_memory(const uint8_t *target, const uint32_t target_len, void (*callback)(uint8_t *)) {
    const struct mach_header_64 *header = (const struct mach_header_64*) _dyld_get_image_header(0);
    const struct section_64 *executable_section = getsectbynamefromheader_64(header, "__TEXT", "__text");
    
    uint8_t *start_address = (uint8_t *) ((intptr_t) header + executable_section->offset);
    uint8_t *end_address = (uint8_t *) (start_address + executable_section->size);
    
    uint8_t *current = start_address;
    uint32_t index = 0;
    
    uint8_t current_target = 0;
    
    while (current < end_address) {
        current_target = target[index];
        
        // Allow 0xFF as wildcard.
        if (current_target == *current++ || current_target == 0xFF) {
            index++;
        } else {
            index = 0;
        }
        
        // Check if match.
        if (index == target_len) {
            index = 0;
            callback(current - target_len);
        }
    }
}

// ====== PATCH CODE ====== //
void SVC80_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
#if defined __arm64__ || defined __arm64e__
    int syscall_num = (int)(uint64_t)reg_ctx->general.regs.x16;
    if (syscall_num == SYS_ptrace) {
        *(unsigned long *)(&reg_ctx->general.regs.x0) = (unsigned long long)0;
    }
#endif
}

void startHookTarget_SVC80(uint8_t* match) {
#if defined __arm64__ || defined __arm64e__
//    dobby_enable_near_branch_trampoline();
    DobbyInstrument((void *)(match), (DBICallTy)SVC80_handler);
//    dobby_disable_near_branch_trampoline();
#endif
}

%ctor {
    const uint8_t target[] = {
        0x01, 0x10, 0x00, 0xD4  //SVC #0x80
    };
    scan_executable_memory(target, sizeof(target), &startHookTarget_SVC80);
}
