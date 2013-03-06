/*
 * udbg backend for mambo. To get kernel console also enable
 * CONFIG_HVC_UDBG
 */

#include <linux/kernel.h>
#include <asm/udbg.h>
#include <asm/systemsim.h>

#define SIM_WRITE_CONSOLE_CODE 0
#define SIM_READ_CONSOLE_CODE 60
#define SIM_HALT_CODE 126

static void udbg_fss_real_putc(char c)
{
        callthru3(SIM_WRITE_CONSOLE_CODE, (unsigned long)&c, 1, 1);
}

static int udbg_fss_real_getc(void)
{
        int c;

        while (1) {
                c = callthru0(SIM_READ_CONSOLE_CODE);
                if (c > 0)
                        break;
                callthru0(SIM_HALT_CODE);
        }
        return c;
}

static int udbg_fss_real_getc_poll(void)
{
        int c = callthru0(SIM_READ_CONSOLE_CODE);
        return c <= 0 ? -1 : c;
}

void __init udbg_init_mambo(void)
{
        udbg_putc = udbg_fss_real_putc;
        udbg_getc = udbg_fss_real_getc;
        udbg_getc_poll = udbg_fss_real_getc_poll;
}
