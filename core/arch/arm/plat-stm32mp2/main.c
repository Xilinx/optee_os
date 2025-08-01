// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#include <config.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/rstctrl.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32_serc.h>
#include <drivers/stm32_uart.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <initcall.h>
#include <kernel/abort.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <trace.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB1_BASE, APB1_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB1_BASE, APB1_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB2_BASE, APB2_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB3_BASE, APB3_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB4_BASE, APB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB2_BASE, AHB2_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB3_BASE, AHB3_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB4_BASE, AHB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB5_BASE, AHB5_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SAPB_BASE, SAPB_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SAHB_BASE, SAHB_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);

#define _ID2STR(id)		(#id)
#define ID2STR(id)		_ID2STR(id)

static TEE_Result platform_banner(void)
{
	IMSG("Platform stm32mp2: flavor %s - DT %s", ID2STR(PLATFORM_FLAVOR),
	     ID2STR(CFG_EMBED_DTB_SOURCE_FILE));

	return TEE_SUCCESS;
}

service_init(platform_banner);

/*
 * Console
 *
 * CFG_STM32_EARLY_CONSOLE_UART specifies the ID of the UART used for
 * trace console. Value 0 disables the early console.
 *
 * We cannot use the generic serial_console support since probing
 * the console requires the platform clock driver to be already
 * up and ready which is done only once service_init are completed.
 */
static struct stm32_uart_pdata console_data;

void plat_console_init(void)
{
#ifdef CFG_STM32_UART
	/* Early console initialization before MMU setup */
	struct uart {
		paddr_t pa;
	} uarts[] = {
		[0] = { .pa = 0 },
		[1] = { .pa = USART1_BASE },
		[2] = { .pa = USART2_BASE },
		[3] = { .pa = USART3_BASE },
		[4] = { .pa = UART4_BASE },
		[5] = { .pa = UART5_BASE },
		[6] = { .pa = USART6_BASE },
		[7] = { .pa = UART7_BASE },
		[8] = { .pa = UART8_BASE },
		[9] = { .pa = UART9_BASE },
	};

	static_assert(ARRAY_SIZE(uarts) > CFG_STM32_EARLY_CONSOLE_UART);

	if (!uarts[CFG_STM32_EARLY_CONSOLE_UART].pa)
		return;

	/* No clock yet bound to the UART console */
	console_data.clock = NULL;
	stm32_uart_init(&console_data, uarts[CFG_STM32_EARLY_CONSOLE_UART].pa);
	register_serial_console(&console_data.chip);

	IMSG("Early console on UART#%u", CFG_STM32_EARLY_CONSOLE_UART);
#endif
}

#ifdef CFG_STM32_UART
static TEE_Result init_console_from_dt(void)
{
	struct stm32_uart_pdata *pd = NULL;
	void *fdt = NULL;
	int node = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	fdt = get_embedded_dt();
	res = get_console_node_from_dt(fdt, &node, NULL, NULL);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		fdt = get_external_dt();
		res = get_console_node_from_dt(fdt, &node, NULL, NULL);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return TEE_SUCCESS;
		if (res != TEE_SUCCESS)
			return res;
	}

	pd = stm32_uart_init_from_dt_node(fdt, node);
	if (!pd) {
		IMSG("DTB disables console");
		register_serial_console(NULL);
		return TEE_SUCCESS;
	}

	/* Replace early console with the new one */
	console_flush();
	console_data = *pd;
	register_serial_console(&console_data.chip);
	IMSG("DTB enables console");
	free(pd);

	return TEE_SUCCESS;
}

/* Probe console from DT once clock inits (service init level) are completed */
service_init_late(init_console_from_dt);
#endif /*STM32_UART*/

vaddr_t stm32_rcc_base(void)
{
	static struct io_pa_va base = { .pa = RCC_BASE };

	return io_pa_or_va_secure(&base, 1);
}

void boot_primary_init_intc(void)
{
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

#ifdef CFG_STM32_RIF
void stm32_rif_access_violation_action(void)
{
}
#endif /* CFG_STM32_RIF */

bool stm32mp_allow_probe_shared_device(const void *fdt, int node)
{
	static int uart_console_node = -1;
	static bool once;

	if (!once) {
		get_console_node_from_dt((void *)fdt, &uart_console_node,
					 NULL, NULL);
		once = true;
	}

	/* Allow OP-TEE console to be shared with non-secure world */
	if (node == uart_console_node)
		return true;

	return false;
}

void plat_external_abort_handler(struct abort_info *ai __unused)
{
	/* External abort may be due to SERC events */
	stm32_serc_handle_ilac();
}

void __noreturn do_reset(const char *str __maybe_unused)
{
	struct rstctrl *rstctrl = NULL;

	if (CFG_TEE_CORE_NB_CORE > 1) {
		/* Halt execution of other CPUs */
		interrupt_raise_sgi(interrupt_get_main_chip(),
				    CFG_HALT_CORES_SGI,
				    ITR_CPU_MASK_TO_OTHER_CPUS);
		mdelay(1);
	}

	IMSG("Forced system reset: %s", str);
	console_flush();

	/* Request system reset to RCC driver */
	rstctrl = stm32mp_rcc_reset_id_to_rstctrl(SYS_R);
	rstctrl_assert(rstctrl);
	udelay(100);

	/* Cannot occur */
	panic();
}
