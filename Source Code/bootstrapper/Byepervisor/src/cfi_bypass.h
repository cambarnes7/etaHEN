/*
 * cfi_bypass.h - KCFI Bypass for PS5 FW 3.00+
 *
 * Redirects IDT[6] (#UD) through kstuff's INT1 handler.
 * KCFI UD2 instructions are silently skipped (RIP += 2).
 */

#ifndef CFI_BYPASS_H
#define CFI_BYPASS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Call AFTER kstuff is loaded and initialized.
 * Returns 0 on success, negative on error:
 *   -1 = firmware not supported
 *   -2 = kstuff handler not installed (IDT[1] is null/invalid)
 *   -3 = verification failed
 */
int patch_idt_cfi_bypass(void);

/* Save original IDT[6] before patching (optional, for clean restore) */
int save_original_idt6(void);

/* Restore original IDT[6] handler */
int unpatch_idt_cfi_bypass(void);

#ifdef __cplusplus
}
#endif

#endif /* CFI_BYPASS_H */
