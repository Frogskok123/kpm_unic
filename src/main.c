#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/kprobes.h>
#include <linux/sched/mm.h>
#include <linux/version.h>
#include "shared.h"
#include "kpm.h" // APatch Headers

KPM_NAME("KPM_Universal_Pro");
KPM_VERSION("3.0.0");
KPM_DESCRIPTION("Supports Kernel 5.4 - 6.12 | Kprobes & Kmap");

// Указатели на функции
void* (*k_kmap_local)(struct page *page);
void (*k_kunmap_local)(void *addr);
struct task_struct* (*k_find_task)(int vpid);

// Поиск символов через kprobes (универсально для GKI)
static void* find_sym(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    void *addr = NULL;
    if (register_kprobe(&kp) < 0) return NULL;
    addr = kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

// Page Table Walk (V2P)
uint64_t v2p_walk(struct mm_struct *mm, uint64_t vaddr) {
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd)) return 0;
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d)) return 0;
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud)) return 0;
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) return 0;
    if (pmd_huge(*pmd)) return (pmd_val(*pmd) & PMD_MASK) | (vaddr & ~PMD_MASK);
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) return 0;
    return (pte_val(*pte) & PTE_ADDR_MASK) | (vaddr & ~PAGE_MASK);
}

// Безопасное чтение/запись физической памяти
static int phys_rw(uint64_t paddr, void* buf, size_t size, int write) {
    struct page *page = pfn_to_page(paddr >> PAGE_SHIFT);
    uint64_t offset = paddr & (PAGE_SIZE - 1);
    void *vaddr;

    if (!pfn_valid(paddr >> PAGE_SHIFT)) return -EINVAL;
    
    vaddr = k_kmap_local(page); // Используем найденный kmap
    if (!vaddr) return -ENOMEM;

    if (write) copy_from_user(vaddr + offset, buf, size);
    else copy_to_user(buf, vaddr + offset, size);

    k_kunmap_local(vaddr);
    return 0;
}

static long kpm_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct kpm_op op;
    if (copy_from_user(&op, (void*)arg, sizeof(op))) return -EFAULT;

    if (cmd == IOCTL_V2P) {
        struct task_struct *task;
        struct mm_struct *mm;
        rcu_read_lock();
        task = k_find_task(op.pid);
        if (task && (mm = get_task_mm(task))) {
            op.paddr = v2p_walk(mm, op.vaddr);
            mmput(mm);
        }
        rcu_read_unlock();
        copy_to_user((void*)arg, &op, sizeof(op));
    } else if (cmd == IOCTL_RW_PHYS) {
        return phys_rw(op.paddr, op.buffer, op.size, op.is_write);
    }
    return 0;
}

static struct file_operations fops = { .unlocked_ioctl = kpm_ioctl };

static long kpm_init(const char *args) {
    k_find_task = find_sym("find_task_by_vpid");
    // Выбор kmap в зависимости от версии
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    k_kmap_local = find_sym("kmap_local_page");
    k_kunmap_local = find_sym("kunmap_local");
#else
    k_kmap_local = find_sym("kmap_atomic");
    k_kunmap_local = find_sym("kunmap_atomic");
#endif
    if (!k_kmap_local || !k_find_task) return -1;
    return register_chrdev(0, DEVICE_NAME, &fops) < 0 ? -1 : 0;
}
KPM_INIT(kpm_init);
