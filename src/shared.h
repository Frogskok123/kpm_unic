#ifndef SHARED_H
#define SHARED_H
#include <linux/types.h>

#define DEVICE_NAME "kpm_universal_pro"
#define IOC_MAGIC 'u'

struct kpm_op {
    int pid;            // Для V2P
    uint64_t vaddr;     // Виртуальный адрес
    uint64_t paddr;     // Физический адрес
    void* buffer;       // Буфер пользователя
    size_t size;        // Размер
    int is_write;       // Флаг записи
};

#define IOCTL_V2P       _IOWR(IOC_MAGIC, 1, struct kpm_op)
#define IOCTL_RW_PHYS   _IOWR(IOC_MAGIC, 2, struct kpm_op)
#endif
