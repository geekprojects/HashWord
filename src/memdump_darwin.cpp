
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/mach_vm.h>
#include <mach/shared_region.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>

bool dumpmem()
{
    FILE* fd = fopen("hashword.dump", "w");

    mach_msg_type_number_t count = TASK_BASIC_INFO_64_COUNT;
    task_t task;
    kern_return_t error;
    struct task_basic_info_64 taskinfo;

    task = mach_task_self();
    error = task_info(task, TASK_BASIC_INFO_64, (task_info_t)&taskinfo, &count);
    if (error != KERN_SUCCESS)
    {
        printf("scanmem: failed to get task info\n");
        return false;
    }

    mach_vm_address_t address = 0;
    while (true)
    {
        mach_vm_size_t size;
        vm_region_top_info_data_t info;
        mach_port_t object_name;

        count = VM_REGION_TOP_INFO_COUNT;

/*
        printf("scanmem: address=0x%llx\n", address);
*/

        error = mach_vm_region(
            task,
            &address,
            &size,
            VM_REGION_TOP_INFO,
            (vm_region_info_t)&info,
            &count,
            &object_name);
        if (error != KERN_SUCCESS)
        {
            break;
        }
/*
        printf("scanmem:  -> size=%llu\n", size);
*/

        vm_region_basic_info_data_64_t basic_info;
        count = VM_REGION_BASIC_INFO_COUNT_64;
        error = mach_vm_region(
            task,
            &address,
            &size,
            VM_REGION_BASIC_INFO,
            (vm_region_info_t)&basic_info,
            &count,
            &object_name);
        if (error != KERN_SUCCESS)
        {
            break;
        }

/*
        printf("scanmem:  -> protection=0x%x\n", basic_info.protection);
*/

        if (basic_info.protection & VM_PROT_READ)
        {
            fwrite((void*)address, size, 1, fd);
        }

        address += size;
    }

    fclose(fd);

    return true;
}

#if 0
int main(int argc, char** argv)
{
    dumpmem();
    return 0;
}
#endif

