#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/err.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>
#include <linux/mm.h>

/* Debug */
#define ERR(...)    pr_alert("smc_forward: " __VA_ARGS__)


/* IOCTL definition */
#define IOCTL_SMC     _IOWR('s', 0, struct smc_data*) // send smc

#define NR_SMC_ARGS 7

struct smc_data {
    uint64_t args[NR_SMC_ARGS];
};

/* Char dev variables */
dev_t dev = 0;
static struct class *dev_class;
static struct cdev smc_forward_cdev;

/*
** Function Prototypes
*/
static int      __init smc_forward_init(void);
static void     __exit smc_forward_exit(void);
static int      smc_forward_open(struct inode *inode, struct file *file);
static int      smc_forward_release(struct inode *inode, struct file *file);
static long     smc_forward_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int      smc_call(struct smc_data *data);

/*
** File operation sturcture
*/
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        // .open           = smc_forward_open,
        // .release        = smc_forward_release,
        .unlocked_ioctl = smc_forward_ioctl,
};

/*
 * Call SMC
 * Register name depend on the architecture
 * (stolen from driver/misc/tzdev/4.2.1/tzdev_internal.h)
 */
#define CONFIG_ARM64 1

#if defined(CONFIG_ARM)
#define REGISTERS_NAME  "r"
#define ARCH_EXTENSION  ".arch_extension sec\n"
#define PARAM_REGISTERS "r7"
#elif defined(CONFIG_ARM64)
#define REGISTERS_NAME  "x"
#define ARCH_EXTENSION  ""
#define PARAM_REGISTERS "x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17"
#endif /* CONFIG_ARM */

#define SMC_NO(x)            "" # x
#define SMC(x)               "smc " SMC_NO(x)


char* global_buf = 0;

static int smc_call(struct smc_data *data)
{
    register unsigned long _r0 __asm__(REGISTERS_NAME "0") = data->args[0];
    register unsigned long _r1 __asm__(REGISTERS_NAME "1") = data->args[1];
    register unsigned long _r2 __asm__(REGISTERS_NAME "2") = data->args[2];
    register unsigned long _r3 __asm__(REGISTERS_NAME "3") = data->args[3];
    register unsigned long _r4 __asm__(REGISTERS_NAME "4") = data->args[4];
    register unsigned long _r5 __asm__(REGISTERS_NAME "5") = data->args[5];
    register unsigned long _r6 __asm__(REGISTERS_NAME "6") = data->args[6];

    ERR("before: r0 = 0x%lx, r1 = 0x%lx, r2 = 0x%lx\n",
                (unsigned long)_r0, (unsigned long)_r1, (unsigned long)_r2);

    __asm__ __volatile__(ARCH_EXTENSION SMC(0): "+r"(_r0) , "+r" (_r1) , "+r" (_r2),
            "+r" (_r3), "+r" (_r4), "+r" (_r5), "+r" (_r6) : : "memory", PARAM_REGISTERS);

    ERR("after: r0 = 0x%lx, r1 = 0x%lx, r2 = 0x%lx\n",
                (unsigned long)_r0, (unsigned long)_r1, (unsigned long)_r2);

    data->args[0] = _r0;
    data->args[1] = _r1;
    data->args[2] = _r2;
    data->args[3] = _r3;

    return 0;
}


/*
** This function will be called when we write IOCTL on the Device file
*/
static long smc_forward_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

        ERR("IOCTL %x\n", cmd);
        switch(cmd) {
            case IOCTL_SMC:
            {
                struct smc_data __user *smc_data = (struct smc_data __user*) arg;
                struct smc_data smc_args;
                if (!smc_data) {
                    ERR("Null smc_data\n");
                    return -EFAULT;
                }

                ret = copy_from_user(&smc_args, smc_data, sizeof(struct smc_data));
                if (ret != 0) {
                    ERR("copy_from_user failed %x", ret);
                    return -EFAULT;
                }

                smc_call(&smc_args);

                ret = copy_to_user(smc_data, &smc_args, sizeof(struct smc_data));
                if (ret != 0) {
                    ERR("copy_to_user failed %x", ret);
                    return -EFAULT;
                }
                break;
            }
            default:
                ERR("Unknown ioctl %x\n", cmd);
                return -ENOTTY;
        }
        return 0;
}

/*
** Module Init function
*/
static int __init smc_forward_init(void)
{
    /*Allocating Major number*/
    if((alloc_chrdev_region(&dev, 0, 1, "smc_forward")) <0){
            ERR("Cannot allocate major number\n");
            return -1;
    }
    ERR("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

    /*Creating cdev structure*/
    cdev_init(&smc_forward_cdev,&fops);

    /*Adding character device to the system*/
    if((cdev_add(&smc_forward_cdev,dev,1)) < 0){
        ERR("Cannot add the device to the system\n");
        goto r_class;
    }

    /*Creating struct class*/
    if(IS_ERR(dev_class = class_create(THIS_MODULE,"qb_debug"))){
        ERR("Cannot create the struct class\n");
        goto r_class;
    }

    /*Creating device*/
    if(IS_ERR(device_create(dev_class,NULL,dev,NULL,"smc_forward"))){
        ERR("Cannot create the Device 1\n");
        goto r_device;
    }
    return 0;
 
r_device:
        class_destroy(dev_class);
r_class:
        unregister_chrdev_region(dev,1);
        return -1;
}
/*
** Module exit function
*/
static void __exit smc_forward_exit(void)
{
    if( !IS_ERR(dev_class))
        device_destroy(dev_class,dev);

    if( !IS_ERR(dev_class))
        class_destroy(dev_class);

    if( dev != 0 ) {
        cdev_del(&smc_forward_cdev);
    }

    unregister_chrdev_region(dev, 1);
    ERR("Device Driver Remove...Done!!!\n");
}


module_init(smc_forward_init);
module_exit(smc_forward_exit);

MODULE_LICENSE("GPL");