// SPDX-License-Identifier: GPL-2.0
/*
 * ctf_driver.c — CyberTrace CTF Character Device Driver
 *
 * Registers /dev/ctf and exposes three ioctl commands:
 *   CTF_SET_INPUT   — copy user-supplied bytes into the kernel buffer
 *   CTF_CHECK_INPUT — transform the buffer and compare to the target
 *   CTF_GET_STATUS  — return "Correct" or "Wrong" to user space
 *
 * The flag is NEVER stored as plaintext.  The only constant compiled
 * into the module is the *transformed* target.  A player must reverse-
 * engineer the transformation pipeline to reconstruct the original flag.
 *
 * Flag format: CyberTrace{....}
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/ioctl.h>

/* ── Module metadata ──────────────────────────────────────────────────────── */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CyberTrace CTF");
MODULE_DESCRIPTION("CTF character device — can you find the flag?");
MODULE_VERSION("1.0");

/* ── Constants ────────────────────────────────────────────────────────────── */
#define DEVICE_NAME   "ctf"
#define CLASS_NAME    "ctf_class"
#define CTF_BUF_SIZE  64      /* maximum accepted input length              */
#define FLAG_LEN      25      /* exact expected input length (with NUL = 26)*/

/* ── ioctl magic & command numbers ───────────────────────────────────────── */
#define CTF_IOC_MAGIC     0xC7
#define CTF_SET_INPUT     _IOW(CTF_IOC_MAGIC, 0x01, char[CTF_BUF_SIZE])
#define CTF_CHECK_INPUT   _IO (CTF_IOC_MAGIC, 0x02)
#define CTF_GET_STATUS    _IOR(CTF_IOC_MAGIC, 0x03, char[16])

/* ── Transformed target ───────────────────────────────────────────────────
 *
 * This is NOT the flag.  It is the output of transform(flag).
 * The three-step pipeline is:
 *   1. Add each byte's index to its value  (mod 256)
 *   2. Swap adjacent byte pairs            (pair-wise XOR swap)
 *   3. Reverse the entire buffer
 *
 * Computed offline from:  CyberTrace{K3rn3l_M4g1c!}  (length = 25)
 *
 * To recover the flag a solver must:
 *   a) un-reverse  the buffer
 *   b) un-swap     the adjacent pairs
 *   c) subtract    the byte's (new) index from its value (mod 256)
 * ─────────────────────────────────────────────────────────────────────── */
static const unsigned char ctf_target[FLAG_LEN] = {
    0x95, 0x79, 0x38, 0x7b, 0x46, 0x5f, 0x47, 0x7c,
    0x70, 0x7c, 0x42, 0x3f, 0x7f, 0x85, 0x56, 0x6b,
    0x6e, 0x78, 0x68, 0x76, 0x59, 0x64, 0x68, 0x43,
    0x7a
};

/* ── Driver state ─────────────────────────────────────────────────────────── */
static int           ctf_major;
static struct class  *ctf_class;
static struct device *ctf_device;
static struct cdev    ctf_cdev;

/* Per-open session state.  Allocated on open(), freed on release(). */
struct ctf_session {
    unsigned char buf[CTF_BUF_SIZE];  /* raw user input                    */
    size_t        buf_len;            /* how many bytes were written        */
    int           validated;          /* 1 if CHECK_INPUT passed            */
    struct mutex  lock;               /* serialise concurrent ioctls        */
};

/* ── Transformation pipeline ──────────────────────────────────────────────
 *
 * transform(src, len) → dst
 *
 * Step 1 — Index-add:
 *   dst[i] = (src[i] + i) & 0xFF
 *
 * Step 2 — Pair-swap:
 *   for i = 0, 2, 4, … (while i+1 < len):
 *       swap dst[i] and dst[i+1]
 *   (odd-length buffers leave the last byte untouched)
 *
 * Step 3 — Full reverse:
 *   reverse dst[0 … len-1] in place
 */
static void ctf_transform(const unsigned char *src, unsigned char *dst,
                           size_t len)
{
    size_t i;

    /* Step 1: add index to each byte */
    for (i = 0; i < len; i++)
        dst[i] = (unsigned char)((src[i] + (unsigned char)i) & 0xFF);

    /* Step 2: swap adjacent pairs */
    for (i = 0; i + 1 < len; i += 2) {
        unsigned char tmp = dst[i];
        dst[i]     = dst[i + 1];
        dst[i + 1] = tmp;
    }

    /* Step 3: reverse the whole buffer */
    {
        size_t lo = 0, hi = len - 1;
        while (lo < hi) {
            unsigned char tmp = dst[lo];
            dst[lo] = dst[hi];
            dst[hi] = tmp;
            lo++;
            hi--;
        }
    }
}

/* ── File operations ──────────────────────────────────────────────────────── */

static int ctf_open(struct inode *inode, struct file *filp)
{
    struct ctf_session *session;

    session = kzalloc(sizeof(*session), GFP_KERNEL);
    if (!session)
        return -ENOMEM;

    mutex_init(&session->lock);
    filp->private_data = session;

    pr_info("ctf: device opened (pid=%d)\n", current->pid);
    return 0;
}

static int ctf_release(struct inode *inode, struct file *filp)
{
    struct ctf_session *session = filp->private_data;

    if (session) {
        /* Wipe the buffer before freeing — avoid leaving flag fragments */
        memzero_explicit(session->buf, sizeof(session->buf));
        kfree(session);
        filp->private_data = NULL;
    }

    pr_info("ctf: device closed (pid=%d)\n", current->pid);
    return 0;
}

/*
 * CTF_SET_INPUT
 * ─────────────
 * Copies up to CTF_BUF_SIZE bytes from user space into the session buffer.
 * The ioctl argument is a pointer to a char array.
 */
static long ctf_ioctl_set_input(struct ctf_session *session,
                                 unsigned long arg)
{
    unsigned char tmp[CTF_BUF_SIZE];
    size_t len;

    memset(tmp, 0, sizeof(tmp));

    if (copy_from_user(tmp, (void __user *)arg, CTF_BUF_SIZE)) {
        pr_warn("ctf: SET_INPUT copy_from_user failed\n");
        return -EFAULT;
    }

    /* Ensure the buffer is NUL-terminated and measure actual length */
    tmp[CTF_BUF_SIZE - 1] = '\0';
    len = strnlen(tmp, CTF_BUF_SIZE);

    mutex_lock(&session->lock);
    memcpy(session->buf, tmp, len);
    session->buf_len  = len;
    session->validated = 0;   /* reset validation on new input */
    mutex_unlock(&session->lock);

    pr_debug("ctf: SET_INPUT received %zu bytes\n", len);
    return 0;
}

/*
 * CTF_CHECK_INPUT
 * ───────────────
 * Applies the three-step transformation to the stored buffer and compares
 * the result byte-for-byte against the hardcoded target.
 * Sets session->validated = 1 on success.
 */
static long ctf_ioctl_check_input(struct ctf_session *session)
{
    unsigned char transformed[CTF_BUF_SIZE];
    int match;

    mutex_lock(&session->lock);

    /* Reject obviously wrong lengths immediately */
    if (session->buf_len != FLAG_LEN) {
        pr_debug("ctf: CHECK_INPUT wrong length (%zu != %d)\n",
                 session->buf_len, FLAG_LEN);
        session->validated = 0;
        mutex_unlock(&session->lock);
        return 0;
    }

    memset(transformed, 0, sizeof(transformed));
    ctf_transform(session->buf, transformed, session->buf_len);

    /* Constant-time comparison to prevent timing side-channels */
    {
        size_t i;
        unsigned char diff = 0;
        for (i = 0; i < FLAG_LEN; i++)
            diff |= (transformed[i] ^ ctf_target[i]);
        match = (diff == 0);
    }

    if (match) {
        session->validated = 1;
        pr_info("ctf: CHECK_INPUT — CORRECT (pid=%d)\n", current->pid);
    } else {
        session->validated = 0;
        pr_debug("ctf: CHECK_INPUT — wrong answer (pid=%d)\n", current->pid);
    }

    /* Scrub the temporary transformed buffer */
    memzero_explicit(transformed, sizeof(transformed));

    mutex_unlock(&session->lock);
    return 0;
}

/*
 * CTF_GET_STATUS
 * ──────────────
 * Writes a short status string into the caller's buffer:
 *   "Correct"  — if the last CHECK_INPUT call succeeded
 *   "Wrong"    — otherwise
 * The ioctl argument is a pointer to a char[16] receive buffer.
 */
static long ctf_ioctl_get_status(struct ctf_session *session,
                                  unsigned long arg)
{
    const char *msg;
    size_t      msg_len;

    mutex_lock(&session->lock);
    if (session->validated) {
        msg     = "Correct";
        msg_len = 8;   /* includes NUL */
    } else {
        msg     = "Wrong";
        msg_len = 6;
    }
    mutex_unlock(&session->lock);

    if (copy_to_user((void __user *)arg, msg, msg_len)) {
        pr_warn("ctf: GET_STATUS copy_to_user failed\n");
        return -EFAULT;
    }

    pr_debug("ctf: GET_STATUS → \"%s\"\n", msg);
    return 0;
}

/* ── Dispatch ─────────────────────────────────────────────────────────────── */

static long ctf_unlocked_ioctl(struct file *filp, unsigned int cmd,
                                unsigned long arg)
{
    struct ctf_session *session = filp->private_data;

    if (!session)
        return -EINVAL;

    switch (cmd) {
    case CTF_SET_INPUT:
        pr_debug("ctf: ioctl CTF_SET_INPUT\n");
        return ctf_ioctl_set_input(session, arg);

    case CTF_CHECK_INPUT:
        pr_debug("ctf: ioctl CTF_CHECK_INPUT\n");
        return ctf_ioctl_check_input(session);

    case CTF_GET_STATUS:
        pr_debug("ctf: ioctl CTF_GET_STATUS\n");
        return ctf_ioctl_get_status(session, arg);

    default:
        pr_warn("ctf: unknown ioctl 0x%08x\n", cmd);
        return -ENOTTY;
    }
}

/* ── File-ops table ───────────────────────────────────────────────────────── */

static const struct file_operations ctf_fops = {
    .owner          = THIS_MODULE,
    .open           = ctf_open,
    .release        = ctf_release,
    .unlocked_ioctl = ctf_unlocked_ioctl,
};

/* ── Module init / exit ───────────────────────────────────────────────────── */

static int __init ctf_init(void)
{
    dev_t devno;
    int   ret;

    /* 1. Allocate a dynamic major/minor pair */
    ret = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("ctf: alloc_chrdev_region failed (%d)\n", ret);
        return ret;
    }
    ctf_major = MAJOR(devno);

    /* 2. Initialise and add the cdev */
    cdev_init(&ctf_cdev, &ctf_fops);
    ctf_cdev.owner = THIS_MODULE;
    ret = cdev_add(&ctf_cdev, devno, 1);
    if (ret < 0) {
        pr_err("ctf: cdev_add failed (%d)\n", ret);
        goto err_cdev;
    }

    /* 3. Create the /sys/class entry so udev creates /dev/ctf */
    ctf_class = class_create(CLASS_NAME);
    if (IS_ERR(ctf_class)) {
        ret = PTR_ERR(ctf_class);
        pr_err("ctf: class_create failed (%d)\n", ret);
        goto err_class;
    }

    /* 4. Create the device node */
    ctf_device = device_create(ctf_class, NULL, devno, NULL, DEVICE_NAME);
    if (IS_ERR(ctf_device)) {
        ret = PTR_ERR(ctf_device);
        pr_err("ctf: device_create failed (%d)\n", ret);
        goto err_device;
    }

    pr_info("ctf: module loaded — /dev/%s (major=%d)\n",
            DEVICE_NAME, ctf_major);
    pr_info("ctf: good luck, hacker.\n");
    return 0;

err_device:
    class_destroy(ctf_class);
err_class:
    cdev_del(&ctf_cdev);
err_cdev:
    unregister_chrdev_region(devno, 1);
    return ret;
}

static void __exit ctf_exit(void)
{
    dev_t devno = MKDEV(ctf_major, 0);

    device_destroy(ctf_class, devno);
    class_destroy(ctf_class);
    cdev_del(&ctf_cdev);
    unregister_chrdev_region(devno, 1);

    pr_info("ctf: module unloaded\n");
}

module_init(ctf_init);
module_exit(ctf_exit);
