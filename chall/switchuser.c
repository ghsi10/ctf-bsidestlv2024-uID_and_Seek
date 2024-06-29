#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "switchuser"
#define CLASS_NAME "switchuser"
#define MAX_LENGTH 33
#define MIN_LENGTH 8

MODULE_AUTHOR("Idan Strovinsky");
MODULE_DESCRIPTION("Switch users module");
MODULE_LICENSE("GPL");

static DEFINE_MUTEX(switchuser_ioctl_lock);
static long switch_user_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static int major;
static struct class *switchuser_class = NULL;
static struct device *switchuser_device = NULL;
static struct file_operations switchuser_fops = {.unlocked_ioctl = switch_user_ioctl};

typedef struct {
    char password[MAX_LENGTH];
    size_t uid;
    size_t new_uid;
} user_data;

typedef struct {
    unsigned int len;
    char *password;
    size_t uid;
} ioctl_input;

enum switchuser_ioctl_cmd {
    GET_UID = 0x1337,
    SET_UID = 0x1338,
    CHANGE_PASSWORD = 0x1339,
};

char *password = NULL;

void print_log(char *level, const char *function_name, const char *format, ...) {
    va_list args;
    va_start(args, format);
    printk("%s (%s): %s", level, DEVICE_NAME, function_name);
    vprintk(format, args);
    msleep(10);
    va_end(args);
}

char *generate_password(int min_length, int max_length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$";
    int length = min_length + get_random_int() % (max_length - min_length);
    int i;
    char *password = kmalloc(MAX_LENGTH * sizeof(char), GFP_KERNEL);

    if (!password) {
        pr_err("Memory allocation failed.\n");
        return NULL;
    } else {
        for (i = 0; i < length; ++i) {
            get_random_bytes(&password[i], 1);
            password[i] = charset[password[i] % (sizeof(charset) - 1)];
        }

        password[length] = '\0';
        return password;
    }
}

int input_validation(unsigned long arg) {
    ioctl_input input;

    if (copy_from_user(&input, (void *)arg, sizeof(ioctl_input))) {
        print_log(KERN_ERR, __func__, "Failed to copy input from user space\n");
        return -EFAULT;
    }
    if (input.len >= MAX_LENGTH) {
        print_log(KERN_ERR, __func__, "Input validation failed\n");
        return -EINVAL;
    }
    print_log(KERN_DEBUG, __func__, "Validation passed\n");

    return 0;
}

int input_to_user(unsigned long arg, user_data *user) {
    ioctl_input input;

    memset(user, 0, sizeof(user_data));
    user->uid = current_uid().val;
    if (copy_from_user(&input, (void *)arg, sizeof(ioctl_input))) {
        print_log(KERN_ERR, __func__, "Failed to copy input from user space\n");
        return -EFAULT;
    }
    if (copy_from_user(user->password, input.password, input.len)) {
        print_log(KERN_ERR, __func__, "Failed to copy password from user space\n");
        return -EFAULT;
    }
    user->new_uid = input.uid;

    return 0;
}

int user_validation(user_data *user) {
    if (strncmp(password, user->password, strlen(password))) {
        print_log(KERN_ERR, __func__, "Login failed\n");
        return -EINVAL;
    }

    if (user->uid == user->new_uid) {
        print_log(KERN_ERR, __func__, "Cannot switch to the same UID\n");
        return -EPERM;
    }
    if (user->new_uid < 1000) {
        print_log(KERN_ERR, __func__, "Permission denied\n");
        return -EPERM;
    }

    return 0;
}

int switch_uid(unsigned int uid) {
    struct cred *switch_cred;
    struct user_namespace *ns;
    kuid_t kuid;
    kgid_t kgid;

    if (!(switch_cred = prepare_creds())) {
        print_log(KERN_ERR, __func__, "Failed to prepare credentials\n");
        return -ENOMEM;
    }

    ns = current_user_ns();
    kuid = make_kuid(ns, uid);
    kgid = make_kgid(ns, uid);
    if (!uid_valid(kuid) || !gid_valid(kgid)) {
        print_log(KERN_ERR, __func__, "Invalid UID or GID\n");
        return -EINVAL;
    }
    switch_cred->suid = switch_cred->uid = kuid;
    switch_cred->fsuid = switch_cred->euid = kuid;
    switch_cred->sgid = switch_cred->gid = kgid;
    switch_cred->fsgid = switch_cred->egid = kgid;
    commit_creds(switch_cred);

    return 0;
}

int handle_get_uid(unsigned long arg) {
    unsigned int uid;

    print_log(KERN_DEBUG, __func__, "GET_UID called\n");

    uid = current_uid().val;
    if (copy_to_user((void *)arg, &uid, sizeof(unsigned int))) {
        print_log(KERN_ERR, __func__, "Failed to copy uid to user space\n");
        return -EFAULT;
    }

    return 0;
}

int handle_set_uid(unsigned long arg) {
    int ret_val;
    user_data user;

    print_log(KERN_DEBUG, __func__, "SET_UID called\n");

    if ((ret_val = input_validation(arg))) {
        return ret_val;
    }

    if ((ret_val = input_to_user(arg, &user))) {
        return ret_val;
    }

    if ((ret_val = user_validation(&user))) {
        return ret_val;
    }

    if ((ret_val = switch_uid(user.new_uid))) {
        return ret_val;
    }

    return 0;
}

int handle_change_password(unsigned long arg) {
    int ret_val;
    user_data user;

    print_log(KERN_DEBUG, __func__, "CHANGE_PASSWORD called\n");

    if ((ret_val = input_validation(arg))) {
        return ret_val;
    }

    if ((ret_val = input_to_user(arg, &user))) {
        return ret_val;
    }

    if (user.uid != 0) {
        print_log(KERN_ERR, __func__, "Permission denied\n");
        return -EPERM;
    }

    if (strlen(user.password) < MIN_LENGTH) {
        print_log(KERN_ERR, __func__, "The password is too short\n");
        return -EINVAL;
    }

    strncpy(password, user.password, MAX_LENGTH - 1);
    password[MAX_LENGTH - 1] = '\0';

    return 0;
}

static long switch_user_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret_val;

    mutex_lock(&switchuser_ioctl_lock);

    switch (cmd) {
    case GET_UID:
        ret_val = handle_get_uid(arg);
        break;
    case SET_UID:
        ret_val = handle_set_uid(arg);
        break;
    case CHANGE_PASSWORD:
        ret_val = handle_change_password(arg);
        break;
    default:
        print_log(KERN_ERR, __func__, "Invalid command\n");
        ret_val = -EINVAL;
        break;
    }
    mutex_unlock(&switchuser_ioctl_lock);
    return ret_val;
}

static int __init init_switchuser(void) {
    print_log(KERN_INFO, __func__, "Initializing module\n");

    password = generate_password(MIN_LENGTH, MAX_LENGTH);
    if (!password) {
        pr_err("Failed to generate password.\n");
        return -ENOMEM;
    }
    // print_log(KERN_INFO, __func__, "Generated password: %s\n", password);

    major = register_chrdev(0, DEVICE_NAME, &switchuser_fops);
    if (major < 0) {
        print_log(KERN_ERR, __func__, "Failed to register character device\n");
        return -ENOMEM;
    }

    switchuser_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(switchuser_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        print_log(KERN_ERR, __func__, "Failed to create class\n");
        return PTR_ERR(switchuser_class);
    }

    switchuser_device = device_create(switchuser_class, 0, MKDEV(major, 0), 0, DEVICE_NAME);
    if (IS_ERR(switchuser_device)) {
        class_destroy(switchuser_class);
        unregister_chrdev(major, DEVICE_NAME);
        print_log(KERN_ERR, __func__, "Failed to create device\n");
        return PTR_ERR(switchuser_device);
    }

    print_log(KERN_INFO, __func__, "Module initialized successfully\n");

    return 0;
}

static void __exit exit_switchuser(void) {
    print_log(KERN_INFO, __func__, "Exiting module\n");

    if (password) {
        kfree(password);
        password = NULL;
    }

    device_destroy(switchuser_class, MKDEV(major, 0));
    class_unregister(switchuser_class);
    class_destroy(switchuser_class);
    unregister_chrdev(major, DEVICE_NAME);

    print_log(KERN_INFO, __func__, "Module exited\n");
}

module_init(init_switchuser);
module_exit(exit_switchuser);
