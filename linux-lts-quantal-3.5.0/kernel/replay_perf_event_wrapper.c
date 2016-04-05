#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <asm/syscall.h>
#include <linux/perf_event.h>
#include "replay_perf_event_wrapper.h"


struct record_perf_event_it {
	char buf[BUFFER_SIZE]; //an internal buffer for storing data from the ring buffer
	__u64 index; //the index w/in the mapping
};


/*
 * helper function for coppying from the ring buffer in the record_perf_event_wrapper
 */
static void copy_from_ring_buffer(struct perf_event_mmap_page* mapping,
				  u_int index, void* dest, size_t bytes) {       
	char *base;
	size_t start_index, end_index, chunk1_size, chunk2_size;
	void *chunk2_dest;


	base = (char*)mapping + PAGE_SIZE; 
	start_index = index % DATA_SIZE;
	end_index = start_index + bytes; 

	if(end_index <= DATA_SIZE) {
		//	memcpy(dest, (void*)(base + start_index), bytes);
		copy_from_user(dest, (void*)(base + start_index), bytes);
		
	} else {
		chunk2_size = end_index - DATA_SIZE;
		chunk1_size = bytes - chunk2_size; 

		chunk2_dest = (void*)((u_int *)(dest) + chunk1_size);

//		memcpy(dest, (void*)(base + start_index), chunk1_size);
//		memcpy(chunk2_dest, (void*)(base), chunk2_size);
		copy_from_user(dest, (void*)(base + start_index), chunk1_size);
		copy_from_user(chunk2_dest, (void*)(base), chunk2_size);
	}
}
static void
print_vmas (struct task_struct* tsk)
{
	struct vm_area_struct* mpnt;
	char buf[256];

	printk ("vmas for task %d mm %p\n", tsk->pid, tsk->mm);
	down_read (&tsk->mm->mmap_sem);
	for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk ("VMA start %lx end %lx", mpnt->vm_start, mpnt->vm_end);
		if (mpnt->vm_flags & VM_MAYSHARE) {
			printk (" s");
		} else {
			printk (" p");
		}
		if (mpnt->vm_file) {
			printk (" file %s ", dentry_path (mpnt->vm_file->f_dentry, buf, sizeof(buf)));
			if (mpnt->vm_flags & VM_READ) {
				printk ("r");
			} else {
				printk ("-");
			}
			if (mpnt->vm_flags & VM_WRITE) {
				printk ("w");
			} else {
				printk ("-");
			}
			if (mpnt->vm_flags & VM_EXEC) {
				printk ("x");
			} else {
				printk ("-");
			}
		}
		printk ("\n");
	}
	up_read (&tsk->mm->mmap_sem);
}

static void
dump_chars(struct record_perf_event_it *it) {
  char *buf = it->buf; 
  
  printk("bytes: ");
  while(buf < (it->buf + ((struct perf_event_header *)it->buf)->size)) { 
	  printk(" %x",*buf);
	  buf++;
  }
  printk("\n");

}
 

static void
begin_it(struct record_perf_event_wrapper *wrapper, struct record_perf_event_it *it) 
{
	copy_from_user(&(it->index), &(wrapper->mapping->data_tail), sizeof(__u64));//weirdly enough, this is what I want. 
//	it->index = wrapper->mapping->data_tail; //start where we last left off
	printk("begin_it %llx\n",it->index);
}

static void
end_it(struct record_perf_event_wrapper *wrapper, struct record_perf_event_it *it) 
{
	printk("end_it index %llx\n",it->index);
	copy_to_user(&(wrapper->mapping->data_tail),&(it->index), sizeof(__u64));
}



static int
it_has_data(struct record_perf_event_wrapper *wrapper, struct record_perf_event_it *it)
{
	struct perf_event_header hdr;
	__u64 data_head;
	int rc = copy_from_user(&(data_head), &(wrapper->mapping->data_head), sizeof(__u64));//weirdly enough, this is what I want. 

	if (rc) {
		printk("bombed out on copy_from_user %d, pointer %p",rc, &(wrapper->mapping->data_head));
		if (wrapper->first_time) { 
			print_vmas(current);
			wrapper->first_time = 0;
		}

		return 0;
	}


	printk("it_has_data, data_head %llx\n",data_head); //should be getting incremented!
	if (wrapper->mapping == NULL) {
		return 0;
	}
	if (it->index + sizeof(struct perf_event_header) >= data_head){
		return 0;
	}
	
	copy_from_ring_buffer(wrapper->mapping, it->index, &hdr, sizeof(struct perf_event_header));
	if (it->index + hdr.size > data_head) { 
		return 0;
	}
	return 1;
}


static void
next_it(struct record_perf_event_wrapper *wrapper, struct record_perf_event_it *it) {
	struct perf_event_header hdr;

	copy_from_ring_buffer(wrapper->mapping, it->index, &hdr, sizeof(struct perf_event_header));
	it->index += hdr.size; //advance to next record
}

static void
get_it(struct record_perf_event_wrapper *wrapper, struct record_perf_event_it *it){
	struct perf_event_header *header;
	copy_from_ring_buffer(wrapper->mapping, it->index, it->buf, sizeof(struct perf_event_header));
	header = (struct perf_event_header *)it->buf;
	copy_from_ring_buffer(wrapper->mapping, it->index, it->buf, header->size);
}

static __u64 
get_ip(struct record_perf_event_it *it) { 

	char *buf;
	mm_segment_t old_fs = get_fs();
	buf = it->buf + sizeof(struct perf_event_header);
	return *((__u64*)buf); //the value right after the header is the ip
}

/*
 * intialize the perf_event_wrapper. this initilizes the ring_buffer for sampling as well
 */
int
init_record_perf_event_wrapper(struct record_perf_event_wrapper *wrapper, unsigned int sample_period)
{ 
	struct perf_event_attr pe;
	u_long ring_buffer;
	int rc;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

//	wrapper->mapping_shared_pages = kmalloc(sizeof(struct page) * (MMAP_SIZE / PAGE_SIZE), GFP_KERNEL);
//	wrapper->vmas = kmalloc(sizeof(struct vm_area_struct) * (MMAP_SIZE / PAGE_SIZE), GFP_KERNEL);


	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.size = sizeof(struct perf_event_attr);
	pe.type = PERF_TYPE_HARDWARE;
	pe.config = PERF_COUNT_HW_INSTRUCTIONS;
	
	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;
	pe.sample_period = sample_period;
	pe.sample_type = PERF_SAMPLE_IP;
	wrapper->perf_fd = sys_perf_event_open(&pe, 0, -1, -1, 0);
	if (wrapper->perf_fd == -1) {
		printk("Error opening leader %llx\n", pe.config);
		return -1;
	}
	//this will be a user address? 
	ring_buffer = sys_mmap_pgoff(0, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, wrapper->perf_fd, 0);
	if (IS_ERR((void *)ring_buffer)) { 
		printk("error making mapping\n");
		sys_close(wrapper->perf_fd);
		return -1;
	}

	printk("mmaped from 0x%lx to 0x%lx, size 0x%lx, fd %d\n",ring_buffer, ring_buffer + MMAP_SIZE, MMAP_SIZE, wrapper->perf_fd);
	print_vmas(current);
	wrapper->first_time = 1;
	wrapper->mapping = (struct perf_event_mmap_page*)ring_buffer;
	printk("init perf_event_wrapper %p, fd %d, mapping %p, data_head %lld (%p) data_tail %lld (%p), sample_period %u\n",
	       wrapper,
	       wrapper->perf_fd,
	       wrapper->mapping,
	       wrapper->mapping->data_head,
	       &(wrapper->mapping->data_head),
	       wrapper->mapping->data_tail,
	       &(wrapper->mapping->data_tail),
		sample_period);

	set_fs(old_fs);
	return 0;
}

void
destroy_record_perf_event_wrapper(struct record_perf_event_wrapper *wrapper) 
{
	/*
	if (wrapper->mapping != NULL) { 
		kunmap(wrapper->mapping_shared_pages);
		put_page(wrapper->mapping_shared_pages);
		}*/
}


void
record_perf_event_wrapper_start_sampling(struct record_perf_event_wrapper *wrapper) 
{
	int rc;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = sys_ioctl(wrapper->perf_fd, PERF_EVENT_IOC_RESET, 0);
	if (rc < 0) printk("cannot PERF_EVENT_IOC_RESET!\n");
	rc = sys_ioctl(wrapper->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (rc < 0) printk("cannot PERF_EVENT_IOC_ENABLE!\n");
	set_fs(old_fs);
}

void
record_perf_event_wrapper_stop_sampling(struct record_perf_event_wrapper *wrapper) 
{
	int rc;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = sys_ioctl(wrapper->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
	if (rc < 0) printk("cannot PERF_EVENT_IOC_DISABLE!\n");
	set_fs(old_fs);
}

void
read_counter(struct record_perf_event_wrapper *wrapper) 
{
	int rc;
	long long count;
	mm_segment_t old_fs = get_fs();
	
	set_fs(KERNEL_DS);
	rc = sys_read(wrapper->perf_fd, &count, sizeof(long long));
	printk("read %lld from the perf_fd\n",count);
	set_fs(old_fs);

}
void
record_perf_event_wrapper_iterate(struct record_perf_event_wrapper *wrapper) //potentially also take in hashtable?
{
	struct record_perf_event_it it;
//	memset(&it, 0, sizeof(struct record_perf_event_it));

	read_counter(wrapper);

	begin_it(wrapper, &it);

	while(it_has_data(wrapper, &it)) { 
		get_it(wrapper, &it); //this loads the buffer
		printk("next index %llx, ip %llx\n",(it.index), get_ip(&it));
		next_it(wrapper, &it); //this advances the iterator
	}
	end_it(wrapper, &it);
}
