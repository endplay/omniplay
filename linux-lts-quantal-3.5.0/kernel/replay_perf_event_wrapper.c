#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <asm/syscall.h>
#include <linux/perf_event.h>
#include <linux/replay.h>
#include "replay_perf_event_wrapper.h"


struct replay_perf_it {
	
        char buf[BUFFER_SIZE]; //an internal buffer for storing data from the ring buffer
	__u64 index; //the index w/in the mapping
	__u64 head; //the head from the mapping (to reduce number of memory accesses)     
};


/*
 * helper function for coppying from the ring buffer in the replay_perf_event_wrapper
 */
static void copy_from_ring_buffer(struct perf_event_mmap_page* mapping,
				  u_int index, 
				  void* dest, 
				  size_t bytes,
				  unsigned int data_size) {       
	char *base;
	size_t start_index, end_index, chunk1_size, chunk2_size;
	void *chunk2_dest;


	base = (char*)mapping + PAGE_SIZE; 
	start_index = index % data_size;
	end_index = start_index + bytes; 

	if(end_index <= data_size) {
		copy_from_user(dest, (void*)(base + start_index), bytes);
		
	} else {
		chunk2_size = end_index - data_size;
		chunk1_size = bytes - chunk2_size; 

		chunk2_dest = (void*)((u_int *)(dest) + chunk1_size);

		copy_from_user(dest, (void*)(base + start_index), chunk1_size);
		copy_from_user(chunk2_dest, (void*)(base), chunk2_size);
	}
}

static void
write_instructions (struct replay_perf_wrapper *wrapper)
{
	char filename[MAX_LOGDIR_STRLEN+20];
	int fd, rc; 
	struct file* file = NULL;
	mm_segment_t old_fs;
	int copied = 0;
	int to_write, written;

	sprintf (filename, "%s/instructions", wrapper->logdir);
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (wrapper->outpos){
		fd = sys_open(filename, O_WRONLY, 0644);
	} else {
		fd = sys_open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	}
	if (fd < 0) {
		printk("Pid %d write_instructions: could not open file %s, %d\n", current->pid, filename, fd);
		wrapper->bufcnt = 0;
		return;
	}
	file = fget(fd);

	to_write = wrapper->bufcnt*sizeof(__u32);
	do {
		written = vfs_write (file, (char *) wrapper->outbuf+copied, to_write-copied, &wrapper->outpos);
		if (written <= 0) {
			printk ("write_instructions: vfs_write returns %d\n", written);
			break;
		}
		copied += written;
	} while (copied < to_write);
		
	if (copied != to_write) {
		printk("Unable to write instructions, wrote only %d bytes out of %d\n", copied, to_write);
	}

	fput(file);
	rc = sys_close (fd);
	if (rc < 0) printk ("write_instructions: file close failed with rc %d\n", rc);
	set_fs(old_fs);
	wrapper->bufcnt = 0;
}

static void
dump_chars(struct replay_perf_it *it) {
  char *buf = it->buf; 
  
  printk("bytes: ");
  while(buf < (it->buf + ((struct perf_event_header *)it->buf)->size)) { 
	  printk(" %x",*buf);
	  buf++;
  }
  printk("\n");

}
 
static __u32
read_counter(struct replay_perf_wrapper *wrapper) 
{
	int rc;
	long long count;
	mm_segment_t old_fs = get_fs();
	
	set_fs(KERNEL_DS);
	rc = sys_read(wrapper->perf_fd, &count, sizeof(long long));
	set_fs(old_fs);
	return (__u32)count;
}


static void
begin_it(struct replay_perf_wrapper *wrapper, struct replay_perf_it *it) 
{
	int rc;

	rc = copy_from_user(&(it->index), &(wrapper->mapping->data_tail), sizeof(__u64));//weirdly enough, this is what I want. 
	if (rc) printk("bombed out on copy_from_user %d, pointer %p",rc, &(wrapper->mapping->data_tail));
	rc = copy_from_user(&(it->head), &(wrapper->mapping->data_head), sizeof(__u64));//weirdly enough, this is what I want. 
	if (rc) printk("bombed out on copy_from_user %d, pointer %p",rc, &(wrapper->mapping->data_head));

	if (it->head >= (it->index + wrapper->data_size - (sizeof(__u64) + sizeof(struct perf_event_header)))) {
		wrapper->overflow_count += 1;
	}

}

static void
end_it(struct replay_perf_wrapper *wrapper, struct replay_perf_it *it) 
{
	copy_to_user(&(wrapper->mapping->data_tail),&(it->index), sizeof(__u64));
}



static int
it_has_data(struct replay_perf_wrapper *wrapper, struct replay_perf_it *it)
{
	struct perf_event_header hdr;


	if (wrapper->mapping == NULL) {
		return 0;
	}
	if (it->index + sizeof(struct perf_event_header) >= it->head){
		return 0;
	}
	
	copy_from_ring_buffer(wrapper->mapping, it->index, &hdr, sizeof(struct perf_event_header), wrapper->data_size);
	if (it->index + hdr.size > it->head) { 
		return 0;
	}
	return 1;
}


static void
next_it(struct replay_perf_wrapper *wrapper, struct replay_perf_it *it) {
	struct perf_event_header hdr;

	copy_from_ring_buffer(wrapper->mapping, it->index, &hdr, sizeof(struct perf_event_header), wrapper->data_size);
	it->index += hdr.size; //advance to next record
}

static void
get_it(struct replay_perf_wrapper *wrapper, struct replay_perf_it *it){
	struct perf_event_header *header;
	copy_from_ring_buffer(wrapper->mapping, it->index, it->buf, sizeof(struct perf_event_header), wrapper->data_size);
	header = (struct perf_event_header *)it->buf;
	copy_from_ring_buffer(wrapper->mapping, it->index, it->buf, header->size, wrapper->data_size);
}

static __u64
get_ip(struct replay_perf_it *it) { 

	char *buf;
	buf = it->buf + sizeof(struct perf_event_header);
	return *((__u64*)buf); //the value right after the header is the ip
}

/*
 * intialize the perf_event_wrapper. this initilizes the ring_buffer for sampling as well
 */
int
init_replay_perf_wrapper(struct replay_perf_wrapper *wrapper, char *logdir, unsigned int sample_type, unsigned int sample_config, unsigned int sample_period, unsigned int data_size)
{ 
	struct perf_event_attr pe;
	u_long ring_buffer;
	u_int mmap_size;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	wrapper->outbuf = kmalloc(sizeof(__u32)*PERF_OUTBUF_ENTRIES, GFP_KERNEL);
	wrapper->logdir = logdir;
	wrapper->data_size = data_size;
	wrapper->bufcnt = 0;
	wrapper->outpos = 0;
	wrapper->overflow_count = 0;
	wrapper->num_syscalls = 0;
	
	mmap_size = PAGE_SIZE + data_size;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.size = sizeof(struct perf_event_attr);
	pe.type = sample_type;
	pe.config = sample_config;
	
	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;
	pe.sample_period = sample_period;
	pe.sample_type = PERF_SAMPLE_IP;
	wrapper->perf_fd = sys_perf_event_open(&pe, 0, -1, -1, 0);
	if (wrapper->perf_fd < 0) {
		printk("Error opening leader %llx fd %d\n", pe.config, wrapper->perf_fd);
		return -1;
	}
	//this will be a user address
	ring_buffer = sys_mmap_pgoff(0, (mmap_size), PROT_READ | PROT_WRITE, MAP_SHARED, wrapper->perf_fd, 0);
	if (IS_ERR((void *)ring_buffer)) { 
		printk("error making mapping: %p\n", ring_buffer);
		sys_close(wrapper->perf_fd);
		return -1;
	}

	printk("mmaped from 0x%lx to 0x%lx, size 0x%lx, fd %d\n",ring_buffer, ring_buffer + mmap_size, mmap_size, wrapper->perf_fd);
//	print_vmas(current);
	wrapper->first_time = 1;
	wrapper->mapping = (struct perf_event_mmap_page*)ring_buffer;
	printk("init perf_wrapperrapper with type %u config %u period %u\n",
	       sample_type,
	       sample_config,
	       sample_period);

	set_fs(old_fs);
	return 0;
}

void
destroy_replay_perf_wrapper(struct replay_perf_wrapper *wrapper) 
{
	/* cleanup memory in here */
	write_instructions(wrapper);
	printk("finished with wrapper, overflow %d, num_syscalls %d\n",wrapper->overflow_count, wrapper->num_syscalls);
	/*need to kfree some memories!*/
}


void
replay_perf_wrapper_start_sampling(struct replay_perf_wrapper *wrapper) 
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
replay_perf_wrapper_stop_sampling(struct replay_perf_wrapper *wrapper) 
{
	int rc;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = sys_ioctl(wrapper->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
	if (rc < 0) printk("cannot PERF_EVENT_IOC_DISABLE!\n");
	set_fs(old_fs);
}

void
replay_perf_wrapper_iterate(struct replay_perf_wrapper *wrapper)
{
	struct replay_perf_it it;
	__u32 inst;

	replay_perf_wrapper_stop_sampling(wrapper);

	//first write out the counter, only if more than 0 events have occured
	inst = read_counter(wrapper);
	if (inst >0)
		wrapper->outbuf[wrapper->bufcnt++] = inst;

	if (wrapper->bufcnt >= PERF_OUTBUF_ENTRIES) { 
		write_instructions(wrapper);
	}

	begin_it(wrapper, &it); 
	while(it_has_data(wrapper, &it)) { 
		get_it(wrapper, &it); //this loads the buffer

		//convert the ip down to 32 bits for some reason sometimes its 0... perf
		// problems! 

		inst = (__u32)get_ip(&it);
		if (inst > 0) 
			wrapper->outbuf[wrapper->bufcnt++] = inst;
		
		if (wrapper->bufcnt >= PERF_OUTBUF_ENTRIES) { 
			write_instructions(wrapper);
		}
		next_it(wrapper, &it); //this advances the iterator
	}
	wrapper->num_syscalls++;
	wrapper->outbuf[wrapper->bufcnt++] = 0;//end of list
	if (wrapper->bufcnt >= PERF_OUTBUF_ENTRIES) { 
		write_instructions(wrapper);
	}

	end_it(wrapper, &it);
	replay_perf_wrapper_start_sampling(wrapper);
}

