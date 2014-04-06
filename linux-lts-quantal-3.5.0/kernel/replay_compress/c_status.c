#include <linux/c_status.h>
#include <linux/kernel.h>

void status_init(struct status_info* s) {
	unsigned int i;
	for (i = 0; i < STATS_OPCODE_MAX; i++) {
		s->status_count_[i] = 0;
		s->status_bitsIn_[i] = 0;
		s->status_bitsOut_[i] = 0;
	}
}
void status_add(struct status_info *s,unsigned int opcode, unsigned int bitsIn, unsigned int bitsOut) {
	s->status_count_[opcode]++;
	s->status_bitsIn_[opcode] += bitsIn;
	s->status_bitsOut_[opcode] += bitsOut;
}

void status_summarize(struct status_info *s,unsigned int *bitsIn, unsigned int *bitsOut) {
	unsigned int totalBitsIn = 0;
	unsigned int totalBitsOut = 0;
	unsigned int i;

	//printk("\nmsg\t\tbits\tbits\tcompression\n");
	printk("\nmsg\t\tbytes\tbytes\tcompression\n");
	printk("type\tcount\tin\tout\tratio\n");
	printk("----\t-----\t-----\t-----\t-----------\n");
	for (i = 0; i < STATS_OPCODE_MAX; i++)
		if (s->status_count_[i]) {
			totalBitsIn += s->status_bitsIn_[i];
			totalBitsOut += s->status_bitsOut_[i];

			if (i == 256) {
				printk("other");
			} else {
				printk("%u", i);
			}
			/*printk("\t%u\t%u\t%u\t%f\t:1\n", s->status_count_[i],
					s->status_bitsIn_[i], s->status_bitsOut_[i],
					(double) s->status_bitsIn_[i] / (double) s->status_bitsOut_[i]);*/


			printk("\t%u\t%u\t%u\t\n", s->status_count_[i],
					s->status_bitsIn_[i]/8, s->status_bitsOut_[i]/8);

		}

	*bitsIn = totalBitsIn;
	*bitsOut = totalBitsOut;
}
