#include <linux/replay.h>

struct file_list_name_struct {
	int length;
	char filename[MAX_LOGDIR_STRLEN+20];
};

struct file_list_struct {
	int ignored_count;
	struct file_list_name_struct* ignored_list;
	int modify_count;
	struct file_list_name_struct* modify_list;
	struct mutex file_list_mutex;
};


int init_file_list (struct file_list_struct* file_list, char* file_list_path);
void free_file_list (struct file_list_struct *file_list);
inline int is_ignored_file (struct file_list_struct *file_list, const char* filename);
inline int is_modify_file (struct file_list_struct *file_list, const char* filename);
