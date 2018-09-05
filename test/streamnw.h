#ifndef __STREAMNW_H__
#define __STREAMNW_H__

long safe_read (int s, void* buf, u_long size);
long safe_write (int s, void* buf, u_long size);
long fetch_file (int s, const char* dest_dir);
long send_file (int s, const char* pathname, const char* filename);

#endif
