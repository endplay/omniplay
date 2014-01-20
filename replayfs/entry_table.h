#ifndef __ENTRY_TABLE_H__
#define __ENTRY_TABLE_H__

#include "data_entry.h"

struct data_entry *entry_table_get(struct data_entry_desc *desc);
void entry_table_put(struct data_entry *entnry);

#endif

