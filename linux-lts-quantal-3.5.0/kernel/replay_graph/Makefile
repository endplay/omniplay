#
# Makefile for the linux kernel.
#

obj-y     = replayfs_filemap.o replayfs_btree.o replayfs_diskalloc.o \
            replayfs_btree128.o


$(obj)/configs.o: $(obj)/config_data.h

# config_data.h contains the same information as ikconfig.h but gzipped.
# Info from config_data can be extracted from /proc/config*
targets += config_data.gz
$(obj)/config_data.gz: $(KCONFIG_CONFIG) FORCE
	$(call if_changed,gzip)

      filechk_ikconfiggz = (echo "static const char kernel_config_data[] __used = MAGIC_START"; cat $< | scripts/bin2c; echo "MAGIC_END;")
targets += config_data.h
$(obj)/config_data.h: $(obj)/config_data.gz FORCE
	$(call filechk,ikconfiggz)

$(obj)/time.o: $(obj)/timeconst.h

quiet_cmd_timeconst  = TIMEC   $@
      cmd_timeconst  = $(PERL) $< $(CONFIG_HZ) > $@
targets += timeconst.h
$(obj)/timeconst.h: $(src)/timeconst.pl FORCE
	$(call if_changed,timeconst)
