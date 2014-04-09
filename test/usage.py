#!/usr/bin/python

import os
import glob
import time
import re

print "Cache stats:"
print

count_by_date = {}
bytes_by_date = {}
total_count = 0
total_bytes = 0

for cfile in glob.glob("/replay_cache/*"):
    st = os.stat (cfile)
    ts_string = time.strftime("%m-%d", time.localtime(st.st_ctime))
    count_by_date[ts_string] = count_by_date.get(ts_string,0) + 1
    total_count += 1
    bytes_by_date[ts_string] = bytes_by_date.get(ts_string,0) + st.st_size
    total_bytes += st.st_size

for k in sorted(count_by_date.keys()):
    print "Date %s: %6d files comprising %5d MB" % (k, count_by_date[k], bytes_by_date[k]/(1024*1024))

print "Total:      %6d files comprising %5d MB" % (total_count, total_bytes/(1024*1024))


groups_by_date = {}
total_groups = 0
cbytes_by_date = {}
cfiles_by_date = {}
total_cbytes = 0
kbytes_by_date = {}
total_kbytes = 0
kfiles_by_date = {}
ubytes_by_date = {}
total_ubytes = 0
ufiles_by_date = {}
mbytes_by_date = {}
total_mbytes = 0
mfiles_by_date = {}
xbytes_by_date = {}
total_xbytes = 0
xfiles_by_date = {}

print
print "Log stats:"
print

# Now get list of recordings that fall within the specified range
recordings = {}
for recdir in glob.glob ("/replay_logdb/rec_*"):
    m = re.search("_([0-9]+)$", recdir)
    if m:
        ndx = int(m.groups()[0])
        recordings[ndx] = recdir

reclist = sorted(recordings.keys())
for rec in reclist:
    try:
        for logfile in glob.glob ("/replay_logdb/rec_" + str(rec) + "/*"):
            st = os.stat (logfile)
            ts_string = time.strftime("%m-%d", time.localtime(st.st_ctime))

            m = re.search("ckpt", logfile)
            if m:
                groups_by_date[ts_string] = groups_by_date.get(ts_string, 0) + 1
                total_groups += 1
                cbytes_by_date[ts_string] = cbytes_by_date.get(ts_string, 0) + st.st_size
                total_cbytes += st.st_size
                if not ts_string in cfiles_by_date:
                    cfiles_by_date[ts_string] = {}
                cfiles_by_date[ts_string][logfile] = 1
                continue
            
            m = re.search("klog", logfile)
            if m:
                kbytes_by_date[ts_string] = kbytes_by_date.get(ts_string, 0) + st.st_size
                total_kbytes += st.st_size
                if not ts_string in kfiles_by_date:
                    kfiles_by_date[ts_string] = {}
                kfiles_by_date[ts_string][logfile] = 1
                continue

            m = re.search("ulog", logfile)
            if m:
                ubytes_by_date[ts_string] = ubytes_by_date.get(ts_string, 0) + st.st_size
                total_ubytes += st.st_size
                if not ts_string in ufiles_by_date:
                    ufiles_by_date[ts_string] = {}
                ufiles_by_date[ts_string][logfile] = 1
                continue

            m = re.search("mlog", logfile)
            if m:
                mbytes_by_date[ts_string] = mbytes_by_date.get(ts_string, 0) + st.st_size
                total_mbytes += st.st_size
                if not ts_string in mfiles_by_date:
                    mfiles_by_date[ts_string] = {}
                mfiles_by_date[ts_string][logfile] = 1
                continue
                
            m = re.search("event.log.id.\d+.\d+", logfile)
            if m:
                xbytes_by_date[ts_string] = xbytes_by_date.get(ts_string, 0) + st.st_size
                total_xbytes += st.st_size
                if not ts_string in xfiles_by_date:
                    xfiles_by_date[ts_string] = {}
                xfiles_by_date[ts_string][logfile] = 1
                continue

            m = re.search("reply.log.id.\d+.\d+", logfile)
            if m:
                xbytes_by_date[ts_string] = xbytes_by_date.get(ts_string, 0) + st.st_size
                total_xbytes += st.st_size
                if not ts_string in xfiles_by_date:
                    xfiles_by_date[ts_string] = {}
                xfiles_by_date[ts_string][logfile] = 1
                continue
                
            m = re.search("debug", logfile)
            if m:
                continue

            print logfile, "is of unknown log type"
        
    except OSError:
        print "ckpt missing for record group", rec

for k in sorted(groups_by_date.keys()):
    print "Date %s: %6d groups" % (k, groups_by_date[k]),
    print "%6d MB ckpt" % (cbytes_by_date.get(k,0)/(1024*1024)),
    print "%6d MB klog" % (kbytes_by_date.get(k,0)/(1024*1024)),
    print "%6d MB ulog" % (ubytes_by_date.get(k,0)/(1024*1024)),
    print "%6d MB mlog" % (mbytes_by_date.get(k,0)/(1024*1024)),
    print "%6d MB xlog" % (xbytes_by_date.get(k,0)/(1024*1024)),
    total_bytes = (cbytes_by_date.get(k,0) + kbytes_by_date.get(k,0) + ubytes_by_date.get(k,0) + mbytes_by_date.get(k,0) + xbytes_by_date.get(k,0))/(1024*1024)
    print "%6d MB total" % (total_bytes)

print "Total:      %6d groups" % (total_groups),
print "%6d MB ckpt" % (total_cbytes/(1024*1024)),
print "%6d MB klog" % (total_kbytes/(1024*1024)),
print "%6d MB ulog" % (total_ubytes/(1024*1024)),
print "%6d MB mlog" % (total_mbytes/(1024*1024)),
print "%6d MB xlog" % (total_xbytes/(1024*1024)),
total_bytes = (total_cbytes + total_kbytes + total_ubytes + total_mbytes + total_xbytes)/(1024*1024)
print "%6d MB total" % (total_bytes)

# Now get compressed sizes
print
print "Log with compression stats:"
print

total_ccompressed = 0
total_kcompressed = 0
total_ucompressed = 0
total_mcompressed = 0
total_xcompressed = 0

for k in sorted(groups_by_date.keys()):
    print "Date %s: %6d groups" % (k, groups_by_date[k]),
    day_bytes = 0
    if k in cfiles_by_date:
        fh = open ("/tmp/usage-filelist", "w")
        for f in sorted(cfiles_by_date[k].keys()):
            print >> fh, f
        fh.close()
        os.system ("tar czf /tmp/usage-tarfile -T /tmp/usage-filelist --absolute-names")
        st = os.stat ("/tmp/usage-tarfile")
        print "%6d MB ckpt" % (st.st_size/(1024*1024)),
        day_bytes += st.st_size
        total_ccompressed += st.st_size;
    else:
        print "     0 MB ckpt",
    if k in kfiles_by_date:
        fh = open ("/tmp/usage-filelist", "w")
        for f in sorted(kfiles_by_date[k].keys()):
            print >> fh, f
        fh.close()
        os.system ("tar czf /tmp/usage-tarfile -T /tmp/usage-filelist --absolute-names")
        st = os.stat ("/tmp/usage-tarfile")
        print "%6d MB klog" % (st.st_size/(1024*1024)),
        day_bytes += st.st_size
        total_kcompressed += st.st_size;
    else:
        print "     0 MB klog",
    if k in ufiles_by_date:
        fh = open ("/tmp/usage-filelist", "w")
        for f in sorted(ufiles_by_date[k].keys()):
            print >> fh, f
        fh.close()
        os.system ("tar czf /tmp/usage-tarfile -T /tmp/usage-filelist --absolute-names")
        st = os.stat ("/tmp/usage-tarfile")
        print "%6d MB ulog" % (st.st_size/(1024*1024)),
        day_bytes += st.st_size
        total_ucompressed += st.st_size;
    else:
        print "     0 MB ulog",
    if k in mfiles_by_date:
        fh = open ("/tmp/usage-filelist", "w")
        for f in sorted(mfiles_by_date[k].keys()):
            print >> fh, f
        fh.close()
        os.system ("tar czf /tmp/usage-tarfile -T /tmp/usage-filelist --absolute-names")
        st = os.stat ("/tmp/usage-tarfile")
        print "%6d MB mlog" % (st.st_size/(1024*1024)),
        day_bytes += st.st_size
        total_mcompressed += st.st_size;
    else:
        print "     0 MB mlog",
    if k in xfiles_by_date:
        fh = open ("/tmp/usage-filelist", "w")
        for f in sorted(xfiles_by_date[k].keys()):
            print >> fh, f
        fh.close()
        os.system ("tar czf /tmp/usage-tarfile -T /tmp/usage-filelist --absolute-names")
        st = os.stat ("/tmp/usage-tarfile")
        print "%6d MB xlog" % (st.st_size/(1024*1024)),
        day_bytes += st.st_size
        total_ucompressed += st.st_size;
    else:
        print "     0 MB xlog",
    print "%6d MB total" % (day_bytes/(1024*1024))

print "Total:      %6d groups" % (total_groups),
print "%6d MB ckpt" % (total_ccompressed/(1024*1024)),
print "%6d MB klog" % (total_kcompressed/(1024*1024)),
print "%6d MB ulog" % (total_ucompressed/(1024*1024)),
print "%6d MB mlog" % (total_mcompressed/(1024*1024)),
print "%6d MB xlog" % (total_xcompressed/(1024*1024)),
total_compressed = (total_ccompressed + total_kcompressed + total_ucompressed + total_mcompressed + total_xcompressed)/(1024*1024)
print "%6d MB total" % (total_compressed)
