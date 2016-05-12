import re
import sys
import math

from scipy.stats import t as ttest

START_DELAY = "start_delay"
PIN_TIME  = "pin_time"
DIFT_TIME = "dift_time"
TOTAL_TIME = "total_time"
RECEIVE_TIME = "receive_time"

PREPRUNE_LOCAL = "preprune_local_time"
RECV_FB_TIME = "receive_fb_set_time"

RECV_LIVE_TIME = "receive_live_set_time"
INSERT_LIVE_TIME = "insert_live_set_time"
PRUNE_LIVE_TIME = "prune_live_set_time"
MAKE_LIVE_TIME = "make_live_set_time"
SEND_LIVE_TIME = "send_live_set_wait_time"


RINDEX_MERGE_TIME ="make_rindex_merge_time"
RINDEX_ADDR_TIME = "make_rindex_addr_time"
RINDEX_STREAM_TIME = "make_rindex_stream_time"


OUTPUT_TIME = "output_processing_time"
INDEX_TIME = "index_wait_time"
ADDR_TIME = "address_processing_time"
FINISH_TIME = "finish_time"


INST_INST = "instructions_instrumented"

THRU = "Thru"
TAINT_STATS = "Taint statistics"

FP="Forward Pass Time"
SP="Backward Pass time"

PRUNE_TOTAL_1_TIME = "total_prune_pass_1_time"
PRUNE_TOTAL_2_TIME = "total_prune_pass_2_time"
MAKE_LIVE_TOTAL_TIME = "total_live_set_make_time" #get these idle's separately!
OUTPUT_TOTAL_TIME = "total_output_time"
ADDRESS_TOTAL_TIME = "total_address_time"

ATTRS = [START_DELAY, PIN_TIME, DIFT_TIME, PREPRUNE_LOCAL, RECV_FB_TIME, RECV_LIVE_TIME, INSERT_LIVE_TIME,PRUNE_LIVE_TIME, MAKE_LIVE_TIME, SEND_LIVE_TIME, OUTPUT_TIME, INDEX_TIME, ADDR_TIME, FINISH_TIME]

STREAM_ATTRS = [START_DELAY, PIN_TIME,DIFT_TIME, PREPRUNE_LOCAL, RINDEX_MERGE_TIME, RINDEX_ADDR_TIME,RINDEX_STREAM_TIME,PRUNE_LIVE_TIME, MAKE_LIVE_TIME, SEND_LIVE_TIME, OUTPUT_TIME, INDEX_TIME, ADDR_TIME, FINISH_TIME]


FIRST_PASS = {RINDEX_MERGE_TIME:1,RINDEX_ADDR_TIME:1, RINDEX_STREAM_TIME:1,PRUNE_LIVE_TIME:1,MAKE_LIVE_TIME:1,INSERT_LIVE_TIME:1,RECV_LIVE_TIME:1}
SECOND_PASS = {OUTPUT_TIME:1,INDEX_TIME:1,ADDR_TIME:1,FINISH_TIME:1,SEND_LIVE_TIME:1}

GRAPH_HEADERS = [START_DELAY,PIN_TIME,DIFT_TIME,PREPRUNE_LOCAL, FP,SP]


START_DELAY_DISP = "Start Delay"
PIN_TIME_DISP  = "Instrumentation Time (est.)"
DIFT_TIME_DISP = "Dift Time"
PREPRUNE_LOCAL_DISP = "Preprune Time"
GRAPH_HEADERS_DISP=[START_DELAY_DISP, PIN_TIME_DISP,DIFT_TIME_DISP,PREPRUNE_LOCAL_DISP,FP,SP]

AGGREGATE_ATTRS = [PREPRUNE_LOCAL,FP,SP]


#we don't acutally capture the total insert_live time work, or the total index work... 
COMP_ATTRS = [START_DELAY, PIN_TIME, DIFT_TIME, PREPRUNE_LOCAL, INSERT_LIVE_TIME, INDEX_TIME, RINDEX_MERGE_TIME, RINDEX_ADDR_TIME, RINDEX_STREAM_TIME, FINISH_TIME, PRUNE_TOTAL_1_TIME, PRUNE_TOTAL_2_TIME, MAKE_LIVE_TOTAL_TIME, OUTPUT_TOTAL_TIME, ADDRESS_TOTAL_TIME]

 


class Test_Results:
    def __init__(self): 
        self.epoch_number = 0
        self.number_of_epochs = 0
        self.idle_index = 0

    def get_titles(self):
        attributes = vars(self)
        a = ATTRS
#        if attributes[RINDEX_MERGE_TIME] + attributes[RINDEX_ADDR_TIME] + attributes[RINDEX_STREAM_TIME] > 0:
#        return STREAM_ATTRS
#        return ATTRS
        
        return GRAPH_HEADERS

    def get_values(self):
        values = []
        s = 0
        attributes = vars(self)
        a = GRAPH_HEADERS
#        if attributes[RINDEX_MERGE_TIME] + attributes[RINDEX_ADDR_TIME] + attributes[RINDEX_STREAM_TIME] > 0:
#        a = STREAM_ATTRS
        for attr in a:
            if attr in attributes:
                total_value = attributes[attr]
                values.append(total_value)
                if attr != TOTAL_TIME:
                    s += total_value
            else:
                values.append(0)
        return values

    def get_total_time(self):
        values = []
        s = 0
        attributes = vars(self)
        total_value = attributes[TOTAL_TIME]
        return total_value
        
    def get_compute_time(self):
        values = []
        s = 0
        attributes = vars(self)
        total_value = 0
        for a in COMP_ATTRS:
            total_value += attributes[a]

        for a in attributes:
            if "idle" in a: 
                total_value -= attributes[a] #hopefully this works!

        return total_value

    def print_compute_times(self):
        values = []
        s = 0
        attributes = vars(self)
        total_value = 0
        for a in COMP_ATTRS:
            total_value += attributes[a]
            print a,attributes[a]


        for a in attributes:
            if "idle" in a: 
                print a,attributes[a]
                total_value -= attributes[a]

        print total_value
        print ""
        return total_value


    def create_variable_name(self, string_list):
        var_name = string_list[0].strip().strip(':').lower()
        for i in range(1,len(string_list)):
            var_name += "_" + string_list[i].strip().strip(':').lower()
        return var_name

    def parse_lines(self,lines): 
        for line in lines:
            line = line.strip()
            if len(line) < 1:
                continue
            
            matched = False
            matches = re.findall(r"([a-zA-z: .]+)[ ]+(\d+[.]*\d*)", line)

            for match in matches:
                if match:
                    matched = True

                    variable  = match[0] 
                    value = match[-1]

                    #create the variable name:
                    variable = self.create_variable_name(variable.split())

                    if "total_prune_pass" in variable:
                        
                        var = self.create_variable_name(line.split()[:5])
                        val = line.split()[5]
#                        print var, val
                        setattr(self,var,int(val))


                    if (variable == "send_idle" or variable == "recv_idle"):
                        setattr(self,str(self.idle_index) + variable,int(value))
                        self.idle_index += 1
                            

                    elif "." not in value:
                        setattr(self,variable,int(value))
                    else:
                        setattr(self,variable,str(value))
                
            if not matched and TAINT_STATS not in line and THRU not in line:
                print line.strip(), "did not match any rules"

    def fix_dift_stats(self):
        attrs = vars(self)
        if "dift_began_at" in attrs:
            dift_start = attrs["dift_began_at"]
        else:
            return
        if "dift_ended_at" in attrs:
            dift_end = attrs["dift_ended_at"]
        else:
            return

        dt_sec = int(dift_start.split(".")[0])
        dt_usec = int(dift_start.split(".")[1])        
        de_sec = int(dift_end.split(".")[0])
        de_usec = int(dift_end.split(".")[1])        
        ms_diff = ((de_sec - dt_sec) * 1000 + (de_usec - dt_usec) / 1000)
        ms_diff2 = attrs[RECEIVE_TIME] - ms_diff
                         
        pt = 0.0775116427052 * attrs[INST_INST]


        if ((ms_diff-pt) < 0): 
            print "hmm.. our model suggests that we have negative dift time!"
            pt = ms_diff
            ms_diff = 0
        else:
            ms_diff -= pt #sub out this time
        setattr(self, PIN_TIME, pt)
        setattr(self, DIFT_TIME,ms_diff)
        setattr(self, START_DELAY,ms_diff2)


    def combine_stats(self): 
        fp = 0
        sp = 0 
        attributes = vars(self)

        for a in attributes: 
            if a in FIRST_PASS:
                fp += attributes[a]
            if a in SECOND_PASS:
                sp += attributes[a]
        
        setattr(self, FP, fp)
        setattr(self, SP, sp)


    def get_aggregation_time(self): 
        values = []
        s = 0
        attributes = vars(self)
        total_value = 0
        for a in AGGREGATE_ATTRS:
            total_value += attributes[a]
            
        return total_value                   
        

        

def main(): 

    streamname = "emulab_output/stats/4.node-0.arquinn-QV12221.Dift.emulab.net.dift-stats1"
    t = Test_Results()
    f = open(streamname)
    string = f.readlines()
    t.parse_lines(string)
    streamname = "emulab_output/stats/4.node-0.arquinn-QV12221.Dift.emulab.net.stream-stats1"
    f = open(streamname)
    string = f.readlines()
    t.parse_lines(string)
    t.fix_dift_stats()

    attrs = vars(t)
    print " ".join("(%s,%s)" % item for item in attrs.items())

    print TOTAL_TIME, attrs[TOTAL_TIME]
    calc = attrs[RECEIVE_TIME] + attrs[OUTPUT_TIME]

    if RECV_LIVE_TIME in attrs:
        calc += attrs[RECV_LIVE_TIME]
    if PRUNE_LIVE_TIME in attrs:
        calc += attrs[PRUNE_LIVE_TIME]
    if MAKE_LIVE_TIME in attrs:
        calc += attrs[MAKE_LIVE_TIME]
    if SEND_LIVE_TIME in attrs:
        calc += attrs[SEND_LIVE_TIME]
    if INDEX_TIME in attrs:
        calc += attrs[INDEX_TIME]
    if ADDR_TIME in attrs:
        calc += attrs[ADDR_TIME]

    print "calced", calc





def _relerror(*vargs):
    '''Compute the relative error dz/z for z = x*y given (x, dx), (y, dy)'''
    if len(vargs) == 0:
        return 0
    if type(vargs[1]) == tuple:
        return math.sqrt(sum( (dx/x)**2 for x, dx in vargs if x != 0))
    elif type(vargs[1]) == _Sample:
        return math.sqrt(sum( (x.ci/x.mean)**2 for x in vargs if x.mean != 0 ))

class Sample(object):
    """
    A single experiment within a test
    """
    def __init__(self, count=0, mean=0, std=0, med=0):
        self.mean = 0
        self.std = 0
        self.ci = 0
        self.mean = mean
        self.std = std
        self.median = med
        self.ci  = ttest.ppf(0.975, count-1) * self.std/math.sqrt(count)

    def __div__(self, other):
        r = Sample()
        if self.mean == 0 or other.mean == 0:
            r.mean = 0
            r.std = 0
            r.ci  = 0
        else:
            r.mean = self.mean / other.mean
            r.std = r.mean * _relerror((self.mean, self.std), (other.mean, other.std))
            r.ci  = r.mean * _relerror((self.mean, self.ci), (other.mean, other.ci))
        return r

    def __str__(self):
        return "Mean: " + str(self.mean) + " Median: " + str(self.median) + " ci: " + str(self.ci)
