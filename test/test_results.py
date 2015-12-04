import re
import sys

class Test_Results:
    def __init__(self): 
        self.epoch_number = 0
        self.number_of_epochs = 0
        self.total_time = 0
        self.start_time = 0
        self.receive_time = 0 #won't be displayed as is
        self.dift_time = 0
        self.output_processing_time = 0
        self.finish_time =  0
        self.index_generation_time = 0
        self.address_processing_time = 0 #needs to be adjusted to remove idle time
        self.idle = 0

        self.output_directs = 0
        self.output_indirects = 0 
        self.output_values = 0
        self.output_merges = 0
        self.address_tokens = 0 
        self.passthrus = 0
        self.resolved = 0
        self.indirects = 0 
        self.values = 0
        self.unmodified = 0
        self.merges = 0
        self.output_other = 0
        self.address_cleared = 0


    @staticmethod
    def get_titles():
        return ["Number of Epochs", "Epoch number", 'Total Time', "Start Delay", "Dift Time", "Output Processing Time",\
                "Index Generation Time", "Idle Time","Address Processing Time", "Finish Time"]

    @staticmethod
    def get_data_titles():
        return ["Number of Epochs", "Epoch number", 'Total Time',"Output Directs", "Output Indirects", 'Output Other', "Output Merges", "Address Tokens", "Passthrus", "Resolved", "Address Indirects", "Address Unmodified", "Address Cleared", "Address Merges"]


    def get_values(self):
        return [self.number_of_epochs, self.epoch_number, self.total_time, self.start_time, self.dift_time, \
                    self.output_processing_time, self.index_generation_time, self.idle, self.address_processing_time,\
                    self.finish_time]



    #merges is on this list multiple times...? The third value is bs... its included b/c its bs-ly included above
    def get_data_values(self): 
        return [self.number_of_epochs, self.epoch_number, self.total_time,self.output_directs, self.output_indirects, self.output_other, self.output_merges, self.address_tokens, self.passthrus, self.resolved, self.indirects, self.unmodified, self.address_cleared,self.merges]
        
    def create_variable_name(self, string_list):
        var_name = string_list[0].strip().strip(':').lower()
        for i in range(1,len(string_list)):
            var_name += "_" + string_list[i].strip().strip(':').lower()
        return var_name


    def parse_lines(self,lines): 
        
#        sys.stderr.write("input to parse_lines: ")
#        sys.stderr.write(str(lines))
#        sys.stderr.write("\n")

        for line in lines:
            line = line.strip()
            if len(line) < 1:
                continue
            
            matched = False
            matches = re.findall(r"([a-zA-z: ]+)[ ]+(\d+)", line)

            for match in matches:
                if match:
                    matched = True
                
#                    print "matched ",match
                
                    #might want to iterate here..
                    variable  = match[0] 
                    value = match[-1]

                    #create the variable name:
                    variable = self.create_variable_name(variable.split())
                    setattr(self,variable,int(value))
                
            if not matched:
                print line.strip(), "did not match any rules"


    def compute_other_values(self):
        self.dift_time = self.receive_time - self.start_time 
        self.address_processing_time = self.address_processing_time - self.idle
        

    def compute_other_data_values(self):
        self.output_other = self.output_values - self.output_directs - self.output_indirects
        self.address_cleared = self.values - self.indirects - self.resolved - self.passthrus - self.unmodified




def main(): 

    streamname = "stream-stats"
    t = Test_Results()
    f = open(streamname)
    string = f.readlines()
    print "stream string: "
    print string

    t.parse_lines(string)

    attrs = vars(t)
    print " ".join("(%s,%s)" % item for item in attrs.items())
    
    print Test_Results.get_data_titles()
    #
    print t.get_data_values()

