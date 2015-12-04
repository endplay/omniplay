import matplotlib.pyplot as plt
import numpy as np
import sys

colors = ["","","","#fc8d59","#d73027","#fee090","#4575b4","#ffffbf","#e0f3f8","#91bfdb"]

#epoch_list: a list of each of each epoch and its results
def make_stacked_chart(epoch_list, labels,arange, filename, legend_loc, fig_number):

    adjusted_input = []
    for i in range(len(epoch_list[0])): 
        adjusted_input.append([epoch_list[j][i] for j in range(len(epoch_list))])
        

    #so adjusted_input[0] is the epoch labels that we want to use... and [1] is basically worthless
    width = 1.0
    plt.figure(fig_number)
    
    plt.bar(arange, adjusted_input[3], width, color=colors[3], label=labels[3])
    curr_level = adjusted_input[3]


    for i in range(4,len(adjusted_input)):
        print labels[i],
        print adjusted_input[i]
        plt.bar(arange, adjusted_input[i], width, color=colors[i], label=labels[i], bottom=curr_level)

        for j in range(len(adjusted_input[i])):
            curr_level[j] += adjusted_input[i][j]
            
    
    xlabels = []
    for epoch in epoch_list:
        xlabels.append(str(epoch[1]))         

    plt.ylabel("Time (ms)") #not always! 
    plt.xticks(np.array(arange) + width/2., xlabels)
    plt.legend(loc=legend_loc)
    plt.savefig(filename +".pdf")


def main(): 
    if len(sys.argv) < 2:
        print "must provide results csv"
        print "USAGE: python make_grapy.py <results.csv>"
        return -1

    filename = sys.argv[1]
    file = open(filename,"r")
    lines = file.readlines()
    labels = lines[0].strip().split(",")

    epoch_list = []
    for i in range(1,len(lines)):
        if len(lines[i]) <= 1:
            continue
        epoch_list.append([int(j) for j in lines[i].strip().split(",")])


    #add sum columns:
    start = 1
    end = 1
    sums = []
    sums.append(epoch_list[0]) #should have a sums column for the very first epoch 

    while end < len(epoch_list):
        #if end is at a different epoch now, then we need to append in the sum 
        if epoch_list[start][0] != epoch_list[end][0]: 
            
            print "sum of ", epoch_list[start][0], "start",start,"end",end
            #for each of the values in our epoch_list, 
            # and each of the epochs between [start, end)
            # sum all of the values
            sum_list = []
            sum_list.append(epoch_list[start][0])
            sum_list.append(epoch_list[start][0])

            for i in range(2, len(epoch_list[0])):
                sum = 0
                for index in range(start, end):
                    sum += epoch_list[index][i]
                sum_list.append(sum)

            #epoch_list.insert(end,sum_list)
            sums.append(sum_list)
            #skip the entry we just added
            #end += 1 I dont' think we should be doing this...? 
            start = end
        end +=1

    #fence-post issue:
    sum_list = []
    sum_list.append(epoch_list[start][0])
    sum_list.append(epoch_list[start][0])

    for i in range(2, len(epoch_list[0])):
        sum = 0
        for index in range(start, len(epoch_list)):
            sum += epoch_list[index][i]
        sum_list.append(sum)

    print "sum of", epoch_list[start][0],"start",start,"end",len(epoch_list)
    sums.append(sum_list)

    print "finished generating sums"
    arange = [0]
    curr_loc = 1

    for i in range(1,len(epoch_list)):     
        if epoch_list[i][0] != epoch_list[i-1][0]:
            curr_loc += 1
            arange.append(curr_loc)
        else:
            arange.append(curr_loc)
        curr_loc += 1

    sum_arange = np.arange(len(sums))

    make_stacked_chart(epoch_list,labels,arange,filename, "upper right", 0)
    make_stacked_chart(sums,labels,sum_arange,filename + ".sum", "upper left", 1)


main()
