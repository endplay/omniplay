import matplotlib.pyplot as plt
import numpy as np
import copy

data_colors = ["#d73027","#fc8d59","#fee090","#e0f3f8","#91bfdb","#4575b4","#e6f598","#abdda4","#66c2a5","#3288bd","#5e4fa2", "#ffed6f", "#ccebc5","#fdae61"]

#epoch_list: a list of each of each epoch and its results
def make_stacked_chart(epoch_list, labels, arange, filename, fig_number):

    colors = data_colors    
    adjusted_input = []
    with open(filename + ".csv","w+") as csv_file:
        l = ",".join([str(label) for label in labels])
        csv_file.write(l + "\n")
        for e,a in zip(epoch_list,arange):
            output = str(a) + ","
            output += ",".join([str(ep) for ep in e])
            csv_file.write(output + "\n")
            
            

    for i in range(len(epoch_list[0])): 
        adjusted_input.append([epoch_list[j][i] for j in range(len(epoch_list))])
        

    #so adjusted_input[0] is the epoch labels that we want to use... and [1] is basically worthless
    width = 1.0
    fig = plt.figure(fig_number)
    
    plt.bar(arange, adjusted_input[0], width, color=colors[0], label=labels[0], linewidth=0)
    curr_level = adjusted_input[0]

    for i in range(1,len(adjusted_input)):
        c = colors[i]
        l = labels[i]

        plt.bar(arange, adjusted_input[i], width, color=c, label=l, bottom=curr_level, linewidth=0)

        for j in range(len(adjusted_input[i])):
            curr_level[j] += adjusted_input[i][j]
            

    #there is definitely a better labeling algorithm... oh well. 
    xlabels = []
    ranges = []
    curr_num_epochs = -1


    plt.ylabel("Time (ms)")
    legend=plt.legend(bbox_to_anchor=(1.0,1.0), loc=0)
    plt.savefig(filename +".pdf", bbox_extra_artists=[legend],bbox_inches='tight',dpi=500)
    plt.close()

def make_line_chart(xdata, ydata, yerror, labels,filename, fig_number, skip = [], title="",xaxis="",yaxis="", show_perfect_scale = True, show_no_scale = True):
    
    fig = plt.figure(fig_number)
#    plt.xscale("log")
#    plt.yscale("log")

    for i in range(len(ydata)):
        yd = ydata[i]
        ye = yerror[i]
        l = labels[i]
        if l not in skip:
            plt.errorbar(xdata,yd,yerr=ye, label = l)

    none  = [1 for i in xdata]
    perf  = [2**i for i in range(len(xdata))]

    if show_perfect_scale:
        plt.errorbar(xdata,perf,label="perfect_scale")
    if show_no_scale:
        plt.errorbar(xdata,none,label="no_scale")

    legend=plt.legend(bbox_to_anchor=(1.0,1.0), loc=0)

    plt.xlabel(xaxis)
    plt.ylabel(yaxis)
    plt.title(title)

    plt.savefig(filename +".pdf", bbox_extra_artists=[legend],bbox_inches='tight')


def make_bar_chart(data, derr, labels, ticks, filename, fig_number, title="",xaxis="",yaxis=""):
    
    fig = plt.figure(fig_number)

    width = (.9) /  len(labels) #each app gets a fair share of space
    print "width", width
    bars = []

    arange = np.arange(len(data[1])) 
    for d,e,c,i in zip(data, derr, data_colors, range(len(data))):
        a = np.arange(len(d)) 
        bars.append(plt.bar(a + (width * i),d, width, color = c, label = "l", yerr=e))
        
#    legend = plt.legend(bars,labels)
    legend=plt.legend(bars, labels,bbox_to_anchor=(1.0,1.0), loc=0)

    ax = plt.gca()
    ax.set_xticks(arange + (1.5 *width))
    ax.set_xticklabels(ticks)

    plt.xlabel(xaxis)
    plt.ylabel(yaxis)
    plt.title(title)

    plt.savefig(filename +".pdf", bbox_extra_artists=[legend],bbox_inches='tight')

def make_scale_chart(data, derr, line, line_err, ticks,filename, fig_number, title="",xaxis="",yaxis=""):
    
    fig = plt.figure(fig_number)

    width = (.9) 
    bars = []

#    arange = np.arange(data) 
#    plt.yscale("log")    
    a = np.arange(len(data))
    plt.bar(a,data, width, color = data_colors[0], yerr=derr)
    
    a2 = np.append(a, a[-1] + width) #want this line to go all the way to the end of the last bar! 
    yd = [line for x in a2] 
    ye = [line_err for x in a2]

    
    print yd
    print ye

    plt.errorbar(a2,yd,yerr=ye)
    

    ax = plt.gca()
    ax.set_xticks(a + .5)
    ax.set_xticklabels(ticks)

    plt.xlabel(xaxis)
    plt.ylabel(yaxis)
    plt.title(title)

    plt.savefig(filename +".pdf")


    
