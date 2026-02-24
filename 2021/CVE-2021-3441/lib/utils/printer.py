# Take output from compromise finder and print to file
def printer(payload, url, outfile):
    f = open(outfile,'a')
    f.write(str(url)+':'+str(payload)+'\n')
    f.close()
    return