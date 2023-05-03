
import os, time
from collections import Counter
import datetime as DT

now = time.strftime("%Y%m%d-%H%M%S")
current_dir = os.getcwd()
template_file = current_dir + "/ct_sandbox.html"
report_file = current_dir + "/report_"+str(now)+".html"
logfile = "../corethreat_server.log"



def generate_html_report(inp):
    # html report
    global report_file
    
    with open(template_file, "rt") as fin:
        with open(report_file, "wt") as fout:
            for line in fin:
                match = False

                if '{{LOG}}' in line:
                    match = True
                    fout.write(line.replace('{{LOG}}', inp))

                if match == False:
                    fout.write(line)
    return






tr_start = '<tr class="table table-dark table-sm">'
tr_end = '</tr>'
log_entry = ""
log_entry_list = []



with open(logfile, "rt") as log:
        for line in log:

            if "HUMANLOG" in line:
                log_line = '<td>' + line + '</td>'
                log_entry = tr_start + log_line + tr_end
                #print(host_entry)
                log_entry_list.append(log_entry)
                log_entry = ""



#print(host_entry_list)
generate_html_report(''.join(log_entry_list))

