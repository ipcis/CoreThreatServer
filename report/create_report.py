
import os, time
from collections import Counter
import datetime as DT

now = time.strftime("%Y%m%d-%H%M%S")
current_dir = os.getcwd()
template_file = current_dir + "/ct_sandbox.html"
report_file = current_dir + "/report_"+str(now)+".html"
logfile = "../corethreat_server.log"




def count_event(event_name):
    file = open(logfile, "r")
    data = file.read()
    occurrences = data.count(event_name)
    #print('Number of occurrences of the word :', occurrences)
    return occurrences 



def generate_html_report(inp):
    # html report
    global report_file
    
    with open(template_file, "rt") as fin:
        with open(report_file, "wt") as fout:
            for line in fin:
                match = False

                if '{{PROCESS_COUNT}}' in line:
                    match = True
                    count_val = count_event("Event ID 1:")
                    fout.write(line.replace('{{PROCESS_COUNT}}', str(count_val)))

                if '{{NETWORK_COUNT}}' in line:
                    match = True
                    count_val = count_event("Event ID 3:")
                    count_val = count_val + count_event("Event ID 22:")
                    fout.write(line.replace('{{NETWORK_COUNT}}', str(count_val)))

                if '{{FILE_COUNT}}' in line:
                    match = True
                    count_val = count_event("Event ID 11:")
                    fout.write(line.replace('{{FILE_COUNT}}', str(count_val)))

                if '{{REGISTRY_COUNT}}' in line:
                    match = True
                    count_val = count_event("Event ID 12:")
                    count_val = count_val + count_event("Event ID 13:")
                    count_val = count_val + count_event("Event ID 14:")
                    fout.write(line.replace('{{REGISTRY_COUNT}}', str(count_val)))


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

