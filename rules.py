
import os

'''
https://attack.mitre.org/techniques/T1087/001/


ID : "123456789"
Name : "Testrule"
Description : "Testrule"
MITREID : "T1087.001" 
EventID : ""
String_1 : "" , all
String_2 : "" , commandline
String_3 : "" , image
'''

debug_mode = False


message_block = "dies ist ein test"
m_EventID = "10"

rule_array = []
rule_index_array = []



def create_Message_Dict():
    message = dict()

    m_all = ""
    m_ComputerName = ""
    m_Image = ""
    m_TargetImage = ""
    m_ParentImage = ""
    m_SourceImage = ""
    m_ImageLoaded = ""
    m_ParentCommandLine = ""
    m_TargetFilename = ""
    m_User = ""
    m_RuleName = ""
    m_MD5 = ""
    m_Signed = ""
    m_Signature = ""
    m_SignatureStatus = ""
    m_OriginalFileName = ""
    m_TargetUser = ""
    m_SourceIP = ""
    m_DestinationIP = ""
    m_SourcePort = ""
    m_DestinationPort = ""
    m_DestinationHostname = ""
    m_CommandLine = ""
    m_QueryName = ""
    m_QueryResults = ""



   # EventID
    message["EventID"] = m_EventID

    # ComputerName
    message["ComputerName"] = m_ComputerName
    
    # Image
    message["Image"] = m_Image
        
    # TargetImage
    message["TargetImage"] = m_TargetImage
        
    # ParentImage
    message["ParentImage"] = m_ParentImage
        
    # SourceImage
    message["SourceImage"] = m_SourceImage
        
    # ImageLoaded
    message["ImageLoaded"] = m_ImageLoaded
        
    # ParentCommandLine
    message["ParentCommandLine"] = m_ParentCommandLine
    
    # TargetFilename
    message["TargetFilename"] = m_TargetFilename
    
    # User
    message["User"] = m_User
    
    # RuleName
    message["RuleName"] = m_RuleName
    
    # MD5
    message["MD5"] = m_MD5
    
    # Signed
    message["Signed"] = m_Signed
    
    # Signature
    message["Signature"] = m_Signature
        
    # SignatureStatus
    message["SignatureStatus"] = m_SignatureStatus
        
    # OriginalFileName
    message["OriginalFileName"] = m_OriginalFileName
        
    # TargetUser
    message["TargetUser"] = m_TargetUser
        
    # SourceIP
    message["SourceIP"] = m_SourceIP
        
    # DestinationIP
    message["DestinationIP"] = m_DestinationIP
        
    # SourcePort
    message["SourcePort"] = m_SourcePort
        
    # DestinationPort
    message["DestinationPort"] = m_DestinationPort
        
    # DestinationHostname
    message["DestinationHostname"] = m_DestinationHostname
        
    # CommandLine
    message["CommandLine"] = m_CommandLine
        
    # QueryName
    message["QueryName"] = m_QueryName
        
    # QueryResults
    message["QueryResults"] = m_QueryResults

    print(message)


def load_rules():
    # lade alle rules

    global rule_array
    global rule_index_array



    #open rule_file
    # assign directory
    application_path = os.path.dirname(__file__)
    directory = application_path + '/rules/'

    #print(directory)
    
    # iterate over files in
    # that directory
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # checking if it is a file
        if os.path.isfile(f):
            #print(f)

            if ".rule" in f:
                #parse file by line
                # Using readlines()
                file = open(f, 'r')
                Lines = file.readlines()
                
                
                # Strips the newline character
                for line in Lines:
                    try:
                        if debug_mode:
                            print("LINE BY LINE:" + line.strip())
                        
                        #rule_line = line.strip()
                        #rule_line = line.replace(',', '')
                        rule_line = line

                        if debug_mode:
                            print("LINE: " + rule_line)

                        if "RULEID :" in rule_line:
                            rule_id = rule_line.split(':')[1]
                            rule_id = rule_id.replace(' ', '').replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "Name :" in rule_line:
                            rule_name = rule_line.split(':')[1]
                            rule_name = rule_name.replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "Description :" in rule_line:
                            rule_description = rule_line.split(':')[1]
                            rule_description = rule_description.replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "MITREID :" in rule_line:
                            rule_mitreid = rule_line.split(':')[1]
                            rule_mitreid = rule_mitreid.replace(' ', '').replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "EventID :" in rule_line:
                            rule_eventid = rule_line.split(':')[1]
                            rule_eventid = rule_eventid.replace(' ', '').replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "String_1 :" in rule_line:
                            rule_string_1 = rule_line.split(':')[1]
                            rule_string_1 = rule_string_1.replace(' ', '').replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "String_2 :" in rule_line:
                            rule_string_2 = rule_line.split(':')[1]
                            rule_string_2 = rule_string_2.replace(' ', '').replace('"', '').replace('\n','').replace('\t','').replace(':','')

                        if "String_3 :" in rule_line:
                            rule_string_3 = rule_line.split(':')[1]
                            rule_string_3 = rule_string_3.replace(' ', '').replace('"', '').replace('\n','').replace('\t','').replace(':','')

                    except:
                        print("Rule parsing error! " + str(file))


                if debug_mode:
                    print("")
                    print("RULE SUMMARY:")
                    print("RULEID:" + rule_id)
                    print("DESC:" + rule_description)
                    print("MITREID:" + rule_mitreid)
                    print("EventID:" + rule_eventid)
                    print("String_1:" + rule_string_1)
                    print("String_2:" + rule_string_2)
                    print("String_3:" + rule_string_3)
                    print("")

                    #try:    
                rule_array.append(rule_id + "," + rule_name + "," + rule_description + "," + rule_mitreid + "," + rule_eventid + "," + rule_string_1 + "," + rule_string_2 + "," + rule_string_3)
                rule_index_array.append(rule_eventid)
                    #except:
                    #    print("Rule parsing error (code2)! " + str(file))


                if debug_mode:
                    print(rule_array)
                    print(rule_index_array)
    print(" [+] loading rules " + str(len(rule_array)) + " completed")

                



def get_EventID_rules(event_id):
    # welches rules passen zu der eventid
    # create list of rules to use for the message

    global rule_index_array

    matching_rules = []

    count = 0
    for rule_index in rule_index_array:
        if int(rule_index) ==  int(event_id):
            #print("found")
            matching_rules.append(count)
        count = count + 1

    #print(matching_rules)

    return matching_rules



def rule_Parsing(rule, message_dict):

    rule_match1 = False
    rule_match2 = False
    rule_match3 = False
    rule_match = False
    # event_id matcht? -true

    global rule_array

    if debug_mode:
        print("RULE:" + rule_array[rule])


    rule_array_elements = rule_array[rule].split(',')


    r_id = rule_array_elements[0]
    r_name = rule_array_elements[1]
    r_desc = rule_array_elements[2]
    r_mitreid = rule_array_elements[3]
    r_eventid = rule_array_elements[4]
    r_str1 = rule_array_elements[5].strip('"')
    r_str1_param = rule_array_elements[6].strip('"')
    r_str2 = rule_array_elements[7].strip('"')
    r_str2_param = rule_array_elements[8].strip('"')
    r_str3 = rule_array_elements[9].strip('"')
    r_str3_param = rule_array_elements[10].strip('"')



    if debug_mode:
        print("")
        print("MATCH1: " + str(r_str1))
        print("MATCH1: " + str(r_str1) + " in " + message_dict[str(r_str1_param)])
        print("MATCH2: " + str(r_str2) + " in " + message_dict[str(r_str2_param)])
        print("MATCH3: " + str(r_str3) + " in " + message_dict[str(r_str3_param)])
        print("")
    
    try:
        if r_str1 in message_dict[str(r_str1_param)]:
            rule_match1 = True
            if debug_mode:
                print("MATCH1: " + str(rule_match1))
        else:
            rule_match1 = False
    except:
        rule_match1 = False
        pass
        #print("rule parsing (match) error - 1")

    try:
        if r_str2 in message_dict[str(r_str2_param)]:
            rule_match2 = True
            if debug_mode:
                print("MATCH2: " + str(rule_match2))
        else:
            rule_match2 = False
    except:
        rule_match2 = False
        pass
        #print("rule parsing (match) error - 2")

    try:
        if r_str3 in message_dict[str(r_str2_param)]:
            rule_match3 = True
            if debug_mode:
                print("MATCH3: " + str(rule_match3))
        else:
            rule_match3 = False
    except:
        rule_match3 = False
        pass
        #print("rule parsing (match) error - 3")

    #print(r_str1 + " " + r_str2 + " " + r_str3)

    if (rule_match1 == True) and (rule_match2 == True)  and (rule_match3 == True):
        rule_match = True
        return r_name
    else:
        rule_match = False

    #print("RULEMATCH: " + str(rule_match))

    return 0



def find_string(string,sub_string):
    #string match
	return string.find(sub_string)



