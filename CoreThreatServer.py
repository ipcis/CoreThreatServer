import socket, re
import rules
from colorama import init
from termcolor import colored
import datetime
import argparse
import logging
import uuid


'''
Event ID 1: Process creation
Event ID 2: A process changed a file creation time
Event ID 3: Network connection
Event ID 4: Sysmon service state changed
Event ID 5: Process terminated
Event ID 6: Driver loaded
Event ID 7: Image loaded
Event ID 8: CreateRemoteThread
Event ID 9: RawAccessRead
Event ID 10: ProcessAccess
Event ID 11: FileCreate
Event ID 12: RegistryEvent (Object create and delete)
Event ID 13: RegistryEvent (Value Set)
Event ID 14: RegistryEvent (Key and Value Rename)
Event ID 15: FileCreateStreamHash
Event ID 16: ServiceConfigurationChange
Event ID 17: PipeEvent (Pipe Created)
Event ID 18: PipeEvent (Pipe Connected)
Event ID 19: WmiEvent (WmiEventFilter activity detected)
Event ID 20: WmiEvent (WmiEventConsumer activity detected)
Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
Event ID 22: DNSEvent (DNS query)
Event ID 23: FileDelete (File Delete archived)
Event ID 24: ClipboardChange (New content in the clipboard)
Event ID 25: ProcessTampering (Process image change)
Event ID 255: Error


https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
'''

# use Colorama to make Termcolor work on Windows too
#print(colored('Hello, World!', 'green', 'on_red'))
init()


print("")
print("#######################")
print("# [Core" + colored("Threat", 'red') + "] Server #")
print("#######################")
print("")



debug_mode = False
monitor_mode = False
sysmonevents_mode = True
localIP     = "192.168.1.35"
localPort   = 5514
bufferSize  = 65500
universal_message_filter = ""

# init logging
logging.basicConfig( level=logging.DEBUG, filemode='w', filename='corethreat_server.log', format='%(name)s - %(levelname)s - %(message)s')


def writeLog(message, level):
    if level == "info":
        logging.info(getDateTime() + " " + str(message))

    if level == "error":
        logging.error(getDateTime() + " " + str(message))

    if level == "critical":
        logging.critical(getDateTime() + " " + str(message))


def getDateTime():  
    ct = datetime.datetime.now()
    return str(ct)

def printMessage(message):
    #color - fix me

    filter = universal_message_filter

    if filter == "":
        print("")
        print(" [+] " + getDateTime() + " " + str(message))
    else:
        #universal_message_filter
        if re.match(filter, message.lower()):
            print("")
            print(" [+] " + getDateTime() + " " + str(message))


def runListener():
    msgFromServer       = "Hello client"
    bytesToSend         = str.encode(msgFromServer)

    # Create a datagram socket
    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # Bind to address and ip
    UDPServerSocket.bind((localIP, int(localPort)))
    printMessage("CoreThreat Server up and listening on: " + localIP + " : " + str(localPort))
    writeLog("CoreThreat Server up and listening on: " + localIP + " : " + str(localPort), "info")

    return UDPServerSocket



def mainLoader():
    #run listener
    udp_socket = runListener()

    # Setup rules parsing
    rules.load_rules()


    # Listen for incoming datagrams
    while(True):
        bytesAddressPair = udp_socket.recvfrom(bufferSize)
        message = bytesAddressPair[0]
        address = bytesAddressPair[1]
        clientMsg = "Message from Client:{}".format(message)
        clientIP  = "Client IP Address:{}".format(address)

        if universal_message_filter == "":
            if debug_mode:
                print(clientMsg)
                print(clientIP)
        else:
            if debug_mode:
                printMessage(clientMsg)
                printMessage(clientIP)

        if monitor_mode:
            print(clientMsg)
            print(clientIP)
        
        # MESSAGE ID
        message_id = uuid.uuid4()

        # CREATE MESSAGE DICT
        message = dict()
        message["message_id"] = message_id
        message["all"] = clientMsg.lower()

        # PRE-CLEANUP FILTER
        regexes = [
            ".*filecoauth.exe.*",
            ".*corethreatagent.exe.*",
            ".*searchapp.exe.*",
            ".*experiencehost.*",
            ".*applicationframehost.*",
            ]

        # Make a regex that matches if any of our regexes match.
        combined = "(" + ")|(".join(regexes) + ")"

        if re.match(combined, clientMsg.lower()):
            # excluded message
            #if debug_mode:
            #    print(" [-] Exclude matched!")
            pass
        else:
            # important messages
            if "microsoft-windows-sysmon" in clientMsg.lower():
                # EventID
                pattern = r'"EventID":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_EventID = m.group(1)
                    message["EventID"] = m_EventID.lower()
                else:
                    m_EventID = ""

                # ComputerName
                pattern = r'"Computer":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_ComputerName = m.group(1)
                    message["ComputerName"] = m_ComputerName.lower()
                else:
                    m_ComputerName = ""
                
                # Image
                pattern = r'"Image", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_Image = m.group(1)
                    message["Image"] = m_Image.lower()
                else:
                    m_Image = ""
                    
                # TargetImage
                pattern = r'"TargetImage", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_TargetImage = m.group(1)
                    message["TargetImage"] = m_TargetImage.lower()
                else:
                    m_TargetImage = ""
                    
                # ParentImage
                pattern = r'"ParentImage", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_ParentImage = m.group(1)
                    message["ParentImage"] = m_ParentImage.lower()
                else:
                    m_ParentImage = ""
                    
                # SourceImage
                pattern = r'"SourceImage", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_SourceImage = m.group(1)
                    message["SourceImage"] = m_SourceImage.lower()
                else:
                    m_SourceImage = ""

                    
                # ImageLoaded
                pattern = r'"ImageLoaded", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_ImageLoaded = m.group(1)
                    message["ImageLoaded"] = m_ImageLoaded.lower()
                else:
                    m_ImageLoaded = ""
                    
                # ParentCommandLine
                pattern = r'"ParentCommandLine", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_ParentCommandLine = m.group(1)
                    message["ParentCommandLine"] = m_ParentCommandLine.lower()
                else:
                    m_ParentCommandLine = ""
                
                # TargetFilename
                pattern = r'"TargetFilename", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_TargetFilename = m.group(1)
                    message["TargetFilename"] = m_TargetFilename.lower()
                else:
                    m_TargetFilename = ""
                
                # User
                pattern = r'"User", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_User = m.group(1)
                    message["User"] = m_User.lower()
                else:
                    m_User = ""
                
                # RuleName
                pattern = r'"RuleName", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_RuleName = m.group(1)
                    message["RuleName"] = m_RuleName.lower()
                else:
                    m_RuleName = ""
                
                # MD5
                pattern = r',MD5=(.*?),'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_MD5 = m.group(1)
                    message["MD5"] = m_MD5.lower()
                else:
                    m_MD5 = ""
                
                # Signed
                pattern = r'"Signed", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_Signed = m.group(1)
                    message["Signed"] = m_Signed.lower()
                else:
                    m_Signed = ""
                
                # Signature
                pattern = r'"Signature", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_Signature = m.group(1)
                    message["Signature"] = m_Signature.lower()
                else:
                    m_Signature = ""
                    
                # SignatureStatus
                pattern = r'"SignatureStatus", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_SignatureStatus = m.group(1)
                    message["SignatureStatus"] = m_SignatureStatus.lower()
                else:
                    m_SignatureStatus = ""
                    
                # OriginalFileName
                pattern = r'"OriginalFileName", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_OriginalFileName = m.group(1)
                    message["OriginalFileName"] = m_OriginalFileName.lower()
                else:
                    m_OriginalFileName = ""
                    
                # TargetUser
                pattern = r'"TargetUser", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_TargetUser = m.group(1)
                    message["TargetUser"] = m_TargetUser.lower()
                else:
                    m_TargetUser = ""
                    
                # SourceIP
                pattern = r'"SourceIp", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_SourceIP = m.group(1)
                    message["SourceIP"] = m_SourceIP.lower()
                else:
                    m_SourceIP = ""
                    
                # DestinationIP
                pattern = r'"DestinationIp", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_DestinationIP = m.group(1)
                    message["DestinationIP"] = m_DestinationIP.lower()
                else:
                    m_DestinationIP = ""
                    
                # SourcePort
                pattern = r'"SourcePort", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_SourcePort = m.group(1)
                    message["SourcePort"] = m_SourcePort.lower()
                else:
                    m_SourcePort = ""
                    
                # DestinationPort
                pattern = r'"DestinationPort", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_DestinationPort = m.group(1)
                    message["DestinationPort"] = m_DestinationPort.lower()
                else:
                    m_DestinationPort = ""
                    
                # DestinationHostname
                pattern = r'"DestinationHostname", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_DestinationHostname = m.group(1)
                    message["DestinationHostname"] = m_DestinationHostname.lower()
                else:
                    m_DestinationHostname = ""
                    
                # CommandLine
                pattern = r'"CommandLine", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_CommandLine = m.group(1)
                    message["CommandLine"] = m_CommandLine.lower()
                else:
                    m_CommandLine = ""
                    
                # QueryName
                pattern = r'"QueryName", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_QueryName = m.group(1)
                    message["QueryName"] = m_QueryName.lower()
                else:
                    m_QueryName = ""
                    
                # QueryResults
                pattern = r'"QueryResults", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_QueryResults = m.group(1)
                    message["QueryResults"] = m_QueryResults.lower()
                else:
                    m_QueryResults = ""

                # TargetObject
                pattern = r'"TargetObject", "#text":."(.*?)"'
                m = re.search(pattern, clientMsg)
                if m:
                    #print(m.group(1))
                    m_TargetObject = m.group(1)
                    message["TargetObject"] = m_TargetObject.lower()
                else:
                    m_TargetObject = ""

                writeLog(str(message), "info")

                #print(m_EventID)
                matching_rules_array = rules.get_EventID_rules(int(m_EventID))
                #print(matching_rules_array)

                if sysmonevents_mode:
                    if int(m_EventID) == 1:
                        printMessage(" [+] Event ID 1: Process creation : " + str(m_ComputerName) + " " + m_Image + " " + m_MD5)
                        #print(" [+] Event ID 1: Process creation : " + str(m_ComputerName) + " " + m_Image + " " + m_MD5)

                    if int(m_EventID) == 3:
                        printMessage(" [+] Event ID 3: Network connection : " + str(m_ComputerName) + " " + m_Image + " " + m_SourceIP + " -> " + m_DestinationIP)
                        #print(" [+] Event ID 3: Network connection : " + str(m_ComputerName) + " " + m_Image + " " + m_SourceIP + " -> " + m_DestinationIP)

                    if int(m_EventID) == 8:
                        printMessage(" [+] Event ID 8: CreateRemoteThread : " + str(m_ComputerName) + " " + m_SourceImage + " -> " + m_TargetImage)
                        #print(" [+] Event ID 8: CreateRemoteThread : " + str(m_ComputerName) + " " + m_SourceImage + " -> " + m_TargetImage)

                    if int(m_EventID) == 10:
                        printMessage(" [+] Event ID 10: ProcessAccess : " + str(m_ComputerName) + " " + m_SourceImage + " -> " + m_TargetImage)
                        #print(" [+] Event ID 10: ProcessAccess : " + str(m_ComputerName) + " " + m_SourceImage + " -> " + m_TargetImage)

                    if int(m_EventID) == 22:
                        printMessage(" [+] Event ID 22: DNSEvent (DNS query) : " + str(m_ComputerName) + " " + m_QueryName + " -> " + m_QueryResults)
                        #print(" [+] Event ID 22: DNSEvent (DNS query) : " + str(m_ComputerName) + " " + m_QueryName + " -> " + m_QueryResults)

                    if int(m_EventID) == 12:
                        printMessage(" [+] Event ID 12: RegistryEvent (Object create and delete) : " + str(m_ComputerName) + " " + m_TargetObject)
                        #noisy
                        #print(" [+] Event ID 12: RegistryEvent (Object create and delete) : " + str(m_ComputerName) + " " + m_TargetObject)
                        #print(colored(str(clientMsg), 'cyan'))
                        pass

                    if int(m_EventID) == 17:
                        printMessage(" [+] Event ID 17: PipeEvent (Pipe Created) : " + str(m_ComputerName))
                        #print(" [+] Event ID 17: PipeEvent (Pipe Created) : " + str(m_ComputerName))
                        print(colored(str(clientMsg), 'cyan'))

                    if int(m_EventID) == 4:
                        printMessage(" [+] Event ID 4: Sysmon service state changed : " + str(m_ComputerName))
                        #print(" [+] Event ID 4: Sysmon service state changed : " + str(m_ComputerName))
                        print(colored(str(clientMsg), 'cyan'))

                    if int(m_EventID) == 5:
                        printMessage(" [+] Event ID 5: Process terminated : " + str(m_ComputerName) + " " + m_Image)
                        #print(" [+] Event ID 5: Process terminated : " + str(m_ComputerName) + " " + m_Image)

                    if int(m_EventID) == 11:
                        printMessage(" [+] Event ID 11: FileCreate : " + str(m_ComputerName) + " " + m_TargetFilename)
                        #noisy
                        #print(" [+] Event ID 11: FileCreate : " + str(m_ComputerName) + " " + m_TargetFilename)
                        #print(colored(str(clientMsg), 'cyan'))
                        pass

                    if int(m_EventID) == 6:
                        printMessage(" [+] Event ID 6: Driver loaded : " + str(m_ComputerName) )
                        #print(" [+] Event ID 6: Driver loaded : " + str(m_ComputerName) )
                        print(colored(str(clientMsg), 'cyan'))

                    if int(m_EventID) == 7:
                        printMessage(" [+] Event ID 7: Image loaded : " + str(m_ComputerName) + " " + m_Image)
                        #noisy
                        #print(" [+] Event ID 7: Image loaded : " + str(m_ComputerName) + " " + m_Image)
                        #print(colored(str(clientMsg), 'cyan'))
                        pass


                for matching_rule in matching_rules_array:
                    #print(rule_array[matching_rule])
                    result_rule_match = rules.rule_Parsing(int(matching_rule), message)
                    if result_rule_match == 0:
                        pass
                    else:
                        print("")
                        threat_found_message = str(m_ComputerName) + " Rule-Name: " + result_rule_match + " Message-ID: " + str(message["message_id"])
                        print(colored(" [!] Threat detected", 'red') + " " + threat_found_message)
                        print("")
                        writeLog("[!] Threat detected : " + threat_found_message, "critical")
            else:
                print(" [+] Non Sysmon message")
                print(colored(str(clientMsg), 'cyan'))

                

        message.clear()
        




def help():
    print("CoreThreat Server")
    print("Usage: CoreThreatServer <action>")
    print("")
    print("Possible actions:")
    print("  run <ip:port> - Run Server default")
    print("  debug - Run Server in debug mode")
    print("  debug <regex> - Run Server in debug mode with filter - example: debug .*lsass.* or .*event.id.3.* or .*event.id.1.*")

def main():
    parser = argparse.ArgumentParser(description='CoreThreat Server')
    parser.add_argument('action', nargs='*', help="")
    args = parser.parse_args()
    actions_list = args.action

    #global vars
    global debug_mode
    global universal_message_filter
    global localIP
    global localPort
    
    #Default action install
    if len(actions_list) == 0:
        help()
    else:
        action = actions_list[0]
        if action == "run" or action == "start":
            if len(actions_list) > 1:
                #print(actions_list)
                action_param = actions_list[1]
                localIP     = action_param.split(':')[0]
                localPort   = action_param.split(':')[1]
                mainLoader()
            else:
                print("Please add ip:port")
        elif action == "debug":
            if len(actions_list) > 1:
                #print(actions_list)
                action_param = actions_list[1]
                print(" [+] active filter: " + str(action_param))
                universal_message_filter = action_param
                debug_mode = True
                mainLoader()
            else:
                debug_mode = True
                mainLoader()
        #elif action == "sysmon":
        #    action_sysmon()
        else:
            parser.error("Unknown action: {}".format(action))



if __name__ == "__main__":
   main()
