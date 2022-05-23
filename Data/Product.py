#Network Scanner For Detecting DoS attacks and IP blocker

#Imports of required packages
import pyshark
import sys

#Defines List with blacklisted IP addresses
filename = 'BlackListIPAddresses.txt'

#Introduction to the program 
print("Welcome to the Network Scanner and IP Blocker tool!")
try:
    # Asks the user if they are conducting a live capture or reading from a file
    A = input("Would you like to capture live traffic or analyse the activity from a file? (Live/File)")
       
    #if statement - live or file capture following respected routes
    if A == "Live":
        #Asks the user which network interface they are using 
        selectInterface = input("What Network Interface do you wish to use? (wlan0 or eth0)")
        #Defines how many packets will be captured in the live scan    
        packetCounter = input("How many packets would you like to scan for?")
        #Live capture
        packetCapture = pyshark.LiveCapture(interface=selectInterface, output_file="DoSCapture.pcap")
        # Lets the User know the scan is starting
        print("Scanning the", selectInterface, "interface for Network Traffic")
    elif A == "File":
        fileName = input("Please enter the name of the file you would like to use: (.pcap)")
        #File Capture    
        filePacketCapture = pyshark.FileCapture(fileName)
        for packets in filePacketCapture:
            print(packets)
            
#Flags error if there is no file in the directory matching the inputted name            
except FileNotFoundError as e:
    print("Your file:", fileName, "could not be found! Please try again")

#Defines live capture to continuously capture packets until it reaches the packet counter limit
for packets in packetCapture.sniff_continuously(packet_count=packetCounter):
    #Defines which modules of the packet to capture
    try:
        packetTimeDate = packets.sniff_time
        sourceIP = packets.ip.src
        destIP = packets.ip.dst
        packetLength = packets.length
        packetProtocol = packets.transport_layer

        print("Time:",packetTimeDate, "IP Source:", sourceIP, "IP Destination:",
              destIP, "Protocol:", packetProtocol, "Packet Length:", packetLength)

    # Prints error message if there is a program error and stops the capture.
    except (RuntimeError, AttributeError) as e:
        print("An issue has been detected whilst capturing packets on the",
              selectInterface, "interface.\nPlease try again.")
        sys.exit()
        pass
#Start of the IP blacklist section of the program
B = input("Would you like to see if the IP address has been previously blacklisted? (Yes/No) ")

if B == "Yes":
    #Opens and reads file containing list of IP addresses
    with open(filename) as IP_File:
        IPBlacklist = IP_File.read()
        #User Input for IP address
        IPAddress = input("Please enter the IP address you wish to check:")
    if IPAddress in IPBlacklist.split():
        print("Your IP with the address:", IPAddress,"has been flagged as being on a Blacklist!")
    else:
        print("Your IP with the address:", IPAddress,"has not been found on a Blacklist!")
        C = input("Would you like to add it to the list? (Yes/No)")
        #Adds inputted IP address to list
        if C == "Yes":
            D = open("Product\Data\BlackListIPAddresses.txt", 'w')
            D.write(IPAddress)
            D.close()
        else:
            print("Thank you for using the program!")    

#Quits program if User selects no
elif B == "No":
    print("Thank you for using the program!")
    quit()
