#!/usr/bin/python 

from modules.mysocket import mysocket
from modules.message import message
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int)
parser.add_argument("-a", "--addr", type=str)
args = parser.parse_args()

s = mysocket()

host = mysocket.gethostname() 
port = 12345
s.bind((host, args.port))

s.connect((host, port))
print s.recv(32, ',')

string = 'Shh!! This is a secret message!'
num = message.strToNum(string)

print num
print string
s.send(str(num),',')

s.close() 
