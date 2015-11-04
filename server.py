#!/usr/bin/python 

from modules.message import message
from modules.mysocket import mysocket

s = mysocket()

host = mysocket.gethostname()
port = 12345 
s.bind((host, port)) 

s.listen(5) 

while True:
   c, addr = s.accept()
   
   print 'Got connection from', addr
   c.send('Thank you for connecting', ',')
   
   num = int(c.recv(32, ','))
   print num

   string = message.numToStr(num)
   print string

   c.close() 
