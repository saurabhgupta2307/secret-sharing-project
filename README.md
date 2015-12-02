# secret-sharing-project
Verifiable Secret Sharing Project

Team: Saurabh Gupta, Omkar Kaptan

CSE 539 Applied Cryptography - Fall 2015

Arizona State University

Usage:
~~~~~~
Execute the following format command in a linux/unix shell.
./demo.py -n <nodes> -k <shares> [-t <faulty>] [-v] [-d]
	-n <nodes> is an integer value representing the number 
		of intermediate nodes and number of shares to be 
		generated.
	-k <shares> is an integer value representing the number 
		of shares requried for reconstruction in the 
		(n, k) secret sharing scheme.
	-t <faulty> is an integer value representing the 
		maximum number of faulty nodes allowed. Default 
		Value is 0.
	-v is for verbose mode. If used, the intermediate node 
		shell windows remain open after the execution is 
		complete. Otherwise, they terminate.
	-d is for debug mode. If used, the error and exception
		messages are displayed as debug information. 
		Otherwise, a secure fail is executed.
