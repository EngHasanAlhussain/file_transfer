# file_transfer
File transfer application in python with encryption and authentication

A client-server file transfer application can be used to exchange files between a client and a server. This program should run on two virtual machines, on real and virtual machine, or on two different machines. Running the code on Pycharm IDE is preferable.
Here are the steps to run the application:
1.	Hardcode the IP-address of the server in line 116 of the client code (c.py).
Note: this is the only edit you need to run the code.
2.	Make sure to ping the server using command prompt to ensure the connectivity.
3.	Now, on the server machine, execute the file s.py that contains the server python code.
4.	Then, on the client machine, execute the file c.py that contains the client python code.
5.	Now, to get a file from the server, choose choice 1 in the client side from the menu.
6.	Then, the user will be asked to type the name of the file, enter the name with its extension i.e., KFUPM_LOGO.png. Make sure the file exists in server’s location.
7.	Same procedure applies to PUT choice where the client types the file name to be sent with its extension. Also, make sure that the file exists in the client location.
8.	After successful GET or PUT, the program will show the menu again.
9.	If the user chooses QUIET (3), then the connection is closed, and the program is terminated. 
