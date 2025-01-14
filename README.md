The Network IP Scanner Application is a graphical user interface (GUI) tool that allows users to scan a specified IP address and port for open/closed status. This project played a role as my final project for my Uni's Computer Network subject's project. 

### Programming Language:
  - Python: The entire application is developed using Python.

### Libraries and Modules:
  - Tkinter: Used for creating the GUI interface of the application.
  - Nmap: A Python wrapper for the popular Nmap tool, which is used for network scanning and checking the status of ports on a given IP.
  - JSON: A built-in Python module used to store and manipulate the data in JSON format.
  - Time: Used for measuring the time taken for the scanning process.

### Protocols Used:
  - TCP/IP: The Nmap tool operates over the TCP/IP protocol, and the app checks the status of ports over this protocol. The application specifically uses the TCP protocol for port checking, focusing on the specified port for each scan.
