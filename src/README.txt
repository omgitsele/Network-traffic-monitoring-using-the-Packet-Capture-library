Dimitrios ELeftheriadis 2015030067

gcc --version: gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0s

To compile the code simply run: make all

To run the code: ./assign_6 -r <NAME_OF_PCAP_FILE>

Folder contains: 
    assign_6.c
        - This file contains all the code for the assignment. The code contains comments and it pretty self
          explanatory.

    Makefile
        - This file is used for compiling the code and removing the generated file
         (To remove the files simply run: make clean)

9. "Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not,
    why?"
    - In order to find out whether a packet is a retransmission, 3 things must happen.
        a) It is not a keepalive packet
        b) The segment length is greater than 0 or the SYN or FIN flag is set.
        c) The next expected sequence number is greater than the current sequence number.

10. "Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not,
    why?"
    - UDP does not retransmit packets.
    
