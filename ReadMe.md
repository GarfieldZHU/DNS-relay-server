# DNS-relay-server
This is a project of design of computer network.
We design a DNS server program to deal DNS request from client. When client send an domain name to DNS delay server, it will
make an enquiry on local database. If it hits, the server resend the IP address back to the client where the request comes from.
Else, it send the request to server who has a higher level, and wait to result. What's more, if the ip is not allowed or 
unexisted,server is expected to send "0.0.0.0" back.
The server need to support multithreading, which means more than two requests' arriving leads server to deal with them at the 
same time.
