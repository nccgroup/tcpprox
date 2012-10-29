TcpProx
=======

A small command-line TCP proxy utility written in Python

Tim Newsham <tim at isecpartners dot com>
29 Oct 2012



Overview
=======

This is a small command-line TCP proxy utility written in python.
It is designed to have very minimal requirements - it runs
directly from python (tested in python 2.7) from a single source
file (unless the auto-certificate option is used). When running, 
the proxy accepts incoming TCP connections and copies data to a TCP 
connection to another machine.  Options allow for SSL and IPv6 
connections and for the logging of all data.  Data is logged in 
a format that preserves connection, timing and direction 
information and a small utility is provided to dump out the 
information in various formats. A small utility is also provided 
for generating CA and SSL certificates. This utility is the only 
component that relies on an external python library, but it can 
be run on a different machine if necessary.


QUICKSTART
=======

- A normal TCP proxy is straightforward:
   - $ ./prox.py -L 8888 www.google.com 80
   - connect in another window using curl
     or connect to localhost port 80 using some other program
   - $ curl http://127.0.0.1:8888/

- For SSL, first create and install a CA cert
   - $ ./ca.py -c
   - $ ./pkcs12.sh ca      # if you need a pkcs12 certificate
   - take ca.pem or ca.pfx and install it as a root
     certificate in your testing browser

- Run the proxy using an auto-generated certificate:
   - modify /etc/hosts to redirect www.test.com to 127.0.0.1
   - $ ./prox.py -L 8888 -A www.test.com www.google.com 80
   - connect using curl or open the URL in your browser
   - $ curl --cacert ca.pem https://www.test.com:8888/


- Or manually generate a certificate (possibly on another machine)
  and then run the proxy using that certificate:
   - $ ./ca.py www.test.com
   - $ ./prox.py -L 8888 www.google.com 80
   - $ curl --cacert ca.pem https://www.test.com:8888/

- To view data logged to a file by prox.py, use proxcat:
   - $ ./proxcat.py -x log.txt


DEPENDENCIES
=======

TcpProx requires a python interpreter and the M2Crypto package
from http://www.heikkitoivonen.net/m2crypto/. The prox.py
program can be run with only the prox.py file and without the
M2Crypto package installed if the -A option is not used.


