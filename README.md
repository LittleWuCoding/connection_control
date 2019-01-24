# connection_control
a postgres plugin to control the connection behavior  and some Statistics of connection information
Aim to control the connection between front and backend, but now has many improvement to do.
At present we can determine refuse the connection for login failed for special times and refuse the
connection from this username for how long time.
We have two parameters:
connection_control.minutes  //minutes to refuse users login

connection_control.threshold //failed times before refuse users login

It is easy to understand the two parameter without explanation.

The installation of the  plugin is just like common postgres contribs. Which are :
1. Download 
2. set the postgres bin in your PATH
3. cd connection_control/ dir, run 
```
make && make install
```
4. modified your postgresql.conf and restart your DB
5.psql into the server and run 
```
create extension connection_control;
```
After that, your DB server will work with connection_control.
Welcome to report bug and confusing, if you have good idea ,you can contact with me.
