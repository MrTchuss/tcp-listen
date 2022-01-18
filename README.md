Tool that allows to determine which port are avalaible and not filtered on a
remote system.

For instance, we have access to a remote system through a webshell and need
to bind to a port, but the remote system is behind a firewall.
Deploy this tool, launch it with `./tcp-listen 4000-5000` and, from our
laptop, scan it (`nmap -p 4000-5000`).

NOTE: This allocate a lot of file descriptor (cannot implement it with
libpcap as we're not sure to have enough privileges), so forks when out of
file descriptor.

compile:

```
clang -Wall -Wextra -o tcp-listen tcp-listen.c
```

TODO: remote connection testing
TODO: command-line help

