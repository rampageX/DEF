DNS-ECS-Forcer
========

Add user defined ECS to dns request.

Install
-------

* Linux / Unix

    [Download a release].

        ./configure && make
        src/dns-ecs-forcer -p 1053 -s 8.8.8.8 -e 202.96.134.33 -v

* Tomoto

    * Download [Tomato toolchain], build by yourself.
    * Uncompress the downloaded file to `~/`.
    * Copy the `brcm` directory under
      `~/WRT54GL-US_v4.30.11_11/tools/` to `/opt`, then

            export PATH=/opt/brcm/hndtools-mipsel-uclibc/bin/:/opt/brcm/hndtools-mipsel-linux/bin/:$PATH
            git clone https://github.com/rampageX/dns-ecs-forcer.git
            cd dns-ecs-forcer
            ./autogen.sh && ./configure --host=mipsel-linux --enable-static && make


Usage
-----

* Linux / Unix
    Run `sudo dns-ecs-forcer -p 1053 -s 8.8.8.8 -e 202.96.134.33 -v` on your local machine. DNS-ECS-Forcer creates a UDP DNS Server at `0.0.0.0:1053`. Note: The upsteam dns server must support ECS.

Test if it works correctly:

    $ dig @192.168.1.1 www.youtube.com -p 1053
	; <<>> DiG 9.12.4 <<>> @192.168.1.1 -p 1053 www.youtube.com
	;; global options: +cmd
	;; Got answer:
	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49828
	;; flags: qr rd ra; QUERY: 1, ANSWER: 17, AUTHORITY: 0, ADDITIONAL: 1

	;; OPT PSEUDOSECTION:
	; EDNS: version: 0, flags:; udp: 512
	; CLIENT-SUBNET: 202.96.134.33/32/24
	;; QUESTION SECTION:
	;www.youtube.com.		IN	A

	;; ANSWER SECTION:
	www.youtube.com.	21599	IN	CNAME	youtube-ui.l.google.com.
	youtube-ui.l.google.com. 299	IN	A	172.217.25.110
	youtube-ui.l.google.com. 299	IN	A	172.217.24.142
	youtube-ui.l.google.com. 299	IN	A	172.217.26.14
	youtube-ui.l.google.com. 299	IN	A	172.217.25.206
	youtube-ui.l.google.com. 299	IN	A	172.217.27.78
	youtube-ui.l.google.com. 299	IN	A	172.217.31.142
	youtube-ui.l.google.com. 299	IN	A	172.217.26.46
	youtube-ui.l.google.com. 299	IN	A	172.217.161.78
	youtube-ui.l.google.com. 299	IN	A	172.217.31.174
	youtube-ui.l.google.com. 299	IN	A	172.217.161.46
	youtube-ui.l.google.com. 299	IN	A	172.217.175.46
	youtube-ui.l.google.com. 299	IN	A	172.217.174.110
	youtube-ui.l.google.com. 299	IN	A	172.217.175.110
	youtube-ui.l.google.com. 299	IN	A	172.217.175.78
	youtube-ui.l.google.com. 299	IN	A	172.217.175.14
	youtube-ui.l.google.com. 299	IN	A	216.58.197.206

	;; Query time: 828 msec
	;; SERVER: 127.0.0.1#5153(127.0.0.1)
	;; WHEN: Tue Mar 24 19:12:38 CST 2020
	;; MSG SIZE  rcvd: 346

Note the `CLIENT-SUBNET: 202.96.134.33/32/24` section. Currently DNS-ECS-Forcer only supports UDP.

Advanced
--------

```
usage: dns-ecs-forcer [-e CLIENT_SUBNET] [-b BIND_ADDR] [-p BIND_PORT] [-s DNS] [-e ECS] [-h] [-v] [-V]
Forward DNS requests.

  -b BIND_ADDR          address that listens, default: 0.0.0.0
  -p BIND_PORT          port that listens, default: 53
  -s DNS                DNS server to use, default: 8.8.8.8
  -e ADDRs              set edns-client-subnet
  -v                    verbose logging
  -h                    show this help message and exit
  -V                    print version and exit

Online help: <https://github.com/rampageX/dns-ecs-forcer>
```

License
-------

Copyright (C) 2015 clowwindy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Bugs and Issues
----------------
Please visit [Issue Tracker]

Mailing list: http://groups.google.com/group/shadowsocks

