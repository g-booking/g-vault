#!/bin/bash
##### gVault simple install script ######
####     works for RedHat / Debian / Ubuntu at least for latest tested versions   ########
###                it is not tricky dicky so you can adapt if you need....        ####


# We need to compile basic stuff so make sure you have a compilier and can make stuff... 
# for REDHAT / CENTOS, something like this:       (otherwise please adjust for your system).
# We need PERL so make sure you have that as well.   (or add perl using your system params)

# We **NEED** the systemd development library...!  
#     ... most likely you will need to find this and install it for your OS.
# This will work on most RedHat stylee systems however others will vary....

# YOU WILL NEED TO RESEARCH THIS IF needed 
#               see https://reposcope.com/package/systemd-devel

echo "Please wait.... installing....."
echo "              __      __            _  _"
echo "              \ \    / /           | || |"
echo "   __ _  ______\ \  / /__ _  _   _ | || |_"

# REDHAT
   yum -y install curl make gcc perl systemd-devel     >>~/g_vault_install.log      2>>~/g_vault_install.err

# DEBIAN and UBUNTU
   apt-get install -y build-essential libnet-ssleay-perl libsystemd-dev curl libextutils-pkgconfig-perl perl     >>~/g_vault_install.log 2>>~/g_vault_install.err
# OTHER Operating System... sorry man (binary girl), you need to fix yourself.

echo '  / _` ||______|\ \/ // _` || | | || || __|'

# ADD g_vault user
# Setting password for g_vault user, should work on most systems this but double check!
   useradd -s /usr/sbin/nologin g_vault        >>~/g_vault_install.log 2>>~/g_vault_install.err
   rand_pass=`cat /proc/sys/kernel/random/uuid`;
   make_echo="g_vault::$rand_pass";
   echo $make_echo | /usr/sbin/chpasswd        >>~/g_vault_install.log 2>>~/g_vault_install.err
echo ' | (_| |  _____  \  /| (_| || |_| || || |_'

# We need to install some PERL modules, this is an all in one installer called CPM and it is brilliant.
#    See https://metacpan.org/pod/App::cpm::Tutorial
   /usr/bin/curl -fsSL https://git.io/cpm >~/g_cpm.exe
   /usr/bin/chmod +x ~/g_cpm.exe

echo "  \__, | / ____|  \/  \__,_| \__,_||_| \__|"

# Let's install what we need
# You don't need the SSL 

# ==>  Here are the core modules we use:
#    ==> (all known and respectable) <==
#         IO::Socket::Timeout............................................................................................................   
#         IO::Handle::Record..........................................................................................                 ||
#         Syntax::Keyword::Try....................................................................                  ||                 ||
#         Linux::Systemd......................................................                  ||                  ||                 ||
#         Crypt::Mode::CBC..................................                ||                  ||                  ||                 ||
#         Crypt::PRNG.......................              ||                ||                  ||                  ||                 ||
#         Crypt::Argon2.......            ||              ||                ||                  ||                  ||                 ||
#                           ||            ||              ||                ||                  ||                  ||                 ||
#                           ||            ||              ||                ||                  ||                  ||                 ||
# Let's install them:       \/            \/              \/                \/                  \/                  \/                 \/
echo "   __/ || (___    ___   ___  _   _  _ __  ___   _   _   ___   _   _  _ __"

  #~/g_cpm.exe install -g  Crypt::Argon2  Crypt::PRNG  Crypt::Mode::CBC  Linux::Systemd  Syntax::Keyword::Try  IO::Handle::Record  IO::Socket::Timeout  >>~/g_vault_install.log      >>~/g_vault_install.err
  ~/g_cpm.exe install -g  Crypt::Argon2        >>~/g_vault_install.log      2>>~/g_vault_install.err
echo "  |___/  \___ \  / _ \ / __|| | | || '__|/ _ \ | | | | / _ \ | | | || '__|"

  ~/g_cpm.exe install -g  Crypt::PRNG          >>~/g_vault_install.log      2>>~/g_vault_install.err
echo "         ____) ||  __/| (__ | |_| || |  |  __/ | |_| || (_) || |_| || |"

  ~/g_cpm.exe install -g  Crypt::Mode::CBC     >>~/g_vault_install.log      2>>~/g_vault_install.err
echo "        |_____/  \___| \___| \__,_||_|   \___|  \__, | \___/  \__,_||_|"

  ~/g_cpm.exe install -g  Linux::Systemd       >>~/g_vault_install.log      2>>~/g_vault_install.err
echo "                     _                           __/ |             _"

  ~/g_cpm.exe install -g  Syntax::Keyword::Try >>~/g_vault_install.log      2>>~/g_vault_install.err
echo "                    (_)                         |___/             | |"
  ~/g_cpm.exe install -g  IO::Handle::Record  IO::Socket::Timeout  >>~/g_vault_install.log      2>>~/g_vault_install.err

echo '   ___  _ __ __   __ _  _ __  ___   _ __   _ __ ___    ___  _ __  | |_'
# ==>  Here are the optional modules we use:
#  ==> These are used for the supporting packages in sys <==
#      ==> (all known and respectable) <==
#             Data::Dump
#             JSON::XS
#             IO::Socket::SSL
#             HTTP::Daemon::SSL
#             HTTP::Status
#             HTTP::Tiny
#             Term::ReadKey
   ~/g_cpm.exe install -g  Data::Dump JSON::XS    >>~/g_vault_install.log  2>>~/g_vault_install.err
echo 'ICAvIF8gXHwgJ18gXFwgXCAvIC98IHx8ICdfX3wvIF8gXCB8ICdfIFwgfCAnXyBgIF8gXCAgLyBfIFx8ICdfIFwgfCBfX3wK' | base64 -d
   ~/g_cpm.exe install -g  common::sense          >>~/g_vault_install.log  2>>~/g_vault_install.err
echo ' |  __/| | | |\ V / | || |  | (_) || | | || | | | | ||  __/| | | || |_'
   ~/g_cpm.exe install -g  IO::Socket::SSL        >>~/g_vault_install.log  2>>~/g_vault_install.err
   ~/g_cpm.exe install -g  HTTP::Daemon::SSL HTTP::Status       >>~/g_vault_install.log  2>>~/g_vault_install.err
   ~/g_cpm.exe install -g  HTTP::Tiny   Term::ReadKey      >>~/g_vault_install.log  2>>~/g_vault_install.err
echo '  \___||_| |_| \_/  |_||_|   \___/ |_| |_||_| |_| |_| \___||_| |_| \__|'


## We only install in a single place... it is possible to install elsewhere but only manually man!
   mkdir /usr/local/_gvault          >>~/g_vault_install.log 2>>~/g_vault_install.err
   mkdir /usr/local/_gvault/bin      >>~/g_vault_install.log 2>>~/g_vault_install.err
   mkdir /usr/local/_gvault/lib      >>~/g_vault_install.log 2>>~/g_vault_install.err
   mkdir /usr/local/_gvault/sock     >>~/g_vault_install.log 2>>~/g_vault_install.err
   mkdir /usr/local/_gvault/sys      >>~/g_vault_install.log 2>>~/g_vault_install.err
   mkdir /usr/local/_gvault/etc      >>~/g_vault_install.log 2>>~/g_vault_install.err
   mkdir /usr/local/_gvault/certs    >>~/g_vault_install.log 2>>~/g_vault_install.err
 
   echo '

If you utilise external SSL authentication then:

    ./fullchain.pem
    ./privkey.pem

files go here... direct from Certbot or another registrar.

' >/usr/local/_gvault/certs/read_me.txt
 
   mv -f ./bin/*     /usr/local/_gvault/bin        >>~/g_vault_install.log 2>>~/g_vault_install.err
   mv -f ./sys/*     /usr/local/_gvault/sys        >>~/g_vault_install.log 2>>~/g_vault_install.err
   mv -f ./lib/*     /usr/local/_gvault/lib        >>~/g_vault_install.log 2>>~/g_vault_install.err

   ln /usr/local/_gvault/bin/gencrypt      /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln /usr/local/_gvault/bin/gdecrypt      /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln /usr/local/_gvault/bin/ginfo         /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln /usr/local/_gvault/bin/gvault        /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln /usr/local/_gvault/bin/ghash         /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln /usr/local/_gvault/bin/g_vault_send  /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln -s /usr/bin/perl                     /usr/local/bin           >>~/g_vault_install.log 2>>~/g_vault_install.err
   ln -s /usr/local/bin/perl               /usr/local/_gvault/bin   >>~/g_vault_install.log 2>>~/g_vault_install.err

   chcon --reference=/usr/bin/perl         /usr/local/_gvault/sys/gvaultd  >>~/g_vault_install.log 2>>~/g_vault_install.err
   rm -f /usr/local/_gvault/sys/cat
   rm -f /usr/local/_gvault/sys/md5sum
   rm -f /usr/local/_gvault/sys/sha512sum
   cp -p /usr/bin/cat                      /usr/local/_gvault/sys
   cp -p /usr/bin/md5sum                   /usr/local/_gvault/sys
   cp -p /usr/bin/sha512sum                /usr/local/_gvault/sys

############################################
### try to install s service on your system... if fails, need to do it yourself...
#  ===>  /etc/systemd/system/gvault.service
#
#  [Unit]
#    Description = g-Booking\'s gVault.
#
#  [Service]
#    Type = notify
#    ExecStart = /usr/local/_gvault/sys/gvaultd
#    ExecReload = /bin/kill -HUP $MAINPID
#    WatchdogSec = 180
#    TimeoutSec  = 180
#
#  [Install]
#    WantedBy=multi-user.target

   echo 'W1VuaXRdCiAgRGVzY3JpcHRpb24gPSBnLUJvb2tpbmcncyBnVmF1bHQuCgpbU2VydmljZV0KICBUeXBlID0gbm90aWZ5CiAgRXhlY1N0YXJ0ICAgPSAvdXNyL2xvY2FsL19ndmF1bHQvc3lzL2d2YXVsdGQKICBFeGVjUmVsb2FkICA9IC9iaW4va2lsbCAtSFVQICRNQUlOUElECiAgV2F0Y2hkb2dTZWMgPSAxODAKICBUaW1lb3V0U2VjICA9IDE4MCAKCltJbnN0YWxsXQogIFdhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==' | base64 -d >/etc/systemd/system/gvault.service       2>>~/g_vault_install.err

############################################

   systemctl daemon-reload

# remove our installer and also remove temp files from that....
   rm -f  ~/g_cpm.exe        >>~/g_vault_install.log 2>>~/g_vault_install.err

   systemctl enable gvault       >>~/g_vault_install.log 2>>~/g_vault_install.err
   systemctl start  gvault       >>~/g_vault_install.log 2>>~/g_vault_install.err
   systemctl stop   gvault       >>~/g_vault_install.log 2>>~/g_vault_install.err
   systemctl start  gvault       >>~/g_vault_install.log 2>>~/g_vault_install.err

   chattr +i /usr/local/_gvault/         >>~/g_vault_install.log 2>>~/g_vault_install.err
   chattr +i /usr/local/_gvault/bin      >>~/g_vault_install.log 2>>~/g_vault_install.err
   chattr +i /usr/local/_gvault/lib      >>~/g_vault_install.log 2>>~/g_vault_install.err
   chattr +i /usr/local/_gvault/sys      >>~/g_vault_install.log 2>>~/g_vault_install.err
   chattr +i /usr/local/_gvault/bin/g*   >>~/g_vault_install.log 2>>~/g_vault_install.err
   chattr +i /usr/local/_gvault/lib/g*   >>~/g_vault_install.log 2>>~/g_vault_install.err
   chattr +i /usr/local/_gvault/sys/*    >>~/g_vault_install.log 2>>~/g_vault_install.err

   systemctl status gvault 2>/dev/null 

echo '
  All done.

  All files are installed at =>   /usr/local/_gvault/
  You can view the error log =>   more ~/g_vault_install.err    
  gVault new service named   =>   gvault
  Try to create a new gVault =>   gvault -c test
 '
