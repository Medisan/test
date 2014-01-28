##################### FIRST LINE
# ---------------------------
#!/bin/bash
# ---------------------------
#
  SBFSCURRENTVERSION1=master
  OS1=$(lsb_release -si)
#
#
function getString
{
  local ISPASSWORD=$1
  local LABEL=$2
  local RETURN=$3
  local DEFAULT=$4
  local NEWVAR1=a
  local NEWVAR2=b
  local YESYES=YESyes
  local NONO=NOno
  local YESNO=$YESYES$NONO

  while [ ! $NEWVAR1 = $NEWVAR2 ] || [ -z "$NEWVAR1" ];
  do
    clear
    echo "#"
    echo "#"
    echo "# Sisif"
    echo "#"
    echo "#"
    echo "#"
    echo

    if [ "$ISPASSWORD" == "YES" ]; then
      read -s -p "$DEFAULT" -p "$LABEL" NEWVAR1
    else
      read -e -i "$DEFAULT" -p "$LABEL" NEWVAR1
    fi
    if [ -z "$NEWVAR1" ]; then
      NEWVAR1=a
      continue
    fi

    if [ ! -z "$DEFAULT" ]; then
      if grep -q "$DEFAULT" <<< "$YESNO"; then
        if grep -q "$NEWVAR1" <<< "$YESNO"; then
          if grep -q "$NEWVAR1" <<< "$YESYES"; then
            NEWVAR1=YES
          else
            NEWVAR1=NO
          fi
        else
          NEWVAR1=a
        fi
      fi
    fi

    if [ "$NEWVAR1" == "$DEFAULT" ]; then
      NEWVAR2=$NEWVAR1
    else
      if [ "$ISPASSWORD" == "YES" ]; then
        echo
        read -s -p "Retype: " NEWVAR2
      else
        read -p "Retype: " NEWVAR2
      fi
      if [ -z "$NEWVAR2" ]; then
        NEWVAR2=b
        continue
      fi
    fi


    if [ ! -z "$DEFAULT" ]; then
      if grep -q "$DEFAULT" <<< "$YESNO"; then
        if grep -q "$NEWVAR2" <<< "$YESNO"; then
          if grep -q "$NEWVAR2" <<< "$YESYES"; then
            NEWVAR2=YES
          else
            NEWVAR2=NO
          fi
        else
          NEWVAR2=a
        fi
      fi
    fi
    echo "---> $NEWVAR2"

  done
  eval $RETURN=\$NEWVAR1
}
# 0.

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

clear

# 1.

#localhost is ok this rtorrent/rutorrent installation
IPADDRESS1=`ifconfig | sed -n 's/.*inet addr:\([0-9.]\+\)\s.*/\1/p' | grep -v 127 | head -n 1`


#those passwords will be changed in the next steps
PASSWORD1=a
PASSWORD2=b

getString NO  "You need to create an user for your seedbox: " NEWUSER1
getString YES "Password for user $NEWUSER1: " PASSWORD1
getString NO  "IP address or hostname of your box: " IPADDRESS1 $IPADDRESS1
getString NO  "vsftp port (usually 21): " NEWFTPPORT1 21
getString NO  "Install Webmin? " INSTALLWEBMIN1 YES
getString NO  "Install Fail2ban? " INSTALLFAIL2BAN1 NO
getString NO  "Wich RTorrent version would you like to install, '0.9.2' or '0.9.3' or 'update'? " RTORRENT1 0.9.2

if [ "$RTORRENT1" != "0.9.3" ] && [ "$RTORRENT1" != "0.9.2" ] && [ "$RTORRENT1" != "update" ]; then
  echo "$RTORRENT1 typed is not 0.9.3 or 0.9.2 or update!"
  exit 1
fi

apt-get --yes install sudo
sudo apt-key adv --keyserver keys.gnupg.net --recv-keys 1C4CBDCDCD2EFD2A
echo "" | tee -a /etc/apt/sources.list > /dev/null
echo "deb http://repo.percona.com/apt squeeze main" | tee -a /etc/apt/sources.list > /dev/null

apt-get --yes update
apt-get --yes install whois makepasswd git

rm -f -r /etc/miscript
git clone https://github.com/W1nst0n/test.git /etc/miscript
mkdir -p cd /etc/miscript/source
mkdir -p cd /etc/miscript/users

# 3.1

#show all commands
set -x verbose

# 4.

groupadd sshdusers
echo "" | tee -a /etc/ssh/sshd_config > /dev/null
echo "UseDNS no" | tee -a /etc/ssh/sshd_config > /dev/null
mkdir -p /usr/share/terminfo/l/
cp /lib/terminfo/l/linux /usr/share/terminfo/l/

service ssh restart

# 6.
#remove cdrom from apt so it doesn't stop asking for it
perl -pi -e "s/deb cdrom/#deb cdrom/g" /etc/apt/sources.list

#add non-free sources to Debian Squeeze# those two spaces below are on purpose
perl -pi -e "s/squeeze main/squeeze  main contrib non-free/g" /etc/apt/sources.list
perl -pi -e "s/squeeze-updates main/squeeze-updates  main contrib non-free/g" /etc/apt/sources.list

# 7.
# update and upgrade packages

apt-get --yes update
apt-get --yes upgrade

# 8.
#install all needed packages

apt-get --yes build-dep znc
apt-get --yes install apache2 apache2-utils autoconf build-essential ca-certificates comerr-dev curl cfv quota mktorrent dtach htop irssi libapache2-mod-php5 libcloog-ppl-dev libcppunit-dev libcurl3 libcurl4-openssl-dev libncurses5-dev libterm-readline-gnu-perl libsigc++-2.0-dev libperl-dev libssl-dev libtool libxml2-dev ncurses-base ncurses-term ntp openssl patch libc-ares-dev pkg-config php5 php5-cli php5-dev php5-curl php5-geoip php5-mcrypt php5-gd php5-xmlrpc pkg-config python-scgi screen ssl-cert subversion texinfo unzip zlib1g-dev expect joe automake1.9 flex bison debhelper binutils-gold ffmpeg libarchive-zip-perl libnet-ssleay-perl libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl libxml-libxml-perl libjson-rpc-perl libarchive-zip-perl znc tcpdump
if [ $? -gt 0 ]; then
  set +x verbose
  echo
  echo
  echo *** ERROR ***
  echo
  echo "Looks like somethig is wrong with apt-get install, aborting."
  echo
  echo
  echo
  set -e
  exit 1
fi
apt-get --yes install zip
apt-get --yes install python-software-properties

apt-get --yes install rar
if [ $? -gt 0 ]; then
  apt-get --yes install rar-free
fi

apt-get --yes install unrar
if [ $? -gt 0 ]; then
  apt-get --yes install unrar-free
fi

apt-get --yes install dnsutils

# 8.1 additional packages for Ubuntu
# this is better to be apart from the others
apt-get --yes install php5-fpm
apt-get --yes install php5-xcache

#Check if its Debian an do a sysvinit by upstart replacement:

if [ "$OS1" = "Debian" ]; then
  echo 'Yes, do as I say!' | apt-get -y --force-yes install upstart
fi

# 8.3 Generate our lists of ports and RPC and create variables

#permanently adding scripts to PATH to all users and root
#echo "PATH=$PATH:/etc/miscript:/sbin" | tee -a /etc/profile > /dev/null
#echo "export PATH" | tee -a /etc/profile > /dev/null
#echo "PATH=$PATH:/etc/miscript:/sbin" | tee -a /root/.bashrc > /dev/null
#echo "export PATH" | tee -a /root/.bashrc > /dev/null

rm -f /etc/miscript/ports.txt
for i in $(seq 51101 51999)
do
  echo "$i" | tee -a /etc/miscript/ports.txt > /dev/null
done

rm -f /etc/miscript/rpc.txt
for i in $(seq 2 1000)
do
  echo "RPC$i"  | tee -a /etc/miscript/rpc.txt > /dev/null
done

# 8.4

if [ "$INSTALLWEBMIN1" = "YES" ]; then
  #if webmin isup, download key
  WEBMINDOWN=YES
  ping -c1 -w2 www.webmin.com > /dev/null
  if [ $? = 0 ] ; then
    wget -t 5 http://www.webmin.com/jcameron-key.asc
    apt-key add jcameron-key.asc
    if [ $? = 0 ] ; then
      WEBMINDOWN=NO
    fi
  fi

  if [ "$WEBMINDOWN"="NO" ] ; then
    #add webmin source
    echo "" | tee -a /etc/apt/sources.list > /dev/null
    echo "deb http://download.webmin.com/download/repository sarge contrib" | tee -a /etc/apt/sources.list > /dev/null
    cd /tmp
  fi

  if [ "$WEBMINDOWN" = "NO" ]; then
    apt-get --yes update
    apt-get --yes install webmin
  fi
fi

if [ "$INSTALLFAIL2BAN1" = "YES" ]; then
  apt-get --yes install fail2ban
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.original
  cp /etc/miscript/etc.fail2ban.jail.conf.template /etc/fail2ban/jail.conf
  fail2ban-client reload
fi

# 9.
apt-get --yes install libmysqlclient18
sudo dpkg --install libapache2-mod-auth-mysql-amd64.deb
echo "libapache2-mod-auth-mysql hold" | sudo dpkg --set-selections

a2enmod auth_mysql
a2enmod ssl
a2enmod auth_digest ## remove this asap
a2enmod reqtimeout
#a2enmod scgi ############### if we cant make python-scgi works

# 10.

#remove timeout if  there are any
perl -pi -e "s/^Timeout [0-9]*$//g" /etc/apache2/apache2.conf

echo "" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "#seedbox values" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "ServerSignature Off" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "ServerTokens Prod" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "Timeout 30" | tee -a /etc/apache2/apache2.conf > /dev/null

service apache2 restart

echo "$IPADDRESS1" > /etc/miscript/hostname.info

# 11.

export TEMPHOSTNAME1=tsfsSeedBox
export CERTPASS1=@@$TEMPHOSTNAME1.$NEWUSER1.ServerP7s$
export NEWUSER1
export IPADDRESS1

echo "$NEWUSER1" > /etc/miscript/mainuser.info
echo "$CERTPASS1" > /etc/miscript/certpass.info

bash /etc/miscript/createOpenSSLCACertificate

mkdir -p /etc/ssl/private/
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem -config /etc/miscript/ssl/CA/caconfig.cnf

if [ "$OS1" = "Debian" ]; then
  apt-get --yes install vsftpd
else
  apt-get --yes install libcap-dev libpam0g-dev libwrap0-dev
  dpkg -i /etc/miscript/vsftpd_2.3.2-3ubuntu5.1_`uname -m`.deb
fi

perl -pi -e "s/anonymous_enable\=YES/anonymous_enable\=NO/g" /etc/vsftpd.conf
perl -pi -e "s/connect_from_port_20\=YES/#connect_from_port_20\=YES/g" /etc/vsftpd.conf
echo "listen_port=$NEWFTPPORT1" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_enable=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "allow_anon_ssl=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "force_local_data_ssl=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "force_local_logins_ssl=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_tlsv1=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_sslv2=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_sslv3=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "require_ssl_reuse=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_ciphers=HIGH" | tee -a /etc/vsftpd.conf >> /dev/null
echo "rsa_cert_file=/etc/ssl/private/vsftpd.pem" | tee -a /etc/vsftpd.conf >> /dev/null
echo "local_enable=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "write_enable=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "local_umask=022" | tee -a /etc/vsftpd.conf >> /dev/null
echo "chroot_local_user=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "chroot_list_file=/etc/vsftpd.chroot_list" | tee -a /etc/vsftpd.conf >> /dev/null
echo "pasv_promiscuous=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "port_promiscuous=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "check_shell=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "/sbin/nologin" | tee -a /etc/shells >> /dev/null

# 13.
mv /etc/apache2/sites-available/default /etc/apache2/sites-available/default.ORI
rm -f /etc/apache2/sites-available/default

cp /etc/miscript/etc.apache2.default.template /etc/apache2/sites-available/default
perl -pi -e "s/http\:\/\/.*\/rutorrent/http\:\/\/$IPADDRESS1\/rutorrent/g" /etc/apache2/sites-available/default
perl -pi -e "s/<servername>/$IPADDRESS1/g" /etc/apache2/sites-available/default
perl -pi -e "s/<username>/$NEWUSER1/g" /etc/apache2/sites-available/default

echo "ServerName $IPADDRESS1" | tee -a /etc/apache2/apache2.conf > /dev/null

# 14.
a2ensite default-ssl

#14.1
#ln -s /etc/apache2/mods-available/scgi.load /etc/apache2/mods-enabled/scgi.load
#service apache2 restart
#apt-get --yes install libxmlrpc-core-c3-dev

# 15.
tar xvfz /etc/miscript/xmlrpc-c-1.16.42.tgz -C /etc/miscript/source/
cd /etc/miscript/source/
unzip ../xmlrpc-c-1.31.06.zip

# 16.
#cd xmlrpc-c-1.16.42 ### old, but stable, version, needs a missing old types.h file
#ln -s /usr/include/curl/curl.h /usr/include/curl/types.h
cd xmlrpc-c-1.31.06
./configure --prefix=/usr --enable-libxml2-backend --disable-libwww-client --disable-wininet-client --disable-abyss-server --disable-cgi-server
make
make install

# 21.

bash /etc/miscript/installRTorrent $RTORRENT1

# 22.
cd /var/www
rm -f -r rutorrent
svn checkout http://rutorrent.googlecode.com/svn/trunk/rutorrent
svn checkout http://rutorrent.googlecode.com/svn/trunk/plugins
rm -r -f rutorrent/plugins
mv plugins rutorrent/

#remove mediainfo plugin
rm -r /var/www/rutorrent/plugins/mediainfo

#remove unpack plugin
rm -r /var/www/rutorrent/plugins/unpack

rm -r -f /var/www/rutorrent/js/webui.js
cp /etc/miscript/rutorrent/js/webui.js /var/www/rutorrent/js/webui.js
mv /etc/miscript/rutorrent/plugins/* /var/www/rutorrent/plugins
mv /etc/miscript/rutorrent/themes/* /var/www/rutorrent/plugins/theme/themes
rm -r -f /var/www/rutorrent/plugins/create/conf.php
cp /etc/miscript/rutorrent/plugins/create/conf.php /var/www/rutorrent/plugins/create/
cp /etc/miscript/action.php.template /var/www/rutorrent/plugins/diskspace/action.php

groupadd admin

echo "www-data ALL=(root) NOPASSWD: /usr/sbin/repquota" | tee -a /etc/sudoers > /dev/null

cp /etc/miscript/favicon.ico /var/www/

cd /var/www/rutorrent/plugins
svn co https://svn.code.sf.net/p/autodl-irssi/code/trunk/rutorrent/autodl-irssi
cd autodl-irssi

cd /var/www/rutorrent/plugins/
wget https://rutorrent-logoff.googlecode.com/files/logoff-1.3.tar.gz
tar -zxf logoff-1.3.tar.gz
rm -f logoff-1.3.tar.gz



# 32.2
chown -R www-data:www-data /var/www/rutorrent
chmod -R 755 /var/www/rutorrent

rm -f /var/www/rutorrent/conf/access.ini
cp /etc/miscript/rutorrent.conf.access.ini.template /var/www/rutorrent/conf/access.ini

ln -s /etc/miscript/seedboxInfo.php.template /var/www/seedboxInfo.php

# 33.

bash /etc/miscript/updateExecutables

#34.

echo $SBFSCURRENTVERSION1 > /etc/miscript/version.info
echo $NEWFTPPORT1 > /etc/miscript/ftp.info

# 36.

wget -P /usr/share/ca-certificates/ --no-check-certificate https://certs.godaddy.com/repository/gd_intermediate.crt https://certs.godaddy.com/repository/gd_cross_intermediate.crt
update-ca-certificates
c_rehash


# 97.

#first user will not be jailed
#  createSeedboxUser <username> <password> <user jailed?> <ssh access?> <?>
bash /etc/miscript/createSeedboxUser $NEWUSER1 $PASSWORD1 YES YES YES

# 98.

set +x verbose

clear

echo ""
echo ""
echo "Looks like everything is set."
echo ""
echo ""
echo "Setup quota(user only) in webmin then reboot"
echo ""
echo ""
echo ""
echo ""
echo ""



##################### LAST LINE ###########
