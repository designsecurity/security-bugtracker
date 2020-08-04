#!/bin/bash

if [ $# -lt 2 ]; then
  echo "Usage"
  echo "  $0 security-plugin directory"
  echo "    to install security-plugin in the specified webissues 2 directory"
  echo "    example: ./install.sh security-plugin /srv/www/htdocs/webissues-server-2.0.0/"
  echo ""
  echo "  $0 openvas-services directory"
  echo "    to install openvas-services in a specified web server directory"
  echo "    example: ./install.sh openvas-services /srv/www/htdocs/openvas-services/"
  echo ""
  echo ""
  exit 1
fi

if [ "security-plugin" = "$1" ]; then
  if [ -d $2 ]; then
    WEBISSUESCLIENT="${2}/client/"
    if [ -d $WEBISSUESCLIENT ]; then
      if [ ! -w $WEBISSUESCLIENT ]; then
        echo "Can't write into $WEBISSUESCLIENT directory"
        exit 1
      fi

      cp -r ./webissues-server-2.0.0/client/* $WEBISSUESCLIENT
    else
      echo "$2 doesn't seem a webissues 2 directory (looking for $WEBISSUESCLIENT folder)"
      exit 1
    fi
    
    WEBISSUESCOMMON="${2}/common/"
    if [ -d $WEBISSUESCOMMON ]; then
      if [ ! -w $WEBISSUESCOMMON ]; then
        echo "Can't write into $WEBISSUESCOMMON directory"
        exit 1
      fi
      
      cp ./webissues-server-2.0.0/common/* $WEBISSUESCOMMON
    else
      echo "$2 doesn't seem a webissues 2 directory (looking for $WEBISSUESCOMMON folder)"
      exit 1
    fi

    echo "security-plugin correctly installed!"
    echo "go to http://localhost:/webissues-server-2.0.0/client/securityplugin.php to configure security-plugin"
    
  else
    echo "$2 directory doesn't exist"
    exit 1
  fi
elif [ "openvas-services" = "$1" ]; then
  if [ -d $2 ]; then
    if [ ! -w $2 ]; then
      echo "Can't write into $2 directory"
      exit 1
    fi

    cp -r ./security_tools/openvas/ $2
    echo "openvas-services correctly installed!"
  else
    echo "$2 directory doesn't exist"
    exit 1
  fi
else
  echo "incorrect argument: $1"
  exit 1
fi
