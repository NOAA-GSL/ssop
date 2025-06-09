#!/bin/sh
################################################################################
## 	Licensed Materials - Property of IBM
##
##    TIVOCIT00
##
## 	(C) Copyright IBM Corp. 2005-2011 All Rights Reserved.
##
##	US Government Users Restricted Rights - Use, duplication,
## 	or disclosure restricted by GSA ADP Schedule Contract with
## 	IBM Corp.
##
################################################################################

option=$1
x_os=$2

if [ "$x_os" = "AIX" ] 
then
  LIBPATH=.:$LIBPATH:"/opt/tivoli/cit/bin"
  export LIBPATH
else
  if [ "$x_os" = "SunOS" ]
  then
    LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH:"/opt/tivoli/cit/bin"
    export LD_LIBRARY_PATH
  else
    if [ "$x_os" = "Linux" ]
    then
      LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH:"/opt/tivoli/cit/bin"
      export LD_LIBRARY_PATH
    else
      if [ "$x_os" = "HP-UX" ]
      then
        SHLIB_PATH=.:$SHLIB_PATH:"/opt/tivoli/cit/bin"
        export SHLIB_PATH
      fi
    fi
  fi
fi



if [ "$option" = "trace" ]
then
  "/opt/tivoli/cit/bin/wscancfg" -s trace_file traceCIT.log
else
  if [ "$option" = "enable" ]
  then
    "/opt/tivoli/cit/bin/wscancfg" -enable all
  else
    if [ "$option" = "shutdown" ]
    then
	  "/opt/tivoli/cit/bin/wscancfg" -enable all
      "/opt/tivoli/cit/bin/wscanfs" -shutdown -nostop
      "/opt/tivoli/cit/bin/wscancfg" -shutdown all -timeout 60 -force
      "/opt/tivoli/cit/bin/wscancfg" -shutdown all -timeout 120
    else
      if [ "$option" = "disable" ]
      then
        "/opt/tivoli/cit/bin/wscancfg" -disable all
      else
        if [ "$option" = "freeze" ]
        then
          "/opt/tivoli/cit/bin/wscanfs" -shutdown -nostop
          "/opt/tivoli/cit/bin/wscancfg" -disable all
          "/opt/tivoli/cit/bin/wscancfg" -shutdown all -timeout 60 -force
          "/opt/tivoli/cit/bin/wscancfg" -shutdown all -timeout 120
        fi
      fi
    fi
  fi
fi
