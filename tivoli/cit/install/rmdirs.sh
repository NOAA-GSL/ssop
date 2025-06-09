#!/bin/sh
################################################################################
## 	Licensed Materials - Property of IBM
##
##    TIVOCIT00
##
## 	(C) Copyright IBM Corp. 2005-2010 All Rights Reserved.
##
##	US Government Users Restricted Rights - Use, duplication,
## 	or disclosure restricted by GSA ADP Schedule Contract with
## 	IBM Corp.
##
################################################################################

ismp_install=$1
wpar_shared=$2
wpar_config_root=$3

rm -rf "/opt/tivoli/cit/config/SingleUserMode"
  
if [ "$ismp_install" = "false" -o -z "$ismp_install" ];then
  rm -rf "/opt/tivoli/cit/install/SWD_CLI"
  rm -rf "/opt/tivoli/cit/_uninst"
  rm -rf "/opt/tivoli/cit/cache_data"
  rm -rf "/opt/tivoli/cit/logs"
  rm -rf "/opt/tivoli/cit/bin/etc"
fi

if [ "$wpar_shared" = "true" ];then
  rm -rf $wpar_config_root/bin
  rm -rf $wpar_config_root/cache_data/*
  rm -rf $wpar_config_root/config
fi
  
TIVOLI_COMMON_DIR=/usr/ibm/tivoli/common
if [ ! -z  "$TIVOLI_COMMON_DIR" ];then
  rm -rf "$TIVOLI_COMMON_DIR/CIT"
fi

