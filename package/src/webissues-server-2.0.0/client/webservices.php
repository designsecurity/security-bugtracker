<?php

namespace securitybugtracker\Webissues\Client;

require_once('../system/bootstrap.inc.php');

include('securityplugin.conf.php');
include('securityplugin.lang.php');
include('securityplugin.common.php');

System_Bootstrap::run('System_Web_Service');

ini_set('soap.wsdl_cache_enabled', 0);
$serversoap=new SoapServer("webservices.wsdl");
$serversoap->setClass("WebserviceServer");
$serversoap->handle();
