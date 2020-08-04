<?php

require_once('../system/bootstrap.inc.php');

include('securityplugin.conf.php');
include('securityplugin.lang.php');
include('securityplugin.common.php');
include('securityplugin.api.php');
include('types/TypeRunOpenvas.php');

System_Bootstrap::run('System_Web_Service');

ini_set('soap.wsdl_cache_enabled', 0);
$serversoap=new SoapServer("webservices.wsdl");
$serversoap->setClass("SecurityPluginApi");
$serversoap->handle();
