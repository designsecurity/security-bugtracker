<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include( 'common.php' ); 

$credentials = array('login' => $CONF_WEBISSUES_OPENVAS_LOGIN, 'password' => $CONF_WEBISSUES_OPENVAS_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_servers();

$addscan = new type_addscan();
$addscan->id_folder_scans = $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_openvas_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_openvas_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "openvas";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

?>
