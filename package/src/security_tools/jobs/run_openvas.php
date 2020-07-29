<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include('../common/common_includes.php');
include('common.php');

$credentials = array('login' => $CONF_WEBISSUES_OPENVAS_LOGIN, 'password' => $CONF_WEBISSUES_OPENVAS_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

if ($argc > 1) {
    echo "argv0 ".htmlentities($argv[0]);
    echo "argv1 ".htmlentities($argv[1]);

    if (is_int($argv[1])) {
        $ids_folder_scans = array((int) $argv[1]);
    } elseif ($argv[1] == "global") {
        $ids_folder_scans = array($CONF_WEBISSUES_FOLDER_SCANS);
    }
  
    add_assets_servers();
} else {
    $ids_folder_scans = add_projects_with_assets_servers();
}

foreach ($ids_folder_scans as $id_folder_scans) {
    $addscan = new TypeAddscan();
    $addscan->id_folder_scans = $id_folder_scans;
    $addscan->name = "scan_".rand()."_openvas_".$id_folder_scans;
    $addscan->description = "scan_".rand()."_openvas_".$id_folder_scans;
    $addscan->tool = "openvas";
    $addscan->filter = "medium";

    $param = new SoapParam($addscan, 'tns:type_addscan');
    $result = $clientsoap->__call('addscan', array('type_addscan'=>$param));
}
