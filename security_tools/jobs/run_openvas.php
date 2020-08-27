<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include('common.php');
include('assets.api.php');

$credentials = array('login' => $CONF_WEBISSUES_OPENVAS_LOGIN, 'password' => $CONF_WEBISSUES_OPENVAS_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);
$clientsoap->__setLocation($CONF_WEBISSUES_WS_ENDPOINT);

/*
run_openvas.php ips/hostnames int_foldertoputscans
run_openvas.php ips/hostnames global <= from config file
run_openvas.php ips/hostnames <= create new projects/folders
*/

$ids_folder_scans = array();

if ($argc > 2) {
    echo "argv0 ".htmlentities($argv[0]);
    echo "argv1 ".htmlentities($argv[1]);
    echo "argv2 ".htmlentities($argv[2]);

    if (is_int($argv[2])) {
        $ids_folder_scans = array((int) $argv[2]);
    } elseif ($argv[2] == "global") {
        $ids_folder_scans = array($CONF_WEBISSUES_FOLDER_SCANS);
    }
  
    if ($argv[1] == "ips") {
        add_assets_servers();
    } elseif ($argv[1] == "hostnames") {
        add_assets_urls();
    }
} elseif ($argc > 1) {
    if ($argv[1] == "ips") {
        $ids_folder_scans = add_projects_with_assets("ips");
    } elseif ($argv[1] == "hostnames") {
        $ids_folder_scans = add_projects_with_assets("hostnames");
    }
}

foreach ($ids_folder_scans as $id_folder_scans) {
    $addscan = new TypeAddscan();
    $addscan->id_folder_scans = $id_folder_scans;
    $addscan->name = "scan_".rand()."_openvas_".$id_folder_scans;
    $addscan->description = "scan_".rand()."_openvas_".$id_folder_scans;
    $addscan->tool = "openvas";
    $addscan->filter = "info";

    $param = new SoapParam($addscan, 'tns:type_addscan');
    $result = $clientsoap->__call('addscan', array('type_addscan'=>$param));
}
