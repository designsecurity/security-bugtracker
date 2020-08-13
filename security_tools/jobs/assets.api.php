<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */
   
function add_assets_urls()
{
    $addurl = new TypeAddurl();

    $fp1 = fopen($GLOBALS["ASSETS_WEB_NAMES"], "r");
    $fp2 = fopen($GLOBALS["ASSETS_WEB_URLS"], "r");
    if ($fp1 && $fp2) {
        while (!feof($fp1) && !feof($fp2)) {
            $name = fgets($fp1);
            $url = fgets($fp2);

            $addurl->id_folder_web = $GLOBALS["CONF_WEBISSUES_FOLDER_WEB"];
            $addurl->name = $name;
            $addurl->description = $name;
            $addurl->url = $url;

            if (!empty($url)) {
                try {
                    $param = new SoapParam($addurl, 'tns:type_addurl');
                    $result = $GLOBALS["clientsoap"]->__call('addurl', array('type_addurl'=>$param));
                } catch (SoapFault $e) {
                    echo $e->getMessage()."\n";
                }
            }
        }
    }

    fclose($fp1);
    fclose($fp2);
}

function add_assets_codes()
{
    $addcode = new TypeAddcode();

    $fp1 = fopen($GLOBALS["ASSETS_CODES_NAMES"], "r");
    $fp2 = fopen($GLOBALS["ASSETS_CODES_PATHS"], "r");
    if ($fp1 && $fp2) {
        while (!feof($fp1) && !feof($fp2)) {
            $name = fgets($fp1);
            $code = fgets($fp2);

            $addcode->id_folder_codes = $GLOBALS["CONF_WEBISSUES_FOLDER_CODES"];
            $addcode->name = $name;
            $addcode->description = $name;
            $addcode->code = $code;

            if (!empty($code)) {
                try {
                    $param = new SoapParam($addcode, 'tns:type_addcode');
                    $result = $GLOBALS["clientsoap"]->__call('addcode', array('type_addcode'=>$param));
                } catch (SoapFault $e) {
                    echo $e->getMessage()."\n";
                }
            }
        }

        fclose($fp1);
        fclose($fp2);
    }
}

function add_assets_servers()
{
    $addserver = new TypeAddserver();

    $fp1 = fopen($GLOBALS["ASSETS_SERVERS_HOSTNAMES"], "r");
    $fp2 = fopen($GLOBALS["ASSETS_SERVERS_IPS"], "r");
    if ($fp1 && $fp2) {
        while (!feof($fp1) && !feof($fp2)) {
            $hostname = rtrim(fgets($fp1));
            
            $sep1 = $GLOBALS["CONF_FILE_IP_SEPARATOR"];
            $sep2 = $GLOBALS["CONF_WEBISSUES_IP_SEPARATOR"];
            
            $ips = str_replace($sep1, $sep2, rtrim(fgets($fp2)));

            echo "'".htmlentities($hostname)."'\n";
            echo "'".htmlentities($ips)."'\n";
            $addserver->id_folder_servers = (int) $GLOBALS["CONF_WEBISSUES_FOLDER_SERVERS"];
            $addserver->hostname = $hostname;
            $addserver->description = $hostname;
            $addserver->use = "Production";
            $addserver->ipsaddress = $ips;

            try {
                $param = new SoapParam($addserver, 'tns:type_addserver');
                $result = $GLOBALS["clientsoap"]->__call('addserver', array('type_addserver'=>$param));
            } catch (SoapFault $e) {
                echo $e->getMessage()."\n";
            }
        }

        fclose($fp1);
        fclose($fp2);
    }
}

function add_projects_with_assets($type = "servers")
{
    $addurl = new TypeAddurl();
    $addserver = new TypeAddserver();
    $addproject = new TypeAddproject();
    $getproject = new TypeGetproject();

    $fp1 = fopen($GLOBALS["ASSETS_SERVERS_PROJECTS"], "r");
    $fp2 = fopen($GLOBALS["ASSETS_SERVERS_HOSTNAMES"], "r");
    $fp3 = fopen($GLOBALS["ASSETS_SERVERS_IPS"], "r");
    if ($fp1 && $fp2 && $fp3) {
        $currentProject = null;
        $currentIdProject = -1;
        $currentIdFolderServers = -1;
        $currentIdFolderWeb = -1;
        $listOfFolderToScans = array();
    
        while (!feof($fp1) && !feof($fp2) && !feof($fp3)) {
            $project = rtrim(fgets($fp1));
            $hostname = rtrim(fgets($fp2));
            
            $sep1 = $GLOBALS["CONF_FILE_IP_SEPARATOR"];
            $sep2 = $GLOBALS["CONF_WEBISSUES_IP_SEPARATOR"];
            
            $ips = str_replace($sep1, $sep2, rtrim(fgets($fp3)));
            
            echo "here >> ".htmlentities($currentProject)."\n";
            echo "here >> ".htmlentities($project)."\n";
        
            if ($currentProject !== $project) {
                $addproject->name = substr($project, 0, 39);
                $addproject->description = $project;
        
                echo "here >> ".htmlentities($project)."\n";

                try {
                    $getproject->name = $addproject->name;
                    $param = new SoapParam($getproject, 'tns:type_getproject');
                    $result = $GLOBALS["clientsoap"]->__call('getproject', array('type_getproject'=>$param));
                    
                    if (isset($result->result_getproject_details->id_project)
                      && is_int($result->result_getproject_details->id_project)) {
                        $currentIdProject = $result->result_getproject_details->id_project;
                      
                        if (isset($result->result_getproject_details->id_folder_servers)
                        && $result->result_getproject_details->id_folder_servers === -1) {
                            echo "project '".$getproject->name."' exist but not the servers folder\n";
                        } else {
                            $currentIdFolderServers = $result->result_getproject_details->id_folder_servers;
                            $currentIdFolderWeb = $result->result_getproject_details->id_folder_web;
                        }
                      
                        if (isset($result->result_getproject_details->id_folder_scans)
                        && $result->result_getproject_details->id_folder_scans === -1) {
                            echo "project '".$getproject->name."' exist but not the scans folder\n";
                        } else {
                            array_push($listOfFolderToScans, $result->result_getproject_details->id_folder_scans);
                        }
                    } else {
                        $param = new SoapParam($addproject, 'tns:type_addproject');
                        $result = $GLOBALS["clientsoap"]->__call('addproject', array('type_addproject'=>$param));
            
                        var_dump($result);
            
                        $currentIdProject = $result->id_details->id_project;
                        $currentIdFolderServers = $result->id_details->id_folder_servers;
                        $currentIdFolderWeb = $result->id_details->id_folder_web;
                        array_push($listOfFolderToScans, $result->id_details->id_folder_scans);
                    }
                    
          
                    $currentProject = $project;
                } catch (SoapFault $e) {
                    echo $e->getMessage()."\n";
                }
            }

            echo "'".htmlentities($currentIdFolderServers)."'\n";
            echo "'".htmlentities($currentIdFolderWeb)."'\n";
            echo "'".htmlentities($hostname)."'\n";
            echo "'".htmlentities($ips)."'\n";
            
            if ($currentIdFolderServers !== -1 && $type === "ips") {
                $addserver->id_folder_servers = $currentIdFolderServers;
                $addserver->hostname = $hostname;
                $addserver->description = $hostname;
                $addserver->use = "Production";
                $addserver->ipsaddress = $ips;

                try {
                    $param = new SoapParam($addserver, 'tns:type_addserver');
                    $result = $GLOBALS["clientsoap"]->__call('addserver', array('type_addserver'=>$param));
                } catch (SoapFault $e) {
                    echo $e->getMessage()."\n";
                }
            }
            
            else if ($currentIdFolderWeb !== -1 && $type === "hostnames") {
                $addurl->id_folder_web = $currentIdFolderWeb;
                $addurl->name = $hostname;
                $addurl->description = $hostname;
                $addurl->url = $hostname;

                try {
                    $param = new SoapParam($addserver, 'tns:type_addurl');
                    $result = $GLOBALS["clientsoap"]->__call('addurl', array('type_addurl'=>$param));
                } catch (SoapFault $e) {
                    echo $e->getMessage()."\n";
                }
            }
        }

        fclose($fp1);
        fclose($fp2);
        fclose($fp3);
    }
    
    return $listOfFolderToScans;
}
