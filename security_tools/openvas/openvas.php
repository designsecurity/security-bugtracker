<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include('openvas.conf.php');
include('openvas.api.php');
include('types/TypeGetparamsfromalertid.php');
include('types/TypeAddissue.php');
include('types/TypeFinishscan.php');

if (isset($_GET["alertscanid"])) {
    $alertscanid = (int) $_GET["alertscanid"];
}

// http://localhost:81/webissues-server-2.0.0/client/security_tools/openvas/openvas.php?alertscanid=10512

if (!empty($alertscanid)) {
    $getparamsfromalertid = new TypeGetparamsfromalertid();
    $getparamsfromalertid->id_alert = $alertscanid;

    $webissueslogin = $GLOBALS['CONF_WEBISSUES_OPENVAS_LOGIN'];
    $webissuespwd = $GLOBALS['CONF_WEBISSUES_OPENVAS_PASSWORD'];

    $openvasomp = $GLOBALS['CONF_OPENVAS_PATH_OMP'];
    $openvaslogin = $GLOBALS['CONF_OPENVAS_ADMIN_LOGIN'];
    $openvaspwd = $GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD'];
    
    $credentials = array('login' => $webissueslogin, 'password' => $webissuespwd);

    try {
        ini_set('default_socket_timeout', 10000);
        ini_set('soap.wsdl_cache_enabled', 0);
        $clientsoap = new SoapClient($GLOBALS['CONF_WEBISSUES_WS_ENDPOINT']."?wsdl", $credentials);
        $param = new SoapParam($getparamsfromalertid, 'tns:getparamsfromalertid');
        $result = $clientsoap->__call('getparamsfromalertid', array('getparamsfromalertid'=>$param));
    } catch (SoapFault $e) {
        OpenvasApi::logp("it's here".$e->getMessage());
    }

    $id_folder_bugs = $result->getparamsfromalertid_details->id_folder_bugs;
    $id_target = $result->getparamsfromalertid_details->id_target;
    $id_task = $result->getparamsfromalertid_details->id_task;
    $id_report = $result->getparamsfromalertid_details->id_report;
    $id_alert = $result->getparamsfromalertid_details->id_alert;
    $severity = $result->getparamsfromalertid_details->severity;
    
    $idxml = $GLOBALS['CONF_OPENVAS_CONFIG_ID_XML'];
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password ".$openvaspwd;
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<get_reports report_id=\"$id_report\" format_id=\"$idxml\" details=\"1\" />'";
    $outputxml = shell_exec($cmd);
    
    $idpdf = $GLOBALS['CONF_OPENVAS_CONFIG_ID_PDF'];
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password ".$openvaspwd;
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<get_reports report_id=\"$id_report\" format_id=\"$idpdf\" details=\"1\" />'";
    $outputpdf = urlencode(shell_exec($cmd));
/*
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<delete_target target_id=\"$id_target\"/>'";
    $output = shell_exec($cmd);
    
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<delete_alert alert_id=\"$id_alert\"/>'";
    $output = shell_exec($cmd);
    
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<delete_task task_id=\"$id_task\"/>'";
    $output = shell_exec($cmd);
    
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<delete_report report_id=\"$id_report\"/>'";
    $output = shell_exec($cmd);
*/
    if (!empty($outputxml)) {
        $report = new SimpleXMLElement($outputxml);
  
        if (isset($report->report->report->results->result)) {
            foreach ($report->report->report->results->result as $result) {
                if (isset($result->threat)) {
                    switch ($result->threat) {
                        case 'Log':
                            $threat = 1;
                            break;
                        case 'Low':
                            $threat = 1;
                            break;
                        case 'Medium':
                            $threat = 2;
                            break;
                        case 'High':
                            $threat = 3;
                            break;
                        default:
                            $threat = 1;
                            break;
                    }
                }

                if ($threat >= $severity) {
                    $target = $result->host.":".$result->port;
                    $description = "vulnerable target : $target \n\n".$result->description;

                    $addissue = new TypeAddissue();
                    $addissue->id_folder_bugs = $id_folder_bugs;
                    $addissue->name = $result->name;
                    $addissue->description = $description;
                    $addissue->assigned = "";
                    $addissue->state = "Actif";
                    $addissue->severity = $threat;
                    $addissue->version = 1;
                    $addissue->target = $target;
                    $addissue->cve = $CONF_ISSUE_DEFAULT_CVENAME;
                    if (isset($result->cve) && !empty($result->cve) && $result->cve != "NOCVE") {
                        $addissue->cve = $result->cve;
                    }
                    $addissue->cwe = $CONF_ISSUE_DEFAULT_CWENAME;

                    try {
                        $param = new SoapParam($addissue, 'tns:addissue');
                        $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                        sleep(1);
                    } catch (SoapFault $e) {
                        OpenvasApi::logp($e->getMessage()/*." issue: ".print_r($addissue, true)*/);
                    }
                }
            }
        }
    }

    $finishscan = new TypeFinishscan();
    $finishscan->id_scan = $alertscanid;
    $finishscan->data_report = $outputpdf;

    try {
        $param = new SoapParam($finishscan, 'tns:finishscan');
        $result = $clientsoap->__call('finishscan', array('finishscan'=>$param));
    } catch (SoapFault $e) {
        OpenvasApi::logp($e->getMessage());
    }
}
      
ini_set('soap.wsdl_cache_enabled', 0);
$openserversoap = new SoapServer("openvas.wsdl");
$openserversoap->setClass("OpenvasApi");
$openserversoap->handle();
