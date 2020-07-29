<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include('openvas.conf.php');
include('../../securityplugin.conf.php');

function logpp($ex)
{
    $fp = fopen("openvas.log", "a+");
    fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
    fclose($fp);
}

if (isset($_GET["alertscanid"])) {
    $alertscanid = (int) $_GET["alertscanid"];
}

// http://localhost:81/webissues-server-2.0.0/client/security_tools/openvas/openvas.php?alertscanid=789

if (!empty($alertscanid)) {
    $getparamsfromalertid = new typeGetparamsfromalertid();
    $getparamsfromalertid->id_alert = $alertscanid;

    $webissueslogin = $GLOBALS['CONF_WEBISSUES_OPENVAS_LOGIN'];
    $webissuespwd = $GLOBALS['CONF_WEBISSUES_OPENVAS_PASSWORD'];

    $openvasomp = $GLOBALS['CONF_OPENVAS_PATH_OMP'];
    $openvaslogin = $GLOBALS['CONF_OPENVAS_ADMIN_LOGIN'];
    $openvaspwd = $GLOBALS['CONF_WEBISSUES_OPENVAS_PASSWORD'];
    
    $credentials = array('login' => $webissueslogin, 'password' => $webissuespwd);

    try {
        ini_set('default_socket_timeout', 10000);
        ini_set('soap.wsdl_cache_enabled', 0);
        $clientsoap = new SoapClient($GLOBALS['CONF_WEBISSUES_WS_ENDPOINT']."?wsdl", $credentials);
        $param = new SoapParam($getparamsfromalertid, 'tns:getparamsfromalertid');
        $result = $clientsoap->__call('getparamsfromalertid', array('getparamsfromalertid'=>$param));
    } catch (SoapFault $e) {
        logpp("it's here".$e->getMessage());
    }

    $id_folder_bugs = $result->getparamsfromalertid_details->id_folder_bugs;
    $id_target = $result->getparamsfromalertid_details->id_target;
    $id_task = $result->getparamsfromalertid_details->id_task;
    $id_report = $result->getparamsfromalertid_details->id_report;
    $id_alert = $result->getparamsfromalertid_details->id_alert;
    $severity = $result->getparamsfromalertid_details->severity;
    
    /*
       /usr/local/bin/omp --get-report 38229f40-5088-4edd-8fe2-70a04825e744 --format a994b278-1f62-11e1-96ac-406186ea4fc5 -u admin -w 07da0873-747d-463f-960f-b7cec649d584 -p 9393
     */

    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password ".$openvaspwd;
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<get_reports report_id=\"$id_report\" format_id=\"".$GLOBALS['CONF_OPENVAS_CONFIG_ID_XML']."\" details=\"1\" />'";
    $outputxml = shell_exec($cmd);
    
    $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password ".$openvaspwd;
    $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
    $cmd .= " --xml='<get_reports report_id=\"$id_report\" format_id=\"".$GLOBALS['CONF_OPENVAS_CONFIG_ID_PDF']."\" details=\"1\" />'";
    $outputpdf = urlencode(shell_exec($cmd));

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

                    $addissue = new typeAddissue();
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
                        logpp($e->getMessage()/*." issue: ".print_r($addissue, true)*/);
                    }
                }
            }
        }
    }

    $finishscan = new typeFinishscan();
    $finishscan->id_scan = $alertscanid;
    $finishscan->data_report = $outputpdf;

    try {
        $param = new SoapParam($finishscan, 'tns:finishscan');
        $result = $clientsoap->__call('finishscan', array('finishscan'=>$param));
    } catch (SoapFault $e) {
        logpp($e->getMessage());
    }
}

class openvas_webservice_server
{
    function logp($ex)
    {
        $fp = fopen("openvas.log", "a+");
        fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
        fclose($fp);
    }

    function authws()
    {
        if (!($_SERVER['PHP_AUTH_USER'] == $GLOBALS['CONF_WS_OPENVAS_LOGIN'] 
          && $_SERVER['PHP_AUTH_PW'] == $GLOBALS['CONF_WS_OPENVAS_PASSWORD'])) {
            $this->logp("authentification failed ".$_SERVER['PHP_AUTH_USER']);
            return false;
        }

        return true;
    }

    function run_openvas($req)
    {
    
        if ($this->authws()) {
            $req = (array) $req;
            //vérifier validiter
            $issueId = $req["id_scan"];

            $targetid = '';
            $taskid = '';
            $reportid = '';
            $alertid = '';

            $configId = $GLOBALS['CONF_OPENVAS_CONFIG_ID'];
            if (isset($req["id_config"]) && !empty($req["id_config"])) {
                $configId = $req["id_config"];
            }

            $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
            $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
            $cmd .= " --xml='<create_target><name>webissue$issueId</name><hosts>".$req["target"]."</hosts></create_target>'";
            $output = shell_exec($cmd);
            
            preg_match('|<create_target_response .* id=\"([^"]*)\"|', $output, $matches);
            if (isset($matches[1])) {
                $targetid = $matches[1];
            } else {
                $this->logp("error '$cmd' create target = ".print_r($output, true));
            }

            if (!empty($targetid)) {
                $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
                $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
                $cmd .= " --xml='<create_alert><name>webissue".$issueId."</name><condition>Always</condition>";
                $cmd .= "<event>Task run status changed<data>Done<name>status</name></data></event>";
                $cmd .= "<method>HTTP Get<data><name>URL</name>".$GLOBALS['CONF_OPENVAS_ALERT_URL']."?alertscanid=".$issueId."</data></method></create_alert>'";
            
                $output = shell_exec($cmd);
                preg_match('|<create_alert_response .* id=\"([^"]*)\"|', $output, $matches);
                if (isset($matches[1])) {
                    $alertid = $matches[1];
                } else {
                    $this->logp("error create alert = ".$output);
                }
            }

            if (!empty($alertid)) {
                $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
                $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
                $cmd .= " --xml='<create_task><name>webissue$issueId</name><comment>test</comment>";
                $cmd .= "<config id=\"$configId\"/><target id=\"$targetid\"/><alert id=\"$alertid\"/>";
                $cmd .= "<scanner id=\"".$GLOBALS['CONF_OPENVAS_SCANNER_ID']."\"/></create_task>'";
                
                $output = shell_exec($cmd);
                preg_match('|<create_task_response .* id=\"([^"]*)\"|', $output, $matches);
                if (isset($matches[1])) {
                    $taskid = $matches[1];
                } else {
                    $this->logp("error create task = ".$output);
                }
            }

            if (!empty($taskid)) {
                $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
                $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
                $cmd .= " --xml='<start_task task_id=\"$taskid\"/>'";
                
                $output = shell_exec($cmd);
                preg_match('@<report_id>(.*)</report_id>.*@i', $output, $matches);
                if (isset($matches[1])) {
                    $reportid = $matches[1];
                } else {
                    $this->logp("error create report = ".$output);
                }
            }

            $tab = array(
                    array(
                        'id_target' => $targetid,
                        'id_task' => $taskid,
                        'id_report' => $reportid,
                        'id_alert' => $alertid
                         )
                    );

            return $tab;
        }
    }
}
      
ini_set('soap.wsdl_cache_enabled', 0);
$openserversoap = new SoapServer("openvas.wsdl");
$openserversoap->setClass("openvas_webservice_server");
$openserversoap->handle();
