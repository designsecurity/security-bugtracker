<?php

namespace securitybugtracker\Tools\Openvas;

class OpenvasWebserviceServer
{
    private function logp($ex)
    {
        $fp = fopen("openvas.log", "a+");
        fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
        fclose($fp);
    }

    private function authws()
    {
        if (!($_SERVER['PHP_AUTH_USER'] == $GLOBALS['CONF_WS_OPENVAS_LOGIN']
          && $_SERVER['PHP_AUTH_PW'] == $GLOBALS['CONF_WS_OPENVAS_PASSWORD'])) {
            $this->logp("authentification failed ".$_SERVER['PHP_AUTH_USER']);
            return false;
        }

        return true;
    }

    private function runOpenvas($req)
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
            $cmd .= " --xml='<create_target><name>webissue$issueId</name>";
            $cmd .= "<hosts>".$req["target"]."</hosts></create_target>'";
            $output = shell_exec($cmd);
            
            preg_match('|<create_target_response .* id=\"([^"]*)\"|', $output, $matches);
            if (isset($matches[1])) {
                $targetid = $matches[1];
            } else {
                $this->logp("error '$cmd'");
            }

            if (!empty($targetid)) {
                $cmd = "sudo -u gvm $openvasomp --gmp-username $openvaslogin --gmp-password $openvaspwd";
                $cmd .= " socket --socketpath /opt/gvm/var/run/gvmd.sock";
                $cmd .= " --xml='<create_alert><name>webissue".$issueId."</name><condition>Always</condition>";
                $cmd .= "<event>Task run status changed<data>Done<name>status</name></data></event>";
                $cmd .= "<method>HTTP Get<data><name>URL</name>":
                $cmd .= $GLOBALS['CONF_OPENVAS_ALERT_URL']."?alertscanid=".$issueId."</data></method></create_alert>'";
            
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
