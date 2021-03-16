<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

class SecurityPluginCommon
{
    public static function getProjectByName($name)
    {
        $query = "SELECT project_id FROM projects where project_name = %s";
            
        $connection = System_Core_Application::getInstance()->getConnection();
        return $connection->queryRow($query, $name);
    }
    
    public static function getIssues($folder)
    {
        $folderId = $folder["folder_id"];
        $query = "SELECT i.issue_name, i.issue_id, f.type_id, i.folder_id FROM {issues}";
        $query .= " AS i JOIN {folders} AS f ON f.folder_id = i.folder_id JOIN {projects}";
        $query .= " AS p ON p.project_id = f.project_id JOIN {issue_types}";
        $query .= " AS t ON t.type_id = f.type_id WHERE i.folder_id = %d";
            
        $connection = System_Core_Application::getInstance()->getConnection();
        return $connection->queryTable($query, $folderId);
    }
    
    public static function logp($ex)
    {
        $fp = fopen("webservices.log", "a+");
        fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
        fclose($fp);
    }

    public static function runDependencycheck($req, $targets)
    {
        return SecurityPluginCommon::commonScan($req);
    }

    public static function runArachni($req, $targets)
    {
        return SecurityPluginCommon::commonScan($req);
    }

    public static function runSonar($req, $targets)
    {
        return SecurityPluginCommon::commonScan($req);
    }

    public static function runZap($req, $targets)
    {
        return SecurityPluginCommon::commonScan($req);
    }

    public static function runSslscan($req, $targets)
    {
        return SecurityPluginCommon::commonScan($req);
    }

    public static function findTargets($req, $type)
    {
        $targets = array();

        try {
            $issueManager = new System_Api_IssueManager();
            $projectManager = new System_Api_ProjectManager();

            // servers
            $id_type = -1;
            $id_attribute = -1;
            if ($type == "static") {
                $id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_CODES'];
                $id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'];
            } elseif ($type == "web") {
                $id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_WEB'];
                $id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'];
            } elseif ($type == "servers") {
                $id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS'];
                $id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'];
            }

            $folderscan = $projectManager->getFolder($req["id_folder_scans"]);
            $project = $projectManager->getProject($folderscan[ 'project_id' ]);

            $id_folder_targets = 0;
            $folders = $projectManager->getFoldersForProject($project);
            foreach ($folders as $folder) {
                if ($folder["type_id"] == $id_type) {
                    $id_folder_targets = $folder["folder_id"];
                    break;
                }
            }

            if ($id_folder_targets > 0) {
                $nbtargets = 0;
                $foldertargets = $projectManager->getFolder($id_folder_targets);
                $targets = SecurityPluginCommon::getIssues($foldertargets);
                foreach ($targets as $target) {
                    $attributes = $issueManager->getAllAttributeValuesForIssue($target);
                    foreach ($attributes as $idattribute => $attribute) {
                        if ($attribute["attr_id"] == $id_attribute) {
                            $targets[$nbtargets] = $attribute["attr_value"];
                            $nbtargets ++;
                        }
                    }
                }
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            //throw new SoapFault("Server", "System_Api_Error $ex");
        }

        return $targets;
    }

    public static function commonScan($req)
    {
        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();
        $formatterManager = new System_Api_Formatter();
      
        try {
            if (empty($req["time"])) {
                $req["time"] = "stopped";
            }

            $folderscan = $projectManager->getFolder($req["id_folder_scans"]);
            $issueId = $issueManager->addIssue($folderscan, $req["name"], null);
            $issue = $issueManager->getIssue($issueId);
            $issueManager->addDescription($issue, $req["description"], System_Const::TextWithMarkup);
            
            $attributetime = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME']);
            $valuetime = $formatterManager->convertAttributeValue($attributetime[ 'attr_def' ], $req["time"]);
            $issueManager->setValue($issue, $attributetime, $valuetime);
            
            $attributetool = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL']);
            $valuetool = $formatterManager->convertAttributeValue($attributetool[ 'attr_def' ], $req["tool"]);
            $issueManager->setValue($issue, $attributetool, $valuetool);
            
            $attributefilter = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY']);
            $valuefilter = $formatterManager->convertAttributeValue($attributefilter[ 'attr_def' ], $req["filter"]);
            $issueManager->setValue($issue, $attributefilter, $valuefilter);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        return $issueId;
    }

    public static function runOpenvas($req, $targets)
    {
        $issueId = SecurityPluginCommon::commonScan($req);

        $issueManager = new System_Api_IssueManager();
        $typeManager = new System_Api_TypeManager();
        $formatterManager = new System_Api_Formatter();

        try {
            $issue = $issueManager->getIssue($issueId);

            $run_openvas = new TypeRunOpenvas();

            for ($i = 0; $i < count($targets); $i++) {
                if ($i == 0) {
                    $run_openvas->target = $targets[$i];
                } else {
                    $run_openvas->target = $run_openvas->target.",".$targets[$i];
                }
            }

            
            $run_openvas->id_scan = $issueId;
            $run_openvas->id_config = $req["id_config_openvas"];
            $run_openvas->id_scanner = $req["id_scanner_openvas"];

            ini_set('default_socket_timeout', 600);
            ini_set('soap.wsdl_cache_enabled', 0);
            $login = $GLOBALS['CONF_OPENVAS_WS_LOGIN'];
            $pwd = $GLOBALS['CONF_OPENVAS_WS_PASSWORD'];
            $credentials = array('login' => $login, 'password' => $pwd);
            $clientsoap = new SoapClient($GLOBALS['CONF_OPENVAS_WS_ENDPOINT']."?wsdl", $credentials);
            $clientsoap->__setLocation($GLOBALS['CONF_OPENVAS_WS_ENDPOINT']);
            $param = new SoapParam($run_openvas, 'tns:run_openvas');
            
            $result = $clientsoap->__call('run_openvas', array('run_openvas'=>$param));
            
            $id_target = $result->result_run_openvas_details->id_target;
            $id_task = $result->result_run_openvas_details->id_task;
            $id_report = $result->result_run_openvas_details->id_report;
            $id_alert = $result->result_run_openvas_details->id_alert;

            if (empty($id_target) || empty($id_task) || empty($id_report) || empty($id_alert)) {
                $issueManager->deleteIssue($issue);
                throw new SoapFault("Server", $GLOBALS['ERROR_OPENVAS']);
            }

            $attribute = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID']);
            $value = $formatterManager->convertAttributeValue($attribute[ 'attr_def' ], $id_target);
            $issueManager->setValue($issue, $attribute, $value);
            
            $attribute = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID']);
            $value = $formatterManager->convertAttributeValue($attribute[ 'attr_def' ], $id_task);
            $issueManager->setValue($issue, $attribute, $value);
            
            $attribute = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID']);
            $value = $formatterManager->convertAttributeValue($attribute[ 'attr_def' ], $id_report);
            $issueManager->setValue($issue, $attribute, $value);
            
            $attribute = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID']);
            $value = $formatterManager->convertAttributeValue($attribute[ 'attr_def' ], $id_alert);
            $issueManager->setValue($issue, $attribute, $value);

            $attributetime = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME']);
            $valuetime = $formatterManager->convertAttributeValue($attributetime[ 'attr_def' ], "in progress");
            $issueManager->setValue($issue, $attributetime, $valuetime);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
        }

        return $issueId;
    }

    public static function validCode($code)
    {
        if (!empty($code) && preg_match('/^[A-Za-z0-9_\-\:\/\.&?\=]*$/i', $code)) {
            return true;
        }

        return false;
    }

    public static function validUrl($url)
    {
        if (filter_var($url, FILTER_VALIDATE_URL) || filter_var($url, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return true;
        }

        return false;
    }

    public static function validIp($ip)
    {
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
        }

        return false;
    }

    public static function validRights($right)
    {
        switch ($right) {
            case "member":
                break;
            case "admin":
                break;
            default:
                return false;
        }

        return true;
    }

    public static function validTool($tool)
    {
        switch ($tool) {
            case "openvas":
                break;
            case "dependency-check":
                break;
            case "arachni":
                break;
            case "sslscan":
                break;
            case "zap":
                break;
            case "openscat":
                break;
            case "sonar":
                break;
            default:
                return false;
        }

        return true;
    }

    public static function validTime($time)
    {
        switch ($time) {
            case "stopped":
                break;
            case "in progress":
                break;
            case "finished":
                break;
            default:
                return false;
        }

        return true;
    }

    public static function validSeverity($severity)
    {
        switch ($severity) {
            case "info":
                break;
            case "minor":
                break;
            case "medium":
                break;
            case "high":
                break;
            default:
                return false;
        }

        return true;
    }

    public static function validUse($use)
    {
        switch ($use) {
            case "Development":
                break;
            case "Test":
                break;
            case "Production":
                break;
            default:
                return false;
        }

        return true;
    }

    public static function validName($name, $max = 150)
    {
        if (SecurityPluginCommon::validString($name) && strlen($name) > 1 && strlen($name) < $max) {
            return true;
        }

        return false;
    }

    public static function validString($string)
    {
        return is_string($string);
    }

    public static function validId($id)
    {
        if (SecurityPluginCommon::validInt($id)) {
            return true;
        }

        return false;
    }

    public static function validInt($int)
    {
        return is_int($int);
    }
}
