<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

class SecurityPluginApi extends System_Api_Base
{
    private function authws()
    {
        $sessionManager = new System_Api_SessionManager();
        try {
            $sessionManager->login($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            return false;
        }

        return true;
    }

    public function adduser($req)
    {
        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validName($req["login"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["username"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["password"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        $userManager = new System_Api_UserManager();
        try {
            $id_user = $userManager->addUser($req["login"], $req["username"], $req["password"], false, null, '', "en");
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_user' => $id_user,
                     )
                );

        return $tab;
    }

    // Gestion des droits bon choix de test
    public function getparamsfromalertid($req)
    {
        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_alert"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $typeManager = new System_Api_TypeManager();
        $projectManager = new System_Api_ProjectManager();
        $issueManager = new System_Api_IssueManager();
        $userManager = new System_Api_UserManager();

        try {
            $issuescan = $issueManager->getIssue($req["id_alert"]);
            $project = $projectManager->getProject($issuescan["project_id"]);
            $id_folder_bugs = 0;
            $folders = $projectManager->getFoldersForProject($project);
            foreach ($folders as $folder) {
                if ($folder["type_id"] == $GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']) { // 2 = TYPE_ID BUGS
                    $id_folder_bugs = $folder["folder_id"];
                    break;
                }
            }

            if ($id_folder_bugs == 0) {
                throw new SoapFault("Server", $GLOBALS['UNKNOWN_ALERT']);
            }

            $attributes = $issueManager->getAllAttributeValuesForIssue($issuescan);
            foreach ($attributes as $attribute) {
                switch ($attribute["attr_id"]) {
                    case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY']:
                        $severity = $attribute["attr_value"];
                        break;
                    case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID']:
                        $targetid = $attribute["attr_value"];
                        break;
                    case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID']:
                        $taskid = $attribute["attr_value"];
                        break;
                    case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID']:
                        $reportid = $attribute["attr_value"];
                        break;
                    case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID']:
                        $alertid = $attribute["attr_value"];
                        break;
                    default:
                        break;
                }
            }

            switch ($severity) {
                case 'info':
                    $severity = 1;
                    break;
                case 'minor':
                    $severity = 1;
                    break;
                case 'medium':
                    $severity = 2;
                    break;
                case 'high':
                    $severity = 3;
                    break;
                default:
                    $severity = 1;
                    break;
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_folder_bugs' => $id_folder_bugs,
                    'id_target' => $targetid,
                    'id_task' => $taskid,
                    'id_report' => $reportid,
                    'id_alert' => $alertid,
                    'severity' => $severity
                     )
                );

        return $tab;
    }

    public function finishscan($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_scan"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $typeManager = new System_Api_TypeManager();

        $issuescan = $issueManager->getIssue($req["id_scan"]);
        if (!empty($req["data_report"])) {
            $path = "./reports_tmp/html_report_".$req["id_scan"].".html";
            file_put_contents($path, urldecode($req["data_report"]));
            $size = filesize($path);
            $attachment = System_Core_Attachment::fromFile($path, $size, "report.html");
            $issueManager->addFile($issuescan, $attachment, "report.html", "html_report");
            unlink($path);
        }

        try {
            $formatterManager = new System_Api_Formatter();
            
            $attributetime = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME']);
            $valuetime = $formatterManager->convertAttributeValue($attributetime["attr_def"], "finished");
            $issueManager->setValue($issuescan, $attributetime, $valuetime);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function addscan($req)
    {

        $req = (array) $req;
            
        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validTool($req["tool"])) {
            throw new SoapFault("Server", $GLOBALS['UNKNOWN_TOOL']);
        }

        if (!SecurityPluginCommon::validSeverity($req["filter"])) {
            throw new SoapFault("Server", $GLOBALS['UNKNOWN_SEVERITY']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_scans"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        $folder = $projectManager->getFolder($req["id_folder_scans"]);

        $duplicate = false;
        $issues = SecurityPluginCommon::getIssues($folder);
        foreach ($issues as $issue) {
            if ($issue["issue_name"] == $req["name"]) {
                $duplicate = true;
                break;
            }
        }

        if ($duplicate) {
            throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
        }

        switch ($req["tool"]) {
            case "openvas":
                $targetsweb = SecurityPluginCommon::findTargets($req, "web");
                $targetsservers = SecurityPluginCommon::findTargets($req, "servers");
                $targets = array_merge($targetsweb, $targetsservers);
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                var_dump($targetsweb);
                var_dump($targetsservers);
                var_dump($targets);
                $issueId = SecurityPluginCommon::runOpenvas($req, $targets);
                break;
            case "dependency-check":
                $targets = SecurityPluginCommon::findTargets($req, "static");
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                $issueId = SecurityPluginCommon::runDependencycheck($req, $targets);
                break;
            case "arachni":
                $targets = SecurityPluginCommon::findTargets($req, "web");
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                $issueId = SecurityPluginCommon::runArachni($req, $targets);
                break;
            case "sslscan":
                $targets = SecurityPluginCommon::findTargets($req, "web");
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                $issueId = SecurityPluginCommon::runSslscan($req, $targets);
                break;
            case "zap":
                $targets = SecurityPluginCommon::findTargets($req, "web");
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                $issueId = SecurityPluginCommon::runZap($req, $targets);
                break;
            case "openscat":
                $targets = SecurityPluginCommon::findTargets($req, "static");
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                //SecurityPluginCommon::run_openscat();
                break;
            case "sonar":
                $targets = SecurityPluginCommon::findTargets($req, "static");
                
                if (count($targets) == 0) {
                    throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
                }
                
                $issueId = SecurityPluginCommon::runSonar($req, $targets);
                break;
        }

        $tab = array(
                array(
                    'id_scan' => $issueId
                     )
                );

        return $tab;
    }

    public function deletescan($req)
    {
        $req = (array) $req;
        $req["id_issue"] = $req["id_scan"];
        $tab = $this->deleteissue($req);
        return $tab;
    }

    public function deleteserver($req)
    {
        $req = (array) $req;
        $req["id_issue"] = $req["id_server"];
        $tab = $this->deleteissue($req);
        return $tab;
    }

    public function deletecode($req)
    {
        $req = (array) $req;
        $req["id_issue"] = $req["id_code"];
        $tab = $this->deleteissue($req);
        return $tab;
    }

    public function deleteurl($req)
    {

        $req = (array) $req;
        $req["id_issue"] = $req["id_url"];
        $tab = $this->deleteissue($req);
        return $tab;
    }

    public function deleteissue($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_issue"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        try {
            $issueManager = new System_Api_IssueManager();
            $issue = $issueManager->getIssue($req["id_issue"]);
            try {
                $desc = $issueManager->getDescription($issue);
                $issueManager->deleteDescription($descr);
            } catch (System_Api_Error $ex_description) {
            }
            
            $issueManager->deleteIssue($issue);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function addurl($req)
    {
        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_web"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validUrl($req["url"])) {
            throw new SoapFault("Server", $GLOBALS['URL_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            $folder = $projectManager->getFolder($req["id_folder_web"]);

            $duplicate = false;
            $issues = SecurityPluginCommon::getIssues($folder);
            foreach ($issues as $issue) {
                if ($issue["issue_name"] == $req["name"]) {
                    $duplicate = true;
                    break;
                }
            }

            if ($duplicate) {
                throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
            }

            $formatterManager = new System_Api_Formatter();

            $issueId = $issueManager->addIssue($folder, $req["name"], null);
            $issue = $issueManager->getIssue($issueId);
            $issueManager->addDescription($issue, $req["description"], System_Const::TextWithMarkup);

            $attributeurl = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL']);
            $valuetime = $formatterManager->convertAttributeValue($attributeurl["attr_def"], $req["url"]);
            $issueManager->setValue($issue, $attributeurl, $value);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_url' => $issueId
                     )
                );

        return $tab;
    }

    public function editurl($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_url"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_web"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validUrl($req["url"])) {
            throw new SoapFault("Server", $GLOBALS['URL_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();
        $formatterManager = new System_Api_Formatter();

        try {
            $folder = $projectManager->getFolder($req["id_folder_web"]);
            $url = $issueManager->getIssue($req["id_url"]);
            $issueManager->moveIssue($url, $folder);
            $issueManager->renameIssue($url, $req["name"]);
            
            try {
                $desc = $issueManager->getDescription($url);
                $issueManager->editDescription($desc, $req["description"], System_Const::TextWithMarkup);
            } catch (System_Api_Error $ex_description) {
                $issueManager->addDescription($url, $req["description"], System_Const::TextWithMarkup);
            }

            $attributeurl = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL']);
            $valuetime = $formatterManager->convertAttributeValue($attributeurl["attr_def"], $req["url"]);
            $issueManager->setValue($url, $attributeurl, $valuetime);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }


    public function geturls($req)
    {

        $req = (array) $req;
        $result_array = array();

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_web"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            $folder = $projectManager->getFolder($req["id_folder_web"]);
            $urls = SecurityPluginCommon::getIssues($folder);

            foreach ($urls as $url) {
                $url = $issueManager->getIssue($url["issue_id"]);

                $attr_value = "";
                $attributes = $issueManager->getAllAttributeValuesForIssue($url);
                foreach ($attributes as $attribute) {
                    if ($attribute["attr_id"] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL']) {
                        $attr_value = $attribute["attr_value"];
                        break;
                    }
                }

                $arr = array(
                        'id_url' => $url["issue_id"],
                        'name' => $url["issue_name"],
                        'url' => $attr_value
                        );

                array_push($result_array, $arr);
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        if (!count($result_array)) {
            throw new SoapFault("Server", $GLOBALS['UNKNOWN_URL']);
        }

        return $result_array;
    }

    public function addcode($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_codes"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            if (!SecurityPluginCommon::validCode($req["code"])) {
                throw new SoapFault("Server", $GLOBALS['CODES_FILTER_INVALID']);
            }

            $folder = $projectManager->getFolder($req["id_folder_codes"]);

            $duplicate = false;
            $issues = SecurityPluginCommon::getIssues($folder);
            foreach ($issues as $issue) {
                if ($issue["issue_name"] == $req["name"]) {
                    $duplicate = true;
                    break;
                }
            }

            if ($duplicate) {
                throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
            }

            $formatterManager = new System_Api_Formatter();

            $issueId = $issueManager->addIssue($folder, $req["name"], null);
            $issue = $issueManager->getIssue($issueId);
            $issueManager->addDescription($issue, $req["description"], System_Const::TextWithMarkup);

            $attributecode = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH']);
            $value = $formatterManager->convertAttributeValue($attributecode["attr_def"], $req["code"]);
            $issueManager->setValue($issue, $attributecode, $value);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_code' => $issueId
                     )
                );

        return $tab;
    }

    public function editcode($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_codes"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_code"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            if (!SecurityPluginCommon::validCode($req["code"])) {
                throw new SoapFault("Server", $GLOBALS['CODES_FILTER_INVALID']);
            }

            $folder = $projectManager->getFolder($req["id_folder_codes"]);
            $code = $issueManager->getIssue($req["id_code"]);
            $issueManager->moveIssue($code, $folder);
            $issueManager->renameIssue($code, $req["name"]);
            
            try {
                $desc = $issueManager->getDescription($code);
                $issueManager->editDescription($desc, $req["description"], System_Const::TextWithMarkup);
            } catch (System_Api_Error $ex_description) {
                $issueManager->addDescription($code, $req["description"], System_Const::TextWithMarkup);
            }

            $formatterManager = new System_Api_Formatter();
            
            $attributecode = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH']);
            $value = $formatterManager->convertAttributeValue($attributecode["attr_def"], $req["code"]);
            $issueManager->setValue($code, $attributecode, $value);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function getcodes($req)
    {

        $req = (array) $req;
        $result_array = array();

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_codes"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            $folder = $projectManager->getFolder($req["id_folder_codes"]);
            $codes = SecurityPluginCommon::getIssues($folder);

            foreach ($codes as $code) {
                $code = $issueManager->getIssue($code["issue_id"]);

                $attr_value = "";
                $attributes = $issueManager->getAllAttributeValuesForIssue($code);
                foreach ($attributes as $attribute) {
                    if ($attribute["attr_id"] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH']) {
                        $attr_value = $attribute["attr_value"];
                        break;
                    }
                }

                $arr = array(
                        'id_code' => $code["issue_id"],
                        'name' => $code["issue_name"],
                        'code' => $attr_value
                        );

                array_push($result_array, $arr);
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        if (!count($result_array)) {
            throw new SoapFault("Server", $GLOBALS['UNKNOWN_CODE']);
        }

        return $result_array;
    }

    public function addserver($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_servers"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["hostname"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validUse($req["use"])) {
            throw new SoapFault("Server", $GLOBALS['USE_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            $ips = explode($GLOBALS['CONF_SERVER_IPS_EXPLODE'], $req["ipsaddress"]);
            foreach ($ips as $ip) {
                if (!SecurityPluginCommon::validIp($ip)) {
                    SecurityPluginCommon::logp($ip." doesn't match the filter");
                    throw new SoapFault("Server", $GLOBALS['IPS_FILTER_INVALID']);
                }
            }

            $folder = $projectManager->getFolder($req["id_folder_servers"]);

            $duplicate = false;
            $issues = SecurityPluginCommon::getIssues($folder);
            
            foreach ($issues as $issue) {
                if ($issue["issue_name"] == $req["hostname"]) {
                    $duplicate = true;
                    break;
                }
            }

            if ($duplicate) {
                throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
            }

            $formatterManager = new System_Api_Formatter();
      
            $issueId = $issueManager->addIssue($folder, $req["hostname"], null);
            $issue = $issueManager->getIssue($issueId);
            $issueManager->addDescription($issue, $req["description"], System_Const::TextWithMarkup);

            $attributeuse = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE']);
            $value = $formatterManager->convertAttributeValue($attributeuse["attr_def"], $req["use"]);
            $issueManager->setValue($issue, $attributeuse, $value);

            $attributeip = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS']);
            $value = $formatterManager->convertAttributeValue($attributeip["attr_def"], $req["ipsaddress"]);
            $issueManager->setValue($issue, $attributeip, $value);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_server' => $issueId
                     )
                );

        return $tab;
    }

    public function getserverfromname($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_servers"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["hostname"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();

        try {
            $folder = $projectManager->getFolder($req["id_folder_servers"]);
            $issues = SecurityPluginCommon::getIssues($folder);
            $find = false;

            foreach ($issues as $issue) {
                if ($issue["issue_name"] == $req["hostname"]) {
                    $find = true;
                    break;
                }
            }

            if (!$find) {
                throw new SoapFault("Server", $GLOBALS['UNKNOWN_SERVER']);
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_server' => $issue["issue_id"]
                     )
                );

        return $tab;
    }

    public function editserver($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_servers"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_server"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["hostname"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validUse($req["use"])) {
            throw new SoapFault("Server", $GLOBALS['USE_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();

        try {
            $ips = explode($GLOBALS['CONF_SERVER_IPS_EXPLODE'], $req["ipsaddress"]);
            foreach ($ips as $ip) {
                if (!SecurityPluginCommon::validIp($ip)) {
                    SecurityPluginCommon::logp($ip." doesn't match the filter");
                    throw new SoapFault("Server", $GLOBALS['IPS_FILTER_INVALID']);
                }
            }

            $folder = $projectManager->getFolder($req["id_folder_servers"]);
            $server = $issueManager->getIssue($req["id_server"]);
            $issueManager->moveIssue($server, $folder);
            $issueManager->renameIssue($server, $req["hostname"]);
            
            try {
                $desc = $issueManager->getDescription($server);
                $issueManager->editDescription($desc, $req["description"], System_Const::TextWithMarkup);
            } catch (System_Api_Error $ex_description) {
                $issueManager->addDescription($server, $req["description"], System_Const::TextWithMarkup);
            }

            $formatterManager = new System_Api_Formatter();
            
            $attributeuse = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE']);
            $value = $formatterManager->convertAttributeValue($attributeuse["attr_def"], $req["use"]);
            $issueManager->setValue($server, $attributeuse, $value);
            
            $attributeips = $typeManager->getAttributeType($GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS']);
            $value = $formatterManager->convertAttributeValue($attributeips["attr_def"], $req["ipsaddress"]);
            $issueManager->setValue($server, $attributeips, $value);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function addissue($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_bugs"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();
        $typeManager = new System_Api_TypeManager();
        $userManager = new System_Api_UserManager();
        $formatterManager = new System_Api_Formatter();

        try {
            $name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']] = "target";
            $name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']] = "cve";
            $name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE']] = "cwe";
            $duplicate = false;

            $folder = $projectManager->getFolder($req["id_folder_bugs"]);
            $type = $typeManager->getIssueTypeForFolder($folder);
            $rows = $typeManager->getAttributeTypesForIssueType($type);
            $issues = SecurityPluginCommon::getIssues($folder);

            foreach ($issues as $issue) {
                $issue["type_id"] = $GLOBALS['CONF_ID_TYPE_FOLDER_BUGS'];

                $attribute_target = null;
                $same_cve = false;
                $same_name = false;

                $issueduplicate = $issueManager->getIssue($issue["issue_id"]);
                $rowsvalues = $issueManager->getAllAttributeValuesForIssue($issue, 1);

                if (strtolower($issue["issue_name"]) == strtolower($req["name"])) {
                    $same_name = true;
                }

                $req["cve"] = strtolower($req["cve"]);
                $req["cwe"] = strtolower($req["cwe"]);

                foreach ($rowsvalues as $attribute) {
                    if (!empty($req["cve"])
                      && $req["cve"] != strtolower($GLOBALS['CONF_ISSUE_DEFAULT_CVENAME'])
                        && strtolower($attribute[ 'attr_value' ]) == $req["cve"]
                          && $attribute[ 'attr_id' ] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']) {
                        $same_cve = true;
                    }

                    if ($attribute[ 'attr_id' ] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']) {
                        $attribute_target = $attribute;
                    }
                }

                if ($same_name || $same_cve) {
                    // target is already vulnerable, just ping
                    if (strpos($attribute_target[ 'attr_value' ], $req["target"]) !== false) {
                        // htmlentities
                        $comment = $GLOBALS['PING_TARGET1']." ".$req["target"]." ".$GLOBALS['PING_TARGET2'];
                        $issueManager->addComment($issueduplicate, $comment, System_Const::TextWithMarkup);
                    } else {
                        // target is new, add the target and ping
                        $comment = $GLOBALS['PING_NEWTARGET1']." ".$req["target"]." ".$GLOBALS['PING_NEWTARGET2'];
                        $issueManager->addComment($issueduplicate, $comment, System_Const::TextWithMarkup);

                        if ($attribute_target != null) {
                            $attribute_target[ 'attr_value' ] = $attribute_target[ 'attr_value' ]."\n".$req["target"];
                            $value = $formatterManager->convertAttributeValue(
                                $attribute_target[ 'attr_def' ],
                                $attribute_target[ 'attr_value' ]
                            );
                            $issueManager->setValue($issueduplicate, $attribute_target, $value);
                            
                            $description = $issueManager->getDescription($issueduplicate);
                            $newdescription = $description["descr_text"]."\n\n".$req["description"];
                            $issueManager->editDescription(
                                $issueduplicate,
                                $newdescription,
                                System_Const::TextWithMarkup
                            );
                        }
                    }

                    $issueId = $issue["issue_id"];
                    $duplicate = true;
                    break;
                }
            }

            if ($duplicate) {
                throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
            }

            $issueId = $issueManager->addIssue($folder, $req["name"], null);
            $issue = $issueManager->getIssue($issueId);
            $issueManager->addDescription($issue, $req["description"], System_Const::TextWithMarkup);

            if (empty($req["assigned"])) {
                $admin = null;
                $members = $userManager->getMembers($folder);
                foreach ($members as $member) {
                    if ($member["project_access"] == System_Const::AdministratorAccess) {
                        $admin = $member;
                        $user = $userManager->getUser($admin["user_id"]);
                        $req["assigned"] = $user["user_name"];
                        break;
                    }
                }
            }

            foreach ($rows as $attribute) {
                $avalue = $req[$name_ws[$attribute["attr_id"]]];
                $value = $formatterManager->convertAttributeValue($attribute[ 'attr_def' ], $avalue);
                $issueManager->setValue($issue, $attribute, $value);
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_issue' => $issueId
                     )
                );

        return $tab;
    }

    // verifier la duplication (cve, name, target) aussi lors de l'édition
    public function editissue($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_issue"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_folder_bugs"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        $issueManager = new System_Api_IssueManager();
        $projectManager = new System_Api_ProjectManager();

        try {
            $folder = $projectManager->getFolder($req["id_folder_bugs"]);
            $issue = $issueManager->getIssue($req["id_issue"]);
            $issueManager->moveIssue($issue, $folder);
            $issueManager->renameIssue($issue, $req["name"]);
            
            try {
                $desc = $issueManager->getDescription($issue);
                $issueManager->editDescription($desc, $req["description"], System_Const::TextWithMarkup);
            } catch (System_Api_Error $ex_description) {
                $issueManager->addDescription($issue, $req["description"], System_Const::TextWithMarkup);
            }
            
            $rows = $issueManager->getAllAttributeValuesForIssue($issue);
            $formatterManager = new System_Api_Formatter();

            $name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']] = "target";
            $name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']] = "cve";
            $name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE']] = "cwe";

            foreach ($rows as $idattribute => $attribute) {
                $avalue = $req[$name_ws[$attribute["attr_id"]]];
                $value = $formatterManager->convertAttributeValue($attribute[ 'attr_def' ], $avalue);
                $issueManager->setValue($issue, $attribute, $value);
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function addmember($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validRights($req["access"])) {
            throw new SoapFault("Server", $GLOBALS['ACCESS_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_user"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_project"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $projectManager = new System_Api_ProjectManager();
        $userManager = new System_Api_UserManager();

        switch ($req["access"]) {
            case "member":
                $req["access"] = System_Const::NormalAccess;
                break;
            case "admin":
                $req["access"] = System_Const::AdministratorAccess;
                break;
            default:
                $req["access"] = System_Const::NormalAccess;
                break;
        }

        try {
            // check before if user exist and throw an exception if not
            $user = $userManager->getUser($req["id_user"]);
            $project = $projectManager->getProject($req["id_project"]);
            $userManager->grantMember($user, $project, $req["access"]);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function deletemember($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_user"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validId($req["id_project"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        $projectManager = new System_Api_ProjectManager();
        $userManager = new System_Api_UserManager();

        try {
            $user = $userManager->getUser($req["id_user"]);
            $project = $projectManager->getProject($req["id_project"]);
            $userManager->grantMember($user, $project, System_Const::NoAccess);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function deleteproject($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_project"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        try {
            $projectManager = new System_Api_ProjectManager();
            $issueManager = new System_Api_IssueManager();

            $project = $projectManager->getProject($req["id_project"]);
            $folders = $projectManager->getFoldersForProject($project);

            foreach ($folders as $folder) {
                $issues = SecurityPluginCommon::getIssues($folder);
                foreach ($issues as $issue) {
                    $desc = $issueManager->getDescription($issue);
                    $issueManager->deleteIssue($issue);
                    $issueManager->deleteDescription($descr);
                }

                $projectManager->deleteFolder($folder);
            }

            try {
                $desc = $projectManager->getProjectDescription($project);
            } catch (System_Api_Error $ex) {
            }
      
            $projectManager->deleteProjectDescription($descr);
            //$projectManager->deleteProject( $project, System_Api_ProjectManager::ForceDelete );
            $projectManager->deleteProject($project);
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function getproject($req)
    {
        $req = (array) $req;

        
            SecurityPluginCommon::logp("here0");
        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        try {
            $project = SecurityPluginCommon::getProjectByName($req["name"]);
        } catch (System_Db_Exception $ex) {
            throw new SoapFault("Server", "System_Db_Exception $ex");
        }
        
            SecurityPluginCommon::logp("here1".$req["name"]);
            SecurityPluginCommon::logp("here1project".print_r($project, true));
        $projectManager = new System_Api_ProjectManager();
        
        $id_project = -1;
        $id_folder_bugs = -1;
        $id_folder_servers = -1;
        $id_folder_codes = -1;
        $id_folder_web = -1;
        $id_folder_scans = -1;
        
            SecurityPluginCommon::logp("here2");
        try {
            $folders = $projectManager->getFoldersForProject($project);
        } catch (System_Api_Error $ex) {
            throw new SoapFault("Server", "System_Api_Error $ex");
        }
            SecurityPluginCommon::logp("here2après".print_r($folders, true));
        foreach ($folders as $folder) {
            SecurityPluginCommon::logp("here2 folder");
            if ($folder["type_id"] === $GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']) {
                $id_folder_bugs = $folder["folder_id"];
            } elseif ($folder["type_id"] === $GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS']) {
                $id_folder_servers = $folder["folder_id"];
            } elseif ($folder["type_id"] === $GLOBALS['CONF_ID_TYPE_FOLDER_CODES']) {
                $id_folder_codes = $folder["folder_id"];
            } elseif ($folder["type_id"] === $GLOBALS['CONF_ID_TYPE_FOLDER_WEB']) {
                $id_folder_web = $folder["folder_id"];
            } elseif ($folder["type_id"] === $GLOBALS['CONF_ID_TYPE_FOLDER_SCANS']) {
                $id_folder_scans = $folder["folder_id"];
            }
        }
          
            SecurityPluginCommon::logp("here2");
        $tab = array(
            array(
              'id_project' => $project["project_id"],
              'id_folder_bugs' => $id_folder_bugs,
              'id_folder_servers' => $id_folder_servers,
              'id_folder_codes' => $id_folder_codes,
              'id_folder_web' => $id_folder_web,
              'id_folder_scans' => $id_folder_scans
            )
        );
        
        return $tab;
    }

    public function editproject($req)
    {

        $req = (array) $req;

        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validId($req["id_project"])) {
            throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);
        }

        if (!SecurityPluginCommon::validName($req["name"])) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

        try {
            // check before if the project already exist and throw an exception if not
            $projectManager = new System_Api_ProjectManager();
            $project = $projectManager->getProject($req["id_project"]);
            $projectManager->renameProject($project, $req["name"]);
            try {
                $desc = $projectManager->getProjectDescription($project);
            } catch (System_Api_Error $ex) {
                if ($req["description"] != '') {
                    $projectManager->addProjectDescription($project, $req["description"], System_Const::TextWithMarkup);
                }
            }

            if ($req["description"] != '') {
                $projectManager->editProjectDescription($desc, $req["description"], System_Const::TextWithMarkup);
            }
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'result' => true
                     )
                );

        return $tab;
    }

    public function addproject($req)
    {

        $req = (array) $req;

            SecurityPluginCommon::logp("tata1");
        if (!$this->authws()) {
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
        }

        if (!SecurityPluginCommon::validName($req["name"], 40)) {
            throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);
        }

            SecurityPluginCommon::logp("tata2");
        try {
            SecurityPluginCommon::logp("tata2bis1");
            // check before if the project already exist and throw an exception if is
            $typeManager = new System_Api_TypeManager();
            $projectManager = new System_Api_ProjectManager();
            SecurityPluginCommon::logp("tata2bis2");
            $type = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']); // Id bugs
            SecurityPluginCommon::logp("tata2bis3");
            $projectId = $projectManager->addProject($req["name"]);
            SecurityPluginCommon::logp("tata2bis4");
            $project = $projectManager->getProject($projectId);
            SecurityPluginCommon::logp("tata2bis5");

            SecurityPluginCommon::logp("tata3");
            if ($req["description"] != '') {
                $projectManager->addProjectDescription($project, $req["description"], System_Const::TextWithMarkup);
            }

            SecurityPluginCommon::logp("tata4");
            $type_folder_servers = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS']);
            $type_folder_codes = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_CODES']);
            $type_folder_web = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_WEB']);
            $type_folder_scans = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_SCANS']);

            $folderId1 = $projectManager->addFolder($project, $type, "Bugs");
            $folderId2 = $projectManager->addFolder($project, $type_folder_servers, "Servers");
            $folderId3 = $projectManager->addFolder($project, $type_folder_codes, "Codes");
            $folderId4 = $projectManager->addFolder($project, $type_folder_web, "Web");
            $folderId5 = $projectManager->addFolder($project, $type_folder_scans, "Scans");
        } catch (System_Api_Error $ex) {
            SecurityPluginCommon::logp($ex);
            throw new SoapFault("Server", "System_Api_Error $ex");
        }

        $tab = array(
                array(
                    'id_project' => $projectId,
                    'id_folder_bugs' => $folderId1,
                    'id_folder_servers' => $folderId2,
                    'id_folder_codes' => $folderId3,
                    'id_folder_web' => $folderId4,
                    'id_folder_scans' => $folderId5
                     )
                );

        return $tab;
    }
}
