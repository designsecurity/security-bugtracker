<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


require_once( '../system/bootstrap.inc.php' );

include( 'securityplugin.conf.php' );
include( 'securityplugin.lang.php' );
include( 'securityplugin.common.php' );

class webservice_server
{
	function authws()
	{
		$sessionManager = new System_Api_SessionManager();
		try {
			$sessionManager->login( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			return false;
		}

		return true;
	}

	function adduser($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_name($req["login"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["username"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["password"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		$userManager = new System_Api_UserManager();
		try {
			$id_user = $userManager->addUser( $req["login"], $req["username"], $req["password"], false );
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
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
	function getparamsfromalertid($req)
	{
		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_alert"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$typeManager = new System_Api_TypeManager();
		$projectManager = new System_Api_ProjectManager();
		$issueManager = new System_Api_IssueManager();
		$userManager = new System_Api_UserManager();

		try {
			$issuescan = $issueManager->getIssue( $req["id_alert"] );
			$project = $projectManager->getProject( $issuescan["project_id"] );
			$id_folder_bugs = 0;
			$projects[0] = $project;
			$folders = $projectManager->getFoldersForProjects( $projects );
			foreach ( $folders as $folder ) {
				if($folder["type_id"] == $GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']) // 2 = TYPE_ID BUGS
				{
					$id_folder_bugs = $folder["folder_id"];
					break;
				}
			}

			if($id_folder_bugs == 0)
				throw new SoapFault("Server", $GLOBALS['UNKNOWN_ALERT']);

			$attributes = $issueManager->getAttributeValuesForIssue( $issuescan );
			foreach ( $attributes as $attribute ) {
				switch($attribute["attr_id"])
				{
					case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY']: $severity = $attribute["attr_value"]; break;
					case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID']: $targetid = $attribute["attr_value"]; break;
					case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID']: $taskid = $attribute["attr_value"]; break;
					case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID']: $reportid = $attribute["attr_value"]; break;
					case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID']: $alertid = $attribute["attr_value"]; break;
					default: break;
				}
			}

			switch($severity)
			{
				case 'info':$severity = 1;break;
				case 'minor':$severity = 1;break;
				case 'medium':$severity = 2;break;
				case 'high':$severity = 3;break;
				default:$severity = 1;break;
			}
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
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

	function finishscan($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_scan"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$typeManager = new System_Api_TypeManager();

		$issuescan = $issueManager->getIssue( $req["id_scan"] );
		if(!empty($req["data_report"]))
		{
			$path = "./reports_tmp/html_report_".$req["id_scan"].".html";
			file_put_contents($path, urldecode($req["data_report"]));
			$size = filesize($path);
			$attachment = System_Core_Attachment::fromFile( $path, $size, "report.html" );
			$issueManager->addFile($issuescan, $attachment, "report.html", "html_report" );
			unlink($path);
		}

		try {

			$parser = new System_Api_Parser();
			$parser->setProjectId( $issuescan["project_id"] );

			$attributetime = $typeManager->getAttributeTypeForIssue( $issuescan, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME'] );
			$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], "finished" );
			$issueManager->setValue( $issuescan, $attributetime, $valuetime );
		}  
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function addscan($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_tool($req["tool"]))
			throw new SoapFault("Server", $GLOBALS['UNKNOWN_TOOL']);

		if(!Common_SecurityPlugin::valid_severity($req["filter"]))
			throw new SoapFault("Server", $GLOBALS['UNKNOWN_SEVERITY']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_scans"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		$folder = $projectManager->getFolder( $req["id_folder_scans"] );

		$duplicate = false;
		$issues = $issueManager->getIssues($folder);
		foreach ($issues as $issue) 
		{
			if($issue["issue_name"] == $req["name"]) 
			{
				$duplicate = true;
				break;
			}
		}

		if($duplicate)
			throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);

		switch($req["tool"])
		{
			case "openvas": 
				$targets = Common_SecurityPlugin::find_targets($req, "dynamic");
				$issueId = Common_SecurityPlugin::run_openvas($req, $targets);
				break;
			case "dependency-check": 
				$targets = Common_SecurityPlugin::find_targets($req, "static");
				$issueId = Common_SecurityPlugin::run_dependencycheck($req, $targets);
				break;
			case "arachni": 
				$targets = Common_SecurityPlugin::find_targets($req, "web");
				$issueId = Common_SecurityPlugin::run_arachni($req, $targets);
				break;
			case "sslscan": 
				$targets = Common_SecurityPlugin::find_targets($req, "web");
				$issueId = Common_SecurityPlugin::run_sslscan($req, $targets);
				break;
			case "zap": 
				$targets = Common_SecurityPlugin::find_targets($req, "web");
				$issueId = Common_SecurityPlugin::run_zap($req, $targets);
				break;
			case "openscat": 
				$targets = Common_SecurityPlugin::find_targets($req, "static");
				//Common_SecurityPlugin::run_openscat();
				break;
			case "sonar": 
				$targets = Common_SecurityPlugin::find_targets($req, "static");
				$issueId = Common_SecurityPlugin::run_sonar($req, $targets);
				break;
		}

		$tab = array(
				array(
					'id_scan' => $issueId
				     )
			    );       

		return $tab;
	}

	function deletescan($req){
		$req = (array) $req;
		$req["id_issue"] = $req["id_scan"];
		$tab = $this->deleteissue($req);
		return $tab;
	}

	function deleteserver($req){
		$req = (array) $req;
		$req["id_issue"] = $req["id_server"];
		$tab = $this->deleteissue($req);
		return $tab;
	}

	function deletecode($req){
		$req = (array) $req;
		$req["id_issue"] = $req["id_code"];
		$tab = $this->deleteissue($req);
		return $tab;
	}

	function deleteurl($req){

		$req = (array) $req;
		$req["id_issue"] = $req["id_url"];
		$tab = $this->deleteissue($req);
		return $tab;
	}

	function deleteissue($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_issue"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		try 
		{
			$issueManager = new System_Api_IssueManager();
			$issue = $issueManager->getIssue( $req["id_issue"] );
			$desc = $issueManager->getDescription( $issue );
			$issueManager->deleteIssue( $issue );
			$issueManager->deleteDescription( $descr );

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function addurl($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_web"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_url($req["url"]))
			throw new SoapFault("Server", $GLOBALS['URL_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {
			$folder = $projectManager->getFolder( $req["id_folder_web"] );

			$duplicate = false;
			$issues = $issueManager->getIssues($folder);
			foreach ($issues as $issue) {
				if($issue["issue_name"] == $req["name"]) 
				{
					$duplicate = true;
					break;
				}
			}

			if($duplicate)
				throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			$issueId = $issueManager->addIssue( $folder, $req["name"]);
			$issue = $issueManager->getIssue( $issueId );
			$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

			$attributeurl = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'] );
			$value = $parser->convertAttributeValue( $attributeurl[ 'attr_def' ], $req["url"] );
			$issueManager->setValue( $issue, $attributeurl, $value );

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'id_url' => $issueId
				     )
			    );

		return $tab;
	}

	function editurl($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_url"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_web"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_url($req["url"]))
			throw new SoapFault("Server", $GLOBALS['URL_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {
			$folder = $projectManager->getFolder( $req["id_folder_web"] );
			$url = $issueManager->getIssue( $req["id_url"] );
			$issueManager->moveIssue( $url, $folder );
			$issueManager->renameIssue( $url, $req["name"] );
			$desc = $issueManager->getDescription( $url );
			$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			$attributeurl = $typeManager->getAttributeTypeForIssue( $url, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'] );
			$value = $parser->convertAttributeValue( $attributeurl[ 'attr_def' ], $req["url"] );
			$issueManager->setValue( $url, $attributeurl, $value );
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}


	function geturls($req){

		$req = (array) $req;
		$result_array = array();

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_web"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try 
		{
			$folder = $projectManager->getFolder( $req["id_folder_web"] );
			$urls = $issueManager->getIssues( $folder );

			foreach($urls as $url)
			{
				$url = $issueManager->getIssue( $url["issue_id"] );

				$attr_value = "";
				$attributes = $issueManager->getAttributeValuesForIssue($url);
				foreach($attributes as $attribute)
				{
					if($attribute["attr_id"] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'])
					{
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
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		if(!count($result_array))
			throw new SoapFault("Server", $GLOBALS['UNKNOWN_URL']);

		return $result_array;
	}

	function addcode($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_codes"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {
			if(!Common_SecurityPlugin::valid_code($req["code"]))
				throw new SoapFault("Server", $GLOBALS['CODES_FILTER_INVALID']);

			$folder = $projectManager->getFolder( $req["id_folder_codes"] );

			$duplicate = false;
			$issues = $issueManager->getIssues($folder);
			foreach ($issues as $issue) {
				if($issue["issue_name"] == $req["name"]) 
				{
					$duplicate = true;
					break;
				}
			}

			if($duplicate)
				throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			$issueId = $issueManager->addIssue( $folder, $req["name"]);
			$issue = $issueManager->getIssue( $issueId );
			$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

			$attributecode = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'] );
			$value = $parser->convertAttributeValue( $attributecode[ 'attr_def' ], $req["code"] );
			$issueManager->setValue( $issue, $attributecode, $value );

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'id_code' => $issueId
				     )
			    );

		return $tab;
	}

	function editcode($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_codes"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_code"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {

			if(!Common_SecurityPlugin::valid_code($req["code"]))
				throw new SoapFault("Server", $GLOBALS['CODES_FILTER_INVALID']);

			$folder = $projectManager->getFolder( $req["id_folder_codes"] );
			$code = $issueManager->getIssue( $req["id_code"] );
			$issueManager->moveIssue( $code, $folder );
			$issueManager->renameIssue( $code, $req["name"] );
			$desc = $issueManager->getDescription( $code );
			$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			$attributecode = $typeManager->getAttributeTypeForIssue( $code, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'] );
			$value = $parser->convertAttributeValue( $attributecode[ 'attr_def' ], $req["code"] );
			$issueManager->setValue( $code, $attributecode, $value );
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function getcodes($req){

		$req = (array) $req;
		$result_array = array();

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_codes"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try 
		{
			Common_SecurityPlugin::logp( "GET CODES = ".$req["id_folder_codes"]  );

			$folder = $projectManager->getFolder( $req["id_folder_codes"] );
			$codes = $issueManager->getIssues( $folder );

			foreach($codes as $code)
			{
				$code = $issueManager->getIssue( $code["issue_id"] );

				$attr_value = "";
				$attributes = $issueManager->getAttributeValuesForIssue($code);
				foreach($attributes as $attribute)
				{
					if($attribute["attr_id"] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'])
					{
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
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		if(!count($result_array))
			throw new SoapFault("Server", $GLOBALS['UNKNOWN_CODE']);

		return $result_array;
	}


	function addserver($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_servers"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["hostname"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_use($req["use"]))
			throw new SoapFault("Server", $GLOBALS['USE_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {
			$ips = explode($GLOBALS['CONF_SERVER_IPS_EXPLODE'], $req["ipsaddress"]);
			foreach($ips as $ip)
			{
				if(!Common_SecurityPlugin::valid_ip($ip))
				{
					Common_SecurityPlugin::logp( $ip." doesn't match the filter" );
					throw new SoapFault("Server", $GLOBALS['IPS_FILTER_INVALID']);
				}
			}

			$folder = $projectManager->getFolder( $req["id_folder_servers"] );

			$duplicate = false;
			$issues = $issueManager->getIssues($folder);
			foreach ($issues as $issue) 
			{
				if($issue["issue_name"] == $req["hostname"]) 
				{
					$duplicate = true;
					break;
				}
			}

			if($duplicate)
				throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			$issueId = $issueManager->addIssue( $folder, $req["hostname"]);
			$issue = $issueManager->getIssue( $issueId );
			$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

			$attributeuse = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE'] );
			$value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
			$issueManager->setValue( $issue, $attributeuse, $value );

			$attributeips = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'] );
			$value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
			$issueManager->setValue( $issue, $attributeips, $value );


		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'id_server' => $issueId
				     )
			    );

		return $tab;
	}

	function getserverfromname($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_servers"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["hostname"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();

		try {
			$folder = $projectManager->getFolder( $req["id_folder_servers"] );
			$issues = $issueManager->getIssues($folder);
			$find = false;

			foreach ($issues as $issue) {
				if($issue["issue_name"] == $req["hostname"]) 
				{
					$find = true;
					break;
				}
			}

			if(!$find)
				throw new SoapFault("Server", $GLOBALS['UNKNOWN_SERVER']);


		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'id_server' => $issue["issue_id"]
				     )
			    );

		return $tab;
	}

	function editserver($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_servers"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_server"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["hostname"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_use($req["use"]))
			throw new SoapFault("Server", $GLOBALS['USE_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {
			$ips = explode($GLOBALS['CONF_SERVER_IPS_EXPLODE'], $req["ipsaddress"]);
			foreach($ips as $ip)
			{
				if(!Common_SecurityPlugin::valid_ip($ip))
				{
					Common_SecurityPlugin::logp( $ip." doesn't match the filter" );
					throw new SoapFault("Server", $GLOBALS['IPS_FILTER_INVALID']);
				}
			}

			$folder = $projectManager->getFolder( $req["id_folder_servers"] );
			$server = $issueManager->getIssue( $req["id_server"] );
			$issueManager->moveIssue( $server, $folder );
			$issueManager->renameIssue( $server, $req["hostname"] );
			$desc = $issueManager->getDescription( $server );
			$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			$attributeuse = $typeManager->getAttributeTypeForIssue( $server, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE'] );
			$value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
			$issueManager->setValue( $server, $attributeuse, $value );

			$attributeips = $typeManager->getAttributeTypeForIssue( $server, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'] );
			$value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
			$issueManager->setValue( $server, $attributeips, $value );

		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function addissue($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_bugs"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();
		$userManager = new System_Api_UserManager();

		try 
		{
			$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']] = "target";
			$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']] = "cve";
			$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE']] = "cwe";
			$duplicate = false;

			$folder = $projectManager->getFolder( $req["id_folder_bugs"] );
			$type = $typeManager->getIssueTypeForFolder( $folder );
			$rows = $typeManager->getAttributeTypesForIssueType( $type );
			$issues = $issueManager->getIssues($folder);

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folder[ 'project_id' ] );

			foreach ($issues as $issue) 
			{
				$issue["type_id"] = $GLOBALS['CONF_ID_TYPE_FOLDER_BUGS'];

				$attribute_target = null;
				$same_cve = false;
				$same_name = false;

				$issueduplicate = $issueManager->getIssue( $issue["issue_id"] );
				$rowsvalues = $issueManager->getAllAttributeValuesForIssue($issue, 1);

				if(strtolower($issue["issue_name"]) == strtolower($req["name"])) 
					$same_name = true;

				$req["cve"] = strtolower($req["cve"]);
				$req["cwe"] = strtolower($req["cwe"]);

				foreach ( $rowsvalues as $attribute ) 
				{
					if( !empty($req["cve"]) && $req["cve"] != strtolower($GLOBALS['CONF_ISSUE_DEFAULT_CVENAME']) && strtolower($attribute[ 'attr_value' ]) == $req["cve"] && $attribute[ 'attr_id' ] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE'])
						$same_cve = true;

					if( $attribute[ 'attr_id' ] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET'])
						$attribute_target = $attribute;
				}

				if($same_name || $same_cve)
				{
					// target is already vulnerable, just ping
					if(strpos($attribute_target[ 'attr_value' ], $req["target"]) !== false)
					{
						// htmlentities
						$issueManager->addComment( $issueduplicate, $GLOBALS['PING_TARGET1']." ".$req["target"]." ".$GLOBALS['PING_TARGET2'], System_Const::TextWithMarkup);
					}
					// target is new, add the target and ping
					else
					{
						$issueManager->addComment( $issueduplicate, $GLOBALS['PING_NEWTARGET1']." ".$req["target"]." ".$GLOBALS['PING_NEWTARGET2'], System_Const::TextWithMarkup);

						if($attribute_target != null)
						{
							$attribute_target[ 'attr_value' ] = $attribute_target[ 'attr_value' ]."\n".$req["target"];
							$value = $parser->convertAttributeValue( $attribute_target[ 'attr_def' ], $attribute_target[ 'attr_value' ] );
							$issueManager->setValue( $issueduplicate, $attribute_target, $value );
						}
					}

					$issueId = $issue["issue_id"];
					$duplicate = true;
					break;
				}
			}

			if($duplicate)
				throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);

			$issueId = $issueManager->addIssue( $folder, $req["name"]);
			$issue = $issueManager->getIssue( $issueId );
			$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

			if(empty($req["assigned"]))
			{
				$admin = null;
				$members = $userManager->getMembers($folder);
				foreach ($members as $member) {

					if($member["project_access"] == System_Const::AdministratorAccess)
					{
						$admin = $member;
						$user = $userManager->getUser($admin["user_id"]);
						$req["assigned"] = $user["user_name"];
						break;
					}
				}
			}

			foreach ( $rows as $attribute ) 
			{
				$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$attribute["attr_id"]]] );
				$issueManager->setValue( $issue, $attribute, $value );
			}
		} 
		catch ( System_Api_Error $ex ) 
		{
			Common_SecurityPlugin::logp( $ex );
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
	function editissue($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_issue"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_folder_bugs"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		$issueManager = new System_Api_IssueManager();

		try {

			$folder = $projectManager->getFolder( $req["id_folder_bugs"] );
			$issue = $issueManager->getIssue( $req["id_issue"] );
			$issueManager->moveIssue( $issue, $folder );
			$issueManager->renameIssue( $issue, $req["name"] );
			$desc = $issueManager->getDescription( $issue );
			$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );

			$rows = $issueManager->getAllAttributeValuesForIssue( $issue );
			$parser = new System_Api_Parser();
			$parser->setProjectId( $issue[ 'project_id' ] );

			$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']] = "target";
			$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']] = "cve";
			$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE']] = "cwe";

			foreach ( $rows as $idattribute => $attribute ) {
				$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$attribute["attr_id"]]] );
				$issueManager->setValue( $issue, $attribute, $value );
			}
		} 
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function addmember($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_rights($req["access"]))
			throw new SoapFault("Server", $GLOBALS['ACCESS_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_user"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_project"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$projectManager = new System_Api_ProjectManager();
		$userManager = new System_Api_UserManager();

		switch($req["access"])
		{
			case "member":$req["access"] = System_Const::NormalAccess; break;
			case "admin":$req["access"] = System_Const::AdministratorAccess; break;
			default:$req["access"] = System_Const::NormalAccess; break;
		}

		try 
		{
			// check before if user exist and throw an exception if not
			$user = $userManager->getUser( $req["id_user"] );
			$project = $projectManager->getProject( $req["id_project"] );
			$userManager->grantMember( $user, $project, $req["access"] );

		} 
		catch ( System_Api_Error $ex ) 
		{
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function deletemember($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_user"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_id($req["id_project"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		$projectManager = new System_Api_ProjectManager();
		$userManager = new System_Api_UserManager();

		try {
			$user = $userManager->getUser( $req["id_user"] );
			$project = $projectManager->getProject( $req["id_project"]);
			$userManager->grantMember( $user, $project, System_Const::NoAccess );

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function deleteproject($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_project"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		try {
			$projectManager = new System_Api_ProjectManager();
			$issueManager = new System_Api_IssueManager();

			$project = $projectManager->getProject( $req["id_project"] );
			$folders = $projectManager->getFoldersForProject( $project );

			foreach ( $folders as $folder )
			{
				$issues = $issueManager->getIssues( $folder );
				foreach ( $issues as $issue )
				{
					$desc = $issueManager->getDescription( $issue );
					$issueManager->deleteIssue( $issue );
					$issueManager->deleteDescription( $descr );
				}

				$projectManager->deleteFolder( $folder );
			}

			$desc = $projectManager->getProjectDescription( $project );
			$projectManager->deleteProjectDescription( $descr );
			//$projectManager->deleteProject( $project, System_Api_ProjectManager::ForceDelete );
			$projectManager->deleteProject( $project);

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function editproject($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_id($req["id_project"]))
			throw new SoapFault("Server", $GLOBALS['ID_FILTER_INVALID']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		try {
			// check before if the project already exist and throw an exception if not
			$projectManager = new System_Api_ProjectManager();
			$project = $projectManager->getProject( $req["id_project"]);
			$projectManager->renameProject( $project, $req["name"] );
			$desc = $projectManager->getProjectDescription( $project );

			if ( $req["description"] != '' ) {
				$projectManager->editProjectDescription( $desc, $req["description"], System_Const::TextWithMarkup);
			}

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		$tab = array(
				array(
					'result' => true
				     )
			    );

		return $tab;
	}

	function addproject($req){

		$req = (array) $req;

		if(!$this->authws())
			throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		if(!Common_SecurityPlugin::valid_name($req["name"]))
			throw new SoapFault("Server", $GLOBALS['NAME_FILTER_INVALID']);

		try {

			// check before if the project already exist and throw an exception if is
			$typeManager = new System_Api_TypeManager();
			$projectManager = new System_Api_ProjectManager();
			$type = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']); // Id bugs
			$projectId = $projectManager->addProject($req["name"]);
			$project = $projectManager->getProject( $projectId );

			if ( $req["description"] != '' ) {
				$projectManager->addProjectDescription( $project, $req["description"], System_Const::TextWithMarkup);
			}

			$type_folder_servers = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS'] );
			$type_folder_codes = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_CODES'] );
			$type_folder_web = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_WEB'] );
			$type_folder_scans = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_SCANS'] );

			$folderId1 = $projectManager->addFolder( $project, $type, "Bugs" );
			$folderId2 = $projectManager->addFolder( $project, $type_folder_servers, "Servers" );
			$folderId3 = $projectManager->addFolder( $project, $type_folder_codes, "Codes" );
			$folderId4 = $projectManager->addFolder( $project, $type_folder_web, "Web" );
			$folderId5 = $projectManager->addFolder( $project, $type_folder_scans, "Scans" );

		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
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

System_Bootstrap::run( 'System_Web_Service');

ini_set('soap.wsdl_cache_enabled', 0);
$serversoap=new SoapServer("webservices.wsdl");
$serversoap->setClass("webservice_server");
$serversoap->handle();



