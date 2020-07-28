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

class type_run_openvas
{
	public $target;
	public $id_config;
	public $id_scan;
}

class Common_SecurityPlugin
{

  public static function getIssues( $folder )
  {
    $folderId = $folder["folder_id"];
    $query = 'SELECT i.issue_name, i.issue_id, f.type_id, i.folder_id FROM {issues}  AS i JOIN {folders} AS f ON f.folder_id = i.folder_id JOIN {projects} AS p ON p.project_id = f.project_id JOIN {issue_types} AS t ON t.type_id = f.type_id WHERE i.folder_id = %d';
            
    $connection = System_Core_Application::getInstance()->getConnection();
    return $connection->queryTable( $query, $folderId );
  }
    
	public static function logp($ex)
	{
		$fp = fopen("webservices.log","a+");
		fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
		fclose($fp);
	}

	public static function run_dependencycheck($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_arachni($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_sonar($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_zap($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_sslscan($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function find_targets($req, $type)
	{
		$targets = array();

		try
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();

			$id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS'];
			$id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'];
			if($type == "static")
			{
				$id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_CODES'];
				$id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'];
			}
			else if($type == "web")
			{
				$id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_WEB'];
				$id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'];
			}

			$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
			$project = $projectManager->getProject( $folderscan[ 'project_id' ] );

			$id_folder_targets = 0;
			$folders = $projectManager->getFoldersForProject( $project );
			foreach ( $folders as $folder ) 
			{
				if($folder["type_id"] == $id_type)
				{
					$id_folder_targets = $folder["folder_id"];
					break;
				}
			}

			if($id_folder_targets > 0)
			{
				$nbtargets = 0;
				$foldertargets = $projectManager->getFolder( $id_folder_targets );
				$targets = Common_SecurityPlugin::getIssues($foldertargets);
				foreach ( $targets as $target ) {
					$attributes = $issueManager->getAllAttributeValuesForIssue( $target );
					foreach ( $attributes as $idattribute => $attribute ) {
						if($attribute["attr_id"] == $id_attribute)
						{
							$targets[$nbtargets] = $attribute["attr_value"];
							$nbtargets ++;
						}
					}
				}
			}
		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			//throw new SoapFault("Server", "System_Api_Error $ex");
		}

		if(count($targets) == 0)
			throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);

		return $targets;
	}

	public static function common_scan($req)
	{
		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();
		$formatterManager = new System_Api_Formatter();
      
		try {
			if(empty($req["time"]))
				$req["time"] = "stopped";

			$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
			$issueId = $issueManager->addIssue( $folderscan, $req["name"], null);
			$issue = $issueManager->getIssue( $issueId );
			$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );
			
			$attributetime = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME'] );
			$valuetime = $formatterManager->convertAttributeValue( $attributetime[ 'attr_def' ], $req["time"] );

			$attributetool = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL'] );
			$valuetool = $formatterManager->convertAttributeValue( $attributetool[ 'attr_def' ], $req["tool"] );

			$attributeseve = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY'] );
			$valueseve = $formatterManager->convertAttributeValue( $attributeseve[ 'attr_def' ], $req["filter"] );

			$issueManager->setValue( $issue, $attributetime, $valuetime );
			$issueManager->setValue( $issue, $attributetool, $valuetool );
			$issueManager->setValue( $issue, $attributeseve, $valueseve );
		}
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		return $issueId;
	}

	public static function run_openvas($req, $targets)
	{
		$issueId = Common_SecurityPlugin::common_scan($req);

		$issueManager = new System_Api_IssueManager();
		$typeManager = new System_Api_TypeManager();
		$formatterManager = new System_Api_Formatter();

		try
		{
			$issue = $issueManager->getIssue( $issueId );

			$run_openvas = new type_run_openvas();

			for($i = 0; $i < count($targets); $i++)
			{
				if($i == 0)
					$run_openvas->target = $targets[$i];
				else
					$run_openvas->target = $run_openvas->target.",".$targets[$i];
			}

			
			$run_openvas->id_scan = $issueId;
			$run_openvas->id_config = $req["id_config_openvas"];

			ini_set('default_socket_timeout', 600);
			ini_set('soap.wsdl_cache_enabled', 0);
			$credentials = array('login' => $GLOBALS['CONF_OPENVAS_WS_LOGIN'], 'password' => $GLOBALS['CONF_OPENVAS_WS_PASSWORD']);
			$clientsoap = new SoapClient($GLOBALS['CONF_OPENVAS_WS_ENDPOINT']."?wsdl", $credentials);
			$clientsoap->__setLocation($GLOBALS['CONF_OPENVAS_WS_ENDPOINT']);
			$param = new SoapParam($run_openvas, 'tns:run_openvas');
			$result = $clientsoap->__call('run_openvas',array('run_openvas'=>$param));

			$id_target = $result->result_run_openvas_details->id_target;
			$id_task = $result->result_run_openvas_details->id_task;
			$id_report = $result->result_run_openvas_details->id_report;
			$id_alert = $result->result_run_openvas_details->id_alert;      

			if(empty($id_target) || empty($id_task) || empty($id_report) || empty($id_alert))
			{
				$issueManager->deleteIssue( $issue );
				throw new SoapFault("Server", $GLOBALS['ERROR_OPENVAS']);
			}

			$attribute = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID']);
			$value = $formatterManager->convertAttributeValue( $attribute[ 'attr_def' ], $id_target );
			$issueManager->setValue( $issue, $attribute, $value);
			
			$attribute = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID']);
			$value = $formatterManager->convertAttributeValue( $attribute[ 'attr_def' ], $id_task );
			$issueManager->setValue( $issue, $attribute, $value );
			
			$attribute = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID']);
			$value = $formatterManager->convertAttributeValue( $attribute[ 'attr_def' ], $id_report );
			$issueManager->setValue( $issue, $attribute, $value );
			
			$attribute = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID']);
			$value = $formatterManager->convertAttributeValue( $attribute[ 'attr_def' ], $id_alert );
			$issueManager->setValue( $issue, $attribute, $value );

			$attributetime = $typeManager->getAttributeType( $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME']);
			$valuetime = $formatterManager->convertAttributeValue( $attributetime[ 'attr_def' ], "in progress" );
			$issueManager->setValue( $issue, $attributetime, $valuetime );
		}
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
		}

		return $issueId;
	}

	public static function valid_code($code)
	{
		if(!empty($code) && preg_match('/^[A-Za-z0-9_\-\:\/\.&?\=]*$/i', $code))
			return true;

		return false;
	}

	public static function valid_url($url)
	{
		if(filter_var($url, FILTER_VALIDATE_URL))
			return true;

		return false;
	}

	public static function valid_ip($ip)
	{
		if(filter_var($ip, FILTER_VALIDATE_IP))
			return true;

		return false;
	}

	public static function valid_rights($right)
	{
		switch($right)
		{
			case "member": break;
			case "admin": break;
			default: return false;
		}

		return true;
	}

	public static function valid_tool($tool)
	{
		switch($tool)
		{
			case "openvas": break;
			case "dependency-check": break;
			case "arachni": break;
			case "sslscan": break;
			case "zap": break;
			case "openscat": break;
			case "sonar": break;
			default: return false;
		}

		return true;
	}

	public static function valid_time($time)
	{
		switch($time)
		{
			case "stopped": break;
			case "in progress": break;
			case "finished": break;
			default: return false;
		}

		return true;
	}

	public static function valid_severity($severity)
	{
		switch($severity)
		{
			case "info": break;
			case "minor": break;
			case "medium": break;
			case "high": break;
			default: return false;
		}

		return true;
	}

	public static function valid_use($use)
	{
		switch($use)
		{
			case "Development": break;
			case "Test": break;
			case "Production": break;
			default: return false;
		}

		return true;
	}

	public static function valid_name($name, $max = 150)
	{
		if(Common_SecurityPlugin::valid_string($name) && strlen($name) > 1 && strlen($name) < $max)
			return true;

		return false;
	}

	public static function valid_string($string)
	{
		return is_string($string);
	}

	public static function valid_id($id)
	{
		if(Common_SecurityPlugin::valid_int($id))
			return true;

		return false;
	}

	public static function valid_int($int)
	{
		return is_int($int);
	}
}

?>
