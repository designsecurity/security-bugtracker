<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include( 'openvas.conf.php' ); 
include( '../../securityplugin.conf.php' );

class type_finishscan
{
	public $id_scan;
	public $data_report;
}

class type_getparamsfromalertid
{
	public $id_alert;
}

class type_addissue
{
	public $id_folder_bugs;
	public $name;
	public $description;
	public $assigned;
	public $state;
	public $severity;
	public $version;
	public $target;
}	

function logpp($ex)
{
	$fp = fopen("openvas.log","a+");
	fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
	fclose($fp);
}

if(isset($_GET["alertscanid"]))
$alertscanid = (int) $_GET["alertscanid"];

if(!empty($alertscanid))
{
	$getparamsfromalertid = new type_getparamsfromalertid();
	$getparamsfromalertid->id_alert = $alertscanid;

	$credentials = array('login' => $GLOBALS['CONF_WEBISSUES_OPENVAS_LOGIN'], 'password' => $GLOBALS['CONF_WEBISSUES_OPENVAS_PASSWORD']);

	try 
	{
		ini_set('default_socket_timeout', 10000);
		ini_set('soap.wsdl_cache_enabled', 0);
		$clientsoap = new SoapClient($GLOBALS['CONF_WEBISSUES_WS_ENDPOINT']."?wsdl", $credentials);
		$param = new SoapParam($getparamsfromalertid, 'tns:getparamsfromalertid');
		$result = $clientsoap->__call('getparamsfromalertid',array('getparamsfromalertid'=>$param));
	} 
	catch (SoapFault $e) {
		logpp($e->getMessage());
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

	$outputxml = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." --get-report ".$id_report." --format a994b278-1f62-11e1-96ac-406186ea4fc5 -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']);      
	$outputhtml = urlencode(shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." --get-report ".$id_report." --format ".$GLOBALS['CONF_OPENVAS_CONFIG_ID_HTML']."  -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']));      

	$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<delete_target target_id=\"".$id_target."\"/>'");
	$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<delete_alert alert_id=\"".$id_alert."\"/>'");
	$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<delete_task task_id=\"".$id_task."\"/>'");
	$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<delete_report report_id=\"".$id_report."\"/>'");

	if(!empty($outputxml))
	{
		$report = new SimpleXMLElement($outputxml);
		if(isset($report->report->results->result))
		{
			foreach ($report->report->results->result as $result) {
				if(isset($result->threat))
				{
					switch($result->threat)
					{
						case 'Log':$threat = 1;break;
						case 'Low':$threat = 1;break;
						case 'Medium':$threat = 2;break;
						case 'High':$threat = 3;break;
						default:$threat = 1;break; 
					}
				}

				if($threat >= $severity)
				{
					$target = $result->host.":".$result->port;
					$description = "vulnerable target : $target \n\n".$result->description;

					$addissue = new type_addissue();
					$addissue->id_folder_bugs = $id_folder_bugs;
					$addissue->name = $result->name;
					$addissue->description = $description;
					$addissue->assigned = "";
					$addissue->state = "Actif";
					$addissue->severity = $threat;
					$addissue->version = 1;
					$addissue->target = $result->host;
					$addissue->cve = $CONF_ISSUE_DEFAULT_CVENAME;
					if(isset($result->cve) && !empty($result->cve) && $result->cve != "NOCVE")
						$addissue->cve = $result->cve;
					$addissue->cwe = $CONF_ISSUE_DEFAULT_CWENAME;

					try 
					{
						$param = new SoapParam($addissue, 'tns:addissue');
						$result = $clientsoap->__call('addissue',array('addissue'=>$param));
						sleep(1);
					} 
					catch (SoapFault $e) 
					{
						logpp($e->getMessage());
					} 
				}
			}
		}
	}

	$finishscan = new type_finishscan();
	$finishscan->id_scan = $alertscanid;
	$finishscan->data_report = $outputhtml;

	try 
	{
		$param = new SoapParam($finishscan, 'tns:finishscan');
		$result = $clientsoap->__call('finishscan',array('finishscan'=>$param));
	} 
	catch (SoapFault $e) 
	{
		logpp($e->getMessage());
	} 
}

class openvas_webservice_server
{
	function logp($ex)
	{
		$fp = fopen("openvas.log","a+");
		fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
		fclose($fp);
	}

	function authws()
	{
		if(!($_SERVER['PHP_AUTH_USER'] == $GLOBALS['CONF_WS_OPENVAS_LOGIN'] && $_SERVER['PHP_AUTH_PW'] == $GLOBALS['CONF_WS_OPENVAS_PASSWORD']))
		{
			$this->logp( "authentification failed ");
			return false;
		}

		return true;
	}

	function run_openvas($req){

		if($this->authws())
		{
			$req = (array) $req;
			//vérifier validiter
			$issueId = $req["id_scan"];

			$targetid = '';
			$taskid = '';
			$reportid = '';
			$alertid = '';

			$configId = $GLOBALS['CONF_OPENVAS_CONFIG_ID'];
			if(isset($req["id_config"]) && !empty($req["id_config"]))
				$configId = $req["id_config"];
			$this->logp("run_openvas configid = ".$configId);

			$cmd = "".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<create_target><name>webissue".$issueId."</name><hosts>".$req["target"]."</hosts></create_target>'";
			$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<create_target><name>webissue".$issueId."</name><hosts>".$req["target"]."</hosts></create_target>'");
			preg_match('|<create_target_response id=\"([^"]*)\"|', $output, $matches);
			if(isset($matches[1]))
				$targetid = $matches[1];
			else
				$this->logp("error $cmd create target = ".$output);

			if(!empty($targetid))
			{
				$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<create_alert><name>webissue".$issueId."</name><condition>Always</condition><event>Task run status changed<data>Done<name>status</name></data></event><method>HTTP Get<data><name>URL</name>".$GLOBALS['CONF_OPENVAS_ALERT_URL']."?alertscanid=".$issueId."</data></method></create_alert>'");
				preg_match('|<create_alert_response id=\"([^"]*)\"|', $output, $matches);
				if(isset($matches[1]))
					$alertid = $matches[1];
				else
					$this->logp("error create alert = ".$output);
			} 

			if(!empty($alertid))
			{
				$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<create_task><name>webissue".$issueId."</name><comment>test</comment><config id=\"".$configId."\"/><target id=\"".$targetid."\"/><alert id=\"".$alertid."\"/></create_task>'");
				preg_match('|<create_task_response id=\"([^"]*)\"|', $output, $matches);
				if(isset($matches[1]))
					$taskid = $matches[1];
				else
					$this->logp("error create task = ".$output);
			}

			if(!empty($taskid))
			{
				$output = shell_exec ("".$GLOBALS['CONF_OPENVAS_PATH_OMP']." -u ".$GLOBALS['CONF_OPENVAS_ADMIN_LOGIN']." -w ".$GLOBALS['CONF_OPENVAS_ADMIN_PASSWORD']." -p ".$GLOBALS['CONF_OPENVAS_PORT_OMP']." --xml='<start_task task_id=\"".$taskid."\"/>'");
				preg_match('@<report_id>(.*)</report_id>.*@i', $output, $matches);
				if(isset($matches[1]))
					$reportid = $matches[1];
				else
					$this->logp("error create report = ".$output);
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
