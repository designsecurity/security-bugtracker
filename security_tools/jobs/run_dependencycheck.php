<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include( 'common.php' ); 

$credentials = array('login' => $CONF_WEBISSUES_DCHECK_LOGIN, 'password' => $CONF_WEBISSUES_DCHECK_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_codes();

$addscan = new type_addscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_dependency-check_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_dependency-check_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "dependency-check";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

if($result)
{
	$id_scan = $result->result_addscan_details->id_scan;

	$getcodes = new type_getcodes();
	$getcodes->id_folder_codes = $CONF_WEBISSUES_FOLDER_CODES;
	$param = new SoapParam($getcodes, 'tns:type_getcodes');
	$results = $clientsoap->__call('getcodes', array('type_getcodes'=>$param));

	if($results)
	{
		if(isset($results->result_getcodes_details) && count($results->result_getcodes_details) > 1)
			$results = $results->result_getcodes_details;

		foreach($results as $resultcode)
		{
			$id_code = $resultcode->id_code;
			$name = $resultcode->name;
			$code = $resultcode->code;

			$out = shell_exec("$CONF_DEPENDENCYCHECK_BIN --app temp --format XML --scan $code --out $code/dependency-check-report.xml"); 
			$outputxml = file_get_contents("$code/dependency-check-report.xml");
			$out = shell_exec("rm $code/dependency-check-report.xml");

			if(!empty($outputxml))
			{
				$report = new SimpleXMLElement($outputxml);
				if(isset($report->dependencies->dependency))
				{
					foreach ($report->dependencies->dependency as $dependency) 
					{
						if(isset($dependency->fileName))
						{
							if(isset($dependency->vulnerabilities))
							{
								$lastthreat = 0;
								$description = "";
								foreach($dependency->vulnerabilities->vulnerability as $vulnerability)
								{
									switch($vulnerability->severity)
									{
										case 'Log':$threat = 1;break;
										case 'Low':$threat = 1;break;
										case 'Medium':$threat = 2;break;
										case 'High':$threat = 3;break;
										default:$threat = 1;break; 
									}

									if($threat > $lastthreat)
										$lastthreat = $threat;

									if($threat >= $GLOBAL_SEVERITY)
										$description = $vulnerability->name."\n".$vulnerability->description."\n\n";
								}

								if($lastthreat >= $GLOBAL_SEVERITY)
								{
									$description = "vulnerable target : $code\n\n".$description;
									$addissue = new type_addissue();
									$addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
									$addissue->name = "known vulnerabilities in ".$dependency->fileName;
									$addissue->description = $description;
									$addissue->assigned = "";
									$addissue->state = "Actif";
									$addissue->severity = $lastthreat;

									$param = new SoapParam($addissue, 'tns:addissue');
									$result = $clientsoap->__call('addissue',array('addissue'=>$param));
								}
							}
						}
					}
				}
			}
		}

		$finishscan = new type_finishscan();
		$finishscan->id_scan = $id_scan;

		$param = new SoapParam($finishscan, 'tns:finishscan');
		$result = $clientsoap->__call('finishscan',array('finishscan'=>$param));
	}
}

?>
