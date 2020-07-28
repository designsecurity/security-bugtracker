<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


require "/home/eric/dev/vendor/autoload.php";
include( 'common.php' ); 

$zap = new Zap\Zapv2($CONF_ZAP_PROXY_ADDRESS);

$version = @$zap->core->version();
if (is_null($version)) {
	echo "PHP API error\n";
	exit();
} else {
	echo "version: ${version}\n";
}

$credentials = array('login' => $CONF_WEBISSUES_ZAP_LOGIN, 'password' => $CONF_WEBISSUES_ZAP_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_urls();

$addscan = new type_addscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_zap_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_zap_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "zap";
$addscan->filter = "info";

try 
{
	$param = new SoapParam($addscan, 'tns:type_addscan');
	$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

	if($result)
	{
		$id_scan = $result->result_addscan_details->id_scan;

		$geturls = new type_geturls();
		$geturls->id_folder_web = $CONF_WEBISSUES_FOLDER_WEB;
		$param = new SoapParam($geturls, 'tns:type_geturls');
		$results = $clientsoap->__call('geturls', array('type_geturls'=>$param));

		if($results)
		{
			if(isset($results->result_geturls_details) && count($results->result_geturls_details) > 1)
				$results = $results->result_geturls_details;

			foreach($results as $resulturl)
			{
				$id_url = $resulturl->id_url;
				$name = $resulturl->name;
				$url = $resulturl->url;

				$url = chop($url);

				echo "Spidering target $url\n";
				// Response JSON looks like {"scan":"1"}
				$scan_id = $zap->spider->scan($url, null, null, null, $CONF_ZAP_API_KEY);
				$count = 0;
				while (true) 
				{
					if ($count > 10) exit();
					// Response JSON looks like {"status":"50"}
					$progress = intval($zap->spider->status($scan_id));
					printf("Spider progress %d\n", $progress);
					if ($progress >= 100) break;
					sleep(2);
					$count++;
				}

				echo "Spider completed\n";
				// Give the passive scanner a chance to finish
				sleep(5);

				echo "Scanning target ${url}\n";
				// Response JSON for error looks like {"code":"url_not_found", "message":"URL is not found"}
				$scan_id = $zap->ascan->scan($url, null, null, null, null, null, $CONF_ZAP_API_KEY);
				$count = 0;
				while (true) 
				{
					if ($count > 10) exit();
					$progress = intval($zap->ascan->status($scan_id));
					printf("Scan progress %d\n", $progress);
					if ($progress >= 100) break;
					sleep(2);
					$count++;
				}
				echo "Scan completed\n";

				$alerts = $zap->core->alerts($target, "", "");

				foreach($alerts as $alert)
				{
					$threat = 0;
					switch($alert["risk"])
					{
						case 'informational':$threat = 1;break;
						case 'Low':$threat = 1;break;
						case 'Medium':$threat = 2;break;
						case 'High':$threat = 3;break;
						default:$threat = 1;break; 
					}

					if($threat >= $severity)
					{
						$addissue = new type_addissue();
						$addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
						$addissue->name = $alert["name"];
						$addissue->description = $alert["description"]."\n\n".$alert["url"];
						$addissue->assigned = "";
						$addissue->state = "Actif";
						$addissue->severity = $threat;

						try 
						{
							$param = new SoapParam($addissue, 'tns:addissue');
							$result = $clientsoap->__call('addissue',array('addissue'=>$param));
						}
						catch (SoapFault $e) 
						{
							echo $e->getMessage()."\n";
						}
					}
				}
			}

			$finishscan = new type_finishscan();
			$finishscan->id_scan = $id_scan;

			try 
			{
				$param = new SoapParam($finishscan, 'tns:finishscan');
				$result = $clientsoap->__call('finishscan',array('finishscan'=>$param));
			}
			catch (SoapFault $e) 
			{
				echo $e->getMessage()."\n";
			}
		}
	}
}
catch (SoapFault $e) 
{
	echo $e->getMessage()."\n";
}

?>
