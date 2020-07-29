<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include('common.php');

$credentials = array('login' => $CONF_WEBISSUES_SONAR_LOGIN, 'password' => $CONF_WEBISSUES_SONAR_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_codes();

$addscan = new TypeAddscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_sonar_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_sonar_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "sonar";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

if ($result) {
    $id_scan = $result->result_addscan_details->id_scan;

    $getcodes = new TypeGetcodes();
    $getcodes->id_folder_codes = $CONF_WEBISSUES_FOLDER_CODES;
    $param = new SoapParam($getcodes, 'tns:type_getcodes');
    $results = $clientsoap->__call('getcodes', array('type_getcodes'=>$param));

    if ($results) {
        if (isset($results->result_getcodes_details) && count($results->result_getcodes_details) > 1) {
            $results = $results->result_getcodes_details;
        }

        foreach ($results as $resultcode) {
        /*
               $id_code = $resultcode->id_code;
               $name = $resultcode->name;
               $code = $resultcode->code;

               $out = shell_exec();
               $outputxml = file_get_contents("$code/dependency-check-report.xml");
               $out = shell_exec("rm $code/dependency-check-report.xml");
             */
        }
        //http://localhost:9000/api/issues/search?componentRoots=1:securitybugtracker
        $outputjson = file_get_contents("sonar.json");

        if (!empty($outputjson)) {
            $parsed_json = json_decode($outputjson);

            if (isset($parsed_json->{'issues'})) {
                $issues = $parsed_json->{'issues'};
                foreach ($issues as $issue) {
                    $name = $issue->{'message'};
                    $rule = $issue->{'rule'};

                    $threat = 0;
                    switch ($issue->{'severity'}) {
                        case 'INFO':
                            $threat = 1;
                            break;
                        case 'MINOR':
                            $threat = 1;
                            break;
                        case 'MAJOR':
                            $threat = 1;
                            break;
                        case 'CRITICAL':
                            $threat = 1;
                            break;
                        case 'BLOCKER':
                            $threat = 3;
                            break;
                        default:
                            $threat = 1;
                            break;
                    }

                    $target = $issue->{'component'};
                    if ($threat >= $GLOBAL_SEVERITY) {
                        $addissue = new TypeAddissue();
                        $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                        $addissue->name = $name;
                        $addissue->description = "$name\n\n$target";
                        $addissue->assigned = "";
                        $addissue->state = "Actif";
                        $addissue->target = $target;
                        $addissue->cve = "";
                        $addissue->cwe = "";
                        $addissue->severity = $threat;

                        try {
                            $param = new SoapParam($addissue, 'tns:addissue');
                            $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                        } catch (SoapFault $e) {
                            echo $e->getMessage()."\n";
                        }
                    }
                }
            }
        }

        $finishscan = new TypeFinishscan();
        $finishscan->id_scan = $id_scan;

        $param = new SoapParam($finishscan, 'tns:finishscan');
        $result = $clientsoap->__call('finishscan', array('finishscan'=>$param));
    }
}
