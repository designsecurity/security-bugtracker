<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


include('common.php');

$credentials = array('login' => $CONF_WEBISSUES_SSLSCAN_LOGIN, 'password' => $CONF_WEBISSUES_SSLSCAN_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_urls();

$addscan = new TypeAddscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_sslscan_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_sslscan__".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "sslscan";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

// https://www.openssl.org/news/vulnerabilities.html

if ($result) {
    $id_scan = $result->result_addscan_details->id_scan;

    $geturls = new TypeGeturls();
    $geturls->id_folder_web = $CONF_WEBISSUES_FOLDER_WEB;
    $param = new SoapParam($geturls, 'tns:type_geturls');
    $results = $clientsoap->__call('geturls', array('type_geturls'=>$param));

    if ($results) {
        if (isset($results->result_geturls_details) && count($results->result_geturls_details) > 1) {
            $results = $results->result_geturls_details;
        }

        foreach ($results as $resulturl) {
            $id_url = $resulturl->id_url;
            $name = $resulturl->name;
            $url = $resulturl->url;
            $url = chop($url);

            $outputjson = shell_exec("$CONF_SSLSCAN_BIN $url");
            //$outputjson = file_get_contents("test.json"); // local

            if (!empty($outputjson)) {
                $parsed_json = json_decode($outputjson);

                if (isset($parsed_json[0]->{'host'})) {
                    if (isset($parsed_json[0]->{'endpoints'}[0])) {
                        $details = $parsed_json[0]->{'endpoints'}[0]->{'details'};
                        if (isset($details->{'vulnBeast'}) && $details->{'vulnBeast'}) {
                            // purely client side vulnerability:
                            // https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat
                            // CVE-2011-3389, CVSS : 4.3 MEDIUM
                            $threat = 2; // medium
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "Beast Vulnerability";
                                $addissue->description = "Beast Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2011-3389";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
                        }

                        if (isset($details->{'drownVulnerable'}) && $details->{'drownVulnerable'}) {
                            // it allows both TLS and SSLv2 : https://drownattack.com/
                            // CVE-2016-0800, CVSS : 5.9 Medium
                            $threat = 2; // Medium
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "Drown Vulnerability";
                                $addissue->description = "Drown Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2016-0800";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
                        }

                        if (isset($details->{'logjam'}) && $details->{'logjam'}) {
                            // The Logjam attack allows a man-in-the-middle attacker
                            // to downgrade vulnerable TLS connections to 512-bit export-grade cryptography.
                            // flaw in the TLS protocol rather than an implementation vulnerability
                            // Disable Export Cipher Suites
                            // openssl s_client -connect www.example.com:443 -cipher 'EXP'
                            // https://weakdh.org/sysadmin.html
                            // CVE-2015-4000, CVSS : 3.7 Low
                            $threat = 1;
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "Logjam Vulnerability";
                                $addissue->description = "Logjam Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2015-4000";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
                        }

                        if (isset($details->{'freak'}) && $details->{'freak'}) {
                            // Disable Export Cipher Suites
                            // https://censys.io/blog/freak
                            // CVE-2015-0204, CVSS :  4.3 MEDIUM
                            $threat = 2;
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "Freak Vulnerability";
                                $addissue->description = "Freak Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2015-0204";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
                        }

                        if (isset($details->{'poodle'}) && $details->{'poodle'}) {
                            // The SSL protocol 3.0, as used in OpenSSL through 1.0.1i
                            // and other products, uses nondeterministic CBC padding,
                            // which makes it easier for man-in-the-middle attackers
                            // to obtain cleartext data via a padding-oracle attack, aka the "POODLE" issue.
                            // Pour atténuer cette vulnérabilité, désactivez SSL 3.0 en forçant l’utilisation de TLS
                            // openssl s_client -connect mon_site:443 -ssl3
                            // CVE-2014-3566, CVSS : 3.1 Low

                            $threat = 1;
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "Poodle Vulnerability";
                                $addissue->description = "Poodle Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2014-3566";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
                        }

                        if (isset($details->{'openSslCcs'}) && $details->{'openSslCcs'}) {
                            // OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
                            // does not properly restrict processing of ChangeCipherSpec
                            // messages, which allows man-in-the-middle attackers
                            // to trigger use of a zero-length master key
                            // in certain OpenSSL-to-OpenSSL communications,
                            // and consequently hijack sessions or obtain sensitive information
                            // via a crafted TLS handshake, aka the "CCS Injection" vulnerability.
                            // CVE-2014-0224, CVSS : 6.8 MEDIUM

                            $threat = 2;
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "CCS Injection Vulnerability";
                                $addissue->description = "CCS Injection Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2014-0224";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
                        }

                        if (isset($details->{'heartbleed'}) && $details->{'heartbleed'}) {
                            // http://heartbleed.com/
                            // CVE-2014-0160, CVSS :  7.5 high

                            $threat = 3;
                            if ($threat >= $GLOBAL_SEVERITY) {
                                $addissue = new TypeAddissue();
                                $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
                                $addissue->name = "Heartbleed Vulnerability";
                                $addissue->description = "Heartbleed Vulnerability\n\n".$parsed_json[0]->{'host'};
                                $addissue->assigned = "";
                                $addissue->state = "Actif";
                                $addissue->target = $parsed_json[0]->{'host'};
                                $addissue->cve = "CVE-2014-0160";
                                $addissue->cwe = "";
                                $addissue->severity = $threat;

                                $param = new SoapParam($addissue, 'tns:addissue');
                                $result = $clientsoap->__call('addissue', array('addissue'=>$param));
                            }
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
