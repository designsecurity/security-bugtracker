<?php

$CONF_WEBISSUES_SSLSCAN_LOGIN = "sslscan";
$CONF_WEBISSUES_SSLSCAN_PASSWORD = "sslscan";
$CONF_WEBISSUES_ARACHNI_LOGIN = "arachni";
$CONF_WEBISSUES_ARACHNI_PASSWORD = "arachni";
$CONF_WEBISSUES_DCHECK_LOGIN = "dependency-check";
$CONF_WEBISSUES_DCHECK_PASSWORD = "dependency-check";
$CONF_WEBISSUES_OPENVAS_LOGIN = "openvas";
$CONF_WEBISSUES_OPENVAS_PASSWORD = "openvas";
$CONF_WEBISSUES_ZAP_LOGIN = "zap";
$CONF_WEBISSUES_ZAP_PASSWORD = "zap";
$CONF_WEBISSUES_SONAR_LOGIN = "sonar";
$CONF_WEBISSUES_SONAR_PASSWORD = "sonar";

$CONF_WEBISSUES_FOLDER_SCANS = 10; 
$CONF_WEBISSUES_FOLDER_BUGS = 6; 
$CONF_WEBISSUES_FOLDER_WEB = 9; 
$CONF_WEBISSUES_FOLDER_CODES = 8;
$CONF_WEBISSUES_FOLDER_SERVERS = 7;

// 2 = medium;
$GLOBAL_SEVERITY = 2;

$ASSETS_CODES_NAMES = "./assets/codes_names.txt";
$ASSETS_CODES_PATHS = "./assets/codes_paths.txt";
$ASSETS_SERVERS_HOSTNAMES = "./assets/servers_hostnames.txt";
$ASSETS_SERVERS_IPS = "./assets/servers_ips.txt";
$ASSETS_WEB_COOKIES = "./assets/web_cookies.txt";
$ASSETS_WEB_NAMES = "./assets/web_names.txt";
$ASSETS_WEB_URLS = "./assets/web_urls.txt";

$CONF_WEBISSUES_WS_ENDPOINT = "http://localhost/security-bugtracker/webissues-server-1.1.4/client/webservices.php";
$CONF_WEBISSUES_IP_SEPARATOR = ',';
$CONF_FILE_IP_SEPARATOR = '|';

$CONF_SSLSCAN_BIN = '/home/eric/Téléchargements/ssllabs-scan/ssllabs-scan';
$CONF_ARACHNI_BIN = '/home/eric/arachni-2.0dev-1.0dev/bin/arachni';
$CONF_ARACHNI_REPORT_BIN = '/home/eric/arachni-2.0dev-1.0dev/bin/arachni_reporter';
$CONF_DEPENDENCYCHECK_BIN = '/usr/local/dependency-check/bin/dependency-check.sh';
$CONF_ZAP_PROXY_ADDRESS = 'tcp://localhost:8080';
$CONF_ZAP_API_KEY = 's1s4659fs4qduib9hohcj03iie';

?>
