<?php

// default directory to look for to put scans, issues etc
$CONF_WEBISSUES_FOLDER_SCANS = 5;
$CONF_WEBISSUES_FOLDER_BUGS = 1;
$CONF_WEBISSUES_FOLDER_WEB = 4;
$CONF_WEBISSUES_FOLDER_CODES = 3;
$CONF_WEBISSUES_FOLDER_SERVERS = 2;

// OpenVas
$CONF_WEBISSUES_OPENVAS_LOGIN = "openvas";
$CONF_WEBISSUES_OPENVAS_PASSWORD = "openvas";

// SonarQube
$CONF_WEBISSUES_SONAR_LOGIN = "sonar";
$CONF_WEBISSUES_SONAR_PASSWORD = "sonar";
$CONF_SONARQUBE_ADDRESS = 'http://localhost:9000/api/issues/search?componentKeys=';

// DependencyCheck
$CONF_WEBISSUES_DCHECK_LOGIN = "dependency-check";
$CONF_WEBISSUES_DCHECK_PASSWORD = "dependency-check";
$CONF_DEPENDENCYCHECK_BIN = '/home/eric/dev/TMP/DependencyCheck/cli/target/release/bin/dependency-check.sh';

// Arachni
$CONF_WEBISSUES_ARACHNI_LOGIN = "arachni";
$CONF_WEBISSUES_ARACHNI_PASSWORD = "arachni";
$CONF_ARACHNI_BIN = '/home/eric/dev/TMP/arachni/bin/arachni';
$CONF_ARACHNI_REPORT_BIN = '/home/eric/dev/TMP/arachni/bin/arachni_reporter';

// Zap
$CONF_WEBISSUES_ZAP_LOGIN = "zap";
$CONF_WEBISSUES_ZAP_PASSWORD = "zap";
$CONF_ZAP_PROXY_ADDRESS = 'tcp://localhost:8080';
$CONF_ZAP_API_KEY = 's1s4659fs4qduib9hohcj03iie';

// Sslscan
$CONF_WEBISSUES_SSLSCAN_LOGIN = "sslscan";
$CONF_WEBISSUES_SSLSCAN_PASSWORD = "sslscan";
$CONF_SSLSCAN_BIN = '/home/eric/dev/TMP/ssllabs-scan/ssllabs-scan-v3';

// 2 = medium;
$GLOBAL_SEVERITY = 2;

$ASSETS_CODES_NAMES = "./data/codes_names.txt";
$ASSETS_CODES_PATHS = "./data/codes_paths.txt";
$ASSETS_SERVERS_PROJECTS = "./data/servers_projects.txt";
$ASSETS_SERVERS_HOSTNAMES = "./data/servers_hostnames.txt";
$ASSETS_SERVERS_IPS = "./data/servers_ips.txt";
$ASSETS_WEB_COOKIES = "./data/web_cookies.txt";
$ASSETS_WEB_NAMES = "./data/web_names.txt";
$ASSETS_WEB_URLS = "./data/web_urls.txt";

$CONF_WEBISSUES_WS_ENDPOINT = "http://localhost:81/webissues/client/webservices.php";
$CONF_WEBISSUES_IP_SEPARATOR = ',';
$CONF_FILE_IP_SEPARATOR = '|';

$CONF_SUBLIST3R_BIN = 'python3 /home/eric/dev/perso/Sublist3r/sublist3r.py';
