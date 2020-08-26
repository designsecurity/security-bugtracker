<?php

// the login to request openvas.wsdl web services
$CONF_WS_OPENVAS_LOGIN = "test";
// the password to request openvas.wsdl web services
$CONF_WS_OPENVAS_PASSWORD = "test";
// the administrator account created in webissues for openvas
$CONF_WEBISSUES_OPENVAS_LOGIN = "openvas";
// the password of the administrator account created in webissues for openvas
$CONF_WEBISSUES_OPENVAS_PASSWORD = "openvas";
// the url of security-bugtracker webservices.php
$CONF_WEBISSUES_WS_ENDPOINT = "http://localhost:81/webissues/client/webservices.php";
// the url of security-bugtracker openvas plugin
$CONF_OPENVAS_ALERT_URL = "http://localhost:81/openvas-services/openvas.php";
// the openvas account to run scans
$CONF_OPENVAS_ADMIN_LOGIN = "gvmadmin";
// the password of the openvas account to run scans
$CONF_OPENVAS_ADMIN_PASSWORD = "gvmadmin";
// the default config id of openvas
$CONF_OPENVAS_CONFIG_ID = "74db13d6-7489-11df-91b9-002264764cea";
// the default scanner id of openvas
$CONF_OPENVAS_SCANNER_ID = "762632c8-61e5-4a37-9a90-2be9266c1146";
// the path to the gvm-cli tool
$CONF_OPENVAS_PATH_OMP = "/opt/gvm/.local/bin/gvm-cli";
// the port on which openvas run
$CONF_OPENVAS_PORT_OMP = "9393";
// default text to display when no cve is found associated to the vulnerability
$CONF_ISSUE_DEFAULT_CVENAME = "nocve";
// default text to display when no cwe is found associated to the vulnerability
$CONF_ISSUE_DEFAULT_CWENAME = "nocwe";
// the config id to generate pdf report in openvas
$CONF_OPENVAS_CONFIG_ID_PDF = "c402cc3e-b531-11e1-9163-406186ea4fc5";
// the config id to generate xml report in openvas
$CONF_OPENVAS_CONFIG_ID_XML = "a994b278-1f62-11e1-96ac-406186ea4fc5";
