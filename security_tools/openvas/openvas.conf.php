<?php

// the login to request openvas.wsdl web services
$CONF_WS_OPENVAS_LOGIN = getenv("GVM_WS_USERNAME");
// the password to request openvas.wsdl web services
$CONF_WS_OPENVAS_PASSWORD = getenv("GVM_WS_PASSWORD");
// the administrator account created in webissues for openvas
$CONF_WEBISSUES_OPENVAS_LOGIN = getenv("OPENVAS_WEBISSUES_USERNAME");
// the password of the administrator account created in webissues for openvas
$CONF_WEBISSUES_OPENVAS_PASSWORD = getenv("OPENVAS_WEBISSUES_PASSWORD");
// the url of security-bugtracker webservices.php
$CONF_WEBISSUES_WS_ENDPOINT = "http://".getenv("SECURITYBUGTRACKER_HOST")."/client/webservices.php";
// the url of security-bugtracker openvas plugin
$CONF_OPENVAS_ALERT_URL = "http://localhost:1080/openvas.php";
// the openvas account to run scans
$CONF_OPENVAS_ADMIN_LOGIN = getenv("GVM_ADMIN_USERNAME");
// the password of the openvas account to run scans
$CONF_OPENVAS_ADMIN_PASSWORD = getenv("GVM_ADMIN_PASSWORD");
// the default config id of openvas after a fresh installation
$CONF_OPENVAS_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea";
// the default scanner id of openvas after a fresh installation
$CONF_OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73";
// the default port list id
$CONF_OPENVAS_PORTLIST_ID = "730ef368-57e2-11e1-a90f-406186ea4fc5";
// the path to the gvm-cli tool
$CONF_OPENVAS_PATH_OMP = "gvm-cli";
// default text to display when no cve is found associated to the vulnerability
$CONF_ISSUE_DEFAULT_CVENAME = "nocve";
// default text to display when no cwe is found associated to the vulnerability
$CONF_ISSUE_DEFAULT_CWENAME = "nocwe";
// the config id to generate pdf report in openvas
$CONF_OPENVAS_CONFIG_ID_PDF = "c402cc3e-b531-11e1-9163-406186ea4fc5";
// the config id to generate xml report in openvas
$CONF_OPENVAS_CONFIG_ID_XML = "a994b278-1f62-11e1-96ac-406186ea4fc5";
