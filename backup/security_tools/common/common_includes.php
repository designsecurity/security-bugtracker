<?php

include(__DIR__.'/dev/conf.php');
include(__DIR__.'/types/type_addcode.php');
include(__DIR__.'/types/type_addissue.php');
include(__DIR__.'/types/type_addproject.php');
include(__DIR__.'/types/type_addscan.php');
include(__DIR__.'/types/type_addserver.php');
include(__DIR__.'/types/type_addurl.php');
include(__DIR__.'/types/type_finishscan.php');
include(__DIR__.'/types/type_getcodes.php');
include(__DIR__.'/types/type_geturls.php');

ini_set('default_socket_timeout', 600);
ini_set('soap.wsdl_cache_enabled', 0); 
