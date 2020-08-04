<?php

include(__DIR__.'/config/dev.php');
include(__DIR__.'/types/TypeAddcode.php');
include(__DIR__.'/types/TypeAddissue.php');
include(__DIR__.'/types/TypeAddproject.php');
include(__DIR__.'/types/TypeAddscan.php');
include(__DIR__.'/types/TypeAddserver.php');
include(__DIR__.'/types/TypeAddurl.php');
include(__DIR__.'/types/TypeGetcodes.php');
include(__DIR__.'/types/TypeGeturls.php');
include(__DIR__.'/types/TypeGetproject.php');

ini_set('default_socket_timeout', 600);
ini_set('soap.wsdl_cache_enabled', 0);
