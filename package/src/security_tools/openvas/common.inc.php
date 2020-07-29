<?php

namespace securitybugtracker\Tools\Openvas;

function logpp($ex)
{
    $fp = fopen("openvas.log", "a+");
    fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
    fclose($fp);
}
