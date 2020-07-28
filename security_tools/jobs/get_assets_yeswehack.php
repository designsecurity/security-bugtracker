<?php

include( 'common.php' ); 


$programs = json_decode(file_get_contents("https://api.yeswehack.com/programs?page=1"));

$fp1 = fopen(__DIR__."/".$GLOBALS["ASSETS_SERVERS_PROJECTS"], "w");
$fp2 = fopen(__DIR__."/".$GLOBALS["ASSETS_SERVERS_HOSTNAMES"], "w");
$fp3 = fopen(__DIR__."/".$GLOBALS["ASSETS_SERVERS_IPS"], "w");

if($fp1 == false || $fp2 == false || $fp3 == false) {
  echo "can't open '".$GLOBALS["ASSETS_SERVERS_HOSTNAMES"]."' or '".$GLOBALS["ASSETS_SERVERS_IPS"]."' or '".$GLOBALS["ASSETS_SERVERS_PROJECTS"]."'\n";
}
else {
  if(isset($programs->items)) {
    foreach($programs->items as $program)
    {
      echo $program->slug . "\n";
      $programContent = json_decode(file_get_contents("https://api.yeswehack.com/programs/".$program->slug));

      if(isset($programContent->scopes)) {
        foreach($programContent->scopes as $scope)
        {
          if(strpos($scope->scope_type, "mobile") == false) {
          
            $host = null;
            $ip = null;
            
            if(filter_var($scope->scope, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
              $host = $scope->scope;
              $ip = gethostbyname($scope->scope);
            }
            else if(filter_var($scope->scope, FILTER_VALIDATE_URL)) {
              $url = parse_url($scope->scope);
              
              if(isset($url["host"])) {
                $host = $url["host"];
                $ip = gethostbyname($host);
              }
            }
            else if(filter_var($scope->scope, FILTER_VALIDATE_IP)) {
              $host = $scope->scope;
              $ip = $scope->scope;
            }
            
            if(filter_var($ip, FILTER_VALIDATE_IP) && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            
            echo "program slug:".$program->slug."\n";
            
              if(strpos($host, "github.com") !== false || strpos($host, "apps.apple.com") !== false || strpos($host, "play.google.com") !== false) {
                fwrite($fp1, $program->slug."\n");
                fwrite($fp2, $scope->scope."\n");
                fwrite($fp3, $ip."\n");
              }
            }
            else {
              echo "can't find host or ip for scope: ".$scope->scope." (host=$host, ip=$ip) \n";
            }
          }
        } 
      } 
    }
  }

  fclose($fp1);
  fclose($fp2);
  fclose($fp3);
}
