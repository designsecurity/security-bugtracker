<?php

include('common.php');
include('assets.api.php');

$programs = json_decode(file_get_contents("https://api.yeswehack.com/programs?page=1"));

$fp1 = fopen(__DIR__."/".$GLOBALS["ASSETS_SERVERS_PROJECTS"], "w");
$fp2 = fopen(__DIR__."/".$GLOBALS["ASSETS_SERVERS_HOSTNAMES"], "w");
$fp3 = fopen(__DIR__."/".$GLOBALS["ASSETS_SERVERS_IPS"], "w");

if ($fp1 == false || $fp2 == false || $fp3 == false) {
    echo "can't open '".$GLOBALS["ASSETS_SERVERS_HOSTNAMES"];
    echo "or '".$GLOBALS["ASSETS_SERVERS_IPS"];
    echo "or '".$GLOBALS["ASSETS_SERVERS_PROJECTS"]."'\n";
} else {
    if (isset($programs->items)) {
        foreach ($programs->items as $program) {
            $programContent = json_decode(file_get_contents("https://api.yeswehack.com/programs/".$program->slug));

            if (isset($programContent->scopes)) {
                foreach ($programContent->scopes as $scope) {
                    if (strpos($scope->scope_type, "mobile") === false) {
                        $host = null;
                        $ip = null;
                        
                        $guessedHosts = [];
                        if(strpos($scope->scope, "*") !== false) {
                          echo "HUM HUM I HAVE A STAR HERE1: '".$scope->scope."'\n";
                          
                          $substar = substr($scope->scope, strpos($scope->scope, "*") + 2);
                          echo "HUM HUM I HAVE A STAR HERE2: '$substar'\n";
                          
                          $cmd = $CONF_SUBLIST3R_BIN." -d $substar -o tmp/output.txt";
                          $output = shell_exec($cmd);
                          
                          $guessedHosts = [];
                          $handle = fopen("./tmp/output.txt", "r");
                          if ($handle) {
                              while (($line = fgets($handle)) !== false) {
                                  preg_match("/(.*\\.$substar)/", $line, $match);
                                  if(isset($match[0])) {
                                    array_push($guessedHosts, $match[0]);
                                  }
                              }

                              fclose($handle);
                          } else {
                              // error opening the file.
                          }

                          var_dump($output);
                          var_dump($match);
                        }
                        else {
                          array_push($guessedHosts, $scope->scope);
                        }
                        
                        foreach($guessedHosts as $guessedHost) {
                          if (filter_var($guessedHost, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                              $host = $guessedHost;
                              $ip = gethostbyname($guessedHost);
                          } elseif (filter_var($guessedHost, FILTER_VALIDATE_URL)) {
                              $url = parse_url($guessedHost);
                
                              if (isset($url["host"])) {
                                  $host = $url["host"];
                                  $ip = gethostbyname($host);
                              }
                          } elseif (filter_var($guessedHost, FILTER_VALIDATE_IP)) {
                              $host = $guessedHost;
                              $ip = $guessedHost;
                          }
              
                          if (filter_var($ip, FILTER_VALIDATE_IP)
                            && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                              if (strpos($host, "github.com") === false
                                && strpos($host, "apps.apple.com") === false
                                  && strpos($host, "play.google.com") === false
                                    && strpos($host, "itunes.apple.com") === false) {
                                  fwrite($fp1, $program->slug."\n");
                                  fwrite($fp2, $host."\n");
                                  fwrite($fp3, $ip."\n");
                              }
                          } else {
                              echo "can't find host or ip for scope: ".$guessedHost." (host=$host, ip=$ip) \n";
                          }
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
