Security-bugtracker is a tool based on :
- webissues bug tracker : http://webissues.mimec.org/
- openvas  : http://www.openvas.org/
- dirb : http://dirb.sourceforge.net/
- nmap : https://nmap.org/
- arachni : www.arachni-scanner.com
- sslscan : https://github.com/ssllabs/ssllabs-scan
- node security platform : https://nodesecurity.io/ 
- sensiolabs security checker : https://security.sensiolabs.org/
- dependency check : https://github.com/jeremylong/DependencyCheck

the main additions to webissues are the use of webservices to run security test tools and track bugs.

 - add a project :
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="http://securitybugtracker/V1">
   <soapenv:Header/>
   <soapenv:Body>
      <v1:addproject>
         <name>TEST</name>
         <description>TEST DESC</description>
      </v1:addproject>
   </soapenv:Body>
</soapenv:Envelope>
```
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://securitybugtracker/V1">
   <SOAP-ENV:Body>
      <ns1:addproject_Response>
         <id_details>
            <id_project>27</id_project>
            <id_folder_bugs>73</id_folder_bugs>
            <id_folder_servers>74</id_folder_servers>
            <id_folder_codes>75</id_folder_codes>
            <id_folder_scans>76</id_folder_scans>
         </id_details>
      </ns1:addproject_Response>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
 - add a server :
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="http://securitybugtracker/V1">
   <soapenv:Header/>
   <soapenv:Body>
      <v1:addserver>
         <id_folder_servers>74</id_folder_servers>
         <hostname>test</hostname>
         <description>test</description>
         <use>Développement</use>
         <ipsaddress>127.0.0.1</ipsaddress>
      </v1:addserver>
   </soapenv:Body>
</soapenv:Envelope>
```
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://securitybugtracker/V1">
   <SOAP-ENV:Body>
      <ns1:addserver_Response>
         <result_addserver_details>
            <id_server>1150</id_server>
         </result_addserver_details>
      </ns1:addserver_Response>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
- run a security scan with openvas :
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="http://securitybugtracker/V1">
   <soapenv:Header/>
   <soapenv:Body>
      <v1:addscan>
         <id_folder_scans>76</id_folder_scans>
         <name>test openvas soapui</name>
         <description>test openvas soapui</description>
         <tool>openvas</tool>
         <filter>medium</filter>
         <!--Optional:-->
         <id_config_openvas>?</id_config_openvas>
      </v1:addscan>
   </soapenv:Body>
</soapenv:Envelope>
```
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://securitybugtracker/V1">
   <SOAP-ENV:Body>
      <ns1:addscan_Response>
         <result_addscan_details>
            <id_scan>1154</id_scan>
         </result_addscan_details>
      </ns1:addscan_Response>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

- view detected bug with the HMI of webissues: 

![ScreenShot](https://raw.githubusercontent.com/forgesecurity/security-bugtracker/master/documentation/bugs.png)


