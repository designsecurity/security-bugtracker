# security-bugtracker
> A tool to run security tools and track security bugs easily

---

## Supported tools
- [OpenVAS](https://www.openvas.org/)
- [DependencyCheck](https://github.com/jeremylong/DependencyCheck)
- [arachni](https://www.arachni-scanner.com/)
- [SonarQube](https://www.sonarqube.org/)
- [sslscan](https://github.com/rbsec/sslscan)
- [Owasp ZAP](https://www.zaproxy.org/)

## Prerequisites

Clone security-bugtracker to a temprary directory of your choice (`tmp-security-bugtracker` below):

```shell
git clone https://github.com/designsecurity/security-bugtracker tmp-security-bugtracker
```

### Webissues installation
Security-bugtracker is just a plugin of the awesome [webissues](https://github.com/mimecorg/webissues) bugtracker.  
Clone webissues repository to your web server directory of your choice (`/srv/www/htdocs/webissues` below):

```shell
git clone https://github.com/mimecorg/webissues /srv/www/htdocs/webissues
cd /srv/www/htdocs/webissues
npm install
npm run build:web
```

Go to http://localhost/webissues/setup/install.php to configure webissues

### OpenVAS plugin installation

[OpenVAS](https://www.openvas.org/) is the only mandatory security tool to install, security-bugtracker is deeply integrated with it.  
Edit the OpenVAS-plugin configuration file *tmp-security-bugtracker/security_tools/openvas/openvas.conf* with the required informations.  

## Configuration

*Merge* webissues and security-bugtracker with the chosen directory (step 1 of the [prerequisites](#prerequisites)) as argument of the install.sh utility:
```shell
cd tmp-security-bugtracker
./install.sh security-plugin /srv/www/htdocs/webissues/
```

Go to http://localhost/webissues/client/securityplugin.php to finalize the configuration:
- **openvas_ws_login**: is the login of the openvas webservice (the same than $CONF_WS_OPENVAS_LOGIN defined during the [OpenVAS plugin installation](#openvas-plugin-installation))
- **openvas_ws_password**: is the password of the openvas webservice (the same than $CONF_WS_OPENVAS_PASSWORD defined during the [OpenVAS plugin installation](#openvas-plugin-installation))
- **openvas_ws_endpoint**: is the url address of the openvas webservice (the same address than $CONF_OPENVAS_ALERT_URL defined during the [OpenVAS plugin installation](#openvas-plugin-installation))
- **type_folder_bugs**: is the id of the "folder type bugs" in openvas, by default it's 2.


*Copy* security-bugtracker OpenVAS plugin in the directory of your choice (can be on another server):
```shell
cd tmp-security-bugtracker
./install.sh openvas-services /srv/www/htdocs/openvas-services/
```

## Run security scans

### With SOAP-UI

Use your favorite SOAP client to request security bugtracker webservices:

![ScreenShot](./soapuidemo.png)

When OpenVAS scan will end, corresponding issues will be automatically added to bugs folder of your newly project:

![ScreenShot](./soapuidemo.png)
