<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


require_once( '../system/bootstrap.inc.php' );

class Client_SecurityPlugin extends System_Web_Component
{
	protected function __construct()
	{
		parent::__construct();
	}

	function logp($ex)
	{
		$fp = fopen("securityplugin.log","a+");
		fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
		fclose($fp);
	}

	protected function execute()
	{
		$this->view->setDecoratorClass( 'Common_Window' );
		$this->view->setSlot( 'page_title', $this->t( 'Security Plugin Configuration' ) );

		include( 'securityplugin.conf.php' );
		$this->install_security = $this->request->getQueryString( 'install' );
		$this->error_install = 0;

		$typeManager = new System_Api_TypeManager();
		$projectManager = new System_Api_ProjectManager();
		$issueManager = new System_Api_IssueManager();
		$userManager = new System_Api_UserManager();

		if($this->install_security == "yes")
		{
			$this->form = new System_Web_Form( 'installation', $this );
			$this->form->addField( 'openvas_ws_login', "admin" );
			$this->form->addField( 'openvas_ws_password', "" );
			$this->form->addField( 'openvas_ws_endpoint', "" );

			if ( $this->form->loadForm() ) {
				if ( $this->form->isSubmittedWith( 'ok' ) && !$this->form->hasErrors() ) {
					$openvas_ws_login = $this->request->getFormField( 'openvas_ws_login' );
					$openvas_ws_password = $this->request->getFormField( 'openvas_ws_password' );
					$openvas_ws_endpoint = $this->request->getFormField( 'openvas_ws_endpoint' );
					$id_type_folder_bugs = $this->request->getFormField( 'type_folder_bugs' );

					if (preg_match('/^[A-Za-z0-9\-]*$/i', $openvas_ws_login) &&
							preg_match('/^[A-Za-z0-9\-]*$/i', $openvas_ws_password) &&
							preg_match('/^[A-Za-z0-9_\-\:\/\.&?\=]*$/i', $openvas_ws_endpoint))
					{
						$this->install_security = "do";

						$id_type_folder_servers = $typeManager->addIssueType( "Servers" );
						$id_type_folder_codes = $typeManager->addIssueType( "Codes" );
						$id_type_folder_scans = $typeManager->addIssueType( "Scans" );
						$id_type_folder_web = $typeManager->addIssueType( "Web" );

						$type_folder_servers = $typeManager->getIssueType($id_type_folder_servers);
						$type_folder_codes = $typeManager->getIssueType($id_type_folder_codes);
						$type_folder_scans = $typeManager->getIssueType($id_type_folder_scans);
						$type_folder_web = $typeManager->getIssueType($id_type_folder_web);

						// ************************** FOLDER BUGS ***************************************** 
						$type_folder_bugs = $typeManager->getIssueType($id_type_folder_bugs);

						$info1 = new System_Api_DefinitionInfo();
						$info1->setType( 'TEXT' );
						$info1->setMetadata( 'multi-line', 1 );
						$info1->setMetadata( 'min-length', 1 );
						$info1->setMetadata( 'max-length', 1000 );
						$info1->setMetadata( 'required', 0 );
						$info1->setMetadata( 'default', "" );

						$id_attribute_folder_bugs_target = $typeManager->addAttributeType( $type_folder_bugs, "target", $info1->toString() );
						$id_attribute_folder_bugs_cve = $typeManager->addAttributeType( $type_folder_bugs, "cve", $info1->toString() );
						$id_attribute_folder_bugs_cwe = $typeManager->addAttributeType( $type_folder_bugs, "cwe", $info1->toString() );
						
						/*
						   $attributes_bugs = $typeManager->getAttributeTypesForIssueType( $type_folder_bugs );
						   foreach ( $attributes_bugs as $attribute )
						   $columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];

						   $info = new System_Api_DefinitionInfo();
						   $info->setType( 'VIEW' );

						   $columns = array_keys( $columns );
						   $info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
						   $info->setMetadata( 'sort-column', System_Api_Column::ID );

						   $viewManager = new System_Api_ViewManager();
						   try {
						   $viewManager->setViewSetting( $type_folder_bugs, 'default_view', $info->toString() );
						   } catch ( System_Api_Error $ex ) {
						   $this->form->getErrorHelper()->handleError( 'viewName', $ex );
						   }
						 */
						// ********************************************************************************


						// ************************** FOLDER SERVERS ************************************** 
						$info1 = new System_Api_DefinitionInfo();
						$info1->setType( 'ENUM' );
						$info1->setMetadata( 'items', array('Development', 'Test', 'Production') );
						$info1->setMetadata( 'editable', 0 );
						$info1->setMetadata( 'multi-select', 0 );
						$info1->setMetadata( 'min-length', 1 );
						$info1->setMetadata( 'max-length', 30 );
						$info1->setMetadata( 'required', 1 );
						$info1->setMetadata( 'default', "Production" );

						$info2 = new System_Api_DefinitionInfo();
						$info2->setType( 'ENUM' );
						$info2->setMetadata( 'items', array() );
						$info2->setMetadata( 'editable', 1 );
						$info2->setMetadata( 'multi-select', 0 );
						$info2->setMetadata( 'min-length', 1 );
						$info2->setMetadata( 'max-length', 5000 );
						$info2->setMetadata( 'required', 1 );
						$info2->setMetadata( 'default', "" );

						$id_attribute_folder_servers_ipsaddress = $typeManager->addAttributeType( $type_folder_servers, "ips address", $info2->toString() );
						$id_attribute_folder_servers_use = $typeManager->addAttributeType( $type_folder_servers, "use", $info1->toString() );

						$attributes_servers = $typeManager->getAttributeTypesForIssueType( $type_folder_servers );
						foreach ( $attributes_servers as $attribute )
							$columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];


						$info = new System_Api_DefinitionInfo();
						$info->setType( 'VIEW' );

						$columns = array_keys( $columns );
						$info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
						$info->setMetadata( 'sort-column', System_Api_Column::ID );

						$viewManager = new System_Api_ViewManager();
						try {
							$viewManager->setViewSetting( $type_folder_servers, 'default_view', $info->toString() );
						} catch ( System_Api_Error $ex ) {
							$this->form->getErrorHelper()->handleError( 'viewName', $ex );
						}
						// ********************************************************************************





						// **************************** FOLDER CODES ************************************** 
						$info1 = new System_Api_DefinitionInfo();
						$info1->setType( 'TEXT' );
						$info1->setMetadata( 'multi-line', 0 );
						$info1->setMetadata( 'min-length', 1 );
						$info1->setMetadata( 'max-length', 40 );
						$info1->setMetadata( 'required', 0 );
						$info1->setMetadata( 'default', "" );

						$id_attribute_folder_codes_path = $typeManager->addAttributeType( $type_folder_codes, "code", $info1->toString() );

						$attributes_codes = $typeManager->getAttributeTypesForIssueType( $type_folder_codes );
						foreach ( $attributes_codes as $attribute )
							$columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];

						$info = new System_Api_DefinitionInfo();
						$info->setType( 'VIEW' );

						$columns = array_keys( $columns );
						$info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
						$info->setMetadata( 'sort-column', System_Api_Column::ID );

						$viewManager = new System_Api_ViewManager();
						try {
							$viewManager->setViewSetting( $type_folder_codes, 'default_view', $info->toString() );
						} catch ( System_Api_Error $ex ) {
							$this->form->getErrorHelper()->handleError( 'viewName', $ex );
						}
						// ********************************************************************************






						// **************************** FOLDER WEB ************************************** 
						$info1 = new System_Api_DefinitionInfo();
						$info1->setType( 'TEXT' );
						$info1->setMetadata( 'multi-line', 0 );
						$info1->setMetadata( 'min-length', 1 );
						$info1->setMetadata( 'max-length', 150 );
						$info1->setMetadata( 'required', 0 );
						$info1->setMetadata( 'default', "" );

						$id_attribute_folder_web_url = $typeManager->addAttributeType( $type_folder_web, "url", $info1->toString() );

						$attributes_web = $typeManager->getAttributeTypesForIssueType( $type_folder_web );
						foreach ( $attributes_web as $attribute )
							$columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];

						$info = new System_Api_DefinitionInfo();
						$info->setType( 'VIEW' );

						$columns = array_keys( $columns );
						$info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
						$info->setMetadata( 'sort-column', System_Api_Column::ID );

						$viewManager = new System_Api_ViewManager();
						try {
							$viewManager->setViewSetting( $type_folder_web, 'default_view', $info->toString() );
						} catch ( System_Api_Error $ex ) {
							$this->form->getErrorHelper()->handleError( 'viewName', $ex );
						}
						// ********************************************************************************


						// ************************** FOLDER SCANS **************************************
						$info1 = new System_Api_DefinitionInfo();
						$info1->setType( 'ENUM' );
						$info1->setMetadata( 'items', array('openvas', 'dependency-check', 'arachni', 'sslscan', 'zap', 'sonar') );
						$info1->setMetadata( 'editable', 0 );
						$info1->setMetadata( 'multi-select', 0 );
						$info1->setMetadata( 'min-length', 1 );
						$info1->setMetadata( 'max-length', 30 );
						$info1->setMetadata( 'required', 1 );
						$info1->setMetadata( 'default', "openvas" );

						$info2 = new System_Api_DefinitionInfo();
						$info2->setType( 'ENUM' );
						$info2->setMetadata( 'items', array('stopped', 'in progress', 'finished') );
						$info2->setMetadata( 'editable', 0 );
						$info2->setMetadata( 'multi-select', 0 );
						$info2->setMetadata( 'min-length', 1 );
						$info2->setMetadata( 'max-length', 30 );
						$info2->setMetadata( 'required', 1 );
						$info2->setMetadata( 'default', "stopped" );

						$info3 = new System_Api_DefinitionInfo();
						$info3->setType( 'ENUM' );
						$info3->setMetadata( 'items', array('info', 'minor', 'medium', 'high') );
						$info3->setMetadata( 'editable', 0 );
						$info3->setMetadata( 'multi-select', 0 );
						$info3->setMetadata( 'min-length', 1 );
						$info3->setMetadata( 'max-length', 30 );
						$info3->setMetadata( 'required', 1 );
						$info3->setMetadata( 'default', "info" );

						$id_attribute_folder_scans_tool = $typeManager->addAttributeType( $type_folder_scans, "tool", $info1->toString() );
						$id_attribute_folder_scans_time = $typeManager->addAttributeType( $type_folder_scans, "time", $info2->toString() );
						$id_attribute_folder_scans_severity = $typeManager->addAttributeType( $type_folder_scans, "severity", $info3->toString() );

						$attributes_servers = $typeManager->getAttributeTypesForIssueType( $type_folder_scans );
						foreach ( $attributes_servers as $attribute )
							$columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];


						$info = new System_Api_DefinitionInfo();
						$info->setType( 'VIEW' );

						$columns = array_keys( $columns );
						$info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
						$info->setMetadata( 'sort-column', System_Api_Column::ID );

						$viewManager = new System_Api_ViewManager();
						try {
							$viewManager->setViewSetting( $type_folder_scans, 'default_view', $info->toString() );
						} catch ( System_Api_Error $ex ) {
							$this->form->getErrorHelper()->handleError( 'viewName', $ex );
						}



						$info1 = new System_Api_DefinitionInfo();
						$info1->setType( 'TEXT' );
						$info1->setMetadata( 'multi-line', 0 );
						$info1->setMetadata( 'min-length', 1 );
						$info1->setMetadata( 'max-length', 40 );
						$info1->setMetadata( 'required', 0 );
						$info1->setMetadata( 'default', "" );

						$id_attribute_folder_scans_targetid = $typeManager->addAttributeType( $type_folder_scans, "targetid", $info1->toString() );


						$info2 = new System_Api_DefinitionInfo();
						$info2->setType( 'TEXT' );
						$info2->setMetadata( 'multi-line', 0 );
						$info2->setMetadata( 'min-length', 1 );
						$info2->setMetadata( 'max-length', 40 );
						$info2->setMetadata( 'required', 0 );
						$info2->setMetadata( 'default', "" );

						$id_attribute_folder_scans_tasktid = $typeManager->addAttributeType( $type_folder_scans, "tasktid", $info2->toString() );


						$info3 = new System_Api_DefinitionInfo();
						$info3->setType( 'TEXT' );
						$info3->setMetadata( 'multi-line', 0 );
						$info3->setMetadata( 'min-length', 1 );
						$info3->setMetadata( 'max-length', 40 );
						$info3->setMetadata( 'required', 0 );
						$info3->setMetadata( 'default', "" );

						$id_attribute_folder_scans_reportid = $typeManager->addAttributeType( $type_folder_scans, "reportid", $info3->toString() );


						$info4 = new System_Api_DefinitionInfo();
						$info4->setType( 'TEXT' );
						$info4->setMetadata( 'multi-line', 0 );
						$info4->setMetadata( 'min-length', 1 );
						$info4->setMetadata( 'max-length', 40 );
						$info4->setMetadata( 'required', 0 );
						$info4->setMetadata( 'default', "" );

						$id_attribute_folder_scans_alertid = $typeManager->addAttributeType( $type_folder_scans, "alertid", $info4->toString() );

						// *********************************************************************************
						$fp = fopen("securityplugin.conf.php", "w");
						if($fp != FALSE) {
              fputs($fp,"<?php\n\n");
              fputs($fp,"\$CONF_SERVER_IPS_EXPLODE = \",\";\n");
              fputs($fp,"\$CONF_ISSUE_DEFAULT_CVENAME = \"nocve\";\n");
              fputs($fp,"\$CONF_ISSUE_DEFAULT_CWENAME = \"nocwe\";\n");
              fputs($fp,"\$CONF_OPENVAS_WS_LOGIN = \"$openvas_ws_login\";\n");
              fputs($fp,"\$CONF_OPENVAS_WS_PASSWORD = \"$openvas_ws_password\";\n");
              fputs($fp,"\$CONF_OPENVAS_WS_ENDPOINT = \"$openvas_ws_endpoint\";\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_WEB_URL = $id_attribute_folder_web_url;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH = $id_attribute_folder_codes_path;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE = $id_attribute_folder_servers_use;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS = $id_attribute_folder_servers_ipsaddress;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL = $id_attribute_folder_scans_tool;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME = $id_attribute_folder_scans_time;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY = $id_attribute_folder_scans_severity;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID = $id_attribute_folder_scans_targetid;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID = $id_attribute_folder_scans_tasktid;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID = $id_attribute_folder_scans_reportid;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID = $id_attribute_folder_scans_alertid;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET = $id_attribute_folder_bugs_target;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE = $id_attribute_folder_bugs_cve;\n");
              fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE = $id_attribute_folder_bugs_cwe;\n");
              fputs($fp,"\$CONF_ID_TYPE_FOLDER_BUGS = $id_type_folder_bugs;\n");
              fputs($fp,"\$CONF_ID_TYPE_FOLDER_SERVERS = $id_type_folder_servers;\n");
              fputs($fp,"\$CONF_ID_TYPE_FOLDER_CODES = $id_type_folder_codes;\n");
              fputs($fp,"\$CONF_ID_TYPE_FOLDER_WEB = $id_type_folder_web;\n");
              fputs($fp,"\$CONF_ID_TYPE_FOLDER_SCANS = $id_type_folder_scans;\n\n");
              fputs($fp,"?>");
              fclose($fp);
            }
            else {
							$this->error_install = "Impossible to write in securityplugin.conf.php file, check the permissions file";
            }
					}
				}
			}
		}

		elseif($this->install_security == "no" ) {

			$type_folder_servers = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_SERVERS );
			$type_folder_codes = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_CODES );
			$type_folder_web = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_WEB );
			$type_folder_scans = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_SCANS );
			$type_folder_bugs = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_BUGS );

			$folders = $projectManager->getFoldersByIssueType( $type_folder_servers );
			foreach ( $folders as $folder )
			{
				$issues = $issueManager->getIssues( $folder );
				foreach ( $issues as $issue )
				{
					$desc = $issueManager->getDescription( $issue );
					$issueManager->deleteIssue( $issue );
					$issueManager->deleteDescription( $descr );
				}

				$projectManager->deleteFolder( $folder );
			}


			$folders = $projectManager->getFoldersByIssueType( $type_folder_codes );
			foreach ( $folders as $folder )
			{
				$issues = $issueManager->getIssues( $folder );
				foreach ( $issues as $issue )
				{
					$desc = $issueManager->getDescription( $issue );
					$issueManager->deleteIssue( $issue );
					$issueManager->deleteDescription( $descr );
				}

				$projectManager->deleteFolder( $folder );
			}


			$folders = $projectManager->getFoldersByIssueType( $type_folder_web );
			foreach ( $folders as $folder )
			{
				$issues = $issueManager->getIssues( $folder );
				foreach ( $issues as $issue )
				{
					$desc = $issueManager->getDescription( $issue );
					$issueManager->deleteIssue( $issue );
					$issueManager->deleteDescription( $descr );
				}

				$projectManager->deleteFolder( $folder );
			}


			$folders = $projectManager->getFoldersByIssueType( $type_folder_scans );
			foreach ( $folders as $folder )
			{
				$issues = $issueManager->getIssues( $folder );
				foreach ( $issues as $issue )
				{
					$desc = $issueManager->getDescription( $issue );
					$issueManager->deleteIssue( $issue );
					$issueManager->deleteDescription( $descr );
				}
				// 	      
				$projectManager->deleteFolder( $folder );
			}


			$folders = $projectManager->getFoldersByIssueType( $type_folder_bugs );
			foreach ( $folders as $folder )
			{
				$issues = $issueManager->getIssues( $folder );
				foreach ( $issues as $issue )
				{
					$desc = $issueManager->getDescription( $issue );
					$issueManager->deleteIssue( $issue );
					$issueManager->deleteDescription( $descr );
				}
				// 	      
				$projectManager->deleteFolder( $folder );
			}

			$attributes_servers = $typeManager->getAttributeTypesForIssueType( $type_folder_servers );
			foreach ( $attributes_servers as $attribute )
				$typeManager->deleteAttributeType( $attribute );

			$attributes_codes = $typeManager->getAttributeTypesForIssueType( $type_folder_codes );
			foreach ( $attributes_codes as $attribute )
				$typeManager->deleteAttributeType( $attribute );

			$attributes_web = $typeManager->getAttributeTypesForIssueType( $type_folder_web );
			foreach ( $attributes_web as $attribute )
				$typeManager->deleteAttributeType( $attribute );

			$attributes_scans = $typeManager->getAttributeTypesForIssueType( $type_folder_scans );
			foreach ( $attributes_scans as $attribute )
				$typeManager->deleteAttributeType( $attribute );

			$attributes_bugs = $typeManager->getAttributeTypesForIssueType( $type_folder_bugs );
			foreach ( $attributes_bugs as $attribute )
				$typeManager->deleteAttributeType( $attribute );

			$typeManager->deleteIssueType( $type_folder_servers, System_Api_TypeManager::ForceDelete );
			$typeManager->deleteIssueType( $type_folder_codes, System_Api_TypeManager::ForceDelete );
			$typeManager->deleteIssueType( $type_folder_web, System_Api_TypeManager::ForceDelete );
			$typeManager->deleteIssueType( $type_folder_scans, System_Api_TypeManager::ForceDelete );
			
			unlink("securityplugin.conf.php");
		}
	}
}

System_Bootstrap::run( 'Common_CustomApplication', 'Client_SecurityPlugin' );
