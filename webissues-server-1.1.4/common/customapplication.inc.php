<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


if ( !defined( 'WI_VERSION' ) ) die( -1 );

class Common_CustomApplication extends System_Web_Application
{
	protected $isAnonymous = false;

	protected function __construct( $pageClass )
	{
		parent::__construct( $pageClass );
	}

	protected function preparePage()
	{
		parent::preparePage();
		$this->page->getView()->setDecoratorClass( 'Common_PageLayout' );
	}

	protected function displayErrorPage()
	{
		$exception = $this->getFatalError();

		if ( $this->isAnonymous && is_a( $exception, 'System_Api_Error' ) ) {
			$message = $exception->getMessage();
			if ( $message == System_Api_Error::UnknownProject || $message == System_Api_Error::UnknownFolder || $message == System_Api_Error::UnknownIssue
					|| $message == System_Api_Error::UnknownFile || $message == System_Api_Error::UnknownView || $message == System_Api_Error::ItemNotFound )
				$this->redirectToLoginPage();
		}

		if ( is_a( $exception, 'System_Core_SetupException' ) )
			$errorPage = System_Web_Component::createComponent( 'Common_Errors_Setup' );
		else if ( $this->isDebugInfoEnabled() )
			$errorPage = System_Web_Component::createComponent( 'Common_Errors_Debug' );
		else
			$errorPage = System_Web_Component::createComponent( 'Common_Errors_General' );

		$this->response->setContentType( 'text/html; charset=UTF-8' );

		$content = $errorPage->run();
		$this->response->setContent( $content );

		$this->response->send();
	}

	public function getManualUrl()
	{
		$language = $this->translator->getLanguage( System_Core_Translator::UserLanguage );

		while ( $language != '' ) {
			$url = '/doc/' . $language . '/index.html';

			if ( file_exists( WI_ROOT_DIR . $url ) )
				return $url;

			$pos = strrpos( $language, '_' );
			if ( $pos === false )
				break;

			$language = substr( $language, 0, $pos );
		}

		return '/doc/en/index.html';
	}

}


