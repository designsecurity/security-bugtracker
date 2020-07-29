<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */


if (!defined('WI_VERSION')) {
    die(-1);
}
function logp1($ex)
{
    $fp = fopen("securityplugin.log", "a+");
    fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
    fclose($fp);
}
class Common_CustomApplication extends System_Web_Application
{
    protected $isAnonymous = false;

    protected function __construct($pageClass)
    {
        logp1("__construct Common_CustomApplication 1");
        parent::__construct($pageClass);
        logp1("__construct Common_CustomApplication 2");
    }

    protected function preparePage()
    {
        logp1("preparePage Common_CustomApplication 1");
        parent::preparePage();
        $this->page->getView()->setDecoratorClass('Common_PageLayout');
        logp1("preparePage Common_CustomApplication 2");
    }

    protected function displayErrorPage()
    {
        logp1("preparePage displayErrorPage 1");
        $exception = $this->getFatalError();
        logp1("preparePage displayErrorPage 2");
        if ($this->isAnonymous && is_a($exception, 'System_Api_Error')) {
            $message = $exception->getMessage();
            if ($message == System_Api_Error::UnknownProject || $message == System_Api_Error::UnknownFolder || $message == System_Api_Error::UnknownIssue
                    || $message == System_Api_Error::UnknownFile || $message == System_Api_Error::UnknownView || $message == System_Api_Error::ItemNotFound) {
                $this->redirectToLoginPage();
            }
        }

        if (is_a($exception, 'System_Core_SetupException')) {
            $errorPage = System_Web_Component::createComponent('Common_Errors_Setup');
        } elseif ($this->isDebugInfoEnabled()) {
            $errorPage = System_Web_Component::createComponent('Common_Errors_Debug');
        } else {
            $errorPage = System_Web_Component::createComponent('Common_Errors_General');
        }

        $this->response->setContentType('text/html; charset=UTF-8');

        $content = $errorPage->run();
        $this->response->setContent($content);

        $this->response->send();
    }

    public function getManualUrl()
    {
        logp1("preparePage getManualUrl 1");
        $language = $this->translator->getLanguage(System_Core_Translator::UserLanguage);

        while ($language != '') {
            $url = '/doc/' . $language . '/index.html';

            if (file_exists(WI_ROOT_DIR . $url)) {
                return $url;
            }

            $pos = strrpos($language, '_');
            if ($pos === false) {
                break;
            }

            $language = substr($language, 0, $pos);
        }
        logp1("preparePage getManualUrl 2");

        return '/doc/en/index.html';
    }
}
