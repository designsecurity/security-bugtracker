<?php

/*
 * This file is part of security-bugtracker, a bugtracker for security
 *
 * @copyright 2017 Eric Therond. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

class System_Web_Service extends System_Core_Application
{
    protected $pageClass = null;

    protected function __construct($pageClass)
    {
        parent::__construct();
        $this->pageClass = $pageClass;
    }

    protected function execute()
    {
        $this->response->setContentType('text/xml; charset=UTF-8');
    }
}
