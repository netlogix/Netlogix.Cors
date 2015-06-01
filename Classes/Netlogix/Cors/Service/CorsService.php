<?php
namespace Netlogix\Cors\Service;

/***************************************************************
 *  Copyright notice
 *
 *  (c) 2012 Lienhart Woitok <lienhart.woitok@netlogix.de>, netlogix GmbH & Co. KG
 *
 *  All rights reserved
 *
 *  This script is part of the TYPO3 project. The TYPO3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/


/**
 * Cross Origin Resource Sharing (CORS) service
 *
 * @package nxcors
 * @license http://www.gnu.org/licenses/lgpl.html GNU Lesser General Public License, version 3 or later
 *
 */
class CorsService {

	/**
	 * Allowed origin domains
	 *
	 * @var array
	 */
	protected $allowedOrigins = array();

	/**
	 * Allowed request methods (GET, POST, OPTIONS, ...)
	 *
	 * @var array
	 */
	protected $allowedMethods = array('GET');

	/**
	 * Allowed custom HTTP headers
	 *
	 * @var array
	 */
	protected $allowedHeaders = array();

	/**
	 * Whether sending credentials is allowed (cookies, basic auth, ...)
	 *
	 * @var bool
	 */
	protected $allowCredentials = FALSE;

	/**
	 * @param boolean $allowCredentials
	 */
	public function setAllowCredentials($allowCredentials) {
		$this->allowCredentials = $allowCredentials;
	}

	/**
	 * @return boolean
	 */
	public function getAllowCredentials() {
		return $this->allowCredentials;
	}

	/**
	 * @param array $allowedHeaders
	 */
	public function setAllowedHeaders($allowedHeaders) {
		$this->allowedHeaders = $allowedHeaders;
	}

	/**
	 * @return array
	 */
	public function getAllowedHeaders() {
		return $this->allowedHeaders;
	}

	/**
	 * @param array $allowedMethods
	 */
	public function setAllowedMethods($allowedMethods) {
		$this->allowedMethods = $allowedMethods;
	}

	/**
	 * @return array
	 */
	public function getAllowedMethods() {
		return $this->allowedMethods;
	}

	/**
	 * @param array $allowedOrigins
	 */
	public function setAllowedOrigins($allowedOrigins) {
		$this->allowedOrigins = $allowedOrigins;
	}

	/**
	 * @return array
	 */
	public function getAllowedOrigins() {
		return $this->allowedOrigins;
	}

	/**
	 * Send HTTP headers for current request
	 */
	public function sendHeaders() {
		if (!$this->isCorsRequest()) {
			return;
		}

		if ($this->isCurrentRequestAllowed()) {
			header('Access-Control-Allow-Methods: ' . implode(', ', $this->allowedMethods));
			header('Access-Control-Allow-Credentials: ' . ($this->allowCredentials ? 'true' : 'false'));
			if (in_array('*', $this->allowedOrigins)) {
				header('Access-Control-Allow-Origin: *');
			} else {
				header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
			}
			if (!empty($this->allowedHeaders)) {
				header('Access-Control-Allow-Headers: ' . implode(', ', $this->allowedHeaders));
			}
		} else {
			$this->denyRequest();
		}
	}

	/**
	 * @return bool
	 */
	protected function isCorsRequest() {
		return isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== NULL && $_SERVER['HTTP_ORIGIN'] !== '';
	}

	/**
	 * Check whether the current request is allowed according to configuration
	 *
	 * @return bool
	 */
	protected function isCurrentRequestAllowed() {
		$currentRequestIsAllowed = TRUE;

		$requestMethod = $_SERVER['REQUEST_METHOD'];
		$requestOrigin = $_SERVER['HTTP_ORIGIN'];

		if (!in_array($requestMethod, $this->allowedMethods)) {
			$currentRequestIsAllowed = FALSE;
		}
		if ($currentRequestIsAllowed && !in_array($requestOrigin, $this->allowedOrigins) && !in_array('*', $this->allowedOrigins)) {
			$currentRequestIsAllowed = FALSE;
		}
		return $currentRequestIsAllowed;
	}

	/**
	 * Deny request and send forbidden header
	 *
	 * @throws \TYPO3\Flow\Http\Exception
	 */
	protected function denyRequest() {
		throw new \TYPO3\Flow\Security\Exception\AccessDeniedException('CORS request not allowed', 1337172748);
	}
}
