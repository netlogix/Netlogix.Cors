<?php
namespace Netlogix\Cors\Service;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Netlogix.Cors".         *
 *                                                                        *
 *                                                                        */

use TYPO3\Flow\Core\Bootstrap;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Security\Exception\AccessDeniedException;

/**
 * Cross Origin Resource Sharing (CORS) service
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
				header('Access-Control-Allow-Origin: ' . Bootstrap::getEnvironmentConfigurationSetting('HTTP_ORIGIN'));
			}
			if (!empty($this->allowedHeaders)) {
				header('Access-Control-Allow-Headers: ' . implode(', ', $this->allowedHeaders));
			}
		} else {
			$this->denyRequest();
		}

		if (Bootstrap::getEnvironmentConfigurationSetting('REQUEST_METHOD') === 'OPTIONS') {
			exit;
		}
	}

	/**
	 * @return bool
	 */
	protected function isCorsRequest() {
		$origin = Bootstrap::getEnvironmentConfigurationSetting('HTTP_ORIGIN');
		if (!$origin) {
			return FALSE;
		}
		if (rtrim($origin, '/') == rtrim(Request::createFromEnvironment()->getBaseUri(), '/')) {
			// Unfortunately Chrome always adds the "HTTP_ORIGIN" header to POST, POT and DELETE request.
			return FALSE;
		}
		return TRUE;
	}

	/**
	 * Check whether the current request is allowed according to configuration
	 *
	 * @return bool
	 */
	protected function isCurrentRequestAllowed() {
		$currentRequestIsAllowed = TRUE;

		$requestMethod = Bootstrap::getEnvironmentConfigurationSetting('REQUEST_METHOD');
		$requestOrigin = Bootstrap::getEnvironmentConfigurationSetting('HTTP_ORIGIN');

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
		throw new AccessDeniedException('CORS request not allowed', 1337172748);
	}
}
