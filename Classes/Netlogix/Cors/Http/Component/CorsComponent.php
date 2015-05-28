<?php
namespace Netlogix\Cors\Http\Component;

/*                                                                        *
 * This script belongs to the TYPO3 Flow framework.                       *
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU Lesser General Public License, either version 3   *
 * of the License, or (at your option) any later version.                 *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use TYPO3\Flow\Annotations as Flow;

/**
 * HTTP component sending CORS (Access-Control-Allow-*) headers.
 */
class CorsComponent implements \TYPO3\Flow\Http\Component\ComponentInterface {

	/**
	 * @var array
	 */
	protected $options;

	/**
	 * @param array $options
	 */
	public function __construct(array $options = array()) {
		$this->options = $options;
	}

	/**
	 * If this one is no CORS, this component let pass the request.
	 * In case of CORS requests, either the allow headers are sent or the
	 * AccessDeniedException is thrown.
	 *
	 * @param \TYPO3\Flow\Http\Component\ComponentContext $componentContext
	 * @return void
	 */
	public function handle(\TYPO3\Flow\Http\Component\ComponentContext $componentContext) {
		static $possibleMethods = array('GET', 'POST', 'OPTIONS');

		$corsService = new \Netlogix\Cors\Service\CorsService();

		/**
		 * allowedMethods
		 */
		if (isset($this->options['allowedMethods']) && is_array($this->options['allowedMethods'])) {
			$configuredMethods = $this->options['allowedMethods'];
			$configuredMethods = array_map('strtoupper', $configuredMethods);
			$configuredMethods = array_filter($configuredMethods, function($method) use ($possibleMethods) {
				return in_array($method, $possibleMethods);
			});
			$corsService->setAllowedMethods($configuredMethods);
		}

		/**
		 * allowedOrigins
		 */
		$configuredOrigins = array();
		if (isset($this->options['allowedOrigins']) && is_array($this->options['allowedOrigins'])) {
			$configuredOrigins = array_values($this->options['allowedOrigins']);
		} elseif (isset($this->options['allowedOrigins']) && is_string($this->options['allowedOrigins'])) {
			$configuredOrigins = \TYPO3\Flow\Utility\Arrays::trimExplode(',', $this->options['allowedOrigins']);
		}
		$corsService->setAllowedOrigins($configuredOrigins);

		/**
		 * allowedHeaders
		 */
		$configuredHeaders = array();
		if (isset($this->options['allowedHeaders']) && is_array($this->options['allowedHeaders'])) {
			$configuredHeaders = array_values($this->options['allowedHeaders']);
		} elseif (isset($this->options['allowedHeaders']) && is_string($this->options['allowedHeaders'])) {
			$configuredHeaders = \TYPO3\Flow\Utility\Arrays::trimExplode(',', $this->options['allowedHeaders']);
		}
		$corsService->setAllowedHeaders($configuredHeaders);

		/**
		 * allowCredentials
		 */
		if (isset($this->options['allowCredentials']) && $this->options['allowCredentials']) {
			$corsService->setAllowCredentials(TRUE);
		} else {
			$corsService->setAllowCredentials(FALSE);
		}

		$corsService->sendHeaders();

	}

}