<?php
namespace Netlogix\Cors\Http\Component;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Netlogix.Cors".         *
 *                                                                        *
 *                                                                        */

use Netlogix\Cors\Service\CorsService;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Http\Component\ComponentContext;
use TYPO3\Flow\Http\Component\ComponentInterface;
use TYPO3\Flow\Utility\Arrays;

/**
 * HTTP component sending CORS (Access-Control-Allow-*) headers.
 */
class CorsComponent implements ComponentInterface
{

    /**
     * @var array
     */
    protected $options;

    /**
     * @param array $options
     */
    public function __construct(array $options = array())
    {
        $this->options = $options;
    }

    /**
     * If this one is no CORS, this component let pass the request.
     * In case of CORS requests, either the allow headers are sent or the
     * AccessDeniedException is thrown.
     *
     * @param ComponentContext $componentContext
     * @return void
     */
    public function handle(ComponentContext $componentContext)
    {
        static $possibleMethods = array('GET', 'POST', 'OPTIONS', 'DELETE', 'PUT');

        $corsService = new CorsService();

        /**
         * allowedMethods
         */
        if (isset($this->options['allowedMethods']) && is_array($this->options['allowedMethods'])) {
            $configuredMethods = $this->options['allowedMethods'];
            $configuredMethods = array_map('strtoupper', $configuredMethods);
            $configuredMethods = array_filter($configuredMethods, function ($method) use ($possibleMethods) {
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
            $configuredOrigins = Arrays::trimExplode(',', $this->options['allowedOrigins']);
        }
        $corsService->setAllowedOrigins($configuredOrigins);

        /**
         * allowedHeaders
         */
        $configuredHeaders = array();
        if (isset($this->options['allowedHeaders']) && is_array($this->options['allowedHeaders'])) {
            $configuredHeaders = array_values($this->options['allowedHeaders']);
        } elseif (isset($this->options['allowedHeaders']) && is_string($this->options['allowedHeaders'])) {
            $configuredHeaders = Arrays::trimExplode(',', $this->options['allowedHeaders']);
        }
        $corsService->setAllowedHeaders($configuredHeaders);

        /**
         * allowCredentials
         */
        if (isset($this->options['allowCredentials']) && $this->options['allowCredentials']) {
            $corsService->setAllowCredentials(true);
        } else {
            $corsService->setAllowCredentials(false);
        }

        /**
         * maxAge
         */
        if (isset($this->options['maxAge']) && $this->options['maxAge']) {
            $corsService->setMaxAge(intval($this->options['maxAge']));
        } else {
            $corsService->setMaxAge(600);
        }

        $corsService->sendHeaders();

    }

}