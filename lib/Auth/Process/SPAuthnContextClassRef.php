<?php

namespace SimpleSAML\Module\assurance\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;

/**
 * Filter for saving the SP AuthnContextClassRef in the response.
 *
 * @package SimpleSAMLphp
 */
class SPAuthnContextClassRef extends ProcessingFilter
{
    /**
     * Initialize this filter.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML\Error\Exception if the mandatory 'attribute' option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');
    }

    /**
     * Save the AuthnContextClassRef in the SAML 2 response.
     *
     * @param array &$state The state array for this request.
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        if (!empty($state['saml:sp:State']['saml:sp:AuthnContext'])) {
            $state['Attributes']['sp:AuthnContext'] = array($state['saml:sp:State']['saml:sp:AuthnContext']);
        }

        return;
    }
}
