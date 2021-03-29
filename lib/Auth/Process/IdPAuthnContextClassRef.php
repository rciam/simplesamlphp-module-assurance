<?php

namespace SimpleSAML\Module\assurance\Auth\Process;

/**
 * Filter for saving the IdP AuthnContextClassRef in the response based on the 
 * value of the supplied attribute.
 * 
 * This filter should be configured on the IdP:
 * - Specific for only one hosted IdP in saml20-idp-hosted or shib13-idp-hosted
 * - Specific for only one remote SP in saml20-sp-remote or shib13-sp-remote
 * 
 * Example configuration in metadata/saml20-idp-hosted.php:
 * 
 *      authproc = array(
 *          ...
 *          41 => array(
 *              'class' => 'assurance:IdPAuthnContextClassRef',
 *              'attribute' => 'eduPersonAssurance',
 *              'assuranceWhitelist' = array(
 *                  'https://refeds.org/profile/sfa',
 *                  'https://refeds.org/profile/mfa',
 *              ),
 *          ),
 *
 *
 * @package SimpleSAMLphp
 */
class IdPAuthnContextClassRef extends SimpleSAML\Auth\ProcessingFilter
{
    /**
     * The attribute whose value should be set as the AuthnContextClassRef in 
     * the login response.
     *
     * @var string
     */
    private $attribute;

    private $assuranceWhitelist = array();

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

        if (!array_key_exists($config['attribute'])) {
            throw new SimpleSAML\Error\Exception('Missing attribute option in processing filter.');
        }
        $this->attribute = (string) $config['attribute'];

        if (array_key_exists('assuranceWhitelist', $config)) {
            if (!is_array($this->assuranceWhitelist)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'assuranceWhitelist\' should be an array');
            }
            $this->assuranceWhitelist = $config['assuranceWhitelist'];
        }
    }

    /**
     * Set the AuthnContextClassRef in the SAML 2 response.
     *
     * @param array &$state The state array for this request.
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        if (array_key_exists($this->attribute, $state['Attributes']) && !empty(array_intersect($state['Attributes'][$this->attribute], $this->assuranceWhitelist))) {
            $authnContextClassRef = $state['Attributes'][$this->attribute][0];
        } elseif (!empty($state['Attributes']['sp:AuthnContext'])) {
            $authnContextClassRef = $state['Attributes']['sp:AuthnContext'][0];
        }

        if (!empty($authnContextClassRef)) {
            $state['saml:AuthnContextClassRef'] = $authnContextClassRef;
        }
    }
}
