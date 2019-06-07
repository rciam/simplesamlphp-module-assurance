<?php


/**
 * Filter for saving the IdP AuthnContextClassRef in the response based on the 
 * value of the supplied attribute.
 * 
 * Example configuration in metadata/saml20-idp-hosted.php:
 * 
 *      authproc = array(
 *          ...
 *          41 => array(
 *              'class' => 'assurance:IdPAuthnContextClassRef',
 *              'attribute' => 'eduPersonAssurance',
 *          ),
 *
 *
 * @package SimpleSAMLphp
 */
class sspmod_assurance_Auth_Process_IdPAuthnContextClassRef extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * The attribute whose value should be set as the AuthnContextClassRef in 
     * the login response.
     *
     * @var string
     */
    private $attribute;


    /**
     * Initialize this filter.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML_Error_Exception if the mandatory 'attribute' option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (!isset($config['attribute'])) {
            throw new SimpleSAML_Error_Exception('Missing attribute option in processing filter.');
        }

        $this->attribute = (string) $config['attribute'];
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

        $assuranceWhitelist = array(
            'https://refeds.org/profile/sfa',
            'https://refeds.org/profile/mfa',
        );

        if (array_key_exists($this->attribute, $state['Attributes']) && !empty(array_intersect($state['Attributes'][$this->attribute], $assuranceWhitelist))) {
            $authnContextClassRef = $state['Attributes'][$this->attribute][0];
        } elseif (!empty($state['Attributes']['sp:AuthnContext'])) {
            $authnContextClassRef = $state['Attributes']['sp:AuthnContext'][0];
        }

        if (!empty($authnContextClassRef)) {
            $state['saml:AuthnContextClassRef'] = $authnContextClassRef;
        }
    }
}
