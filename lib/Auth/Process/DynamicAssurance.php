<?php

/**
 * Filter for setting the AuthnContextClassRef in the response based on the 
 * value of the supplied attribute.
 * Example configuration in metadata/saml20-idp-hosted.php:
 * 
 *      authproc = array(
 *          ...
 *          40 => array(
 *              'class' => 'assurance:DynamicAssurance',
 *              'attribute' => 'eduPersonAssurance',
 *              'candidates' => array(
 *                  'https://refeds.org/profile/sfa',
 *                  'https://refeds.org/profile/mfa',
 *              ),
 *              'entitlementWhitelist' => array(
 *                  'urn:mace:www.example.org:entitlement01',
 *                  'urn:mace:www.example.org:entitlement02',
 *              ),
 *              'defaultAccurance' => 'https://example.org/LowAssurance',
 *              'defaultElevatedAssurance' => 'https://example.org/HighAssurance',
 *              'idpPolicies' => array(
 *                  'example.org:policy01',
 *                  'example.org:policy02',
 *              ),
 *              'idpTags' => array(
 *                  'exampleTag01',
 *                  'exampleTag02',
 *              ),
 *          ),
 *
 * @package SimpleSAMLphp
 */
class sspmod_assurance_Auth_Process_DynamicAssurance extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * The attribute whose value should convey the LoA in 
     * the SAML assertion.
     *
     * @var string
     */
    private $_attribute = 'eduPersonAssurance';

    private $_candidates = array(
        'https://refeds.org/profile/sfa',
        'https://refeds.org/profile/mfa',
    );

    private $_defaultAccurance = 'https://www.example.org/low';
    
    private $_defaultElevatedAssurance = 'https://www.example.org/Substantial';

    private $_entitlementWhitelist = array();

    private $idpPolicies = array();

    private $idpTags = array();

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

        if (array_key_exists('attribute', $config)) {
            if (!is_string($this->_attribute)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'attribute\' should be a string');
            }
            $this->_attribute = $config['attribute'];
        }

        if (array_key_exists('candidates', $config)) {
            if (!is_array($this->_candidates)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'candidates\' should be an array');
            }
            $this->_candidates = $config['candidates'];
        }

        if (array_key_exists('defaultAccurance', $config)) {
            if (!is_string($this->_defaultAccurance)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'defaultAccurance\' should be a string');
            }
            $this->_defaultAccurance = $config['defaultAccurance'];
        }

        if (array_key_exists('defaultElevatedAssurance', $config)) {
            if (!is_string($this->_defaultElevatedAssurance)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'defaultElevatedAssurance\' should be a string');
            }
            $this->_defaultElevatedAssurance = $config['defaultElevatedAssurance'];
        }

        if (array_key_exists('entitlementWhitelist', $config)) {
            if (!is_array($this->_entitlementWhitelist)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'entitlementWhitelist\' should be an array');
            }
            $this->_entitlementWhitelist = $config['entitlementWhitelist'];
        }
    }

    /**
     * Set the assurance in the SAML 2 response.
     *
     * @param array &$state The state array for this request.
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        // Return early if assurance matches one of the well known values
        if (!empty($state['Attributes'][$this->_attribute]) &&       
            !empty(array_intersect($state['Attributes'][$this->_attribute], $this->_candidates))) {
            SimpleSAML_Logger::debug("[DynamicAssurance] Assurance matches known value: " . var_export(array_intersect($state['Attributes'][$this->_attribute], $this->_candidates), true));
            return;
        }

        $assurance = $this->_defaultAccurance;

        // Elevate assurance?
        // If the module is active on a bridge,
        // $state['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpMetadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            $idpEntityId = $state['Source']['entityid'];
            $idpMetadata = $state['Source'];
        }
        if (!empty($idpMetadata['tags']) && !empty(array_intersect($idpMetadata['tags'], $this->idpTags))) {
            SimpleSAML_Logger::debug("[DynamicAssurance] IdP tag matches known value: " . var_export(array_intersect($idpMetadata['tags'], $this->idpTags), true));
            $assurance = $this->_defaultElevatedAssurance;
        }

        if (!empty($state['Attributes']['eduPersonAssurance']) && !empty(array_intersect($state['Attributes']['eduPersonAssurance'], $this->idpPolicies))) {
            SimpleSAML_Logger::debug("[DynamicAssurance] Assurance matches known policy value: " . var_export(array_intersect($state['Attributes']['eduPersonAssurance'], $this->idpPolicies), true));
            $assurance = $this->_defaultElevatedAssurance;
        }

        if (array_key_exists('eduPersonEntitlement', $state['Attributes']) && !empty(array_intersect($state['Attributes']['eduPersonEntitlement'], $this->_entitlementWhitelist))) {
            SimpleSAML_Logger::debug("[DynamicAssurance] Assurance matches known entitlement value: " . var_export(array_intersect($state['Attributes']['eduPersonEntitlement'], $this->_entitlementWhitelist), true));
            $assurance = $this->_defaultElevatedAssurance;
        }
        
        $state['Attributes'][$this->_attribute] = array($assurance);
    }
}
