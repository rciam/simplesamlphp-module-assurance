<?php


/**
 * Filter for setting the AuthnContextClassRef in the response based on the 
 * value of the supplied attribute.
 * 
 * Example configuration in metadata/saml20-idp-hosted.php:
 * 
 *      authproc = array(
 *          ...
 *          40 => array(
 *              'class' => 'assurance:DynamicAssurance',
 *              'entitlements' => array(
 *                  'urn:mace:www.example.org:entitlement01',
 *                  'urn:mace:www.example.org:entitlement02',
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

    private $_default = 'https://www.example.org/low';

    private $_entitlements;

    private $idpPolicies = array(
        '1.2.840.113612.5.2.2.1',
        '1.2.840.113612.5.2.2.5',
    );

    private $idpTags = array(
        'edugain',
    );

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
            $this->_attribute = $config['attribute'];
            if (!is_string($this->_attribute)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'attribute\' should be a string');
            }
        }

        if (array_key_exists('candidates', $config)) {
             $this->_candidates = $config['candidates'];
             if (!is_array($this->_candidates)) {
                 throw new Exception('DynamicAssurance auth processing filter configuration error: \'candidates\' should be an array');
             }
        }

        if (array_key_exists('default', $config)) {
            $this->_default = $config['default'];
            if (!is_string($this->_default)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'default\' should be a string');
            }
        }

        if (array_key_exists('entitlements', $config)) {
            $this->_entitlements = $config['entitlements'];
            if (!is_array($this->_entitlements)) {
                throw new Exception('DynamicAssurance auth processing filter configuration error: \'entitlements\' should be an array');
            }
        } else {
            throw new Exception('DynamicAssurance auth processing filter configuration error: \'entitlements\' have not been set');
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

        $assurance = $this->_default;

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
            $assurance = 'https://www.example.org/medium';
        }

        if (!empty($state['Attributes']['eduPersonAssurance']) && !empty(array_intersect($state['Attributes']['eduPersonAssurance'], $this->idpPolicies))) {
            SimpleSAML_Logger::debug("[DynamicAssurance] Assurance matches known policy value: " . var_export(array_intersect($state['Attributes']['eduPersonAssurance'], $this->idpPolicies), true));
            $assurance = 'https://www.example.org/medium';
        }

        if (array_key_exists('eduPersonEntitlement', $state['Attributes']) && !empty(array_intersect($state['Attributes']['eduPersonEntitlement'], $this->_entitlements))) {
            SimpleSAML_Logger::debug("[DynamicAssurance] Assurance matches known entitlement value: " . var_export(array_intersect($state['Attributes']['eduPersonEntitlement'], $this->_entitlements), true));
            $assurance = 'https://www.example.org/medium';
        }
        
            $state['Attributes'][$this->_attribute] = array($assurance);
    }
}
