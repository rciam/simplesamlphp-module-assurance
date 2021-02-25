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
 *              'defaultAssurance' => 'https://example.org/LowAssurance',
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
    private $attribute = 'eduPersonAssurance';

    /**
     * @var string[]
     */
    private $candidates = array(
        'https://refeds.org/profile/sfa',
        'https://refeds.org/profile/mfa',
    );

    /**
     * @var string
     */
    private $defaultAssurance = 'https://www.example.org/low';

    /**
     * @var string
     */
    private $defaultElevatedAssurance = 'https://www.example.org/Substantial';

    /**
     * @var array
     */
    private $entitlementWhitelist = array();

    /**
     * @var array
     */
    private $idpPolicies = array();

    /**
     * @var array
     */
    private $idpTags = array();

    /**
     * @var string[]
     */
    private $config_param_str = array(
        'attribute',
        'defaultAssurance',
        'defaultElevatedAssurance',
    );

    /**
     * @var string[]
     */
    private $config_param_array = array(
        'candidates',
        'entitlementWhitelist',
        'idpTags',
        'idpPolicies',
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

        foreach ($this->config_param_str as $param) {
            if (array_key_exists($param, $config)) {
                $this->$param = $config[$param];
                if (!is_string($this->$param)) {
                    throw new Exception(
                        "DynamicAssurance auth processing filter configuration error: '" . $param . "' should be a string"
                    );
                }
            }
        }

        foreach ($this->config_param_array as $param) {
            if (array_key_exists($param, $config)) {
                $this->$param = $config[$param];
                if (!is_array($this->$param)) {
                    throw new Exception(
                        "DynamicAssurance auth processing filter configuration error: '" . $param . "' should be a string"
                    );
                }
            }
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
        // Candidates
        if (
            !empty($state['Attributes'][$this->attribute])
            && !empty(array_intersect($state['Attributes'][$this->attribute], $this->candidates))
        ) {
            SimpleSAML_Logger::debug(
                "[DynamicAssurance] Assurance matches known value: "
                . var_export(array_intersect($state['Attributes'][$this->attribute], $this->candidates), true)
            );
            return;
        }

        $assurance = $this->defaultAssurance;

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
        // IdP Tags
        if (
            !empty($idpMetadata['tags'])
            && !empty(array_intersect($idpMetadata['tags'], $this->idpTags))
        ) {
            SimpleSAML_Logger::debug(
                "[DynamicAssurance] IdP tag matches known value: "
                . var_export(array_intersect($idpMetadata['tags'], $this->idpTags), true)
            );
            $assurance = $this->defaultElevatedAssurance;
        }

        // IdP Policies
        if (
            !empty($state['Attributes']['eduPersonAssurance'])
            && !empty(array_intersect($state['Attributes']['eduPersonAssurance'], $this->idpPolicies))
        ) {
            SimpleSAML_Logger::debug(
                "[DynamicAssurance] Assurance matches known policy value: "
                . var_export(array_intersect($state['Attributes']['eduPersonAssurance'], $this->idpPolicies), true)
            );
            $assurance = $this->defaultElevatedAssurance;
        }

        // Entitlements
        if (
            array_key_exists('eduPersonEntitlement', $state['Attributes'])
            && !empty(array_intersect($state['Attributes']['eduPersonEntitlement'], $this->entitlementWhitelist))
        ) {
            SimpleSAML_Logger::debug(
                "[DynamicAssurance] Assurance matches known entitlement value: "
                . var_export(array_intersect($state['Attributes']['eduPersonEntitlement'], $this->entitlementWhitelist), true)
            );
            $assurance = $this->defaultElevatedAssurance;
        }

        $state['Attributes'][$this->attribute] = array($assurance);
    }
}
