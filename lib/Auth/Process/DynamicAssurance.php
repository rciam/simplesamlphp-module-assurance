<?php
/**
 * Filter for setting the AuthnContextClassRef in the response based on the
 * value of the supplied attribute.
 * Example configuration in metadata/saml20-idp-hosted.php:
 *
 *     authproc = array(
 *          ...
 *          40 => array(
 *              'class' => 'assurance:DynamicAssurance',
 *              'attribute' => 'eduPersonAssurance',
 *              'attributeMap' => array(
 *                  'eduPersonAssurance' => array(
 *                      '1.2.840.113612.5.2.2.1' => array(                      // Classic
 *                          'https://refeds.org/assurance/IAP/low',
 *                          'https://refeds.org/assurance/IAP/medium',
 *                          'https://example.org/profile/Assurance/Low',
 *                      ),
 *                      '1.2.840.113612.5.2.2.5' => array(                      // MICS
 *                          'https://refeds.org/assurance/IAP/low',
 *                          'https://refeds.org/assurance/IAP/medium',
 *                          'https://example.org/profile/Assurance/High',
 *                      ),
 *                      'pregMatch' => array(
 *                          '#^https://example\.org/assurance#m',               // Pass Through values
 *                      ),
 *                  ),
 *                  'eduPersonEntitlement' => array(
 *                      'vo_test:IdP Proxy test' => array(
 *                          'https://example.org/LoA#AssuranceHigh',
 *                      ),
 *                      'vo_test2:IdP Proxy test2' => array(
 *                          'https://example.org/LoA#AssuranceLow',
 *                      ),
 *                  ),
 *                  'voPersonVerifiedEmail' => array(
 *                      'pregMatch' => array(
 *                          '/^.+$/m' => array(
 *                              'https://example.org/LoA#AssuranceLow',
 *                          ),
 *                      ),
 *                  ),
 *              ),
 *              'defaultAssurance' => array(
 *                  'https://example.org/LowAssurance'
 *              ),
 *              'idpTagMap' => array(
 *                  'exampleTag01' => array(
 *                      'https://example.org/HighAssurance'
 *                  ),
 *                  'exampleTag02' => array(
 *                      'https://example-other.org/HighAssurance'
 *                  ),
 *              ),
 *          ),
 *     )
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
     * @var array[]
     */
    private $attributeMap = array(
        'eduPersonAssurance' => array(
            '1.2.840.113612.5.2.2.1' => array(                      // Classic
                'https://refeds.org/assurance/IAP/low',
                'https://refeds.org/assurance/IAP/medium',
            ),
            '1.2.840.113612.5.2.2.5' => array(                      // MICS
                'https://refeds.org/assurance/IAP/low',
                'https://refeds.org/assurance/IAP/medium',
            ),
            'pregMatch' => array(
                '#^https://refeds\.org/assurance#m',                // REFEDS passthrough values
                '#^https://aarc-community\.org/assurance#m',        // AARC passthrough values
            ),
        ),
        'voPersonVerifiedEmail' => array(
            'pregMatch' => array(
                '/^.+$/m' => array(
                    'https://refeds.org/assurance/IAP/low'
                ),
            ),
        ),
    );

    /**
     * @var string
     */
    private $defaultAssurance = array();

    /**
     * @var array
     */
    private $idpTagMap = array();

    /**
     * @var string[]
     */
    private $config_param_str = array(
        'attribute',
    );

    /**
     * @var string[]
     */
    private $config_param_array = array(
        'attributeMap',
        'idpTagMap',
        'defaultAssurance',
    );

    /**
     * Initialize this filter.
     *
     * @param   array  $config    Configuration information about this filter.
     * @param   mixed  $reserved  For future use.
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
                if (!empty($this->$param)) {
                    // If i have default values then merge with ones provided in the configuration
                    $this->$param = array_merge_recursive($this->$param, $config[$param]);
                } else {
                    // No default value available. Just assign and continue
                    $this->$param = $config[$param];
                }
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

        SimpleSAML_Logger::debug(
            "[DynamicAssurance][process] Assurance Map config: " . var_export($this->attributeMap, true)
        );

        // Append in the Assurance Attribute all the configured values
        $assurance_from_candidates = array();
        foreach ($this->attributeMap as $attribute => $valAssuranceCandidates) {
            // This attribute is not available in the state
            if (empty($state['Attributes'][$attribute])) {
                continue;
            }

            SimpleSAML_Logger::debug(
                "[DynamicAssurance][process] state['Attributes']['" . $attribute . "']: " . var_export(
                    $state['Attributes'][$attribute],
                    true
                )
            );

            $preg_match = array();
            // Check if there is a pregMatch key
            if(!empty($valAssuranceCandidates['pregMatch'])) {
                $preg_match = $valAssuranceCandidates['pregMatch'];
            }

            // Handle any State Attribute having an exact match into configuration
            foreach ($state['Attributes'][$attribute] as $attribute_value) {
                if (!empty($valAssuranceCandidates[$attribute_value])) {
                    $assurance_from_candidates = array_merge(
                        $assurance_from_candidates,
                        $valAssuranceCandidates[$attribute_value]
                    );
                }
            }

            // Handle regex Match
            foreach ($preg_match as $key => $val) {
                // These are the pass through values
                if(is_string($val)) {
                    $passthrough_values        = preg_grep($valAssuranceCandidates, $state['Attributes'][$attribute]);
                    if(!empty($passthrough_values)) {
                        $assurance_from_candidates = array_merge(
                            $assurance_from_candidates,
                            $passthrough_values
                        );
                    }
                } elseif(is_array($val)) {  // Regex with list of Assurance values
                    foreach ($state['Attributes'][$attribute] as $attribute_values) {
                        if(preg_match($key, $attribute_values) === 1) {
                            $assurance_from_candidates = array_merge(
                                $assurance_from_candidates,
                                $val
                            );
                            break;
                        }
                    }
                }
            } // Handle Regex foreach
        } // List of Attribute Map foreach

        // If the module is active on a bridge,
        // $state['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($this->idpTagMap)) {
            if (!empty($state['saml:sp:IdP'])) {
                $idpEntityId = $state['saml:sp:IdP'];
                $idpMetadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler()->getMetaData(
                    $idpEntityId,
                    'saml20-idp-remote'
                );
            } else {
                $idpEntityId = $state['Source']['entityid'];
                $idpMetadata = $state['Source'];
            }
        }

        foreach ($this->idpTagMap as $idpTag => $assurance_values) {
            if (in_array($idpTag, $idpMetadata['tags'])) {
                if (!empty($assurance_values)) {
                    $assurance_from_candidates = array_merge(
                        $assurance_from_candidates,
                        $assurance_values
                    );
                }
            }
        }

        $assurance_from_candidates = array_unique($assurance_from_candidates);

        SimpleSAML_Logger::debug(
            "[DynamicAssurance][process] Assurance Values: " . var_export($assurance_from_candidates, true)
        );

        // Append the Default Assurance if the Assurance list is empty
        if(!empty($this->defaultAssurance)
           && empty($assurance_from_candidates)) {
            $assurance_from_candidates = array_merge($assurance_from_candidates, $this->defaultAssurance);
        }
        //  Remove any duplicates
        $assurance_from_candidates = array_unique($assurance_from_candidates);
        // Add Assurance into state
        if(!empty($assurance_from_candidates)) {
            $state['Attributes'][$this->attribute] = $assurance_from_candidates;
        }
    }

}
