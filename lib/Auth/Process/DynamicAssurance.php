<?php

namespace SimpleSAML\Module\assurance\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;

/**
 * Filter for setting the AuthnContextClassRef in the response based on the
 * value of the supplied attribute.
 * Example configuration in metadata/saml20-idp-hosted.php:
 *
 *     authproc = [
 *          ...
 *          40 => [
 *              'class' => 'assurance:DynamicAssurance',
 *              'attribute' => 'eduPersonAssurance',
 *              'attributeMap' => [
 *                  'eduPersonAssurance' => [
 *                      '1.2.840.113612.5.2.2.1' => [ // Classic
 *                          'https://refeds.org/assurance/IAP/low',
 *                          'https://refeds.org/assurance/IAP/medium',
 *                          'https://example.org/profile/Assurance/Low',
 *                      ],
 *                      '1.2.840.113612.5.2.2.5' => [ // MICS
 *                          'https://refeds.org/assurance/IAP/low',
 *                          'https://refeds.org/assurance/IAP/medium',
 *                          'https://example.org/profile/Assurance/High',
 *                      ],
 *                      'pregMatch' => [
 *                          '#^https://example\.org/assurance#m', // Pass Through values
 *                      ],
 *                  ],
 *                  'eduPersonEntitlement' => [
 *                      'vo_test:IdP Proxy test' => [
 *                          'https://example.org/LoA#AssuranceHigh',
 *                      ],
 *                      'vo_test2:IdP Proxy test2' => [
 *                          'https://example.org/LoA#AssuranceLow',
 *                      ],
 *                  ],
 *                  'voPersonVerifiedEmail' => [
 *                      'pregMatch' => [
 *                          '/^.+$/m' => [
 *                              'https://example.org/LoA#AssuranceLow',
 *                          ],
 *                      ],
 *                  ],
 *              ],
 *              'defaultAssurance' => [
 *                  'https://example.org/LowAssurance'
 *              ],
 *              'minAssurance' => [
 *                  'https://example.org/LowAssurance'
 *              ],
 *              'idpTagMap' => [
 *                  'exampleTag01' => [
 *                      'https://example.org/HighAssurance'
 *                  ],
 *                  'exampleTag02' => [
 *                      'https://example-other.org/HighAssurance'
 *                  ],
 *              ],
 *          ],
 *
 * @package SimpleSAMLphp
 */
class DynamicAssurance extends ProcessingFilter
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
    private $attributeMap = [
        'eduPersonAssurance' => [
            '1.2.840.113612.5.2.2.1' => [ // Classic
                'https://refeds.org/assurance/IAP/low',
                'https://refeds.org/assurance/IAP/medium',
            ],
            '1.2.840.113612.5.2.2.5' => [ // MICS
                'https://refeds.org/assurance/IAP/low',
                'https://refeds.org/assurance/IAP/medium',
            ],
            'pregMatch' => [
                '#^https://refeds\.org/assurance#m', // REFEDS passthrough values
                '#^https://aarc-community\.org/assurance#m', // AARC passthrough values
            ],
        ],
        'voPersonVerifiedEmail' => [
            'pregMatch' => [
                '/^.+$/m' => [
                    'https://refeds.org/assurance/IAP/low'
                ],
            ],
        ],
    ];

    /**
     * @var array
     */
    private $minAssurance = [];

    /**
     * @var string
     */
    private $defaultAssurance = [];

    /**
     * @var array
     */
    private $idpTagMap = [];

    /**
     * @var string[]
     */
    private $configParamStr = [
        'attribute',
    ];

    /**
     * @var string[]
     */
    private $configParamArray = [
        'attributeMap',
        'idpTagMap',
        'defaultAssurance',
        'minAssurance',
    ];

    /**
     * Initialize this filter.
     *
     * @param array $config   Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML\Error\Exception if the mandatory 'attribute' option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        foreach ($this->configParamStr as $param) {
            if (array_key_exists($param, $config)) {
                $this->$param = $config[$param];
                if (!is_string($this->$param)) {
                    throw new Exception(
                        "DynamicAssurance auth processing filter configuration error: '"
                        . $param . "' should be a string"
                    );
                }
            }
        }

        foreach ($this->configParamArray as $param) {
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
                        "DynamicAssurance auth processing filter configuration error: '"
                        . $param . "' should be a string"
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

        Logger::debug(
            "[DynamicAssurance][process] Assurance Map config: " . var_export($this->attributeMap, true)
        );

        // Append in the Assurance Attribute all the configured values
        $assuranceFromCandidates = [];
        foreach ($this->attributeMap as $attribute => $valAssuranceCandidates) {
            // This attribute is not available in the state
            if (empty($state['Attributes'][$attribute])) {
                continue;
            }

            Logger::debug(
                "[DynamicAssurance][process] state['Attributes']['" . $attribute . "']: " . var_export(
                    $state['Attributes'][$attribute],
                    true
                )
            );

            $pregMatch = [];
            // Check if there is a pregMatch key
            if (!empty($valAssuranceCandidates['pregMatch'])) {
                $pregMatch = $valAssuranceCandidates['pregMatch'];
            }

            // Handle any State Attribute having an exact match into configuration
            foreach ($state['Attributes'][$attribute] as $attributeValue) {
                if (!empty($valAssuranceCandidates[$attributeValue])) {
                    $assuranceFromCandidates = array_merge(
                        $assuranceFromCandidates,
                        $valAssuranceCandidates[$attributeValue]
                    );
                }
            }

            // Handle regex Match
            foreach ($pregMatch as $key => $val) {
                // These are the pass through values
                if (is_string($val)) {
                    $passthroughValues = preg_grep($val, $state['Attributes'][$attribute]);
                    if (!empty($passthroughValues)) {
                        $assuranceFromCandidates = array_merge(
                            $assuranceFromCandidates,
                            $passthroughValues
                        );
                    }
                } elseif (is_array($val)) { // Regex with list of Assurance values
                    foreach ($state['Attributes'][$attribute] as $attributeValues) {
                        if (preg_match($key, $attributeValues) === 1) {
                            $assuranceFromCandidates = array_merge(
                                $assuranceFromCandidates,
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
                $idpMetadata = MetaDataStorageHandler::getMetadataHandler()->getMetaData(
                    $idpEntityId,
                    'saml20-idp-remote'
                );
            } else {
                $idpEntityId = $state['Source']['entityid'];
                $idpMetadata = $state['Source'];
            }

            foreach ($this->idpTagMap as $idpTag => $assuranceValues) {
                if (in_array($idpTag, $idpMetadata['tags'])) {
                    if (!empty($assuranceValues)) {
                        $assuranceFromCandidates = array_merge(
                            $assuranceFromCandidates,
                            $assuranceValues
                        );
                    }
                }
            }
        }

        $assuranceFromCandidates = array_unique($assuranceFromCandidates);

        Logger::debug(
            "[DynamicAssurance][process] Assurance Values: " . var_export($assuranceFromCandidates, true)
        );

        // Check the required Assurance values
        $appendDefault = true;
        if (!empty($this->minAssurance)) {
            $foundValues = array_intersect($assuranceFromCandidates, $this->minAssurance);
            $appendDefault = !empty($foundValues) ? false : true;
        }

        // Append the Default Assurance if the Assurance list is empty
        if (
            (!empty($this->defaultAssurance) && $appendDefault)
            || empty($assuranceFromCandidates)
        ) {
            $assuranceFromCandidates = array_merge($assuranceFromCandidates, $this->defaultAssurance);
        }
        // Remove any duplicates
        $assuranceFromCandidates = array_unique($assuranceFromCandidates);
        // Add Assurance into state
        if (!empty($assuranceFromCandidates)) {
            $state['Attributes'][$this->attribute] = $assuranceFromCandidates;
        }
    }
}
