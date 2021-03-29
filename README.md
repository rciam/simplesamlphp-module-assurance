# simplesamlphp-module-assurance

A SimpleSAMLphp module for determining and indicating the Level of Assurance (LoA) of an authentication event.

To this end, the LoA that the module will determine for the authnticating user, will be saved in the SAML 2 response.

## Module configuration

The following classes are needed to configure, in order to execute the module.

### DynamicAssurance

This filter evaluates the assurance values based on specific attribute mapping rules. The evaluation process can optionally take into account the tag(s) of the authenticating Identity Provider.

#### Configuration

The following authproc filter configuration options are supported:

* `attribute`: _Optional_, a string that defines the name of the attribute that will store the value of LoA. Defaults to `eduPersonAssurance`.
* `attributeMap`: _Optional_,  a map whose keys identify attribute names whose values can be mapped to assurance values. For each identified attribute, you can specify an array of values that will be treated as literal strings for exact matching. It is also possible to use the `pregMatch` key for defining a list of regular expressions that will be matched against the attribute values. For each matching value, the filter appends the specified assurance values to the assurance attribute. Defaults to

```php
    $attributeMap = [
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
```

:warning: The configured Assurance Map array is merged recursively with the default one from above.

* `defaultAssurance`: _Optional_, an array containing assurance values to set by default when no assurance information is available or none of the required assurance values is present (see `minAssurance`). No assurance values are added by default.
* `minAssurance`: _Optional_, an array containing required assurance values. No assurance values are required. When specified, at least one of the specified assurance values in the array MUST be present, otherwise the default assurance values will be assigned (see `defaultAssurance`).
* `idpTagMap`: _Optional_, a map whose `keys` identify IdP Tags which can be mapped to assurance values. If the metadata of the user's authenticating IdP contain any of the specified tags, then the filter will append these values to the assurance attribute.

#### Example

This filter should be configured on IdP:

* Specific for only one hosted IdP in `saml20-idp-hosted.php` or `shib13-idp-hosted.php`.

```php
    authproc = [
        ...
        40 => [
            'class' => 'assurance:DynamicAssurance',
            'attribute' => 'eduPersonAssurance',
            'assuranceMap' => [
                'eduPersonAssurance' => [
                    '1.2.840.113612.5.2.2.1' => [                    // Classic
                        'https://example.org/profile/Assurance/Low',
                    ],
                    '1.2.840.113612.5.2.2.5' => [                    // MICS
                        'https://example.org/profile/Assurance/High',
                    ],
                    'pregMatch' => [
                        '/^https:\/\/example\.org\/assurance/m',          // Pass Through values
                    ],
                ],
                'eduPersonEntitlement' => [
                    'vo_test:IdP Proxy test' => [
                        'https://example.org/LoA#AssuranceHigh',
                    ],
                    'vo_test2:IdP Proxy test2' => [
                        'https://example.org/LoA#AssuranceLow',
                    ],
                ],
                // The Attribute maps to an assurance level. All Assurance values must be underneath the key zero(0)
                'voPersonVerifiedEmail' => [
                    'pregMatch' => [
                        '/^.+$/m' => [
                            'https://example.org/LoA#AssuranceLow',
                        ],
                    ],
                ],
            ],
            'defaultAssurance' => [
                'https://example.org/LowAssurance'
            ],
            'minAssurance' => [
                'https://example.org/LowAssurance'
            ],
            'idpTagMap' => [
                'exampleTag01' => [
                    'https://example.org/HighAssurance'
                ],
                'exampleTag02' => [
                    'https://example-other.org/HighAssurance'
                ],
            ],
        ],
```

### IdPAuthnContextClassRef

#### Configuration

The following authproc filter configuration options are supported:

* `attribute`: Optional, a string, the name of the LoA attribute which will be added in the SAML response. Defaults to `eduPersonAssurance`. Note: Could be the same value with the 'attribute' of `DynamicAssurance` class.
* `assuranceWhitelist`: Optional, an array of strings that contains the allowed LoA values.

#### Example

This filter should be configured on the IdP:

* Specific for only one hosted IdP in `saml20-idp-hosted.php` or `shib13-idp-hosted.php`
* Specific for only one remote SP in `saml20-sp-remote.php` or `shib13-sp-remote.php`

```php
    authproc = [
        ...
        41 => [
            'class' => 'assurance:IdPAuthnContextClassRef',
            'attribute' => 'assuranceAttribute',
            'assuranceWhitelist' => [
                'https://refeds.org/profile/sfa',
                'https://refeds.org/profile/mfa',
            ],
        ],
```

### SPAuthnContextClassRef

#### Configuration

The following authproc filter configuration options are supported:

* `entitlements`: Required, an array of strings containing values that can get higher assurance.
* `attribute`: Optional, a string that will be used as the name of the LoA attribute. Defaults to `eduPersonAssurance`.
* `default`: Optional, a string to use as the default value of LoA. Defaults to `https://www.example.org/low`.
* `attribute`: Optional, a strings that defines the name of the attribute that will store the value of LoA. Defaults to `eduPersonAssurance`.
* `candidates`: Optional, an array of strings that contains the allowed LoA values.

#### Example

This filter should be configured on the SP:

* Specific for only the SP in `authsources.php`
* Specific for only one remote IdP in `saml20-idp-remote.php` or `shib13-idp-remote.php`

```php
    authproc = [
        ...
        80 => [
            'class' => 'assurance:SPAuthnContextClassRef',
            'attribute' => 'sp:AuthnContext',
        ],
```

## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.
| Module | SimpleSAMLphp |
|:------:|:-------------:|
|  v1.x  |     v1.14     |

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
