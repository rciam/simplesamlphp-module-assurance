# simplesamlphp-module-assurance
A SimpleSAMLphp module for determining and indicating the Level of Assurance (LoA) of an authentication event.
Specifically the module determines the LoA baced on:
* `candidates`, if the represented LoA attribute of the authenticating user contains any value of the allowed values, then the module will skip execution.
* `idpTags`, Identity Providers (IdPs) that are providing a higher level of assuranse for the authincating user can be marked, by adding the attribute `'tags' => array (0 => 'exampleTag',)` in the IdP's metadata in `saml20-idp-remote.php`.
* `idpPolicies`, if the 'eduPersonAssurance' attribute of the authenticating user contains any value of this list, then the user will grand higher LoA.
* `entitlements`, if the 'eduPersonEntitlement' attribute of the authenticating user contains any value of this list, then the user will grant higher LoA.

To this end, the LoA that the module will determine for the authnticating user, will be saved in the SAML 2 response.

## Module configuration
The following classes are needed to configure, in order to execute the module.
### DynamicAssurance
#### Configuration
The following authproc filter configuration options are supported:
  * `entitlementWhitelist`: Required, an array of strings containing values that can get higher assurance.
  * `attribute`: Optional, a string that defines the name of the attribute that will store the value of LoA. Defaults to `eduPersonAssurance`.
  * `candidates`: Optional, an array of strings that contains the allowed LoA values.
  * `defaultAssurance`: Optional, a string to use as the default value of LoA. Defaults to `https://www.example.org/low`.
  * `defaultElevatedAssurance`: Optional, a string to use as the default value of LoA. Defaults to `https://www.example.org/Substantial`.
  * `idpPolicies`: Optional, an array of stings that contains the allowed IdP Policies.
  * `idpTags`: Optional, an array of stings that contains the allowed IdP Tags.

#### Example
This filter should be configured on IdP:
- Specific for only one hosted IdP in `saml20-idp-hosted.php` or `shib13-idp-hosted.php`.
```
    authproc = array(
        ...
        40 => array(
            'class' => 'assurance:DynamicAssurance',
            'attribute' => 'eduPersonAssurance',
            'candidates' => array(
                'https://refeds.org/profile/sfa',
                'https://refeds.org/profile/mfa',
            ),
            'entitlementWhitelist' => array(
                'urn:mace:www.example.org:entitlement01',
                'urn:mace:www.example.org:entitlement02',
            ),
            'defaultAccurance' => 'https://example.org/LowAssurance',
            'defaultElevatedAssurance' => 'https://example.org/HighAssurance',
            'idpPolicies' => array(
                'example.org:policy01',
                'example.org:policy02',
            ),
            'idpTags' => array(
                'exampleTag01',
                'exampleTag02',
            ),
        ),
```
### IdPAuthnContextClassRef
#### Configuration
The following authproc filter configuration options are supported:
  * `attribute`: Optional, a string, the name of the LoA attribute which will be added in the SAML response. Defaults to `eduPersonAssurance`. Note: Sould be the same value with the 'attribute' of `DynamicAssurance` class.
  * `assuranceWhitelist`: Optional, an array of strings that contains the allowed LoA values.

#### Example
This filter should be configured on the IdP:
- Specific for only one hosted IdP in `saml20-idp-hosted.php` or `shib13-idp-hosted.php`
- Specific for only one remote SP in `saml20-sp-remote.php` or `shib13-sp-remote.php`

```
    authproc = array(
        ...
        41 => array(
            'class' => 'assurance:IdPAuthnContextClassRef',
            'attribute' => 'assuranceAttribute',
            'assuranceWhitelist' => array(
                'https://refeds.org/profile/sfa',
                'https://refeds.org/profile/mfa',
            ),
        ),
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
- Specific for only the SP in `authsources.php`
- Specific for only one remote IdP in `saml20-idp-remote.php` or `shib13-idp-remote.php`

```
    authproc = array(
        ...
        80 => array(
            'class' => 'assurance:SPAuthnContextClassRef',
            'attribute' => 'sp:AuthnContext',
        ),
```
## Compatibility matrix
This table matches the module version with the supported SimpleSAMLphp version.
| Module |  SimpleSAMLphp |
|:------:|:--------------:|
| v1.x   | v1.14          |

## License
Licensed under the Apache 2.0 license, for details see `LICENSE`.
