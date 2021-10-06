# Flask-Multipass-CERN

This package provides the `cern` auth and identity providers for [Flask-Multipass][multipass].

These providers are only useful if you are at CERN and intend to use Flask-Multipass
with the new Keycloak-based CERN authentication infrastructure.

In its current state it also overkill if all you want to do is logging in via OIDC. If that's your
goal use the `authlib` multipass provider since Keycloak works perfectly fine with it.

In case you need access to arbitrary group membership information (e.g. for user-managed ACLs) and
the ability to search for CERN users, then this is a good choice for you.

## CERN usage details

The following permissions (requested through the application portal) are needed:

- Token exchange with `authorization-service-api` for basic login functionality
- Group membership in `authorization-service-groups-readers` for group functionality
- Group membership in `authorization-service-identity-readers` for user search functionality
- Tokens with group membership information (optional) - this needs to be requested directly from
  the authorization service team

Requesting them will most likely require you to have a professional justification.

## Performance

When using group membership or user search, the library need to get an "API access" token from
keycloak which typically takes 200-300ms. Set the `cache` key of the multipass identity
provider configuration to the import path of a Flask-Caching instance or a function returning such
an instance, or the instance itself to enable caching of tokens (until they expire) and group
data (30 minutes).

If group membership information is included in tokens, it will be cached during login so the extra
API call when checking whether a user is in a group won't be needed unless the cached data already
expired.

## Note

In applying the MIT license, CERN does not waive the privileges and immunities granted to it
by virtue of its status as an Intergovernmental Organization or submit itself to any jurisdiction.


[multipass]: https://github.com/indico/flask-multipass
