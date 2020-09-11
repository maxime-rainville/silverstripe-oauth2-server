<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\ScopeEntity;
use AdvancedLearning\Oauth2Server\Models\Client;
use AdvancedLearning\Oauth2Server\Models\Scope;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LogicException;
use SilverStripe\Security\Permission;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * {@inheritDoc}
     */
    public function getScopeEntityByIdentifier($identifier)
    {
        $codes = Permission::get_codes(false);
        if (isset($codes[$identifier])) {
            return new ScopeEntity($identifier);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function finalizeScopes(
        array $scopes,
        $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null
    ) {
        if ($grantType === 'client_credentials') {
            return $this->clientGrant($scopes, $clientEntity);
        }

        var_dump($grantType);

        // only check if we have a user, should a client have scopes?
        if (empty($userIdentifier)) {

        }

        $userEntity = (new UserRepository())->getUserEntityByIdentifier($userIdentifier);

        $approvedScopes = [];
        foreach ($scopes as $scope) {
            if ($userEntity->hasScope($scope->getIdentifier())) {
                $approvedScopes[] = $scope;
            }
        }
        return $approvedScopes;
    }

    /**
     * Build a list of valid scopes for a client credential grant.
     * @param array $scopes
     * @param ClientEntityInterface $clientEntity
     * @return array
     */
    private function clientGrant(array $scopes, ClientEntityInterface $clientEntity): array
    {
        /** @var Client $client */
        $client = Client::get()->filter('Identifier', $clientEntity->getIdentifier())->first();
        if (!$client) {
            throw new LogicException('Cannot finalizeScopes without a valid client.');
        }

        $allowedScopes = $client->Permissions()->map('Code', 'Code')->toArray();

        if (empty($scopes)) {
            // If no scopes are requested, return the default ones specified on the client.
            $scopes = array_map(function ($code) {
                return new ScopeEntity($code);
            }, $allowedScopes);
        } else {
            // If specific scopes are requested, make sure they are allowed by the client.
            $scopes = array_filter($scopes, function (ScopeEntityInterface $scope) use ($allowedScopes) {
                return isset($allowedScopes[$scope->getIdentifier()]);
            });
        }

        return $scopes;
    }
}
