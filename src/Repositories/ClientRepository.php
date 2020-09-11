<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\ClientEntity;
use AdvancedLearning\Oauth2Server\Models\Client;
use function hash_equals;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use const PHP_EOL;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true)
    {
        $client = Client::get()->filter([
           'Identifier' => $clientIdentifier
        ])->first();

        if ($mustValidateSecret && $client && !$client->validateSecret($clientSecret)) {
            $client = null;
        }

        return $client && $client->hasGrantType($grantType) ? new ClientEntity($clientIdentifier, $client->Title, 'something') : null;
    }
}
