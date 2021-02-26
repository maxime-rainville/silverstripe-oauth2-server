<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\ClientEntity;
use AdvancedLearning\Oauth2Server\Models\Client;
use function hash_equals;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use const PHP_EOL;

class ClientRepository implements ClientRepositoryInterface
{

    public function getClientEntity($clientIdentifier)
    {
        return Client::get()->filter([
           'Identifier' => $clientIdentifier
        ])->first();
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType)
    {
        $client = $this->getClientEntity($clientIdentifier);
        return $client && $client->hasGrantType($grantType) && $client->validateSecret($clientSecret);
    }
}
