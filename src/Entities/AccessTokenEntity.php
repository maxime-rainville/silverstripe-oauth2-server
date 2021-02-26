<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use AdvancedLearning\Oauth2Server\Repositories\UserRepository;
use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
    use TokenEntityTrait, EntityTrait, AccessTokenTrait;

    /**
     * AccessTokenEntity constructor.
     *
     * @param null|string $userIdentifier The identifier of the user.
     * @param array       $scopes         The scopes to assign the user.
     */
    public function __construct(ClientEntityInterface $client, ?string $userIdentifier, array $scopes)
    {
        $this->setClient($client);
        $this->setUserIdentifier($userIdentifier);

        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }
    }


    protected function getUserEntity()
    {
        return (new UserRepository())->getUserEntityByIdentifier($this->getUserIdentifier());
    }
}
