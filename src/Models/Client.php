<?php

namespace AdvancedLearning\Oauth2Server\Models;

use AdvancedLearning\Oauth2Server\DBSecret;
use AdvancedLearning\Oauth2Server\Form\PermissionCheckboxSetField;
use Faker\Provider\Text;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\PasswordField;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\ArrayList;
use SilverStripe\ORM\DataList;
use SilverStripe\Security\Member;
use SilverStripe\Versioned\Versioned;
use function base64_encode;
use SilverStripe\ORM\DataObject;

/**
 * Stores ClientEntity information.
 *
 * @package AdvancedLearning\Oauth2Server\Models
 *
 * @property string $Title
 * @property string $Identifier
 * @property int $CreatorID
 * @property int $RevokerID
 * @method DataList Permissions()
 */
class Client extends DataObject implements ClientEntityInterface
{

    const SESSION_SECRET_KEY = 'OAuthClientSecret';

    private static $table_name = 'OauthClient';

    private static $db = [
        'Title' => 'Varchar(100)',
        'Identifier' => 'Varchar(255)',
        'Secret' => DBSecret::class,
        'State' => 'Enum("Active,Expired,Revoke", "Active")'
    ];

    private static $indexes = [
        'Identifier' => 'unique'
    ];

    private static $has_many = [
        'Permissions' => Permission::class
    ];

    private static $summary_fields = [
        'Title'
    ];

    private static $extensions = [
        Versioned::class . '.versioned',
    ];

    private static $identifier_prefix = 'ss-';

    /**
     * @var string Temporarily holds the plain text secret to display once to the user.
     */
    private $plaintextSecret;

    /**
     * Checks whether this ClientEntity has the given grant type.
     *
     * @param string $grantType The grant type to check.
     *
     * @return boolean
     */
    public function hasGrantType($grantType)
    {
        return $grantType === 'client_credentials';
    }

    /**
     * On before write. Generate a secret if we don't have one.
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();

        $this->plaintextSecret = '';

        if (!$this->isInDB()) {
            $this->plaintextSecret = $this->dbObject('Secret')->generate($this);
            $this->Identifier = uniqid(static::config()->get('identifier_prefix'));
        }
    }

    public function onAfterWrite()
    {
        parent::onAfterWrite();

        if ($this->plaintextSecret) {
            $request = Injector::inst()->get(HTTPRequest::class);
            $session = $request->getSession();
            // Need to double check storing the secret in the session in between request is safe
            $session->set(self::SESSION_SECRET_KEY, [$this->Identifier => $this->plaintextSecret]);
        }
    }

    public function getCMSFields()
    {
        $fields = parent::getCMSFields();

        $fields->removeByName('Permissions');

        $fields->addFieldToTab('Root.Main', $permissionsField = PermissionCheckboxSetField::create(
            'Permissions',
            false,
            Permission::class,
            'ParentID'
        ));

        $fields->dataFieldByName('Title')->setAttribute('required', 'required');

        if ($this->isInDB()) {
            $permissionsField->setRecord(ArrayList::create([$this]));
            if ($secret = $this->retrievePlaintextSecret()) {
                $secretField = TextField::create('SecretPlaceHolder', 'Secret', $secret)->setDescription(
                    'You can only view this value once. Copy it now or you will have to generate a new client.'
                );
            } else {
                $secretField = TextField::create('SecretPlaceHolder', 'Secret', '*********');
            }
            $fields->replaceField('Secret', $secretField);
            $fields = $fields->makeReadonly();
        } else {
            $fields->removeByName('Secret');
            $fields->removeByName('Identifier');
            $fields->removeByName('State');
        }

        return $fields;
    }

    public function validate()
    {
        $results = parent::validate();

        if (empty(trim($this->Title))) {
            $results->addFieldError('Title', 'Field is required');
        }

        return $results;
    }

    /**
     * Retrieve a plain text secret from the session.
     * @return string
     */
    private function retrievePlaintextSecret(): string
    {
        $request = Injector::inst()->get(HTTPRequest::class);
        $session = $request->getSession();
        // Need to double check storing the secret in the session in between request is safe
        $secretData = $session->get(self::SESSION_SECRET_KEY);
        if ($secretData) {
            $session->clear(self::SESSION_SECRET_KEY);
            return $secretData[$this->Identifier] ?? '';
        }

        return '';
    }

    /**
     * Validate that the provided secret matches our stored hash.
     * @param string $secret
     * @return bool
     * @throws \SilverStripe\Security\PasswordEncryptor_NotFoundException
     */
    public function validateSecret(string $secret): bool
    {
        /** @var DBSecret $dbField */
        $dbField = $this->dbObject('Secret');
        return $dbField->validate($secret);
    }

//    public function canDelete($member = null)
//    {
//        // No user is ever allowed to delete a client.
//        return false;
//    }

//    public function canEdit($member = null)
//    {
//        // No user is ever allowed to delete a client.
//        return false;
//    }

    public function getIdentifier()
    {
        return $this->getField('Identifier');
    }

    public function getName()
    {
        $this->getTitle();
    }

    public function getRedirectUri()
    {
        return '';
    }

    public function isConfidential()
    {
        return true;
    }
}
