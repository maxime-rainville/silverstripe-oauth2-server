<?php

namespace AdvancedLearning\Oauth2Server\Form;


/**
 * Extends the default PermissionCheckboxSetField to supress the ADMIN permission. API keys should never have
 * blanket permissions.
 */
class PermissionCheckboxSetField extends \SilverStripe\Security\PermissionCheckboxSetField
{

    /**
     * Prevent some permissions from being picked for Client and API keys
     * @var string[]
     * @config
     */
    private static $disallowed_permission_codes = ['ADMIN'];

    public function __construct($name, $title, $managedClass, $filterField)
    {
        parent::__construct($name, $title, $managedClass, $filterField);
        $this->removePermissions();
    }

    private function removePermissions(): void
    {
        /**
         * $source is a multi dimensional array of permission in the following format:
         * ```
         * [
         *   'Administrator' => [
         *     'ADMIN' => [ ... ]
         *   ],
         *   'CMS Access' => [
         *     'CMS_ACCESS_LeftAndMain' => [ ... ],
         *     'CMS_ACCESS_CMSMain' => [ ... ],
         *     ...
         *   ],
         *   ...
         * ]
         * ```
         *
         * First, we want to remove all dissallowed permission code. Then we want to remove all empty cateogries.
         */
        $source = $this->source;

        $dissallowed = static::config()->get('disallowed_permission_codes');
        if (empty($dissallowed)) {
            return;
        }


        foreach ($source as $group => &$permissions) {
            foreach($dissallowed as $dissallowedKey) {
                unset($permissions[$dissallowedKey]);
            }
        }

        ;

        $this->source = array_filter($source);
    }

    public function setRecord($record) {
        $this->records = $record;
    }

}
