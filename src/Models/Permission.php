<?php

namespace AdvancedLearning\Oauth2Server\Models;

use SilverStripe\ORM\DataObject;

/**
 * Represents a permission assigned to a Client.
 *
 * @property string Code
 * @property int Arg
 * @property int Type
 * @property int ParentID
 * @method Client Parent()
 */
class Permission extends DataObject
{

    // the (1) after Type specifies the DB default value which is needed for
    // upgrades from older SilverStripe versions
    private static $db = [
        "Code" => "Varchar(255)",
    ];

    private static $has_one = [
        "Parent" => Client::class,
    ];

    private static $indexes = [
        "Code" => true
    ];

    private static $table_name = "OauthPermission";

    /**
     * a list of permission codes which doesn't appear in the Permission list
     * when make the {@link PermissionCheckboxSetField}
     * @config
     * @var array;
     */
    private static $hidden_permissions = [];
}
