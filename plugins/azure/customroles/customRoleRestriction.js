var async = require('async');
const msRestAzure = require("ms-rest-azure");
const AuthorizationManagementClient = require("azure-arm-authorization");

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Custom Role Restrictions',
    category: 'Custom Roles',
    description: 'Ensure that no custom subscription owner roles are created.',
    more_info: 'Immutable storage helps financial institutions and related industries--particularly broker-dealer organizations--to store data securely. It can also be leveraged in any scenario to protect critical data against deletion.',
    recommended_action: 'Classic subscription admin roles offer basic access management and include Account Administrator, Service Administrator, and Co-Administrators. It is recommended, to begin with, the least necessary permission, and add permissions as needed by the account holder.',
    link: 'https://docs.microsoft.com/en-us/azure/role-based-access-control/rbac-and-directory-admin-roles',
    apis: ['authorizationService:roleDefinitions'/*, 'authorizationService:customRolesList'*/],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var locations = helpers.locations(settings.govcloud);

        async.each(locations.AuthorizationService, function(location, rcb){
            var roleDefinitions = helpers.addSource(cache, source,
                ['authorizationService', 'roleDefinitions', location]);
            //
            // var getGroup = helpers.addSource(cache, source,
            //     ['iam', 'getGroup', region, group.GroupName]);

            if (!roleDefinitions) return rcb();

            if (roleDefinitions.err || !roleDefinitions.data) {
                helpers.addResult(results, 3,
                    'Unable to query Authorization Service: ' + helpers.addError(roleDefinitions), location);
                return rcb();
            }

            if (!roleDefinitions.data.entries.length) {
                helpers.addResult(results, 0, 'No existing role defination', location);
            } else {
                for (srvc in roleDefinitions.data.entries) {
                    var def = roleDefinitions.data.entries[srvc];

                    if (def.properties.type === 'CustomRole') {
						helpers.addResult(results, 3, 'Failed due to custom role found', location, def.name);
						return;
					}
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};