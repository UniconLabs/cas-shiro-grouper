package net.unicon.iamlabs.shirogrouper;

import edu.internet2.middleware.grouperClient.api.GcGetGroups;
import edu.internet2.middleware.grouperClient.api.GcGetPermissionAssignments;
import edu.internet2.middleware.grouperClient.ws.beans.WsGetGroupsResult;
import edu.internet2.middleware.grouperClient.ws.beans.WsGroup;
import edu.internet2.middleware.grouperClient.ws.beans.WsPermissionAssign;
import edu.internet2.middleware.grouperClient.ws.beans.WsSubjectLookup;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Shiro's <code>AuthorizingRealm</code> implementation that fetches groups from Grouper back-end data store for an authenticated Subject
 * and exposes them as this Subject's Shiro Roles, so then Shiro could be utilized for any authorization checks for this application.
 *
 * @author Dmitriy Kopylenko
 */
public class GrouperAuthorizingRealm extends AuthorizingRealm {


	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		final String subject = (String) principals.getPrimaryPrincipal();
		final SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

		//Add Grouper Groups as Shiro roles
		final GcGetGroups groupsClient = new GcGetGroups().addSubjectId(subject);
		for (WsGetGroupsResult groupsResult : groupsClient.execute().getResults()) {
			for (WsGroup group : groupsResult.getWsGroups()) {
				authorizationInfo.addRole(group.getName());
			}
		}

		//Add Grouper permission attributes as Shiro permissions
		GcGetPermissionAssignments permissionsClient = new GcGetPermissionAssignments().addSubjectLookup(new WsSubjectLookup(subject, null, null));
		for (WsPermissionAssign permission : permissionsClient.execute().getWsPermissionAssigns()) {
			final String perm = permission.getAttributeDefNameName().substring(permission.getAttributeDefNameName().indexOf(":") + 1)
					+ ":" + permission.getAction();
			authorizationInfo.addStringPermission(perm);
		}

		return authorizationInfo;
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		//This Realm is used only to fetch authorization info. Returning null signals to Shiro to ignore it during an authentication request.
		return false;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		//This Realm is used only for authorization, so it is safe to return null here.
		return null;
	}
}
