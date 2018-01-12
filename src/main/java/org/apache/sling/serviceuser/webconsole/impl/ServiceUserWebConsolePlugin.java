/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.serviceuser.webconsole.impl;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.jcr.AccessDeniedException;
import javax.jcr.Property;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.nodetype.NodeType;
import javax.jcr.query.Query;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.felix.webconsole.SimpleWebConsolePlugin;
import org.apache.felix.webconsole.WebConsoleConstants;
import org.apache.felix.webconsole.WebConsoleUtil;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.ModifiableValueMap;
import org.apache.sling.api.resource.PersistenceException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceUtil;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.serviceusermapping.Mapping;
import org.apache.sling.serviceusermapping.ServiceUserMapper;
import org.apache.sling.xss.XSSAPI;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Web console plugin to test configuration resolution.
 */
@Component(service = Servlet.class, property = {
		Constants.SERVICE_DESCRIPTION + "=Apache Sling Service User Manager Web Console Plugin",
		WebConsoleConstants.PLUGIN_LABEL + "=" + ServiceUserWebConsolePlugin.LABEL,
		WebConsoleConstants.PLUGIN_TITLE + "=" + ServiceUserWebConsolePlugin.TITLE,
		WebConsoleConstants.PLUGIN_CATEGORY + "=Sling" })
@SuppressWarnings("serial")
public class ServiceUserWebConsolePlugin extends SimpleWebConsolePlugin {

	public ServiceUserWebConsolePlugin() {
		super(LABEL, TITLE, "Sling", new String[0]);
	}

	public static final String COMPONENT_NAME = "org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended";
	public static final String LABEL = "serviceusers";
	public static final String TITLE = "Service Users";

	public static final String PN_ACTION = "action";
	public static final String PN_ALERT = "alert";
	public static final String PN_APP_PATH = "appPath";
	public static final String PN_BUNDLE = "bundle";
	public static final String PN_NAME = "name";
	public static final String PN_SUB_SERVICE = "subService";
	public static final String PN_USER = "user";
	public static final String PN_USER_PATH = "userPath";

	private static final Logger log = LoggerFactory.getLogger(ServiceUserWebConsolePlugin.class);

	private BundleContext bundleContext;

	@Reference(policyOption = ReferencePolicyOption.GREEDY)
	private XSSAPI xss;

	@Reference
	private ServiceUserMapper mapper;

	private boolean createOrUpdateMapping(HttpServletRequest request, ResourceResolver resolver) {

		String appPath = getParameter(request, PN_APP_PATH, "");

		Iterator<Resource> configs = resolver.findResources("SELECT * FROM [sling:OsgiConfig] WHERE ISDESCENDANTNODE(["
				+ appPath + "]) AND NAME() LIKE '" + COMPONENT_NAME + "%'", Query.JCR_SQL2);

		try {
			boolean dirty = false;
			Resource config = null;
			if (configs.hasNext()) {

				config = configs.next();
				log.debug("Using existing configuration {}", config);
			} else {
				String path = appPath + "/config/" + COMPONENT_NAME + "-" + appPath.substring(appPath.lastIndexOf('/'));
				log.debug("Creating new configuration {}", path);
				config = ResourceUtil.getOrCreateResource(resolver, path, new HashMap<String, Object>() {
					{
						put(Property.JCR_PRIMARY_TYPE, "sling:OsgiConfig");
					}
				}, NodeType.NT_FOLDER, false);
				dirty = true;
			}

			String bundle = getParameter(request, PN_BUNDLE, "");
			String subService = getParameter(request, PN_SUB_SERVICE, "");
			String name = getParameter(request, PN_NAME, "");
			String mapping = bundle + (StringUtils.isNotBlank(subService) ? ":" + subService : "") + "=" + name;

			ModifiableValueMap properties = config.adaptTo(ModifiableValueMap.class);
			String[] mappings = properties.get("user.mapping", new String[0]);
			if (!ArrayUtils.contains(mappings, mapping)) {
				log.debug("Adding {} into service user mapping", mapping);
				List<String> m = new ArrayList<String>();
				m.addAll(Arrays.asList(mappings));
				m.add(mapping);
				properties.put("user.mapping", m.toArray(new String[m.size()]));
				dirty = true;
			} else {
				log.debug("Already found {} in service user mapping", mapping);
			}
			if (dirty) {
				log.debug("Saving changes to osgi config");
				resolver.commit();
			}
		} catch (PersistenceException e) {
			log.warn("Exception creating service mapping", e);
			return false;
		}

		return true;
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		log.debug("Creating service user");

		if (StringUtils.isBlank(getParameter(request, PN_NAME, ""))
				|| StringUtils.isBlank(getParameter(request, PN_BUNDLE, ""))
				|| StringUtils.isBlank(getParameter(request, PN_APP_PATH, ""))) {
			sendErrorRedirect(request, response, "Missing required parameters!");
			return;
		}

		ResourceResolver resolver = getResourceResolver(request);
		if (resolver == null) {
			log.warn("Unable to get serviceresolver from request!");
			sendErrorRedirect(request, response, "Unable to get serviceresolver from request!");
			return;
		} else {
			Resource userResource = getOrCreateServiceUser(request, resolver);
			if (userResource == null) {
				log.warn("Unable to create service user!");
				sendErrorRedirect(request, response, "Unable to create service user!");
				return;
			} else {
				if (createOrUpdateMapping(request, resolver)) {
					if (updatePrivileges(request, resolver)) {
						List<String> params = new ArrayList<String>();
						params.add(PN_ACTION + "=" + "details");
						params.add(PN_ALERT + "="
								+ URLEncoder.encode(
										"Service user " + userResource.getName() + " created / updated successfully!",
										"UTF-8"));
						params.add(PN_USER + "=" + URLEncoder.encode(userResource.getName(), "UTF-8"));

						WebConsoleUtil.sendRedirect(request, response,
								"/system/console/" + LABEL + "?" + StringUtils.join(params, "&"));
					} else {
						sendErrorRedirect(request, response, "Unable to update service user permissions!");
					}
				} else {
					sendErrorRedirect(request, response, "Unable to create service user mapping!");
				}
			}
		}

	}

	private boolean updatePrivileges(HttpServletRequest request, ResourceResolver resolver) {

		List<Pair<String, String>> privileges = this.getPrivileges(request);
		String name = getParameter(request, PN_NAME, "");

		List<String> currentPolicies = new ArrayList<String>();
		findACLs(resolver, name, currentPolicies);
		for (int i = 0; i < currentPolicies.size(); i++) {
			String path = StringUtils.substringBefore(currentPolicies.get(i), "/rep:policy");
			currentPolicies.set(i, StringUtils.isNotBlank(path) ? path : "/");
		}
		log.debug("Loaded current policy paths: {}", currentPolicies);

		Map<String, List<String>> toSet = new HashMap<String, List<String>>();
		for (Pair<String, String> privilege : privileges) {
			if (!toSet.containsKey(privilege.getKey())) {
				toSet.put(privilege.getKey(), new ArrayList<String>());
			}
			toSet.get(privilege.getKey()).add(privilege.getValue());
		}
		log.debug("Loaded updated policy paths: {}", currentPolicies);

		String lastEntry = null;

		try {

			Session session = resolver.adaptTo(Session.class);
			AccessControlManager accessManager = session.getAccessControlManager();
			PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);

			for (Entry<String, List<String>> pol : toSet.entrySet()) {
				lastEntry = pol.getKey();
				currentPolicies.remove(pol.getKey());
				log.debug("Updating policies for {}", pol.getKey());

				AccessControlPolicy[] policies = accessManager.getPolicies(pol.getKey());
				List<String> toRemove = new ArrayList<String>();
				for (AccessControlPolicy p : policies) {
					if (p instanceof AccessControlList) {
						AccessControlList policy = (AccessControlList) p;
						for (AccessControlEntry entry : policy.getAccessControlEntries()) {
							Principal prin = entry.getPrincipal();
							if (prin.getName().equals(name)) {
								for (Privilege privilege : entry.getPrivileges()) {
									if (!pol.getValue().contains(privilege.getName())) {
										log.debug("Removing privilege {}", privilege);
										toRemove.add(privilege.getName());
									}
								}
							}
						}
					}
				}
				Principal principal = principalManager.getPrincipal(name);
				AccessControlUtil.replaceAccessControlEntry(session, pol.getKey(), principal,
						pol.getValue().toArray(new String[pol.getValue().size()]), new String[0],
						toRemove.toArray(new String[toRemove.size()]), null);
			}
			session.save();

			for (String oldPolicy : currentPolicies) {
				boolean removed = false;
				log.debug("Removing policy for {}", oldPolicy);
				AccessControlPolicy[] policies = accessManager.getPolicies(oldPolicy);
				AccessControlEntry toRemove = null;
				for (AccessControlPolicy p : policies) {
					if (p instanceof AccessControlList) {
						AccessControlList policy = (AccessControlList) p;
						for (AccessControlEntry entry : policy.getAccessControlEntries()) {
							Principal prin = entry.getPrincipal();
							if (prin.getName().equals(name)) {
								toRemove = entry;
								break;
							}
						}
						if (toRemove != null) {
							removed = true;
							policy.removeAccessControlEntry(toRemove);
							accessManager.setPolicy(oldPolicy, policy);
							session.save();
							log.debug("Removed access control entry {}", toRemove);
						}
					}
				}
				if (!removed) {
					log.warn("No policy found for {}", oldPolicy);
				}
			}
		} catch (RepositoryException e) {
			log.error("Exception updating principals with {}, failed on {}", toSet, lastEntry, e);
			return false;
		}

		return true;
	}

	private List<String> extractPrincipals(Mapping mapping) {
		List<String> principals = new ArrayList<String>();
		String userName = mapping.map(mapping.getServiceName(), mapping.getSubServiceName());
		if (StringUtils.isNotBlank(userName)) {
			principals.add(userName);
		}
		Iterable<String> ps = mapping.mapPrincipals(mapping.getServiceName(), mapping.getSubServiceName());
		if (ps != null) {
			for (String principal : ps) {
				principals.add(principal);
			}
		}
		return principals;
	}

	private String[] findACLs(ResourceResolver resolver, String name, List<String> affectedPaths) {
		List<String> acls = new ArrayList<String>();

		Iterator<Resource> aclResources = resolver.findResources(
				"SELECT * FROM [rep:GrantACE] AS s WHERE  [rep:principalName] = '" + name + "'", Query.JCR_SQL2);
		while (aclResources.hasNext()) {
			Resource aclResource = aclResources.next();
			affectedPaths.add(aclResource.getPath());
			ValueMap properties = aclResource.adaptTo(ValueMap.class);
			String acl = aclResource.getPath().substring(0, aclResource.getPath().indexOf("/rep:policy")) + "="
					+ StringUtils.join(properties.get("rep:privileges", String[].class), ",");
			acls.add(acl);
		}
		return acls.toArray(new String[acls.size()]);
	}

	private Bundle findBundle(String symbolicName, Map<String, Bundle> bundles) {
		if (bundles.isEmpty()) {
			for (Bundle bundle : bundleContext.getBundles()) {
				bundles.put(bundle.getSymbolicName(), bundle);
			}
		}
		return bundles.get(symbolicName);
	}

	private Object findConfigurations(ResourceResolver resolver, String name, List<String> affectedPaths) {
		List<String> configurations = new ArrayList<String>();

		Iterator<Resource> configResources = resolver.findResources(
				"SELECT * FROM [sling:OsgiConfig] AS s WHERE (ISDESCENDANTNODE([/apps]) OR ISDESCENDANTNODE([/libs])) AND NAME(s) LIKE 'org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended%' AND [user.mapping] LIKE '%="
						+ name + "'",
				Query.JCR_SQL2);
		while (configResources.hasNext()) {
			Resource configResource = configResources.next();
			affectedPaths.add(configResource.getPath());
			configurations.add(configResource.getPath());
		}
		configResources = resolver.findResources(
				"SELECT * FROM [nt:file] AS s WHERE (ISDESCENDANTNODE([/apps]) OR ISDESCENDANTNODE([/libs])) AND NAME(s) LIKE 'org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended%' AND [jcr:content/jcr:data] LIKE '%="
						+ name + "%'",
				Query.JCR_SQL2);
		while (configResources.hasNext()) {
			Resource configResource = configResources.next();
			affectedPaths.add(configResource.getPath());
			configurations.add(configResource.getPath());
		}

		return configurations.toArray();
	}

	private String[] findMappings(ResourceResolver resolver, String name) {
		List<String> mappings = new ArrayList<String>();
		for (Mapping map : mapper.getActiveMappings()) {
			if (name.equals(map.map(map.getServiceName(), map.getSubServiceName())) || hasPrincipal(map, name)) {
				mappings.add(map.getServiceName()
						+ (map.getSubServiceName() != null ? (":" + map.getSubServiceName()) : ""));
			}
		}
		return mappings.toArray(new String[mappings.size()]);
	}

	private Collection<String> getBundles() {
		List<String> bundles = new ArrayList<String>();
		for (Bundle bundle : bundleContext.getBundles()) {
			bundles.add(bundle.getSymbolicName());
		}
		Collections.sort(bundles);
		return bundles;
	}

	private Resource getOrCreateServiceUser(HttpServletRequest request, ResourceResolver resolver) {

		final String name = getParameter(request, PN_NAME, "");

		Session session = resolver.adaptTo(Session.class);
		try {
			UserManager userManager = AccessControlUtil.getUserManager(session);
			if (userManager.getAuthorizable(name) != null) {
				Authorizable user = userManager.getAuthorizable(name);
				log.debug("Using existing user: {}", user);
				return resolver.getResource(user.getPath());
			} else {

				final String userPath = getParameter(request, PN_USER_PATH, "system");

				log.debug("Creating new user with name {} and intermediate path {}", name, userPath);

				User user = userManager.createSystemUser(name, userPath);
				session.save();

				String path = "/home/users/" + userPath + "/" + name;
				log.debug("Moving {} to {}", user.getPath(), path);
				session.getWorkspace().move(user.getPath(), path);
				session.save();

				return resolver.getResource(path);
			}
		} catch (RepositoryException e) {
			log.warn("Exception getting / creating service user {}", name, e);
			try {
				session.refresh(false);
			} catch (RepositoryException e1) {
				log.error("Unexpected exception reverting changes", e1);
			}
		}
		return null;
	}

	private String getParameter(final HttpServletRequest request, final String name, final String defaultValue) {
		String value = request.getParameter(name);
		if (value != null && !value.trim().isEmpty()) {
			return value.trim();
		}
		return defaultValue;
	}

	private ResourceResolver getResourceResolver(HttpServletRequest request) {
		ResourceResolver resolver = (ResourceResolver) request
				.getAttribute("org.apache.sling.auth.core.ResourceResolver");
		return resolver;
	}

	private boolean hasPrincipal(Mapping map, String name) {
		Iterable<String> principals = map.mapPrincipals(map.getServiceName(), map.getSubServiceName());
		if (principals != null) {
			for (String principal : principals) {
				if (principal.equals(name)) {
					return true;
				}
			}
		}
		return false;
	}

	private void info(PrintWriter pw, String text) {
		pw.print("<p class='statline ui-state-highlight'>");
		pw.print(xss.encodeForHTML(text));
		pw.println("</p>");
	}

	private void infoDiv(PrintWriter pw, String text) {
		if (StringUtils.isBlank(text)) {
			return;
		}
		pw.println("<div>");
		pw.print("<span style='float:left'>");
		pw.print(xss.encodeForHTML(text));
		pw.println("</span>");
		pw.println("</div>");
	}

	@Activate
	protected void init(ComponentContext context) {
		this.bundleContext = context.getBundleContext();
	}

	private void printPrincipals(List<Mapping> activeMappings, PrintWriter pw) {
		List<Pair<String, Mapping>> mappings = new ArrayList<Pair<String, Mapping>>();
		for (Mapping mapping : activeMappings) {
			for (String principal : extractPrincipals(mapping)) {
				mappings.add(new ImmutablePair<String, Mapping>(principal, mapping));
			}
		}
		Collections.sort(mappings, new Comparator<Pair<String, Mapping>>() {
			@Override
			public int compare(Pair<String, Mapping> o1, Pair<String, Mapping> o2) {
				if (o1.getKey().equals(o2.getKey())) {
					return o1.getValue().getServiceName().compareTo(o2.getValue().getServiceName());
				} else {
					return o1.getKey().compareTo(o2.getKey());
				}
			}
		});

		for (Pair<String, Mapping> mapping : mappings) {
			tableRows(pw);
			pw.println("<td><a href=\"/system/console/serviceusers?action=details&amp;user="
					+ xss.encodeForHTML(mapping.getKey()) + "\">" + xss.encodeForHTML(mapping.getKey()) + "</a></td>");

			Map<String, Bundle> bundles = new HashMap<String, Bundle>();
			Bundle bundle = findBundle(mapping.getValue().getServiceName(), bundles);
			if (bundle != null) {
				bundleContext.getBundle();
				pw.println("<td><a href=\"/system/console/bundles/" + bundle.getBundleId() + "\">"
						+ xss.encodeForHTML(
								bundle.getHeaders().get(Constants.BUNDLE_NAME) + " (" + bundle.getSymbolicName())
						+ ")</a></td>");
				pw.println("<td>" + xss.encodeForHTML(mapping.getValue().getSubServiceName()) + "</td>");
			} else {
				bundleContext.getBundle();
				pw.println("<td>" + xss.encodeForHTML(mapping.getValue().getServiceName()) + "</td>");
				pw.println("<td>" + xss.encodeForHTML(
						mapping.getValue().getSubServiceName() != null ? mapping.getValue().getSubServiceName() : "")
						+ "</td>");
			}
		}

	}

	private void printServiceUserDetails(HttpServletRequest request, PrintWriter pw)
			throws AccessDeniedException, UnsupportedRepositoryOperationException, RepositoryException {
		String name = getParameter(request, PN_USER, "");

		tableStart(pw, "Details for " + name, 2);

		ResourceResolver resolver = getResourceResolver(request);

		List<String> affectedPaths = new ArrayList<String>();
		td(pw, "Service User Name");
		td(pw, name);

		tableRows(pw);

		td(pw, "User Path");
		Session session = resolver.adaptTo(Session.class);
		UserManager userManager = AccessControlUtil.getUserManager(session);
		if (userManager.getAuthorizable(name) != null) {
			Authorizable user = userManager.getAuthorizable(name);
			td(pw, user.getPath());
			affectedPaths.add(user.getPath());
		}

		tableRows(pw);

		String[] mappings = findMappings(resolver, name);
		td(pw, "Mappings");
		td(pw, mappings);

		tableRows(pw);

		td(pw, "OSGi Configurations");
		td(pw, findConfigurations(resolver, name, affectedPaths));

		tableRows(pw);

		td(pw, "ACLs");
		td(pw, findACLs(resolver, name, affectedPaths));

		tableEnd(pw);

		pw.write("<br/>");

		pw.write("<h3>Example Filter</h3>");

		pw.write("<br/>");

		pw.write("<pre><code>&lt;workspaceFilter version=\"1.0\"&gt;<br/>");
		for (String affectedPath : affectedPaths) {
			pw.write("  &lt;filter root=\"" + affectedPath + "\" /&gt;<br/>");
		}
		pw.write("&lt;/workspaceFilter\"&gt</code></pre>");

		pw.write("<br/>");

		pw.write("<h3>Use Example(s)</h3>");

		pw.write("<br/>");

		pw.write("<pre><code>");

		boolean includeNonSubService = false;
		for (String mapping : mappings) {
			if (mapping.contains(":")) {
				String subService = StringUtils.substringAfter(mapping, ":");
				pw.write("// Example using Sub Service " + subService
						+ "<br/>ResourceResolver resolver = resolverFactory.getServiceResourceResolver(new HashMap<String, Object>() {<br/>  private static final long serialVersionUID = 1L;<br/>  {<br/>    put(ResourceResolverFactory.SUBSERVICE,\""
						+ subService + "\");<br/>  }<br/>});<br/><br/>");
			} else {
				includeNonSubService = true;
			}
		}
		if (includeNonSubService) {
			pw.write(
					"// Example using bundle authentication<br/>ResourceResolver resolver = resolverFactory.getServiceResourceResolver(null);");
		}
		pw.write("</code></pre>");
	}

	private void printServiceUsers(HttpServletRequest request, PrintWriter pw) {

		try {

			pw.println("<form method='post' action='/system/console/serviceusers'>");

			tableStart(pw, "Create Service User", 2);

			String name = getParameter(request, PN_NAME, "");
			textField(pw, "Service User Name", PN_NAME, name,
					"The name of the service user to create, can already exist");

			tableRows(pw);
			String userContextPath = getParameter(request, PN_USER_PATH, "");
			textField(pw, "Intermediate Path", PN_USER_PATH, userContextPath,
					"Optional: The intermediate path under which to create the user. Should start with system, e.g. system/myapp");

			tableRows(pw);
			String bundle = getParameter(request, PN_BUNDLE, "");
			selectField(pw, "Bundle", PN_BUNDLE, bundle, getBundles(),
					"The bundle from which this service user will be useable");

			tableRows(pw);
			String serviceName = getParameter(request, PN_SUB_SERVICE, "");
			textField(pw, "Sub Service Name", PN_SUB_SERVICE, serviceName,
					"Optional: Allows for different permissions for different services within a bundle");

			tableRows(pw);
			String appPath = getParameter(request, PN_APP_PATH, "");
			textField(pw, "Application Path", PN_APP_PATH, appPath,
					"The application under which to create the OSGi Configuration for the Service User Mapping, e.g. /apps/myapp");

			tableRows(pw);

			List<Pair<String, String>> privileges = getPrivileges(request);
			printPrivilegeSelect(pw, "ACLs", privileges, getSupportedPrivileges(request),
					"Set the privileges for this service user");

			tableRows(pw);

			pw.println("<td></td>");
			pw.println("<td><input type='submit' value='Create / Update'/></td>");
			tableEnd(pw);

			pw.println("</form>");

			pw.println("<br/><br/>");

			// Service Users
			List<Mapping> activeMappings = mapper.getActiveMappings();
			tableStart(pw, "Active Service Users", 3);
			pw.println("<th>Name</th>");
			pw.println("<th>Bundle</th>");
			pw.println("<th>SubService</th>");
			printPrincipals(activeMappings, pw);

			tableEnd(pw);

			pw.println("<br/>");

		} finally {
		}
	}

	private List<Pair<String, String>> getPrivileges(HttpServletRequest request) {
		List<Pair<String, String>> privileges = new ArrayList<Pair<String, String>>();
		List<String> params = Collections.list(request.getParameterNames());

		for (String param : params) {
			if (param.startsWith("acl-path-")) {
				String path = request.getParameter(param);
				String privilege = request.getParameter(param.replace("-path-", "-privilege-"));
				if (StringUtils.isNotBlank(path) && StringUtils.isNotBlank(privilege)) {
					privileges.add(new ImmutablePair<String, String>(path, privilege));
				} else {
					log.warn("Unable to load ACL due to missing value {}={}", path, privilege);
				}
			}
		}

		return privileges;
	}

	private String[] getSupportedPrivileges(HttpServletRequest request) {
		String[] names = null;
		try {
			ResourceResolver resolver = getResourceResolver(request);
			Session session = resolver.adaptTo(Session.class);
			AccessControlManager accessControl = session.getAccessControlManager();
			Privilege[] privileges = accessControl.getSupportedPrivileges("/");
			names = new String[privileges.length];
			for (int i = 0; i < privileges.length; i++) {
				names[i] = privileges[i].getName();
			}
			Arrays.sort(names);
		} catch (RepositoryException re) {
			log.error("Exception loading Supported Privileges", re);
		}
		return names;

	}

	@Override
	protected void renderContent(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		final PrintWriter pw = response.getWriter();

		pw.println("<br/>");

		String alert = getParameter(request, "alert", "");
		if (StringUtils.isNotBlank(alert)) {
			info(pw, alert);
		}

		String action = getParameter(request, "action", "");
		if (StringUtils.isBlank(action)) {
			log.debug("Rendering service users page");
			info(pw, "Service users are used by OSGi Services to access the Sling repository. Use this form to find and create service users.");
			printServiceUsers(request, pw);
		} else if ("details".equals(action)) {
			log.debug("Rendering service user details page");
			try {
				printServiceUserDetails(request, pw);
			} catch (RepositoryException e) {
				log.warn("Exception rendering details for user", e);
				info(pw, "Exception rendering details for user");
			}
		} else {
			info(pw, "Unknown action: " + action);
		}
	}

	private void printPrivilegeSelect(PrintWriter pw, String label, List<Pair<String, String>> privileges,
			String[] supportedPrivileges, String alertMessage) {
		pw.print("<td style='width:20%'>");
		pw.print(xss.encodeForHTMLAttr(label));
		pw.println("</td>");
		pw.print("<td><table class=\"repeating-container\" style=\"width: 100%\" data-length=\"" + privileges.size()
				+ "\"><tr><td>Path</td><td>Privilege</td><td></td>");

		int idx = 0;
		for (Pair<String, String> privilege : privileges) {
			pw.print("</tr><tr class=\"repeating-item\"><td>");

			pw.print("<input type=\"text\"  name=\"acl-path-" + idx + "\" value='");
			pw.print(xss.encodeForHTMLAttr(StringUtils.defaultString(privilege.getKey())));
			pw.print("' style='width:100%' />");

			pw.print("</td><td>");

			pw.print("<input type=\"text\" list=\"data-privileges\" name=\"acl-privilege-" + idx + "\" value='");
			pw.print(xss.encodeForHTMLAttr(StringUtils.defaultString(privilege.getValue())));
			pw.print("' style='width:100%' />");

			pw.print("</td><td>");

			pw.print("<input type=\"button\" value=\"&nbsp;-&nbsp;\" class=\"repeating-remove\" /></td>");
		}
		pw.print("</tr></table>");

		pw.print("<input type=\"button\" value=\"&nbsp;+&nbsp;\" class=\"repeating-add\" />");

		pw.print("<datalist id=\"data-privileges\">");
		for (String option : supportedPrivileges) {
			pw.print("<option");
			pw.print(">");
			pw.print(xss.encodeForHTMLAttr(option));
			pw.print("</option>");
		}
		pw.print("</datalist><script src=\"/system/console/serviceusers/res/ui/serviceusermanager.js\"></script>");
		infoDiv(pw, alertMessage);
		pw.println("</td>");
	}

	private void selectField(PrintWriter pw, String label, String fieldName, String value, Collection<String> options,
			String... alertMessages) {
		pw.print("<td style='width:20%'>");
		pw.print(xss.encodeForHTMLAttr(label));
		pw.println("</td>");
		pw.print("<td><input type=\"text\" list=\"data-" + xss.encodeForHTMLAttr(fieldName) + "\" name='");
		pw.print(xss.encodeForHTMLAttr(fieldName));
		pw.print("' value='");
		pw.print(xss.encodeForHTMLAttr(StringUtils.defaultString(value)));
		pw.print("' style='width:100%' />");
		pw.print("<datalist id=\"data-" + xss.encodeForHTMLAttr(fieldName) + "\">");
		for (String option : options) {
			pw.print("<option");
			pw.print(">");
			pw.print(xss.encodeForHTMLAttr(option));
			pw.print("</option>");
		}
		pw.print("</datalist>");
		for (String alertMessage : alertMessages) {
			infoDiv(pw, alertMessage);
		}
		pw.println("</td>");
	}

	private void sendErrorRedirect(HttpServletRequest request, HttpServletResponse response, String alert)
			throws IOException {
		List<String> params = new ArrayList<String>();
		for (String param : new String[] { PN_APP_PATH, PN_BUNDLE, PN_NAME, PN_SUB_SERVICE, PN_USER_PATH }) {
			params.add(param + "=" + URLEncoder.encode(this.getParameter(request, param, ""), "UTF-8"));
		}

		int idx = 0;
		List<Pair<String, String>> privs = getPrivileges(request);
		for (Pair<String, String> priv : privs) {
			params.add("acl-path-" + idx + "=" + URLEncoder.encode(priv.getKey(), "UTF-8"));
			params.add("acl-privilege-" + idx + "=" + URLEncoder.encode(priv.getValue(), "UTF-8"));
			idx++;
		}

		if (StringUtils.isNotBlank(alert)) {
			params.add(PN_ALERT + "=" + URLEncoder.encode(alert, "UTF-8"));
		}

		WebConsoleUtil.sendRedirect(request, response,
				"/system/console/" + LABEL + "?" + StringUtils.join(params, "&"));
	}

	private void tableEnd(PrintWriter pw) {
		pw.println("</tr>");
		pw.println("</tbody>");
		pw.println("</table>");
	}

	private void tableRows(PrintWriter pw) {
		pw.println("</tr>");
		pw.println("<tr>");
	}

	private void tableStart(PrintWriter pw, String title, int colspan) {
		pw.println("<table class='nicetable ui-widget'>");
		pw.println("<thead class='ui-widget-header'>");
		pw.println("<tr>");
		pw.print("<th colspan=");
		pw.print(String.valueOf(colspan));
		pw.print(">");
		pw.print(xss.encodeForHTML(title));
		pw.println("</th>");
		pw.println("</tr>");
		pw.println("</thead>");
		pw.println("<tbody class='ui-widget-content'>");
		pw.println("<tr>");
	}

	private void td(PrintWriter pw, Object value, String... title) {
		pw.print("<td");
		if (title.length > 0 && !StringUtils.isBlank(title[0])) {
			pw.print(" title='");
			pw.print(xss.encodeForHTML(title[0]));
			pw.print("'");
		}
		pw.print(">");

		if (value != null) {
			if (value.getClass().isArray()) {
				for (int i = 0; i < Array.getLength(value); i++) {
					Object itemValue = Array.get(value, i);
					pw.print(xss.encodeForHTML(ObjectUtils.defaultIfNull(itemValue, "").toString()));
					pw.println("<br>");
				}
			} else {
				pw.print(xss.encodeForHTML(value.toString()));
			}
		}

		if (title.length > 0 && !StringUtils.isBlank(title[0])) {
			pw.print("<span class='ui-icon ui-icon-info' style='float:left'></span>");
		}
		pw.print("</td>");
	}

	private void textField(PrintWriter pw, String label, String fieldName, String value, String... alertMessages) {
		pw.print("<td style='width:20%'>");
		pw.print(xss.encodeForHTMLAttr(label));
		pw.println("</td>");
		pw.print("<td><input name='");
		pw.print(xss.encodeForHTMLAttr(fieldName));
		pw.print("' value='");
		pw.print(xss.encodeForHTMLAttr(StringUtils.defaultString(value)));
		pw.print("' style='width:100%'/>");
		for (String alertMessage : alertMessages) {
			infoDiv(pw, alertMessage);
		}
		pw.println("</td>");
	}

}
