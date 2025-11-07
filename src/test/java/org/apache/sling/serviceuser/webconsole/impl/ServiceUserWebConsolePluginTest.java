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

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.nodetype.NodeType;
import javax.jcr.query.Query;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ModifiableValueMap;
import org.apache.sling.api.resource.PersistenceException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.ResourceUtil;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.serviceusermapping.impl.MappingConfigAmendment;
import org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl;
import org.apache.sling.testing.mock.jcr.MockJcr;
import org.apache.sling.testing.mock.osgi.MockBundle;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.apache.sling.testing.mock.sling.servlet.MockSlingHttpServletRequest;
import org.apache.sling.testing.mock.sling.servlet.MockSlingHttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.withSettings;

/**
 * SLING-12994 junit tests for code coverage
 */
@ExtendWith(SlingContextExtension.class)
class ServiceUserWebConsolePluginTest {
    private final SlingContext context = new SlingContext(ResourceResolverType.JCR_MOCK);

    private ServiceUserWebConsolePlugin plugin;

    /**
     * Some options to use for test parameters
     */
    private enum TestConfigOptions {
        PRECREATE_SERVICEUSER,
        PRECREATE_MAPPING_CONFIG,
        PRECREATE_MAPPING_CONFIG_USERMAPPING,
        PRECREATE_ACLS,
        USE_ADMINISTRATIVE_RESOURCE_RESOLVER
    }

    @BeforeEach
    void beforeEach() {
        context.registerInjectActivateService(ServiceUserMapperImpl.class);
        plugin = context.registerInjectActivateService(ServiceUserWebConsolePlugin.class);
    }

    /**
     * Test method for {@link org.apache.sling.serviceuser.webconsole.impl.ServiceUserWebConsolePlugin#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)}.
     */
    protected static Stream<Arguments> testDoPostArgs() {
        Map<String, Object> reqParams1 = new HashMap<>();
        reqParams1.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        reqParams1.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        reqParams1.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");

        Map<String, Object> reqParams2 = new HashMap<>(reqParams1);
        reqParams2.put(ServiceUserWebConsolePlugin.PN_SUB_SERVICE, "subservice1");

        Map<String, Object> reqParams3 = new HashMap<>(reqParams1);
        // privilege params
        reqParams3.put("acl-path-0", "/content/node1");
        reqParams3.put("acl-privilege-0", "jcr:read");

        return Stream.of(
                Arguments.of(reqParams1, new HashSet<>()),
                Arguments.of(
                        reqParams1,
                        new HashSet<>(Arrays.asList(TestConfigOptions.USE_ADMINISTRATIVE_RESOURCE_RESOLVER))),
                Arguments.of(reqParams1, new HashSet<>(Arrays.asList(TestConfigOptions.PRECREATE_SERVICEUSER))),
                Arguments.of(reqParams1, new HashSet<>(Arrays.asList(TestConfigOptions.PRECREATE_MAPPING_CONFIG))),
                Arguments.of(
                        reqParams1,
                        new HashSet<>(Arrays.asList(
                                TestConfigOptions.PRECREATE_SERVICEUSER, TestConfigOptions.PRECREATE_MAPPING_CONFIG))),
                Arguments.of(
                        reqParams2,
                        new HashSet<>(Arrays.asList(
                                TestConfigOptions.PRECREATE_SERVICEUSER,
                                TestConfigOptions.PRECREATE_MAPPING_CONFIG,
                                TestConfigOptions.PRECREATE_MAPPING_CONFIG_USERMAPPING))),
                Arguments.of(reqParams3, new HashSet<>(Arrays.asList(TestConfigOptions.PRECREATE_ACLS))));
    }

    @ParameterizedTest
    @MethodSource("testDoPostArgs")
    void testDoPost(Map<String, Object> requestParams, Set<TestConfigOptions> options)
            throws ServletException, IOException, RepositoryException, LoginException {
        final @NotNull MockSlingHttpServletRequest request = context.request();
        request.setParameterMap(requestParams);

        final ResourceResolver rr = request.getResourceResolver();
        final @Nullable Session jcrSession = rr.adaptTo(Session.class);

        if (options.contains(TestConfigOptions.PRECREATE_SERVICEUSER)) {
            String name = request.getParameter(ServiceUserWebConsolePlugin.PN_NAME);
            ((JackrabbitSession) jcrSession).getUserManager().createSystemUser(name, null);
        }

        if (options.contains(TestConfigOptions.PRECREATE_MAPPING_CONFIG)) {
            // create the mapping and mock the jcr query
            String appPath = request.getParameter(ServiceUserWebConsolePlugin.PN_APP_PATH);
            String identifier = appPath.substring(appPath.lastIndexOf('/') + 1);
            String pid = String.format("%s~%s", ServiceUserWebConsolePlugin.COMPONENT_NAME, identifier);
            String path = String.format("%s/config/%s", appPath, pid);

            String mapping = null;
            if (options.contains(TestConfigOptions.PRECREATE_MAPPING_CONFIG_USERMAPPING)) {
                String bundle = request.getParameter(ServiceUserWebConsolePlugin.PN_BUNDLE);
                String subService = request.getParameter(ServiceUserWebConsolePlugin.PN_SUB_SERVICE);
                String name = request.getParameter(ServiceUserWebConsolePlugin.PN_NAME);
                mapping = toUserMappingValue(bundle, subService, name);
            }
            Resource config = createOsgiConfig(rr, path, mapping);

            String statement = String.format(
                    "SELECT * FROM [sling:OsgiConfig] WHERE ISDESCENDANTNODE([%s]) AND NAME() = '%s'", appPath, pid);
            List<Node> resultList = new ArrayList<>();
            resultList.add(config.adaptTo(Node.class));
            MockJcr.setQueryResult(jcrSession, statement, Query.JCR_SQL2, resultList);
        }

        // provide a mocked AccessControlManager object
        JackrabbitAccessControlManager acm = Mockito.mock(JackrabbitAccessControlManager.class);
        if (options.contains(TestConfigOptions.USE_ADMINISTRATIVE_RESOURCE_RESOLVER)) {
            mockAdministrativeResourceResolver(acm);
        } else {
            MockJcr.setAccessControlManager(jcrSession, acm);

            // simulate the resolver request attribute existing
            request.setAttribute("org.apache.sling.auth.core.ResourceResolver", rr);
        }

        if (options.contains(TestConfigOptions.PRECREATE_ACLS)) {
            Resource node1 = createNodeWithAce(rr, "/content/node1", "myserviceuser1");
            // also an ACE for the root resource for code coverage
            final @Nullable Resource rootResource = createAce(rr, "myserviceuser1", rr.getResource("/"));
            // mock the findACLs query to return the expected results
            MockJcr.setQueryResult(
                    jcrSession,
                    "SELECT * FROM [rep:GrantACE] AS s WHERE  [rep:principalName] = 'myserviceuser1'",
                    Query.JCR_SQL2,
                    Arrays.asList(node1.adaptTo(Node.class), rootResource.adaptTo(Node.class)));

            // mock the access API calls
            AccessControlPolicy mockPolicy1 = Mockito.mock(AccessControlPolicy.class);
            AccessControlList mockPolicy2 = Mockito.mock(AccessControlList.class);
            AccessControlEntry ace1 = mockAccessControlEntry(acm, "myserviceuser2", "jcr:read");
            AccessControlEntry ace2 = mockAccessControlEntry(acm, "myserviceuser1", "jcr:read", "jcr:write");
            Mockito.doReturn(new AccessControlEntry[] {ace1, ace2})
                    .when(mockPolicy2)
                    .getAccessControlEntries();
            Mockito.doReturn(new AccessControlPolicy[] {mockPolicy1, mockPolicy2})
                    .when(acm)
                    .getPolicies(anyString());
        }

        final @NotNull MockSlingHttpServletResponse response = context.response();

        // NOTE: replace the replaceAccessControlEntry method with one that does nothing since we are not
        //  testing that functionality here and it doesn't work with the partially mocked acm.
        try (MockedStatic<AccessControlUtil> subjectMock = Mockito.mockStatic(
                AccessControlUtil.class, withSettings().defaultAnswer(InvocationOnMock::callRealMethod)); ) {
            subjectMock
                    .when(() -> AccessControlUtil.replaceAccessControlEntry(
                            any(Session.class),
                            anyString(),
                            any(Principal.class),
                            any(String[].class),
                            any(String[].class),
                            any(String[].class),
                            isNull()))
                    .thenAnswer(invocation -> {
                        // replaced the method to do nothing
                        return null;
                    });

            plugin.doPost(request, response);
        }

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Service+user+myserviceuser1+created+%2F+updated+successfully%21"));
    }

    @Test
    void testDoPostWithFailureInCreateOrUpdateMapping() throws ServletException, IOException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        // simulate the resolver request attribute existing
        final ResourceResolver rr = Mockito.spy(request.getResourceResolver());
        // simulate an exception thrown during commit
        Mockito.doThrow(PersistenceException.class).when(rr).commit();
        request.setAttribute("org.apache.sling.auth.core.ResourceResolver", rr);

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        params.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        params.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = context.response();

        // provide a mocked AccessControlManager object
        JackrabbitAccessControlManager acm = Mockito.mock(JackrabbitAccessControlManager.class);
        MockJcr.setAccessControlManager(rr.adaptTo(Session.class), acm);

        plugin.doPost(request, response);

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Unable+to+create+service+user+mapping%21"));
    }

    @Test
    void testDoPostWithFailureInUpdatePrivileges() throws ServletException, IOException, RepositoryException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        // simulate the resolver request attribute existing
        final ResourceResolver rr = Mockito.spy(request.getResourceResolver());
        request.setAttribute("org.apache.sling.auth.core.ResourceResolver", rr);

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        params.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        params.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = context.response();

        // simulate an exception thrown during the updatePrivileges logic
        Session jcrSession = Mockito.spy(rr.adaptTo(Session.class));
        Mockito.doThrow(RepositoryException.class).when(jcrSession).getAccessControlManager();
        Mockito.doReturn(jcrSession).when(rr).adaptTo(Session.class);

        plugin.doPost(request, response);

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Unable+to+update+service+user+permissions%21"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testDoPostWithFailureToCreateServiceUser(boolean throwExceptionDuringRefresh)
            throws ServletException, IOException, RepositoryException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        // simulate a RepositoryException thrown while creating the system user
        final ResourceResolver rr = Mockito.spy(request.getResourceResolver());
        JackrabbitSession jcrSession = Mockito.spy((JackrabbitSession) rr.adaptTo(Session.class));
        Mockito.doReturn(jcrSession).when(rr).adaptTo(Session.class);
        if (throwExceptionDuringRefresh) {
            // throw exception during refresh for code coverage
            Mockito.doThrow(RepositoryException.class).when(jcrSession).refresh(false);
        } else {
            // NOTE: the refresh(false) is not yet implemented by the MockSession
            //   so we have to replace the method to get through this test code path
            Mockito.doNothing().when(jcrSession).refresh(false);
        }
        final UserManager um = Mockito.mock(UserManager.class);
        Mockito.doReturn(um).when(jcrSession).getUserManager();
        Mockito.doThrow(RepositoryException.class).when(um).createSystemUser(anyString(), nullable(String.class));

        // simulate the resolver request attribute existing
        request.setAttribute("org.apache.sling.auth.core.ResourceResolver", rr);

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        params.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        params.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = context.response();

        plugin.doPost(request, response);

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Unable+to+create+service+user%21"));
    }

    @Test
    void testDoPostWithCaughtLoginException() throws LoginException, ServletException, IOException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        mockResolverFactoryThrowsLoginException();

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        params.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        params.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = context.response();

        plugin.doPost(request, response);

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Unexpected+exception"));
    }

    @SuppressWarnings("deprecation")
    @Test
    void testDoPostWithNullResourceResolver() throws LoginException, ServletException, IOException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        // simulate the resolverFactory returning a null administrative resource resolver
        ResourceResolverFactory rrf =
                ReflectionTools.getFieldWithReflection(plugin, "resolverFactory", ResourceResolverFactory.class);
        rrf = Mockito.spy(rrf);
        Mockito.doReturn(null).when(rrf).getAdministrativeResourceResolver(null);
        ReflectionTools.setFieldWithReflection(plugin, "resolverFactory", rrf);

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        params.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        params.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = context.response();

        plugin.doPost(request, response);

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Unable+to+get+serviceresolver+from+request"));
    }

    @Test
    void testDoPostWithIOExceptionDuringErrorRedirect() throws LoginException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        mockResolverFactoryThrowsLoginException();

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        params.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        params.put(ServiceUserWebConsolePlugin.PN_APP_PATH, "/apps/myapp1");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = Mockito.spy(context.response());
        Mockito.doThrow(IOException.class).when(response).sendRedirect(anyString());

        assertThrows(IOException.class, () -> plugin.doPost(request, response));
    }

    protected static Stream<Arguments> testDoPostWithMissingParametersArgs() {
        Map<String, Object> params1 = new HashMap<>();
        Map<String, Object> params2 = Collections.singletonMap(ServiceUserWebConsolePlugin.PN_NAME, "myserviceuser1");
        Map<String, Object> params3 = new HashMap<>(params2);
        params3.put(ServiceUserWebConsolePlugin.PN_BUNDLE, "my.bundle1");
        Map<String, Object> params4 = new HashMap<>();
        params4.put("acl-path-0", "/content");
        params4.put("acl-privilege-0", "jcr:read");
        Map<String, Object> params4b = new HashMap<>(params4);
        params4.put("acl-path-1", "/content/node1");
        params4.put("acl-privilege-1", "");
        params4.put("acl-path-2", "");
        params4.put("acl-privilege-2", "jcr:read");

        return Stream.of(
                Arguments.of(params1, params1),
                Arguments.of(params2, params2),
                Arguments.of(params3, params3),
                Arguments.of(params4, params4b));
    }

    @ParameterizedTest
    @MethodSource("testDoPostWithMissingParametersArgs")
    void testDoPostWithMissingParameters(Map<String, Object> params, Map<String, Object> expectedRedirectParams)
            throws ServletException, IOException {
        final @NotNull MockSlingHttpServletRequest request = context.request();
        request.setParameterMap(params);
        final @NotNull MockSlingHttpServletResponse response = context.response();

        plugin.doPost(request, response);

        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
        final String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("Missing+required+parameters%21"));

        // verify that the request parameters are echoed back in the redirect location
        for (Map.Entry<String, Object> param : expectedRedirectParams.entrySet()) {
            final String key = param.getKey();
            final String charset = StandardCharsets.UTF_8.name();
            String expected = String.format(
                    "%s=%s", URLEncoder.encode(key, charset), URLEncoder.encode((String) param.getValue(), charset));
            assertTrue(location.contains(expected), "Expected value in redirect location for: " + key);
        }
    }

    /**
     * Test method for {@link org.apache.sling.serviceuser.webconsole.impl.ServiceUserWebConsolePlugin#getLabel()}.
     */
    @Test
    void testGetLabel() {
        assertEquals("serviceusers", plugin.getLabel());
    }

    /**
     * Test method for {@link org.apache.sling.serviceuser.webconsole.impl.ServiceUserWebConsolePlugin#getResource(java.lang.String)}.
     */
    @Test
    void testGetResource() {
        assertNotNull(plugin.getResource("/serviceusers/res/ui/serviceusermanager.js"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"/serviceusers/invalid.js"})
    void testGetResourceForInvalidPath(String path) {
        assertNull(plugin.getResource(path));
    }

    /**
     * Test method for {@link org.apache.sling.serviceuser.webconsole.impl.ServiceUserWebConsolePlugin#getTitle()}.
     */
    @Test
    void testGetTitle() {
        assertEquals("Service Users", plugin.getTitle());
    }

    /**
     * Test method for {@link org.apache.sling.serviceuser.webconsole.impl.ServiceUserWebConsolePlugin#renderContent(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)}.
     */
    @ParameterizedTest
    @NullAndEmptySource
    void testRenderContentForServiceUsers(String action) throws ServletException, IOException, RepositoryException {

        final @NotNull BundleContext bundleContext = context.bundleContext();

        // provide some data to print in the output
        mockMappingConfigAmendment(bundleContext.getBundle().getSymbolicName(), null, "serviceuser2", 3);
        mockMappingConfigAmendment(bundleContext.getBundle().getSymbolicName(), "subservice1", "serviceuser2", 1);
        mockMappingConfigAmendment("another.bundle1", "subservice1", "serviceuser2", 2);
        mockMappingConfigAmendment("another.bundle1", null, "serviceuser2", 4);
        // NOTE: the MockBundle doesn't have a Bundle-Name header, so supply one
        ((MockBundle) bundleContext.getBundle())
                .setHeaders(Collections.singletonMap(Constants.BUNDLE_NAME, "Mock Bundle"));

        // NOTE: The MockBundleContext#getBundles api is always returning an empty array
        // so we need to replace it to get some data to print out during ServiceUserWebConsolePlugin#findBundle
        BundleContext bc =
                Mockito.spy(ReflectionTools.getFieldWithReflection(plugin, "bundleContext", BundleContext.class));
        Mockito.doReturn(new Bundle[] {bc.getBundle()}).when(bc).getBundles();
        ReflectionTools.setFieldWithReflection(plugin, "bundleContext", bc);

        final @NotNull MockSlingHttpServletRequest request = context.request();
        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_ACTION, action);
        params.put(ServiceUserWebConsolePlugin.PN_ALERT, "some alert here");
        // privilege params
        params.put("acl-path-0", "/content");
        params.put("acl-privilege-0", "jcr:read");
        request.setParameterMap(params);

        // simulate the resolver request attribute existing
        final ResourceResolver rr = request.getResourceResolver();
        request.setAttribute("org.apache.sling.auth.core.ResourceResolver", rr);

        // provide a mocked AccessControlManager object
        JackrabbitAccessControlManager acm = Mockito.mock(JackrabbitAccessControlManager.class);
        final Privilege[] supportedPrivileges = new Privilege[] {
            createMockPrivilege(acm, Privilege.JCR_READ), createMockPrivilege(acm, Privilege.JCR_WRITE)
        };
        Mockito.doReturn(supportedPrivileges).when(acm).getSupportedPrivileges("/");
        MockJcr.setAccessControlManager(rr.adaptTo(Session.class), acm);

        final @NotNull MockSlingHttpServletResponse response = context.response();
        plugin.renderContent(request, response);
        final String outputAsString = response.getOutputAsString();
        assertNotNull(outputAsString);
    }

    @Test
    void testRenderContentForServiceUsersWithCaughtLoginException()
            throws ServletException, IOException, LoginException {
        final @NotNull MockSlingHttpServletRequest request = context.request();
        Map<String, Object> params = new HashMap<>();
        request.setParameterMap(params);

        mockResolverFactoryThrowsLoginException();

        final @NotNull MockSlingHttpServletResponse response = context.response();
        plugin.renderContent(request, response);
        final String outputAsString = response.getOutputAsString();
        assertNotNull(outputAsString);
        assertTrue(outputAsString.contains("Exception rendering service users"));
    }

    protected static Stream<Arguments> testRenderContentForServiceUserDetailsArgs() {
        return Stream.of(
                Arguments.of(new HashSet<>()),
                Arguments.of(new HashSet<>(Arrays.asList(TestConfigOptions.USE_ADMINISTRATIVE_RESOURCE_RESOLVER))),
                Arguments.of(new HashSet<>(Arrays.asList(TestConfigOptions.PRECREATE_SERVICEUSER))));
    }

    @ParameterizedTest
    @MethodSource("testRenderContentForServiceUserDetailsArgs")
    void testRenderContentForServiceUserDetails(Set<TestConfigOptions> options)
            throws ServletException, IOException, RepositoryException, LoginException {
        final @NotNull BundleContext bundleContext = context.bundleContext();

        // provide some mapping data to print in the output
        mockMappingConfigAmendment(
                bundleContext.getBundle().getSymbolicName(), null, null, Arrays.asList("myserviceuser1"), 3);
        mockMappingConfigAmendment(bundleContext.getBundle().getSymbolicName(), "subservice1", "myserviceuser1", 1);
        mockMappingConfigAmendment(
                "another.bundle1", "subservice2", null, Arrays.asList("otheruser1", "otheruser2"), 2);
        mockMappingConfigAmendment("another.bundle2", "subservice3", "otheruser3", 5);

        final @NotNull MockSlingHttpServletRequest request = context.request();

        final ResourceResolver rr = request.getResourceResolver();
        final @Nullable Session jcrSession = rr.adaptTo(Session.class);

        // provide some "OSGi Configurations" to print in the output and mock the queries
        String mapping1 =
                toUserMappingValue(bundleContext.getBundle().getSymbolicName(), "subservice1", "myserviceuser1");
        Resource config1 = createOsgiConfig(
                rr,
                "/apps/sling/install/org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended~test1",
                mapping1);
        MockJcr.setQueryResult(
                jcrSession,
                "SELECT * FROM [sling:OsgiConfig] AS s WHERE (ISDESCENDANTNODE([/apps]) OR ISDESCENDANTNODE([/libs])) AND NAME(s) LIKE 'org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended%' AND [user.mapping] LIKE '%=myserviceuser1'",
                Query.JCR_SQL2,
                Arrays.asList(config1.adaptTo(Node.class)));
        // also the alternate code path where the config is stored as a nt:file resource
        String mapping2 =
                toUserMappingValue(bundleContext.getBundle().getSymbolicName(), "subservice2", "myserviceuser1");
        Resource config2 = createFileConfig(
                rr,
                "/apps/sling/install/org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended~test2",
                mapping2);
        MockJcr.setQueryResult(
                jcrSession,
                "SELECT * FROM [nt:file] AS s WHERE (ISDESCENDANTNODE([/apps]) OR ISDESCENDANTNODE([/libs])) AND NAME(s) LIKE 'org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended%' AND [jcr:content/jcr:data] LIKE '%=myserviceuser1%'",
                Query.JCR_SQL2,
                Arrays.asList(config2.adaptTo(Node.class)));

        // provide some "ACLs" to print in the output and mock the query
        Resource node1 = createNodeWithAce(rr, "/content/node1", "myserviceuser1");
        MockJcr.setQueryResult(
                jcrSession,
                "SELECT * FROM [rep:GrantACE] AS s WHERE  [rep:principalName] = 'myserviceuser1'",
                Query.JCR_SQL2,
                Arrays.asList(node1.adaptTo(Node.class)));

        if (options.contains(TestConfigOptions.PRECREATE_SERVICEUSER)) {
            ((JackrabbitSession) jcrSession).getUserManager().createSystemUser("myserviceuser1", null);
        }

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_ACTION, "details");
        params.put(ServiceUserWebConsolePlugin.PN_USER, "myserviceuser1");
        request.setParameterMap(params);

        // provide a mocked AccessControlManager object
        JackrabbitAccessControlManager acm = Mockito.mock(JackrabbitAccessControlManager.class);
        final Privilege[] supportedPrivileges = new Privilege[] {
            createMockPrivilege(acm, Privilege.JCR_READ), createMockPrivilege(acm, Privilege.JCR_WRITE)
        };
        Mockito.doReturn(supportedPrivileges).when(acm).getSupportedPrivileges("/");
        if (options.contains(TestConfigOptions.USE_ADMINISTRATIVE_RESOURCE_RESOLVER)) {
            mockAdministrativeResourceResolver(acm);
        } else {
            MockJcr.setAccessControlManager(jcrSession, acm);

            // simulate the resolver request attribute existing
            request.setAttribute("org.apache.sling.auth.core.ResourceResolver", rr);
        }

        final @NotNull MockSlingHttpServletResponse response = context.response();
        plugin.renderContent(request, response);
        final String outputAsString = response.getOutputAsString();
        assertNotNull(outputAsString);
    }

    @Test
    void testRenderContentForServiceUserDetailsWithCaughtLoginException()
            throws ServletException, IOException, LoginException {
        final @NotNull MockSlingHttpServletRequest request = context.request();
        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_ACTION, "details");
        params.put(ServiceUserWebConsolePlugin.PN_USER, "myserviceuser1");
        request.setParameterMap(params);

        // simulate the resolverFactory throwing a LoginException
        mockResolverFactoryThrowsLoginException();

        final @NotNull MockSlingHttpServletResponse response = context.response();
        plugin.renderContent(request, response);
        final String outputAsString = response.getOutputAsString();
        assertNotNull(outputAsString);
        assertTrue(outputAsString.contains("Exception rendering details for user"));
    }

    @Test
    void testRenderContentForUnknownAction() throws ServletException, IOException {
        final @NotNull MockSlingHttpServletRequest request = context.request();

        Map<String, Object> params = new HashMap<>();
        params.put(ServiceUserWebConsolePlugin.PN_ACTION, "invalid");
        request.setParameterMap(params);

        final @NotNull MockSlingHttpServletResponse response = context.response();
        plugin.renderContent(request, response);
        final String outputAsString = response.getOutputAsString();
        assertNotNull(outputAsString);
        assertTrue(outputAsString.contains("Unknown action: invalid"));
    }

    // -------------------------- begin helper methods ---------------------------

    /**
     * Register a mock a service user mapping config amendment service
     *
     * @param bundleContext the bundle context
     * @param bundle the symbolic name of the bundle
     * @param subService the subservice name (or null)
     * @param name the service user name
     * @param serviceRanking the ranking value of the registered service
     */
    private void mockMappingConfigAmendment(
            @NotNull String bundle, @Nullable String subService, @NotNull String name, long serviceRanking) {
        mockMappingConfigAmendment(bundle, subService, name, Collections.emptyList(), serviceRanking);
    }

    /**
     * Register a mock a service user mapping config amendment service
     *
     * @param bundleContext the bundle context
     * @param bundle the symbolic name of the bundle
     * @param subService the subservice name (or null)
     * @param name (optional) the service user name
     * @param principalNames the service user names (used only when "name" is null)
     * @param serviceRanking the ranking value of the registered service
     */
    private void mockMappingConfigAmendment(
            @NotNull String bundle,
            @Nullable String subService,
            @Nullable String name,
            @NotNull Collection<String> principalNames,
            long serviceRanking) {
        String mapping = toUserMappingValue(bundle, subService, name, principalNames);

        Map<String, Object> config1 = new HashMap<>();
        config1.put("user.mapping", mapping);
        config1.put(Constants.SERVICE_RANKING, serviceRanking);
        context.registerInjectActivateService(MappingConfigAmendment.class, config1);
    }

    /**
     * Creates a mocked privilege
     *
     * @param acm the access control manager
     * @param name the privilege name
     * @return the mocked privilege
     */
    private static @NotNull Privilege createMockPrivilege(@Nullable AccessControlManager acm, @NotNull String name)
            throws RepositoryException {
        Privilege p;
        if (acm == null) {
            p = Mockito.mock(Privilege.class);
            Mockito.when(p.getDeclaredAggregatePrivileges()).thenReturn(new Privilege[0]);
            Mockito.when(p.getName()).thenReturn(name);
        } else {
            p = acm.privilegeFromName(name);
            if (p == null) {
                // does not exist yet?
                p = Mockito.mock(Privilege.class);
                Mockito.when(p.getName()).thenReturn(name);
                Mockito.when(p.getDeclaredAggregatePrivileges()).thenReturn(new Privilege[0]);
                Mockito.when(acm.privilegeFromName(name)).thenReturn(p);
            }
        }
        return p;
    }

    /**
     * Creates a mocked access control entry
     *
     * @param acm the access control manager
     * @param user the user name
     * @param privilegeNames the names of the privileges
     * @return the mocked access control entry
     */
    private @NotNull AccessControlEntry mockAccessControlEntry(
            @NotNull AccessControlManager acm, @NotNull String user, @NotNull String... privilegeNames)
            throws RepositoryException {
        AccessControlEntry ace1 = Mockito.mock(AccessControlEntry.class);
        Principal principal1 = () -> user;
        Mockito.doReturn(principal1).when(ace1).getPrincipal();
        List<Privilege> privileges = new ArrayList<>();
        for (String pname : privilegeNames) {
            privileges.add(createMockPrivilege(acm, pname));
        }
        Privilege[] privilegesArray = privileges.toArray(new Privilege[privileges.size()]);
        Mockito.doReturn(privilegesArray).when(ace1).getPrivileges();
        return ace1;
    }

    /**
     * Creates a sling:OsgiConfig configuration resource
     *
     * @param rr the resource resolver
     * @param path the path for the cresource
     * @param mapping (optional) the mapping to apply
     * @return
     * @throws PersistenceException
     */
    private @NotNull Resource createOsgiConfig(
            final @NotNull ResourceResolver rr, @NotNull String path, @Nullable String mapping)
            throws PersistenceException {
        Resource config = ResourceUtil.getOrCreateResource(
                rr,
                path,
                Collections.singletonMap(JcrConstants.JCR_PRIMARYTYPE, "sling:OsgiConfig"),
                NodeType.NT_FOLDER,
                false);

        if (mapping != null) {
            ModifiableValueMap properties = config.adaptTo(ModifiableValueMap.class);
            List<String> m = new ArrayList<>();
            m.add(mapping);
            properties.put("user.mapping", m.toArray(new String[m.size()]));
        }
        rr.commit();

        return config;
    }

    /**
     * Creates a nt:file configuration resource
     *
     * @param rr the resource resolver
     * @param path the path for the cresource
     * @param mapping (optional) the mapping to apply
     * @return
     * @throws PersistenceException
     */
    private @NotNull Resource createFileConfig(
            final @NotNull ResourceResolver rr, @NotNull String path, @Nullable String mapping)
            throws PersistenceException {
        Resource config = ResourceUtil.getOrCreateResource(
                rr, path, Collections.singletonMap(JcrConstants.JCR_PRIMARYTYPE, "nt:file"), NodeType.NT_FOLDER, false);

        Map<String, Object> properties = new HashMap<>();
        if (mapping != null) {
            List<String> m = new ArrayList<>();
            m.add(mapping);
            properties.put("jcr:data", m.toArray(new String[m.size()]));
        }
        rr.create(config, "jcr:content", properties);
        rr.commit();

        return config;
    }

    /**
     * Creates a folder resource with an ACL pre-created
     *
     * @param rr the resource resolver
     * @param path the path of the resource
     * @param userid the user name to apply the access control entry for
     * @return the created resource
     */
    private @NotNull Resource createNodeWithAce(
            @NotNull ResourceResolver rr, @NotNull String path, @NotNull String userid) throws PersistenceException {
        Resource config = ResourceUtil.getOrCreateResource(
                rr,
                path,
                Collections.singletonMap(JcrConstants.JCR_PRIMARYTYPE, (Object) "nt:folder"),
                NodeType.NT_FOLDER,
                false);
        Resource ace = createAce(rr, userid, config);
        rr.commit();
        return ace;
    }

    /**
     * Creates an ACL with an ACE for a resource
     *
     * @param rr the resource resolver
     * @param userid the user name to apply the access control entry for
     * @param parent the resource to add the ACL to
     * @return the created ACE resource
     */
    private @NotNull Resource createAce(@NotNull ResourceResolver rr, @NotNull String userid, @NotNull Resource parent)
            throws PersistenceException {
        Resource acl =
                rr.create(parent, "rep:policy", Collections.singletonMap(JcrConstants.JCR_PRIMARYTYPE, "rep:ACL"));
        Map<String, Object> props = new HashMap<>();
        props.put(JcrConstants.JCR_PRIMARYTYPE, "rep:GrantACE");
        props.put("rep:privileges", new String[] {"jcr:read"});
        props.put("rep:principalName", userid);
        Resource ace = rr.create(acl, userid, props);
        rr.commit();
        return ace;
    }

    /**
     * Mock the factory calls for an administrative resource resolver
     *
     * @param acm the access control manager
     */
    @SuppressWarnings("deprecation")
    private void mockAdministrativeResourceResolver(@NotNull JackrabbitAccessControlManager acm) throws LoginException {
        // hack to workaround the mock administrative session not having the access control manager set
        ResourceResolverFactory factory = Mockito.spy(
                ReflectionTools.getFieldWithReflection(plugin, "resolverFactory", ResourceResolverFactory.class));
        ReflectionTools.setFieldWithReflection(plugin, "resolverFactory", factory);
        // overwrite the getAdministrativeResourceResolver method to produce a ResourceResolver that has the
        // accessControlManager set
        Mockito.doAnswer(invocation -> {
                    ResourceResolver arr = (ResourceResolver) invocation.callRealMethod();
                    Session session = arr.adaptTo(Session.class);
                    ReflectionTools.setFieldWithReflection(session, "accessControlManager", acm);
                    return arr;
                })
                .when(factory)
                .getAdministrativeResourceResolver(null);
    }

    /**
     * Mocks the scenario where the ResourceResolverFactory throws a LoginException
     * during the getAdministrativeResourceResolver call
     */
    @SuppressWarnings("deprecation")
    private void mockResolverFactoryThrowsLoginException() throws LoginException {
        ResourceResolverFactory rrf =
                ReflectionTools.getFieldWithReflection(plugin, "resolverFactory", ResourceResolverFactory.class);
        rrf = Mockito.spy(rrf);
        Mockito.doThrow(LoginException.class).when(rrf).getAdministrativeResourceResolver(null);
        ReflectionTools.setFieldWithReflection(plugin, "resolverFactory", rrf);
    }

    /**
     * Formats the data it a user.mapping string
     *
     * @param bundle the bundle name
     * @param subService (optional) the subservice name
     * @param name the service username
     * @return the formatted mapping value
     */
    private String toUserMappingValue(@NotNull String bundle, @Nullable String subService, @NotNull String name) {
        return toUserMappingValue(bundle, subService, name, Collections.emptyList());
    }

    /**
     * Formats the data it a user.mapping string
     *
     * @param bundle the bundle name
     * @param subService (optional) the subservice name
     * @param name (optional) the service username
     * @param principalNames the names of the principals (used only if "name" is null)
     * @return the formatted mapping value
     */
    private String toUserMappingValue(
            @NotNull String bundle,
            @Nullable String subService,
            @Nullable String name,
            @NotNull Collection<String> principalNames) {
        String value;
        if (name != null) {
            value = name;
        } else {
            value = "[" + String.join(",", principalNames) + "]";
        }
        return bundle + (StringUtils.isNotBlank(subService) ? ":" + subService : "") + "=" + value;
    }
}
