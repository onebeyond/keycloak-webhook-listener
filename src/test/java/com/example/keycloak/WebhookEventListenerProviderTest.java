package com.example.keycloak;

import org.apache.commons.io.IOExceptionWithCause;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.Event;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static uk.org.lidalia.slf4jext.Level.ERROR;
import static uk.org.lidalia.slf4jext.Level.INFO;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class WebhookEventListenerProviderTest {

  @Mock
  private KeycloakSession session;

  @Mock
  private KeycloakContext context;

  @Mock
  private RealmModel realmModel;

  @Mock
  private CloseableHttpClient httpClient;

  @Mock
  private org.slf4j.Logger providerLogger;

  @InjectMocks
  private WebhookEventListenerProvider provider;

  @SystemStub
  private EnvironmentVariables environmentVariables;

  private TestLogger testLogger = TestLoggerFactory.getTestLogger(WebhookEventListenerProvider.class);

  @BeforeEach
  void setup() {
    TestLoggerFactory.clear();
    testLogger = TestLoggerFactory.getTestLogger(WebhookEventListenerProvider.class);
    provider = new WebhookEventListenerProvider(session, httpClient, testLogger);
    when(session.getContext()).thenReturn(context);
    when(context.getRealm()).thenReturn(realmModel);
    when(realmModel.getName()).thenReturn("test");
  }

  @Test
  void testOnEvent_WithBasicAuth() throws Exception {
    setupEnvironmentVariablesForBasicAuth();
    Event event = createTestEvent();
    CloseableHttpResponse mockResponse = mock(CloseableHttpResponse.class);
    when(httpClient.execute(any(HttpPost.class))).thenReturn(mockResponse);

    provider.onEvent(event);

    verifyHttpPostExecution("http://example.com/webhook", "application/json", true);
  }

  @Test
  void testOnEvent_NoBasicAuth() throws Exception {
    setupEnvironmentVariablesForNoAuth();
    Event event = createTestEvent();
    CloseableHttpResponse mockResponse = mock(CloseableHttpResponse.class);
    when(httpClient.execute(any(HttpPost.class))).thenReturn(mockResponse);

    provider.onEvent(event);

    verifyHttpPostExecution("http://example.com/webhook", "application/json", false);
  }

  @Test
  void testOnEvent_HttpExecutionFailure() throws Exception {
    setupEnvironmentVariablesForNoAuth();
    Event event = createTestEvent();

    doThrow(new IOExceptionWithCause("Simulated IO Exception", null)).when(httpClient).execute(any(HttpPost.class));

    provider.onEvent(event);

    assertTrue(testLogger.getLoggingEvents().stream().anyMatch(log -> log.getLevel().equals(ERROR)));
    assertTrue(testLogger.getLoggingEvents().stream()
        .anyMatch(log -> log.getMessage().contains("Error while sending webhook")));
  }

  @Test
  void testOnEvent_BasicAuthWithoutCredentials() throws Exception {
    environmentVariables.set("WEBHOOK_URL_TEST", "http://example.com/webhook");
    environmentVariables.set("WEBHOOK_AUTH_METHOD_TEST", "basic");
    // deliberately not setting USERNAME and PASSWORD

    Event event = createTestEvent();
    CloseableHttpResponse mockResponse = mock(CloseableHttpResponse.class);
    when(httpClient.execute(any(HttpPost.class))).thenReturn(mockResponse);

    provider.onEvent(event);

    // Ensure no Authorization header is added
    verifyHttpPostExecution("http://example.com/webhook", "application/json", false);
  }

  @Test
  void testOnEvent_BasicAuthWithWrongUsername() throws Exception {
    setupEnvironmentVariablesForBasicAuth();
    environmentVariables.set("WEBHOOK_AUTH_METHOD_TEST", "basic");
    environmentVariables.set("WEBHOOK_BASIC_AUTH_USERNAME_TEST", "wronguser");

    Event event = createTestEvent();

    CloseableHttpResponse unauthorizedResponse = mock(CloseableHttpResponse.class);
    when(unauthorizedResponse.getStatusLine())
        .thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 401, "Unauthorized"));

    when(httpClient.execute(any(HttpPost.class))).thenReturn(unauthorizedResponse);

    provider.onEvent(event);

    verifyHttpPostExecution("http://example.com/webhook", "application/json", true);

    assertTrue(testLogger.getLoggingEvents().stream()
        .anyMatch(log -> log.getLevel().equals(INFO) && log.getMessage().contains("Webhook response")
            && log.getArguments().get(0).toString().contains("401 Unauthorized")));
  }

  @Test
  void testOnEvent_BasicAuthWithWrongPassword() throws Exception {
    setupEnvironmentVariablesForBasicAuth();
    environmentVariables.set("WEBHOOK_AUTH_METHOD_TEST", "basic");
    environmentVariables.set("WEBHOOK_BASIC_AUTH_PASSWORD_TEST", "wrongpassword");

    Event event = createTestEvent();

    CloseableHttpResponse unauthorizedResponse = mock(CloseableHttpResponse.class);
    when(unauthorizedResponse.getStatusLine())
        .thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 401, "Unauthorized"));

    when(httpClient.execute(any(HttpPost.class))).thenReturn(unauthorizedResponse);

    provider.onEvent(event);

    verifyHttpPostExecution("http://example.com/webhook", "application/json", true);

    assertTrue(testLogger.getLoggingEvents().stream()
        .anyMatch(log -> log.getLevel().equals(INFO) && log.getMessage().contains("Webhook response")
            && log.getArguments().get(0).toString().contains("401 Unauthorized")));
  }

  private void setupEnvironmentVariablesForBasicAuth() {
    environmentVariables.set("WEBHOOK_URL_TEST", "http://example.com/webhook");
    environmentVariables.set("WEBHOOK_AUTH_METHOD_TEST", "basic");
    environmentVariables.set("WEBHOOK_BASIC_AUTH_USERNAME_TEST", "testuser");
    environmentVariables.set("WEBHOOK_BASIC_AUTH_PASSWORD_TEST", "testpass");
  }

  private void setupEnvironmentVariablesForNoAuth() {
    environmentVariables.set("WEBHOOK_URL_TEST", "http://example.com/webhook");
    environmentVariables.set("WEBHOOK_AUTH_METHOD_TEST", "none");
  }

  private Event createTestEvent() {
    return new Event();
  }

  private void verifyHttpPostExecution(String expectedUrl, String expectedContentType, boolean expectAuthHeader)
      throws Exception {
    ArgumentCaptor<HttpPost> captor = ArgumentCaptor.forClass(HttpPost.class);
    verify(httpClient).execute(captor.capture());
    HttpPost actualPost = captor.getValue();
    assertEquals(expectedUrl, actualPost.getURI().toString());
    assertEquals(expectedContentType, actualPost.getFirstHeader("Content-Type").getValue());

    if (expectAuthHeader) {
      assertNotNull(actualPost.getFirstHeader("Authorization"));
    } else {
      System.err.println("-------------------------------" + actualPost.getFirstHeader("Authorization"));
      assertNull(actualPost.getFirstHeader("Authorization"));
    }
  }
}
