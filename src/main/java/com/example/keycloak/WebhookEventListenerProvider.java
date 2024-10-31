package com.example.keycloak;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import com.fasterxml.jackson.databind.ObjectMapper;

public class WebhookEventListenerProvider implements EventListenerProvider {
  private final KeycloakSession session;
  private final CloseableHttpClient httpClient;
  private final Logger logger;

  public WebhookEventListenerProvider(KeycloakSession session, CloseableHttpClient httpClient, Logger logger) {
    this.session = session;
    this.httpClient = httpClient;
    this.logger = logger;
  }

  @Override
  public void onEvent(Event event) {
    processEvent(event, "USER_EVENT");
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    processEvent(event, "ADMIN_EVENT");
  }

  private void processEvent(Object event, String eventType) {
    logger.info("Processing {}: {}", eventType, event);
    String realmName = session.getContext().getRealm().getName();

    try {
      logger.info("Sending webhook for {} type", eventType);
      String webhookUrl = getWebhookUrlForRealm(realmName);
      HttpPost httpPost = prepareHttpPost(webhookUrl, realmName, event);
      httpClient.execute(httpPost);
    } catch (Exception e) {
      logger.error("Error while sending webhook for {}: {}", eventType, e.getMessage(), e);
    }
  }

  private String getEnvVariableForRealm(String prefix, String realm, String severity) {
    String envVar = prefix + "_" + realm.toUpperCase().replace("-", "_");
    String value = System.getenv(envVar);
    if (value == null) {
      String message = "Environment variable " + envVar + " not specified for realm: " + realm;
      if ("error".equals(severity)) {
        throw new IllegalArgumentException(message);
      } else {
        logger.warn(message);
      }
    }
    return value;
  }

  private String getWebhookUrlForRealm(String realmName) {
    return getEnvVariableForRealm("WEBHOOK_URL", realmName, "error");
  }

  private String getWebhookAuthMethodForRealm(String realmName) {
    return getEnvVariableForRealm("WEBHOOK_AUTH_METHOD", realmName, "warn");
  }

  private String getWebhookBasicAuthUsernameForRealm(String realmName) {
    return getEnvVariableForRealm("WEBHOOK_BASIC_AUTH_USERNAME", realmName, "warn");
  }

  private String getWebhookBasicAuthPasswordForRealm(String realmName) {
    return getEnvVariableForRealm("WEBHOOK_BASIC_AUTH_PASSWORD", realmName, "warn");
  }

  private HttpPost prepareHttpPost(String webhookUrl, String realmName, Object event) throws Exception {
    HttpPost httpPost = new HttpPost(webhookUrl);
    httpPost.setHeader("Content-Type", "application/json");

    String authMethod = getWebhookAuthMethodForRealm(realmName);
    if ("basic".equalsIgnoreCase(authMethod)) {
      configureBasicAuth(httpPost, realmName);
    }

    ObjectMapper mapper = new ObjectMapper();
    String json = mapper.writeValueAsString(event);
    httpPost.setEntity(new StringEntity(json));

    return httpPost;
  }

  private void configureBasicAuth(HttpPost httpPost, String realmName) throws Exception {
    String username = getWebhookBasicAuthUsernameForRealm(realmName);
    String password = getWebhookBasicAuthPasswordForRealm(realmName);
    if (username != null && password != null) {
      UsernamePasswordCredentials creds = new UsernamePasswordCredentials(username, password);
      httpPost.addHeader(new BasicScheme().authenticate(creds, httpPost, new BasicHttpContext()));
    } else {
      logger.warn("Basic authentication enabled, but username or password not set.");
    }
  }

  @Override
  public void close() {
    logger.info("Closing WebhookEventListenerProvider");
  }
}
