package com.example.keycloak;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebhookEventListenerProvider implements EventListenerProvider {
  private static final Logger logger = LoggerFactory.getLogger(WebhookEventListenerProvider.class);
  private final KeycloakSession session;

  public WebhookEventListenerProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void onEvent(Event event) {
    logger.info("Received event: {}", event);
    String realmName = session.getContext().getRealm().getName();
    String webhookUrl = getWebhookUrlForRealm(realmName);
    sendWebhook("USER_EVENT", event, webhookUrl);
  }

  private String getWebhookUrlForRealm(String realmName) {
    String envVarName = "WEBHOOK_URL_" + realmName.toUpperCase().replace("-", "_");
    String webhookUrl = System.getenv(envVarName);
    if (webhookUrl == null) {
      throw new IllegalArgumentException("Webhook URL not specified for realm: " + realmName
          + ". Please set the WEBHOOK_URL_" + realmName.toUpperCase().replace("-", "_) environment variable."));
    }
    return webhookUrl;
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    logger.info("Received admin event: {}", event);
    String realmName = session.getContext().getRealm().getName();
    String webhookUrl = getWebhookUrlForRealm(realmName);
    sendWebhook("ADMIN_EVENT", event, webhookUrl);
  }

  @Override
  public void close() {
    logger.info("Closing WebhookEventListenerProvider");
  }

  private void sendWebhook(String type, Object event, String webhookUrl) {
    try (CloseableHttpClient client = HttpClients.createDefault()) {
      HttpPost httpPost = new HttpPost(webhookUrl);
      httpPost.setHeader("Content-Type", "application/json");

      ObjectMapper mapper = new ObjectMapper();
      String json = mapper.writeValueAsString(event);

      httpPost.setEntity(new StringEntity(json));

      logger.info("Sending webhook for event type: {}", type);
      client.execute(httpPost);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
