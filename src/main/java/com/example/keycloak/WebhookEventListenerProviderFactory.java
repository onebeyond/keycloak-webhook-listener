package com.example.keycloak;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebhookEventListenerProviderFactory implements EventListenerProviderFactory {

  private static final Logger logger = LoggerFactory.getLogger(WebhookEventListenerProviderFactory.class);
  private static final Logger providerLogger = LoggerFactory.getLogger(WebhookEventListenerProvider.class);

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    logger.info("Creating WebhookEventListenerProvider");

    // Create or configure the CloseableHttpClient
    CloseableHttpClient httpClient = HttpClients.createDefault();

    // Pass the httpClient to the provider
    return new WebhookEventListenerProvider(session, httpClient, providerLogger);
  }

  @Override
  public void init(org.keycloak.Config.Scope config) {
    // Initialize configuration if needed
    logger.info("Initializing WebhookEventListenerProviderFactory");
  }

  @Override
  public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
    // Post-initialization configuration if needed
    logger.info("Post-initializing WebhookEventListenerProviderFactory");
  }

  @Override
  public void close() {
    // Cleanup resources if needed
    logger.info("Closing WebhookEventListenerProviderFactory");
  }

  @Override
  public String getId() {
    // This ID should be unique and used to identify the provider in Keycloak
    return "webhook-event-listener";
  }
}
