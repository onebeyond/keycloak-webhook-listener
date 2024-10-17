package com.example.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.jboss.logging.Logger;

public class WebhookEventListenerProviderFactory implements EventListenerProviderFactory {

  private static final Logger logger = Logger.getLogger(WebhookEventListenerProviderFactory.class);

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    logger.info("Creating WebhookEventListenerProvider");
    return new WebhookEventListenerProvider(session);
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
