/**
 * Copyright (c) 2026 FinkTech
 */

export const HIGH_CONFIDENCE_PATTERNS = [
  { name: "stripe-key",         pattern: /^(?:rk|sk)_(?:test|live)_[0-9a-zA-Z]{24}$/ },
  { name: "stripe-publishable", pattern: /^pk_(?:test|live)_[0-9a-zA-Z]{24,}$/ },
  { name: "anthropic-api-key",  pattern: /^sk-ant-(?:api\d{2}-)?[a-zA-Z0-9_-]{90,}$/ },
  { name: "openai-api-key",     pattern: /^sk-[a-zA-Z0-9_-]{20,}$/ },
  { name: "openai-proj-key",    pattern: /^sk-proj-[a-zA-Z0-9_-]{40,}$/ },
  { name: "github-pat-classic", pattern: /^ghp_[a-zA-Z0-9]{36}$/ },
  { name: "github-oauth",       pattern: /^gho_[a-zA-Z0-9]{36}$/ },
  { name: "github-app-token",   pattern: /^(?:ghs|ghu)_[a-zA-Z0-9]{36}$/ },
  { name: "github-pat-fine",    pattern: /^github_pat_[a-zA-Z0-9_]{82}$/ },
  { name: "gitlab-pat",         pattern: /^glpat-[a-zA-Z0-9_-]{20}$/ },
  { name: "gitlab-pipeline",    pattern: /^glcbt-[a-zA-Z0-9_-]{20}$/ },
  { name: "aws-access-key",     pattern: /^(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}$/ },
  { name: "gcp-api-key",        pattern: /^AIza[0-9a-zA-Z_-]{35}$/ },
  { name: "google-oauth",       pattern: /^ya29\.[0-9A-Za-z_-]{50,}$/ },
  { name: "xai-api-key",        pattern: /^xai-[a-zA-Z0-9_-]{40,}$/ },
  { name: "slack-bot-token",    pattern: /^xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}$/ },
  { name: "slack-user-token",   pattern: /^xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}$/ },
  { name: "slack-app-token",    pattern: /^xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-f0-9]{64}$/ },
  { name: "slack-config-token", pattern: /^xoxe\.[a-zA-Z0-9_-]{200,}$/ },
  { name: "twilio-sid",         pattern: /^AC[a-z0-9]{32}$/ },
  { name: "twilio-auth-token",  pattern: /^[a-f0-9]{32}$/ },
  { name: "sendgrid-api-key",   pattern: /^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$/ },
  { name: "huggingface-token",  pattern: /^hf_[a-zA-Z0-9]{34,}$/ },
  { name: "npm-access-token",   pattern: /^npm_[a-zA-Z0-9]{36}$/ },
  { name: "doppler-token",      pattern: /^dp\.(?:st|ct|sa)\.[a-zA-Z0-9]{40,}$/ },
  { name: "linear-api-key",     pattern: /^lin_api_[a-zA-Z0-9]{40}$/ },
  { name: "jwt",                pattern: /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/ }
];
