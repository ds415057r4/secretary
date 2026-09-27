import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const usedLogos = [
  "google-icon", "youtube-icon", "github-icon", "gitlab-icon", "discord-icon",
  "notion-icon", "figma", "dropbox", "apple", "facebook", "instagram-icon",
  "microsoft-icon", "linkedin-icon", "slack-icon", "salesforce", "adobe", "openai-icon", "cloudflare-icon",
  "atlassian", "auth0-icon", "okta-icon", "paypal", "steam", "twitch",
  "reddit-icon", "spotify-icon", "netflix-icon", "telegram", "whatsapp-icon",
  "tiktok-icon", "wordpress-icon", "shopify", "docker-icon", "zoom-icon",
  "aws", "azure-icon", "google-cloud", "ibm", "oracle", "digital-ocean",
  "heroku-icon", "twilio-icon", "bitbucket", "datadog", "sentry-icon", "grafana",
  "trello", "asana", "linear", "mailchimp", "stripe",
];

function selectedBrandLogos() {
  const virtualId = "\0virtual:brand-logos";
  return {
    name: "selected-brand-logos",
    resolveId(id) {
      return id === "virtual:brand-logos" ? virtualId : undefined;
    },
    load(id) {
      if (id !== virtualId) return undefined;
      const path = fileURLToPath(new URL("../node_modules/@iconify-json/logos/icons.json", import.meta.url));
      const source = JSON.parse(readFileSync(path, "utf8"));
      const icons = Object.fromEntries(
        usedLogos.flatMap((name) => source.icons[name] ? [[name, source.icons[name]]] : [])
      );
      return `export default ${JSON.stringify({ width: source.width, height: source.height, icons })};`;
    },
  };
}

export default defineConfig({ plugins: [selectedBrandLogos()] });
