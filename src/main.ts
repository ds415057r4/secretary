import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import {
  createElement as createLucideIcon,
  Download,
  Eye,
  EyeOff,
  FolderClock,
  Fingerprint,
  ImagePlus,
  KeyRound,
  LockKeyhole,
  Minus,
  Pencil,
  Plus,
  RefreshCw,
  ScanLine,
  Search,
  SearchX,
  Settings,
  Star,
  Trash2,
  Upload,
  X,
  type IconNode,
} from "lucide";
import {
  si1password,
  siApple,
  siAtlassian,
  siAsana,
  siAuth0,
  siBinance,
  siBitbucket,
  siBitwarden,
  siCloudflare,
  siCoinbase,
  siDatadog,
  siDiscord,
  siDigitalocean,
  siDocker,
  siDropbox,
  siEbay,
  siEpicgames,
  siFacebook,
  siFigma,
  siGithub,
  siGitlab,
  siGoogle,
  siGooglecloud,
  siGrafana,
  siInstagram,
  siLastpass,
  siLinear,
  siMailchimp,
  siNetflix,
  siNaver,
  siNordvpn,
  siNotion,
  siOkta,
  siOpenvpn,
  siPaypal,
  siPlaystation,
  siProton,
  siProtonvpn,
  siReddit,
  siRiotgames,
  siRoblox,
  siSentry,
  siShopify,
  siSpotify,
  siStripe,
  siSteam,
  siTailscale,
  siTelegram,
  siTiktok,
  siTwitch,
  siTrello,
  siUbisoft,
  siVercel,
  siWhatsapp,
  siWordpress,
  siX,
  siYoutube,
  siYubico,
  siZoom,
  type SimpleIcon,
} from "simple-icons";
import logoIcons from "virtual:brand-logos";
import { ktOfficialLogo } from "./kt-logo";
import "pretendard/dist/web/variable/pretendardvariable.css";
import "./style.css";

type VaultStatus = { initialized: boolean; unlocked: boolean };
type CodeView = {
  id: string;
  issuer: string;
  account: string;
  code: string;
  period: number;
  remaining: number;
  icon?: string | null;
  brandIcon?: string | null;
  favorite: boolean;
};
type ImportSummary = { added: number; skipped: number; weakSecrets: number; batchIndex: number; batchSize: number };
type BackupSettingsView = {
  automaticFile: boolean; directory: string; retention: number;
};
type BackupStatusView = {
  configured: boolean; healthy: boolean; fileCount: number; lastBackupAt?: number | null; message: string;
};
type BiometricStatus = { supported: boolean; enabled: boolean; method: string };

const root = document.querySelector<HTMLDivElement>("#app")!;
const axgateVpnLogo = new URL("./assets/brands/axgate-vpn.png", import.meta.url).href;
const hunesionLogo = new URL("./assets/brands/hunesion.png", import.meta.url).href;
let codes: CodeView[] = [];
let refreshTimer: number | undefined;
let refreshingCodes = false;
let searchQuery = "";
let dragInProgress = false;
let draggedCard: HTMLElement | null = null;
let suppressCopyUntil = 0;
let checkingUpdate = false;
let updatePromptShown = false;
let vaultVisible = false;
let lastActivitySync = 0;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function icon(node: IconNode, className = "symbol") {
  const svg = createLucideIcon(node, { width: 18, height: 18, "aria-hidden": "true" });
  svg.classList.add(className);
  return svg;
}

function passwordField(placeholder: string, autocomplete: AutoFill, minLength?: number) {
  const field = el("div", "password-field");
  const leading = el("span", "password-field-icon");
  leading.append(icon(LockKeyhole));
  const input = el("input") as HTMLInputElement;
  input.type = "password";
  input.autocomplete = autocomplete;
  input.placeholder = placeholder;
  input.required = true;
  if (minLength !== undefined) input.minLength = minLength;
  const visibility = el("button", "password-visibility") as HTMLButtonElement;
  visibility.type = "button";
  const updateVisibility = (visible: boolean) => {
    input.type = visible ? "text" : "password";
    visibility.replaceChildren(icon(visible ? EyeOff : Eye));
    visibility.setAttribute("aria-label", visible ? "암호 숨기기" : "암호 표시");
    visibility.title = visible ? "암호 숨기기" : "암호 표시";
  };
  visibility.addEventListener("click", () => {
    const selectionStart = input.selectionStart;
    const selectionEnd = input.selectionEnd;
    updateVisibility(input.type === "password");
    input.focus();
    if (selectionStart !== null && selectionEnd !== null) input.setSelectionRange(selectionStart, selectionEnd);
  });
  updateVisibility(false);
  field.append(leading, input, visibility);
  return { field, input };
}

type BrandRule = { aliases: string[]; icon: SimpleIcon; logo?: string; custom?: "nhn-cloud" | "kt-cloud" | "axgate-vpn" | "hunesion" };
const brandInfo = (slug: string, title: string, hex: string) => ({
  slug, title, hex, path: "", source: "",
}) as SimpleIcon;
const brandRules: BrandRule[] = [
  { aliases: ["i-onengs", "i-one ngs", "ionengs", "hunesion", "휴네시온"], icon: brandInfo("hunesion", "i-oneNGS", "0868B2"), custom: "hunesion" },
  { aliases: ["axgate vpn", "axgate", "엑스게이트"], icon: brandInfo("axgate-vpn", "AXGATE VPN", "F15A24"), custom: "axgate-vpn" },
  { aliases: ["nhn cloud", "nhn클라우드", "nhn 클라우드"], icon: brandInfo("nhn-cloud", "NHN Cloud", "3E64FF"), custom: "nhn-cloud" },
  { aliases: ["kt cloud", "kt클라우드", "kt 클라우드"], icon: brandInfo("kt-cloud", "KT Cloud", "E60012"), custom: "kt-cloud" },
  { aliases: ["naver cloud", "navercloud", "네이버 클라우드", "네이버클라우드", "ncloud"], icon: siNaver },
  { aliases: ["amazon web services", "amazon aws", "aws"], icon: brandInfo("aws", "Amazon Web Services", "FF9900"), logo: "aws" },
  { aliases: ["microsoft azure", "azure"], icon: brandInfo("azure", "Microsoft Azure", "0078D4"), logo: "azure-icon" },
  { aliases: ["google cloud platform", "google cloud", "gcp"], icon: siGooglecloud, logo: "google-cloud" },
  { aliases: ["ibm cloud", "ibm클라우드", "ibm 클라우드", "ibm"], icon: brandInfo("ibm", "IBM", "4589FF"), logo: "ibm" },
  { aliases: ["oracle cloud infrastructure", "oracle cloud", "oraclecloud", "oracle 클라우드", "오라클 클라우드", "oracle"], icon: brandInfo("oracle-cloud", "Oracle Cloud", "F80000"), logo: "oracle" },
  { aliases: ["google", "gmail"], icon: siGoogle, logo: "google-icon" },
  { aliases: ["youtube"], icon: siYoutube, logo: "youtube-icon" },
  { aliases: ["github"], icon: siGithub, logo: "github-icon" },
  { aliases: ["gitlab"], icon: siGitlab, logo: "gitlab-icon" },
  { aliases: ["discord"], icon: siDiscord, logo: "discord-icon" },
  { aliases: ["notion"], icon: siNotion, logo: "notion-icon" },
  { aliases: ["figma"], icon: siFigma, logo: "figma" },
  { aliases: ["dropbox"], icon: siDropbox, logo: "dropbox" },
  { aliases: ["apple", "icloud"], icon: siApple, logo: "apple" },
  { aliases: ["facebook", "meta"], icon: siFacebook, logo: "facebook" },
  { aliases: ["instagram", "인스타그램", "insta"], icon: siInstagram, logo: "instagram-icon" },
  { aliases: ["microsoft", "office 365", "microsoft 365", "m365", "outlook", "onedrive", "entra"], icon: brandInfo("microsoft", "Microsoft", "5E5E5E"), logo: "microsoft-icon" },
  { aliases: ["linkedin", "링크드인"], icon: brandInfo("linkedin", "LinkedIn", "0A66C2"), logo: "linkedin-icon" },
  { aliases: ["slack", "슬랙"], icon: brandInfo("slack", "Slack", "4A154B"), logo: "slack-icon" },
  { aliases: ["salesforce"], icon: brandInfo("salesforce", "Salesforce", "00A1E0"), logo: "salesforce" },
  { aliases: ["adobe", "어도비"], icon: brandInfo("adobe", "Adobe", "FF0000"), logo: "adobe" },
  { aliases: ["openai", "chatgpt"], icon: brandInfo("openai", "OpenAI", "10A37F"), logo: "openai-icon" },
  { aliases: ["cloudflare"], icon: siCloudflare, logo: "cloudflare-icon" },
  { aliases: ["atlassian", "jira", "confluence"], icon: siAtlassian, logo: "atlassian" },
  { aliases: ["auth0"], icon: siAuth0, logo: "auth0-icon" },
  { aliases: ["okta"], icon: siOkta, logo: "okta-icon" },
  { aliases: ["proton"], icon: siProton }, { aliases: ["bitwarden"], icon: siBitwarden },
  { aliases: ["1password"], icon: si1password }, { aliases: ["lastpass"], icon: siLastpass },
  { aliases: ["yubico"], icon: siYubico }, { aliases: ["paypal"], icon: siPaypal, logo: "paypal" },
  { aliases: ["binance"], icon: siBinance }, { aliases: ["coinbase"], icon: siCoinbase },
  { aliases: ["steam"], icon: siSteam, logo: "steam" }, { aliases: ["twitch"], icon: siTwitch, logo: "twitch" },
  { aliases: ["twitter", "x.com"], icon: siX }, { aliases: ["reddit"], icon: siReddit, logo: "reddit-icon" },
  { aliases: ["spotify"], icon: siSpotify, logo: "spotify-icon" },
  { aliases: ["netflix"], icon: siNetflix, logo: "netflix-icon" },
  { aliases: ["telegram"], icon: siTelegram, logo: "telegram" },
  { aliases: ["whatsapp"], icon: siWhatsapp, logo: "whatsapp-icon" },
  { aliases: ["tiktok"], icon: siTiktok, logo: "tiktok-icon" },
  { aliases: ["wordpress"], icon: siWordpress, logo: "wordpress-icon" },
  { aliases: ["shopify"], icon: siShopify, logo: "shopify" },
  { aliases: ["docker"], icon: siDocker, logo: "docker-icon" },
  { aliases: ["digitalocean", "digital ocean"], icon: siDigitalocean, logo: "digital-ocean" },
  { aliases: ["heroku"], icon: brandInfo("heroku", "Heroku", "430098"), logo: "heroku-icon" },
  { aliases: ["twilio"], icon: brandInfo("twilio", "Twilio", "F22F46"), logo: "twilio-icon" },
  { aliases: ["bitbucket"], icon: siBitbucket, logo: "bitbucket" },
  { aliases: ["datadog"], icon: siDatadog, logo: "datadog" },
  { aliases: ["sentry"], icon: siSentry, logo: "sentry-icon" },
  { aliases: ["grafana"], icon: siGrafana, logo: "grafana" },
  { aliases: ["trello"], icon: siTrello, logo: "trello" },
  { aliases: ["asana"], icon: siAsana, logo: "asana" },
  { aliases: ["linear"], icon: siLinear, logo: "linear" },
  { aliases: ["mailchimp"], icon: siMailchimp, logo: "mailchimp" },
  { aliases: ["stripe"], icon: siStripe, logo: "stripe" },
  { aliases: ["ebay"], icon: siEbay },
  { aliases: ["epic games", "epicgames"], icon: siEpicgames },
  { aliases: ["ubisoft"], icon: siUbisoft },
  { aliases: ["playstation", "playstation network", "psn"], icon: siPlaystation },
  { aliases: ["riot games", "riotgames"], icon: siRiotgames },
  { aliases: ["roblox"], icon: siRoblox },
  { aliases: ["tailscale"], icon: siTailscale },
  { aliases: ["openvpn"], icon: siOpenvpn },
  { aliases: ["proton vpn", "protonvpn"], icon: siProtonvpn },
  { aliases: ["vercel", "vercel.com"], icon: siVercel },
  { aliases: ["nordvpn"], icon: siNordvpn }, { aliases: ["zoom"], icon: siZoom, logo: "zoom-icon" },
];

function matchedBrand(item: CodeView) {
  if (item.brandIcon) {
    const selected = brandRules.find((brand) => brand.icon.slug === item.brandIcon);
    if (selected) return selected;
  }
  const haystack = `${item.issuer} ${item.account}`.toLocaleLowerCase();
  return brandRules.find((brand) => brand.aliases.some((alias) => haystack.includes(alias)));
}

function brandSymbol(brand: SimpleIcon) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("brand-service-symbol");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", brand.path);
  svg.append(path);
  return svg;
}

function fullColorBrandSymbol(name: string) {
  const collection = logoIcons as unknown as {
    width?: number;
    height?: number;
    icons: Record<string, { body: string; width?: number; height?: number }>;
  };
  const data = collection.icons[name];
  if (!data) return null;
  const width = data.width ?? collection.width ?? 24;
  const height = data.height ?? collection.height ?? 24;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("brand-service-symbol", "full-color-logo");
  if (width / height > 1.7) svg.classList.add("wide-brand-symbol");
  const body = name === "aws" ? data.body.replaceAll("#252f3e", "#f4f4f6") : data.body;
  const parsed = new DOMParser().parseFromString(
    `<svg xmlns="http://www.w3.org/2000/svg">${body}</svg>`,
    "image/svg+xml"
  );
  for (const child of Array.from(parsed.documentElement.childNodes)) {
    svg.append(document.importNode(child, true));
  }
  return svg;
}

function customCloudSymbol(name: "nhn-cloud" | "kt-cloud" | "axgate-vpn" | "hunesion") {
  if (name === "axgate-vpn" || name === "hunesion") {
    const image = el("img", "brand-service-image") as HTMLImageElement;
    image.src = name === "hunesion" ? hunesionLogo : axgateVpnLogo;
    image.alt = "";
    image.draggable = false;
    return image;
  }
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("brand-service-symbol", `${name}-symbol`);
  if (name === "nhn-cloud") {
    for (const [cx, cy, radius, fill] of [
      [7, 13, 4, "#315EFF"], [12, 9, 4, "#6548E8"], [17, 13, 4, "#21B8E6"],
    ] as const) {
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", String(cx)); circle.setAttribute("cy", String(cy));
      circle.setAttribute("r", String(radius)); circle.setAttribute("fill", fill);
      svg.append(circle);
    }
  } else {
    const image = document.createElementNS("http://www.w3.org/2000/svg", "image");
    image.setAttribute("href", ktOfficialLogo);
    image.setAttribute("x", "1"); image.setAttribute("y", "1");
    image.setAttribute("width", "22"); image.setAttribute("height", "22");
    image.setAttribute("preserveAspectRatio", "xMidYMid meet");
    svg.append(image);
  }
  return svg;
}

function renderBrandSymbol(brand: BrandRule) {
  if (brand.custom) return customCloudSymbol(brand.custom);
  if (brand.logo && hasDarkBrandColor(brand.icon.hex) && brand.icon.path) {
    return brandSymbol(brand.icon);
  }
  return (brand.logo ? fullColorBrandSymbol(brand.logo) : null) ?? brandSymbol(brand.icon);
}

function hasDarkBrandColor(hex: string) {
  const value = Number.parseInt(hex, 16);
  const red = (value >> 16) & 255;
  const green = (value >> 8) & 255;
  const blue = value & 255;
  const luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  return luminance < 90;
}

function toast(message: string, kind: "ok" | "error" = "ok") {
  const node = el("div", `toast ${kind}`, message);
  document.body.append(node);
  requestAnimationFrame(() => node.classList.add("visible"));
  window.setTimeout(() => node.remove(), 2400);
}

function passwordPanel(initialized: boolean) {
  vaultVisible = false;
  codes = [];
  if (refreshTimer) window.clearInterval(refreshTimer);
  refreshTimer = undefined;
  root.replaceChildren();
  const titlebar = createTitlebar(false);
  titlebar.classList.add("auth-titlebar");
  const shell = el("main", "auth-shell");
  const card = el("section", "auth-card");
  card.append(el("h1", "", initialized ? "Secretary 잠금 해제" : "Secretary 설정"));
  card.append(el("p", "muted", initialized
    ? "마스터 비밀번호를 입력하세요."
    : "사용할 마스터 비밀번호를 설정하세요."));

  const form = el("form", "auth-form");
  const password = passwordField("마스터 비밀번호 (최소 12자)", initialized ? "current-password" : "new-password", 12);
  const pw = password.input;
  form.append(password.field);
  let confirm: HTMLInputElement | undefined;
  if (!initialized) {
    const confirmation = passwordField("마스터 비밀번호 확인", "new-password", 12);
    confirm = confirmation.input;
    form.append(confirmation.field);
  }
  const submit = el("button", "primary", initialized ? "잠금 해제" : "금고 생성") as HTMLButtonElement;
  submit.type = "submit";
  form.append(submit);
  if (initialized) {
    void invoke<BiometricStatus>("biometric_status").then((status) => {
      if (!status.enabled) return;
      const biometric = symbolButton(`${status.method}로 잠금 해제`, Fingerprint, async () => {
        biometric.disabled = true;
        try {
          await invoke("unlock_with_biometric");
          await showVault();
        } catch (error) {
          toast(String(error), "error");
        } finally {
          biometric.disabled = false;
        }
      }, "ghost biometric-unlock");
      biometric.disabled = !status.supported;
      if (!status.supported) biometric.title = `${status.method}을 현재 사용할 수 없습니다.`;
      form.append(biometric);
    }).catch(() => undefined);
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!initialized && pw.value !== confirm?.value) return toast("비밀번호가 일치하지 않습니다.", "error");
    submit.disabled = true;
    try {
      await invoke(initialized ? "unlock_vault" : "initialize_vault", { password: pw.value });
      pw.value = "";
      if (confirm) confirm.value = "";
      await showVault();
    } catch (error) {
      toast(String(error), "error");
    } finally {
      submit.disabled = false;
    }
  });
  card.append(form);
  shell.append(card);
  root.append(titlebar, shell);
  pw.focus();
}

function actionButton(label: string, action: () => void | Promise<void>, className = "ghost") {
  const button = el("button", className, label) as HTMLButtonElement;
  button.type = "button";
  button.addEventListener("click", () => void action());
  return button;
}

function symbolButton(label: string, symbol: IconNode, action: () => void | Promise<void>, className = "ghost") {
  const button = actionButton("", action, className);
  button.append(icon(symbol), el("span", "button-label", label));
  button.setAttribute("aria-label", label);
  return button;
}

function showSettingsMenu(anchor: HTMLElement) {
  document.querySelector(".popup-menu-layer")?.remove();
  const layer = el("div", "popup-menu-layer");
  const menu = el("div", "popup-menu settings-menu");
  menu.append(
    symbolButton("업데이트 확인", RefreshCw, () => {
      layer.remove();
      void checkForUpdates(true);
    }, "popup-menu-action"),
    symbolButton("백업 및 복구", FolderClock, () => {
      layer.remove();
      void backupCenterDialog();
    }, "popup-menu-action"),
    symbolButton("생체 인증", Fingerprint, () => {
      layer.remove();
      void biometricSettingsDialog();
    }, "popup-menu-action"),
    symbolButton("잠금", LockKeyhole, async () => {
      layer.remove();
      await invoke("lock_vault");
      passwordPanel(true);
    }, "popup-menu-action")
  );
  layer.append(menu);
  document.body.append(layer);
  const anchorRect = anchor.getBoundingClientRect();
  const menuRect = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(anchorRect.right - menuRect.width, window.innerWidth - menuRect.width - 8))}px`;
  menu.style.top = `${anchorRect.bottom + 5}px`;
  layer.addEventListener("pointerdown", (event) => {
    if (event.target === layer) layer.remove();
  });
}

async function biometricSettingsDialog() {
  let status: BiometricStatus;
  try {
    status = await invoke<BiometricStatus>("biometric_status");
  } catch (error) {
    toast(String(error), "error");
    return;
  }
  const body = el("section", "stack biometric-settings");
  const symbol = el("div", `biometric-symbol${status.enabled ? " enabled" : ""}`);
  symbol.append(icon(Fingerprint));
  const state = status.enabled ? "사용 중" : status.supported ? "사용 가능" : "사용할 수 없음";
  body.append(
    symbol,
    el("strong", "biometric-title", status.method),
    el("p", "muted biometric-description", status.enabled
      ? `다음 로그인부터 ${status.method}으로 금고를 잠금 해제할 수 있습니다.`
      : status.supported
        ? `마스터 비밀번호 대신 ${status.method}으로 빠르게 잠금을 해제합니다.`
        : `${status.method}이 설정되어 있는지 운영체제 설정에서 확인하세요.`),
    el("p", "biometric-state", state),
  );
  const action = el("button", status.enabled ? "ghost" : "primary", status.enabled ? "생체 인증 해제" : "생체 인증 설정") as HTMLButtonElement;
  action.type = "button";
  action.disabled = !status.supported && !status.enabled;
  body.append(action);
  const dialog = modal("생체 인증", body);
  action.addEventListener("click", async () => {
    action.disabled = true;
    try {
      await invoke(status.enabled ? "disable_biometric" : "enable_biometric");
      dialog.remove();
      toast(status.enabled ? "생체 인증을 해제했습니다." : `${status.method}을 설정했습니다.`);
    } catch (error) {
      toast(String(error), "error");
      action.disabled = false;
    }
  });
}

function updateDialog(update: Update) {
  if (updatePromptShown) return;
  updatePromptShown = true;
  const body = el("div", "stack update-dialog-body");
  body.append(
    el("p", "update-version", `Secretary ${update.version}`),
    el("p", "muted", "새 버전이 준비되었습니다."),
  );
  const notes = el("div", "update-notes", update.body?.trim() || "이번 릴리스의 변경 사항이 제공되지 않았습니다.");
  const progress = el("progress", "update-progress") as HTMLProgressElement;
  progress.max = 100;
  progress.value = 0;
  progress.hidden = true;
  const status = el("p", "muted update-status");
  const actions = el("div", "update-actions");
  const later = el("button", "ghost", "나중에") as HTMLButtonElement;
  later.type = "button";
  const install = el("button", "primary", "업데이트") as HTMLButtonElement;
  install.type = "button";
  actions.append(later, install);
  body.append(notes, progress, status, actions);
  const dialog = modal("업데이트", body);
  dialog.addEventListener("mousedown", (event) => {
    if (event.target === dialog) updatePromptShown = false;
  });
  const close = () => {
    updatePromptShown = false;
    dialog.remove();
  };
  later.addEventListener("click", close);
  dialog.querySelector<HTMLButtonElement>(".modal-head .icon-button")?.addEventListener("click", () => {
    updatePromptShown = false;
  });
  install.addEventListener("click", async () => {
    install.disabled = true;
    later.disabled = true;
    progress.hidden = false;
    status.textContent = "업데이트를 다운로드하고 있습니다.";
    let downloaded = 0;
    let total = 0;
    try {
      await update.downloadAndInstall((event) => {
        if (event.event === "Started") {
          total = event.data.contentLength ?? 0;
          progress.removeAttribute("value");
        } else if (event.event === "Progress") {
          downloaded += event.data.chunkLength;
          if (total > 0) {
            progress.value = Math.min(100, (downloaded / total) * 100);
          }
        } else if (event.event === "Finished") {
          progress.value = 100;
          status.textContent = "설치가 완료되었습니다. 다시 시작합니다.";
        }
      });
      await relaunch();
    } catch (error) {
      install.disabled = false;
      later.disabled = false;
      progress.hidden = true;
      status.textContent = "";
      toast(`업데이트 실패: ${String(error)}`, "error");
    }
  });
}

async function checkForUpdates(manual = false) {
  if (checkingUpdate) return;
  checkingUpdate = true;
  try {
    const update = await check();
    if (update) updateDialog(update);
    else if (manual) toast("현재 최신 버전을 사용하고 있습니다.");
  } catch (error) {
    if (manual) toast(`업데이트 확인 실패: ${String(error)}`, "error");
  } finally {
    checkingUpdate = false;
  }
}

async function backupCenterDialog() {
  let settings: BackupSettingsView;
  let backupStatus: BackupStatusView | null = null;
  try {
    [settings, backupStatus] = await Promise.all([
      invoke<BackupSettingsView>("get_backup_settings"),
      invoke<BackupStatusView>("get_backup_status"),
    ]);
  } catch (error) {
    toast(String(error), "error");
    return;
  }
  const form = el("form", "stack backup-settings-form");
  const status = el("section", `backup-status ${backupStatus.healthy ? "healthy" : "warning"}`);
  const statusTitle = backupStatus.healthy ? "백업 정상" : backupStatus.configured ? "백업 점검 필요" : "자동 백업 꺼짐";
  const lastBackup = backupStatus.lastBackupAt
    ? new Date(backupStatus.lastBackupAt * 1000).toLocaleString()
    : "없음";
  status.append(
    el("strong", "backup-status-title", statusTitle),
    el("p", "muted", backupStatus.message),
    el("p", "backup-status-meta", `파일 ${backupStatus.fileCount}개 · 최근 백업 ${lastBackup}`),
  );
  const enabledLabel = el("label", "toggle-row");
  const enabled = el("input") as HTMLInputElement;
  enabled.type = "checkbox";
  enabled.checked = settings.automaticFile;
  enabledLabel.append(enabled, el("span", "", "변경할 때마다 자동 백업"));

  const directoryRow = el("div", "directory-row");
  const directory = el("input") as HTMLInputElement;
  directory.value = settings.directory;
  directory.placeholder = "백업 폴더를 선택하세요";
  directory.readOnly = true;
  const choose = el("button", "ghost compact", "선택") as HTMLButtonElement;
  choose.type = "button";
  choose.addEventListener("click", async () => {
    const selected = await invoke<string | null>("choose_backup_directory");
    if (selected) directory.value = selected;
  });
  directoryRow.append(directory, choose);

  const retention = el("input") as HTMLInputElement;
  retention.type = "number";
  retention.min = "1";
  retention.max = "100";
  retention.value = String(settings.retention);
  const submit = el("button", "primary", "설정 저장") as HTMLButtonElement;
  submit.type = "submit";
  const manualActions = el("div", "backup-manual-actions");
  const exportButton = symbolButton("파일로 백업", Upload, () => {
    dialog.remove();
    backupDialog("export");
  }, "ghost");
  const importButton = symbolButton("파일에서 복구", Download, () => {
    dialog.remove();
    backupDialog("import");
  }, "ghost");
  manualActions.append(exportButton, importButton);
  form.append(
    status,
    el("p", "muted", "자동 백업도 AES-256-GCM으로 암호화되며 현재 마스터 비밀번호로 복구할 수 있습니다."),
    enabledLabel,
    el("p", "field-label", "백업 폴더"), directoryRow,
    el("p", "field-label", "보관할 백업 개수 (1~100)"), retention,
    el("p", "field-label backup-manual-label", "수동 백업 및 복구"), manualActions,
    submit
  );
  const dialog = modal("백업 및 복구", form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      await invoke("save_backup_settings", {
        automaticFile: enabled.checked,
        directory: directory.value,
        retention: Number(retention.value),
      });
      dialog.remove();
      toast(enabled.checked ? "자동 백업을 설정했습니다." : "자동 백업을 껐습니다.");
    } catch (error) {
      toast(String(error), "error");
    } finally {
      submit.disabled = false;
    }
  });
}

function showAddMenu(anchor: HTMLElement) {
  document.querySelector(".popup-menu-layer")?.remove();
  const layer = el("div", "popup-menu-layer");
  const menu = el("div", "popup-menu add-menu");
  menu.append(
    symbolButton("직접 추가", KeyRound, () => {
      layer.remove();
      addDialog();
    }, "popup-menu-action"),
    symbolButton("QR 스캔", ScanLine, async () => {
      layer.remove();
      try {
        await invoke("open_scanner");
      } catch (error) {
        toast(String(error), "error");
      }
    }, "popup-menu-action")
  );
  layer.append(menu);
  document.body.append(layer);
  const anchorRect = anchor.getBoundingClientRect();
  const menuRect = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(anchorRect.right - menuRect.width, window.innerWidth - menuRect.width - 8))}px`;
  menu.style.top = `${anchorRect.bottom + 5}px`;
  layer.addEventListener("pointerdown", (event) => {
    if (event.target === layer) layer.remove();
  });
}

function createTitlebar(showLock: boolean) {
  const header = el("header", "app-header");
  header.setAttribute("data-tauri-drag-region", "");
  const title = el("div", "brand");
  title.setAttribute("data-tauri-drag-region", "");
  title.append(el("div", "", "Secretary"));

  const actions = el("div", "window-actions");
  if (showLock) {
    const add = actionButton("", () => showAddMenu(add), "header-icon-button");
    add.append(icon(Plus));
    add.setAttribute("aria-label", "인증키 추가");
    add.title = "인증키 추가";
    const settings = actionButton("", () => showSettingsMenu(settings), "header-icon-button");
    settings.append(icon(Settings));
    settings.setAttribute("aria-label", "설정");
    settings.title = "설정";
    actions.append(add, settings);
  }
  let minimizing = false;
  const minimize = actionButton("", async () => {
    if (minimizing) return;
    minimizing = true;
    try {
      await invoke("minimize_main_window");
      codes = [];
      document.querySelector("#code-grid")?.replaceChildren();
    } catch (error) {
      toast(String(error), "error");
    } finally {
      minimizing = false;
    }
  }, "window-control");
  minimize.append(icon(Minus));
  minimize.setAttribute("aria-label", "최소화");
  const close = actionButton("", () => invoke("close_main_window"), "window-control close-window");
  close.append(icon(X));
  close.setAttribute("aria-label", "닫기");
  actions.append(minimize, close);
  header.append(title, actions);
  return header;
}

function modal(title: string, body: HTMLElement) {
  const backdrop = el("div", "modal-backdrop");
  const card = el("section", "modal");
  const head = el("div", "modal-head");
  head.append(el("h2", "", title));
  const close = actionButton("", () => backdrop.remove(), "icon-button");
  close.append(icon(X));
  close.setAttribute("aria-label", "닫기");
  head.append(close);
  card.append(head, body);
  backdrop.append(card);
  backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) backdrop.remove(); });
  document.body.append(backdrop);
  return backdrop;
}

function addDialog() {
  const form = el("form", "stack");
  const uri = el("textarea") as HTMLTextAreaElement;
  uri.placeholder = "otpauth://totp/서비스:계정?secret=...";
  uri.required = true;
  uri.spellcheck = false;
  const submit = el("button", "primary", "암호화하여 추가") as HTMLButtonElement;
  submit.type = "submit";
  form.append(el("p", "muted", "URI는 Rust 백엔드에서 검증되며 평문으로 저장되지 않습니다."), uri, submit);
  const dialog = modal("인증키 직접 추가", form);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      await invoke("add_otpauth_uri", { uri: uri.value });
      uri.value = "";
      dialog.remove();
      await refreshCodes();
      toast("인증키를 안전하게 추가했습니다.");
    } catch (error) { toast(String(error), "error"); }
    finally { submit.disabled = false; }
  });
  uri.focus();
}

function backupDialog(mode: "export" | "import") {
  const form = el("form", "stack");
  const password = passwordField(
    mode === "export" ? "백업 암호 (최소 12자)" : "백업 파일 암호",
    "off",
    12,
  );
  const pw = password.input;
  const submit = el("button", "primary", mode === "export" ? "저장 위치 선택" : "백업 파일 선택") as HTMLButtonElement;
  submit.type = "submit";
  form.append(el("p", "muted", mode === "export"
    ? "새 salt와 nonce로 다시 암호화된 .enc 파일을 만듭니다."
    : "가져온 항목은 현재 열린 금고를 대체합니다."), password.field, submit);
  const dialog = modal(mode === "export" ? "암호화 백업 내보내기" : "암호화 백업 복구", form);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      if (mode === "export") {
        const saved = await invoke<boolean>("export_backup", { password: pw.value });
        pw.value = "";
        if (saved) {
          dialog.remove();
          toast("암호화 백업을 저장했습니다.");
        }
      } else {
        const restoredEntries = await invoke<number | null>("import_backup", { password: pw.value });
        pw.value = "";
        if (restoredEntries !== null) {
          dialog.remove();
          searchQuery = "";
          await refreshCodes();
          toast(`백업에서 인증키 ${restoredEntries}개를 복구했습니다.`);
        }
      }
    } catch (error) { toast(String(error), "error"); }
    finally { submit.disabled = false; }
  });
  pw.focus();
}

function editEntryDialog(item: CodeView) {
  const form = el("form", "stack");
  let selectedBrandIcon = item.brandIcon ?? null;
  let selectedIcon = item.icon ?? null;
  const iconField = el("section", "icon-field");
  iconField.append(el("p", "field-label", "아이콘"));
  const picker = el("div", "icon-picker");
  const pickerButtons: HTMLButtonElement[] = [];
  const selectButton = (button: HTMLButtonElement, selected: boolean) => {
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  };
  const automatic = actionButton("", () => {
    selectedBrandIcon = null;
    selectedIcon = null;
    pickerButtons.forEach((button) => selectButton(button, button === automatic));
  }, "icon-choice");
  automatic.title = "자동 선택";
  automatic.setAttribute("aria-label", "자동 선택");
  automatic.append(icon(KeyRound));
  pickerButtons.push(automatic);
  picker.append(automatic);
  for (const brand of brandRules) {
    const button = actionButton("", () => {
      selectedBrandIcon = brand.icon.slug;
      selectedIcon = null;
      pickerButtons.forEach((candidate) => selectButton(candidate, candidate === button));
    }, "icon-choice");
    button.title = brand.icon.title;
    button.setAttribute("aria-label", brand.icon.title);
    const darkBrand = hasDarkBrandColor(brand.icon.hex);
    if (!brand.logo || (darkBrand && brand.icon.path)) {
      button.style.color = darkBrand ? "#f4f4f6" : `#${brand.icon.hex}`;
    }
    button.append(renderBrandSymbol(brand));
    selectButton(button, item.brandIcon === brand.icon.slug);
    pickerButtons.push(button);
    picker.append(button);
  }
  const custom = actionButton("", async () => {
    try {
      const chosen = await invoke<string | null>("choose_entry_icon");
      if (chosen) {
        selectedBrandIcon = null;
        selectedIcon = chosen;
        pickerButtons.forEach((button) => selectButton(button, button === custom));
      }
    } catch (error) { toast(String(error), "error"); }
  }, "icon-choice custom-icon-choice");
  custom.title = "사용자 이미지";
  custom.setAttribute("aria-label", "사용자 이미지");
  custom.append(icon(ImagePlus));
  selectButton(automatic, !item.icon && !item.brandIcon);
  selectButton(custom, Boolean(item.icon));
  pickerButtons.push(custom);
  picker.append(custom);
  iconField.append(picker);
  const issuer = el("input") as HTMLInputElement;
  issuer.value = item.issuer;
  issuer.placeholder = "서비스명";
  issuer.maxLength = 256;
  const account = el("input") as HTMLInputElement;
  account.value = item.account;
  account.placeholder = "계정";
  account.maxLength = 512;
  account.required = true;
  const submit = el("button", "primary", "저장") as HTMLButtonElement;
  submit.type = "submit";
  form.append(iconField, issuer, account, submit);
  const dialog = modal("인증키 수정", form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      await invoke("update_entry", {
        id: item.id,
        issuer: issuer.value,
        account: account.value,
        brandIcon: selectedBrandIcon,
        icon: selectedIcon,
      });
      dialog.remove();
      await refreshCodes();
      toast("수정 완료");
    } catch (error) {
      toast(String(error), "error");
    } finally {
      submit.disabled = false;
    }
  });
  issuer.focus();
  issuer.select();
}

async function deleteEntry(item: CodeView) {
  if (!window.confirm(`${item.issuer || "인증키"} (${item.account}) 인증키를 삭제할까요?`)) return;
  try {
    await invoke("delete_entry", { id: item.id });
    await refreshCodes();
    toast("삭제 완료");
  } catch (error) {
    toast(String(error), "error");
  }
}

function showEntryContextMenu(item: CodeView, x: number, y: number) {
  document.querySelector(".context-menu-layer")?.remove();
  const layer = el("div", "context-menu-layer");
  const menu = el("div", "context-menu");
  menu.setAttribute("role", "menu");
  const edit = symbolButton("수정", Pencil, () => {
    layer.remove();
    editEntryDialog(item);
  }, "context-menu-action");
  edit.setAttribute("role", "menuitem");
  const favorite = symbolButton(item.favorite ? "즐겨찾기 해제" : "즐겨찾기", Star, async () => {
    layer.remove();
    try {
      await invoke("set_entry_favorite", { id: item.id, favorite: !item.favorite });
      await refreshCodes();
      toast(item.favorite ? "즐겨찾기에서 해제했습니다." : "즐겨찾기에 추가했습니다.");
    } catch (error) {
      toast(String(error), "error");
    }
  }, "context-menu-action");
  favorite.setAttribute("role", "menuitem");
  if (item.favorite) favorite.classList.add("favorite-active");
  const remove = symbolButton("삭제", Trash2, () => {
    layer.remove();
    void deleteEntry(item);
  }, "context-menu-action danger");
  remove.setAttribute("role", "menuitem");
  menu.append(favorite, edit, remove);
  layer.append(menu);
  document.body.append(layer);
  const rect = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - rect.width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, window.innerHeight - rect.height - 8))}px`;
  layer.addEventListener("pointerdown", (event) => {
    if (event.target === layer) layer.remove();
  });
}

function codeCard(item: CodeView) {
  const card = el("article", "otp-card");
  card.dataset.entryId = item.id;
  card.draggable = false;
  card.title = "드래그해 순서 변경 · 클릭해 OTP 복사";
  const left = el("div", "entry-left");
  const tile = el("div", "entry-icon");
  const colorIndex = [...item.id].reduce((total, char) => total + char.charCodeAt(0), 0) % 4;
  const brand = matchedBrand(item);
  if (item.icon) {
    const image = el("img", "custom-entry-icon") as HTMLImageElement;
    image.src = item.icon;
    image.alt = "";
    tile.append(image);
  } else if (brand) {
    const darkBrand = hasDarkBrandColor(brand.icon.hex);
    tile.style.color = darkBrand ? "#f4f4f6" : `#${brand.icon.hex}`;
    tile.style.backgroundColor = brand.logo ? "#1b1c1e" : (darkBrand ? "#25272a" : `#${brand.icon.hex}20`);
    tile.style.borderColor = brand.logo ? "rgba(255,255,255,.16)" : (darkBrand ? "rgba(255,255,255,.14)" : `#${brand.icon.hex}35`);
    tile.append(renderBrandSymbol(brand));
  } else {
    tile.dataset.accent = String(colorIndex);
    tile.append(icon(KeyRound, "entry-symbol"));
  }
  const identity = el("div", "entry-identity");
  const issuerRow = el("div", "issuer-row");
  issuerRow.append(el("h2", "issuer", item.issuer || "인증키"));
  if (item.favorite) issuerRow.append(icon(Star, "favorite-marker"));
  identity.append(issuerRow, el("p", "account", item.account));
  left.append(tile, identity);
  const right = el("div", "entry-right");
  const copyCode = async () => {
    try {
      await invoke("copy_code", { id: item.id });
      toast("복사 완료");
    } catch (error) { toast(String(error), "error"); }
  };
  const code = el("div", "otp-code");
  const splitAt = Math.floor(item.code.length / 2);
  code.append(
    el("span", "otp-group", item.code.slice(0, splitAt)),
    el("span", "otp-group", item.code.slice(splitAt))
  );
  const expiring = item.remaining <= 5;
  if (expiring) code.classList.add("expiring");
  code.setAttribute("aria-label", `${item.issuer} OTP 복사`);
  const timer = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  timer.classList.add("timer-ring");
  timer.setAttribute("viewBox", "0 0 24 24");
  const track = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  track.classList.add("timer-track");
  track.setAttribute("cx", "12");
  track.setAttribute("cy", "12");
  track.setAttribute("r", "9");
  const value = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  value.classList.add("timer-value");
  value.setAttribute("cx", "12");
  value.setAttribute("cy", "12");
  value.setAttribute("r", "9");
  const circumference = 2 * Math.PI * 9;
  const ratio = Math.max(0, Math.min(1, item.remaining / item.period));
  value.style.strokeDasharray = `${circumference}`;
  value.style.strokeDashoffset = `${circumference * (1 - ratio)}`;
  timer.append(track, value);
  if (expiring) timer.classList.add("expiring");
  timer.setAttribute("role", "img");
  timer.setAttribute("aria-label", "OTP 만료 진행률");
  right.append(code, timer);
  card.append(left, right);
  card.tabIndex = 0;
  card.setAttribute("role", "button");
    card.setAttribute("aria-label", `${item.issuer || "인증키"} OTP 복사`);
  card.addEventListener("click", (event) => {
    if (Date.now() < suppressCopyUntil) return;
    void copyCode();
  });
  card.addEventListener("keydown", (event) => {
    if (event.target !== card || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    void copyCode();
  });
  card.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    showEntryContextMenu(item, event.clientX, event.clientY);
  });
  let pointerId: number | null = null;
  let pointerStart = { x: 0, y: 0 };
  let pointerDragging = false;
  const finishPointerDrag = async (event: PointerEvent, persist: boolean) => {
    if (pointerId !== event.pointerId) return;
    if (card.hasPointerCapture(pointerId)) card.releasePointerCapture(pointerId);
    pointerId = null;
    if (!pointerDragging) return;
    pointerDragging = false;
    card.classList.remove("dragging");
    dragInProgress = false;
    draggedCard = null;
    suppressCopyUntil = Date.now() + 350;
    if (!persist) {
      await refreshCodes();
      return;
    }
    const orderedIds = Array.from(document.querySelectorAll<HTMLElement>("#code-grid .otp-card"))
      .map((node) => node.dataset.entryId)
      .filter((id): id is string => Boolean(id));
    try {
      await invoke("reorder_entries", { orderedIds });
      await refreshCodes();
    } catch (error) {
      toast(String(error), "error");
      await refreshCodes();
    }
  };
  card.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || pointerId !== null) return;
    pointerId = event.pointerId;
    pointerStart = { x: event.clientX, y: event.clientY };
    card.setPointerCapture(event.pointerId);
  });
  card.addEventListener("pointermove", (event) => {
    if (pointerId !== event.pointerId) return;
    if (!pointerDragging) {
      if (Math.hypot(event.clientX - pointerStart.x, event.clientY - pointerStart.y) < 6) return;
      pointerDragging = true;
      dragInProgress = true;
      draggedCard = card;
      card.classList.add("dragging");
    }
    event.preventDefault();
    const list = card.parentElement;
    if (!list) return;
    const listBounds = list.getBoundingClientRect();
    if (event.clientY < listBounds.top + 32) list.scrollTop -= 10;
    else if (event.clientY > listBounds.bottom - 32) list.scrollTop += 10;
    const hit = document.elementFromPoint(event.clientX, event.clientY);
    const target = hit?.closest<HTMLElement>(".otp-card");
    if (target && target !== card && target.parentElement === list) {
      const bounds = target.getBoundingClientRect();
      list.insertBefore(card, event.clientY < bounds.top + bounds.height / 2 ? target : target.nextSibling);
      return;
    }
    const last = list.querySelector<HTMLElement>(".otp-card:last-child");
    if (last && last !== card && event.clientY > last.getBoundingClientRect().top) list.append(card);
  });
  card.addEventListener("pointerup", (event) => void finishPointerDrag(event, true));
  card.addEventListener("pointercancel", (event) => void finishPointerDrag(event, false));
  card.addEventListener("lostpointercapture", (event) => {
    if (pointerId === event.pointerId) void finishPointerDrag(event, true);
  });
  card.addEventListener("dragstart", (event) => event.preventDefault());
  return card;
}

function renderCodes() {
  const list = document.querySelector("#code-grid");
  if (!list) return;
  list.replaceChildren();
  const normalized = searchQuery.trim().toLocaleLowerCase();
  const visible = normalized
    ? codes.filter((item) => `${item.issuer} ${item.account}`.toLocaleLowerCase().includes(normalized))
    : codes;
  if (!visible.length) {
    const empty = el("section", "empty");
    const emptyIcon = el("div", "empty-icon");
    emptyIcon.append(icon(normalized ? SearchX : KeyRound, "empty-symbol"));
    empty.append(
      emptyIcon,
      el("h2", "", normalized ? "검색 결과가 없습니다" : "인증키가 없습니다"),
      el("p", "muted", normalized ? "다른 서비스명이나 계정으로 검색해 보세요." : "QR 스캔 또는 직접 추가로 첫 인증키를 등록하세요.")
    );
    list.append(empty);
  } else visible.forEach((item) => list.append(codeCard(item)));
}

function sameCodeStructure(previous: CodeView[], next: CodeView[]) {
  return previous.length === next.length && previous.every((item, index) => {
    const candidate = next[index];
    return item.id === candidate.id
      && item.issuer === candidate.issuer
      && item.account === candidate.account
      && item.period === candidate.period
      && item.icon === candidate.icon
      && item.brandIcon === candidate.brandIcon
      && item.favorite === candidate.favorite;
  });
}

function updateCodeValues() {
  const circumference = 2 * Math.PI * 9;
  for (const card of document.querySelectorAll<HTMLElement>("#code-grid .otp-card[data-entry-id]")) {
    const item = codes.find((candidate) => candidate.id === card.dataset.entryId);
    if (!item) continue;
    const groups = card.querySelectorAll<HTMLElement>(".otp-group");
    const splitAt = Math.floor(item.code.length / 2);
    if (groups.length === 2) {
      groups[0].textContent = item.code.slice(0, splitAt);
      groups[1].textContent = item.code.slice(splitAt);
    }
    const expiring = item.remaining <= 5;
    card.querySelector(".otp-code")?.classList.toggle("expiring", expiring);
    const timer = card.querySelector<SVGElement>(".timer-ring");
    timer?.classList.toggle("expiring", expiring);
    const value = timer?.querySelector<SVGCircleElement>(".timer-value");
    if (value) {
      const ratio = Math.max(0, Math.min(1, item.remaining / item.period));
      value.style.strokeDashoffset = `${circumference * (1 - ratio)}`;
    }
  }
}

function tickCodes() {
  if (document.hidden || dragInProgress || refreshingCodes) return;
  const now = Math.floor(Date.now() / 1000);
  let rolledOver = false;
  for (const item of codes) {
    const remaining = item.period - (now % item.period);
    if (remaining > item.remaining) rolledOver = true;
    item.remaining = remaining;
  }
  if (rolledOver) void refreshCodes();
  else updateCodeValues();
}

async function refreshCodes() {
  if (dragInProgress || refreshingCodes) return;
  refreshingCodes = true;
  try {
    const next = await invoke<CodeView[]>("list_codes");
    const structureChanged = !sameCodeStructure(codes, next);
    codes = next;
    if (structureChanged) renderCodes();
    else updateCodeValues();
  } catch {
    if (refreshTimer) window.clearInterval(refreshTimer);
    passwordPanel(true);
  } finally {
    refreshingCodes = false;
  }
}

async function showVault() {
  vaultVisible = true;
  lastActivitySync = Date.now();
  root.replaceChildren();
  const page = el("main", "app-shell");
  const header = createTitlebar(true);

  const palette = el("section", "command-palette");
  const searchBar = el("div", "palette-search");
  const searchSymbol = el("span", "search-icon");
  searchSymbol.append(icon(Search));
  searchBar.append(searchSymbol);
  const search = el("input", "search-input") as HTMLInputElement;
  search.type = "search";
  search.placeholder = "인증키 검색…";
  search.autocomplete = "off";
  search.value = searchQuery;
  search.addEventListener("input", () => { searchQuery = search.value; renderCodes(); });
  searchBar.append(search);
  const grid = el("section", "code-grid");
  grid.id = "code-grid";
  palette.append(searchBar, grid);
  page.append(header, palette);
  root.append(page);
  await refreshCodes();
  if (refreshTimer) window.clearInterval(refreshTimer);
  refreshTimer = window.setInterval(tickCodes, 1000);
}

async function scannerMode() {
  document.documentElement.classList.add("scanner-root");
  document.body.classList.add("scanner-body");
  root.replaceChildren();
  const overlay = el("main", "scanner-overlay");
  const hint = el("div", "scanner-hint", "QR 코드 영역을 드래그하세요 · ESC 취소");
  const cancel = el("button", "scanner-cancel", "취소") as HTMLButtonElement;
  cancel.type = "button";
  cancel.addEventListener("pointerdown", (event) => event.stopPropagation());
  cancel.addEventListener("pointerup", (event) => event.stopPropagation());
  cancel.addEventListener("click", (event) => {
    event.stopPropagation();
    void invoke("close_scanner");
  });
  const selection = el("div", "selection");
  overlay.append(hint, cancel, selection);
  root.append(overlay);
  let start: { x: number; y: number } | null = null;
  overlay.addEventListener("pointerdown", (e) => {
    if (e.target !== overlay) return;
    start = { x: e.clientX, y: e.clientY };
    selection.style.display = "block";
    selection.style.left = `${e.clientX}px`;
    selection.style.top = `${e.clientY}px`;
    selection.style.width = "0";
    selection.style.height = "0";
    overlay.setPointerCapture(e.pointerId);
  });
  overlay.addEventListener("pointermove", (e) => {
    if (!start) return;
    selection.style.left = `${Math.min(start.x, e.clientX)}px`;
    selection.style.top = `${Math.min(start.y, e.clientY)}px`;
    selection.style.width = `${Math.abs(e.clientX - start.x)}px`;
    selection.style.height = `${Math.abs(e.clientY - start.y)}px`;
  });
  overlay.addEventListener("pointerup", async (e) => {
    if (!start) return;
    const x = Math.min(start.x, e.clientX);
    const y = Math.min(start.y, e.clientY);
    const width = Math.abs(e.clientX - start.x);
    const height = Math.abs(e.clientY - start.y);
    start = null;
    if (width < 24 || height < 24) return;
    hint.textContent = "QR 코드를 안전하게 분석하는 중…";
    try {
      await invoke("scan_screen_region", {
        x: Math.round(x * devicePixelRatio), y: Math.round(y * devicePixelRatio),
        width: Math.round(width * devicePixelRatio), height: Math.round(height * devicePixelRatio)
      });
    } catch (error) {
      hint.textContent = String(error);
      selection.style.display = "none";
    }
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      void invoke("close_scanner");
    }
  });
}

function miniMode() {
  document.documentElement.classList.add("mini-root");
  document.body.classList.add("mini-body");
  root.replaceChildren();
  const button = el("button", "mini-tab") as HTMLButtonElement;
  button.type = "button";
  button.title = "Secretary 열기";
  button.setAttribute("aria-label", "Secretary 창 열기");
  let revealed = false;
  let transitionId = 0;
  let miniTimer: number | undefined;
  let favorites: CodeView[] = [];
  let refreshingFavorites = false;

  const favoritesStructure = (items: CodeView[]) => items
    .map((item) => [item.id, item.issuer, item.account, item.icon ?? "", item.brandIcon ?? ""].join("\u0000"))
    .join("\u0001");

  const updateFavoriteValues = () => {
    const rows = root.querySelectorAll<HTMLElement>(".mini-otp-row[data-entry-id]");
    rows.forEach((row) => {
      const item = favorites.find((candidate) => candidate.id === row.dataset.entryId);
      const code = row.querySelector<HTMLElement>(".mini-code");
      if (!item || !code) return;
      code.classList.toggle("expiring", item.remaining <= 5);
      if (code.dataset.copyFeedback !== "true") code.textContent = item.code;
    });
  };

  const renderFavorites = () => {
    const panel = el("section", "mini-panel");
    const head = el("button", "mini-head") as HTMLButtonElement;
    head.type = "button";
    head.append(el("strong", "", "즐겨찾기"), el("span", "", "Secretary 열기"));
    head.addEventListener("click", () => void invoke("restore_main_window"));
    panel.append(head);
    if (!favorites.length) {
      panel.append(el("p", "mini-empty", "즐겨찾기한 OTP가 없습니다."));
    } else {
      for (const item of favorites) {
        const row = el("button", "mini-otp-row") as HTMLButtonElement;
        row.type = "button";
        row.dataset.entryId = item.id;
        const tile = el("span", "mini-entry-icon");
        const brand = matchedBrand(item);
        if (item.icon) {
          const image = el("img", "custom-entry-icon") as HTMLImageElement;
          image.src = item.icon;
          image.alt = "";
          tile.append(image);
        } else if (brand) {
          tile.style.color = hasDarkBrandColor(brand.icon.hex) ? "#f4f4f6" : `#${brand.icon.hex}`;
          tile.append(renderBrandSymbol(brand));
        } else {
          tile.append(icon(KeyRound, "entry-symbol"));
        }
        const identity = el("span", "mini-identity");
        identity.append(el("strong", "", item.issuer || "인증키"), el("small", "", item.account));
        const code = el("span", `mini-code${item.remaining <= 5 ? " expiring" : ""}`, item.code);
        row.append(tile, identity, code);
        row.addEventListener("click", async () => {
          try {
            await invoke("copy_code", { id: item.id });
            code.dataset.copyFeedback = "true";
            code.textContent = "복사됨";
            window.setTimeout(() => {
              delete code.dataset.copyFeedback;
              code.textContent = favorites.find((candidate) => candidate.id === item.id)?.code ?? item.code;
            }, 700);
          } catch {
            await invoke("restore_main_window");
          }
        });
        panel.append(row);
      }
    }
    root.replaceChildren(panel);
  };

  const refreshFavorites = async () => {
    if (refreshingFavorites) return;
    refreshingFavorites = true;
    try {
      const previousStructure = favoritesStructure(favorites);
      const next = await invoke<CodeView[]>("list_favorite_codes");
      const structureChanged = previousStructure !== favoritesStructure(next);
      const countChanged = favorites.length !== next.length;
      favorites = next;
      if (!revealed) return;
      if (countChanged) {
        await invoke("set_mini_revealed", { revealed: true, itemCount: favorites.length });
      }
      if (structureChanged) renderFavorites();
      else updateFavoriteValues();
    } finally {
      refreshingFavorites = false;
    }
  };

  const tickFavorites = () => {
    if (!revealed || refreshingFavorites) return;
    const now = Math.floor(Date.now() / 1000);
    let rolledOver = false;
    for (const item of favorites) {
      const remaining = item.period - (now % item.period);
      if (remaining > item.remaining) rolledOver = true;
      item.remaining = remaining;
    }
    if (rolledOver) void refreshFavorites();
    else updateFavoriteValues();
  };

  const reveal = async () => {
    if (revealed) return;
    const id = ++transitionId;
    try {
      favorites = await invoke<CodeView[]>("list_favorite_codes");
      await invoke("set_mini_revealed", { revealed: true, itemCount: favorites.length });
      if (id !== transitionId) return;
      requestAnimationFrame(() => {
        if (id !== transitionId) return;
        revealed = true;
        renderFavorites();
        miniTimer = window.setInterval(tickFavorites, 1000);
      });
    } catch (error) {
      await invoke("restore_main_window");
    }
  };
  const conceal = async () => {
    if (!revealed) return;
    const id = ++transitionId;
    revealed = false;
    if (miniTimer) window.clearInterval(miniTimer);
    root.classList.add("mini-concealing");
    await new Promise((resolve) => window.setTimeout(resolve, 180));
    if (id !== transitionId) return;
    try {
      await invoke("set_mini_revealed", { revealed: false });
      root.classList.remove("mini-concealing");
      favorites = [];
      root.replaceChildren(button);
    } catch (error) {
      toast(String(error), "error");
    }
  };
  root.addEventListener("pointerenter", () => void reveal());
  root.addEventListener("pointerleave", () => void conceal());
  root.append(button);
}

async function bootstrap() {
  window.addEventListener("contextmenu", (event) => event.preventDefault());
  if (getCurrentWindow().label === "scanner") return scannerMode();
  if (getCurrentWindow().label === "mini") return miniMode();
  const registerActivity = () => {
    if (!vaultVisible || Date.now() - lastActivitySync < 10_000) return;
    lastActivitySync = Date.now();
    void invoke("touch_session").catch(() => {
      if (vaultVisible) passwordPanel(true);
    });
  };
  window.addEventListener("pointerdown", registerActivity, { capture: true, passive: true });
  window.addEventListener("keydown", registerActivity, { capture: true });
  await listen<ImportSummary>("vault-changed", async (event) => {
    await refreshCodes();
    const skipped = event.payload.skipped ? ` · 중복 ${event.payload.skipped}개 제외` : "";
    const batch = event.payload.batchSize > 1
      ? ` · 내보내기 QR ${event.payload.batchIndex + 1}/${event.payload.batchSize}`
      : "";
    const legacy = event.payload.weakSecrets ? ` · 레거시 짧은 Secret ${event.payload.weakSecrets}개` : "";
    toast(`인증키 ${event.payload.added}개를 추가했습니다${skipped}${legacy}${batch}`);
  });
  await listen("main-restored", () => {
    if (vaultVisible) void refreshCodes();
  });
  const status = await invoke<VaultStatus>("vault_status");
  status.unlocked ? await showVault() : passwordPanel(status.initialized);
  window.setTimeout(() => void checkForUpdates(false), 1200);
}

void bootstrap();
