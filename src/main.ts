import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import {
  createElement as createLucideIcon,
  Copy,
  Dices,
  Download,
  FolderClock,
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
  Trash2,
  Upload,
  X,
  type IconNode,
} from "lucide";
import {
  si1password,
  siApple,
  siAtlassian,
  siAuth0,
  siBinance,
  siBitwarden,
  siCloudflare,
  siCoinbase,
  siDiscord,
  siDocker,
  siDropbox,
  siFacebook,
  siFigma,
  siGithub,
  siGitlab,
  siGoogle,
  siGooglecloud,
  siLastpass,
  siNetflix,
  siNaver,
  siNordvpn,
  siNotion,
  siOkta,
  siPaypal,
  siProton,
  siReddit,
  siShopify,
  siSpotify,
  siSteam,
  siTelegram,
  siTiktok,
  siTwitch,
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
};
type ImportSummary = { added: number; skipped: number; weakSecrets: number; batchIndex: number; batchSize: number };
type BackupSettingsView = {
  automaticFile: boolean; directory: string; retention: number;
};

const root = document.querySelector<HTMLDivElement>("#app")!;
const axgateVpnLogo = new URL("./assets/brands/axgate-vpn.png", import.meta.url).href;
let codes: CodeView[] = [];
let refreshTimer: number | undefined;
let searchQuery = "";
let dragInProgress = false;
let draggedCard: HTMLElement | null = null;
let suppressCopyUntil = 0;
let checkingUpdate = false;
let updatePromptShown = false;

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

type BrandRule = { aliases: string[]; icon: SimpleIcon; logo?: string; custom?: "nhn-cloud" | "kt-cloud" | "axgate-vpn" };
const brandInfo = (slug: string, title: string, hex: string) => ({
  slug, title, hex, path: "", source: "",
}) as SimpleIcon;
const brandRules: BrandRule[] = [
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

function customCloudSymbol(name: "nhn-cloud" | "kt-cloud" | "axgate-vpn") {
  if (name === "axgate-vpn") {
    const image = el("img", "brand-service-image") as HTMLImageElement;
    image.src = axgateVpnLogo;
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
  const pw = el("input") as HTMLInputElement;
  pw.type = "password";
  pw.autocomplete = initialized ? "current-password" : "new-password";
  pw.placeholder = "마스터 비밀번호 (최소 12자)";
  pw.required = true;
  pw.minLength = 12;
  form.append(pw);
  let confirm: HTMLInputElement | undefined;
  if (!initialized) {
    confirm = el("input") as HTMLInputElement;
    confirm.type = "password";
    confirm.autocomplete = "new-password";
    confirm.placeholder = "마스터 비밀번호 확인";
    confirm.required = true;
    form.append(confirm);
  }
  const submit = el("button", "primary", initialized ? "잠금 해제" : "금고 생성") as HTMLButtonElement;
  submit.type = "submit";
  form.append(submit);
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
  try {
    settings = await invoke<BackupSettingsView>("get_backup_settings");
  } catch (error) {
    toast(String(error), "error");
    return;
  }
  const form = el("form", "stack backup-settings-form");
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
    }, "popup-menu-action"),
    symbolButton("암호 생성", Dices, () => {
      layer.remove();
      passwordGeneratorDialog();
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

function passwordGeneratorDialog() {
  const body = el("section", "stack password-generator");
  const output = el("input", "generated-password") as HTMLInputElement;
  output.readOnly = true;
  output.spellcheck = false;
  output.setAttribute("aria-label", "생성된 암호");
  const lengthRow = el("label", "password-length-row");
  lengthRow.append(el("span", "", "길이"));
  const length = el("input") as HTMLInputElement;
  length.type = "number";
  length.min = "12";
  length.max = "128";
  length.value = "24";
  lengthRow.append(length);
  const options = el("div", "password-options");
  const option = (label: string, checked: boolean) => {
    const wrapper = el("label", "toggle-row");
    const input = el("input") as HTMLInputElement;
    input.type = "checkbox";
    input.checked = checked;
    wrapper.append(input, el("span", "", label));
    options.append(wrapper);
    return input;
  };
  const lowercase = option("소문자", true);
  const uppercase = option("대문자", true);
  const digits = option("숫자", true);
  const symbols = option("특수문자", true);
  const actions = el("div", "password-actions");
  const regenerate = symbolButton("다시 생성", RefreshCw, () => void generate(), "ghost");
  const copy = symbolButton("복사", Copy, async () => {
    if (!output.value) return;
    try {
      await invoke("copy_generated_password", { password: output.value });
      toast("복사 완료");
    } catch (error) { toast(String(error), "error"); }
  }, "primary");
  actions.append(regenerate, copy);
  body.append(output, lengthRow, options, actions);
  modal("암호 생성", body);

  async function generate() {
    regenerate.disabled = true;
    try {
      output.value = await invoke<string>("generate_password", {
        length: Number(length.value),
        lowercase: lowercase.checked,
        uppercase: uppercase.checked,
        digits: digits.checked,
        symbols: symbols.checked,
      });
    } catch (error) {
      toast(String(error), "error");
    } finally {
      regenerate.disabled = false;
    }
  }
  void generate();
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
  const pw = el("input") as HTMLInputElement;
  pw.type = "password";
  pw.placeholder = mode === "export" ? "백업 암호 (최소 12자)" : "백업 파일 암호";
  pw.minLength = 12;
  pw.required = true;
  const submit = el("button", "primary", mode === "export" ? "저장 위치 선택" : "백업 파일 선택") as HTMLButtonElement;
  submit.type = "submit";
  form.append(el("p", "muted", mode === "export"
    ? "새 salt와 nonce로 다시 암호화된 .enc 파일을 만듭니다."
    : "가져온 항목은 현재 열린 금고를 대체합니다."), pw, submit);
  const dialog = modal(mode === "export" ? "암호화 백업 내보내기" : "암호화 백업 복구", form);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      const result = await invoke<boolean>(mode === "export" ? "export_backup" : "import_backup", { password: pw.value });
      pw.value = "";
      if (result) {
        dialog.remove();
        if (mode === "import") await refreshCodes();
        toast(mode === "export" ? "암호화 백업을 저장했습니다." : "백업을 복구했습니다.");
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
  const remove = symbolButton("삭제", Trash2, () => {
    layer.remove();
    void deleteEntry(item);
  }, "context-menu-action danger");
  remove.setAttribute("role", "menuitem");
  menu.append(edit, remove);
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
  card.draggable = true;
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
  const identity = el("div");
    identity.append(el("h2", "issuer", item.issuer || "인증키"), el("p", "account", item.account));
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
  card.addEventListener("dragstart", (event) => {
    dragInProgress = true;
    draggedCard = card;
    event.dataTransfer?.setData("text/plain", item.id);
    if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
    requestAnimationFrame(() => card.classList.add("dragging"));
  });
  card.addEventListener("dragover", (event) => {
    if (!draggedCard || draggedCard === card) return;
    event.preventDefault();
    const bounds = card.getBoundingClientRect();
    const before = event.clientY < bounds.top + bounds.height / 2;
    card.parentElement?.insertBefore(draggedCard, before ? card : card.nextSibling);
  });
  card.addEventListener("drop", (event) => event.preventDefault());
  card.addEventListener("dragend", async () => {
    card.classList.remove("dragging");
    dragInProgress = false;
    draggedCard = null;
    suppressCopyUntil = Date.now() + 300;
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
  });
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

async function refreshCodes() {
  if (dragInProgress) return;
  try {
    codes = await invoke<CodeView[]>("list_codes");
    renderCodes();
  } catch {
    if (refreshTimer) window.clearInterval(refreshTimer);
    passwordPanel(true);
  }
}

async function showVault() {
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
  refreshTimer = window.setInterval(refreshCodes, 1000);
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
  const reveal = async () => {
    if (revealed) return;
    const id = ++transitionId;
    try {
      await invoke("set_mini_revealed", { revealed: true });
      if (id !== transitionId) return;
      requestAnimationFrame(() => {
        if (id !== transitionId) return;
        revealed = true;
        button.classList.add("revealed");
      });
    } catch (error) {
      toast(String(error), "error");
    }
  };
  const conceal = async () => {
    if (!revealed) return;
    const id = ++transitionId;
    revealed = false;
    button.classList.remove("revealed");
    await new Promise((resolve) => window.setTimeout(resolve, 220));
    if (id !== transitionId) return;
    try {
      await invoke("set_mini_revealed", { revealed: false });
    } catch (error) {
      toast(String(error), "error");
    }
  };
  button.addEventListener("pointerenter", () => void reveal());
  button.addEventListener("pointerleave", () => void conceal());
  let restoring = false;
  button.addEventListener("click", async () => {
    if (restoring) return;
    restoring = true;
    try {
      await invoke("restore_main_window");
    } catch (error) {
      toast(String(error), "error");
    } finally {
      restoring = false;
    }
  });
  root.append(button);
}

async function bootstrap() {
  if (getCurrentWindow().label === "scanner") return scannerMode();
  if (getCurrentWindow().label === "mini") return miniMode();
  await listen<ImportSummary>("vault-changed", async (event) => {
    await refreshCodes();
    const skipped = event.payload.skipped ? ` · 중복 ${event.payload.skipped}개 제외` : "";
    const batch = event.payload.batchSize > 1
      ? ` · 내보내기 QR ${event.payload.batchIndex + 1}/${event.payload.batchSize}`
      : "";
    const legacy = event.payload.weakSecrets ? ` · 레거시 짧은 Secret ${event.payload.weakSecrets}개` : "";
    toast(`인증키 ${event.payload.added}개를 추가했습니다${skipped}${legacy}${batch}`);
  });
  const status = await invoke<VaultStatus>("vault_status");
  status.unlocked ? await showVault() : passwordPanel(status.initialized);
  window.setTimeout(() => void checkForUpdates(false), 1200);
}

void bootstrap();
