#!/usr/bin/env node
// Static contrast audit for the canonical ui-kit theme tokens.
//
// Text pairs use WCAG AA 4.5:1; non-text indicators use 3:1. Required pairs are
// the combinations the kit styles itself use and every theme must satisfy.
// Advisory pairs cover host theme values and decorative borders that can carry
// an upstream palette; they print warnings and only fail with --strict.
//
//   node testing/ui/contrast.mjs
//   node testing/ui/contrast.mjs --strict
//   node testing/ui/contrast.mjs --file internal/ui/design-system/ui-kit.css
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const defaultFile = resolve(root, "internal/ui/design-system/ui-kit.css");

const REQUIRED_PAIRS = [
  { fg: "--ui-text", bg: "--ui-bg", min: 4.5, use: "正文 on 画布" },
  { fg: "--ui-text", bg: "--ui-surface", min: 4.5, use: "正文 on 卡片" },
  { fg: "--ui-text", bg: "--ui-surface-raised", min: 4.5, use: "正文 on 抬升面" },
  { fg: "--ui-text-secondary", bg: "--ui-bg", min: 4.5, use: "次要文字 on 画布" },
  { fg: "--ui-text-secondary", bg: "--ui-surface", min: 4.5, use: "次要文字 on 卡片" },
  { fg: "--ui-text-tertiary", bg: "--ui-surface", min: 4.5, use: "辅助文字 on 卡片" },
  { fg: "--ui-text-muted", bg: "--ui-surface", min: 4.5, use: "弱化文字 on 卡片" },
  { fg: "--ui-danger-text", bg: "--ui-surface", min: 4.5, use: "危险文字 on 卡片" },
  { fg: "--ui-success-text", bg: "--ui-surface", min: 4.5, use: "成功文字 on 卡片" },
  { fg: "--ui-warning-text", bg: "--ui-surface", min: 4.5, use: "警告文字 on 卡片" },
  { fg: "--ui-success-text", bg: "--ui-success-soft", min: 4.5, use: "成功徽章文字 on 软底" },
  { fg: "--ui-warning-text", bg: "--ui-warning-soft", min: 4.5, use: "警告徽章文字 on 软底" },
  { fg: "--ui-on-danger", bg: "--ui-danger-button", min: 4.5, use: "危险按钮文字" },
  { fg: "--ui-on-primary", bg: "--ui-primary-hover", min: 4.5, use: "主按钮悬停文字" },
  { fg: "--ui-on-primary", bg: "--ui-primary-active", min: 4.5, use: "主按钮按下文字" },
  { fg: "--ui-primary", bg: "--ui-bg", min: 3, use: "主色指示 on 画布" },
  { fg: "--ui-primary", bg: "--ui-surface", min: 3, use: "主色指示 on 卡片" },
  { fg: "--ui-danger", bg: "--ui-surface", min: 3, use: "危险指示 on 卡片" },
];

const ADVISORY_PAIRS = [
  { fg: "--ui-on-primary", bg: "--ui-primary", min: 4.5, use: "主按钮文字（宿主主题原值）" },
  { fg: "--ui-danger-text", bg: "--ui-danger-soft", min: 4.5, use: "危险徽章文字 on 软底" },
  { fg: "--ui-success", bg: "--ui-surface", min: 3, use: "成功图标 on 卡片" },
  { fg: "--ui-warning", bg: "--ui-surface", min: 3, use: "警告图标 on 卡片" },
  { fg: "--ui-border-strong", bg: "--ui-surface", min: 3, use: "强边框 on 卡片" },
];

const NAMED = { white: [255, 255, 255, 1], black: [0, 0, 0, 1], transparent: [0, 0, 0, 0] };

function parseColor(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) throw new Error("颜色为空");
  if (NAMED[text]) return [...NAMED[text]];
  const hex = text.match(/^#([0-9a-f]{3,8})$/);
  if (hex) {
    let digits = hex[1];
    if (digits.length === 3 || digits.length === 4) digits = [...digits].map((digit) => digit + digit).join("");
    const channels = [0, 2, 4].map((offset) => parseInt(digits.slice(offset, offset + 2), 16));
    const alpha = digits.length === 8 ? parseInt(digits.slice(6, 8), 16) / 255 : 1;
    return [...channels, alpha];
  }
  const rgb = text.match(/^rgba?\(([^)]+)\)$/);
  if (rgb) {
    const parts = rgb[1].replace(/\//g, " ").split(/[\s,]+/).filter(Boolean).map(Number);
    if (parts.length < 3 || parts.some((part) => !Number.isFinite(part))) throw new Error(`无法解析颜色 ${value}`);
    return [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1];
  }
  throw new Error(`无法解析颜色 ${value}`);
}

const over = (color, base) => {
  const alpha = color[3] ?? 1;
  return [0, 1, 2].map((index) => color[index] * alpha + base[index] * (1 - alpha));
};

function luminance(color) {
  const channels = color.slice(0, 3).map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

export function contrastRatio(foreground, background, base = [255, 255, 255]) {
  const fg = parseColor(foreground);
  const raw = parseColor(background);
  const bg = (raw[3] ?? 1) < 1 ? [...over(raw, base), 1] : raw;
  const solidFg = (fg[3] ?? 1) < 1 ? [...over(fg, bg), 1] : fg;
  const [high, low] = [luminance(solidFg), luminance(bg)].sort((left, right) => right - left);
  return (high + 0.05) / (low + 0.05);
}

const blocksOf = (cssText) => {
  const clean = cssText.replace(/\/\*[\s\S]*?\*\//g, "");
  return [...clean.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((match) => ({
    selectors: match[1].split(",").map((selector) => selector.trim()),
    body: match[2],
  }));
};

const tokensOf = (body) => Object.fromEntries([...body.matchAll(/(--ui-[\w-]+)\s*:\s*([^;]+);/g)].map((match) => [match[1], match[2].trim()]));

function resolveToken(name, tokens, seen = new Set()) {
  if (seen.has(name)) throw new Error(`循环 token 引用 ${name}`);
  const raw = tokens[name];
  if (raw === undefined) throw new Error(`缺少 token ${name}`);
  const reference = raw.match(/^var\((--ui-[\w-]+)(?:\s*,\s*([^)]+))?\)$/);
  if (!reference) return raw;
  const [, target, fallback] = reference;
  if (tokens[target] !== undefined) return resolveToken(target, tokens, new Set([...seen, name]));
  if (fallback) return fallback.trim();
  throw new Error(`token ${name} 引用了不存在的 ${target}`);
}

export function themeTokens(cssText) {
  const blocks = blocksOf(cssText);
  const rootBlock = blocks.find((block) => block.selectors.includes(":root"));
  if (!rootBlock) throw new Error("ui-kit.css 缺少 :root token");
  const defaults = tokensOf(rootBlock.body);
  const tokens = {};
  for (const block of blocks) {
    for (const selector of block.selectors) {
      const match = selector.match(/^\[data-theme="([^"]+)"\]$/);
      if (!match) continue;
      tokens[match[1]] = { ...(tokens[match[1]] || defaults), ...tokensOf(block.body) };
    }
  }
  for (const [name, values] of Object.entries(tokens)) tokens[name] = { ...defaults, ...values };
  return { defaults, themes: tokens };
}

export function auditThemes(cssText) {
  const { themes } = themeTokens(cssText);
  const names = Object.keys(themes);
  if (!names.length) throw new Error("ui-kit.css 没有 data-theme 主题块");
  const results = [];
  for (const [theme, tokens] of Object.entries(themes)) {
    const base = parseColor(resolveToken("--ui-surface", tokens));
    for (const pair of [...REQUIRED_PAIRS.map((item) => ({ ...item, advisory: false })), ...ADVISORY_PAIRS.map((item) => ({ ...item, advisory: true }))]) {
      const ratio = contrastRatio(resolveToken(pair.fg, tokens), resolveToken(pair.bg, tokens), base);
      results.push({ theme, ...pair, ratio, pass: ratio >= pair.min });
    }
  }
  const required = results.filter((item) => !item.advisory);
  const advisory = results.filter((item) => item.advisory);
  return {
    themes: names,
    results,
    failures: required.filter((item) => !item.pass),
    warnings: advisory.filter((item) => !item.pass),
  };
}

const format = (item) => `${item.theme}: ${item.fg} on ${item.bg} = ${item.ratio.toFixed(2)} < ${item.min}（${item.use}）`;

export async function main(argv = process.argv.slice(2)) {
  let file = defaultFile;
  let strict = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--strict") strict = true;
    else if (flag === "--file") {
      file = resolve(argv[index + 1] || "");
      index += 1;
    } else if (flag === "-h" || flag === "--help") {
      console.log("用法：node testing/ui/contrast.mjs [--strict] [--file path]");
      return;
    } else {
      throw new Error(`未知参数 ${flag}`);
    }
  }
  const { themes, failures, warnings, results } = auditThemes(await readFile(file, "utf8"));
  console.log(`主题 token 对比度（${file}）`);
  for (const theme of themes) {
    const required = results.filter((item) => item.theme === theme && !item.advisory);
    const passed = required.filter((item) => item.pass).length;
    console.log(`${theme.padEnd(13)} ${passed}/${required.length} 必需组合通过`);
  }
  for (const failure of failures) console.log(`FAIL ${format(failure)}`);
  for (const warning of warnings) console.log(`WARN ${format(warning)}`);
  const requiredPassed = results.filter((item) => !item.advisory && item.pass).length;
  const requiredTotal = results.filter((item) => !item.advisory).length;
  console.log(`\n${requiredPassed}/${requiredTotal} 必需组合通过，${warnings.length} 项可选组合低于阈值。`);
  if (failures.length || (strict && warnings.length)) process.exitCode = 1;
}

const invokedDirectly = () => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return resolve(entry) === resolve(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
};

if (invokedDirectly()) {
  main().catch((error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  });
}
