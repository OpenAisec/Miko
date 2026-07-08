const version = process.env.KIMO_VERSION ?? '0.1.0';
const packageUrl = process.env.KIMO_PACKAGE_URL ?? 'kimo';
const buildTime = process.env.KIMO_BUILD_TIME ?? new Date().toISOString();

process.env.KIMO_SKIP_REMOTE_PREFETCH ??= '1';
process.env.CLAUDE_CODE_USE_NATIVE_FILE_SEARCH ??= '1';

Object.assign(globalThis, {
  MACRO: {
    VERSION: version,
    PACKAGE_URL: packageUrl,
    NATIVE_PACKAGE_URL: packageUrl,
    BUILD_TIME: buildTime,
    FEEDBACK_CHANNEL: 'local',
    VERSION_CHANGELOG: '',
    ISSUES_EXPLAINER: '',
  },
});
// Switch to the current workspace
if (process.env.CALLER_DIR) {
  process.chdir(process.env.CALLER_DIR);
}