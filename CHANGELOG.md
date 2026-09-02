# Changelog

## [1.0.2](https://github.com/forbiddenlink/security-trainer/compare/v1.0.1...v1.0.2) (2026-09-02)


### Bug Fixes

* **ci:** let pnpm/action-setup read the version from packageManager ([5667d65](https://github.com/forbiddenlink/security-trainer/commit/5667d6512ecf913c3d788f8c232e6fd5295b01a2))
* **deps:** give every resolution override an upper bound ([ac77bbb](https://github.com/forbiddenlink/security-trainer/commit/ac77bbbf57bd3ef82e7e9b66950099dea4806e34))
* **security:** pin transitive dependencies flagged by Dependabot ([d40a8c8](https://github.com/forbiddenlink/security-trainer/commit/d40a8c8b81baa4351f54ad70e1da8348f3a8dc7c))

## [1.0.1](https://github.com/forbiddenlink/security-trainer/compare/v1.0.0...v1.0.1) (2026-08-29)


### Bug Fixes

* **deps:** move resolution overrides to package.json and add missing patches ([#72](https://github.com/forbiddenlink/security-trainer/issues/72)) ([8446174](https://github.com/forbiddenlink/security-trainer/commit/84461744ee4700e12da29d48e60de301c2d450d8))

## 1.0.0 (2026-08-29)


### Features

* add 13 training modules across 3 new learning paths ([350cfc9](https://github.com/forbiddenlink/security-trainer/commit/350cfc94e291f416d7ae98bbd4f613801625449e))
* add onboarding role selector and module category filtering ([6c07584](https://github.com/forbiddenlink/security-trainer/commit/6c075842d47dbd00c9c1e90dc4a32fce6d135919))
* add terminal component, biome config, release automation, and pnpm migration ([a974457](https://github.com/forbiddenlink/security-trainer/commit/a97445742ad941ef41edb926ce2850a5983b0ad5))
* add vishing voice-phishing lesson with audio example ([82cd1e6](https://github.com/forbiddenlink/security-trainer/commit/82cd1e6d12d29ea2ea9810feb402a231f7f75b2b))
* earnable badges, module-completion flow, a11y, and lazy lab bundle ([#62](https://github.com/forbiddenlink/security-trainer/issues/62)) ([675f05b](https://github.com/forbiddenlink/security-trainer/commit/675f05b697aa0c38662efd8d8b3c9a06c730f359))
* **labs:** live practice targets and shared UI primitives ([ada7427](https://github.com/forbiddenlink/security-trainer/commit/ada7427d527aba627a15178f6d13cbd24831bceb))
* launch hardening — stat rings, streak freeze, activity heatmap, lab hints ([#65](https://github.com/forbiddenlink/security-trainer/issues/65)) ([e1d493d](https://github.com/forbiddenlink/security-trainer/commit/e1d493d7e58de9d00fc8aa59aa37c757e74a72de))
* launch-readiness hardening from audit-pack pass ([#51](https://github.com/forbiddenlink/security-trainer/issues/51)) ([23b41eb](https://github.com/forbiddenlink/security-trainer/commit/23b41eb92553b9b22d6161011c1bd5c7c6f46a8f))
* overhaul design with dark theme, new assets, and improved UI ([291af2e](https://github.com/forbiddenlink/security-trainer/commit/291af2eaa01e6f5d06f807158dffc64cbb48505a))
* **tutor:** Socratic AI tutor with rate-limited hint endpoint ([b1c9e72](https://github.com/forbiddenlink/security-trainer/commit/b1c9e72fbe581208a69c962628400a79a41f847c))
* **ui:** cyber range briefing room visual signature ([9f470dc](https://github.com/forbiddenlink/security-trainer/commit/9f470dc805f61257fac1cb58b345eea3f025e4d0))
* **ui:** spy/ops design-language pass and module enrichment ([c18d5fd](https://github.com/forbiddenlink/security-trainer/commit/c18d5fde501f0b86cf9d5a7f179fcd0a9c4d9e14))
* visual redesign — tighter tokens, border-only elevation, monospace data ([913132d](https://github.com/forbiddenlink/security-trainer/commit/913132d78de9fade524519c7cddc2eb705ef0252))


### Bug Fixes

* add missing learning_steps field to FSRS Card in spacedRepetition ([6f4a6c9](https://github.com/forbiddenlink/security-trainer/commit/6f4a6c91d55f85f5fe409f344bb4fb71f04c53c8))
* align package.json name with project/repo identity ([c70079a](https://github.com/forbiddenlink/security-trainer/commit/c70079a8c197233a8637dc1a389931529c7d26af))
* break mermaid circular chunk dep and fix CSP for Google Fonts ([66221e4](https://github.com/forbiddenlink/security-trainer/commit/66221e4db9baf3ed07b6fe147fe0ad54c2dd6f0f))
* **ci:** let pnpm/action-setup read version from packageManager ([98fa655](https://github.com/forbiddenlink/security-trainer/commit/98fa6557a71e430246930b2c643562e3ef31ffd5))
* correct xterm imports to @xterm/xterm ([86a6448](https://github.com/forbiddenlink/security-trainer/commit/86a6448101b4549462905ccd165b0b0fcae88551))
* **deps:** add pnpm-workspace overrides for security patches ([07c9fb9](https://github.com/forbiddenlink/security-trainer/commit/07c9fb98bd87ec590d4907cf4fabad3400bec6e6))
* **deps:** pin pnpm and keep security overrides in package.json ([93fff49](https://github.com/forbiddenlink/security-trainer/commit/93fff4957f4b1e2402a2454c8d7d71a25c105bf5))
* **deps:** regenerate pnpm-lockfile to match package.json ([28f08fb](https://github.com/forbiddenlink/security-trainer/commit/28f08fb7544071122b7064aee09d5446b20f2fd0))
* patch 8 security vulnerabilities ([6ddeecd](https://github.com/forbiddenlink/security-trainer/commit/6ddeecd213a0e74643a4e671080ab9101bb9a2ab))
* remove dompurify from mermaid-vendor chunk to prevent eager mermaid load ([c834645](https://github.com/forbiddenlink/security-trainer/commit/c834645c185a23743babdce098e10fac7d9b84ec))
* remove unavailable socketsecurity/socket-action from security workflow ([b333e12](https://github.com/forbiddenlink/security-trainer/commit/b333e121e1943c1ecb776d923126b500e064eda8))
* silence react-hooks v7 false-positive ESLint errors ([#43](https://github.com/forbiddenlink/security-trainer/issues/43)) ([3d7a528](https://github.com/forbiddenlink/security-trainer/commit/3d7a528b8fed54555e27aaa06bfe2290a54368dc))
* switch CI to pnpm and resolve lint errors ([de20ef0](https://github.com/forbiddenlink/security-trainer/commit/de20ef05c247a80ba1c09cef3f3223d4122615b1))
