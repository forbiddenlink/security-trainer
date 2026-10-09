# Changelog

## [1.1.0](https://github.com/forbiddenlink/security-trainer/compare/v1.0.4...v1.1.0) (2026-10-09)


### Features

* **assets:** align brand assets with signal range instrument aesthetic ([1d02497](https://github.com/forbiddenlink/security-trainer/commit/1d02497d661aaa20a364e83ac96f9416a6e52759))
* **auth:** offer GitHub sign-in once the provider is configured ([bf58bea](https://github.com/forbiddenlink/security-trainer/commit/bf58beabc2edc419e4bf2d35ecfb7192584e7fd9))
* **design:** add retry and a live timer to the final exam ([45bd46d](https://github.com/forbiddenlink/security-trainer/commit/45bd46db4be25d91afd8152f9f75e531abdcd96d))
* **design:** bring overlays, toasts and leftover widgets onto Signal Range ([da7437c](https://github.com/forbiddenlink/security-trainer/commit/da7437c65fd374df608e68c60709afc676920bb3))
* **design:** give review and leaderboard pages a clear next action ([cccc6f2](https://github.com/forbiddenlink/security-trainer/commit/cccc6f26b7de40ffdbade28a26cccb367e69fe74))
* **design:** rebuild modules catalog and lesson player on Signal Range ([c2b6e7c](https://github.com/forbiddenlink/security-trainer/commit/c2b6e7c1586ca53f4df84ff3453013f559751e35))
* **design:** rebuild profile as an agent dossier ([cae96d6](https://github.com/forbiddenlink/security-trainer/commit/cae96d668f8ceae08e359e2e0d063eeb044013b8))
* **design:** Signal Range foundation and new dashboard ([1d104e9](https://github.com/forbiddenlink/security-trainer/commit/1d104e96e7c7ace5e598ded78e2d7aefcc46a523))
* **design:** turn learning paths into routes with clear next steps ([abab207](https://github.com/forbiddenlink/security-trainer/commit/abab2078c0070a2a978e59eefe60a953212ae137))
* **modules:** tag modules with their OWASP Top 10:2025 category ([6ccb38a](https://github.com/forbiddenlink/security-trainer/commit/6ccb38ab166dcd354e81c858a7a23e805ece7881))
* **progress:** add a weekly XP goal, field ranks and a hide-solved CTF filter ([b945cc4](https://github.com/forbiddenlink/security-trainer/commit/b945cc4a2a6a16f95f33e022f61f6e16350ea47b))
* Signal Range redesign, CTF and diagram fixes, OWASP tags and progress features ([87c6257](https://github.com/forbiddenlink/security-trainer/commit/87c6257b42d4848603f991fb0f670c5cc8067d97))


### Bug Fixes

* **a11y:** make biome:check runnable and clear its accessibility errors ([6c16a0d](https://github.com/forbiddenlink/security-trainer/commit/6c16a0d34c4bb0e79193b77af86755b3973e8345))
* **ctf:** accept correct flags and rebuild the challenge board ([9c9df05](https://github.com/forbiddenlink/security-trainer/commit/9c9df05d813544b244af505c44be4d8726b94355))
* **deps:** apply override fix plan ([#99](https://github.com/forbiddenlink/security-trainer/issues/99)) ([f1c7bc8](https://github.com/forbiddenlink/security-trainer/commit/f1c7bc89964f75d21550072bfdd2c2775a7ca36f))
* **deps:** raise stale override floors ([#97](https://github.com/forbiddenlink/security-trainer/issues/97)) ([d6ad757](https://github.com/forbiddenlink/security-trainer/commit/d6ad757a42abc518d1d2e1c9ad3ee1aed7108b4e))
* **lesson:** keep a single h1 per lesson page ([a385eac](https://github.com/forbiddenlink/security-trainer/commit/a385eac08da8fa7eb6fba5c6e327a9b7b4cd3f2c))
* **lint:** keep biome:check at zero errors after the new features ([631f7d7](https://github.com/forbiddenlink/security-trainer/commit/631f7d77115d5dbd03cfea5f3a35e73b489640f5))


### Performance Improvements

* self-host fonts and keep diagram, terminal and analytics code off first load ([d73b6ec](https://github.com/forbiddenlink/security-trainer/commit/d73b6ec3e2ff831acd8027ce8a06fa19b647bdbd))

## [1.0.4](https://github.com/forbiddenlink/security-trainer/compare/v1.0.3...v1.0.4) (2026-09-19)


### Bug Fixes

* **config:** drop env example vars no code reads ([#91](https://github.com/forbiddenlink/security-trainer/issues/91)) ([1b3de75](https://github.com/forbiddenlink/security-trainer/commit/1b3de7554fcfff9664b76291a1996ad2a133cc3d))

## [1.0.3](https://github.com/forbiddenlink/security-trainer/compare/v1.0.2...v1.0.3) (2026-09-08)


### Bug Fixes

* show profile save failures instead of false success ([#85](https://github.com/forbiddenlink/security-trainer/issues/85)) ([a95811b](https://github.com/forbiddenlink/security-trainer/commit/a95811b5de7a9cf9a42c7604fcf3985cb933ca1d))

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
