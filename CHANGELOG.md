# Changelog

## [0.3.0](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.2.0...v0.3.0) (2026-05-23)


### Features

* Monaco YARA editor with inline validation ([a0c38aa](https://github.com/c0dewhacker/Yara-Kiosk/commit/a0c38aab8c6d17f7a1d8c25e76e5397bebc466c4))
* replace textarea rule editor with Monaco + YARA-X inline validation ([b9e4d6f](https://github.com/c0dewhacker/Yara-Kiosk/commit/b9e4d6f9416e595b2a2958448d9a27e2a620ef57))


### Bug Fixes

* correct artifact paths and rust-cache config in release workflow ([6c7f26d](https://github.com/c0dewhacker/Yara-Kiosk/commit/6c7f26db1cda70ab1f9c981520f40ff309828472))
* correct artifact paths in release workflow ([5a5fef1](https://github.com/c0dewhacker/Yara-Kiosk/commit/5a5fef19be959813578720e1abe1e6d376381a84))
* move rule reload off main thread to fix Save freeze ([145d35b](https://github.com/c0dewhacker/Yara-Kiosk/commit/145d35b8af497ec7ecf036be226e858bd8ae4ddc))
* move rule reload off the main thread to fix Save freeze ([1facc1e](https://github.com/c0dewhacker/Yara-Kiosk/commit/1facc1e1417bac1e44b50ea9a7138f52facc7681))
* open post-scan report in-app modal instead of browser ([b2befb0](https://github.com/c0dewhacker/Yara-Kiosk/commit/b2befb0523cfbb259c34d9c052506fc03f7f0730))
* open post-scan report in-app modal instead of browser ([53bdbac](https://github.com/c0dewhacker/Yara-Kiosk/commit/53bdbac064f397152f27f66b0f5776baf1968dd6))
* resolve DRIVE_REMOVABLE import error in Windows build ([7b7f4e9](https://github.com/c0dewhacker/Yara-Kiosk/commit/7b7f4e95e3f02dc8a110a062c36a458176df348e))
* resolve DRIVE_REMOVABLE import error in Windows build ([2a883f7](https://github.com/c0dewhacker/Yara-Kiosk/commit/2a883f739f7573a1915a903f90d045f65e70dd36))
* restore invoke import removed in error ([83d346d](https://github.com/c0dewhacker/Yara-Kiosk/commit/83d346d35fa6ee40eab80dd8f1aa3632f49bbfa8))

## [0.2.0](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.1.0...v0.2.0) (2026-05-22)


### Features

* in-app report viewer — kiosk-safe report display ([9af0b46](https://github.com/c0dewhacker/Yara-Kiosk/commit/9af0b46e2c81479a732cc63f6d75efc220808fdb))
* in-app report viewer and dashboard heading fix ([c70c002](https://github.com/c0dewhacker/Yara-Kiosk/commit/c70c002bd763023b4bd1a0d5583147b6a9eb9b62))


### Bug Fixes

* add packages key to release-please config so commits are matched ([84e1700](https://github.com/c0dewhacker/Yara-Kiosk/commit/84e17009ef6dd4c020a3cb803214e225df97109a))
* CI libclang support, Tailwind v4 migration, npm dep upgrades ([2d5d35d](https://github.com/c0dewhacker/Yara-Kiosk/commit/2d5d35d0bb2f2d63f4d78d952de142ad2c285cbd))
* CI libclang support, Tailwind v4 migration, npm dep upgrades ([2d5d35d](https://github.com/c0dewhacker/Yara-Kiosk/commit/2d5d35d0bb2f2d63f4d78d952de142ad2c285cbd))
* hero strip overflow-hidden clipping gradient heading text ([426ef0d](https://github.com/c0dewhacker/Yara-Kiosk/commit/426ef0d25f9d46e29b5bec551343922e6cca1bff))
* switch Vite minifier from esbuild to oxc for Vite 8 compatibility ([05dda06](https://github.com/c0dewhacker/Yara-Kiosk/commit/05dda06d84e7caf5f3dbd1e4f85a0aea8786cdf8))
* upgrade pam to 0.8 and update auth.rs for new Client API ([c3e60d5](https://github.com/c0dewhacker/Yara-Kiosk/commit/c3e60d534446a8c7ab061f3f00d79f13341bb0db))
* upgrade pam to 0.8, update auth.rs API, fix users crate vulns ([1f51d1f](https://github.com/c0dewhacker/Yara-Kiosk/commit/1f51d1f6be2853038d927027122ccb8a13846c10))
* upgrade pam to 0.8, update auth.rs API, fix users crate vulns ([1f51d1f](https://github.com/c0dewhacker/Yara-Kiosk/commit/1f51d1f6be2853038d927027122ccb8a13846c10))


### Performance Improvements

* faster AppImage startup — async YARA compilation ([1e66986](https://github.com/c0dewhacker/Yara-Kiosk/commit/1e669867a65ce144ee7cabb55ca0fb2f7d1c43be))
* move YARA compilation off the main thread for faster AppImage startup ([c0b66dc](https://github.com/c0dewhacker/Yara-Kiosk/commit/c0b66dc50ee526983b9fed6ca29d897cae1ef1e5))
