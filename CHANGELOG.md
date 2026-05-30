# Changelog

## [0.5.1](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.5.0...v0.5.1) (2026-05-30)


### Bug Fixes

* **auth:** GetUserNameW now takes Option&lt;PWSTR&gt; in windows 0.62 ([6103474](https://github.com/c0dewhacker/Yara-Kiosk/commit/610347437710f954c89dab4aff6acbdb3f3cc3d0))
* **auth:** GetUserNameW takes Option&lt;PWSTR&gt; in windows 0.62 ([195c0cb](https://github.com/c0dewhacker/Yara-Kiosk/commit/195c0cbcff5d9c70e08bc0ee349337d29c4ab393))

## [0.5.0](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.4.1...v0.5.0) (2026-05-30)


### Features

* **rules:** cache compiled ruleset for instant startup ([d3a963a](https://github.com/c0dewhacker/Yara-Kiosk/commit/d3a963a7f1248822f87ccd3e65caaf80a29c2eb6))
* **rules:** cache compiled ruleset for instant startup ([895d96f](https://github.com/c0dewhacker/Yara-Kiosk/commit/895d96f5a44c73ce33131a5447b6399db33ee4a6))


### Bug Fixes

* **csp:** add data: to default-src for inline SVG assets ([491097d](https://github.com/c0dewhacker/Yara-Kiosk/commit/491097d71064049d3699ce62f0f856dbe15d3876))
* remove duplicate CSP meta tag, bump rule cache filename ([21d3044](https://github.com/c0dewhacker/Yara-Kiosk/commit/21d3044beb83d56f9d4357dbc9de1749992ee3a2))

## [0.4.1](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.4.0...v0.4.1) (2026-05-28)


### Bug Fixes

* assorted robustness — atomic settings, canonicalize toggle, defer auto-refresh ([#37](https://github.com/c0dewhacker/Yara-Kiosk/issues/37)) ([9c7b440](https://github.com/c0dewhacker/Yara-Kiosk/commit/9c7b44081e280a7fc83b18a6c34a1daa9e7078d4))
* **ci:** drop redundant gh auth login on Windows release upload ([7e03de6](https://github.com/c0dewhacker/Yara-Kiosk/commit/7e03de63435dcf2f31153fb402774683ea80d278))
* **ci:** drop redundant gh auth login on Windows release upload ([ae35049](https://github.com/c0dewhacker/Yara-Kiosk/commit/ae350495d95d8130686047166617b47bc47240a6))


### Performance Improvements

* **reports:** write JSON sidecar so list_reports skips HTML parsing ([#35](https://github.com/c0dewhacker/Yara-Kiosk/issues/35)) ([f4f40ca](https://github.com/c0dewhacker/Yara-Kiosk/commit/f4f40ca276a8e187898fc68c8641b75960a53f7e))
* **scanner:** mmap files, use walkdir, report all matched rules ([#34](https://github.com/c0dewhacker/Yara-Kiosk/issues/34)) ([4f49390](https://github.com/c0dewhacker/Yara-Kiosk/commit/4f4939095a06d93b8e3bd25ac77af3806ba6538c))

## [0.4.0](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.3.1...v0.4.0) (2026-05-27)


### Features

* kiosk improvements — scan guard, rule names, USB labels, report mgmt, settings ([c66158b](https://github.com/c0dewhacker/Yara-Kiosk/commit/c66158bd62bb3778bbb5be647c1621db53f37467))
* kiosk improvements (items 4–13, 15–20) ([bbfcb0f](https://github.com/c0dewhacker/Yara-Kiosk/commit/bbfcb0f14110af3f1a403433b70b146e95a5f524))


### Bug Fixes

* **ci:** bump setup-node to v5 for Node.js 24 compatibility ([90dc57f](https://github.com/c0dewhacker/Yara-Kiosk/commit/90dc57fe27882e3171da22b1ecf4914a434d544a))
* **ci:** bump setup-node to v5 for Node.js 24 compatibility ([fa31848](https://github.com/c0dewhacker/Yara-Kiosk/commit/fa31848a79681d086e4fa98900e8302631cdf2cf))
* **ci:** force gh auth on Windows to fix 401 on release upload ([32163e4](https://github.com/c0dewhacker/Yara-Kiosk/commit/32163e43773dacbff6773b112e0fac5c32d81e2e))
* **ci:** force gh auth on Windows to fix 401 on release upload ([de763f2](https://github.com/c0dewhacker/Yara-Kiosk/commit/de763f2700222d03e8b502159064f2c2d61b9844))

## [0.3.1](https://github.com/c0dewhacker/Yara-Kiosk/compare/v0.3.0...v0.3.1) (2026-05-23)


### Bug Fixes

* compiling state, auth redirect, lock icons, Open Report browser ([b71f469](https://github.com/c0dewhacker/Yara-Kiosk/commit/b71f46901fed064747e07389fde68d11ad3624a9))
* compiling state, auth redirect, lock icons, Open Report browser ([ae1e790](https://github.com/c0dewhacker/Yara-Kiosk/commit/ae1e7905ac5dfe2dc560fbf07117ac507d9ae9c9))
* GetDriveTypeW returns u32, not DRIVE_TYPE newtype ([557c54d](https://github.com/c0dewhacker/Yara-Kiosk/commit/557c54d4146f5dc28da411f725b7185b990ec2c1))
* GetDriveTypeW returns u32, remove .0 field access ([f34250b](https://github.com/c0dewhacker/Yara-Kiosk/commit/f34250bf52c110216c841123ea98528ee5f33841))

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
