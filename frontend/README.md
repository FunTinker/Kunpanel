# KunPanel Web

The panel UI is a dependency-light browser application. `src/main.js` contains
the complete navigation and API workflows for the server panel, while
`src/app.css` contains the shared responsive shell and component styles.

The previous Vue prototype is kept in `src/App.vue` as a reference. The
production UI is now directly rebuildable from the checked-in JavaScript and
CSS sources instead of relying on an opaque prebuilt-only bundle.

开发：

```bash
npm install
npm run dev
```

生产构建会输出到 `../web/dist`，随后重新编译 Go 程序即可。
