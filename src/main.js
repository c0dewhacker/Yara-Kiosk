import { App } from './app';
document.addEventListener('DOMContentLoaded', () => {
    const mountEl = document.getElementById('app');
    if (!mountEl) {
        console.error('Mount element #app not found');
        return;
    }
    new App(mountEl);
});
//# sourceMappingURL=main.js.map