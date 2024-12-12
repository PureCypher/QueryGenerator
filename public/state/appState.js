class AppState {
    constructor() {
        this.parameters = [];
        this.selectedSources = new Set();
        this.customSources = [];
    }

    clearSelectedSources() {
        this.selectedSources.clear();
    }

    addSelectedSource(source) {
        this.selectedSources.add(source);
    }

    removeSelectedSource(source) {
        this.selectedSources.delete(source);
    }

    addCustomSource(source) {
        this.customSources.push(source);
    }

    getSelectedSources() {
        return Array.from(this.selectedSources);
    }

    getCustomSources() {
        return [...this.customSources];
    }
}

export const state = new AppState();
