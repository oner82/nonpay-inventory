(() => {
  window.createSettingsModule = (context) => {
    const renderSettings = () => {
      if (!context.canManageSettings()) return `<div class="empty">관리자와 책임사용자만 설정을 사용할 수 있습니다.</div>`;
      const views = {
        products: context.renderProducts,
        doctors: context.renderDoctors,
        surgeries: context.renderSurgeries,
        usageRules: context.renderUsageRules,
        implantVendors: context.renderImplantVendors,
        backup: context.renderBackup
      };
      return `
        <section>
          <div class="settings-tabs">
            ${context.settingsMenus.map(([key, label]) => `<button class="settings-tab ${context.getCurrentSettingsView() === key ? "active" : ""}" data-settings-view="${key}" type="button">${label}</button>`).join("")}
          </div>
          ${views[context.getCurrentSettingsView()]()}
        </section>
      `;
    };

    const bindSettings = () => {
      if (!context.canManageSettings()) return;
      const app = context.getApp();
      app.querySelectorAll("[data-settings-view]").forEach((button) => {
        button.addEventListener("click", () => {
          context.setCurrentSettingsView(button.dataset.settingsView);
          context.render();
        });
      });
      const handlers = {
        products: context.bindProducts,
        doctors: context.bindDoctors,
        surgeries: context.bindSurgeries,
        usageRules: context.bindUsageRules,
        implantVendors: context.bindImplantVendors,
        backup: context.bindBackup
      };
      handlers[context.getCurrentSettingsView()]?.();
    };

    return {
      renderSettings,
      bindSettings
    };
  };
})();
