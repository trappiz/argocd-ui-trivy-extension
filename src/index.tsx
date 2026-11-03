import * as React from "react";
import { SecurityTab } from "./components/SecurityTab";
import { Flyout, StatusPanel } from "./components/StatusPanel";
import styles from "./styles.css";
import type { FlyoutProps, ResourceTabProps, StatusPanelProps } from "./types/argocd";

declare const __VERSION__: string;

interface ExtensionsAPI {
  registerResourceExtension(
    component: React.ComponentType<ResourceTabProps>,
    group: string,
    kind: string,
    tabTitle: string,
    opts?: { icon?: string },
  ): void;
  registerStatusPanelExtension?(
    component: React.ComponentType<StatusPanelProps>,
    title: string,
    id: string,
    flyout?: React.ComponentType<FlyoutProps>,
  ): void;
}

declare global {
  interface Window {
    extensionsAPI?: ExtensionsAPI;
  }
}

// Kinds that trivy-operator writes reports for, directly or via an owner.
const RESOURCE_KINDS: Array<[group: string, kind: string]> = [
  ["apps", "Deployment"],
  ["apps", "StatefulSet"],
  ["apps", "DaemonSet"],
  ["apps", "ReplicaSet"],
  ["batch", "CronJob"],
  ["batch", "Job"],
  ["", "Pod"],
  ["argoproj.io", "Rollout"],
  ["", "Service"],
  ["networking.k8s.io", "Ingress"],
  ["networking.k8s.io", "NetworkPolicy"],
];

const TAB_TITLE = "Security";
const ICON = "fa fa-shield-halved";

function injectStyles() {
  const id = "argocd-trivy-extension-styles";
  if (document.getElementById(id)) return;
  const style = document.createElement("style");
  style.id = id;
  style.textContent = styles;
  document.head.appendChild(style);
}

((window: Window) => {
  const api = window.extensionsAPI;
  if (!api) return;

  injectStyles();
  for (const [group, kind] of RESOURCE_KINDS) {
    api.registerResourceExtension(SecurityTab, group, kind, TAB_TITLE, { icon: ICON });
  }
  // Status panel extensions were added in Argo CD 2.10.
  api.registerStatusPanelExtension?.(StatusPanel, "Vulnerabilities", "trivy-vulnerabilities", Flyout);

  console.debug(`argocd-trivy-extension ${__VERSION__} loaded`);
})(window);
