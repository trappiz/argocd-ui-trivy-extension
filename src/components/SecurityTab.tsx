import * as React from "react";
import { getManifests } from "../api";
import { toConfigAuditReport, toExposedSecretReport, toVulnerabilityReport } from "../normalize";
import { appKey, useAsync } from "../hooks";
import { dedupeVulnerabilities } from "../reports";
import { findReportNodes } from "../tree";
import type { ResourceTabProps } from "../types/argocd";
import { ErrorMessage, Loading, Message } from "./common";
import { ConfigAudit } from "./ConfigAudit";
import { Secrets } from "./Secrets";
import { Vulnerabilities } from "./Vulnerabilities";

type Section = "vulnerabilities" | "config" | "secrets";

interface SectionInfo {
  id: Section;
  label: string;
  count: number;
  present: boolean;
}

const byContainer = (a: { metadata: { name: string } }, b: { metadata: { name: string } }) =>
  a.metadata.name.localeCompare(b.metadata.name);

export const SecurityTab = ({ application, resource, tree }: ResourceTabProps) => {
  const nodes = React.useMemo(() => findReportNodes(tree, resource), [tree, resource]);
  const key = nodes.map((n) => `${n.uid}@${n.resourceVersion}`).join(",");

  const state = useAsync(
    async () => {
      const load = async <T,>(kind: string, parse: (raw: unknown) => T) =>
        (
          await getManifests(
            application,
            nodes.filter((n) => n.kind === kind),
            parse,
          )
        ).map((f) => f.manifest);
      const [vulnerabilities, config, secrets] = await Promise.all([
        load("VulnerabilityReport", toVulnerabilityReport),
        load("ConfigAuditReport", toConfigAuditReport),
        load("ExposedSecretReport", toExposedSecretReport),
      ]);
      return {
        vulnerabilities: vulnerabilities.sort(byContainer),
        config,
        secrets: secrets.sort(byContainer),
      };
    },
    `${appKey(application)}|${key}`,
  );

  const [section, setSection] = React.useState<Section | undefined>();

  if (nodes.length === 0) {
    return (
      <div className="tv">
        <Message title="No Trivy reports for this resource">
          trivy-operator writes reports shortly after a workload is created or its spec changes. If none show up, check
          that the operator is running and that <code>aquasecurity.github.io</code> resources are not listed in Argo
          CD's <code>resource.exclusions</code>.
        </Message>
      </div>
    );
  }
  if (state.error)
    return (
      <div className="tv">
        <ErrorMessage error={state.error} />
      </div>
    );
  if (!state.data)
    return (
      <div className="tv">
        <Loading />
      </div>
    );

  const { vulnerabilities, config, secrets } = state.data;
  const sections = (
    [
      {
        id: "vulnerabilities",
        label: "Vulnerabilities",
        count: vulnerabilities.reduce((n, r) => n + dedupeVulnerabilities(r.report.vulnerabilities ?? []).length, 0),
        present: vulnerabilities.length > 0,
      },
      {
        id: "config",
        label: "Misconfigurations",
        count: config.reduce((n, r) => n + (r.report.checks ?? []).filter((c) => !c.success).length, 0),
        present: config.length > 0,
      },
      {
        id: "secrets",
        label: "Exposed secrets",
        count: secrets.reduce((n, r) => n + (r.report.secrets ?? []).length, 0),
        present: secrets.length > 0,
      },
    ] as SectionInfo[]
  ).filter((s) => s.present);

  const active = sections.find((s) => s.id === section) ?? sections[0];
  if (!active) return null;

  return (
    <div className="tv">
      {sections.length > 1 && (
        <div className="tv-tabs" role="tablist">
          {sections.map((s) => (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={s.id === active.id}
              className={`tv-tab${s.id === active.id ? " tv-tab--active" : ""}`}
              onClick={() => setSection(s.id)}
            >
              {s.label} <span className="tv-tab__count">{s.count}</span>
            </button>
          ))}
        </div>
      )}
      {active.id === "vulnerabilities" && <Vulnerabilities reports={vulnerabilities} />}
      {active.id === "config" && <ConfigAudit reports={config} />}
      {active.id === "secrets" && <Secrets reports={secrets} />}
    </div>
  );
};
