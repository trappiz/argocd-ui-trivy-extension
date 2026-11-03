// The subset of Argo CD's UI models this extension relies on.

export interface ObjectMeta {
  name: string;
  namespace?: string;
  uid?: string;
  resourceVersion?: string;
  creationTimestamp?: string;
  labels?: Record<string, string>;
}

export interface Application {
  metadata: ObjectMeta;
  spec: { project: string };
}

export interface ResourceRef {
  group?: string;
  kind: string;
  namespace?: string;
  name: string;
  uid?: string;
}

export interface ResourceNode extends ResourceRef {
  version?: string;
  resourceVersion?: string;
  parentRefs?: ResourceRef[];
  createdAt?: string;
}

export interface ApplicationTree {
  nodes?: ResourceNode[];
}

export interface K8sObject {
  apiVersion?: string;
  kind: string;
  metadata: ObjectMeta;
}

export interface ResourceTabProps {
  application: Application;
  resource: K8sObject;
  tree: ApplicationTree;
}

export interface StatusPanelProps {
  application: Application;
  openFlyout: () => void;
}

export interface FlyoutProps {
  application: Application;
  tree: ApplicationTree;
}
