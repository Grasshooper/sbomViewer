export interface SBOMData {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata?: {
    timestamp?: string;
    tools?: Tool[];
    component?: Component;
  };
  components?: Component[];
  dependencies?: Dependency[];
  externalReferences?: ExternalReference[];
}

export interface Tool {
  name: string;
  version: string;
}

export interface Component {
  type: string;
  'bom-ref': string;
  author?: string;
  publisher?: string;
  name: string;
  version?: string;
  description?: string;
  hashes?: Hash[];
  licenses?: License[];
  copyright?: string;
  purl?: string;
  components?: Component[];
  properties?: Property[];
  modified?: boolean;
  externalReferences?: ExternalReference[];
}

export interface Hash {
  alg: string;
  content: string;
}

export interface License {
  license?: {
    id?: string;
    name?: string;
    url?: string;
  };
}

export interface Property {
  name: string;
  value: string;
}

export interface Dependency {
  ref: string;
  dependsOn: string[];
}

export interface ExternalReference {
  url: string;
  type: string;
}