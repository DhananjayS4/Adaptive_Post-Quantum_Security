export type JsonObject = Record<string, any>;

export interface SystemStatus {
  generated_at: string;
  model: {
    available: boolean;
    version?: string;
    dataset?: string;
    task?: string;
    calibrated?: boolean;
  };
  edge: {
    records_replayed: number;
    accepted_deliveries: number;
    fail_closed: number;
    central_workload?: JsonObject;
  };
  assurance: {
    secure_boot_allowed?: boolean;
    active_slot?: string;
    pqc: JsonObject;
  };
  result_availability: Record<string, boolean>;
}

export interface Job {
  id: string;
  kind: string;
  status: "queued" | "running" | "succeeded" | "failed";
  submitted_at: string;
  started_at?: string;
  completed_at?: string;
  options: JsonObject;
  error?: string;
}
