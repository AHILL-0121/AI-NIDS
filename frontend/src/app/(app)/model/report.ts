/** Shape of `report.json` written by `nids train` (backend/src/nids/ml/train.py). The endpoint
 * returns it as a free-form object, so every field is optional here. */

export interface BinaryMetrics {
  threshold?: number;
  precision?: number;
  recall?: number;
  false_positive_rate?: number;
  pr_auc?: number;
  roc_auc?: number;
  tp?: number;
  fp?: number;
  fn?: number;
  tn?: number;
}

export interface ClassMetrics {
  precision: number;
  recall: number;
  "f1-score": number;
  support: number;
}

export interface ModelReport {
  rows?: number;
  multiclass?: {
    macro_f1_known_families?: number;
    known_families?: string[];
    per_class?: Record<string, ClassMetrics>;
    confusion_matrix?: { labels: string[]; matrix: number[][] };
  };
  binary?: { supervised?: BinaryMetrics; novelty?: BinaryMetrics; alert_rule?: BinaryMetrics };
  per_family?: Record<string, { rows: number; seen_in_training: boolean; alert_rate: number }>;
  false_positives_per_hour?: number | null;
  false_alerts_per_hour?: number | null;
  attack_alerts?: number;
  benign_hours?: number | null;
  threshold_sweep_supervised?: {
    threshold: number;
    precision: number;
    recall: number;
    false_positive_rate: number;
  }[];
  validation?: {
    method?: string;
    budget_alerts_per_hour?: number;
    threshold?: number;
    validation_false_alerts_per_hour?: number | null;
    validation_novelty_recall?: number;
    validation_classifier_fpr?: number;
  };
  training?: {
    dataset?: string;
    split?: string;
    feature_set?: string;
    features?: string[];
    best_iteration?: number;
    rows?: Record<string, number>;
    families_train?: Record<string, number>;
    families_test?: Record<string, number>;
    config?: Record<string, unknown>;
  };
}

export function asReport(value: unknown): ModelReport {
  return value && typeof value === "object" ? (value as ModelReport) : {};
}
