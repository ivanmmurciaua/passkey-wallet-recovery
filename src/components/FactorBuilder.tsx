"use client";

import { RecoveryFactor } from "@rarimo/unforgettable-sdk";

// The recovery "recipe": an ORDERED list of N factors, repeats allowed. The
// exact sequence (types, count, order) must be reproduced at restore or Rarimo
// yields a different K_recovery. The 4 enum values are just the available
// TYPES: the array length is unbounded.
const FACTOR_LABELS: Record<RecoveryFactor, string> = {
  [RecoveryFactor.Face]: "Face",
  [RecoveryFactor.Image]: "Image",
  [RecoveryFactor.Password]: "Password",
  [RecoveryFactor.Geolocation]: "Geolocation",
};

const ALL: RecoveryFactor[] = [
  RecoveryFactor.Face,
  RecoveryFactor.Image,
  RecoveryFactor.Password,
  RecoveryFactor.Geolocation,
];

export default function FactorBuilder({
  factors,
  onChange,
  disabled,
}: {
  factors: RecoveryFactor[];
  onChange: (next: RecoveryFactor[]) => void;
  disabled?: boolean;
}) {
  const add = (f: RecoveryFactor) => onChange([...factors, f]);
  const remove = (i: number) => onChange(factors.filter((_, idx) => idx !== i));
  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= factors.length) return;
    const next = [...factors];
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };

  return (
    <div style={{ margin: "8px 0" }}>
      <label style={{ fontSize: 12, color: "#666" }}>
        Recovery recipe (ordered, repeats allowed): must match exactly at restore:
      </label>

      <ol style={{ margin: "6px 0", paddingLeft: 22 }}>
        {factors.length === 0 && (
          <li style={{ listStyle: "none", color: "#999", fontSize: 12, marginLeft: -22 }}>
            _ no factors yet: add at least one
          </li>
        )}
        {factors.map((f, i) => (
          <li key={i} style={{ fontSize: 13, marginBottom: 2 }}>
            <code>{FACTOR_LABELS[f]}</code>{" "}
            <button onClick={() => move(i, -1)} disabled={disabled || i === 0} style={miniBtn}>↑</button>
            <button onClick={() => move(i, 1)} disabled={disabled || i === factors.length - 1} style={miniBtn}>↓</button>
            <button onClick={() => remove(i)} disabled={disabled} style={{ ...miniBtn, color: "#c00" }}>×</button>
          </li>
        ))}
      </ol>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {ALL.map((f) => (
          <button key={f} onClick={() => add(f)} disabled={disabled} style={addBtn}>
            + {FACTOR_LABELS[f]}
          </button>
        ))}
      </div>
    </div>
  );
}

const miniBtn: React.CSSProperties = {
  fontFamily: "monospace",
  fontSize: 11,
  padding: "0 5px",
  marginLeft: 3,
  cursor: "pointer",
};

const addBtn: React.CSSProperties = {
  fontFamily: "monospace",
  fontSize: 12,
  padding: "3px 8px",
  cursor: "pointer",
};
