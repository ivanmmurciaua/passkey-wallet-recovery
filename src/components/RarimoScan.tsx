"use client";

import { useState, useSyncExternalStore } from "react";
import QrImage from "./QrImage";

// Dual-path Rarimo prompt, auto-selected by device:
//  - desktop  → show the QR (scan with the phone running the Rarimo app).
//  - mobile   → show a tap button (same device → can't scan its own screen).
// Either way the encrypted K_recovery returns via the API polling running in
// this tab. A small toggle covers misdetection (iPad, touchscreen laptops).
function detectMobile(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent;
  // iPadOS 13+ reports as "Macintosh" but has touch points.
  const iPadLike = /Macintosh/.test(ua) && navigator.maxTouchPoints > 1;
  return /Android|iPhone|iPod|Mobile|Silk/i.test(ua) || iPadLike;
}

const noopSubscribe = () => () => {};

export default function RarimoScan({ url }: { url: string }) {
  // Device detection without a setState-in-effect: null on the server (no hydration flash),
  // the real value on the client. The toggle below overrides a misdetection.
  const detected = useSyncExternalStore(noopSubscribe, detectMobile, () => null);
  const [override, setOverride] = useState<boolean | null>(null);
  const mobile = override ?? detected;

  if (mobile === null) return null; // avoid SSR/hydration flash

  const OpenButton = (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      style={{
        display: "inline-block",
        fontFamily: "monospace",
        fontSize: 13,
        padding: "10px 16px",
        border: "1px solid #333",
        borderRadius: 4,
        textDecoration: "none",
        color: "#111",
      }}
    >
      Open Rarimo on this device →
    </a>
  );

  return (
    <div style={{ margin: "10px 0" }}>
      {mobile ? OpenButton : <QrImage value={url} />}

      <p style={{ fontSize: 12, color: "#888", marginTop: 8 }}>
        {mobile
          ? "Tap to open Rarimo, complete your factors, then return here: polling resumes automatically."
          : "Scan with the Rarimo app on your phone · polling…"}
      </p>

      <button
        onClick={() => setOverride(!mobile)}
        style={{
          background: "none",
          border: "none",
          color: "#aaa",
          fontSize: 11,
          fontFamily: "monospace",
          cursor: "pointer",
          padding: 0,
          textDecoration: "underline",
        }}
      >
        {mobile ? "On a desktop? show QR instead" : "On the same device? show button instead"}
      </button>
    </div>
  );
}
