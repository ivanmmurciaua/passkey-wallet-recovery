"use client";

import { useEffect, useState } from "react";
import QRCode from "qrcode";

// Renders a value as a scannable QR (dark-on-white). Used for the Rarimo
// recovery URL: the user scans it with the Rarimo app.
export default function QrImage({ value, size = 240 }: { value: string; size?: number }) {
  const [dataUrl, setDataUrl] = useState<string>("");

  useEffect(() => {
    let alive = true;
    QRCode.toDataURL(value, { width: size, margin: 1 })
      .then((url) => {
        if (alive) setDataUrl(url);
      })
      .catch(() => {
        if (alive) setDataUrl("");
      });
    return () => {
      alive = false;
    };
  }, [value, size]);

  if (!dataUrl) {
    return (
      <div
        style={{
          width: size,
          height: size,
          background: "#f4f4f4",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 12,
          color: "#888",
        }}
      >
        generating QR…
      </div>
    );
  }

  // eslint-disable-next-line @next/next/no-img-element
  return <img src={dataUrl} alt="Rarimo recovery QR" width={size} height={size} />;
}
