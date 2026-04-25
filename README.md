# Zplus — Premium Phishing Detector

Zplus is an enterprise-grade URL analysis tool designed for security researchers and professionals to identify and secure phishing links instantly. It uses a combination of OWASP-inspired heuristics and real-time behavioral scanning to provide total clinical precision.

## Core Features

- **Neural Ingestion:** Instantly normalizes URLs, strips obfuscation layers, and establishes a secure transient sandbox container.
- **Heuristic Extraction:** Applies multiple OWASP-inspired checks (e.g., Punycode/Homoglyph detection, entropy-based DGA analysis) to dissect a URL's anatomy for malicious markers.
- **Visual Forensics:** Captures a live behavioral snapshot via a sandbox. View the site's true appearance in grayscale without executing its code locally, neutralizing drive-by threats.
- **Node Intelligence:** Analyzes the target's IP address, geographic location, TLD risk, and latency.

## Technology Stack

- **Frontend:** HTML5, Tailwind CSS (via CDN)
- **Styling:** Custom CSS with Glassmorphism UI and matrix background effects.
- **Logic Engine:** Vanilla JavaScript (`script.js`) handling real-time analysis simulations and UI transitions.
- **Icons:** [Lucide Icons](https://lucide.dev/)

## How to Use

1. Clone the repository to your local machine.
2. Open `index.html` in any modern web browser.
3. Paste a suspicious URL into the input field and click **Scan Link**.
4. Review the generated Forensic Analysis Report to determine the risk level.
5. Here's the link :- https://zplusec.vercel.app/

## Philosophy

_"Visibility is the first line of defense. Precision is the second."_

Designed with no trackers and no cookies, Zplus ensures that all scans are conducted in a transient, non-persistent environment.

Developed by Chirag
