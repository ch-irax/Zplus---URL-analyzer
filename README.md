# Zplus — Premium Phishing Detector (URL analysis tool)

Zplus is a professional URL analysis tool designed to identify and secure phishing links instantly. It uses advanced safety protocols and real-time behavioral scanning to provide high-precision security audits.

## Core Features

- **Smart Link Analysis:** Instantly normalizes links, strips hidden layers, and establishes a secure, temporary sandbox for the target.
- **Security Pattern Check:** Applies multiple safety checks (e.g., fake character detection, suspicious domain analysis) to scan the link's structure for malicious signs.
- **Visual Forensics:** Captures a live behavioral snapshot. View the site's true appearance in grayscale without executing its code locally, neutralizing threats.
- **Node Intelligence:** Analyzes the target's IP address, geographic location, TLD risk, and latency.

## Technology Stack

- **Frontend:** HTML5, Tailwind CSS (via CDN)
- **Styling:** Custom CSS with Glassmorphism UI and matrix background effects.
- **Logic Engine:** Vanilla JavaScript (`script.js`) handling real-time analysis and UI transitions.
- **Icons:** [Lucide Icons](https://lucide.dev/)

## How to Use

1. Clone the repository to your local machine.
2. Open `index.html` in any modern web browser.
3. Paste a suspicious URL into the input field and click **Scan Link**.
4. Review the generated Forensic Analysis Report to determine the risk level.
5. Live Demo: [zplusec.vercel.app](https://zplusec.vercel.app/)

## Philosophy

_"Visibility is the first line of defense. Precision is the second."_

Designed with no trackers and no cookies, Zplus ensures that all scans are conducted in a transient, non-persistent environment.

## License

This project is licensed under the [MIT License](LICENSE).

Developed by Chirag
