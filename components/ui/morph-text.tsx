"use client";

import React, { useState, useEffect, useCallback } from "react";

export interface MorphTextProps {
  words?: string[];
  interval?: number;
  subtext?: string;
  fontSize?: string;
  fontFamily?: string;
  className?: string;
  textClassName?: string;
  subtextClassName?: string;
  showAccentLines?: boolean;
}

export function MorphText({
  words = ["CREATE", "DESIGN", "DEVELOP"],
  interval = 2500,
  subtext,
  fontSize = "clamp(2rem, 10vw, 8rem)",
  fontFamily = "'Orbitron', 'Inter', sans-serif",
  className = "",
  textClassName = "",
  subtextClassName = "",
  showAccentLines = true,
}: MorphTextProps) {
  const [index, setIndex] = useState(0);
  const [isAnimating, setIsAnimating] = useState(false);
  const [nextIndex, setNextIndex] = useState(1 % words.length);

  const triggerNext = useCallback(() => {
    if (words.length <= 1 || isAnimating) return;
    const targetNext = (index + 1) % words.length;
    setNextIndex(targetNext);
    setIsAnimating(true);

    const timer = setTimeout(() => {
      setIndex(targetNext);
      setIsAnimating(false);
    }, 850);

    return () => clearTimeout(timer);
  }, [index, words.length, isAnimating]);

  useEffect(() => {
    if (words.length <= 1) return;
    const intervalTimer = setInterval(() => {
      triggerNext();
    }, interval + 850);

    return () => clearInterval(intervalTimer);
  }, [triggerNext, interval, words.length]);

  return (
    <div
      className={`relative flex flex-col items-center justify-center text-center select-none ${className}`}
      style={{ fontFamily }}
    >
      {/* SVG Gooey Filter */}
      <svg
        className="sr-only"
        aria-hidden="true"
        style={{ position: "absolute", width: 0, height: 0, pointerEvents: "none" }}
      >
        <defs>
          <filter id="react-morph-gooey">
            <feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur" />
            <feColorMatrix
              in="blur"
              mode="matrix"
              values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 19 -8"
              result="goo"
            />
            <feComposite in="SourceGraphic" in2="goo" operator="atop" />
          </filter>
        </defs>
      </svg>

      {/* Cyber Frame with Top & Bottom Emerald Lines */}
      <div className="relative w-full max-w-4xl px-4 py-6 md:py-8">
        {showAccentLines && (
          <div
            className="absolute top-0 left-0 right-0 h-[2px] pointer-events-none"
            style={{
              background:
                "linear-gradient(90deg, #10B981 0%, #10B981 60%, rgba(16, 185, 129, 0.25) 90%, transparent 100%)",
              boxShadow: "0 0 12px rgba(16, 185, 129, 0.7), 0 0 3px #10B981",
            }}
          />
        )}

        <div
          className="relative inline-flex items-center justify-center font-extrabold tracking-tight text-white leading-tight"
          style={{
            fontSize,
            filter: "url(#react-morph-gooey)",
            textShadow:
              "0 0 20px rgba(255, 255, 255, 0.2), 0 0 35px rgba(16, 185, 129, 0.15)",
          }}
        >
          {/* Active Word */}
          <span
            className={`inline-block transition-all duration-[850ms] ease-in-out will-change-transform ${
              isAnimating
                ? "opacity-0 blur-[8px] scale-105 -translate-y-1"
                : "opacity-100 blur-0 scale-100 translate-y-0"
            } ${textClassName}`}
          >
            {words[index]}
          </span>

          {/* Morphing Incoming Word */}
          {isAnimating && (
            <span
              className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 inline-block transition-all duration-[850ms] ease-in-out will-change-transform opacity-100 blur-0 scale-100 ${textClassName}`}
            >
              {words[nextIndex]}
            </span>
          )}
        </div>

        {showAccentLines && (
          <div
            className="absolute bottom-0 left-0 right-0 h-[2px] pointer-events-none"
            style={{
              background:
                "linear-gradient(90deg, #10B981 0%, #10B981 65%, rgba(16, 185, 129, 0.3) 90%, transparent 100%)",
              boxShadow: "0 0 12px rgba(16, 185, 129, 0.7), 0 0 3px #10B981",
            }}
          />
        )}
      </div>

      {/* Subtext */}
      {subtext && (
        <p
          className={`mt-4 text-base md:text-xl text-zinc-400 font-sans tracking-wide max-w-2xl mx-auto ${subtextClassName}`}
        >
          {subtext}
        </p>
      )}
    </div>
  );
}

// Default — cycles CREATE / DESIGN / DEVELOP
export function MyHero() {
  return <MorphText subtext="The Art of Code" />;
}

// Custom words and interval
export function CustomMorph() {
  return (
    <MorphText
      words={["INNOVATE", "BUILD", "SHIP"]}
      interval={2500}
      subtext="Move fast. Break things."
      fontSize="clamp(2rem, 10vw, 8rem)"
    />
  );
}

// Zplus Cyber Hero Headline matching the exact uploaded design
export function ZplusHero() {
  return (
    <div className="relative text-center space-y-6 max-w-4xl mx-auto py-8">
      <div className="relative inline-block w-full px-4">
        {/* Top Accent Line */}
        <div
          className="w-full h-[2px] mb-6"
          style={{
            background:
              "linear-gradient(90deg, #10B981 0%, #10B981 60%, rgba(16, 185, 129, 0.25) 90%, transparent 100%)",
            boxShadow: "0 0 12px rgba(16, 185, 129, 0.7), 0 0 3px #10B981",
          }}
        />

        <h1
          className="font-extrabold text-white tracking-tight leading-[1.15]"
          style={{
            fontFamily: "'Orbitron', sans-serif",
            fontSize: "clamp(2.2rem, 5.8vw, 4.8rem)",
          }}
        >
          <span className="block">Identify &amp; Secure</span>
          <span className="block my-1">
            <MorphText
              words={[
                "Phishing Links",
                "Malicious URLs",
                "Zero-Day Threats",
                "Suspicious Domains",
              ]}
              interval={2500}
              fontSize="inherit"
              fontFamily="'Orbitron', sans-serif"
              showAccentLines={false}
              className="inline-block"
            />
          </span>
          <span className="block">Instantly</span>
        </h1>

        {/* Bottom Accent Line */}
        <div
          className="w-full h-[2px] mt-6"
          style={{
            background:
              "linear-gradient(90deg, #10B981 0%, #10B981 65%, rgba(16, 185, 129, 0.3) 90%, transparent 100%)",
            boxShadow: "0 0 12px rgba(16, 185, 129, 0.7), 0 0 3px #10B981",
          }}
        />
      </div>

      <p className="text-base md:text-xl text-zinc-400 max-w-2xl mx-auto">
        Enterprise-grade URL analysis using global safety protocols and real-time behavioral scanning. No trackers, no cookies, total clinical precision.
      </p>
    </div>
  );
}

export default MorphText;

