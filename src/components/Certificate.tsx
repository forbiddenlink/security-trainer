import React, { useRef, useCallback } from "react";
import { toPng } from "html-to-image";
import download from "downloadjs";
import { Award, CheckCircle } from "lucide-react";
import { RangeMark } from "./RangeMark";
import { useGameStore } from "../store/gameStore";
import { useAuthStore } from "../store/authStore";

export const Certificate: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  const { level } = useGameStore();
  const { profile } = useAuthStore();
  const name = profile?.display_name || "Agent";
  const date = new Date().toLocaleDateString();

  const handleDownload = useCallback(() => {
    if (ref.current === null) {
      return;
    }

    toPng(ref.current, { cacheBust: true })
      .then((dataUrl) => {
        download(dataUrl, "security-clearance-certificate.png");
      })
      .catch((err) => {
        console.error(err);
      });
  }, [ref]);

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <button
          onClick={handleDownload}
          className="btn-ghost-rule !h-10 text-body-sm"
        >
          <Award className="w-4 h-4" aria-hidden="true" />
          Download Certificate
        </button>
      </div>

      <div className="overflow-x-auto">
        {/* The actual certificate area to capture */}
        <div
          ref={ref}
          className="relative mx-auto flex aspect-[1.414/1] w-full min-w-[560px] max-w-[800px] flex-col bg-[#fbfbf7] p-10 text-[#12130f]"
        >
          <div
            className="pointer-events-none absolute inset-4 border border-[#12130f]"
            aria-hidden="true"
          />
          <div
            className="pointer-events-none absolute inset-[22px] border border-[#12130f]/30"
            aria-hidden="true"
          />
          <div className="relative flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.18em] text-[#55554c]">
            <span className="flex items-center gap-2">
              <RangeMark className="h-5 w-5 text-[#12130f]" />
              SecTrainer · Signal Range
            </span>
            <span>Clearance L{level}</span>
          </div>

          <div className="relative flex flex-1 flex-col items-center justify-center text-center">
            <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-[#55554c]">
              Security Awareness Training Program
            </p>
            <p className="mt-3 font-display text-[2.5rem] font-extrabold uppercase leading-none [font-stretch:75%]">
              Certificate of Completion
            </p>
            <p className="mt-8 text-[15px]">This certifies that</p>
            <p className="mt-2 border-b-2 border-[#d7f75b] px-10 pb-1 font-display text-[2rem] font-bold [font-stretch:85%]">
              {name}
            </p>
            <p className="mt-6 max-w-[46ch] text-[14px] leading-relaxed text-[#3a3b34]">
              Has successfully demonstrated proficiency in identifying and
              patching web security vulnerabilities, achieving{" "}
              <strong>Level {level}</strong> Clearance.
            </p>
          </div>

          <div className="relative flex items-end justify-between font-mono text-[10px] uppercase tracking-[0.14em] text-[#55554c]">
            <div>
              <p className="w-40 border-t border-[#12130f] pt-2 text-[13px] normal-case tracking-normal text-[#12130f]">
                {date}
              </p>
              <p className="mt-1">Date</p>
            </div>
            <div className="flex flex-col items-center gap-1">
              <CheckCircle
                className="h-6 w-6 text-[#2f7a4a]"
                aria-hidden="true"
              />
              <p>Verified Secure</p>
            </div>
            <div className="text-right">
              <p className="w-40 border-t border-[#12130f] pt-2 text-[13px] normal-case tracking-normal text-[#12130f]">
                Security Trainer AI
              </p>
              <p className="mt-1">Instructor</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
