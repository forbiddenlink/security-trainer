import React, { useRef, useCallback } from 'react';
import { toPng } from 'html-to-image';
import download from 'downloadjs';
import { Shield, Award, CheckCircle } from 'lucide-react';
import { useGameStore } from '../store/gameStore';

export const Certificate: React.FC = () => {
    const ref = useRef<HTMLDivElement>(null);
    const { level } = useGameStore();
    const name = "Agent Zero"; // In a real app, this would be the user's name
    const date = new Date().toLocaleDateString();

    const handleDownload = useCallback(() => {
        if (ref.current === null) {
            return;
        }

        toPng(ref.current, { cacheBust: true, })
            .then((dataUrl) => {
                download(dataUrl, 'security-clearance-certificate.png');
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
                    className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-md font-medium text-sm flex items-center gap-2 transition-colors"
                >
                    <Award className="w-4 h-4" />
                    Download Certificate
                </button>
            </div>

            <div className="overflow-hidden rounded-lg shadow-2xl border-4 border-double border-primary/50 relative group">
                {/* The actual certificate area to capture */}
                <div ref={ref} className="bg-background text-foreground p-12 w-full max-w-[800px] aspect-[1.414/1] mx-auto flex flex-col items-center justify-center relative">
                    {/* Background Pattern */}
                    <div className="absolute inset-0 bg-[linear-gradient(45deg,#1a1a1a_25%,transparent_25%,transparent_75%,#1a1a1a_75%,#1a1a1a),linear-gradient(45deg,#1a1a1a_25%,transparent_25%,transparent_75%,#1a1a1a_75%,#1a1a1a)] bg-[size:60px_60px] opacity-[0.03] pointer-events-none" />
                    <div className="absolute inset-0 border-[20px] border-border/50 pointer-events-none" />

                    <Shield className="w-24 h-24 text-primary mb-6" />

                    <h1 className="text-4xl font-bold tracking-wider uppercase mb-2 text-center text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400">
                        Certificate of Completion
                    </h1>

                    <p className="text-muted-foreground tracking-widest uppercase text-sm mb-12">
                        Security Awareness Training Program
                    </p>

                    <p className="text-lg text-center mb-2">This certifies that</p>
                    <p className="text-3xl font-serif italic text-primary mb-8 border-b-2 border-primary/20 pb-2 px-12">
                        {name}
                    </p>

                    <p className="text-center text-muted-foreground w-3/4 mb-12">
                        Has successfully demonstrated proficiency in identifying and patching web security vulnerabilities, achieving <strong>Level {level}</strong> Clearance.
                    </p>

                    <div className="flex justify-between w-full px-12 items-end">
                        <div className="text-center">
                            <p className="font-bold border-t pt-2 w-48 mx-auto">{date}</p>
                            <p className="text-xs text-muted-foreground uppercase">Date</p>
                        </div>
                        <div className="flex flex-col items-center">
                            <CheckCircle className="w-10 h-10 text-emerald-500 mb-2 opacity-80" />
                            <p className="text-xs text-muted-foreground uppercase opacity-80">Verified Secure</p>
                        </div>
                        <div className="text-center">
                            <p className="font-bold border-t pt-2 w-48 mx-auto">Security Trainer AI</p>
                            <p className="text-xs text-muted-foreground uppercase">Instructor</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};
