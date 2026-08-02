import React, { useEffect, useId } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { cn } from "../../lib/cn";
import { useFocusTrap } from "../../utils/useFocusTrap";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
  ariaLabel?: string;
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  description,
  children,
  className,
  ariaLabel,
}) => {
  const trapRef = useFocusTrap<HTMLDivElement>(open, onClose);
  const descId = useId();

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  if (typeof document === "undefined") return null;

  return createPortal(
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <motion.div
            role="presentation"
            className="absolute inset-0 bg-background/70 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.div
            ref={trapRef}
            role="dialog"
            aria-modal="true"
            aria-label={ariaLabel ?? title}
            aria-describedby={description ? descId : undefined}
            initial={{ opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.98 }}
            transition={{ duration: 0.2, ease: [0.25, 1, 0.5, 1] }}
            className={cn(
              "relative z-10 w-full max-w-lg ui-card ui-card-lg border-l-[3px] border-l-primary shadow-[var(--shadow-lg)]",
              className,
            )}
          >
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                {title && <h2 className="text-h3">{title}</h2>}
                {description && (
                  <p
                    id={descId}
                    className="text-body-sm text-muted-foreground mt-1"
                  >
                    {description}
                  </p>
                )}
              </div>
              <button
                type="button"
                onClick={onClose}
                className="p-1.5 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground hover:bg-muted/60"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            {children}
          </motion.div>
        </div>
      )}
    </AnimatePresence>,
    document.body,
  );
};
