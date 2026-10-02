import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, AlertCircle, Loader2, Check } from "lucide-react";
import { useAuthStore } from "../store/authStore";
import { useFocusTrap } from "../utils/useFocusTrap";
import { Button, Input } from "./ui";

interface ProfileEditModalProps {
  isOpen: boolean;
  onClose: () => void;
}

/**
 * Inner form component - resets state on each mount
 * By only rendering when isOpen is true, state resets each time the modal opens
 */
const ProfileEditForm: React.FC<{
  initialDisplayName: string;
  onClose: () => void;
}> = ({ initialDisplayName, onClose }) => {
  const { updateProfile, loading } = useAuthStore();
  const [displayName, setDisplayName] = useState(initialDisplayName);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const closeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clean up timeout on unmount to prevent memory leaks
  useEffect(() => {
    return () => {
      if (closeTimeoutRef.current) {
        clearTimeout(closeTimeoutRef.current);
      }
    };
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    const trimmedName = displayName.trim();
    if (!trimmedName) {
      setError("Display name cannot be empty");
      return;
    }

    if (trimmedName.length < 2) {
      setError("Display name must be at least 2 characters");
      return;
    }

    if (trimmedName.length > 50) {
      setError("Display name must be 50 characters or less");
      return;
    }

    const result = await updateProfile({ display_name: trimmedName });
    if (result.error) {
      setError(result.error.message);
      return;
    }
    setSuccess(true);

    // Close after brief success feedback (with cleanup on unmount)
    closeTimeoutRef.current = setTimeout(() => {
      onClose();
    }, 1000);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="displayName" className="ui-label block mb-2">
          Display Name
        </label>
        <Input
          id="displayName"
          type="text"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="Your agent codename"
          maxLength={50}
          autoFocus
        />
        <p className="text-body-sm text-muted-foreground mt-1">
          {displayName.length}/50 characters
        </p>
      </div>

      {/* Error message */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-2 p-3 rounded-[var(--radius-sm)] border border-border border-l-[3px] border-l-destructive text-destructive text-body-sm"
          role="alert"
        >
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </motion.div>
      )}

      {/* Success message */}
      {success && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-2 p-3 rounded-[var(--radius-sm)] border border-border border-l-[3px] border-l-accent text-accent text-body-sm"
          role="alert"
        >
          <Check className="w-4 h-4 flex-shrink-0" />
          Profile updated successfully
        </motion.div>
      )}

      {/* Actions */}
      <div className="flex gap-3 pt-2">
        <Button
          type="button"
          variant="outline"
          onClick={onClose}
          className="flex-1"
        >
          Cancel
        </Button>
        <Button
          type="submit"
          variant="signal"
          className="flex-1"
          disabled={loading || success}
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : success ? (
            <>
              <Check className="w-4 h-4" />
              Saved
            </>
          ) : (
            "Save Changes"
          )}
        </Button>
      </div>
    </form>
  );
};

/**
 * Profile edit modal - allows users to change their display name
 */
export const ProfileEditModal: React.FC<ProfileEditModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { profile } = useAuthStore();

  // Focus trap for accessibility
  const modalRef = useFocusTrap<HTMLDivElement>(isOpen, onClose);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-background/80 z-50"
            onClick={onClose}
            aria-hidden="true"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 6 }}
            transition={{ duration: 0.2, ease: [0.25, 1, 0.5, 1] }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div
              ref={modalRef}
              className="w-full max-w-md ui-card ui-card-lg ui-card-elevated relative"
              role="dialog"
              aria-modal="true"
              aria-labelledby="profile-edit-title"
            >
              {/* Close button */}
              <button
                type="button"
                onClick={onClose}
                className="absolute top-4 right-4 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground transition-colors"
                aria-label="Close profile editor"
              >
                <X className="w-5 h-5" />
              </button>

              {/* Header */}
              <div className="mb-5 pb-4 border-b border-border pr-10">
                <p className="ui-label mb-2">Agent record</p>
                <h2
                  id="profile-edit-title"
                  className="font-display [font-stretch:75%] font-extrabold text-h3"
                >
                  Edit Profile
                </h2>
              </div>

              {/* Form - only rendered when modal is open, so state resets on each open */}
              <ProfileEditForm
                initialDisplayName={profile?.display_name || ""}
                onClose={onClose}
              />
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
