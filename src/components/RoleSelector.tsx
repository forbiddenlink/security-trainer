import React, { useState } from "react";
import { useGameStore } from "../store/gameStore";
import { Code2, Server, Briefcase, Users } from "lucide-react";
import { Link } from "react-router-dom";

const ROLES = [
  {
    id: "developer",
    title: "Developer / Engineer",
    description: "I write code and want to build secure applications",
    icon: Code2,
    recommendedPath: "Web Security Fundamentals",
  },
  {
    id: "devops",
    title: "DevOps / IT Admin",
    description: "I manage infrastructure, deployments, and systems",
    icon: Server,
    recommendedPath: "Cloud & Infrastructure Security",
  },
  {
    id: "manager",
    title: "Manager / Executive",
    description: "I lead teams and need to understand security risks",
    icon: Briefcase,
    recommendedPath: "Compliance & Regulatory",
  },
  {
    id: "general",
    title: "General Staff",
    description: "I use company tools and want to stay security-aware",
    icon: Users,
    recommendedPath: "Security for Everyone",
  },
] as const;

export const RoleSelector: React.FC = () => {
  const setUserRole = useGameStore((state) => state.setUserRole);
  const [selectedRole, setSelectedRole] = useState<
    (typeof ROLES)[number] | null
  >(null);

  const handleSelect = (role: (typeof ROLES)[number]): void => {
    setSelectedRole(role);
    setUserRole(role.id);
  };

  return (
    <section className="ui-card ui-card-lg" aria-label="Role selection">
      {!selectedRole ? (
        <>
          <p className="ui-chip mb-3">Getting Started</p>
          <h2 className="text-h1 mb-2">Select Your Role</h2>
          <p className="text-muted-foreground text-body-sm mb-6">
            Choose your role to get personalized training recommendations.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {ROLES.map((role) => {
              const Icon = role.icon;
              return (
                <button
                  key={role.id}
                  type="button"
                  onClick={() => handleSelect(role)}
                  className="ui-card p-4 flex items-start gap-4 text-left transition-colors hover:border-primary cursor-pointer"
                >
                  <Icon
                    className="w-5 h-5 text-primary mt-0.5 shrink-0"
                    aria-hidden="true"
                  />
                  <div>
                    <p className="font-semibold text-body">{role.title}</p>
                    <p className="text-muted-foreground text-body-sm">
                      {role.description}
                    </p>
                  </div>
                </button>
              );
            })}
          </div>
          <button
            type="button"
            onClick={() => setUserRole("skipped")}
            className="mt-4 text-muted-foreground text-body-sm hover:text-foreground transition-colors"
          >
            Skip
          </button>
        </>
      ) : (
        <div className="flex flex-col items-start gap-4">
          <div>
            <p className="ui-chip mb-3">Role Selected</p>
            <h2 className="text-h1 mb-2">{selectedRole.title}</h2>
            <p className="text-muted-foreground text-body-sm">
              Recommended path:{" "}
              <span className="text-primary font-semibold">
                {selectedRole.recommendedPath}
              </span>
            </p>
          </div>
          <div className="flex items-center gap-4">
            <Link
              to="/paths"
              className="inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-5 font-semibold text-primary-foreground transition-colors hover:bg-primary-hover"
            >
              Start recommended path
            </Link>
            <button
              type="button"
              onClick={() => setSelectedRole(null)}
              className="text-muted-foreground text-body-sm hover:text-foreground transition-colors"
            >
              Change role
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
