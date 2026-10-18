import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Badge, Metric, Panel } from "./ui";

describe("console primitives", () => {
  it("renders dense operational metrics and status", () => {
    render(
      <Panel title="Runtime state">
        <Metric label="PQC provider" value="Fallback" status="warn" />
        <Badge tone="ok">Secure boot verified</Badge>
      </Panel>,
    );

    expect(screen.getByRole("heading", { name: "Runtime state" })).toBeInTheDocument();
    expect(screen.getByText("Fallback")).toBeInTheDocument();
    expect(screen.getByText("Secure boot verified")).toBeInTheDocument();
  });
});
