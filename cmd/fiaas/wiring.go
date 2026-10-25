// Wiring added by the coordinator: connects the real store, engine,
// runner, and policy packages to the CLI's OpenStore / RunnerLoop
// hooks and to the MCP server's policy/cost evaluators. Nothing here
// is a stub: OpenStore opens SQLite (default) or Postgres (when
// FIAAS_DATABASE_URL is set), and RunnerLoop runs the real runner.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/azmi2409/forge-iaas/internal/api"
	"github.com/azmi2409/forge-iaas/internal/engine"
	"github.com/azmi2409/forge-iaas/internal/mcp"
	"github.com/azmi2409/forge-iaas/internal/model"
	"github.com/azmi2409/forge-iaas/internal/policy"
	"github.com/azmi2409/forge-iaas/internal/runner"
	"github.com/azmi2409/forge-iaas/internal/store"
	"github.com/azmi2409/forge-iaas/internal/store/postgres"
	"github.com/azmi2409/forge-iaas/internal/store/sqlite"
)

// policyEval adapts the policy package's Evaluate function to the
// runner and MCP PolicyEvaluator interfaces.
type policyEval struct{}

func (policyEval) Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult {
	return policy.Evaluate(plan, sets)
}

// costEval adapts the policy package's Estimate function to the
// runner and MCP CostEstimator interfaces.
type costEval struct{}

func (costEval) Estimate(plan *model.PlanSummary) model.CostEstimate {
	return policy.Estimate(plan)
}

func openRealStore(path string) (api.Store, error) {
	key, _, err := store.MasterKeyFromEnv()
	if err != nil {
		return nil, err
	}
	if dsn := os.Getenv("FIAAS_DATABASE_URL"); dsn != "" {
		return postgres.New(dsn, key)
	}
	return sqlite.New(path, key)
}

func runRealRunner(ctx context.Context, s api.Store) error {
	rs, ok := s.(runner.Store)
	if !ok {
		return fmt.Errorf("store does not implement the runner interface; cannot execute runs")
	}
	r := runner.New(rs, engine.NewFromEnv(), policyEval{}, costEval{})
	r.RunLoop(ctx, 2*time.Second)
	return nil
}

func init() {
	OpenStore = openRealStore
	RunnerLoop = runRealRunner
}

// mcpPolicyCost returns the wired policy/cost evaluators for MCP
// servers built by the serve and mcp commands.
func mcpPolicyCost() (mcp.PolicyEvaluator, mcp.CostEstimator) {
	return policyEval{}, costEval{}
}
