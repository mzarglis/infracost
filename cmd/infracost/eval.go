package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/util"
	"github.com/spf13/cobra"

	"github.com/infracost/infracost/internal/config"
	"github.com/infracost/infracost/internal/ui"
)

func evalCmd(ctx *config.RunContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate an Infracost breakdown against a cost policy",
		Long:  "Evaluate an Infracost breakdown against a cost policy",
		Example: `  Use Terraform directory with any required Terraform flags:

      infracost eval --path /path/to/code --terraform-plan-flags "-var-file=my.tfvars" --policy infracost.rego

  Use Terraform plan JSON:

      terraform plan -out tfplan.binary
      terraform show -json tfplan.binary > plan.json
      infracost eval --path plan.json --policy infracost.rego`,
		ValidArgs: []string{"--", "-"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkAPIKey(ctx.Config.APIKey, ctx.Config.PricingAPIEndpoint, ctx.Config.DefaultPricingAPIEndpoint); err != nil {
				return err
			}

			err := loadRunFlags(ctx.Config, cmd)
			if err != nil {
				return err
			}

			ctx.Config.Format = "json"
			ctx.Config.SkipErrLine = true
			ctx.SetContextValue("outputFormat", ctx.Config.Format)

			err = checkRunConfig(cmd.ErrOrStderr(), ctx.Config)
			if err != nil {
				ui.PrintUsage(cmd)
				return err
			}

			buf := &bytes.Buffer{}
			err = runMain(cmd, ctx, buf)
			if err != nil {
				return err
			}

			errs, err := queryPolicy(ctx, cmd, buf)
			if err != nil {
				return err
			}

			if !ctx.Config.IsLogging() {
				cmd.PrintErrln()
			}

			if len(errs) == 0 {
				ui.PrintSuccess(cmd.ErrOrStderr(), "Policy check passed.")
				return nil
			}

			outErr := bytes.NewBuffer([]byte("Policy check failed:\n\n"))
			for _, e := range errs {
				outErr.WriteString(e + "\n")
			}

			ui.PrintError(cmd.ErrOrStderr(), outErr.String())
			os.Exit(1)
			return nil
		},
	}

	addRunFlags(cmd)
	cmd.Flags().String("policy", "", "Path to the Infracost cost policy")

	return cmd
}

func queryPolicy(runCtx *config.RunContext, cmd *cobra.Command, buf *bytes.Buffer) ([]string, error) {
	spinnerOpts := ui.SpinnerOptions{
		EnableLogging: runCtx.Config.IsLogging(),
		NoColor:       runCtx.Config.NoColor,
		Indent:        "  ",
	}

	s := ui.NewSpinner("Evaluating cost policy", spinnerOpts)
	defer s.Fail()

	var input interface{}
	err := util.Unmarshal(buf.Bytes(), &input)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse infacost output into rego query: %s", err.Error())
	}

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		return nil, fmt.Errorf("Unable to process infracost output into rego input: %s", err.Error())
	}

	policyPath, err := cmd.Flags().GetString("policy")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	r := rego.New(
		rego.Query("data.infracost.deny"),
		rego.ParsedInput(inputValue),
		rego.Load([]string{policyPath}, func(abspath string, info os.FileInfo, depth int) bool {
			return false
		}),
	)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("Unable to query cost policy: %s", err.Error())
	}

	res, err := pq.Eval(ctx)
	if err != nil {
		return nil, err
	}

	var errs []string
	for _, e := range res[0].Expressions {
		switch v := e.Value.(type) {
		case []interface{}:
			for _, i := range v {
				errs = append(errs, fmt.Sprintf("%s", i))
			}
		case interface{}:
			errs = append(errs, e.String())
		}
	}

	if len(errs) == 0 {
		s.Success()
		return errs, nil
	}

	return errs, nil
}
