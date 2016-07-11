/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"io"
	"strings"

	"github.com/spf13/cobra"

	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"os"
)

const help_long = `Help provides help for any command in the application.
Simply type kubectl help [path to command] for full details.`

func NewCmdHelp(f *cmdutil.Factory, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "help [command] | STRING_TO_SEARCH",
		Short: "Help about any command",
		Long:  help_long,

		Run: RunHelp,
	}

	return cmd
}

func printUsage(cmd *cobra.Command) {
	cmd.Root().SetOutput(os.Stdout)
	cmd.Root().Usage()
}

func RunHelp(cmd *cobra.Command, args []string) {
	foundCmd, a, err := cmd.Root().Find(args)

	// NOTE(andreykurilin): actually, I did not find any cases when foundCmd can be nil,
	//   but let's make this check since it is included in original code of initHelpCmd
	//   from github.com/spf13/cobra
	if foundCmd == nil {
		cmd.Printf("Unknown help topic %#q.\n", args)
		printUsage(cmd)
	} else if err != nil {
		// print error message at first, since it can contain suggestions
		cmd.Println(err)

		argsString := strings.Join(args, " ")
		var matchedMsgIsPrinted bool = false
		for _, foundCmd := range foundCmd.Commands() {
			if strings.Contains(foundCmd.Short, argsString) {
				if !matchedMsgIsPrinted {
					cmd.Printf("Matchers of string '%s' in short descriptions of commands: \n", argsString)
					matchedMsgIsPrinted = true
				}
				cmd.Printf("  %-14s %s\n", foundCmd.Name(), foundCmd.Short)
			}
		}

		if !matchedMsgIsPrinted {
			// if nothing is found, just print usage
			printUsage(cmd)
		}
	} else if len(a) == 0 {
		// help message for help command :)
		printUsage(cmd)
	} else {
		helpFunc := foundCmd.HelpFunc()
		helpFunc(foundCmd, args)
	}
}
