/*
Copyright © 2022 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package img4

import (
	"fmt"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(infoCmd)
	infoCmd.Flags().BoolP("json", "j", false, "Extract as JSON")
	viper.BindPFlag("img4.info.json", infoCmd.Flags().Lookup("json"))
}

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:           "info",
	Short:         "Print information",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", args[0], err)
		}
		defer f.Close()

		if viper.GetBool("img4.kbag.json") {

		} else {
			ii, err := img4.Parse(f)
			if err != nil {
				return fmt.Errorf("failed to parse img4 file: %v", err)
			}
			fmt.Println(ii)
		}

		return nil
	},
}
