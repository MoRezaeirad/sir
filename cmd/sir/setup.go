package main

import (
	"fmt"
	"strings"
)

func cmdSetup(projectRoot string, args []string) {
	yes := false
	profile := ""
	runInstall := true
	for _, arg := range args {
		switch arg {
		case "--yes", "-y":
			yes = true
		case "--personal", "--default", "--standard":
			profile = "personal"
		case "--team":
			profile = "team"
		case "--strict":
			profile = "strict"
		case "--managed":
			profile = "managed"
		case "--no-install":
			runInstall = false
		default:
			fatal("usage: sir setup [--personal|--team|--strict|--managed] [--no-install] [--yes]")
		}
	}
	fmt.Println("sir setup")
	fmt.Println()
	if profile == "" {
		if yes {
			profile = "strict"
		} else {
			fmt.Print("Policy profile [personal/team/strict/managed] (strict): ")
			var answer string
			fmt.Scanln(&answer)
			answer = strings.TrimSpace(strings.ToLower(answer))
			switch answer {
			case "", "strict":
				profile = "strict"
			case "personal", "default", "standard":
				profile = "personal"
			case "team":
				profile = "team"
			case "managed":
				profile = "managed"
			default:
				fatal("unknown profile: %s (valid: personal, team, strict, managed)", answer)
			}
		}
	}
	cmdPolicyInit(projectRoot, []string{"--profile", profile, "--yes"})
	if runInstall {
		if yes {
			cmdInstall(projectRoot, "guard")
		} else {
			fmt.Print("Install hooks for detected agents now? [Y/n] ")
			var answer string
			fmt.Scanln(&answer)
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer == "" || answer == "y" || answer == "yes" {
				cmdInstall(projectRoot, "guard")
			}
		}
	}
	fmt.Println()
	fmt.Println("Setup complete. Review with `sir status` and `sir policy show`.")
}
